# Integration checklist

Production deployment checklist for applications using
safeuploads. Each item links to the relevant threat in the
[Threat Model](threat-model.md) or the safeuploads feature
that addresses it.

---

## HTTPS & transport security

- [ ] All upload endpoints served over HTTPS.
- [ ] `Strict-Transport-Security` header set with
  `max-age=31536000; includeSubDomains`.
- [ ] HTTP requests redirected to HTTPS at the reverse proxy.

## Rate limiting

- [ ] Per-IP rate limits applied to upload endpoints
  (see [Rate Limiting](../rate-limiting.md) guide).
- [ ] Per-user rate limits applied after authentication.
- [ ] Reverse proxy layer enforces body size and request rate
  before traffic reaches the application.
- [ ] `429 Too Many Requests` responses include a
  `Retry-After` header.

## File validation configuration

- [ ] `FileValidator` instantiated with explicit
  `FileSecurityConfig` (not relying solely on defaults).
- [ ] `SecurityLimits` tuned for your use case:
    - `max_image_size` — appropriate for expected upload sizes.
    - `max_zip_size` — set to the maximum acceptable ZIP size.
    - `max_activity_file_size` — set if accepting GPX/TCX/FIT.
    - `max_gzip_size` — set if accepting gzip files.
    - `max_compression_ratio` — default 100:1 is reasonable
      for most workloads; lower for stricter environments.
    - `max_xml_elements` — default 1,000,000; lower if you only
      accept small GPX/TCX files.
    - `gzip_analysis_timeout` — default 25 s for gzip inflation,
      sized to cover `max_uncompressed_size` at a conservative
      50 MB/s. Lower it only alongside `max_uncompressed_size`:
      a timeout too short for the permitted size rejects slow
      but legitimate uploads as decompression bombs, and
      configuration validation warns when the two disagree.
    - `max_validation_time_seconds` — default 30 s; lower in
      latency-sensitive services.
    - `max_validation_memory_mb` — default 512 MB. This is
      **telemetry, not a limit** (see below).
- [ ] Allowed extensions and MIME types reviewed and narrowed
  to only what your application accepts.

Anything you leave out of `SecurityLimits` keeps its secure
default, and the limits object is copied, so nothing is shared
between configs:

```python
from concurrent.futures import ThreadPoolExecutor

from safeuploads import (
    FileSecurityConfig,
    FileValidator,
    SecurityLimits,
)

config = FileSecurityConfig(
    SecurityLimits(
        max_image_size=10 * 1024 * 1024,  # 10 MiB
        max_image_pixels=50_000_000,  # Reject bigger decoded images
        max_compression_ratio=50,
        # Decompress every ZIP entry to reject archives with
        # forged central-directory metadata
        verify_zip_decompression=True,
        # Keep spilled uploads off the system temp directory
        temp_dir="/var/lib/myapp/uploads-tmp",
    )
)

# Optionally offload blocking inspection to a bounded pool
validator = FileValidator(
    config=config,
    executor=ThreadPoolExecutor(max_workers=4),
)
```

## ZIP metadata verification

safeuploads reads the declared entry sizes from the ZIP central
directory, which an attacker controls. `verify_zip_decompression`
is **off by default** because enabling it decompresses every
entry, costing up to `max_uncompressed_size` of inflation per
upload. That default is safe only because of who consumes the
archive afterwards:

- [ ] Determine how your application extracts the archive.
    - Python's `zipfile` caps reads at the declared size and
      raises `BadZipFile` on the resulting CRC mismatch, so
      forged metadata cannot bomb it. The default is fine.
    - Anything that inflates the raw DEFLATE stream directly
      (`zlib`), or an external tool that trusts local headers
      (`unzip`, `7z`), is **not** protected by the declared
      sizes. Set `verify_zip_decompression=True`.
- [ ] If enabling it, confirm `max_validation_time_seconds` is
  large enough for the archive sizes you accept, since the
  whole archive is now inflated during validation.

## Memory enforcement

- [ ] Leave `enforce_memory_limit` at its default (`False`)
  unless the process validates one upload at a time. The
  underlying metric is the process-wide peak RSS, so under
  concurrency it attributes other requests' allocations to this
  one and will reject legitimate uploads.
- [ ] Rely on the byte limits (`max_image_size`, `max_zip_size`,
  `max_uncompressed_size`, `max_memory_buffer_size`,
  `content_scan_max_size`, `max_xml_elements`) as the real
  memory bound, plus a container memory limit.
- [ ] Alert on the "memory budget exceeded (not enforced)"
  warning rather than treating it as a control.

## Content analysis

- [ ] `enable_content_analysis` set to `True` if accepting
  files from untrusted users.
- [ ] `content_scan_max_size` set appropriately (default 50 MB).
- [ ] Consider supplemental antivirus scanning (ClamAV or
  similar) for high-risk environments.

## Audit logging

- [ ] `enable_audit_logging` set to `True` in production.
- [ ] Log handler attached to `safeuploads.audit` logger
  (or parent `safeuploads` logger).
- [ ] Structured log output configured (JSON formatter
  recommended for log aggregation).
- [ ] `set_source_ip()` called with the client address before
  validating, so audit events can be attributed to a caller.
- [ ] `reset_source_ip()` called when the address must not
  outlive the request, if your framework reuses the context.
- [ ] Log storage retention policy defined (minimum 90 days
  recommended for security incident investigation).
- [ ] Alerting configured for `THREAT_DETECTED` and
  `RESOURCE_LIMIT` audit event types.

## Error handling

- [ ] Application catches specific exception types
  (`FileSizeError`, `ExtensionSecurityError`, etc.) and
  returns user-appropriate messages.
- [ ] Internal error details from exceptions are **not**
  forwarded to API responses.
- [ ] `ErrorCode` values used for machine-readable API error
  responses, not raw exception messages.
- [ ] Generic 500 errors for unexpected failures — no stack
  traces in production responses.

!!! warning
    Exception messages embed values derived from the upload — the
    detected MIME type, ZIP entry names, declared image
    dimensions — and `err.filename` carries the client-supplied
    name. Returning `str(err)` or `err.filename` to a client
    reflects attacker-controlled bytes back to the browser.
    Branch on the exception type and surface `err.error_code`,
    which is a stable machine-readable string.

```python
import logging

from safeuploads.exceptions import (
    FileValidationError,      # Base exception
    FileSizeError,            # File too large
    ExtensionSecurityError,   # Dangerous extension
    ImageSecurityError,       # Image decompression bomb
    ZipBombError,             # Compression attack
)

logger = logging.getLogger(__name__)

try:
    await validator.validate_image_file(file)
except FileSizeError as err:
    return {"error": "File too large", "max_size": err.max_size}
except ExtensionSecurityError as err:
    return {"error": "File type not allowed", "code": err.error_code}
except ImageSecurityError as err:
    return {"error": "Image too large to decode", "code": err.error_code}
except FileValidationError as err:
    # Full detail goes to the log; the client only sees the code.
    logger.warning("Upload rejected: %s", err)
    return {"error": "Upload rejected", "code": err.error_code}
```

## File storage security

- [ ] Uploaded files stored outside the web-accessible
  document root.
- [ ] Uploaded files renamed to random identifiers (UUIDs);
  original filenames stored in metadata only.
- [ ] Storage directory permissions restrict access to the
  application user only (`0700` or equivalent).
- [ ] If serving uploaded files back to users, use:
    - `Content-Disposition: attachment` to force download.
    - `Content-Type` set from validated MIME type, not from
      the filename.
    - `X-Content-Type-Options: nosniff` header.

## Security headers (for serving uploaded content)

- [ ] `Content-Security-Policy` configured to prevent inline
  script execution if serving HTML/SVG content.
- [ ] `X-Content-Type-Options: nosniff` on all responses.
- [ ] `X-Frame-Options: DENY` or `SAMEORIGIN` as appropriate.
- [ ] `Cache-Control: no-store` for sensitive uploaded content.

## Resource limits

- [ ] Container or process memory limits set — safeuploads
  `max_validation_memory_mb` should be below the container
  limit.
- [ ] Request timeout configured at the reverse proxy and
  application level — should be above
  `max_validation_time_seconds`.
- [ ] Disk space monitored for temporary file spill
  (uploads above `max_memory_buffer_size` are written to disk).
- [ ] `temp_dir` set to a dedicated, quota-enforced partition,
  or `TMPDIR` set if you prefer to configure it out of band.
  The directory must exist; configuration validation reports
  `invalid_temp_dir` when it does not.

## Dependency management

- [ ] `safeuploads` pinned to a specific version in
  `requirements.txt` or `pyproject.toml`.
- [ ] Release provenance verified before promoting a new version
  (see below).
- [ ] `pip-audit` or `safety` run in CI to detect known
  vulnerabilities in dependencies.
- [ ] `defusedxml` and `python-magic` dependencies kept
  up to date.
- [ ] `libmagic` system library installed and up to date
  on the deployment target.

Releases are built and published by the repository's release
workflow through PyPI Trusted Publishing, with
[PEP 740](https://peps.python.org/pep-0740/) attestations, so
you can confirm a downloaded artifact came from that workflow
and was not substituted:

```bash
uvx pypi-attestations verify pypi \
  --repository https://github.com/endurain-project/safeuploads \
  pypi:safeuploads-<version>-py3-none-any.whl
```

A successful run prints `OK: <filename>`. `Provenance for file
... was not found` means the artifact predates attested
publishing rather than that verification failed.

Each release run also produces a CycloneDX SBOM and
`SHA256SUMS`, generated from a clean install of the built wheel.
These are retained as workflow artifacts on the release run
rather than published to PyPI.

## Testing

- [ ] Unit tests verify validation rejects known-bad payloads
  for each file type your app accepts.
- [ ] Integration tests confirm error responses match the
  expected format and status codes.
- [ ] Fuzz tests run periodically (`pytest -m fuzz`) to catch
  edge cases.
- [ ] Penetration testing includes crafted uploads: ZIP bombs,
  polyglot files, XXE payloads, traversal filenames.

## Monitoring & incident response

- [ ] Upload validation metrics tracked (success rate, failure
  rate, latency).
- [ ] Anomaly detection on upload volume and failure rate.
- [ ] Incident response runbook covers: detected malware
  upload, resource exhaustion, and audit log review
  procedures.
- [ ] Contact information for security reports published
  (`SECURITY.md` or equivalent).
