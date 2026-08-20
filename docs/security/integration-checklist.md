# Integration Checklist

Production deployment checklist for applications using
safeuploads. Each item links to the relevant threat in the
[Threat Model](threat-model.md) or the safeuploads feature
that addresses it.

---

## HTTPS & Transport Security

- [ ] All upload endpoints served over HTTPS.
- [ ] `Strict-Transport-Security` header set with
  `max-age=31536000; includeSubDomains`.
- [ ] HTTP requests redirected to HTTPS at the reverse proxy.

## Rate Limiting

- [ ] Per-IP rate limits applied to upload endpoints
  (see [Rate Limiting](../rate-limiting.md) guide).
- [ ] Per-user rate limits applied after authentication.
- [ ] Reverse proxy layer enforces body size and request rate
  before traffic reaches the application.
- [ ] `429 Too Many Requests` responses include a
  `Retry-After` header.

## File Validation Configuration

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
    - `gzip_analysis_timeout` — default 5 s for gzip inflation.
    - `max_validation_time_seconds` — default 30 s; lower in
      latency-sensitive services.
    - `max_validation_memory_mb` — default 512 MB. This is
      **telemetry, not a limit** (see below).
- [ ] Allowed extensions and MIME types reviewed and narrowed
  to only what your application accepts.

## ZIP Metadata Verification

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

## Memory Enforcement

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

## Content Analysis

- [ ] `enable_content_analysis` set to `True` if accepting
  files from untrusted users.
- [ ] `content_scan_max_size` set appropriately (default 50 MB).
- [ ] Consider supplemental antivirus scanning (ClamAV or
  similar) for high-risk environments.

## Audit Logging

- [ ] `enable_audit_logging` set to `True` in production.
- [ ] Log handler attached to `safeuploads.audit` logger
  (or parent `safeuploads` logger).
- [ ] Structured log output configured (JSON formatter
  recommended for log aggregation).
- [ ] Log storage retention policy defined (minimum 90 days
  recommended for security incident investigation).
- [ ] Alerting configured for `THREAT_DETECTED` and
  `RESOURCE_LIMIT` audit event types.

## Error Handling

- [ ] Application catches specific exception types
  (`FileSizeError`, `ExtensionSecurityError`, etc.) and
  returns user-appropriate messages.
- [ ] Internal error details from exceptions are **not**
  forwarded to API responses.
- [ ] `ErrorCode` values used for machine-readable API error
  responses, not raw exception messages.
- [ ] Generic 500 errors for unexpected failures — no stack
  traces in production responses.

## File Storage Security

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

## Security Headers (for serving uploaded content)

- [ ] `Content-Security-Policy` configured to prevent inline
  script execution if serving HTML/SVG content.
- [ ] `X-Content-Type-Options: nosniff` on all responses.
- [ ] `X-Frame-Options: DENY` or `SAMEORIGIN` as appropriate.
- [ ] `Cache-Control: no-store` for sensitive uploaded content.

## Resource Limits

- [ ] Container or process memory limits set — safeuploads
  `max_validation_memory_mb` should be below the container
  limit.- [ ] Request timeout configured at the reverse proxy and
  application level — should be above
  `max_validation_time_seconds`.
- [ ] Disk space monitored for temporary file spill
  (`SpooledTemporaryFile` uses the system temp directory).
- [ ] Consider setting `TMPDIR` environment variable to a
  dedicated partition with quota enforcement.

## Dependency Management

- [ ] `safeuploads` pinned to a specific version in
  `requirements.txt` or `pyproject.toml`.
- [ ] `pip-audit` or `safety` run in CI to detect known
  vulnerabilities in dependencies.
- [ ] `defusedxml` and `python-magic` dependencies kept
  up to date.
- [ ] `libmagic` system library installed and up to date
  on the deployment target.

## Testing

- [ ] Unit tests verify validation rejects known-bad payloads
  for each file type your app accepts.
- [ ] Integration tests confirm error responses match the
  expected format and status codes.
- [ ] Fuzz tests run periodically (`pytest -m fuzz`) to catch
  edge cases.
- [ ] Penetration testing includes crafted uploads: ZIP bombs,
  polyglot files, XXE payloads, traversal filenames.

## Monitoring & Incident Response

- [ ] Upload validation metrics tracked (success rate, failure
  rate, latency).
- [ ] Anomaly detection on upload volume and failure rate.
- [ ] Incident response runbook covers: detected malware
  upload, resource exhaustion, and audit log review
  procedures.
- [ ] Contact information for security reports published
  (`SECURITY.md` or equivalent).
