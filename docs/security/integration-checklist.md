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
    - `max_image_pixels` — default 89,478,485 (Pillow's
      `Image.MAX_IMAGE_PIXELS`); lower it to the largest image
      your application needs. An image whose header declares
      more pixels is rejected with `IMAGE_DIMENSIONS_EXCEEDED`,
      and one whose dimension header is missing or malformed
      with `IMAGE_INVALID_STRUCTURE`.
    - `max_zip_size` — set to the maximum acceptable ZIP size.
    - `max_activity_file_size` — set if accepting GPX/TCX/FIT.
      FIT uploads must be structurally valid (headers, CRCs,
      sections covering the file exactly) or are rejected with
      `FIT_INVALID_STRUCTURE`.
    - `max_gzip_size` — set if accepting gzip files.
    - `max_compression_ratio` — default 100:1 is reasonable
      for most workloads; lower for stricter environments.
    - `max_validation_time_seconds` — default 30 s wall-clock;
      lower in latency-sensitive services.
    - `max_validation_memory_mb` — default 512 MB of peak-RSS
      growth; adjust based on container memory limits.
- [ ] `allow_nested_archives` left `False` unless needed. When
  enabled it requires `scan_zip_content=True` (the constructor
  raises `FileSecurityConfigurationError` otherwise), and every
  inner ZIP is inspected like the top level; one that is
  oversized, corrupt or uninspectable is rejected.
- [ ] `ALLOWED_*_TYPES` reviewed and narrowed to the MIME types
  your application accepts and the extensions each may carry.
- [ ] `FileSecurityConfigurationError` from the `FileValidator`
  constructor handled at startup: it is raised for any
  error-severity configuration issue (a removed
  `ALLOWED_*_MIMES` or `ALLOWED_*_EXTENSIONS` setting, invalid
  limit types, non-positive limits, an empty allowed-types
  mapping, a MIME
  type with no extensions, empty or uppercase extension entries,
  empty block lists or reserved names, reserved names that are
  not lowercase, a content scan window smaller than an image or
  activity size limit), including sets overridden on the
  instance;
  warnings are only logged.

## Content Analysis

- [ ] `enable_content_analysis` set to `True` if accepting
  files from untrusted users. It covers image and activity
  uploads; ZIP contents are scanned entry by entry by the ZIP
  inspector.
- [ ] `content_scan_max_size` at least `max_image_size` and
  `max_activity_file_size` (default 50 MB). With content analysis
  on, a smaller window is a configuration error.
- [ ] Consider supplemental antivirus scanning (ClamAV or
  similar) for high-risk environments.

## Image Processing

safeuploads checks the dimensions an image header declares but
does not decode pixel data, so decoder bugs and corrupt image
bodies are not caught (see
[Image Decompression Bombs](threat-model.md#image-decompression-bombs-cwe-400)).

- [ ] Images are decoded, resized or re-encoded in an isolated
  worker process or container with its own memory and time
  limits, not in the process that serves requests.
- [ ] The decoder's own pixel limit stays set at or below
  `max_image_pixels` (with Pillow, keep `Image.MAX_IMAGE_PIXELS`;
  never set it to `None`).
- [ ] A re-encoded copy is stored or served instead of the
  uploaded bytes, so metadata (EXIF, GPS), data appended to the
  image and secondary images are dropped.
- [ ] Image decoder libraries (Pillow, libjpeg-turbo, libpng,
  libwebp) kept up to date.

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
  returns user-appropriate messages. Malformed or forbidden XML
  (`XmlSecurityError`), content threats (`ContentThreatError`)
  and images over the pixel limit (`ImageDimensionError`) are
  `FileValidationError` subclasses.
- [ ] `FileProcessingError` (including `ResourceLimitError`) is
  caught as well: it is not a `FileValidationError`, and it is
  raised only for internal errors and exceeded resource limits.
- [ ] Internal error details from exceptions are **not**
  forwarded to API responses.
- [ ] `ErrorCode` values used for machine-readable API error
  responses, not raw exception messages. A `ZipContentError`
  carries the code of the first threat found (for example
  `ZIP_DIRECTORY_TRAVERSAL`), not always `ZIP_CONTENT_THREAT`,
  and `threats` lists all messages.
- [ ] Generic 500 errors for unexpected failures — no stack
  traces in production responses.

## File Storage Security

- [ ] Uploaded files stored outside the web-accessible
  document root.
- [ ] Uploaded files renamed to random identifiers (UUIDs);
  original filenames stored in metadata only. If the stored name
  needs an extension, derive it from `ValidationResult.mime_type`,
  not from the uploaded name.
- [ ] Storage directory permissions restrict access to the
  application user only (`0700` or equivalent).
- [ ] If serving uploaded files back to users, use:
    - `Content-Disposition: attachment` to force download.
    - `Content-Type` set from `ValidationResult.mime_type`,
      not from the filename.
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
  limit. The monitor measures the increase in process-wide peak
  RSS, so it cannot bound validation memory by itself (an
  earlier, higher peak hides later allocations) and other work in
  the same process can also trip it; the container limit stays
  the hard bound. On Windows memory accounting is disabled and
  only the time limit applies.
- [ ] Both limits are checked at loop boundaries (upload
  streaming, ZIP entry loops, gzip decompression, each XML
  chunk, each JPEG segment before the frame header) and on exit; a single blocking call, such as one
  `zipfile` central-directory parse or one libmagic call, is
  not interrupted mid-call. A `ResourceLimitError` keeps its
  own `RESOURCE_TIME_EXCEEDED` or `RESOURCE_MEMORY_EXCEEDED`
  code.
- [ ] Request timeout configured at the reverse proxy and
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
  on the deployment target. Without it `import safeuploads`
  fails with `ImportError`. If the detector fails to initialize,
  every upload is rejected with `MIME_DETECTION_FAILED`; there is
  no extension-based fallback.

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
