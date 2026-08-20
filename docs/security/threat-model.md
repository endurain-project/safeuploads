# Threat Model

This document describes the threat categories that safeuploads
protects against, the attack vectors for each, and the
mitigations implemented in the library.

---

## Filename Attacks

### Directory Traversal (CWE-22)

**Attack:** Filenames containing `../`, `..\\`, or URL-encoded
variants (`%2e%2e%2f`) attempt to write files outside the
intended upload directory.

**Mitigations:**

- `UnicodeSecurityValidator` normalizes Unicode to NFC form and
  strips zero-width characters before any path checks.
- `ExtensionSecurityValidator` rejects filenames containing
  traversal sequences from `SuspiciousFilePattern.DIRECTORY_TRAVERSAL`.
- Null bytes in filenames are rejected to prevent C-string
  truncation attacks.

### Unicode Obfuscation (CWE-116)

**Attack:** Right-to-left override characters (U+202E) and
zero-width joiners can disguise file extensions so that
`report.pdf` visually appears safe while the real extension
is `.exe`.

**Mitigations:**

- All filenames are NFC-normalized before validation.
- Characters in `UnicodeAttackCategory` (directional overrides,
  zero-width characters, confusing punctuation) are detected
  and rejected.
- Fullwidth period (U+FF0E) and dot leader (U+2024) are
  flagged to prevent extension spoofing.

### Windows Reserved Names (CWE-20)

**Attack:** Filenames like `CON`, `PRN`, `NUL`, or `COM1`
cause undefined behavior on Windows file systems, potentially
leading to denial of service.

**Mitigations:**

- `WindowsSecurityValidator` checks the stem of each filename
  against `FileSecurityConfig.WINDOWS_RESERVED_NAMES` (case-
  insensitive).

---

## Extension Attacks

### Dangerous Extensions (CWE-434)

**Attack:** Uploading executable files (`.exe`, `.bat`, `.ps1`,
`.php`, `.jsp`) that could be executed if served or stored
improperly.

**Mitigations:**

- `ExtensionSecurityValidator` maintains a blocklist generated
  from `DangerousExtensionCategory` covering 16 categories:
  Windows executables, script files, web scripts, Unix/macOS
  executables, Java, mobile apps, browser extensions, package
  formats, archives, virtualization, Office macros, system
  files, drivers, themes, and help files.
- Compound extensions (`.tar.gz`, `.user.js`, `.min.css`) are
  checked via `CompoundExtensionCategory`.
- Allowed extensions are validated against a configurable
  allowlist per file type.

---

## Compression Attacks

### ZIP Bombs (CWE-400)

**Attack:** A small ZIP archive that decompresses to an
enormous size (e.g., 42.zip — 42 KB compressed, 4.5 PB
uncompressed), exhausting disk and memory.

**Mitigations:**

- `CompressionSecurityValidator` enforces `max_compression_ratio`
  (default 100:1) by comparing compressed vs. reported
  uncompressed sizes.
- `max_uncompressed_size` (default 1 GB) caps total extraction.
- `max_individual_file_size` (default 500 MB) caps per-entry
  size.
- `zip_analysis_timeout` (default 5 s) prevents slow analysis.
- All timeout checks use `time.monotonic()` to prevent bypass
  via NTP clock adjustment.

**Metadata trust boundary:**

- The size and ratio checks above read the ZIP central-
  directory `file_size` / `compress_size` fields, which are
  attacker-controlled. A forged *small* `file_size` cannot bomb
  a `zipfile`-based consumer: Python's `zipfile` caps reads at
  the declared size and raises `BadZipFile` on the resulting
  CRC mismatch. The residual risk is a consumer that inflates
  the raw DEFLATE stream while ignoring the ZIP metadata.
- safeuploads does **not** extract archives. Consumers must
  extract safely — prefer `zipfile` (which enforces the
  declared sizes) over raw `zlib` inflation.
- Set `verify_zip_decompression=True` to make safeuploads read
  every entry through `zipfile`, forcing CRC and decompression
  validation. Archives whose real content does not match their
  declared metadata are then rejected as `ZIP_CORRUPT`. This is
  off by default because it decompresses the full archive.

### Recursive / Quine ZIP Archives

**Attack:** A ZIP containing itself (quine) or deeply nested
ZIPs that cause infinite recursion during inspection.

**Mitigations:**

- `ZipContentInspector.inspect_nested_archives()` tracks
  archive SHA-256 hashes; encountering a previously seen hash
  raises `ZIP_QUINE_DETECTED`.
- `max_zip_depth` (default 10) limits nesting level.
- `max_total_entries_recursive` (default 50,000) limits the
  cumulative entry count across all nesting levels.
- `ZIP_RECURSIVE_STRUCTURE` and `ZIP_COMPLEXITY_ATTACK` error
  codes provide precise feedback.

### Nested Archive Detection

**Attack:** Archives hidden inside other archives to bypass
single-level content inspection.

**Mitigations:**

- When `allow_nested_archives=False` (default), any entry with
  an extension in `ZipThreatCategory.NESTED_ARCHIVES` raises
  `ZIP_NESTED_ARCHIVE`.
- When allowed, recursive inspection applies all depth, count,
  and hash checks.

---

## Content Threats (ZIP Entries)

### Path Traversal in ZIP Entry Names (CWE-22)

**Attack:** ZIP entry filenames like `../../etc/passwd` write
outside the extraction directory (Zip Slip).

**Mitigations:**

- `ZipContentInspector._inspect_zip_entry()` checks for
  traversal patterns and absolute paths.
- Null bytes in entry filenames are rejected first to prevent
  C-string truncation bypasses (CWE-158).

### Executable Content in ZIP

**Attack:** Executables, scripts, system files, or shortcuts
hidden inside ZIP archives.

**Mitigations:**

- `ZipContentInspector._check_dangerous_extension()` rejects any
  entry whose name carries an extension from
  `ZipThreatCategory.EXECUTABLE_FILES`, `SCRIPT_FILES`, or
  `SYSTEM_FILES`. Every dot-separated suffix is checked, so a
  disguised name such as `invoice.php.txt` is still rejected.
  This check is metadata-level and runs even when
  `scan_zip_content=False`.
- Binary content is scanned for executable magic bytes from
  `SuspiciousFilePattern.EXECUTABLE_SIGNATURES`.
- Text content is scanned for script injection patterns
  (shebangs, `eval()`, `<?php`, `<script`).

### Symbolic Links in ZIP (CWE-59)

**Attack:** Symlinks inside ZIP archives can point to
arbitrary system files when extracted.

**Mitigations:**

- Symlink entries are detected and rejected when
  `allow_symlinks=False` (default).

---

## File Content Attacks

### Image Decompression Bombs (CWE-409)

**Attack:** A small PNG or JPEG that declares enormous pixel
dimensions. A ~10 KB file claiming 30000x30000 passes every
byte-size check but expands to several gigabytes in any
downstream decoder (Pillow, ImageMagick, a browser).

**Mitigations:**

- `FileValidator` parses the declared dimensions directly from
  the header: the PNG `IHDR` chunk, or the first JPEG
  start-of-frame segment.
- `width * height` is bounded by `max_image_pixels` (default
  89,478,485, matching Pillow's `MAX_IMAGE_PIXELS`). Breaches
  raise `ImageSecurityError` with
  `IMAGE_DIMENSIONS_EXCEEDED`.
- The header is searched across the first 1 MiB, so padding the
  EXIF block to push the frame header past the MIME sample does
  not bypass the check.
- The check fails closed: an image whose dimensions cannot be
  read, or which declares a zero dimension, is rejected with
  `IMAGE_DIMENSIONS_UNREADABLE`.

### MIME Type Mismatch (CWE-434)

**Attack:** A file with a `.jpg` extension but containing
executable content, relying on the server trusting the
extension.

**Mitigations:**

- `python-magic` detects the actual MIME type from file content
  (first 8 KB).
- The detected MIME type is validated against the allowlist for
  the file type being validated.
- File signatures (magic bytes) are verified independently of
  the MIME type.

### Polyglot Files

**Attack:** Files valid in multiple formats simultaneously
(e.g., GIFAR — a file that is both a valid GIF and a valid
JAR) that bypass type checks but execute as the malicious
format.

**Mitigations:**

- `ContentSecurityInspector` (when `enable_content_analysis=
  True`) scans for secondary format signatures
  (`MalwareSignatureCategory.POLYGLOT_SIGNATURES`) that should
  not appear in image or activity files: ZIP/JAR headers,
  Java class headers, RAR headers.
- Polyglot checks are context-aware — ZIP signatures inside a
  file being validated as a ZIP are not flagged.

### Embedded Malware Signatures

**Attack:** Executable headers (PE, ELF, Mach-O, Java class,
Windows shortcuts) embedded within uploaded files.

**Mitigations:**

- `ContentSecurityInspector` scans file content for byte
  signatures from `MalwareSignatureCategory`: PE/MZ headers,
  ELF headers, Mach-O headers (32/64-bit, both endiannesses),
  Java class magic, and Windows shortcut headers.
- Web shell markers (`<?php`, `<%`, `<script`) are detected
  in text content.

### XML External Entity Injection (CWE-611)

**Attack:** GPX and TCX files are XML-based; malicious DTD
declarations can trigger external entity resolution, leadingto server-side file reads or SSRF.

**Mitigations:**

- `XmlSecurityValidator` uses `defusedxml` with
  `forbid_dtd=True`, blocking all DTD declarations, external
  entities, and entity expansion attacks (billion laughs).
- `DTDForbidden`, `EntitiesForbidden`, and
  `ExternalReferenceForbidden` are caught and reported as
  validation failures.

### Arbitrary XML Behind an Activity Extension

**Attack:** Well-formed XML is not a GPX file. An attacker
uploads `<html><script>...</script></html>` named `track.gpx`;
it passes the `<?xml` signature check and parses cleanly. If
the application later serves the stored file with a sniffable
content type, the payload executes (stored XSS).

**Mitigations:**

- The document root must match the uploaded extension:
  `.gpx` requires a `gpx` root and `.tcx` requires a
  `TrainingCenterDatabase` root, per
  `FileSecurityConfig.ACTIVITY_XML_ROOTS`.
- Namespaces are stripped before matching, so a namespaced
  `{http://www.topografix.com/GPX/1/1}gpx` root is accepted.
- Mismatches raise `FileProcessingError` with
  `XML_INVALID_ROOT`. A TCX document uploaded as `.gpx` is
  rejected.

### XML Element Amplification

**Attack:** `defusedxml` blocks entity expansion, but a flat
document needs no entities: 50 MB of `<a/>` is roughly twelve
million elements, and a full DOM of those costs an order of
magnitude more memory than the file itself.

**Mitigations:**

- Parsing is incremental (`iterparse`); completed elements and
  the accumulated root children are discarded as they close, so
  peak memory stays flat regardless of document length.
- The element count is capped by `max_xml_elements`
  (default 1,000,000), raising `XML_TOO_MANY_ELEMENTS`.

---

## Resource Exhaustion

### Memory Exhaustion (CWE-400)

**Attack:** Uploading very large files or files that expand
significantly during validation consumes all available memory.

**Mitigations:**

- Streaming validation via `SpooledTemporaryFile` keeps memory
  usage under `max_memory_buffer_size` (default 10 MB) by
  spilling to disk for larger files.
- Every buffer the library allocates is bounded by an explicit
  byte limit: `chunk_size`, `content_scan_max_size`,
  `max_uncompressed_size`, and `max_xml_elements`.
- File size is enforced progressively during chunked reads,
  not after loading the entire file.
- `ResourceMonitor` additionally reports peak-RSS growth against
  `max_validation_memory_mb`. See the caveat under CPU
  Exhaustion: this is telemetry, not a limit, unless
  `enforce_memory_limit` is set.

### CPU Exhaustion (CWE-400)

**Attack:** Crafted files that trigger expensive validation
paths (e.g., ZIP with many entries, deeply nested structures).

**Mitigations:**

- `ResourceMonitor` enforces `max_validation_time_seconds`
  (default 30 s) using `time.monotonic()`. The budget is
  checked on every chunk of the streaming reads, every ZIP
  entry, every recursive nesting step, and every gzip chunk, so
  a runaway file is aborted while it runs rather than reported
  after the fact.
- ZIP analysis has its own `zip_analysis_timeout` (default 5 s),
  compared against `time.monotonic()` on each entry during
  iteration.
- `max_zip_entries` (default 10,000) caps per-archive entry
  count.

**Memory accounting caveat:** the memory budget samples the
process-wide peak RSS (`ru_maxrss`), a monotonic high-water
mark. It cannot be attributed to a single validation: after the
first peak the measured delta is near zero, and under
concurrency it picks up other requests' allocations. It is
therefore **best-effort telemetry, not a limit** — exceeding
`max_validation_memory_mb` is logged, not enforced. Set
`enforce_memory_limit=True` to make it fail the validation, and
only do so in a process that validates one upload at a time.
The real memory bounds are structural: `max_memory_buffer_size`,
`chunk_size`, `content_scan_max_size`, `max_uncompressed_size`
and `max_xml_elements` cap every buffer the library allocates.

### Gzip Decompression Bombs

**Attack:** A small gzip file that decompresses to massive
size, similar to ZIP bombs.

**Mitigations:**
- `GzipContentInspector` reads gzip streams in chunks, checking
  the compression ratio and uncompressed size against
  `SecurityLimits` progressively.
- Exceeding either limit raises a validation error immediately,
  without reading the rest of the stream.
- Inflation is additionally bounded by `gzip_analysis_timeout`
  (default 5 s), so a stream that stays inside the ratio and
  size limits still cannot burn unbounded CPU. The bound does
  not depend on the caller supplying a `ResourceMonitor`.

---

## Audit & Observability

### Log Injection (CWE-117)

**Attack:** A filename or ZIP entry name containing a newline
(`upload.jpg\nWARNING forged entry`) forges an extra log line,
or uses directional and zero-width characters to hide the real
name from an analyst reading the log.

**Mitigations:**

- `safe_label()` escapes control, format, surrogate and
  line-separator characters to `\uXXXX` and bounds the length
  before any untrusted text reaches a log record, an audit
  event, or an exception message.
- The raw client filename is escaped in `FileValidator` before
  the first audit event is emitted, which happens before any
  sanitization has run.
- `SecurityAuditLogger.log_event()` escapes the filename,
  result and details fields again at the emission point, so
  every caller is covered regardless of how the event was
  built.
- Unicode validation errors report the offending code point and
  its Unicode name rather than echoing the character itself.

### Undetected Security Events (CWE-778)

**Attack:** Security-relevant events (validation failures,
threat detections) go unlogged, preventing incident response.

**Mitigations:**

- `SecurityAuditLogger` emits structured log records under the
  `safeuploads.audit` logger for every validation start,
  success, failure, and threat detection.
- Correlation IDs (via `contextvars`) link all log messages
  from a single validation call.
- Audit logging is off by default (`enable_audit_logging=
  False`) to avoid noise in development, enabled in production.

---

## Error Information Leakage (CWE-209)

**Attack:** Detailed internal error messages in API responses
help attackers understand the validation pipeline and craft
bypass attempts.

**Mitigations:**

- Exception messages use static, generic text rather than
  including raw internal error details.
- `ErrorCode` constants provide machine-readable classification
  without exposing implementation details.
- Application code controls what error text reaches the client
  by catching specific exception types.
