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

- Entry extensions are checked against
  `ZipThreatCategory.EXECUTABLE_FILES`, `SCRIPT_FILES`, and
  `SYSTEM_FILES`.
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
declarations can trigger external entity resolution, leading
to server-side file reads or SSRF.

**Mitigations:**

- `XmlSecurityValidator` uses `defusedxml` with
  `forbid_dtd=True`, blocking all DTD declarations, external
  entities, and entity expansion attacks (billion laughs).
- `DTDForbidden`, `EntitiesForbidden`, and
  `ExternalReferenceForbidden` are caught and reported as
  validation failures.

---

## Resource Exhaustion

### Memory Exhaustion (CWE-400)

**Attack:** Uploading very large files or files that expand
significantly during validation consumes all available memory.

**Mitigations:**

- Streaming validation via `SpooledTemporaryFile` keeps memory
  usage under `max_memory_buffer_size` (default 10 MB) by
  spilling to disk for larger files.
- `ResourceMonitor` tracks memory delta via
  `resource.getrusage()` and enforces
  `max_validation_memory_mb` (default 512 MB).
- File size is enforced progressively during chunked reads,
  not after loading the entire file.

### CPU Exhaustion (CWE-400)

**Attack:** Crafted files that trigger expensive validation
paths (e.g., ZIP with many entries, deeply nested structures).

**Mitigations:**

- `ResourceMonitor` enforces `max_validation_time_seconds`
  (default 30 s) using `time.monotonic()`.
- ZIP analysis has its own `zip_analysis_timeout` (default 5 s)
  with periodic `check_time()` calls during iteration.
- `max_zip_entries` (default 10,000) caps per-archive entry
  count.

### Gzip Decompression Bombs

**Attack:** A small gzip file that decompresses to massive
size, similar to ZIP bombs.

**Mitigations:**

- `GzipContentInspector` reads gzip streams in chunks, checking
  the compression ratio and uncompressed size against
  `SecurityLimits` progressively.
- Exceeding either limit raises a validation error immediately,
  without reading the rest of the stream.

---

## Audit & Observability

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
