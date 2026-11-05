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

- `UnicodeSecurityValidator` rejects filenames containing
  dangerous Unicode characters (including zero-width ones) with
  `UnicodeSecurityError` and normalizes the rest to NFC form
  before any path checks.
- A filename whose NFKC form contains a path separator (`/`,
  `\`) or `..` that its NFC form does not, such as a fullwidth
  solidus (U+FF0F), is rejected with `FILENAME_INVALID` before
  `os.path.basename` runs.
- Upload filenames are reduced to their last path component
  (`os.path.basename`), and the characters `<>:"/\|?*` are
  replaced with `_`, so traversal sequences cannot survive into
  the sanitized name. The traversal patterns in
  `SuspiciousFilePattern.DIRECTORY_TRAVERSAL` are applied to ZIP
  entry names only.
- Null bytes and other control characters are rejected, not
  stripped, so C-string truncation attacks and names that
  change meaning after cleaning never reach storage (see
  Unicode Obfuscation below).
- The extension and Windows reserved-name checks run again on
  the final name after it is shortened to
  `max_sanitized_name_length`, so truncation cannot expose a
  blocked extension.

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
- Every character in the Unicode general categories Cc
  (controls, including NUL, DEL and C1), Cf (format characters,
  including soft hyphen, bidi marks and zero-width joiner), Co
  (private use), Cn (unassigned), Cs (surrogates), Zl and Zp is
  rejected with `UnicodeSecurityError`; none is stripped. A
  filename containing an emoji ZWJ sequence is therefore
  rejected.
- Categories come from the running Python's Unicode database
  (14.0 on Python 3.11, 15.0 on 3.12, 15.1 on 3.13), so a
  character assigned in a later Unicode version is unassigned
  (Cn) and rejected on an older Python. Older versions only
  reject more.
- The Windows reserved-name and extension checks run on the NFC
  name and on its NFKC form, so fullwidth letters or
  superscript digits cannot disguise `CON`, `COM1` or `.php`.
  The returned name stays NFC.
- Fullwidth period (U+FF0E) and dot leader (U+2024) are
  flagged to prevent extension spoofing.

### Windows Reserved Names (CWE-20)

**Attack:** Filenames like `CON`, `PRN`, `NUL`, or `COM1`
cause undefined behavior on Windows file systems, potentially
leading to denial of service.

**Mitigations:**

- `WindowsSecurityValidator` checks the stem of each filename
  against `FileSecurityConfig.WINDOWS_RESERVED_NAMES`
  (case-insensitive, compared case-folded). The list includes
  `com0`, `lpt0`, `conin$`, `conout$` and `clock$`.

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
- Trailing dots and spaces are ignored by the blocked-extension
  check, because Windows drops them when it saves a file. The
  check also runs on the NFKC form, so `run.exe ` or
  `invoice.docm` followed by U+3000 (an ideographic space that
  NFKC folds to a space) is rejected.
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
- A directory entry (name ending in `/`) that declares
  uncompressed data is rejected with `ZIP_INVALID_STRUCTURE`, so
  data cannot hide from the size and ratio checks behind a
  directory name.
- `zip_analysis_timeout` (default 5 s) prevents slow analysis;
  exceeding it raises `ZipBombError` with `ZIP_ANALYSIS_TIMEOUT`.
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

- `ZipContentInspector.inspect_nested_archives()` tracks the
  SHA-256 hashes of an archive's ancestors; an inner archive
  whose hash matches one of its ancestors raises
  `ZIP_QUINE_DETECTED`. Identical sibling archives are not a
  quine and are accepted. The `seen_hashes` argument holds
  ancestor hashes and is not modified.
- `max_zip_depth` (default 10) limits nesting level.
- `max_total_entries_recursive` (default 50,000) limits the
  cumulative entry count across all nesting levels. Together
  with `max_zip_depth` and the analysis timeout, it bounds the
  work for many identical sibling archives.
- `ZIP_RECURSIVE_STRUCTURE` and `ZIP_COMPLEXITY_ATTACK` error
  codes provide precise feedback.

### Nested Archive Detection

**Attack:** Archives hidden inside other archives to bypass
single-level content inspection.

**Mitigations:**

- When `allow_nested_archives=False` (default), any entry with
  an extension in `ZipThreatCategory.NESTED_ARCHIVES` raises
  `ZIP_NESTED_ARCHIVE`.
- Extensions are taken from the entry name after stripping
  trailing dots and spaces, as Windows drops them on
  extraction.
- When `scan_zip_content` is enabled (default) and nested
  archives are not allowed, the first bytes of each entry are
  checked against `ZipThreatCategory.NESTED_ARCHIVE_SIGNATURES`
  (ZIP and ZIP-based formats such as `.docx` and `.jar`, gzip,
  bzip2, xz, 7z and RAR). A renamed archive is rejected and
  reported under `ZIP_CONTENT_THREAT`. Tar is recognised by
  extension only.
- When allowed, `ZipContentInspector.inspect_nested_archives()`
  inspects every inner ZIP, found by a recursable archive
  extension or a ZIP signature. The inner archive is streamed in
  `chunk_size` chunks into a spooled temporary file and gets the
  same checks as the top level: the entry count, exact layout,
  size and ratio checks of `CompressionSecurityValidator` and
  the entry and structure checks of `ZipContentInspector`, plus
  the depth, count and ancestor hash checks above.
- An inner archive that is larger than
  `max_individual_file_size` (`FILE_TOO_LARGE`), cannot be read,
  is corrupt (`ZIP_CORRUPT`) or cannot be inspected is rejected,
  not skipped. Threats name the nesting path (entry names joined
  by `/`), and a nested ratio bomb raises `ZipBombError` with
  the path in its message.
- Nested archives need `scan_zip_content`: a configuration with
  `allow_nested_archives=True` and `scan_zip_content=False` is
  rejected at construction with the `nested_archives_require_scan`
  configuration error.
- Memory is bounded by the nesting depth times
  `max_memory_buffer_size`, since each level holds one spooled
  temporary file that spills to disk beyond that size.

### Ambiguous Archive Layout (Parser Differential)

**Attack:** A ZIP built so that `zipfile`, which reads the
central directory, sees different entries from an extractor
that walks local headers from the start of the file. Examples
are a fake end record or a whole benign archive hidden in the
archive comment, two concatenated archives, an unlisted entry
between listed ones, a local header whose sizes or name differ
from the central directory, a Unicode Path extra field naming
the entry differently from its raw header name, and a deflate
stream that ends before a data-descriptor entry's declared
size. The validated archive then passes while the extractor
writes hidden files.

**Mitigations:**

- `CompressionSecurityValidator` requires the listed entries to
  fill the file exactly: local headers start at offset 0 and
  follow one another without gaps or overlaps, the central
  directory sits at its declared offset right after the last
  entry, and the end records with their declared comment end
  the file. Prepended or trailing bytes, including zero
  padding, are rejected.
- Each local header must agree with its central-directory
  record: name bytes, name encoding flag, compression method,
  data-descriptor flag and, without a descriptor, CRC-32 and
  sizes (ZIP64 sizes are read from the local extra field). With
  a descriptor, each local CRC-32 and size must be zero or equal
  to the central value, so a streaming reader cannot end the
  entry early and read a hidden entry from its data.
- Every Info-ZIP Unicode Path extra field (`0x7075`), local or
  central, must carry exactly the raw name bytes, and both extra
  fields must be well formed. `zipfile` names an entry by the
  central field while other extractors use the raw name or the
  local field, so the name checks would otherwise see a benign
  alias of a traversal or executable name.
- Entries with a data descriptor are accepted only when a
  streaming reader can find the descriptor unambiguously: a
  deflated entry is inflated in `chunk_size` chunks and its
  stream must end exactly at the declared compressed size, and
  a stored entry must be empty with a signed descriptor right
  after its header. Other descriptor entries are rejected. The
  descriptor values must equal the central directory's, in
  8-byte sizes when the local header has a ZIP64 extra field and
  in 4-byte sizes otherwise (APPNOTE 4.3.9.2), so every reader
  parses the descriptor the same way.
- This check runs after the size and ratio limits, so inflation
  is bounded by them, and it raises `ZIP_INVALID_STRUCTURE`.
- With `allow_nested_archives=True`, nested archives get the
  same layout check as the top level.

---

## Content Threats (ZIP Entries)

### Path Traversal in ZIP Entry Names (CWE-22)

**Attack:** ZIP entry filenames like `../../etc/passwd` write
outside the extraction directory (Zip Slip).

**Mitigations:**

- `ZipContentInspector._inspect_zip_entry()` checks for
  traversal patterns and absolute paths. A `ZipContentError`
  carries the `error_code` of the first threat found, in entry
  order and then structure checks: `ZIP_DIRECTORY_TRAVERSAL`,
  `ZIP_ABSOLUTE_PATH`, `ZIP_SYMLINK_DETECTED`,
  `ZIP_NESTED_ARCHIVE`, otherwise `ZIP_CONTENT_THREAT`. Its
  `threats` attribute lists every message, and an inner archive
  keeps the code of its own threat.
- Null bytes are rejected first, checked on the raw entry name
  (`ZipInfo.orig_filename`), to prevent C-string truncation
  bypasses (CWE-158). Python's `zipfile` truncates `filename`
  at the first NUL, so the raw name is needed.

### Spoofed or Blocked Entry Names (CWE-184, CWE-434)

**Attack:** A file refused as a standalone upload (a
macro-enabled Office document, an `.hta`, a name with a
right-to-left override, `CON.txt`) is wrapped in a ZIP so that a
host extracting or listing the entries stores it anyway.

**Mitigations:**

- Every entry name gets the filename checks a top-level upload
  gets, driven by the same `FileSecurityConfig` fields, so a
  configuration that extends a list covers entries too:
  - the whole name is checked against `DANGEROUS_UNICODE_CHARS`
    and the rejected Unicode categories, and its NFKC form must
    not introduce a path separator or `..`;
  - every path component is checked against
    `WINDOWS_RESERVED_NAMES`;
  - a file's base name is checked against `BLOCKED_EXTENSIONS`
    (every extension in the name) and
    `COMPOUND_BLOCKED_EXTENSIONS`.
- The reserved-name and extension checks run on the NFC name and
  its NFKC form, after stripping trailing dots and spaces that
  Windows drops on extraction.
- A failing name is reported as `ZIP_CONTENT_THREAT`; the message
  shows the name with control and bidi characters escaped.

### Executable Content in ZIP

**Attack:** Executables, scripts, system files, or shortcuts
hidden inside ZIP archives.

**Mitigations:**

- Besides `BLOCKED_EXTENSIONS` (see above), the entry's final
  extension, after stripping trailing dots and spaces, is checked
  against `ZipThreatCategory.EXECUTABLE_FILES`, `SCRIPT_FILES`,
  and `SYSTEM_FILES`, which also cover configuration files such
  as `.ini`, `.cfg` and `.conf`.
- Binary content is scanned for executable magic bytes from
  `SuspiciousFilePattern.EXECUTABLE_SIGNATURES`. The first 512
  bytes of each entry are read for this scan.
- Text content is scanned for script injection patterns from
  `SuspiciousFilePattern.SCRIPT_PATTERNS` (shebangs, `eval()`,
  `<?php`, `<script`, `<%`) in the first 512 bytes of each
  entry. Unlike content analysis, this scan still counts a bare
  `<%`.
- An entry that starts with the gzip magic (`\x1f\x8b`) is
  decided by content, not name: its first 512 decompressed bytes
  are checked for executable signatures and script patterns, so
  compressed bytes cannot match a pattern by chance. The script
  scan is skipped when the name without `.gz` has a binary
  extension (`x.fit.gz`). An entry with the gzip magic that is
  not a readable gzip stream, or whose content is itself gzip,
  is rejected as uninspectable. Only this start is decompressed,
  so the expansion of the whole stream is not checked here.
- An entry whose content cannot be opened or read (encrypted,
  unsupported compression method, local header name differing
  from the central directory, or a CRC mismatch seen during
  the read) is rejected with `ZIP_CONTENT_THREAT`, because its
  content cannot be inspected.
- A CRC mismatch is seen by this read only when the read
  reaches the end of the entry's data, which is the case for
  small entries. For larger entries it is caught only with
  `verify_zip_decompression=True`.

### Symbolic Links in ZIP (CWE-59)

**Attack:** Symlinks inside ZIP archives can point to
arbitrary system files when extracted.

**Mitigations:**

- Symlink entries are detected and rejected when
  `allow_symlinks=False` (default). An entry is a symlink when
  the file-type bits of its Unix mode equal `S_IFLNK`
  (`stat.S_ISLNK`), so other modes that share some of those
  bits are not mistaken for symlinks.

---

## File Content Attacks

### MIME Type Mismatch (CWE-434)

**Attack:** A file with a `.jpg` extension but containing
executable content, relying on the server trusting the
extension.

**Mitigations:**

- `python-magic` detects the actual MIME type from file content
  (first 8 KB).
- Detection never falls back to the filename extension. If the
  libmagic detector cannot be initialized, `FileValidator` still
  constructs, logs an error and rejects every upload with
  `MimeTypeError` (`MIME_DETECTION_FAILED`). A libmagic failure
  or an empty result for a file is rejected the same way. If the
  libmagic library itself is missing, `python-magic` raises
  `ImportError` when `safeuploads` is imported, so nothing is
  validated.
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
  Java class headers, RAR headers. A Java class magic counts
  only with a valid class-file version. The search starts at the
  first byte: no allowed image or activity signature begins with
  one of these, so a ZIP right after the 3-byte JPEG header is
  found.
- Content analysis covers image and activity (GPX, TCX, FIT)
  uploads. ZIP uploads are not byte-scanned as a whole, because
  compressed bytes match signatures by chance; the ZIP inspector
  scans the decompressed entries instead.

### Embedded Malware Signatures

**Attack:** Executable headers (PE, ELF, Mach-O, Java class,
Windows shortcuts) embedded within uploaded files.

**Mitigations:**

- `ContentSecurityInspector` scans file content for byte
  signatures from `MalwareSignatureCategory`: PE/MZ headers,
  ELF headers, Mach-O headers (32/64-bit, both endiannesses,
  and universal binaries), Java class magic, and Windows
  shortcut headers.
- An executable signature counts only when the header structure
  verifies at that offset, because a bare 2-4 byte magic occurs
  by chance in random data. PE needs an `e_lfanew` of any size
  that points at `PE\0\0` inside the scanned sample; ELF needs
  a valid class, byte order and version; Mach-O needs a known
  CPU type and file type; a universal Mach-O needs a plausible
  architecture count and CPU type; a Java class needs a valid
  class-file version; a Windows shortcut needs the Shell Link
  CLSID.
- Web shell markers are `<?php`, `<script` and the ASP/JSP
  directive forms `<%@ page` and `<%@ language` (with or
  without the space). A bare `<%` is not a marker in content
  analysis. Patterns are matched on the raw bytes, lower-cased
  in ASCII, without decoding; memory use is about twice the
  scanned sample.

### XML External Entity Injection (CWE-611)

**Attack:** GPX and TCX files are XML-based; malicious DTD
declarations can trigger external entity resolution, leading
to server-side file reads or SSRF.

**Mitigations:**

- `XmlSecurityValidator` parses with `defusedxml`'s
  `DefusedXMLParser` and `forbid_dtd=True`, blocking all DTD declarations, external
  entities, and entity expansion attacks (billion laughs).
- Entities and external references can only be declared in a
  DTD, so any DOCTYPE raises `XmlSecurityError`, a
  `FileValidationError`, with `XML_DTD_FORBIDDEN`. Malformed
  input (`ParseError`, an undeclared entity or an unknown
  encoding declaration) raises it with `XML_MALFORMED`. Only
  unexpected internal failures raise `FileProcessingError`.
  `ResourceLimitError` is re-raised unchanged.
- The document is fed to the parser in `chunk_size` chunks with
  a target that builds no element tree, so memory does not grow
  with the document, and the resource limits are checked after
  each chunk.

### Malformed FIT Files

**Attack:** A file with a valid `.FIT` header that carries
extra data before, between or after its sections, or a corrupt
body, so that a consumer parses something other than what was
validated.

**Mitigations:**

- `FitSecurityValidator` requires a FIT upload to be one or
  more sections that cover the file exactly. Each section has a
  12 or 14 byte header with the `.FIT` signature, a header CRC
  (checked when non-zero), a non-zero data size that fits in the
  file, and the FIT CRC-16 over header and data. Anything else
  raises `FileSignatureError` with `FIT_INVALID_STRUCTURE`.
- The file is read in `chunk_size` chunks with resource limits
  checked after each. Record contents are not interpreted.
- With `enable_content_analysis=True`, GPX, TCX and FIT uploads
  also get content analysis.

---

## Resource Exhaustion

### Memory Exhaustion (CWE-400)

**Attack:** Uploading very large files or files that expand
significantly during validation consumes all available memory.

**Mitigations:**

- Streaming validation via `SpooledTemporaryFile` keeps memory
  usage under `max_memory_buffer_size` (default 10 MB) by
  spilling to disk for larger files.
- `ResourceMonitor` tracks the process peak RSS
  (`resource.getrusage()` `ru_maxrss`, a high-water mark) and
  enforces `max_validation_memory_mb` (default 512 MB) as the
  increase in process peak RSS since the monitor started. This
  is not an upper bound for validation memory: an earlier, higher
  process peak hides later allocations. Concurrent work in the
  same process can also trip the limit; on Windows memory
  accounting is disabled.
- The limit is checked at loop boundaries (upload streaming, ZIP
  entry loops, gzip decompression, each XML chunk) and on exit,
  and raises `ResourceLimitError` with
  `RESOURCE_MEMORY_EXCEEDED`. A single blocking call is not
  interrupted mid-call.
- File size is enforced progressively during chunked reads,
  not after loading the entire file.

### CPU Exhaustion (CWE-400)

**Attack:** Crafted files that trigger expensive validation
paths (e.g., ZIP with many entries, deeply nested structures).

**Mitigations:**

- `ResourceMonitor` enforces `max_validation_time_seconds`
  (default 30 s wall-clock, `time.monotonic()`) at the same loop
  boundaries and on exit, raising `ResourceLimitError` with
  `RESOURCE_TIME_EXCEEDED`. The monitor is held in a context
  variable, which worker threads inherit through the copied
  context. A single blocking call, such as one `zipfile`
  central-directory parse, is not interrupted mid-call.
- ZIP analysis has its own `zip_analysis_timeout` (default 5 s),
  compared against `time.monotonic()` on each entry during
  iteration.
- `max_zip_entries` (default 10,000) caps per-archive entry
  count. Before `zipfile` parses the archive, the
  central-directory headers are counted (located as `zipfile`
  locates them, reading only the fixed headers and building no
  `ZipInfo`) and the walk stops at `max_zip_entries + 1`, so an
  archive with too many entries is rejected with
  `ZIP_TOO_MANY_ENTRIES` at bounded cost, even if its end record
  under-reports the count. Malformed directories are left to
  `zipfile` (`ZIP_CORRUPT`), including names flagged as UTF-8
  that are not, extract versions above 6.3 and ZIP features
  `zipfile` does not support. The parsed count is checked again
  after parsing.

### Gzip Decompression Bombs

**Attack:** A small gzip file that decompresses to massive
size, similar to ZIP bombs.

**Mitigations:**

- `GzipContentInspector` decompresses gzip streams with `zlib`
  member by member, reading and producing at most `chunk_size`
  bytes per step, and checks the compression ratio and
  uncompressed size against `SecurityLimits` progressively.
- The active `ResourceMonitor` is checked on every step, so a
  stream of empty members or a long header field cannot run past
  `max_validation_time_seconds`. The same decompression samples
  gzip ZIP entries. Zero padding between and after members is
  accepted; other trailing data, reserved header flags and a
  mismatched header CRC are rejected with `ZIP_CORRUPT`.
- Exceeding either limit raises a validation error immediately,
  without reading the rest of the stream.
- Deflate data that `zlib` cannot decode is rejected with
  `CompressionSecurityError` (`ZIP_CORRUPT`).

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
  from a single validation call. A correlation ID the host has
  already set is reused, so host logs and audit records share
  it, and the previous value is restored after validation.
- The `filename`, `result` and `details` fields of an audit
  record are attacker-controlled, so `SecurityAuditLogger`
  escapes control, format (such as bidi overrides), surrogate,
  private-use, unassigned and line or paragraph separator
  characters with `repr()`-style escapes and caps each field at
  1,024 characters, marking a cut with `...[truncated]`. A
  newline in a filename therefore cannot forge a second log
  record. Other log messages that print a filename use `%r`.
- The correlation ID and source IP can come from the host's
  request, so audit records escape and cap them the same way,
  and `log_extra()` adds the escaped correlation ID to other
  records. The host still reads back the ID it set.
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
- Every `FileSecurityError` subclass has a default `ErrorCode`,
  so a host can always read `error_code` on the library's
  exceptions. `FileSecurityConfigurationError` is not one of
  them and exposes its `errors` instead.

