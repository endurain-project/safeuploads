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
- The base name is shortened to `max_sanitized_name_length`
  UTF-8 bytes, cut between characters, the unit filesystem name
  limits use; configuration validation requires the limit plus
  the longest allowed extension to fit in 255 bytes
  (`invalid_name_length`). The extension and Windows
  reserved-name checks run again on the final name, so
  truncation cannot expose a blocked extension or reserved name.

### Unicode Obfuscation (CWE-116)

**Attack:** Right-to-left override characters (U+202E) and
zero-width joiners can disguise file extensions so that
`report.pdf` visually appears safe while the real extension
is `.exe`.

**Mitigations:**

- All filenames are NFC-normalized before validation.
- Characters in `UnicodeAttackCategory` (directional overrides,
  zero-width characters, confusing punctuation) are detected
  and rejected. The zero-width set also holds letters and symbols
  that render as blank space but are not format characters: the
  Hangul fillers (U+115F, U+1160, U+3164, U+FFA0) and the braille
  blank (U+2800).
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
  formats, archives, virtualization, container and disk images
  (`.iso`, `.img`, `.vhd`), Office documents and add-ins that can
  run code (macros, `.xll`, `.one`, Access `.ade` and `.mde`),
  system files and shortcuts (`.lnk`, `.appref-ms`,
  `.settingcontent-ms`), drivers, themes, and help files.
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
  attacker-controlled, so every entry's data must then hold
  exactly its declared sizes: a stored entry's `compress_size`
  must equal its `file_size`, and a deflated entry is inflated
  in `chunk_size` chunks, stopping once the output passes
  `file_size`, and must produce exactly `file_size` bytes from a
  stream that ends exactly at `compress_size`. Otherwise the
  archive is rejected with `ZIP_INVALID_STRUCTURE`, and deflate
  data `zlib` cannot decode with `ZIP_CORRUPT`. A forged small
  `file_size` therefore cannot hide expansion, or content such
  as executables and nested archives, from the checks, whether
  the consumer trusts the metadata or inflates the raw stream.
  This check runs on every archive, independent of
  `verify_zip_decompression` and `scan_zip_content`.
- Only stored and deflated entries are accepted. `zipfile`
  inflates other methods (bzip2, LZMA) without an output bound,
  so an entry using one is rejected with
  `ZIP_UNSUPPORTED_COMPRESSION` before any entry data is read.
- safeuploads does **not** extract archives. Consumers must
  extract safely and enforce their own size limits while
  extracting.
- Set `verify_zip_decompression=True` to make safeuploads also
  read every entry through `zipfile`, verifying its CRC-32; an
  entry whose CRC does not match, or that `zipfile` refuses to
  read (compressed patched data, strong encryption), is rejected
  as `ZIP_CORRUPT`. With `scan_zip_content` (default) the content
  scan already reads every entry to its end, so a CRC mismatch
  is seen there too. This is off by default because it reads the
  full archive again.

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
  `ZIP_NESTED_ARCHIVE`. `allow_nested_archives=True` permits
  only nested ZIP archives and gzip streams: every other archive
  extension (`.tar`, `.tgz`, `.tbz2`, `.bz2`, `.xz`, `.7z`,
  `.rar`) and every other archive signature (bzip2, xz, 7z, RAR,
  and the tar `ustar` magic at offset 257) is rejected with
  `ZIP_NESTED_ARCHIVE` regardless of the flag.
- Extensions are taken from the entry name after stripping
  trailing dots and spaces, as Windows drops them on
  extraction.
- When `scan_zip_content` is enabled (default) and nested
  archives are not allowed, the first bytes of each entry are
  checked against `ZipThreatCategory.NESTED_ARCHIVE_SIGNATURES`
  (ZIP and ZIP-based formats such as `.docx` and `.jar`, gzip,
  bzip2, xz, 7z and RAR), and the rest of the entry is read for
  an end-of-central-directory signature (`PK\x05\x06`) in its
  last 65,557 bytes, where `zipfile` and `unzip` look for an
  archive, so bytes prepended to a ZIP do not hide it. A renamed
  archive is rejected and reported under `ZIP_NESTED_ARCHIVE`.
  Tar has no leading signature; a USTAR or GNU tar is recognised
  by the `ustar` magic at offset 257 of its first header, within
  the 512-byte sample, under any name and with nesting allowed
  or not. A pre-POSIX tar carries no magic and is recognised by
  extension only.
- When allowed, `ZipContentInspector.inspect_nested_archives()`
  streams every file entry in `chunk_size` chunks into a spooled
  temporary file and inspects every inner ZIP, found by a
  recursable archive extension, a ZIP signature or an end record
  signature in its last 65,557 bytes. The inner archive gets the
  same checks as the top level: the entry count, exact layout,
  size and ratio checks of `CompressionSecurityValidator` and
  the entry and structure checks of `ZipContentInspector`, plus
  the depth, count and ancestor hash checks above. An inner ZIP
  behind prepended bytes therefore fails the layout check
  (`ZIP_INVALID_STRUCTURE`).
- With nesting allowed, an entry that starts with the gzip magic
  (`\x1f\x8b`), under any name, is inflated by
  `GzipContentInspector` in `chunk_size` steps under
  `max_uncompressed_size` and `max_compression_ratio` (relative
  to the entry's size), like a top-level gzip upload, into a
  spooled temporary file. Concatenated members and zero padding
  are accepted; trailing data, a bad CRC-32 or size and a
  truncated stream are rejected with `ZIP_CORRUPT`. The content
  counts as one entry toward `max_total_entries_recursive`, is
  scanned like an entry's content (the script scan is skipped
  when the name without `.gz` has a binary extension, as in
  `x.fit.gz`), and a ZIP or gzip stream inside it is inspected
  one level deeper under `max_zip_depth`. Gzip levels are bounded
  by depth; the ancestor hash check applies to ZIP levels.
- An inner archive or entry that is larger than
  `max_individual_file_size` (`FILE_TOO_LARGE`), cannot be read,
  is corrupt (`ZIP_CORRUPT`) or cannot be inspected is rejected,
  not skipped. Threats name the nesting path (entry names joined
  by `/`), and a nested ratio bomb raises `ZipBombError` with
  the path in its message.
- Nested archives need `scan_zip_content`: recursion and gzip
  inflation read entry contents, so a configuration with
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
stream that ends before its entry's declared compressed size or
inflates past its declared size. The validated archive then
passes while the extractor writes hidden files.

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
- Every entry's data must hold exactly its declared sizes (see
  the metadata trust boundary above): a deflated entry's stream
  must end exactly at its compressed size and inflate to exactly
  its uncompressed size, and a stored entry's two sizes must be
  equal.
- Entries with a data descriptor are accepted only when a
  streaming reader can find the descriptor unambiguously: a
  deflated entry, whose stream ends where the descriptor starts,
  or an empty stored entry with a signed descriptor right after
  its header. Other descriptor entries are rejected. The
  descriptor values must equal the central directory's, in
  8-byte sizes when the local header has a ZIP64 extra field and
  in 4-byte sizes otherwise (APPNOTE 4.3.9.2), so every reader
  parses the descriptor the same way.
- This check applies to every entry and runs after the size and
  ratio limits, so inflation is bounded by them; it raises
  `ZIP_INVALID_STRUCTURE`, or `ZIP_CORRUPT` for deflate data
  `zlib` cannot decode.
- With `allow_nested_archives=True`, nested archives get the
  same layout check as the top level.

---

## Content Threats (ZIP Entries)

### Path Traversal in ZIP Entry Names (CWE-22)

**Attack:** ZIP entry filenames like `../../etc/passwd` write
outside the extraction directory (Zip Slip).

**Mitigations:**

- `ZipContentInspector._inspect_zip_entry()` checks for
  traversal patterns and absolute paths. Entry names and
  metadata are always checked; `scan_zip_content=False` only
  skips reading entry contents. A `ZipContentError`
  carries the `error_code` of the first threat found, in entry
  order and then structure checks: `ZIP_DIRECTORY_TRAVERSAL`,
  `ZIP_ABSOLUTE_PATH`, `ZIP_SYMLINK_DETECTED`,
  `ZIP_NESTED_ARCHIVE`, `ZIP_UNSUPPORTED_COMPRESSION`, otherwise
  `ZIP_CONTENT_THREAT`. Its `threats` attribute lists every
  message, and an inner archive keeps the code of its own threat.
- A path component made only of dots and spaces with two or more
  dots (`a/..`, `a/. ./x.txt`) is a traversal, because Windows
  drops trailing dots and spaces from a component. `./x.txt`,
  `a/.config/x` and `a/b..c.txt` are accepted.
- An entry name containing `:`, in its NFC or NFKC form (so a
  fullwidth colon U+FF1A too), is rejected with
  `ZIP_CONTENT_THREAT`: NTFS reads it as an alternate data stream
  (`run.exe::$DATA`) or device (`CON:`) separator. A drive
  letter (`C:x`) is reported as `ZIP_ABSOLUTE_PATH`, and with
  `allow_absolute_paths=True` it is still rejected, as
  `ZIP_CONTENT_THREAT`.
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
- An entry that starts with the gzip magic (`\x1f\x8b`) is not
  script-scanned as it is, since compressed bytes match a
  pattern only by chance. Without `allow_nested_archives` it is
  rejected as a nested archive (`ZIP_NESTED_ARCHIVE`); with it,
  the whole stream is inflated under the gzip limits and its
  content is scanned (see Nested Archive Detection).
- An entry compressed with a method other than stored or
  deflated is rejected with `ZIP_UNSUPPORTED_COMPRESSION` and
  never opened.
- An entry whose content cannot be opened or read (encrypted,
  local header name differing from the central directory, or a
  CRC mismatch seen during the read) is rejected with
  `ZIP_CONTENT_THREAT`, because its content cannot be inspected.
- With `scan_zip_content` the whole entry is read (for the end
  record search, or by the nested inspection), so a CRC mismatch
  is always seen.

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
- The filename's extension must be one the configuration lists
  for the detected MIME type (`ALLOWED_*_TYPES`), so a file that
  is a valid, allowed image under another image format's name
  (for example a WebP named `photo.jpg`) is rejected with
  `EXTENSION_MIME_MISMATCH`. Downstream tools that pick a decoder
  or a `Content-Type` from the extension never see a name that
  contradicts the content.
- File signatures (magic bytes) are verified independently of
  the MIME type. A WebP must carry `WEBP` at bytes 8-11 of its
  RIFF container, so WAV, AVI and other RIFF files are not
  accepted as images. A HEIC must open with an `ftyp` box that
  names `heic` or `heix` (HEVC still images) as its major or a
  compatible brand, so AVIF, HEIF image sequences, MP4 and other
  ISO media are not accepted as HEIC.

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
- Content analysis covers image, activity (GPX, TCX, FIT) and
  PDF uploads; the polyglot signatures are checked for image and
  activity uploads only. A PDF is rejected outright when its
  header is not at offset 0 or data follows its final `%%EOF`
  (see PDF Parser Differentials). ZIP uploads are not byte-scanned as a whole, because
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
- A GPX or TCX upload must open with an XML declaration
  (`<?xml` followed by a space, tab, CR or LF), after an optional
  UTF-8 BOM and whitespace; another processing instruction such
  as `<?xml-stylesheet ...?>` first is rejected with
  `FILE_SIGNATURE_MISMATCH`.
- The root element's local name must be `gpx` for `.gpx` and
  `TrainingCenterDatabase` for `.tcx`, case-sensitive and in any
  namespace, so another XML document (an XSLT stylesheet, XHTML)
  is not accepted under an activity extension. A mismatch, or an
  XML activity extension with no root element defined (such as
  `.xml` added to `ALLOWED_ACTIVITY_TYPES`), raises
  `XmlSecurityError` with `XML_ROOT_MISMATCH`. The content is not
  validated against the GPX or TCX schema.

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

### PDF Active Content

**Attack:** A PDF runs JavaScript when opened or when a page,
field or annotation is used, launches an application, carries
an attached executable, submits form data to a remote server,
or opens a remote document, all without any malformed bytes.

**Mitigations:**

- `PdfContentInspector` tokenizes the whole file, so names in
  objects that no cross-reference entry lists (older revisions,
  orphans) are checked as well. Every name outside strings,
  comments and stream data is decoded (`#xx` escapes, so
  `/J#61vaScript` is `/JavaScript`) and compared, case-sensitive
  as PDF names are, against `FileSecurityConfig.BLOCKED_PDF_NAMES`.
  A match raises `PdfSecurityError` with `PDF_ACTIVE_CONTENT`.
- Object streams (PDF 1.5+) hold objects inside compressed
  streams, where a byte scan cannot see them. Every stream typed
  `/ObjStm`, and every stream a compressed cross-reference entry
  names as its container, is decoded and its objects are parsed
  and checked the same way.
- The default `BLOCKED_PDF_NAMES` covers JavaScript (`/JS`,
  `/JavaScript`), `/Launch`, embedded files (`/EmbeddedFile`,
  `/EmbeddedFiles`, `/EF`, `/FileAttachment`), `/RichMedia`,
  XFA forms (`/XFA`), form submission and import
  (`/SubmitForm`, `/ImportData`) and remote or embedded
  documents (`/GoToR`, `/GoToE`). `/OpenAction` and `/AA` are not
  blocked on their own: they also name harmless actions, such as
  the `/OpenAction [page /Fit]` that LaTeX writes, while the
  dangerous actions they can start are blocked by name. `/URI`
  links and AcroForm fields without XFA are accepted.
- A stream whose dictionary has `/F`, `/FFilter` or
  `/FDecodeParms` reads its data from another file and is
  rejected with `PDF_ACTIVE_CONTENT`.
- The block-list is configurable; configuration validation
  rejects an empty list (`empty_blocked_pdf_names`) and entries
  that a decoded PDF name can never equal, such as one with a
  leading `/`, whitespace, a delimiter or `#`
  (`invalid_pdf_name`).

**Residual risk:**

- Bugs in a reader's font, image (JBIG2, JPX, CCITT) and colour
  decoders are triggered by rendering, which the library does
  not do; image codec data is not decoded.
- A `/URI` link can still point at a `file:` or UNC address,
  which some Windows readers follow, leaking NTLM credentials.
  Hosts that render or open PDFs for other users add `URI` to
  `BLOCKED_PDF_NAMES` or render in a sandbox.

### PDF Parser Differentials

**Attack:** A PDF that two readers interpret differently, so
that the validator sees a harmless document and the reader sees
active content: a cross-reference offset pointing into a string
or into stream data, a stream `/Length` that ends before the
data a search for `endstream` finds, an object stream offset
inside another object, a key repeated with another value, or
data after `%%EOF` that another format parses (PDF/ZIP and
PDF/HTML polyglots).

**Mitigations:**

- The header must be `%PDF-1.x` or `%PDF-2.x` at offset 0
  (readers accept it anywhere in the first 1,024 bytes), and the
  file must end with `startxref`, its offset and `%%EOF`, with
  only whitespace after it.
- Every in-use entry of every cross-reference section, from
  `startxref` through `/XRefStm` and `/Prev`, must point (after
  whitespace) at the start of an object the scan parsed, with the
  same object and generation number. A loop of sections, an entry
  at offset 0 and an xref table whose counts do not match its
  entries are rejected rather than repaired: repairing readers
  rebuild the table by scanning, and may find objects the
  validator did not parse.
- In a hybrid file the chain continues from the trailer's
  `/Prev`, so an `/XRefStm` stream dictionary with its own
  `/Prev` is rejected; the section it links would go unverified.
- The newest trailer's `/Root` must resolve, through the
  verified cross-reference (including object streams), to a
  catalog dictionary whose `/Pages` resolves to a dictionary.
- A stream's data ends at the first `endstream`, and `/Length`
  (resolved when indirect) must end it there, with only whitespace
  between, so readers that trust `/Length` and readers that search
  for `endstream` read the same bytes.
- Object stream offsets must increase, and each object is parsed
  on its own from its offset, exactly as a reader does; the bytes
  between the header and the first object must hold no token.
  Every compressed cross-reference entry must point at its object
  in its container.
- A key repeated with a different value in a stream dictionary,
  its `/DecodeParms` or a trailer is rejected; elsewhere it cannot
  change what the checks read, as every name is checked as a
  token. Repeated values are compared without recursion, so
  deeply nested values are compared like shallow ones.
- Malformed syntax (unterminated strings, arrays or dictionaries,
  invalid name escapes, unknown keywords, data between objects)
  is rejected with `PDF_INVALID_STRUCTURE` instead of being
  repaired. Broken files that readers repair silently are
  therefore rejected.

### Encrypted PDFs

**Attack:** An encrypted PDF hides its strings and stream data,
including object streams, from inspection; one with an empty
user password opens in readers without a prompt.

**Mitigations:**

- A `/Encrypt` name anywhere in the file is rejected with
  `PDF_ENCRYPTED`, including documents that only restrict
  permissions with an owner password.

---

## Resource Exhaustion

### Memory Exhaustion (CWE-400)

**Attack:** Uploading very large files or files that expand
significantly during validation consumes all available memory.

**Mitigations:**

- Streaming validation via `SpooledTemporaryFile` keeps memory
  usage under `max_memory_buffer_size` (default 10 MB) by
  spilling to disk for larger files.
- `ResourceMonitor` enforces `max_validation_memory_mb`
  (default 512 MB) as the growth of the process's current RSS
  since the monitor started, read from `/proc/self/statm` on
  Linux and mach `task_info` on macOS. RSS is process-wide, so
  concurrent validations and other work in the same process add
  to each other's growth, and memory the allocator kept after a
  free and later reuses is not counted as growth. Other Unix
  platforms use the peak RSS (`ru_maxrss`), where an earlier,
  higher peak hides later allocations; on Windows memory
  accounting is disabled. A failing memory reading fails the
  validation instead of skipping the check.
- The limit is checked at loop boundaries (upload streaming, ZIP
  entry loops, gzip decompression, each XML chunk, each PNG chunk
  and JPEG segment before the image data, each HEIC box and item
  entry, PDF tokenizing, inflation and predictor rows) and on
  exit, and raises `ResourceLimitError` with
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
  `max_validation_time_seconds`. The same decompression, through
  `iter_decompressed_chunks`, inflates gzip ZIP entries when
  nested archives are allowed. Zero padding between and after
  members is accepted; other trailing data, reserved header
  flags and a mismatched header CRC are rejected with
  `ZIP_CORRUPT`.
- Exceeding either limit raises a validation error immediately,
  without reading the rest of the stream.
- Deflate data that `zlib` cannot decode is rejected with
  `CompressionSecurityError` (`ZIP_CORRUPT`).

### PDF Stream Decompression Bombs (CWE-409)

**Attack:** A small PDF whose Flate streams, possibly chained
(`[/FlateDecode /FlateDecode]`), inflate to gigabytes when a
reader or thumbnailer renders it.

**Mitigations:**

- `PdfContentInspector` inflates every Flate stage of every
  stream, `chunk_size` bytes at a time, and counts the output of
  all streams together. More than `max_pdf_uncompressed_size`
  (default 200 MB), or more than `max_compression_ratio` times the
  file size, raises `PdfSecurityError` with `PDF_STREAM_BOMB`.
  Only object and cross-reference streams are kept in memory.
- ASCIIHex and ASCII85 stages are decoded so the Flate stages
  after them are measured. A stream with an LZW, RunLength, Crypt
  or unknown filter, or with an image codec before another filter,
  is rejected with `PDF_INVALID_STRUCTURE`; image codecs as the
  last filter are not decoded, so image pixel counts are not
  limited.
- The whole PDF is read into memory, bounded by `max_pdf_size`
  (default 50 MB), and the active `ResourceMonitor` is checked
  every 1,024 tokens, on every inflation step and every
  `chunk_size` bytes of each predictor row, so a very wide row
  cannot run past the time limit.

### Image Decompression Bombs (CWE-400)

**Attack:** A small image whose header declares a huge canvas,
such as a 50 KB PNG declaring 60,000 × 60,000 pixels or a WebP
canvas of 16,777,216 × 16,777,216, passes every byte-level
check and exhausts memory when the host decodes it, for example
to make a thumbnail. A 24-bit decode needs 3 bytes per pixel,
so 60,000 × 60,000 pixels is about 10 GB.

**Mitigations:**

- `ImageDimensionValidator` reads width and height from the
  image header without decoding pixel data, and rejects an
  image whose width × height exceeds `max_image_pixels` with
  `ImageDimensionError` (`IMAGE_DIMENSIONS_EXCEEDED`). The
  default, 89,478,485, is Pillow's `Image.MAX_IMAGE_PIXELS`,
  about 256 MB decoded at 24 bits per pixel. Configuration
  validation rejects a limit of 0 or less and warns above twice
  the default, where Pillow refuses to open an image.
- PNG: the first chunk must be IHDR with 13 bytes of data, and
  width and height must be 1 to 2³¹ − 1. Pillow keeps the last
  IHDR before the image data, so the chunks are walked by their
  lengths, skipping their data by seek, from IHDR to the first
  IDAT. A second IHDR, a chunk (including that IDAT) running past
  the end of the file, and IEND or end of file before an IDAT are
  rejected with `FileSignatureError` (`IMAGE_INVALID_STRUCTURE`).
- JPEG: the marker segments of an image are walked from the
  start of image to its first scan (SOS). Pillow keeps the last
  frame header, so exactly one frame header (SOF0 to SOF15,
  except DHT, JPG and DAC) must precede the scan. Each segment's
  payload is skipped by its length, so a frame header behind
  large EXIF, XMP or ICC segments is still found. A second frame
  header, a DHP marker (hierarchical JPEG, which Pillow reads as
  a frame header), the JPG and JPG0 to JPG13 markers (0xC8,
  0xF0 to 0xFD, which Pillow reads without a length, so a
  length walk and Pillow could disagree on the next marker),
  other standalone markers, scan data or end of image before a
  frame header, a truncated or malformed segment, a segment
  length below 2, and a zero width or height (including a
  height deferred to a DNL segment) are rejected with
  `FileSignatureError` (`IMAGE_INVALID_STRUCTURE`).
- JPEG multi-picture (MPO): Pillow decodes every image an APP2
  `MPF` index lists when it lists more than one, at its data
  offset from the MPF header, ignoring the listed size. The index
  is parsed (TIFF byte order, one image count, 16-byte entries,
  no repeated tag), and a second MPF segment is rejected, since
  Pillow keeps the last. The first entry must be the primary
  image at offset 0, and later offsets must increase strictly and
  lie inside the file. Each listed image must start with a start
  of image and pass the same walk before the next listed image
  (the last before end of file), and its frame size must fit
  `max_image_pixels`. MPF segments inside later images are
  ignored, as Pillow ignores them.
- WebP: the first chunk after the `WEBP` form type must be
  `VP8 ` (a key frame with a valid start code; the two
  upscaling bits of each dimension are ignored), `VP8L`
  (signature 0x2F, version 0) or `VP8X`, whose canvas size is
  checked. Any other first chunk is rejected with
  `IMAGE_INVALID_STRUCTURE`.
- HEIC: the top-level boxes are walked to the one `meta` box,
  whose `hdlr` must be `pict`. The primary item (`pitm`) must be
  an HEVC image (`hvc1`) or a grid, and its size is its one
  `ispe` property. Every `ispe` in the file is checked against
  the limit, so a thumbnail, alpha, depth or tile image cannot
  declare a larger size than the primary. A decoder can decode
  any image item, so every item must be an HEVC image (`hvc1`:
  the primary, tiles, thumbnails and auxiliary alpha, depth or
  gain-map images), a grid or an ISO 21496-1 tone map (`tmap`),
  each with an `ispe`, or Exif or XMP (`mime`) metadata; any
  other item type (overlays, identity derivations, other codecs)
  is rejected. For every grid, which a decoder sizes from its
  descriptor rather than its `ispe`, the descriptor is read from
  the location in `iloc` (in `idat` or at a file offset, at most
  12 bytes) and its output size must equal the `ispe`. The grid
  must reference (`dimg`) exactly rows × columns HEVC tiles of
  one size that cover the output, trimmed only at the right and
  bottom edges, so the tiles decoded add up to about the output
  size. A tone map must reference exactly two distinct inputs, a
  base image then a gain map, each an HEVC image or grid, and its
  `ispe` must equal the base image's, the size a decoder outputs.
  Missing, repeated, truncated or oversized boxes, unsupported box
  versions, protected (encrypted) items, a primary item that is
  not an HEVC image or grid, and data outside the file or `idat`
  are rejected with `IMAGE_INVALID_STRUCTURE`.
- The check runs after the signature check and before content
  analysis, on the upload streamed to a spooled temp file. The
  PNG walk checks the active `ResourceMonitor` on every chunk,
  and the JPEG walk on every segment of the primary image and of
  each MPF image; their cost grows with the number of chunks or
  segments before the image data, so a 20 MB JPEG made only of
  4-byte segments takes seconds, bounded by `max_image_size` and
  `max_validation_time_seconds`. Listed MPF images are walked
  only up to the next one, so the JPEG walk reads the file about
  twice at most. A run of 0xFF fill bytes is skipped
  `chunk_size` bytes at a time. The HEIC walk checks it on every
  box and every `ipma` and `iloc` entry; the `meta` box is read
  into memory whole, bounded by `max_image_size`.

**Decoding trust boundary:**

- safeuploads does **not** decode images. Only the dimension
  header is parsed: compressed pixel data, ancillary chunks and
  metadata are not validated, so a truncated or corrupt image
  body is accepted.
- Bugs in image decoders (for example CVE-2023-4863 in libwebp)
  are triggered by decoding. The library cannot detect them, and
  decoding inside the validator would expose the validating
  process to them.
- Images a JPEG's MPF index lists are checked; other data after
  a JPEG's end of image is not parsed. For APNG and animated WebP
  only the canvas is checked: the specifications require
  animation frames to fit it, but the number of frames is not
  limited.
- HEIC: the size an HEVC bitstream's own parameter sets declare
  is not read, so a coded image larger than its `ispe` is not
  detected; libheif's security limits bound it when decoding.
  HEIF image sequences are rejected rather than inspected.
- A host that decodes uploads should decode in an isolated
  worker process with a memory limit, keep the decoder's own
  pixel limit set (for example Pillow's `Image.MAX_IMAGE_PIXELS`)
  and store a re-encoded copy instead of the original bytes;
  re-encoding also drops metadata and data appended to the
  image. See the integration checklist.

---

## Audit & Observability

### Undetected Security Events (CWE-778)

**Attack:** Security-relevant events (validation failures,
threat detections) go unlogged, preventing incident response.

**Mitigations:**

- `SecurityAuditLogger` emits structured log records under the
  `safeuploads.audit` logger for every validation start,
  success, failure, and threat detection. A cancelled async
  validation ends with a failure record whose result is
  `cancelled`, and the cancellation is re-raised.
- Correlation IDs (via `contextvars`) link all log messages
  from a single validation call. A correlation ID the host has
  already set is reused, so host logs and audit records share
  it, and the previous value is restored after validation.
- A host sets each request's ID with `correlation_scope(cid)`,
  which restores the previous ID when its block exits, even on
  an exception. `set_correlation_id()` leaves the ID set for the
  rest of the context, so on a pooled thread it would label
  later requests' records. Both raise `TypeError` for an ID that
  is neither a `str` nor `None`.
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

