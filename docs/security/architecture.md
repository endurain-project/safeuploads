# Architecture

This document describes the safeuploads validation pipeline,
component responsibilities, and data flow for each file type.

---

## Component Overview

```
safeuploads/
├── file_validator.py          # FileValidator — orchestrator
├── config.py                  # FileSecurityConfig, SecurityLimits
├── protocols.py               # SeekableFile, UploadFileProtocol
├── exceptions.py              # Exception hierarchy, ErrorCode
├── enums.py                   # Threat categories, patterns
├── audit.py                   # SecurityAuditLogger, correlation IDs
├── utils.py                   # ResourceMonitor
├── validators/
│   ├── base.py                # BaseValidator interface
│   ├── unicode_validator.py   # Unicode normalization & checks
│   ├── extension_validator.py # Extension allow/block rules
│   ├── filename_validator.py  # Path and length rules for filenames
│   ├── signature_validator.py # File header signature checks
│   ├── mime_validator.py      # Content MIME detection and enforcement
│   ├── windows_validator.py   # Windows reserved name checks
│   ├── fit_validator.py       # FIT container structure checks
│   ├── image_dimension_validator.py # Pixel count from image headers
│   ├── compression_validator.py # ZIP bomb detection
│   ├── entry_name_validator.py # Archive entry-name checks
│   └── xml_validator.py       # XXE-safe XML parsing
└── inspectors/
    ├── base.py                # BaseInspector interface
    ├── zip_inspector.py       # Deep ZIP content analysis
    ├── gzip_inspector.py      # Gzip bomb detection
    ├── pdf_inspector.py       # PDF structure, active content, stream bombs
    └── content_inspector.py   # Malware/polyglot scanning
```

### Roles

| Component | Responsibility |
|---|---|
| `FileValidator` | Orchestrates validation for each file type. Manages streaming, resource monitoring and audit events, and delegates to validators/inspectors. The async methods offload blocking inspection to a worker thread (or a configured `executor`, which must be a `ThreadPoolExecutor`; any other type raises `TypeError` at construction) and bound each `await file.read()` by the time left under `max_validation_time_seconds`; the `*_sync` methods run the same pipeline in the calling thread and refuse to run on an event-loop thread; they can check the time limit only between chunks. Exposes them as `filename_validator`, `signature_validator`, `mime_validator` and the other validator attributes; `magic_mime` and `magic_available` are properties that delegate to `mime_validator`. The configuration is re-validated at construction (warnings are logged only then) and at the start of every validation call, so an error-severity issue, such as a limit changed after construction, raises `FileSecurityConfigurationError` before any byte is read. |
| `FileSecurityConfig` | Centralizes all configuration: allowed MIME types mapped to the extensions each permits, blocked extensions, Unicode characters, Windows reserved names, and the PDF names (`BLOCKED_PDF_NAMES`) that reject a PDF. |
| `SecurityLimits` | Holds numeric thresholds: file sizes, compression ratios, timeouts, entry limits, resource caps. |
| `BaseValidator` | Abstract base class; validators inherit and implement `validate()`. |
| `UnicodeSecurityValidator` | NFC normalization and dangerous character detection (rejects with `UnicodeSecurityError`). |
| `ExtensionSecurityValidator` | Blocked, dangerous and compound extension checks. `validate_allowed` checks an extension against the allowlist and the blocked list. |
| `WindowsSecurityValidator` | Rejects Windows reserved device names. |
| `FilenameSecurityValidator` | Strips path components and dangerous characters from a filename and limits its base name (extension excluded) to `max_sanitized_name_length` UTF-8 bytes, cut between characters. |
| `FileSignatureValidator` | Checks that the file header matches the signatures of the expected type (image: JPEG, PNG, WebP, or HEIC: an ISOBMFF `ftyp` box naming the `heic` or `heix` brand; ZIP, gzip, activity, FIT, or PDF with `%PDF-` at offset 0). |
| `MimeTypeValidator` | Detects the MIME type from content with libmagic (serialized by a lock, never falling back to the filename), enforces the allowed MIME types and requires the filename's extension to be one listed for the detected type. |
| `CompressionSecurityValidator` | Checks compression method (stored or deflated only), that no entry is flagged as encrypted (`ZIP_ENCRYPTED_ENTRY`, from header metadata, also without `scan_zip_content`; an encryption flag that differs between the local and central header is `ZIP_INVALID_STRUCTURE`), compression ratio, uncompressed size, entry count, and nested archive limits, that the listed entries fill the file exactly, and that each entry's data holds exactly its declared sizes. It takes an entry's extension from the name as extractors write it (`effective_entry_name`), and `has_zip_end_record` tells whether `zipfile` would open a file as a ZIP archive. |
| `EntryNameValidator` | Internal (not exported); used by `ZipContentInspector` and `GzipContentInspector`. Checks a name stored in an archive, a ZIP entry name or a gzip member name (FNAME), for traversal, absolute paths, length limits, suspicious names, nested archive names, the top-level Unicode and Windows reserved-name checks and dangerous extensions. Empty and `.` components and the trailing dots and spaces of each component are dropped first, as extractors drop them, so `evil.exe/.` is checked as `evil.exe`. |
| `XmlSecurityValidator` | Parses XML with `defusedxml`, blocking DTDs and external entities, and requires the root element `gpx` for `.gpx` and `TrainingCenterDatabase` for `.tcx`, in any namespace (raises `XmlSecurityError`). |
| `FitSecurityValidator` | Checks the FIT container: headers, header CRC, data size, CRC-16 per section, and that the sections cover the file exactly. |
| `ImageDimensionValidator` | Reads width and height without decoding pixels and rejects an image whose pixel count exceeds `max_image_pixels` (raises `ImageDimensionError`): PNG from the IHDR chunk after walking the chunks to the first IDAT (a second IHDR is rejected); JPEG from the one frame header (SOF) before the first scan, and the same for every image a multi-picture (MPF) index lists; WebP from the first chunk (VP8, VP8L or VP8X canvas); HEIC from the primary item's `ispe` property. For HEIC, every `ispe` in the file is checked and every image item (HEVC image, grid or `tmap` tone map) must have one; every grid's descriptor and tiles must match its `ispe`, and a tone map must reference a base image and a gain map (HEVC images or grids) and have the base image's `ispe`. Any other HEIC item, except Exif and XMP (`mime`) metadata, is rejected, as is a top-level `moov` box (an image sequence). A missing, repeated or malformed dimension header or MPF index raises `FileSignatureError` with `IMAGE_INVALID_STRUCTURE`. |
| `ZipContentInspector` | Iterates ZIP entries checking for traversal, executables, scripts, symlinks, unsupported compression methods and recursive structures, and runs the top-level Unicode, Windows reserved-name and blocked-extension checks on each entry name through `EntryNameValidator`; a name stored without the UTF-8 flag whose raw bytes are valid UTF-8 also gets the Unicode checks on that decoding. Entry names are always checked; entry contents (signatures, end record, scripts) only with `scan_zip_content`. With `allow_nested_archives`, inspects every inner ZIP like the top level and inflates every gzip entry under the gzip limits, scanning its content; other nested archives are always rejected. `max_uncompressed_size` is cumulative across the whole nesting tree: each archive level's declared entry sizes plus each gzip stream's output count toward it (`ZIP_BOMB_DETECTED`). |
| `GzipContentInspector` | Streams gzip decompression, checking ratio and size progressively; `iter_decompressed_chunks` yields the checked output, which the ZIP inspector uses for nested gzip entries. Rejects a file `zipfile` would also open as a ZIP archive (a ZIP in FEXTRA or in a stored deflate block, `GZIP_ZIP_POLYGLOT`), and parses every member header (RFC 1952): the FNAME field (ISO-8859-1) gets the `EntryNameValidator` checks, and a malformed header or an FNAME over 65,535 bytes is `ZIP_CORRUPT`. |
| `PdfContentInspector` | Tokenizes the whole PDF and verifies the structure readers rely on (header, trailing `startxref` and `%%EOF`, every cross-reference entry, every stream `/Length`, every object stream offset, and a newest-trailer `/Root` that resolves to a catalog dictionary whose `/Pages` resolves to a dictionary), so no reader parses an object the scan did not see. Every cross-reference table and xref stream the scan finds must be reached from `startxref`, `/Prev` or `/XRefStm`; a section only another reader would start from, such as a hidden first-page table, is rejected. Number tokens are matched without backtracking, a cross-reference offset is resolved by binary search over the header positions the scan recorded, and the time and memory limits are checked inside the xref entry loops. Rejects encryption, names in `BLOCKED_PDF_NAMES` after `#xx` decoding (including inside object streams), external stream data, unsupported filters and Flate output past `max_pdf_uncompressed_size` or `max_compression_ratio` (raises `PdfSecurityError`). |
| `ContentSecurityInspector` | Scans raw bytes for structurally verified executable headers, web shells, and polyglot patterns (image, activity and PDF uploads; polyglot signatures for image and activity only). |
| `ResourceMonitor` | Context manager enforcing wall-clock time and memory limits at loop boundaries and on exit. Memory is the growth of the process's current RSS since entry (`/proc/self/statm` on Linux, mach `task_info` on macOS; peak RSS on other Unix platforms, none on Windows); RSS is process-wide, so concurrent validations add to each other. `remaining_seconds` is the time budget left, which the async methods use to bound each upload read. |
| `SecurityAuditLogger` | Emits structured audit events under `safeuploads.audit` with correlation IDs, escaping and length-capping attacker-controlled fields. |

---

## Validation Pipelines

The `validate_*_file_sync` methods run the identical steps listed below in the calling thread, without the worker-thread offload. Every method returns a `ValidationResult` with the sanitized filename and the detected MIME type; every step after filename validation uses that sanitized name. The async methods assign it to the upload's `filename` only after validation succeeds; a rejected upload keeps the client's name.

### Image Validation (`validate_image_file`)

```
UploadFile
  │
  ▼
┌─────────────────────────────┐
│ 1. Audit: VALIDATION_START  │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 2. Filename Validation      │
│    ├── Unicode normalization │
│    ├── Dangerous characters  │
│    ├── Windows reserved name │
│    ├── Extension blocklist   │
│    ├── Length limit, recheck │
│    └── Extension allowlist   │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 3. ResourceMonitor START    │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 4. Stream to SpooledTempFile│
│    (size checked per chunk; │
│    memory < 10MB → disk)    │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 5. File Signature Check     │
│    (magic bytes)            │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 6. MIME Type Check          │
│    (python-magic, first 8KB)│
│    ├── Type allowed         │
│    └── Extension listed for │
│        the detected type    │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 7. Dimension Check          │
│    (header only, no decode) │
│    ├── PNG IHDR (chunks to  │
│    │   first IDAT)          │
│    ├── JPEG frame header    │
│    │   per image (MPF)      │
│    ├── WebP VP8/VP8L/VP8X   │
│    ├── HEIC ispe, grid, tmap│
│    └── width × height ≤     │
│        max_image_pixels     │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 8. Content Analysis         │
│    (if enabled)             │
│    ├── Executable signatures│
│    ├── Script injection     │
│    └── Polyglot detection   │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 9. ResourceMonitor END      │
└─────────────┬───────────────┘
              │
              ▼
┌──────────────────────────────┐
│ 10. Audit: VALIDATION_SUCCESS│
└──────────────────────────────┘
```

### ZIP Validation (`validate_zip_file`)

```
UploadFile
  │
  ▼
┌─────────────────────────────┐
│ 1. Audit: VALIDATION_START  │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 2. Filename Validation      │
│    (same as image)          │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 3. ResourceMonitor START    │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 4. Stream to SpooledTempFile│
│    (size checked per chunk; │
│    memory < 10MB → disk)    │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 5. MIME + Signature Check   │
│    (extension listed for    │
│    the detected type)       │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 6. Compression Validation   │
│    ├── Compression method   │
│    ├── Encrypted entries    │
│    ├── Ratio check          │
│    ├── Uncompressed size    │
│    ├── Entry count          │
│    ├── Nested archive check │
│    ├── Exact file layout    │
│    └── Declared sizes match │
│        entry data           │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 7. ZIP Content Inspection   │
│    ├── Entry name checks    │
│    │   ├── Null bytes       │
│    │   ├── Path traversal   │
│    │   ├── Absolute paths   │
│    │   ├── Symlinks         │
│    │   ├── Colons, dot-only │
│    │   │   components       │
│    │   ├── Name as extracted│
│    │   │   (trailing dots,  │
│    │   │   spaces, '.')     │
│    │   └── Top-level name   │
│    │       checks (Unicode, │
│    │       Windows names,   │
│    │       blocked exts)    │
│    ├── Compression method   │
│    ├── Dangerous entry types│
│    ├── Binary signatures    │
│    ├── Nested archive magic │
│    │   and end record       │
│    ├── Script patterns      │
│    ├── Unreadable entries   │
│    └── Recursive inspection │
│        (if nested allowed)  │
│        ├── Depth tracking   │
│        ├── Hash tracking    │
│        ├── Entry count cap  │
│        ├── Cumulative size  │
│        │   cap              │
│        ├── Each inner ZIP:  │
│        │   same checks as   │
│        │   top level (steps │
│        │   6 and 7)         │
│        └── Each gzip entry: │
│            inflated under   │
│            gzip limits and  │
│            scanned          │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 8. ResourceMonitor END      │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 9. Audit: VALIDATION_SUCCESS│
└─────────────────────────────┘
```

### Activity File Validation (`validate_activity_file`)

```
UploadFile (.gpx, .tcx, .fit)
  │
  ▼
┌──────────────────────────────┐
│ 1. Audit: VALIDATION_START   │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 2. Filename Validation       │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 3. ResourceMonitor START     │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 4. Stream to SpooledTempFile │
│    (size checked per chunk   │
│    against                   │
│    max_activity_file_size)   │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 5. MIME + Signature Check    │
│    ├── FIT: binary signature │
│    │   (.FIT at bytes 8-11)  │
│    ├── GPX/TCX: XML          │
│    │   declaration (<?xml    │
│    │   + whitespace)         │
│    └── Extension listed for  │
│        the detected type     │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 6. Structure Validation      │
│    ├── GPX/TCX: XML security │
│    │   ├── defusedxml parse  │
│    │   ├── DTD forbidden     │
│    │   ├── Entity expansion  │
│    │   │   block             │
│    │   └── Root element      │
│    │       matches extension │
│    └── FIT: container check  │
│        ├── Header + CRCs     │
│        └── Sections cover    │
│            the file exactly  │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 7. Content Analysis          │
│    (if enabled)              │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 8. ResourceMonitor END       │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 9. Audit: VALIDATION_SUCCESS │
└──────────────────────────────┘
```

### Gzip Validation (`validate_gzip_file`)

```
UploadFile (.gz)
  │
  ▼
┌──────────────────────────────┐
│ 1. Audit: VALIDATION_START   │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 2. Filename Validation       │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 3. ResourceMonitor START     │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 4. Stream to SpooledTempFile │
│    (size checked per chunk   │
│    against max_gzip_size)    │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 5. MIME + Signature Check    │
│    (gzip magic: \x1f\x8b)   │
│    (extension listed for     │
│    the detected type)        │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 6. Gzip Content Inspection   │
│    ├── Chunked decompression │
│    ├── Progressive ratio chk │
│    └── Progressive size chk  │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 7. ResourceMonitor END       │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 8. Audit: VALIDATION_SUCCESS │
└──────────────────────────────┘
```

### PDF Validation (`validate_pdf_file`)

```
UploadFile (.pdf)
  │
  ▼
┌──────────────────────────────┐
│ 1. Audit: VALIDATION_START   │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 2. Filename Validation       │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 3. ResourceMonitor START     │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 4. Stream to SpooledTempFile │
│    (size checked per chunk   │
│    against max_pdf_size)     │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 5. MIME + Signature Check    │
│    (%PDF- at offset 0)       │
│    (extension listed for     │
│    the detected type)        │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 6. PDF Inspection            │
│    ├── Header version and    │
│    │   startxref + %%EOF end │
│    ├── Tokenize whole file   │
│    │   ├── Blocked names     │
│    │   │   (#xx decoded)     │
│    │   └── /Encrypt          │
│    ├── Cross-reference chain │
│    │   (table, stream, /Prev,│
│    │   /XRefStm): every entry│
│    │   at a parsed object; no│
│    │   /Prev in an /XRefStm  │
│    │   stream                │
│    ├── Object streams parsed │
│    │   and scanned           │
│    ├── /Root → catalog with  │
│    │   /Pages dictionary     │
│    ├── Stream /Length ends   │
│    │   at endstream          │
│    └── Flate output within   │
│        size and ratio limits │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 7. Content Analysis          │
│    (if enabled)              │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 8. ResourceMonitor END       │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 9. Audit: VALIDATION_SUCCESS │
└──────────────────────────────┘
```

---

## Data Flow: Where File Content Is Read

| Stage | What is read | Buffer size |
|---|---|---|
| Stream to temp (size check) | Chunked reads (`chunk_size`, 64 KB default) to `SpooledTemporaryFile`, counted against the type's size limit | In-memory up to `max_memory_buffer_size` (10 MB), then disk |
| MIME detection | First 8 KB via `python-magic` | 8 KB |
| Signature check | First 4-12 bytes depending on format | Minimal |
| Compression validation | ZIP central directory, local headers and data descriptors; the data of every deflated entry | Metadata; every deflated entry is inflated in `chunk_size` chunks, stopping once the output passes its declared size |
| ZIP content inspection | Per-entry read for binary/text scan; without `allow_nested_archives`, the rest of each entry for an end record signature | First 512 bytes per entry scanned; the rest read in `chunk_size` chunks, keeping the last 65,557 bytes |
| Nested ZIP inspection | Every file entry streamed to a spooled temp file | `chunk_size` at a time; one spooled file (up to `max_memory_buffer_size`) per nesting level |
| Nested gzip inspection | Each gzip entry inflated into a spooled temp file | `chunk_size` at a time; output bounded by `max_compression_ratio` per stream, and by `max_uncompressed_size` together with the declared entry sizes of every archive level in the nesting tree |
| Gzip inspection | The ZIP end record search (`has_zip_end_record`), then chunked streaming decompression; each member header is read field by field, keeping the FNAME (at most 65,535 bytes) | `chunk_size` at a time |
| XML validation | Chunked feed to `defusedxml`'s parser, no element tree built | `chunk_size` at a time |
| FIT validation | Chunked CRC-16 over each section | `chunk_size` at a time |
| PDF inspection | The whole file, tokenized outside stream data; Flate streams inflated, object and xref streams kept decoded to parse them; predictor rows undone `chunk_size` bytes at a time | Whole file (bounded by `max_pdf_size`); inflation `chunk_size` at a time, kept output bounded by `max_pdf_uncompressed_size` |
| Image dimension check | WebP: first 30 bytes. PNG: the length and type of each chunk up to the first IDAT, skipping chunk data by seek. JPEG: the marker and length of each segment up to the first scan, skipping payloads by seek (the first 4 bytes of each APP2 are read), then the MPF index and the same walk for each listed image, up to the next listed image. HEIC: the header of each top-level box, skipping payloads by seek, then the whole `meta` box and the grid descriptors | Minimal for PNG, JPEG and WebP; a run of 0xFF fill bytes is read `chunk_size` at a time; the MPF index at most 64 KB. HEIC: the `meta` box (bounded by `max_image_size`, a few KB in camera files) |
| Content analysis | Byte scan of image, activity and PDF uploads (not ZIP) | Bounded by `content_scan_max_size` (50 MB); about twice the sample while matching |

---

## Exception Hierarchy

```
Exception
├── FileSecurityConfigurationError
└── FileSecurityError
    ├── FileValidationError
    │   ├── FilenameSecurityError
    │   │   ├── UnicodeSecurityError
    │   │   ├── ExtensionSecurityError
    │   │   └── WindowsReservedNameError
    │   ├── FileSizeError
    │   ├── MimeTypeError
    │   ├── FileSignatureError
    │   ├── ImageDimensionError
    │   ├── CompressionSecurityError
    │   │   ├── ZipBombError
    │   │   └── ZipContentError
    │   ├── XmlSecurityError
    │   ├── PdfSecurityError
    │   └── ContentThreatError
    └── FileProcessingError
        └── ResourceLimitError
```

All `FileSecurityError` subclasses carry an `error_code` from
`ErrorCode` for machine-readable classification.
`FileSecurityConfigurationError` is separate and exposes its
`errors` list of `ConfigValidationIssue` records instead. When no code is passed, the default is:

| Exception | Default `ErrorCode` |
|---|---|
| `FileSecurityError`, `FileProcessingError` | `PROCESSING_ERROR` |
| `FileValidationError` | `VALIDATION_FAILED` |
| `FilenameSecurityError` | `FILENAME_INVALID` |
| `UnicodeSecurityError` | `UNICODE_DANGEROUS_CHARS` |
| `ExtensionSecurityError` | `EXTENSION_BLOCKED` |
| `WindowsReservedNameError` | `WINDOWS_RESERVED_NAME` |
| `FileSizeError` | `FILE_TOO_LARGE` |
| `MimeTypeError` | `MIME_TYPE_INVALID` (uploads whose detected MIME is not allowed are reported as `MIME_TYPE_MISMATCH`, and an extension not listed for the detected MIME as `EXTENSION_MIME_MISMATCH`) |
| `FileSignatureError` | `FILE_SIGNATURE_MISMATCH` (a missing or invalid FIT structure is reported as `FIT_INVALID_STRUCTURE`, and a missing or invalid image dimension header as `IMAGE_INVALID_STRUCTURE`) |
| `ImageDimensionError` | `IMAGE_DIMENSIONS_EXCEEDED` |
| `CompressionSecurityError` | `ZIP_INVALID_STRUCTURE` (an archive or deflate data `zipfile` or `zlib` cannot read is reported as `ZIP_CORRUPT`, and an entry neither stored nor deflated as `ZIP_UNSUPPORTED_COMPRESSION`, an encrypted entry as `ZIP_ENCRYPTED_ENTRY`, and a gzip file that is also a ZIP archive as `GZIP_ZIP_POLYGLOT`) |
| `ZipBombError` | `ZIP_BOMB_DETECTED` |
| `ZipContentError` | `ZIP_CONTENT_THREAT` (the ZIP inspector passes the code of the first threat found, such as `ZIP_UNSUPPORTED_COMPRESSION`, `ZIP_ENCRYPTED_ENTRY` or `ZIP_DIRECTORY_TRAVERSAL`; a gzip member name is checked the same way) |
| `XmlSecurityError` | `XML_MALFORMED` (a DTD is reported as `XML_DTD_FORBIDDEN`, and a root element that does not match the extension as `XML_ROOT_MISMATCH`) |
| `PdfSecurityError` | `PDF_INVALID_STRUCTURE` (an encrypted PDF is reported as `PDF_ENCRYPTED`, a blocked name or external stream data as `PDF_ACTIVE_CONTENT`, and Flate output over the limits as `PDF_STREAM_BOMB`) |
| `ContentThreatError` | `CONTENT_THREAT_DETECTED` |
| `ResourceLimitError` | `RESOURCE_LIMIT_EXCEEDED` |

`FileProcessingError` covers internal errors and its subclass
`ResourceLimitError` only; validation failures, including XML,
PDF and content threats, are `FileValidationError` subclasses.

---

## Audit Event Flow

```
FileValidator.validate_*()  (_validation_run)
  │
  ├── bind_correlation_id()    # reuses the host's ID, if set
  ├── audit.start()            # VALIDATION_START
  │
  ├── [validation pipeline]
  │   │
  │   ├── ZipContentInspector ──► audit.threat()
  │   ├── GzipContentInspector ─► audit.threat()
  │   ├── PdfContentInspector ──► audit.threat()
  │   ├── CompressionSecurityValidator ► audit.threat()
  │   └── ContentSecurityInspector ► audit.threat()
  │
  ├── On success: audit.success()   # VALIDATION_SUCCESS
  ├── On failure: audit.failure()   # VALIDATION_FAILURE
  ├── On resource limit: audit.resource_limit()   # RESOURCE_LIMIT
  ├── On cancellation: audit.failure()   # VALIDATION_FAILURE, result
  │                                      # "cancelled"; CancelledError
  │                                      # re-raised
  │
  └── restore the previous correlation ID
```

A host sets its own per-request ID with `correlation_scope(cid)`,
which restores the previous ID when its block exits;
`set_correlation_id()` leaves the ID set for the rest of the
context, which on a pooled thread includes later work. Both raise
`TypeError` for an ID that is neither a `str` nor `None`.

`start`, `success`, `failure`, `threat` and `resource_limit` are methods of
`SecurityAuditLogger`; each builds an `AuditEvent` and passes it
to `log_event`. Audit records carry the correlation ID as
`audit_correlation_id` in `extra`, together with the
`audit_event_type`, `audit_filename`, `audit_result`,
`audit_details`, `audit_duration_ms` and `audit_source_ip`
fields. Other log records from validators and inspectors add
`correlation_id` to `extra` through `log_extra()` where they call
it, enabling request-level tracing across those sub-components.

`log_event` escapes control, format, surrogate, private-use,
unassigned and line or paragraph separator characters in the
correlation ID, filename, result, details and source IP fields
with `repr()`-style escapes, and caps each field at 1,024
characters, marking a cut with `...[truncated]`. `log_extra()`
adds the escaped correlation ID.
