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
│   ├── compression_validator.py # ZIP bomb detection
│   └── xml_validator.py       # XXE-safe XML parsing
└── inspectors/
    ├── base.py                # BaseInspector interface
    ├── zip_inspector.py       # Deep ZIP content analysis
    ├── gzip_inspector.py      # Gzip bomb detection
    └── content_inspector.py   # Malware/polyglot scanning
```

### Roles

| Component | Responsibility |
|---|---|
| `FileValidator` | Orchestrates validation for each file type. Manages streaming, resource monitoring and audit events, and delegates to validators/inspectors. The async methods offload blocking inspection to a worker thread (or a configured `executor`); the `*_sync` methods run the same pipeline in the calling thread and refuse to run on an event-loop thread. Exposes them as `filename_validator`, `signature_validator`, `mime_validator` and the other validator attributes; `magic_mime` and `magic_available` are properties that delegate to `mime_validator`. |
| `FileSecurityConfig` | Centralizes all configuration: allowed MIME types mapped to the extensions each permits, blocked extensions, Unicode characters, and Windows reserved names. |
| `SecurityLimits` | Holds numeric thresholds: file sizes, compression ratios, timeouts, entry limits, resource caps. |
| `BaseValidator` | Abstract base class; validators inherit and implement `validate()`. |
| `UnicodeSecurityValidator` | NFC normalization and dangerous character detection (rejects with `UnicodeSecurityError`). |
| `ExtensionSecurityValidator` | Blocked, dangerous and compound extension checks. `validate_allowed` checks an extension against the allowlist and the blocked list. |
| `WindowsSecurityValidator` | Rejects Windows reserved device names. |
| `FilenameSecurityValidator` | Strips path components and dangerous characters from a filename and limits its length to `max_sanitized_name_length`. |
| `FileSignatureValidator` | Checks that the file header matches the signatures of the expected type (image: JPEG, PNG or WebP; ZIP, gzip, activity or FIT). |
| `MimeTypeValidator` | Detects the MIME type from content with libmagic (serialized by a lock, never falling back to the filename), enforces the allowed MIME types and requires the filename's extension to be one listed for the detected type. |
| `CompressionSecurityValidator` | Checks compression ratio, uncompressed size, entry count, and nested archive limits, and that the listed entries fill the file exactly. |
| `XmlSecurityValidator` | Parses XML with `defusedxml`, blocking DTDs and external entities (raises `XmlSecurityError`). |
| `FitSecurityValidator` | Checks the FIT container: headers, header CRC, data size, CRC-16 per section, and that the sections cover the file exactly. |
| `ZipContentInspector` | Iterates ZIP entries checking for traversal, executables, scripts, symlinks, and recursive structures, and runs the top-level Unicode, Windows reserved-name and blocked-extension checks on each entry name. With `allow_nested_archives`, inspects every inner ZIP like the top level. |
| `GzipContentInspector` | Streams gzip decompression, checking ratio and size progressively. |
| `ContentSecurityInspector` | Scans raw bytes for structurally verified executable headers, web shells, and polyglot patterns (image and activity uploads). |
| `ResourceMonitor` | Context manager enforcing wall-clock time and peak-RSS memory limits at loop boundaries and on exit. |
| `SecurityAuditLogger` | Emits structured audit events under `safeuploads.audit` with correlation IDs, escaping and length-capping attacker-controlled fields. |

---

## Validation Pipelines

The `validate_*_file_sync` methods run the identical steps listed below in the calling thread, without the worker-thread offload. Every method returns a `ValidationResult` with the sanitized filename and the detected MIME type.

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
│ 4. File Size Check          │
│    (chunked progressive)    │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 5. MIME Type Check          │
│    (python-magic, first 8KB)│
│    ├── Type allowed         │
│    └── Extension listed for │
│        the detected type    │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 6. File Signature Check     │
│    (magic bytes)            │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 7. Content Analysis         │
│    (if enabled)             │
│    ├── Executable signatures│
│    ├── Script injection     │
│    └── Polyglot detection   │
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
│ 4. File Size Check          │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 5. Stream to SpooledTempFile│
│    (memory < 10MB → disk)   │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 6. MIME + Signature Check   │
│    (extension listed for    │
│    the detected type)       │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 7. Compression Validation   │
│    ├── Ratio check          │
│    ├── Uncompressed size    │
│    ├── Entry count          │
│    ├── Nested archive check │
│    └── Exact file layout    │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 8. ZIP Content Inspection   │
│    ├── Entry name checks    │
│    │   ├── Null bytes       │
│    │   ├── Path traversal   │
│    │   ├── Absolute paths   │
│    │   ├── Symlinks         │
│    │   └── Top-level name   │
│    │       checks (Unicode, │
│    │       Windows names,   │
│    │       blocked exts)    │
│    ├── Dangerous entry types│
│    ├── Binary signatures    │
│    ├── Nested archive magic │
│    ├── Script patterns      │
│    ├── Gzip entry start     │
│    ├── Unreadable entries   │
│    └── Recursive inspection │
│        ├── Depth tracking   │
│        ├── Hash tracking    │
│        ├── Entry count cap  │
│        └── Each inner ZIP:  │
│            same checks as   │
│            top level (steps │
│            7 and 8), if     │
│            nested allowed   │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 9. ResourceMonitor END      │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 10. Audit: VALIDATION_SUCCESS│
└──────────────────────────────┘
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
│ 4. File Size Check           │
│    (max_activity_file_size)  │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 5. MIME + Signature Check    │
│    ├── FIT: binary signature │
│    │   (.FIT at bytes 8-11)  │
│    ├── GPX/TCX: XML header   │
│    │   (<?xml)               │
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
│    │   └── Entity expansion  │
│    │       block             │
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
│ 4. File Size Check           │
│    (max_gzip_size)           │
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

---

## Data Flow: Where File Content Is Read

| Stage | What is read | Buffer size |
|---|---|---|
| File size check | Chunked reads (`chunk_size`, 64 KB default) | Progressive, discarded after counting |
| Stream to temp | Chunked reads to `SpooledTemporaryFile` | In-memory up to `max_memory_buffer_size` (10 MB), then disk |
| MIME detection | First 8 KB via `python-magic` | 8 KB |
| Signature check | First 4-12 bytes depending on format | Minimal |
| Compression validation | ZIP central directory, local headers and data descriptors | Metadata; entries with a data descriptor are inflated in `chunk_size` chunks |
| ZIP content inspection | Per-entry read for binary/text scan | First 512 bytes per entry |
| Nested ZIP inspection | Each inner ZIP streamed to a spooled temp file | `chunk_size` at a time; one spooled file (up to `max_memory_buffer_size`) per nesting level |
| Gzip inspection | Chunked streaming decompression | `chunk_size` at a time |
| XML validation | Chunked feed to `defusedxml`'s parser, no element tree built | `chunk_size` at a time |
| FIT validation | Chunked CRC-16 over each section | `chunk_size` at a time |
| Content analysis | Byte scan of image and activity uploads (not ZIP) | Bounded by `content_scan_max_size` (50 MB); about twice the sample while matching |

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
    │   ├── CompressionSecurityError
    │   │   ├── ZipBombError
    │   │   └── ZipContentError
    │   ├── XmlSecurityError
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
| `FileSignatureError` | `FILE_SIGNATURE_MISMATCH` |
| `CompressionSecurityError` | `ZIP_INVALID_STRUCTURE` |
| `ZipBombError` | `ZIP_BOMB_DETECTED` |
| `ZipContentError` | `ZIP_CONTENT_THREAT` (the ZIP inspector passes the code of the first threat found) |
| `XmlSecurityError` | `XML_MALFORMED` |
| `ContentThreatError` | `CONTENT_THREAT_DETECTED` |
| `ResourceLimitError` | `RESOURCE_LIMIT_EXCEEDED` |

`FileProcessingError` covers internal errors and its subclass
`ResourceLimitError` only; validation failures, including XML
and content threats, are `FileValidationError` subclasses.

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
  │   ├── CompressionSecurityValidator ► audit.threat()
  │   └── ContentSecurityInspector ► audit.threat()
  │
  ├── On success: audit.success()   # VALIDATION_SUCCESS
  ├── On failure: audit.failure()   # VALIDATION_FAILURE
  ├── On resource limit: audit.resource_limit()   # RESOURCE_LIMIT
  │
  └── restore the previous correlation ID
```

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
