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
│   ├── windows_validator.py   # Windows reserved name checks
│   ├── compression_validator.py # ZIP bomb detection
│   └── xml_validator.py       # XXE-safe XML parsing
└── inspectors/
    ├── zip_inspector.py       # Deep ZIP content analysis
    ├── gzip_inspector.py      # Gzip bomb detection
    └── content_inspector.py   # Malware/polyglot scanning
```

### Roles

| Component | Responsibility |
|---|---|
| `FileValidator` | Orchestrates validation for each file type. Manages streaming, resource monitoring, audit events, and delegates to validators/inspectors. |
| `FileSecurityConfig` | Centralizes all configuration: allowed MIME types, extensions, blocked extensions, Unicode characters, and Windows reserved names. |
| `SecurityLimits` | Holds numeric thresholds: file sizes, compression ratios, timeouts, entry limits, resource caps. |
| `BaseValidator` | Abstract base class; validators inherit and implement `validate()`. |
| `UnicodeSecurityValidator` | NFC normalization, dangerous character detection, null byte rejection. |
| `ExtensionSecurityValidator` | Allowlist/blocklist enforcement, compound extension checks. |
| `WindowsSecurityValidator` | Rejects Windows reserved device names. |
| `CompressionSecurityValidator` | Checks compression ratio, uncompressed size, entry count, and nested archive limits. |
| `XmlSecurityValidator` | Parses XML with `defusedxml`, blocking DTDs and external entities. |
| `ZipContentInspector` | Iterates ZIP entries checking for traversal, executables, scripts, symlinks, and recursive structures. |
| `GzipContentInspector` | Streams gzip decompression, checking ratio and size progressively. |
| `ContentSecurityInspector` | Scans raw bytes for malware signatures, web shells, and polyglot patterns. |
| `ResourceMonitor` | Context manager enforcing wall-clock time and memory limits. |
| `SecurityAuditLogger` | Emits structured audit events under `safeuploads.audit` with correlation IDs. |

---

## Validation Pipelines

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
│    ├── Extension allowlist   │
│    ├── Extension blocklist   │
│    └── Windows reserved name │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 3. File Size Check          │
│    (chunked progressive)    │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 4. ResourceMonitor START    │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 5. MIME Type Detection      │
│    (python-magic, first 8KB)│
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
│ 3. File Size Check          │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 4. ResourceMonitor START    │
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
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 7. Compression Validation   │
│    ├── Ratio check          │
│    ├── Uncompressed size    │
│    ├── Entry count          │
│    └── Nested archive check │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 8. ZIP Content Inspection   │
│    ├── Entry name checks    │
│    │   ├── Null bytes       │
│    │   ├── Path traversal   │
│    │   ├── Absolute paths   │
│    │   └── Symlinks         │
│    ├── Extension checks     │
│    ├── Binary signatures    │
│    ├── Script patterns      │
│    └── Recursive inspection │
│        ├── Depth tracking   │
│        ├── Hash tracking    │
│        └── Entry count cap  │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 9. Content Analysis         │
│    (if enabled)             │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 10. ResourceMonitor END     │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ 11. Audit: VALIDATION_SUCCESS│
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
│ 3. File Size Check           │
│    (max_activity_file_size)  │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 4. ResourceMonitor START     │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 5. MIME + Signature Check    │
│    ├── FIT: binary signature │
│    │   (.FIT at bytes 8-11)  │
│    └── GPX/TCX: XML header   │
│        (<?xml)               │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 6. XML Security Validation   │
│    (GPX/TCX only)            │
│    ├── defusedxml parsing    │
│    ├── DTD forbidden         │
│    └── Entity expansion block│
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
│ 3. File Size Check           │
│    (max_gzip_size)           │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 4. ResourceMonitor START     │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 5. MIME + Signature Check    │
│    (gzip magic: \x1f\x8b)   │
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
| Compression validation | ZIP central directory (metadata only) | Metadata |
| ZIP content inspection | Per-entry read for binary/text scan | Per-entry, bounded by `max_individual_file_size` |
| Gzip inspection | Chunked streaming decompression | `chunk_size` at a time |
| XML validation | Full XML content parsed by `defusedxml` | Full file (bounded by `max_activity_file_size`) |
| Content analysis | Full file byte scan | Bounded by `content_scan_max_size` (50 MB) |

---

## Exception Hierarchy

```
Exception
└── FileSecurityError
    ├── FileValidationError
    │   ├── FilenameSecurityError
    │   ├── UnicodeSecurityError
    │   ├── ExtensionSecurityError
    │   ├── WindowsReservedNameError
    │   ├── FileSizeError
    │   ├── MimeTypeError
    │   └── FileSignatureError
    ├── FileProcessingError
    │   ├── CompressionSecurityError
    │   │   └── ZipBombError
    │   ├── ZipContentError
    │   └── ResourceLimitError
    └── FileSecurityConfigurationError
```

All exceptions carry an `error_code` from `ErrorCode` for
machine-readable classification.

---

## Audit Event Flow

```
FileValidator.validate_*()
  │
  ├── set_correlation_id()
  ├── audit.log(VALIDATION_START)
  │
  ├── [validation pipeline]
  │   │
  │   ├── ZipContentInspector ──► audit.log(THREAT_DETECTED)
  │   ├── GzipContentInspector ─► audit.log(THREAT_DETECTED)
  │   ├── CompressionValidator ─► audit.log(THREAT_DETECTED)
  │   └── ContentSecurityInspector ► audit.log(THREAT_DETECTED)
  │
  ├── On success: audit.log(VALIDATION_SUCCESS)
  ├── On failure: audit.log(VALIDATION_FAILURE)
  │
  └── reset_correlation_id()
```

All log records include the correlation ID in `extra` via
`log_extra()`, enabling full request-level tracing across
sub-components.
