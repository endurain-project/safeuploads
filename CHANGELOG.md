# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-11-01

### Added

- `FitSecurityValidator` and `ErrorCode.FIT_INVALID_STRUCTURE`: `validate_activity_file` checks that a FIT upload is structurally valid (12 or 14 byte headers, header CRC when non-zero, data size, FIT CRC-16 per section, sections covering the file exactly).
- `XmlSecurityError` and `ContentThreatError` (both `FileValidationError` subclasses) with the codes `XML_DTD_FORBIDDEN`, `XML_MALFORMED`, `CONTENT_THREAT_DETECTED` and `VALIDATION_FAILED`.
- Every `FileSecurityError` subclass has a default `ErrorCode` when none is passed: `PROCESSING_ERROR` (`FileSecurityError`, `FileProcessingError`), `VALIDATION_FAILED` (`FileValidationError`), `FILENAME_INVALID`, `ZIP_INVALID_STRUCTURE` (`CompressionSecurityError`), `XML_MALFORMED`, `CONTENT_THREAT_DETECTED`, and the specific code of each other subclass. `FileSecurityConfigurationError` is not a `FileSecurityError` and carries its list of `errors` instead of a code.
- `safeuploads.__version__` (`0+unknown` when the package metadata is not installed); `UploadFileProtocol`, `XmlSecurityError`, `ContentThreatError` and `FitSecurityValidator` are exported from the package root.
- `XmlSecurityValidator.validate_xml_safety` and `validate` take a keyword-only `filename`; `FitSecurityValidator.validate` takes the same.
- `find_embedded_signature` takes an optional `start` offset.
- `FileSignatureValidator`, `MimeTypeValidator` and `FilenameSecurityValidator`, exported from `safeuploads` and `safeuploads.validators`, and `ExtensionSecurityValidator.validate_allowed`. `FileValidator` exposes them as `signature_validator`, `mime_validator` and `filename_validator`; `magic_mime` and `magic_available` are properties that delegate to `mime_validator`. Validation behaviour is unchanged.
- `SecurityAuditLogger.resource_limit`: resource-limit failures emit a `RESOURCE_LIMIT` audit event instead of `VALIDATION_FAILURE`.

### Security

- ZIP entries whose content cannot be opened or read (encrypted flag, unsupported compression method, CRC mismatch, local/central header name mismatch) are now rejected with `ZIP_CONTENT_THREAT`; they were accepted unscanned.
- Uploaded filenames truncated to `max_sanitized_name_length` are re-checked for blocked extensions, so a name such as `<96 chars>.phpXXXX.jpg` can no longer become `….php.jpg`.
- ZIP entries with an extension in `ZipThreatCategory.EXECUTABLE_FILES`, `SCRIPT_FILES` or `SYSTEM_FILES` are now rejected, as the threat model already documented.
- Nested archives are detected by magic bytes (`ZipThreatCategory.NESTED_ARCHIVE_SIGNATURES`) as well as by archive extension, so an entry whose content is a ZIP, such as a `.docx`, `.xlsx` or `.jar` file, is rejected unless `allow_nested_archives=True`. These extensions alone do not reject an entry.
- The null-byte check on ZIP entry names now inspects the raw name; it previously could never trigger.
- Directory entries that declare data are rejected with `ZIP_INVALID_STRUCTURE`.
- ZIP entries that start with the gzip magic are scanned by their first 512 decompressed bytes for executable signatures and script patterns. The compressed bytes were scanned before, which missed real content and rejected valid entries such as `.fit.gz` files from Strava exports when the compressed data happened to contain a pattern such as `<%`.
- Audit records escape control, format, surrogate, private-use, unassigned and line/paragraph separator characters in the filename, result, details, correlation ID and source IP fields, in the message and in `extra`, and cap each at 1,024 characters (`...[truncated]` marks a cut; only the characters that can reach the result are examined), so an attacker-controlled filename or a host-supplied request header cannot forge log lines. `log_extra()` adds the escaped correlation ID. `get_correlation_id()` still returns the ID the host set. Other log messages that print a filename use `%r`.
- MIME detection no longer falls back to the filename extension. A libmagic failure or empty result rejects the upload with `MIME_DETECTION_FAILED`.
- The image header is read from byte 0 regardless of where the host left the stream position.
- The `.tar.Z` compound extension is now matched (stored as `.tar.z`, since filenames are lowercased before matching); the old spelling could never match.
- `max_validation_time_seconds` and `max_validation_memory_mb` are enforced during the work, not only when validation ends: the upload streaming loops, the ZIP compression and inspection entry loops, the gzip decompression loop and each XML chunk check the active `ResourceMonitor`. A single blocking call, such as one `zipfile` central-directory parse, is not interrupted mid-call.
- `ResourceLimitError` propagates from the inspectors and validators with its own `RESOURCE_TIME_EXCEEDED` or `RESOURCE_MEMORY_EXCEEDED` code; it was wrapped into a generic internal-error `FileProcessingError`.
- The ZIP entry count is bounded before `zipfile` parses the archive: the central-directory headers are counted, stopping at `max_zip_entries + 1`, so an archive with too many entries is rejected with `ZIP_TOO_MANY_ENTRIES` at bounded cost even if its end record under-reports the count.
- GPX and TCX files are parsed in `chunk_size` chunks with a target that builds no element tree, so memory does not grow with the document. The DTD, entity and external-reference protections are unchanged.
- ZIP archives whose listed entries do not fill the file exactly are rejected with `ZIP_INVALID_STRUCTURE`, so an extractor that walks local headers cannot see entries that validation never saw. This covers fake end records or archives hidden in the comment, concatenated archives, unlisted entries, prepended or trailing bytes, local headers that disagree with the central directory, and data-descriptor entries whose end a streaming reader cannot find (a deflate stream must end exactly at the declared size; stored entries with a descriptor must be empty). For descriptor entries, each local CRC-32 and size must be zero or equal to the central directory's, and the descriptor must use the width the local header selects: 8-byte sizes with a ZIP64 extra field, 4-byte sizes otherwise (APPNOTE 4.3.9.2).
- With `allow_nested_archives=True`, every inner ZIP (found by a recursable extension or a ZIP signature) is streamed to a spooled temporary file in `chunk_size` chunks and gets the same checks as the top-level archive (entry count, layout, size and ratio, entry and structure checks). Inner archives larger than `max_individual_file_size` (`FILE_TOO_LARGE`), unreadable, corrupt (`ZIP_CORRUPT`) or uninspectable are rejected instead of skipped. Threats name the nesting path, and a nested ratio bomb raises `ZipBombError` with the path in the message. Memory is bounded by the nesting depth times `max_memory_buffer_size`.
- Executable signatures in content analysis count only when the header structure verifies (PE `e_lfanew` pointing at `PE\0\0`, ELF class/byte order/version, Mach-O CPU and file type, universal Mach-O, Java class version, Shell Link CLSID), so random data in images and activity files no longer matches by chance. Web shell markers are `<?php`, `<script` and the `<%@ page` / `<%@ language` forms; a bare `<%` no longer counts in content analysis (the ZIP inspector still matches it in entry content). Patterns are matched on bytes without decoding. `MalwareSignatureCategory.PE_EXECUTABLE` no longer holds `b"PE\x00\x00"` and `WEBSHELL_PATTERNS` no longer holds `b"<%"`.
- With `enable_content_analysis=True`, GPX, TCX and FIT uploads get content analysis; it was only applied to images and ZIP files.
- Filenames containing characters of the Unicode categories Cc, Cf, Co, Cn, Cs, Zl or Zp (NUL, DEL, C1 controls, soft hyphen, bidi marks, zero-width joiner and the like) are rejected instead of stripped. The reserved-name and extension checks also run on the NFKC form of the name, which is not returned; a name whose NFKC form hides a path separator or `..` is rejected with `FILENAME_INVALID`.
- Windows reserved names `com0`, `lpt0`, `conin$`, `conout$` and `clock$` are rejected, and reserved names are compared case-folded.
- Blocked extensions added to `DangerousExtensionCategory`: `.vbe`, `.wsc`, `.php7`, `.php8`, `.phar`, `.phps`, `.pht`, `.shtml`, `.shtm` and `.stm`.
- A correlation ID set by the host (`set_correlation_id`) is reused by validation and restored afterwards, instead of being replaced and cleared, including when the audit start event raises.
- Symlink entries in a ZIP are detected with the exact file-type bits (`stat.S_ISLNK`) instead of a bit mask that other modes also matched.
- With `allow_nested_archives=True`, identical sibling inner archives are accepted: quine detection compares an archive only with its ancestors. `inspect_nested_archives(seen_hashes=...)` takes the hashes of ancestor archives and does not modify the set. Fan-out stays bounded by `max_total_entries_recursive`, `max_zip_depth` and the analysis timeout.
- Image MIME detection and temp-file writes that spill to disk run in the worker thread, not on the event loop. Cancelling a validation closes its temp files after any running worker finishes and propagates `CancelledError`.
- Every Info-ZIP Unicode Path extra field (`0x7075`), in the central or the local header, must carry the entry's raw name bytes, and both extra fields must be well formed; otherwise the archive is rejected with `ZIP_INVALID_STRUCTURE`. `zipfile` replaced the entry name with the field's name while other extractors kept the raw one, so a name such as `../../evil.sh` or `evil.exe` passed every name check under a benign alias.
- Gzip data is decompressed with `zlib` member by member, reading and producing at most `chunk_size` bytes per step and checking the active `ResourceMonitor` on each step, for gzip uploads and for the 512-byte sample of gzip ZIP entries. A stream of empty members or a long header field ran inside one `gzip` read call, beyond `max_validation_time_seconds`.
- `FileValidator(config)` validates the instance's own MIME, extension, reserved-name and dangerous-Unicode sets, which the validators use; an instance override such as an empty `BLOCKED_EXTENSIONS` was never checked.
- With `enable_content_analysis=True`, a `content_scan_max_size` smaller than `max_image_size` or `max_activity_file_size` is a configuration error (`content_scan_window_too_small`). Content past the scan window was accepted without analysis.
- Content analysis searches for polyglot signatures from the first byte, so a ZIP, RAR or Java class right after the 3-byte JPEG header is detected; the search started at offset 8. A PE header is detected whatever its `e_lfanew`, as long as it points at `PE\0\0` in the scanned sample; offsets of 64 KiB or more were ignored. The polyglot threat message reads `found in content` instead of `found after header`.

### Changed

- **Breaking:** with `allow_nested_archives=True`, inner ZIP archives that were skipped (oversized, unreadable or corrupt) or inspected less strictly are now rejected, and that setting together with `scan_zip_content=False` fails at construction with `FileSecurityConfigurationError` (`nested_archives_require_scan`).
- **Breaking:** FIT uploads that are not structurally valid are rejected with `FIT_INVALID_STRUCTURE`.
- **Breaking:** filenames with control, format, private-use, unassigned, surrogate or line/paragraph separator characters are rejected, so names that were cleaned before (and emoji ZWJ sequences) now fail with `UnicodeSecurityError`; the reserved names and extensions listed under Security are also newly blocked.
- **Breaking:** forbidden or malformed XML raises `XmlSecurityError` (a `FileValidationError`) and content analysis findings raise `ContentThreatError`, instead of `FileProcessingError`. `FileProcessingError` is now raised only for internal errors and as `ResourceLimitError`; hosts that caught it for these cases must catch `FileValidationError`.
- **Breaking:** `ResourceLimitError` parameters after `message` are keyword-only.
- **Breaking:** ZIP uploads are no longer byte-scanned as a whole by content analysis; the ZIP inspector scans the decompressed entries.
- `FileSecurityConfigurationError` can be pickled.
- **Breaking:** the ZIP entry extension and nested-archive checks under Security reject uploads that 1.1.3 accepted under the default configuration, for example `.bin`, `.ini` or `.cfg` entries, and `.docx`, `.xlsx` or `.jar` entries whose content is a ZIP.
- **Breaking:** with `allow_nested_archives=True`, ZIP entries that start with the gzip magic but are not a readable gzip stream, or that contain a gzip stream inside the gzip stream, are rejected with `ZIP_CONTENT_THREAT`.
- **Breaking:** `FileValidator(config)` raises `FileSecurityConfigurationError` when `validate_instance()` reports any error-severity issue; it only logged them before. New error-severity checks: type checks on every `SecurityLimits` field, positive values for the size, buffer, chunk, memory, scan, timeout, filename/path length and entry-count limits, `max_zip_depth >= 0`, allow-lists for activity and gzip files checked like image and ZIP, uppercase extension entries, Windows reserved names that are not lowercase (they could never match), empty `WINDOWS_RESERVED_NAMES`, `COMPOUND_BLOCKED_EXTENSIONS` or `DANGEROUS_UNICODE_CHARS`, and, with `enable_content_analysis=True`, a `content_scan_max_size` smaller than `max_image_size` or `max_activity_file_size` (`content_scan_window_too_small`), which left content past the scan window unanalyzed. The sets are read from the instance, so an instance override such as an empty `BLOCKED_EXTENSIONS` is validated; only the class attributes were before. Warnings are still only logged.
- **Breaking:** ZIP archives with bytes outside their listed entries, such as trailing padding written by `bsdtar` to a pipe, or with non-empty stored entries that use a data descriptor, are rejected with `ZIP_INVALID_STRUCTURE`, as are archives whose Info-ZIP Unicode Path extra field spells a name other than the raw header name (such as a legacy code-page name with a UTF-8 alias), data-descriptor entries whose local CRC-32 or sizes are non-zero and differ from the central directory, and descriptors of the other size width than the local header selects.
- **Breaking:** uploads are rejected with `MIME_DETECTION_FAILED` when the libmagic detector fails to initialize or to detect. `FileValidator` still constructs, sets `magic_available=False` and logs an error. If the libmagic library itself is missing, `python-magic` raises `ImportError` on `import safeuploads`.
- **Breaking:** `ZipContentError.error_code` is the code of the first threat found (entry order, then structure): `ZIP_DIRECTORY_TRAVERSAL`, `ZIP_ABSOLUTE_PATH`, `ZIP_SYMLINK_DETECTED`, `ZIP_NESTED_ARCHIVE`, otherwise `ZIP_CONTENT_THREAT`. `threats` still lists all messages, and nested levels keep the inner code.
- **Breaking:** a corrupt ZIP in `ZipContentInspector.inspect_zip_content` raises `CompressionSecurityError` with `ZIP_CORRUPT` instead of `FileProcessingError` with `PROCESSING_ERROR`. Corrupt gzip deflate data (`zlib.error`) also raises `CompressionSecurityError` with `ZIP_CORRUPT`, and so does a ZIP that `zipfile` cannot parse because a UTF-8-flagged name or Unicode Path field is not UTF-8 or the extract version is above 6.3; these gave `PROCESSING_ERROR`.
- **Breaking:** the per-entry analysis timeout of `CompressionSecurityValidator` raises `ZipBombError` with `ZIP_ANALYSIS_TIMEOUT` instead of `ZIP_BOMB_DETECTED`.
- **Breaking:** image uploads with a disallowed MIME type are rejected with `MIME_TYPE_MISMATCH` instead of `MIME_TYPE_INVALID`, like the other upload types.
- **Breaking:** ZIP, gzip and activity uploads too small to carry a signature are rejected with `FILE_SIGNATURE_MISSING` instead of `FILE_SIGNATURE_MISMATCH`, as images already were.
- **Breaking:** gzip streams with reserved header flag bits set, or a header CRC (`FHCRC`) that does not match, are rejected with `ZIP_CORRUPT`; the `gzip` module ignored both.
- **Breaking:** with `verify_zip_decompression=True`, ZIP entries with an unsupported compression method, patched data or strong encryption are rejected with `ZIP_CORRUPT` instead of `PROCESSING_ERROR`.
- **Breaking:** the category enums (`DangerousExtensionCategory`, `CompoundExtensionCategory`, `UnicodeAttackCategory`, `SuspiciousFilePattern`, `BinaryFileCategory` and the other enums with set values) hold `frozenset` values. The `FileSecurityConfig` getters return mutable `set` copies.
- The `Allowed:` extension list in the extension error message is sorted.

### Fixed

- Valid GPX and TCX files that libmagic reports as `text/plain`, such as exports from OsmAnd~ with namespaced `<extensions>` elements, are no longer rejected with `MIME_TYPE_MISMATCH`: `text/plain` is in `ALLOWED_ACTIVITY_MIMES`. This widens a security allow-list: libmagic reports any text as `text/plain`, so for GPX and TCX uploads the MIME check no longer narrows the content, and the `<?xml` signature check and the XXE-safe XML parse decide. They still reject content that does not start with `<?xml` or is not well-formed XML, with `FILE_SIGNATURE_MISMATCH` or an `XmlSecurityError`. FIT uploads skip the MIME check, and the image, ZIP and gzip MIME sets are unchanged. A host that sets its own `ALLOWED_ACTIVITY_MIMES` keeps its set.

### Removed

- **Breaking:** the `ErrorCode` members `FILENAME_TOO_LONG`, `UNICODE_SECURITY`, `FILE_SIZE_UNKNOWN`, `FILE_SIGNATURE_INVALID`, `IO_ERROR` and `MEMORY_ERROR`, which the library never raised.
- **Breaking:** the unused `strict` parameter of `FileSecurityConfig.validate_configuration` and `validate_instance`. `validate_and_report` and `validate_and_report_instance` keep theirs.

## [1.1.3] - 2026-10-22

### Changed

- Development: the Astral `ty` type checker runs beside mypy as an advisory CI job (`Type check (ty, advisory)`); mypy remains the gate.
- `SeekableFile.read` and `seek` take positional-only parameters, so `BytesIO` and `SpooledTemporaryFile` satisfy the protocol under `ty`. No runtime change.
- `UploadFileProtocol.seek` may return `int | None`, so FastAPI/Starlette's `UploadFile` (whose `seek` returns `None`) satisfies the protocol under strict type checking. No runtime change.

## [1.1.2] - 2026-10-22

### Changed

- Updated all dependency groups to their latest versions.
- Updated uv to 0.13.5.
- Updated GitHub Actions to their latest releases, pinned by commit hash.

## [1.1.1] - 2026-08-19

### Changed

- Migrated CI/CD from Forgejo/Codeberg to GitHub Actions: lint & test, scheduled fuzz, docs deploy, PyPI publish, and Conventional Commits checks.
- Added Dependabot configuration, a `CODEOWNERS` file, and a scheduled dependency-vulnerability audit workflow (`pip-audit`).
- Updated all repository, documentation, and badge links from Codeberg to GitHub.

## [1.1.0] - 2026-07-20


### Added

- `verify_zip_decompression` option that decompresses every ZIP entry to reject archives with forged central-directory metadata.
- Custom `executor` parameter on `FileValidator` to offload blocking inspection to a bounded thread pool instead of the default `asyncio` pool.
- Instance-level configuration validation and isolation so a per-instance `limits` object never mutates the shared class defaults.
- New `SecurityLimits` size limits plus additional recursable-archive types and script patterns for deeper threat detection.
- `BaseInspector` base class sharing configuration and audit state across inspectors.
- PEP 561 `py.typed` marker so downstream projects consume the shipped type hints.
- Integration tests exercising a real Starlette `UploadFile` and an end-to-end FastAPI multipart request.

### Changed

- `ErrorCode` is now a `StrEnum`. This is backward compatible: members still compare and hash equal to their string values, so existing comparisons and JSON serialization are unaffected.
- Validation flow refactored around a single generic runner for consistent audit logging and error mapping.
- Thread safety hardened: access to the shared `python-magic` instance is locked, and blocking inspection is offloaded off the event loop.
- File-size validation now rejects uploads whose declared size already exceeds the limit and verifies the real byte count by streaming.
- **Potentially breaking:** the public allow-list constants (`ALLOWED_IMAGE_MIMES`, `ALLOWED_ZIP_MIMES`, `ALLOWED_IMAGE_EXTENSIONS`, `ALLOWED_ZIP_EXTENSIONS`) are now immutable `frozenset`s. Read-only use is unaffected; in-place mutation (e.g. `.add(...)`) is no longer supported, assign a new set instead.

### Fixed

- Corrected the filename-sanitization debug log so it reports the true original filename rather than the already-sanitized value.
- Documentation URLs updated to the new site.

## [1.0.1] - 2026-06-03

### Fixed

- `_stream_to_temp_file` now seeks the original `UploadFile` back to position 0 (#3).

### Changed

- Dependency version bumps.

## [1.0.0] - 2026-03-26

First stable, production-ready release. Every layer of the validation
pipeline was expanded, hardened, and documented since v0.1.2.

### Added

- **Activity & gzip validation:** `validate_activity_file` (GPX/TCX/FIT) and `validate_gzip_file` with decompression-bomb detection, plus `XmlSecurityValidator` using `defusedxml` to block XXE, DTD, and entity-expansion attacks in XML-based activity files.
- **Audit logging:** `SecurityAuditLogger`, `AuditEvent`, and `AuditEventType` with per-request correlation IDs, toggled by `enable_audit_logging`.
- **Content security inspector:** `ContentSecurityInspector` for malware-signature scanning, script/webshell marker detection, and polyglot detection, controlled by `enable_content_analysis` and `content_scan_max_size`.
- **Nested ZIP complexity checks:** recursive inspection with cumulative entry, depth, hash, and timing checks, archive-quine and ZIP-of-ZIPs detection, and a new `max_total_entries_recursive` limit.

### Changed

- **Security hardening:** streaming file-size enforcement via `chunk_size`, tightened ZIP inspection (null-byte filename detection, monotonic timers, 512-byte content scans, sanitized error messages), and a hardened MIME cache (256 → 64 entries, extension-only derivation).
- `defusedxml` added as a runtime dependency.
- FastAPI example now binds to `127.0.0.1` instead of `0.0.0.0`.
- **Performance:** pre-computed `frozenset` collections, cached lookup sets at initialization, and LRU-cached MIME guessing.

### Other

- Hypothesis fuzz tests and integration suites; GitHub Actions for lint/test, fuzzing, docs, and PyPI publish; Dependabot and `CODEOWNERS`; new security docs (threat model, architecture, integration checklist).

## [0.1.2] - 2025-10-31

### Fixed

- Added `BinaryFileCategory` to the exported enums in `safeuploads/__init__.py` so it is available for external use.

## [0.1.1] - 2025-10-31

### Added

- `max_number_files_same_type` in `SecurityLimits`; `ZipContentInspector` now uses this configurable limit instead of a hardcoded value when checking for excessive files of the same type in a ZIP archive.
- `BinaryFileCategory` enum categorizing binary file extensions (starting with fitness files such as `.fit`); `ZipContentInspector` skips script-content checks for these binary files.

## [0.1.0] - 2025-10-30

Initial release.

### Added

- **Filename security:** Unicode normalization, directory-traversal protection, Windows reserved-name blocking.
- **Extension validation:** configurable allow/block lists with dangerous-extension detection.
- **ZIP bomb protection:** compression-ratio limits, nested-archive inspection, size constraints.
- **MIME type verification:** magic-number validation for common file types.
- Framework-agnostic async validation, a rich exception hierarchy with machine-readable error codes, secure defaults, and full type hints.

[2.0.0]: https://github.com/endurain-project/safeuploads/compare/v1.1.3...v2.0.0
[1.1.3]: https://github.com/endurain-project/safeuploads/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/endurain-project/safeuploads/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/endurain-project/safeuploads/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/endurain-project/safeuploads/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/endurain-project/safeuploads/releases/tag/v1.0.1
[1.0.0]: https://github.com/endurain-project/safeuploads/releases/tag/v1.0.0
[0.1.2]: https://github.com/endurain-project/safeuploads/releases/tag/v0.1.2
[0.1.1]: https://github.com/endurain-project/safeuploads/releases/tag/v0.1.1
[0.1.0]: https://github.com/endurain-project/safeuploads/releases/tag/v0.1.0
