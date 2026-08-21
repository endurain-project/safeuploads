# Changelog

All notable changes to this project are documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-08-21

Major version because this release removes public symbols and changes
which uploads are accepted. Read the upgrade notes before bumping.

### Upgrade notes

1. **`max_validation_memory_mb` no longer fails a validation by
   default.** This is the only change that makes safeuploads accept
   something it previously rejected. If you relied on it, set
   `enforce_memory_limit=True` — and only in a process that validates
   one upload at a time. Configuration validation warns when the
   budget is customised but enforcement is off.
2. **More uploads are rejected than before.** Images whose dimensions
   cannot be read, arbitrary XML behind a `.gpx`/`.tcx` name, and ZIPs
   containing executable, script, or system-file entries all now fail.
   Re-run your own fixtures before deploying.
3. **The time budget aborts mid-flight.** Uploads that previously ran
   past `max_validation_time_seconds` and still completed now raise
   `ResourceLimitError`.
4. **Removed symbols raise `AttributeError`.** See *Removed* below;
   none of them could produce a meaningful result before.

### Added

- Image decompression bomb detection. PNG `IHDR` and JPEG
  start-of-frame headers are parsed and the declared pixel count is
  bounded by the new `max_image_pixels` limit (default 89,478,485,
  matching Pillow's `MAX_IMAGE_PIXELS`). Breaches raise the new
  `ImageSecurityError`.
- `ResourceMonitor.check()`, which enforces the configured budgets
  together, and the `enforce_memory_limit` flag that opts memory back
  into enforcement.
- Activity XML files must now declare the root element matching their
  extension: `.gpx` requires a `gpx` root, `.tcx` requires a
  `TrainingCenterDatabase` root. Namespaces are stripped before
  matching. Arbitrary XML (including an HTML or SVG payload) wearing a
  `.gpx` name is rejected with the new `XML_INVALID_ROOT` code.
- `max_xml_elements` limit (default 1,000,000). XML is now parsed
  incrementally and completed elements are discarded as they close, so
  a flat document with millions of elements can no longer amplify a
  bounded upload into an unbounded object graph.
- `gzip_analysis_timeout` limit (default 5 s) bounding gzip inflation
  independently of any caller-supplied `ResourceMonitor`. A breach
  raises `ZipBombError` with `ZIP_ANALYSIS_TIMEOUT`, matching the ZIP
  inspector's timeout.
- `safe_label()` utility, applied to every untrusted filename and ZIP
  entry name before it reaches a log record, audit event, or exception
  message.
- `temp_dir` limit controlling where uploads larger than
  `max_memory_buffer_size` spill to disk. Configuration validation
  reports `invalid_temp_dir` when the directory does not exist, rather
  than failing later at rollover time.
- `FileSecurityConfig` now accepts `limits` directly
  (`FileSecurityConfig(SecurityLimits(...))`). The object is copied, so
  it is never aliased or shared, and configuring an instance no longer
  requires mutating class state.
- `UploadFileProtocol` and `reset_correlation_id` are now exported from
  the top-level package. `UploadFileProtocol` is the interface a
  non-FastAPI framework adapter implements, so it belonged in the
  public API alongside `SeekableFile`.
- `set_source_ip()`, which attaches the client address to every audit
  event in the current context. `AuditEvent.source_ip` existed but was
  never populated.
- Release-verification instructions for consumers, covering PEP 740
  attestation checks with `pypi-attestations`.

### Changed

- **Breaking:** `max_validation_memory_mb` is no longer enforced by
  default. It samples the process-wide peak RSS, which never decreases
  and misattributes concurrent work, so it is near-inert after a
  process's first peak and fires mainly when it is wrong. Exceeding it
  is now logged as a warning; set `enforce_memory_limit=True` (or
  `ResourceMonitor(enforce_memory=True)`) to restore the previous
  behaviour, and only in a process that validates one upload at a
  time. The real memory bounds are the byte limits in
  `SecurityLimits`, which cap every buffer the library allocates.
- **Breaking:** the validation time budget is now enforced *during*
  validation instead of only on completion. `ResourceMonitor` is
  threaded through the streaming reads, the ZIP entry loop, recursive
  nested-archive inspection, strict decompression verification, and
  the gzip inflation loop, so a runaway upload is aborted while it
  runs. Uploads that previously completed after exceeding the budget
  now raise `ResourceLimitError` earlier.
- **Lowered the minimum supported Python from 3.13 to 3.11.**
  Supported and tested on 3.11, 3.12, 3.13 and 3.14.
- `ResourceLimitError` now propagates out of the ZIP and gzip
  inspectors instead of being wrapped as an internal
  `FileProcessingError`.
- A breached resource budget is now audited as `RESOURCE_LIMIT`
  instead of a generic `VALIDATION_FAILURE`. The integration checklist
  already told integrators to alert on this event type, but nothing
  emitted it.
- `FileProcessingError` accepts an optional `error_code`, and XML
  failures now carry `XML_MALFORMED`, `XML_FORBIDDEN_CONSTRUCT`,
  `XML_INVALID_ROOT`, or `XML_TOO_MANY_ELEMENTS`.
- `find_text_pattern()` scans raw bytes with a cached compiled pattern
  instead of decoding and lower-casing the whole buffer, removing two
  full-size copies of the content-analysis window (up to 50 MB each).
- Documentation and the FastAPI example no longer return `str(err)` to
  clients. Exception messages embed the client-supplied filename, so
  reflecting them hands attacker-controlled bytes back to the browser;
  the examples now log the detail and return `err.error_code`.

### Removed

- **Breaking:** the `validate()` alias on every validator, and the
  `BaseValidator` abstract method behind it. The abstraction was
  false: each validator takes different arguments, so the "uniform"
  interface could never be used polymorphically. Call the
  purpose-named method instead
  (`validate_unicode_security`, `validate_extensions`,
  `validate_windows_reserved_names`, `validate_zip_compression_ratio`,
  `validate_xml_safety`). `BaseValidator` remains as a plain base
  class, matching `BaseInspector`.
- **Breaking:** eight `ErrorCode` members that no code path could ever
  produce: `FILE_SIZE_UNKNOWN`, `MIME_DETECTION_FAILED`,
  `FILE_SIGNATURE_INVALID`, `ZIP_INVALID_STRUCTURE`,
  `ZIP_DIRECTORY_TRAVERSAL`, `ZIP_SYMLINK_DETECTED`,
  `ZIP_ABSOLUTE_PATH`, and `MEMORY_ERROR`.
- **Breaking:** three unused `ZipThreatCategory` members that held
  marker strings rather than extensions: `RECURSIVE_STRUCTURE`,
  `QUINE_ARCHIVE`, and `COMPLEXITY_ATTACK`. The corresponding
  `ErrorCode` values are unaffected and still raised.
- A redundant entry-count check in `CompressionSecurityValidator` that
  applied `max_total_entries_recursive` to a single flat archive. That
  limit counts entries across nesting levels and is enforced in
  `ZipContentInspector`; a flat archive is capped by
  `max_zip_entries`.

### Fixed

- **Log injection (CWE-117):** a filename containing a newline could
  forge an audit log line, and directional or zero-width characters
  could hide the real name from an analyst. Untrusted text is now
  escaped at every logging site and again at the audit emission point.
  Unicode validation errors report the offending code point and its
  Unicode name instead of echoing the character.
- ZIP entries are now rejected when their name carries an extension
  from `ZipThreatCategory.EXECUTABLE_FILES`, `SCRIPT_FILES`, or
  `SYSTEM_FILES`. Every dot-separated suffix is checked, so a
  disguised name such as `invoice.php.txt` is caught. The threat model
  documented this mitigation but it was never implemented.

## [1.1.1] - 2026-08-19

### Changed

- Migrated CI/CD from Forgejo/Codeberg to GitHub Actions: lint & test,
  scheduled fuzz, docs deploy, PyPI publish, and Conventional Commits
  checks.
- Added Dependabot configuration, a `CODEOWNERS` file, and a
  scheduled dependency-vulnerability audit workflow (`pip-audit`).
- Updated all repository, documentation, and badge links from
  Codeberg to GitHub.

## [1.1.0] - 2026-07-20


### Added

- `verify_zip_decompression` option that decompresses every ZIP entry
  to reject archives with forged central-directory metadata.
- Custom `executor` parameter on `FileValidator` to offload blocking
  inspection to a bounded thread pool instead of the default
  `asyncio` pool.
- Instance-level configuration validation and isolation so a
  per-instance `limits` object never mutates the shared class
  defaults.
- New `SecurityLimits` size limits plus additional recursable-archive
  types and script patterns for deeper threat detection.
- `BaseInspector` base class sharing configuration and audit state
  across inspectors.
- PEP 561 `py.typed` marker so downstream projects consume the shipped
  type hints.
- Integration tests exercising a real Starlette `UploadFile` and an
  end-to-end FastAPI multipart request.

### Changed

- `ErrorCode` is now a `StrEnum`. This is backward compatible: members
  still compare and hash equal to their string values, so existing
  comparisons and JSON serialization are unaffected.
- Validation flow refactored around a single generic runner for
  consistent audit logging and error mapping.
- Thread safety hardened: access to the shared `python-magic` instance
  is locked, and blocking inspection is offloaded off the event loop.
- File-size validation now rejects uploads whose declared size already
  exceeds the limit and verifies the real byte count by streaming.
- **Potentially breaking:** the public allow-list constants
  (`ALLOWED_IMAGE_MIMES`, `ALLOWED_ZIP_MIMES`,
  `ALLOWED_IMAGE_EXTENSIONS`, `ALLOWED_ZIP_EXTENSIONS`) are now
  immutable `frozenset`s. Read-only use is unaffected; in-place
  mutation (e.g. `.add(...)`) is no longer supported, assign a new
  set instead.

### Fixed

- Corrected the filename-sanitization debug log so it reports the true
  original filename rather than the already-sanitized value.
- Documentation URLs updated to the new site.

## [1.0.1] - 2026-06-03

### Fixed

- `_stream_to_temp_file` now seeks the original `UploadFile` back to
  position 0 (#3).

### Changed

- Dependency version bumps.

## [1.0.0] - 2026-03-26

First stable, production-ready release. Every layer of the validation
pipeline was expanded, hardened, and documented since v0.1.2.

### Added

- **Activity & gzip validation:** `validate_activity_file` (GPX/TCX/FIT)
  and `validate_gzip_file` with decompression-bomb detection, plus
  `XmlSecurityValidator` using `defusedxml` to block XXE, DTD, and
  entity-expansion attacks in XML-based activity files.
- **Audit logging:** `SecurityAuditLogger`, `AuditEvent`, and
  `AuditEventType` with per-request correlation IDs, toggled by
  `enable_audit_logging`.
- **Content security inspector:** `ContentSecurityInspector` for
  malware-signature scanning, script/webshell marker detection, and
  polyglot detection, controlled by `enable_content_analysis` and
  `content_scan_max_size`.
- **Nested ZIP complexity checks:** recursive inspection with
  cumulative entry, depth, hash, and timing checks, archive-quine and
  ZIP-of-ZIPs detection, and a new `max_total_entries_recursive` limit.

### Changed

- **Security hardening:** streaming file-size enforcement via
  `chunk_size`, tightened ZIP inspection (null-byte filename detection,
  monotonic timers, 512-byte content scans, sanitized error messages),
  and a hardened MIME cache (256 → 64 entries, extension-only
  derivation).
- `defusedxml` added as a runtime dependency.
- FastAPI example now binds to `127.0.0.1` instead of `0.0.0.0`.
- **Performance:** pre-computed `frozenset` collections, cached lookup
  sets at initialization, and LRU-cached MIME guessing.

### Other

- Hypothesis fuzz tests and integration suites; GitHub Actions for
  lint/test, fuzzing, docs, and PyPI publish; Dependabot and
  `CODEOWNERS`; new security docs (threat model, architecture,
  integration checklist).

## [0.1.2] - 2025-10-31

### Fixed

- Added `BinaryFileCategory` to the exported enums in
  `safeuploads/__init__.py` so it is available for external use.

## [0.1.1] - 2025-10-31

### Added

- `max_number_files_same_type` in `SecurityLimits`; `ZipContentInspector`
  now uses this configurable limit instead of a hardcoded value when
  checking for excessive files of the same type in a ZIP archive.
- `BinaryFileCategory` enum categorizing binary file extensions
  (starting with fitness files such as `.fit`); `ZipContentInspector`
  skips script-content checks for these binary files.

## [0.1.0] - 2025-10-30

Initial release.

### Added

- **Filename security:** Unicode normalization, directory-traversal
  protection, Windows reserved-name blocking.
- **Extension validation:** configurable allow/block lists with
  dangerous-extension detection.
- **ZIP bomb protection:** compression-ratio limits, nested-archive
  inspection, size constraints.
- **MIME type verification:** magic-number validation for common file
  types.
- Framework-agnostic async validation, a rich exception hierarchy with
  machine-readable error codes, secure defaults, and full type hints.

[2.0.0]: https://github.com/endurain-project/safeuploads/compare/v1.1.1...v2.0.0
[1.1.1]: https://github.com/endurain-project/safeuploads/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/endurain-project/safeuploads/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/endurain-project/safeuploads/releases/tag/v1.0.1
[1.0.0]: https://github.com/endurain-project/safeuploads/releases/tag/v1.0.0
[0.1.2]: https://github.com/endurain-project/safeuploads/releases/tag/v0.1.2
[0.1.1]: https://github.com/endurain-project/safeuploads/releases/tag/v0.1.1
[0.1.0]: https://github.com/endurain-project/safeuploads/releases/tag/v0.1.0
