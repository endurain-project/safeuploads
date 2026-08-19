# Changelog

All notable changes to this project are documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.1.1]: https://github.com/endurain-project/safeuploads/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/endurain-project/safeuploads/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/endurain-project/safeuploads/releases/tag/v1.0.1
[1.0.0]: https://github.com/endurain-project/safeuploads/releases/tag/v1.0.0
[0.1.2]: https://github.com/endurain-project/safeuploads/releases/tag/v0.1.2
[0.1.1]: https://github.com/endurain-project/safeuploads/releases/tag/v0.1.1
[0.1.0]: https://github.com/endurain-project/safeuploads/releases/tag/v0.1.0
