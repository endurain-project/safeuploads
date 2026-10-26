# Security

`docs/security/threat-model.md` is the list of threats and `docs/security/integration-checklist.md` is what a host must do; update them when a change moves the boundary.

## Fail closed
- Unknown, unparsable or unverifiable input is rejected.
- A check never degrades into a warning, a truncated inspection or a default "allow" because a limit was reached; hitting a limit is a rejection.
- Order matters: normalize and sanitize the name before any extension or reserved-name decision is made on it.

## Filenames and paths
- Never build a filesystem path from an uploaded filename; the library returns a sanitized name and the host generates the storage name.
- Reject null bytes, control characters, bidirectional overrides, homoglyph tricks, double extensions, trailing dots/spaces and Windows reserved names.
- Compare extensions and MIME types case-insensitively against allow-lists; a block-list is a supplement, not the only gate.

## Content
- Verify the MIME type and the file signature (`python-magic`) against the claimed extension; a mismatch is a rejection.
- Parse XML only with `defusedxml`; disable DTDs, external entities and network access (XXE, billion laughs).
- Inspect archives without extracting to disk, and bound compressed and uncompressed size, ratio, entry count, nesting depth and total work (ZIP bombs, recursive archives, gzip bombs).
- Treat embedded scripts, polyglot signatures and executable payloads in content analysis as hostile.

## Resource limits
- Bound memory, CPU time and wall time per validation (`ResourceMonitor`, `SecurityLimits`); stream large files in chunks instead of reading them whole.
- A new limit has a conservative default, validation in `FileSecurityConfig`/`SecurityLimits` and a test on both sides of the boundary.
- Concurrency and rate limiting belong to the host (`docs/rate-limiting.md`); the library only bounds the cost of one validation.

## Secrets and logging
- No secrets in code, tests or examples.
- Audit events carry a correlation id and sanitized identifiers; never file contents or raw, unsanitized filenames.
- Error messages are safe to show a client: no paths, stack detail or internal limits beyond what the code already exposes.

When you add a mitigation, state what it protects against; when you flag a vulnerability, explain the risk.
