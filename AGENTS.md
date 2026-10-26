# safeuploads

Secure file upload validation for Python 3.13+ applications.
Catches dangerous filenames, malicious extensions, Windows reserved names, compression bombs, polyglots and unsafe XML before an upload is accepted.
Runtime dependencies are minimal (`python-magic`, `defusedxml`; FastAPI behind the `fastapi` extra).
Published to PyPI; the public API is governed by SemVer.

## Where the detail lives

| Working on | Read |
| --- | --- |
| Library code or tests | `.agents/skills/safeuploads-library/SKILL.md` |
| Fixing a bug, failing test or CI failure | `.agents/skills/debugging/SKILL.md` |
| Commit messages and PRs | `.agents/skills/conventional-commits/SKILL.md` |
| Writing or editing a skill | `.agents/skills/skill-authoring/SKILL.md` |
| Validation pipeline and component roles | `docs/security/architecture.md` |
| Threats and mitigations | `docs/security/threat-model.md` |
| What a host must do to integrate safely | `docs/security/integration-checklist.md` |
| Public API reference | `docs/api.md` |
| Rate limiting guidance | `docs/rate-limiting.md` |

Skills are plain Markdown; read the relevant `SKILL.md` and the reference files it points to when your tool does not load skills itself.

## Layout

```text
safeuploads/    Package: file_validator, config, exceptions, enums, audit, utils, validators/, inspectors/
tests/          Test suite (unit, integration, fuzz/, performance)
examples/       Runnable usage examples
docs/           Documentation site (mkdocs)
.agents/skills/ Agent skills (symlinked into .claude/skills)
```

## Commands

From the repository root (Python 3.13+, `uv`, system `libmagic`):

```bash
uv sync --dev --extra fastapi
uv run ruff check safeuploads tests examples
uv run ruff format --check safeuploads tests examples
uv run mypy
uv run pytest
```

## Rules for every change

- Do only what was asked; no extra docs, summaries, READMEs or "helpful" files.
- Prefer existing patterns, utilities and files over new ones.
- KISS: pick the simplest design that solves the underlying problem; no indirection, abstraction layer or option without a current need. Simple means few moving parts, not a small diff or a patch over the symptom.
- YAGNI: build only what the task needs now; no speculative parameters, flags, hooks, config or extension points. What you do build must be complete and proper, not a stub or shortcut.
- DRY: reuse an existing helper, validator or fixture before writing another; extract shared code at the third repetition, not the second, and only when the copies change for the same reason.
- Do not add third-party dependencies, and do not change CI workflows, release or publish configuration, supported Python versions, dependency constraints or the `uv` settings unless asked.
- Never run `git commit` (or any commit-creating command) unless the user explicitly asks; staging for inspection is fine.
- Commit messages and PR titles follow Conventional Commits (enforced in CI); see the `conventional-commits` skill.
- Local-only notes go in `devdocs/`, helper scripts in `devscripts/` (both gitignored).
- No hardcoded secrets; real malware samples never enter the repository, tests build hostile payloads in memory.
- Ask for clarification when scope is unclear instead of assuming extra deliverables.
- A change touching the public API, the validation order or more than one validator/inspector starts with a short task list in chat for approval; keep plans in chat or `devdocs/`, never in tracked files.
- Bug fixes and new behavior start with a failing test, with both a valid and a malicious payload.
- A change to the public API is done only when `docs/api.md`, the affected docs page, `README.md` examples and `CHANGELOG.md` agree with the code.
- Done means the checks that apply to what changed ran and their output was read; say which ran and which did not (code checks do not apply to docs, `AGENTS.md` or skill-only changes).
- Before reporting a larger change done, compare the diff to the request and remove anything not asked for.

## Fixing problems

- Fix the root cause, not the symptom. Before changing code, state the cause you found and the evidence for it.
- Do not add workarounds: no special-case branches, swallowed exceptions, retries or sleeps to hide a failure, `type: ignore` / `# noqa`, test skips or loosened assertions, or defensive checks that mask bad state upstream.
- If the proper fix is larger than the request (touches other validators, changes a boundary or the public API, needs a refactor), stop and ask before editing. Present the options:
  1. Proper fix: what it changes and why it is the right one.
  2. Minimal fix: what it leaves broken or the debt it creates.

  Recommend one. Never apply the minimal option without the user's choice.
- If unsure whether a fix is a workaround, treat it as one and ask.
- A security-relevant weakening (a raised limit, a removed check, a widened allow-list, a skipped validation) is never a fix; ask first.

## Building features

- Build the feature the way the architecture intends: correct component, layering and validation order, even when a shortcut would be quicker.
- Do not take shortcuts: no placeholder or stubbed logic, hardcoded values, TODOs standing in for required behavior, copy-pasted code instead of reuse, logic in the wrong layer, or skipped tests, validation, error handling or docs.
- Before writing code, state the approach and the files it touches. If more than one reasonable design exists, or the proper design is larger than the request implies, stop and ask. Present the options:
  1. Proper design: what it involves and why it fits the architecture.
  2. Simpler design: what it cuts or defers, and the debt it creates.

  Recommend one. Never apply the simpler option without the user's choice.
- Scope still applies: complete means done properly, not bigger. Do not add features, options or files that were not requested.

## Library invariants

- Fail closed: an input the library cannot positively accept is rejected, and a failing check never degrades to a warning.
- A validator is single-purpose and extends `BaseValidator`; `FileValidator` orchestrates, and a new check gets its own validator or inspector in the matching package.
- Configuration changes go through `FileSecurityConfig` and `SecurityLimits`, and a new field updates their cross-field validation.
- Failures raise the exceptions in `safeuploads/exceptions.py` (with a stable `ErrorCode`), never a bare `ValueError` or `Exception`.
- The order of filename checks is significant: Unicode sanitization first, Windows reserved names before other normalization.
- Blocking inspection never runs on the event loop; it goes through `FileValidator`'s worker-thread offload.
- XML is parsed only through `defusedxml` (XXE-safe); archives are inspected without extracting to disk and under size, ratio, depth and entry limits.
- Never build a filesystem path from an uploaded filename.
- Logging uses `logging.getLogger(__name__)` and the `SecurityAuditLogger`; never log file contents.
- Comments and docstrings state what the code does now, not what it used to do.
- Python 3.13 syntax, 79-character lines (`pyproject.toml`), PEP 257 docstrings with `Args`, `Returns`, `Raises` where applicable.
