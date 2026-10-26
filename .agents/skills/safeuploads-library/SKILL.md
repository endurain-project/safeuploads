---
name: safeuploads-library
description: safeuploads library conventions (validators, inspectors, config, fail-closed security). Use when adding, moving, refactoring or reviewing code in safeuploads/ or tests/.
---

# safeuploads library

`docs/security/architecture.md` states the pipeline and component roles, `docs/security/threat-model.md` the threats each check answers and `docs/api.md` the public API.
Where this skill and any of them disagree, they win.

## Core rules (always apply)

- Fail closed: reject what cannot be positively accepted; never turn a failed check into a log line.
- One validator or inspector per concern, extending `BaseValidator` where it validates; `FileValidator` orchestrates and holds no check logic of its own.
- A new limit or allow-list entry lives in `FileSecurityConfig` or `SecurityLimits`, with its cross-field validation and a docs entry.
- Never loosen a default (limit, allow-list, block-list, ratio, depth) to make a test or one caller pass; ask first.
- Keep the filename check order: Unicode sanitization, then Windows reserved names, then the remaining normalization.
- Raise a `safeuploads.exceptions` subclass with its `ErrorCode`; the message is safe to show a caller and never contains file contents or filesystem paths.
- Blocking work (archive inspection, hashing, magic) stays off the event loop; use the existing worker-thread offload and `executor` option.
- A released `ErrorCode` never changes meaning; a new failure mode gets a new code.
- A new public name goes in `safeuploads/__init__.py` (`__all__`), `docs/api.md`, the README example if it changes usage, and `CHANGELOG.md`.
- A rename, removal, signature change, default change that accepts or rejects different input, or `ErrorCode` change is breaking: mark it `!` and say so in the changelog.
- KISS, YAGNI, DRY: search the package for an existing helper first; add no parameter, protocol or config field without a current caller; extract on the third repetition.
- Comments and docstrings say what the code does now and why; history goes in the commit message.

## Read on demand

| When you are | Read |
| --- | --- |
| Writing code, docstrings, logging, errors or typing | `references/code-standards.md` |
| Writing or fixing tests, fuzzing or corpus work | `references/testing.md` |
| Adding or changing a check, limit, parser or anything on the threat model | `references/security.md` |

## Before finishing

```bash
uv run ruff check safeuploads tests examples
uv run ruff format --check safeuploads tests examples
uv run mypy
uv run pytest
```

`uv run pytest` enforces the 90% branch-coverage gate.
`uv run ty check` is advisory in CI and not a gate.
`libmagic` must be installed on the machine (`brew install libmagic` or `apt-get install libmagic1`).

## Repo hygiene

- Do only what was asked: no extra docs, summaries or READMEs.
- Prefer existing patterns and utilities over new files; keep it simple, build only what is needed now, do not repeat existing code.
- Do not add dependencies, and do not touch CI, publish configuration, supported Python versions or constraints unless asked.
- Local notes go in `devdocs/`, helper scripts in `devscripts/` (gitignored).
- Never run `git commit` unless asked; use the `conventional-commits` skill for messages.
