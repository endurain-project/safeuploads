# Copilot Coding Guidelines

## Project Context
- Library: `safeuploads` – validates and sanitizes uploaded files for security threats.
- Core modules: configuration (`safeuploads/config.py`), validators (`safeuploads/validators/`), inspectors (`safeuploads/inspectors/`), utilities (`safeuploads/utils.py`).
- External deps are minimal (FastAPI, `python-magic`, stdlib `logging`). Avoid adding new third-party packages unless requested.
- Performance and safety take priority over syntactic brevity; correctness, explicit logging, and clear validation messages matter.

## Task Execution Guidelines
- **Do ONLY what is explicitly requested** - do not add extra documentation, summaries, or "helpful" files unless specifically asked.
- If asked to implement a feature, implement ONLY that feature - no additional documentation beyond code comments.
- Do not create README files, summary documents, quick reference guides, or completion reports unless explicitly requested.
- When implementing changes, focus on the code implementation itself, not supplementary documentation.
- Ask for clarification if the scope is unclear rather than assuming additional deliverables are wanted.

## Style Expectations
- Target Python 3.13+. Use modern type hint syntax (`int | None`, `list[str]`, `dict[str, Any]`) instead of `Optional`, `List`, `Dict`, etc.
- Preserve async boundaries in validator methods; do not block event loops with synchronous I/O inside `async` functions.
- Use module-level `logging.getLogger(__name__)` for security-relevant events; never rely on application-specific loggers.
- Enforce PEP 8 line limits:
	- Code stays at or below 79 characters.
	- Comments and docstrings stay at or below 72 characters.

## Docstring Standard (PEP 257)
- **Always follow PEP 257** with Args/Returns/Raises sections.
- **Format**: One-line summary, blank line, then Args/Returns/Raises sections.
- **Always include Args/Returns/Raises** even when parameters seem obvious.
- **NO examples** in docstrings - keep in external docs or tests.
- **NO extended explanations** - one-line summary + sections only.
- **Keep concise** - describe what, not how.

**Format:**
```python
def function(param: str) -> int:
    """
    One-line summary of what this does.

    Args:
        param: Description of param.

    Returns:
        Description of return value.

    Raises:
        ValueError: When param is invalid.
    """
```

**For classes:**
```python
class MyClass:
    """
    One-line summary of the class.

    Attributes:
        attr: Description of attribute.
    """
```

## Design Principles
- Validators should stay single-purpose and operate through `BaseValidator`; new checks belong in dedicated methods/classes mirroring current patterns.
- Configuration changes must go through `FileSecurityConfig` and `SecurityLimits`; ensure cross-field validation is updated if new knobs are added.
- Prefer raising `ValueError`/custom exceptions defined in `safeuploads/exceptions.py` for validation failures so the caller can surface user-friendly errors.
- Keep filename and compression checks order-sensitive—Unicode sanitization first, Windows reserved names before other normalization, etc.

## Testing & Verification
- When adding features, describe or provide unit/integration tests that cover both valid and malicious payload scenarios.
- Ensure new code paths are covered by logging or test assertions that clearly indicate failure causes.

## Documentation & Examples
- Update docstrings and README examples when public APIs change (e.g., `FileValidator`, utility helpers).
- Demonstrate usage snippets with async FastAPI context where applicable.

## Commits logic

Committing should use clear messages following [Conventional Commits](https://www.conventionalcommits.org/) format:

**Format:** `<type>(<scope>)!: <description>` — `(<scope>)` and the breaking-change `!` are optional.

The following rules are enforced automatically on every PR (against the PR title and every commit subject) by `.forgejo/workflows/conventional-commits.yml`. Validation follows the [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/) spec, with a single project-policy addition (the allowed-type whitelist). Generated commit messages must comply:

- **Header format:** `<type>(<scope>)!: <description>` — the `(<scope>)` and breaking-change `!` are optional, and a space is required after the colon.
- **Allowed types (project policy):** `build`, `chore`, `ci`, `docs`, `feat`, `fix`, `perf`, `refactor`, `revert`, `style`, `test`. Types are matched case-insensitively per the spec.
- **Scope** (optional) is any non-empty string (no parentheses), per the spec.
- **Description** is free-form text, per the spec (no lowercase requirement, no trailing-period restriction, no length limit).
- **Breaking changes** are marked with `!` after the type/scope (e.g. `feat(api)!: ...`) or a `BREAKING CHANGE:` footer in the commit body.

Examples:
- `feat: add GPX max speed parsing`
- `fix(garmin): handle multi-segment GPX distance correctly`
- `docs: update development instructions`
- `test(activities): add regression test for GPX segment handling`
- `refactor(api)!: rename Activity.distance to total_distance`
