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
