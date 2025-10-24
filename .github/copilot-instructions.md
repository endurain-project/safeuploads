# Copilot Coding Guidelines

## Project Context
- Library: `safeuploads` – validates and sanitizes uploaded files for security threats.
- Core modules: configuration (`safeuploads/config.py`), validators (`safeuploads/validators/`), inspectors (`safeuploads/inspectors/`), utilities (`safeuploads/utils.py`).
- External deps are minimal (FastAPI, `python-magic`, stdlib `logging`). Avoid adding new third-party packages unless requested.
- Performance and safety take priority over syntactic brevity; correctness, explicit logging, and clear validation messages matter.

## Style Expectations
- Target Python 3.13+. Use modern type hint syntax (`int | None`, `list[str]`, `dict[str, Any]`) instead of `Optional`, `List`, `Dict`, etc.
- Keep module and class docstrings consistent with existing style: short summary line, blank line, extended description. Prefer reStructuredText/Google-style sections only where necessary.
- Include concise inline comments only when logic is non-obvious (e.g., ordering of security checks). Avoid redundant commentary.
- Preserve async boundaries in validator methods; do not block event loops with synchronous I/O inside `async` functions.
- Use module-level `logging.getLogger(__name__)` for security-relevant events; never rely on application-specific loggers.

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
