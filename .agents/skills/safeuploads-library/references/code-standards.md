# Code standards

## Python
- Python 3.13 syntax (`requires-python = ">=3.13"`): `int | None`, `list[str]`, `dict[str, Any]`; no `typing.Optional/List/Dict`.
- Lines up to 79 characters, enforced by `ruff format` (`line-length = 79`); keep comments and docstrings within it too.
- Imports grouped stdlib / third-party / local; `TYPE_CHECKING` to avoid cycles.
- Every module has a top-level docstring.
- Comments and docstrings state what the code does now and why. History goes in the commit message.
- Performance and safety outrank brevity; correctness, explicit logging and clear validation messages matter.

## Docstrings (PEP 257, Google sections)
Enforced by ruff `D` (`convention = "pep257"`) outside `tests/` and `examples/`.
- Summary on the opening line, then a blank line, then sections.
- Every public module, class, function and method has a docstring.
- `Args`: every parameter of a public function. A `_private` helper gets a summary and `Args` only for a non-obvious parameter.
- `Returns`: when a value comes back. `Returns: None.` is not required.
- `Raises`: the exceptions the function raises or deliberately lets propagate, especially the security ones. Omit it when there are none.
- Classes: summary plus `Attributes`.
- No examples in docstrings; they belong in `docs/` and `examples/`.
- A docstring is not a design document: what, then why, in the fewest lines.
- A docstring with backslashes is a raw string (`r"""`).

## Typing
- `mypy` runs with `strict = true`; every def is fully and precisely typed, and a bare `Any` is a smell.
- Do not add `# type: ignore` or `# noqa` to pass; fix the type or the code. A `per-file-ignores` entry in `pyproject.toml` needs a comment saying why.
- Structural types for uploads live in `protocols.py` (`SeekableFile`, `UploadFileProtocol`); depend on them, not on FastAPI.

## Async
- Keep validator entry points `async`; never call blocking I/O or CPU-heavy inspection directly in an `async def` (ruff `ASYNC` catches the common cases).
- Blocking inspection runs through `FileValidator`'s worker-thread offload.

## Errors
- Raise the subclasses in `exceptions.py` with an `ErrorCode`; a configuration mistake raises `FileSecurityConfigurationError`.
- Keep the hierarchy: filename, size, MIME, signature, compression and processing errors each have their base; add a new subclass, not a new base.
- Do not swallow an exception from a check; an inspector that cannot finish rejects (`FileProcessingError` / `ResourceLimitError`).

## Logging
- `logging.getLogger(__name__)` for diagnostics; security decisions go through `SecurityAuditLogger` with a correlation id.
- The host owns handlers, levels and formatting; never call `basicConfig`, add handlers or set levels.
- Never log file contents, or a filename that has not been sanitized.
- Log text and error wording are not public API.

## Dependencies and extras
- Runtime dependencies stay `python-magic` and `defusedxml`; FastAPI is the `fastapi` extra and imported lazily.
- Adding or changing a dependency is a request-level decision: ask first.
