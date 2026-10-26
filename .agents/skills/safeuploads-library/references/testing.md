# Testing

- Tests live in `tests/`, files `test_*.py`, grouped in `Test*` classes; validator and inspector tests mirror the package under `tests/validators/` and `tests/inspectors/`; shared fixtures in `tests/conftest.py`.
- Every new check has at least one accepted payload and one hostile payload, and covers the boundary on both sides of each limit.
- Build hostile inputs in memory (ZIP bombs, nested archives, polyglots, XXE documents, Unicode tricks); never commit real malware or a large binary.
- Cover empty/None, zero-length, truncated, malformed and over-limit input, and assert the exception type and `ErrorCode`, not only that something raised.
- `with pytest.raises(...) as exc_info` for exceptions.
- Async tests: `async def test_*` (`asyncio_mode = "auto"`).
- Markers are declared in `pyproject.toml` (`unit`, `integration`, `slow`, `performance`, `fuzz`) and run with `--strict-markers`; mark a new test accordingly.
- Skips need `reason=`.
- Coverage is branch coverage with `fail_under = 90`; it is a ratchet, raise it when coverage rises and never lower it.
- Tests are deterministic and offline; a performance test asserts a generous bound, never an exact time.
- Do not mock a validator to test the orchestrator's decision; run the real one on a small payload.

## Fuzzing
- Property tests use Hypothesis under `tests/fuzz/` (`test_fuzz_filenames.py`, `test_fuzz_zip.py`, `test_fuzz_images.py`, `test_fuzz_config.py`) and run weekly in CI (`fuzz.yml`) as well as in the suite.
- A fuzz failure that is a real bug becomes a fixed regression test with the minimal reproducer; do not only raise the example count or add `assume()` to hide it.

```bash
uv run pytest tests/validators -v
uv run pytest -m "not performance and not fuzz"
uv run pytest --cov=safeuploads --cov-report=term-missing
```
