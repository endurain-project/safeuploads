# safeuploads

Secure file upload validation for Python 3.11+ applications. Hand it an upload before you accept it, and it rejects dangerous filenames, disallowed extensions, Windows reserved names, forged MIME types, compression bombs and XXE payloads — raising a typed exception with a machine-readable error code rather than returning a verdict you have to interpret.

Validation is `async` and framework-agnostic: anything matching `UploadFileProtocol` works, and FastAPI's `UploadFile` is picked up when FastAPI happens to be installed — there is no hard dependency on it. Uploads are read in chunks and spooled to a `SpooledTemporaryFile` rather than held whole in memory, and every loop that could be made to run long is bounded by a wall-clock budget.

This site is the reference documentation. For the feature list and project overview, see the [README on GitHub](https://github.com/endurain-project/safeuploads).

## Installation

```bash
pip install safeuploads
```

For FastAPI integration:

```bash
pip install safeuploads[fastapi]
```

`python-magic` needs the `libmagic` system library present on the deployment target.

## Quick start

```python
from fastapi import FastAPI, UploadFile, HTTPException
from safeuploads import FileValidator
from safeuploads.exceptions import FileValidationError

app = FastAPI()
validator = FileValidator()

@app.post("/upload")
async def upload_image(file: UploadFile):
    try:
        await validator.validate_image_file(file)
    except FileValidationError as err:
        # Return the machine-readable code, never `str(err)`: exception
        # messages embed the client-supplied filename, so reflecting them
        # hands attacker-controlled bytes back to the browser.
        raise HTTPException(status_code=400, detail=err.error_code)

    return {"status": "success", "filename": file.filename}
```

`FileValidator()` with no arguments is already a secure configuration. Pass a `FileSecurityConfig` when you want to narrow it further — see [File Validation Configuration](security/integration-checklist.md#file-validation-configuration).

The sibling methods are `validate_zip_file`, `validate_activity_file` (GPX, TCX, FIT) and `validate_gzip_file`. Each pipeline is described in [Architecture](security/architecture.md#validation-pipelines).

## What safeuploads does not do

Knowing where the boundary sits matters more than the feature list, because everything past it is still your application's job:

**It does not rate limit.** A validator that correctly rejects ten thousand ZIP bombs has still burned the CPU rejecting them. Throttling belongs in front of the application — see the [Rate Limiting](rate-limiting.md) guide.

**It does not store, rename, or transform files.** Nothing is written anywhere except the temporary spill buffer, which is discarded afterwards. Choosing a storage path, generating a non-guessable name, and setting permissions are yours to get right; the [Integration Checklist](security/integration-checklist.md#file-storage-security) lists what that involves.

**It is not an antivirus.** `enable_content_analysis` scans for known malware signatures, web shells, and polyglot markers — useful, but a fixed pattern set rather than a maintained threat database. High-risk deployments should run a real scanner as well.

**It does not decode media.** Image bombs are caught by reading the declared dimensions out of the PNG or JPEG header, never by decoding pixels — that is what stops a bomb detonating during validation, and it also means safeuploads cannot tell you whether an image is otherwise well-formed.

**It does not judge accepted content.** A validated GPX file is well-formed XML with the expected root element, in which safeuploads found no attack. Whether its contents mean anything to your domain is a separate question.

## Known limitations

- No built-in rate limiting (application-level concern — see [Rate Limiting](rate-limiting.md) guide)
- MIME detection covers first 8 KB; advanced polyglot attacks may require `enable_content_analysis`
- Image dimensions are read from the declared PNG/IHDR or JPEG/SOF header within the first 1 MiB; images whose dimensions cannot be read are rejected
- `max_validation_memory_mb` is best-effort telemetry, not a limit: it samples the process-wide peak RSS, so it cannot be attributed to a single validation. Exceeding it is logged; set `enforce_memory_limit=True` to enforce, and only in a process that validates one upload at a time
- `verify_zip_decompression` is off by default; enable it if anything other than Python's `zipfile` extracts your archives (see [Integration Checklist](security/integration-checklist.md#zip-metadata-verification))
- Uploads larger than `max_memory_buffer_size` spill to disk; set `temp_dir` to control where, otherwise the system default temporary directory is used

## Where to go next

- [API Reference](api.md) — every public class, method, and exception, generated from the source.
- [Rate Limiting](rate-limiting.md) — the layer safeuploads deliberately leaves to you, with SlowApi, nginx, Caddy, and Traefik recipes.
- [Threat Model](security/threat-model.md) — each attack class, the CWE it maps to, and the check that stops it.
- [Architecture](security/architecture.md) — components, the four validation pipelines, and where file content is actually read.
- [Integration Checklist](security/integration-checklist.md) — the list to work through before running it in production, including how to verify a release's provenance.

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/endurain-project/safeuploads/blob/main/LICENSE.md) file for details.

## Contributing

Contributions welcome! See [Contributing Guidelines](https://github.com/endurain-project/safeuploads/blob/main/CONTRIBUTING.md) for guidelines.

<div align="center">
  <sub>Built with ❤️ from Portugal | Part of the <a href="https://github.com/endurain-project">Endurain</a> ecosystem</sub>
</div>