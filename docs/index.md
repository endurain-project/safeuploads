# safeuploads

<div>
    <a href="https://github.com/endurain-project/safeuploads/blob/main/LICENSE.md">
      <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
    </a>
    <a href="https://github.com/endurain-project/safeuploads/releases">
      <img src="https://img.shields.io/github/v/release/endurain-project/safeuploads?label=release&color=blue" alt="Release">
    </a>
    <a href="https://github.com/endurain-project/safeuploads">
      <img src="https://img.shields.io/github/stars/endurain-project/safeuploads?label=stars&logo=github" alt="Stars">
    </a>
</div>

Secure file upload validation for Python 3.11+ applications. Catches dangerous filenames, malicious extensions, Windows reserved names, and compression-based attacks before you accept an upload.

## Features

- **Framework-agnostic** async validation (FastAPI, generic)
- Filename sanitization and Unicode security checks
- Extension validation with configurable allow/block lists
- ZIP bomb detection, nested archive inspection, and recursive structure protection
- Dangerous ZIP entry rejection (executables, scripts, system files)
- Image decompression bomb detection via declared pixel dimensions
- MIME type verification with file signature validation
- Activity file support (.gpx, .tcx, .fit) with XXE-safe XML parsing and root-element enforcement
- Gzip archive validation with decompression bomb detection
- Streaming validation for memory-efficient large file processing
- Wall-clock limits enforced inside the validation loops
- Log-injection-safe logging of untrusted filenames
- Content analysis with malware signature and polyglot detection
- Structured audit logging with correlation IDs
- Rich exception hierarchy with machine-readable error codes
- Zero configuration required—secure defaults out of the box

## Installation

```bash
pip install safeuploads
```

For FastAPI integration:
```bash
pip install safeuploads[fastapi]
```

### Verifying a release

Releases are built and published by this repository's release workflow through PyPI Trusted Publishing, with [PEP 740](https://peps.python.org/pep-0740/) attestations. You can confirm a downloaded artifact came from that workflow and was not substituted:

```bash
uvx pypi-attestations verify pypi \
  --repository https://github.com/endurain-project/safeuploads \
  pypi:safeuploads-<version>-py3-none-any.whl
```

A successful run prints `OK: <filename>`. `Provenance for file ... was not found` means the artifact predates attested publishing rather than that verification failed.

Each release run also produces a CycloneDX SBOM and `SHA256SUMS`, generated from a clean install of the built wheel. These are retained as workflow artifacts on the release run rather than published to PyPI.

## Quick Start

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

## Configuration

```python
from safeuploads import FileValidator, FileSecurityConfig, SecurityLimits

# Use default secure configuration
validator = FileValidator()

# Or pass explicit limits. Anything you leave out keeps its
# secure default, and the limits object is copied, so nothing
# is shared between configs.
config = FileSecurityConfig(
    SecurityLimits(
        max_image_size=10 * 1024 * 1024,  # 10 MiB
        max_image_pixels=50_000_000,  # Reject bigger decoded images
        max_compression_ratio=50,
        # Decompress every ZIP entry to reject archives with
        # forged central-directory metadata
        verify_zip_decompression=True,
        # Keep spilled uploads off the system temp directory
        temp_dir="/var/lib/myapp/uploads-tmp",
    )
)

validator = FileValidator(config=config)

# Optionally offload blocking inspection to a bounded pool
from concurrent.futures import ThreadPoolExecutor

pooled_validator = FileValidator(
    config=config,
    executor=ThreadPoolExecutor(max_workers=4),
)
```

## Exception Handling

Exception messages are written for your logs, not for your users. They
embed the client-supplied filename and other untrusted values, so never
return `str(err)` to a client. Branch on the exception type and surface
`err.error_code`, which is a stable machine-readable string.

```python
import logging

from safeuploads.exceptions import (
    FileValidationError,      # Base exception
    FileSizeError,            # File too large
    ExtensionSecurityError,   # Dangerous extension
    ImageSecurityError,       # Image decompression bomb
    ZipBombError,             # Compression attack
)

logger = logging.getLogger(__name__)

try:
    await validator.validate_image_file(file)
except FileSizeError as err:
    return {"error": "File too large", "max_size": err.max_size}
except ExtensionSecurityError as err:
    return {"error": "File type not allowed", "code": err.error_code}
except ImageSecurityError as err:
    return {"error": "Image too large to decode", "code": err.error_code}
except FileValidationError as err:
    # Full detail goes to the log; the client only sees the code.
    logger.warning("Upload rejected: %s", err)
    return {"error": "Upload rejected", "code": err.error_code}
```

## Current Status

### Implemented

- **Filename Security**: Unicode normalization, directory traversal prevention, Windows reserved names blocking
- **Extension Validation**: Allow/block lists with configurable rules, dangerous extension detection
- **Compression Security**: ZIP bomb detection, nested archive inspection, recursive structure and quine detection, size and ratio limits, optional strict decompression verification
- **Content Inspection**: Deep ZIP content analysis with configurable depth and entry limits, plus rejection of entries whose extension is an executable, script, or system file
- **Image Bomb Protection**: PNG and JPEG headers are parsed and the declared pixel count is bounded by `max_image_pixels`
- **MIME Type Verification**: Magic number validation for images, ZIP, activity files, and gzip
- **Streaming Validation**: Memory-efficient processing via `SpooledTemporaryFile` for large files
- **Resource Monitoring**: Wall-clock limits enforced by `ResourceMonitor`, checked inside the streaming, ZIP, and gzip loops so a runaway upload is aborted while it runs. Memory is best-effort telemetry (see Known Limitations)
- **Activity File Support**: GPX, TCX, and FIT validation with XXE-safe XML parsing, a required root element per extension, and a cap on parsed element count
- **Gzip Support**: Gzip archive validation with decompression bomb detection and an inflation timeout
- **Content Analysis**: Optional malware signature, web shell, and polyglot file detection
- **Audit Logging**: Structured security event logging with correlation IDs via `contextvars`
- **Performance Optimizations**: Pre-compiled pattern sets, `frozenset` lookups, LRU-cached MIME guessing
- **Rich Exception System**: Machine-readable error codes with detailed context
- **Fuzzing Tests**: Hypothesis-based property testing for filenames, ZIP, images, and config

### Known Limitations

- No built-in rate limiting (application-level concern — see [Rate Limiting](rate-limiting.md) guide)
- MIME detection covers first 8 KB; advanced polyglot attacks may require `enable_content_analysis`
- Image dimensions are read from the declared PNG/IHDR or JPEG/SOF header within the first 1 MiB; images whose dimensions cannot be read are rejected
- `max_validation_memory_mb` is best-effort telemetry, not a limit: it samples the process-wide peak RSS, so it cannot be attributed to a single validation. Exceeding it is logged; set `enforce_memory_limit=True` to enforce, and only in a process that validates one upload at a time
- `verify_zip_decompression` is off by default; enable it if anything other than Python's `zipfile` extracts your archives (see [Integration Checklist](security/integration-checklist.md))
- Uploads larger than `max_memory_buffer_size` spill to disk; set `temp_dir` to control where, otherwise the system default temporary directory is used

## Documentation

- [API Reference](api.md) — full public API documentation
- [Rate Limiting](rate-limiting.md) — production rate limiting guide
- [Threat Model](security/threat-model.md) — threat categories and mitigations
- [Architecture](security/architecture.md) — validation pipeline and data flow
- [Integration Checklist](security/integration-checklist.md) — production deployment checklist

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/endurain-project/safeuploads/blob/main/LICENSE.md) file for details.

## Contributing

Contributions welcome! See [Contributing Guidelines](https://github.com/endurain-project/safeuploads/blob/main/CONTRIBUTING.md) for guidelines.

<div align="center">
  <sub>Built with ❤️ from Portugal | Part of the <a href="https://github.com/endurain-project">Endurain</a> ecosystem</sub>
</div>