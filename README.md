# safeuploads

[![License](https://img.shields.io/badge/license-MIT-green)](https://github.com/endurain-project/safeuploads/blob/main/LICENSE.md)
[![Release](https://img.shields.io/github/v/release/endurain-project/safeuploads?label=release&color=blue)](https://github.com/endurain-project/safeuploads/releases)
[![PyPI version](https://img.shields.io/pypi/v/safeuploads)](https://pypi.org/project/safeuploads/)
[![PyPI downloads](https://img.shields.io/pypi/dm/safeuploads)](https://pypi.org/project/safeuploads/)
[![Python](https://img.shields.io/badge/python-3.13%2B-blue)](https://pypi.org/project/safeuploads/)
[![Docs](https://img.shields.io/badge/docs-safeuploads.endurain.com-blue)](https://safeuploads.endurain.com/)
[![Stars](https://img.shields.io/github/stars/endurain-project/safeuploads?label=stars&logo=github)](https://github.com/endurain-project/safeuploads)

Secure file upload validation for Python 3.13+ applications. Catches dangerous filenames, malicious extensions, Windows reserved names, and compression-based attacks before you accept an upload.

## Features

- **Framework-agnostic** async validation (FastAPI, generic)
- Filename sanitization and Unicode security checks
- Extension validation with configurable allow/block lists
- ZIP bomb detection, nested archive inspection, and recursive structure protection
- Dangerous ZIP entry rejection (executables, scripts, system files)
- Image decompression bomb detection via declared pixel dimensions
- MIME type verification with file signature validation
- Activity file support (.gpx, .tcx, .fit) with XXE-safe XML parsing
- Gzip archive validation with decompression bomb detection
- Streaming validation for memory-efficient large file processing
- Resource monitoring (CPU time and memory limits)
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
from safeuploads import FileValidator, FileSecurityConfig

# Use default secure configuration
validator = FileValidator()

# Or customize limits
config = FileSecurityConfig()
config.limits.max_image_size = 10 * 1024 * 1024  # 10 MiB
config.limits.max_image_pixels = 50_000_000  # Reject bigger decoded images
config.limits.max_compression_ratio = 50

# Opt in to strict ZIP checking: decompress every entry to
# reject archives with forged central-directory metadata
config.limits.verify_zip_decompression = True

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
- **Resource Monitoring**: Wall-clock and memory limits enforced by `ResourceMonitor`, checked inside the streaming, ZIP, and gzip loops so a runaway upload is aborted while it runs
- **Activity File Support**: GPX, TCX, and FIT file validation with XXE-safe XML parsing
- **Gzip Support**: Gzip archive validation with decompression bomb detection
- **Content Analysis**: Optional malware signature, web shell, and polyglot file detection
- **Audit Logging**: Structured security event logging with correlation IDs via `contextvars`
- **Performance Optimizations**: Pre-compiled pattern sets, `frozenset` lookups, LRU-cached MIME guessing
- **Rich Exception System**: Machine-readable error codes with detailed context
- **Fuzzing Tests**: Hypothesis-based property testing for filenames, ZIP, images, and config

### Known Limitations

- No built-in rate limiting (application-level concern — see documentation)
- MIME detection covers first 8 KB; advanced polyglot attacks may require `enable_content_analysis`
- Image dimensions are read from the declared PNG/IHDR or JPEG/SOF header within the first 1 MiB; images whose dimensions cannot be read are rejected
- Memory accounting uses the process-wide peak RSS, so it is a coarse upper bound rather than a per-validation measurement
- `SpooledTemporaryFile` uses the system default temp directory

## Documentation

Full documentation is available at the [safeuploads docs site](https://safeuploads.endurain.com/).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE.md) file for details.

## Contributing

Contributions welcome! See [Contributing Guidelines](CONTRIBUTING.md) for guidelines.

<div align="center">
  <sub>Built with ❤️ from Portugal | Part of the <a href="https://github.com/endurain-project">Endurain</a> ecosystem</sub>
</div>