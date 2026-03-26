# safeuploads

<div>
    <img src="https://img.shields.io/github/license/endurain-project/safeuploads" alt="License">
    <a href="https://github.com/endurain-project/safeuploads/releases">
      <img src="https://img.shields.io/github/v/release/endurain-project/safeuploads" alt="GitHub release">
    </a>
    <a href="https://github.com/endurain-project/safeuploads/stargazers">
      <img src="https://img.shields.io/github/stars/endurain-project/safeuploads.svg?style=social&label=Star" alt="GitHub stars">
    </a>
</div>

Secure file upload validation for Python 3.13+ applications. Catches dangerous filenames, malicious extensions, Windows reserved names, and compression-based attacks before you accept an upload.

## Features

- **Framework-agnostic** async validation (FastAPI, generic)
- Filename sanitization and Unicode security checks
- Extension validation with configurable allow/block lists
- ZIP bomb detection, nested archive inspection, and recursive structure protection
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
    except FileValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
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
config.limits.max_compression_ratio = 50

validator = FileValidator(config=config)
```

## Exception Handling

```python
from safeuploads.exceptions import (
    FileValidationError,      # Base exception
    FileSizeError,            # File too large
    ExtensionSecurityError,   # Dangerous extension
    ZipBombError,             # Compression attack
)

try:
    await validator.validate_image_file(file)
except FileSizeError as err:
    return {"error": "File too large", "max_size": err.max_size}
except ExtensionSecurityError as err:
    return {"error": "File type not allowed", "extension": err.extension}
except FileValidationError as err:
    return {"error": str(err), "code": err.error_code}
```

## Current Status

### Implemented

- **Filename Security**: Unicode normalization, directory traversal prevention, Windows reserved names blocking
- **Extension Validation**: Allow/block lists with configurable rules, dangerous extension detection
- **Compression Security**: ZIP bomb detection, nested archive inspection, recursive structure and quine detection, size and ratio limits
- **Content Inspection**: Deep ZIP content analysis with configurable depth and entry limits
- **MIME Type Verification**: Magic number validation for images, ZIP, activity files, and gzip
- **Streaming Validation**: Memory-efficient processing via `SpooledTemporaryFile` for large files
- **Resource Monitoring**: CPU time and memory limits enforced via `ResourceMonitor`
- **Activity File Support**: GPX, TCX, and FIT file validation with XXE-safe XML parsing
- **Gzip Support**: Gzip archive validation with decompression bomb detection
- **Content Analysis**: Optional malware signature, web shell, and polyglot file detection
- **Audit Logging**: Structured security event logging with correlation IDs via `contextvars`
- **Performance Optimizations**: Pre-compiled pattern sets, `frozenset` lookups, LRU-cached MIME guessing
- **Rich Exception System**: Machine-readable error codes with detailed context
- **Fuzzing Tests**: Hypothesis-based property testing for filenames, ZIP, images, and config

### Known Limitations

- No built-in rate limiting (application-level concern — see [Rate Limiting](rate-limiting.md) guide)
- MIME detection covers first 8 KB; advanced polyglot attacks may require `enable_content_analysis`
- `SpooledTemporaryFile` uses the system default temp directory

## Documentation

- [API Reference](api.md) — full public API documentation
- [Rate Limiting](rate-limiting.md) — production rate limiting guide
- [Threat Model](security/threat-model.md) — threat categories and mitigations
- [Architecture](security/architecture.md) — validation pipeline and data flow
- [Integration Checklist](security/integration-checklist.md) — production deployment checklist

## Sponsors

A huge thank you to the project sponsors! Your support helps keep this project going.

Consider [sponsoring safeuploads on GitHub](https://github.com/sponsors/joaovitoriasilva) to ensure continuous development.
## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/endurain-project/safeuploads/blob/main/LICENSE.md) file for details.

## Contributing

Contributions welcome! See [Contributing Guidelines](https://github.com/endurain-project/safeuploads/blob/main/CONTRIBUTING.md) for guidelines.

<div align="center">
  <sub>Built with ❤️ from Portugal | Part of the <a href="https://github.com/endurain-project">Endurain</a> ecosystem</sub>
</div>