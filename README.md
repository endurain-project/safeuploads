# safeuploads

![License](https://img.shields.io/github/license/joaovitoriasilva/safeuploads)
[![GitHub release](https://img.shields.io/github/v/release/joaovitoriasilva/safeuploads)](https://github.com/joaovitoriasilva/safeuploads/releases)
[![GitHub stars](https://img.shields.io/github/stars/joaovitoriasilva/safeuploads.svg?style=social&label=Star)](https://github.com/joaovitoriasilva/safeuploads/stargazers)

Secure file upload validation for Python 3.13+ applications. Catches dangerous filenames, malicious extensions, Windows reserved names, and compression-based attacks before you accept an upload.

## Features

- **Framework-agnostic** async validation (FastAPI, generic)
- Filename sanitization and Unicode security checks
- Extension validation with configurable allow/block lists
- ZIP bomb detection and content inspection
- MIME type verification with signature validation
- Rich exception hierarchy for precise error handling
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

## Current Status & Roadmap

### What's Working

- **Filename Security**: Unicode normalization, directory traversal prevention, Windows reserved names blocking
- **Extension Validation**: Allow/block lists with configurable rules, dangerous extension detection
- **Compression Security**: ZIP bomb detection, nested archive inspection, size and ratio limits
- **Content Inspection**: Deep ZIP content analysis with configurable depth and entry limits
- **MIME Type Verification**: Magic number validation for common file types
- **Rich Exception System**: Machine-readable error codes with detailed context

### Planned Improvements

#### Critical (Pre-1.0)
- **Streaming Validation**: Memory-efficient processing for large files to prevent resource exhaustion
- **Resource Limits**: CPU and memory monitoring during validation operations
- **Rate Limiting Guide**: Documentation and examples for production deployments

#### High Priority
- **Enhanced ZIP Security**: Protection against recursive ZIP structures and algorithmic complexity attacks
- **Audit Logging**: Structured logging for security-relevant events with request correlation
- **Performance Optimizations**: Pattern caching, compiled regex optimization, async I/O improvements

#### Future Enhancements
- **Additional File Types**: .gpx, .tcx, .fit, .gz
- **Content Analysis**: Malware signature detection, embedded script scanning
- **Fuzzing Tests**: Automated testing with malformed and malicious payloads
- **Security Documentation**: Threat model, architecture diagrams, integration security checklist

### Production Readiness

**Status**: Beta - suitable for testing, not yet recommended for production use

**Before Production**:
1. Address memory exhaustion vulnerability in ZIP inspection
2. Implement streaming validation for large files
3. Complete security audit and penetration testing

**Known Limitations**:
- No built-in rate limiting (must be implemented at application level)
- Limited to synchronous content reading in ZIP inspection
- Performance not yet optimized for high-throughput scenarios

## Documentation

Full documentation available at [link to your docs].

## Sponsors

A huge thank you to the project sponsors! Your support helps keep this project going.

Consider [sponsoring safeuploads on GitHub](https://github.com/sponsors/joaovitoriasilva) to ensure continuous development.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions welcome! See [Contributing Guidelines](CONTRIBUTING.md) for guidelines.


