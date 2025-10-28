# safeuploads

Secure file upload validation for Python 3.13+ applications. Catches dangerous filenames, malicious extensions, Windows reserved names, and compression-based attacks before you accept an upload.

## Features

- **Framework-agnostic** async validation (FastAPI, Starlette, Quart, etc.)
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

## Documentation

Full documentation available at [link to your docs].

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions welcome! See [Contributing Guidelines](CONTRIBUTING.md) for guidelines.


