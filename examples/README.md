# SafeUploads Framework Integration Examples

This directory contains a working example demonstrating how to integrate `safeuploads` with FastAPI.

## Example Overview

| Example | Framework | Description |
|---------|-----------|-------------|
| `fastapi_example.py` | FastAPI | Complete FastAPI integration with custom error handlers |

## Prerequisites

The example requires Python 3.13+ and the `safeuploads` library with FastAPI:

```bash
pip install safeuploads[fastapi]
```

## Running the Example

### FastAPI Example

**Features:**
- Complete FastAPI application with automatic API documentation
- Custom exception handlers with detailed error responses
- Multiple validation endpoints (default and strict)
- Configuration customization examples
- Batch upload support

**Run:**
```bash
python fastapi_example.py
```

**Test:**
```bash
# View API documentation
open http://localhost:8000/docs

# Upload an image
curl -X POST http://localhost:8000/upload/image \
  -F "file=@test_image.jpg"

# Upload with strict validation
curl -X POST http://localhost:8000/upload/image/strict \
  -F "file=@test_image.jpg"

# Upload a ZIP
curl -X POST http://localhost:8000/upload/zip \
  -F "file=@test_archive.zip"

# Upload multiple files
curl -X POST http://localhost:8000/upload/multiple \
  -F "files=@image1.jpg" \
  -F "files=@image2.png" \
  -F "files=@archive.zip"

# View configuration
curl http://localhost:8000/config
```

---

## Key Integration Patterns

### Exception Handling

The example demonstrates how to convert `safeuploads` exceptions to FastAPI responses:

```python
from safeuploads.exceptions import FileValidationError, FileSizeError

try:
    await validator.validate_image_file(file)
except FileSizeError as err:
    # Access exception attributes
    print(f"File size: {err.size}, Max: {err.max_size}")
    print(f"Error code: {err.error_code}")
except FileValidationError as err:
    # Generic validation error
    print(f"Validation failed: {err}")
```

### Custom Configuration

The example shows how to create custom validation configurations:

```python
from safeuploads import FileValidator
from safeuploads.config import FileSecurityConfig, SecurityLimits

# Create custom limits
strict_limits = SecurityLimits(
    max_image_size=2 * 1024 * 1024,  # 2MB
    max_compression_ratio=50,  # Stricter ratio
)

# Apply to config
config = FileSecurityConfig()
config.limits = strict_limits

# Use with validator
validator = FileValidator(config=config)
```

---

## Error Response Examples

### FileSizeError
```json
{
  "error": "file_too_large",
  "message": "File size exceeds limit",
  "size": 25000000,
  "max_size": 20971520,
  "error_code": "FILE_TOO_LARGE"
}
```

### MimeTypeError
```json
{
  "error": "invalid_mime_type",
  "message": "MIME type not allowed",
  "detected": "application/x-msdownload",
  "allowed": ["image/jpeg", "image/png", "image/gif"],
  "error_code": "MIME_TYPE_NOT_ALLOWED"
}
```

### ZipBombError
```json
{
  "error": "zip_bomb_detected",
  "message": "Compression ratio exceeds limit",
  "ratio": 150.5,
  "error_code": "ZIP_BOMB_DETECTED"
}
```

### ZipContentError
```json
{
  "error": "dangerous_zip_content",
  "message": "ZIP contains dangerous content",
  "threats": [
    "Directory traversal detected: ../../../etc/passwd",
    "Nested archive detected: malware.zip"
  ],
  "error_code": "ZIP_CONTENT_THREAT"
}
```

---

## Testing the Example

### Create Test Files

```bash
# Create a test image
convert -size 100x100 xc:white test_image.jpg

# Create a test ZIP
echo "test content" > test.txt
zip test_archive.zip test.txt

# Create a large file for size testing
dd if=/dev/zero of=large_image.jpg bs=1M count=25

# Create a zip bomb for security testing (DO NOT USE IN PRODUCTION)
dd if=/dev/zero bs=1M count=1000 | gzip > zipbomb.gz
```

### Test Security Features

```bash
# Test Unicode security
curl -X POST http://localhost:8000/upload/image \
  -F "file=@test.jpg;filename=test\u202e\u202dgnp.exe"

# Test Windows reserved names
curl -X POST http://localhost:8000/upload/image \
  -F "file=@test.jpg;filename=CON.jpg"

# Test dangerous extensions
curl -X POST http://localhost:8000/upload/zip \
  -F "file=@test.zip;filename=malware.exe.zip"

# Test file size limits
curl -X POST http://localhost:8000/upload/image/strict \
  -F "file=@large_image.jpg"
```

---

## Development Tips

### Enable Debug Logging

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("safeuploads")
logger.setLevel(logging.DEBUG)
```

### Custom Error Codes

Access machine-readable error codes for API responses:

```python
from safeuploads.exceptions import ErrorCode

# Use in your responses
if exc.error_code == ErrorCode.FILE_TOO_LARGE:
    # Special handling
    pass
```

### Multiple Validators

Use different validator instances for different contexts:

```python
# Strict validator for profile pictures
profile_validator = FileValidator(config=strict_config)

# Relaxed validator for general uploads
general_validator = FileValidator()  # Default config
```

---

## Troubleshooting

### "Import could not be resolved" errors

If you see import errors for `uvicorn`, install the FastAPI extras:

```bash
pip install safeuploads[fastapi]
```

### python-magic errors

If you see `magic` library errors, ensure you have both the Python package and system library:

```bash
# macOS
brew install libmagic

# Ubuntu/Debian
sudo apt-get install libmagic1

# Python package
pip install python-magic
```

---

## Additional Resources

- [Main README](../README.md) - Full library documentation
- [API Reference](../docs/) - Detailed API documentation
- [Exception Hierarchy](../README.md#exception-handling) - All exception types
- [Configuration Guide](../README.md#configuration) - Security limits and options

---

## Contributing

Found an issue with the example or have a suggestion? Please open an issue or submit a pull request!

## License

This example is part of the safeuploads project and is licensed under the same terms.
