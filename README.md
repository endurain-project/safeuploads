# safeuploads

File upload hardening for Python 3.13+ services. `safeuploads` bundles a configurable validation pipeline that catches dangerous filenames, double extensions, Windows reserved names, and compressed payload attacks before you accept an upload.

## Features
- **Framework-agnostic**: Works with any async web framework (FastAPI, Starlette, Quart, etc.)
- Covers filename sanitization, Unicode spoofing checks, and Windows reserved name enforcement
- Validates extensions against allow/block lists generated from security enums
- Performs size, compression ratio, entry count, and nested archive checks for ZIP uploads
- Optionally inspects ZIP members for path traversal, symlinks, and archive bombs
- Integrates with `python-magic` for MIME sniffing and falls back to standard detection when unavailable
- Ships with defaults via `FileSecurityConfig` while allowing tuning through `SecurityLimits`
- **Exception-based API** with rich error context for precise error handling

## Installation

```bash
pip install safeuploads
```

For FastAPI integration:fc
```bash
pip install safeuploads[fastapi]
```

Requirements:
- Python 3.13+
- `python-magic` (installed automatically)
- FastAPI (optional, for UploadFile type support)
- Python's standard `logging` configuration to collect `safeuploads` diagnostics

## Quick Start

### FastAPI Example

```python
from fastapi import FastAPI, UploadFile, HTTPException, status
from safeuploads import FileValidator
from safeuploads.exceptions import FileValidationError

app = FastAPI()
validator = FileValidator()


@app.post("/images")
async def upload_image(file: UploadFile):
	try:
		await validator.validate_image_file(file)
	except FileValidationError as err:
		raise HTTPException(
			status_code=status.HTTP_400_BAD_REQUEST,
			detail=str(err)
		) from err

	# Continue with storage once validation passes
	return {"status": "accepted", "filename": file.filename}
```

### Framework-Agnostic Usage

The library works with any framework that provides file upload objects with `filename`, `size`, `read()`, and `seek()` methods:

```python
from safeuploads import FileValidator
from safeuploads.exceptions import (
    FileValidationError,
    FileSizeError,
    ExtensionSecurityError,
    ZipBombError,
)

validator = FileValidator()

# Handle specific exception types
try:
    await validator.validate_image_file(uploaded_file)
except ExtensionSecurityError as e:
    # Dangerous extension detected
    return {"error": "Invalid file type", "code": e.error_code}
except FileSizeError as e:
    # File too large
    return {"error": f"File exceeds {e.max_size} bytes", "code": e.error_code}
except FileValidationError as e:
    # Generic validation failure
    return {"error": str(e), "code": e.error_code}
```

## Configuration

- `FileSecurityConfig` holds the allow/block lists, MIME sets, and Windows reserved names
- `SecurityLimits` governs file sizes, compression ratios, archive depth, and other thresholds
- Configuration validation runs on module import to catch misconfigurations early

Override limits by adjusting the dataclass before instantiating the validator:

```python
from safeuploads import FileValidator, FileSecurityConfig

config = FileSecurityConfig()
config.limits.max_image_size = 10 * 1024 * 1024  # 10 MiB cap

validator = FileValidator(config=config)
```

## API Reference

### FileValidator

Main entry point for file validation.

**Methods:**

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `__init__` | `config: FileSecurityConfig \| None` | `FileValidator` | Initialize validator with optional custom config |
| `sanitize_filename` | `filename: str` | `str` | Sanitize filename, removing dangerous characters |
| `validate_image_file` | `file: UploadFile \| FileUpload` | `None` | Validate image file (raises exception on failure) |
| `validate_zip_file` | `file: UploadFile \| FileUpload` | `None` | Validate ZIP archive (raises exception on failure) |

**Example:**
```python
from safeuploads import FileValidator

validator = FileValidator()

# Sanitize a filename
safe_name = await validator.sanitize_filename("../../etc/passwd")
# Returns: "attachment"

# Validate an image
await validator.validate_image_file(file)  # Raises FileValidationError on failure

# Validate a ZIP
await validator.validate_zip_file(file)  # Raises FileValidationError on failure
```

---

### FileSecurityConfig

Configuration object for validators and security limits.

**Attributes:**

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `limits` | `SecurityLimits` | `SecurityLimits()` | Security limits for file sizes, ratios, etc. |
| `ALLOWED_EXTENSIONS` | `frozenset[str]` | Standard image extensions | Allowed file extensions |
| `BLOCKED_EXTENSIONS` | `frozenset[str]` | Dangerous extensions | Blocked file extensions |
| `COMPOUND_BLOCKED_EXTENSIONS` | `frozenset[str]` | `.tar.gz`, `.zip.exe`, etc. | Blocked compound extensions |
| `WINDOWS_RESERVED_NAMES` | `frozenset[str]` | `CON`, `PRN`, `AUX`, etc. | Windows reserved device names |
| `ALLOWED_IMAGE_MIMES` | `frozenset[str]` | Standard image MIME types | Allowed image MIME types |
| `SUSPICIOUS_ZIP_FILENAMES` | `frozenset[str]` | `.htaccess`, `.env`, etc. | Suspicious filenames in ZIPs |

**Methods:**

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `add_blocked_extensions` | `category: DangerousExtensionCategory` | `None` | Add extensions from category to block list |
| `remove_blocked_extensions` | `category: DangerousExtensionCategory` | `None` | Remove extensions from block list |
| `validate` | `None` | `None` | Validate configuration (called automatically) |

**Example:**
```python
from safeuploads import FileSecurityConfig
from safeuploads.enums import DangerousExtensionCategory

config = FileSecurityConfig()

# Modify limits
config.limits.max_image_size = 10 * 1024 * 1024  # 10MB

# Add additional blocked extensions
config.add_blocked_extensions(DangerousExtensionCategory.SCRIPTS)

# Remove blocked extension category
config.remove_blocked_extensions(DangerousExtensionCategory.ARCHIVES)

# Modify allowed extensions
config.ALLOWED_EXTENSIONS = frozenset([".jpg", ".png", ".webp"])
```

---

### SecurityLimits

Dataclass containing security thresholds.

**Attributes:**

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `max_filename_length` | `int` | `255` | Maximum filename length |
| `max_file_size` | `int` | `100 * 1024 * 1024` | Maximum file size (100MB) |
| `max_image_size` | `int` | `20 * 1024 * 1024` | Maximum image file size (20MB) |
| `max_zip_size` | `int` | `100 * 1024 * 1024` | Maximum ZIP file size (100MB) |
| `max_individual_file_size` | `int` | `50 * 1024 * 1024` | Max size for single file in ZIP (50MB) |
| `max_compression_ratio` | `int` | `100` | Maximum compression ratio (100:1) |
| `max_zip_entries` | `int` | `1000` | Maximum files in ZIP |
| `max_zip_depth` | `int` | `10` | Maximum directory nesting in ZIP |
| `zip_analysis_timeout` | `float` | `30.0` | ZIP analysis timeout (seconds) |

**Example:**
```python
from safeuploads.config import SecurityLimits, FileSecurityConfig

# Create custom limits
limits = SecurityLimits(
    max_image_size=5 * 1024 * 1024,  # 5MB
    max_compression_ratio=50,         # More conservative
    max_zip_entries=100,              # Fewer entries
)

config = FileSecurityConfig()
config.limits = limits
```

---

### Enums

#### DangerousExtensionCategory

Categories of dangerous file extensions.

**Values:**
- `EXECUTABLES` - `.exe`, `.dll`, `.com`, `.bat`, `.cmd`, `.scr`, `.pif`
- `SCRIPTS` - `.js`, `.vbs`, `.ps1`, `.sh`, `.bash`, `.php`, `.py`, `.rb`
- `ARCHIVES` - `.zip`, `.rar`, `.7z`, `.tar`, `.gz`, `.bz2`
- `OFFICE` - `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.pptx`
- `WEB` - `.html`, `.htm`, `.svg`, `.xml`

**Example:**
```python
from safeuploads.enums import DangerousExtensionCategory

# Get all executable extensions
exts = DangerousExtensionCategory.EXECUTABLES.extensions()
# Returns: {'.exe', '.dll', '.com', ...}
```

#### CompoundExtensionCategory

Categories of compound extensions.

**Values:**
- `COMPRESSED_ARCHIVES` - `.tar.gz`, `.tar.bz2`, `.tar.xz`
- `DOUBLE_EXTENSIONS` - `.pdf.exe`, `.jpg.exe`, `.zip.exe`

#### ImageExtensionCategory

Categories of image file extensions.

**Values:**
- `STANDARD_IMAGE` - `.jpg`, `.jpeg`, `.png`, `.gif`, `.bmp`, `.webp`
- `RAW_IMAGE` - `.raw`, `.cr2`, `.nef`, `.arw`, `.dng`
- `VECTOR_IMAGE` - `.svg`, `.eps`, `.ai`, `.pdf`

---

### Exception Classes Quick Reference

| Exception | When Raised | Key Attributes |
|-----------|-------------|----------------|
| `FileValidationError` | Base exception for all validation errors | `message`, `error_code`, `filename` |
| `FilenameSecurityError` | Dangerous filename patterns | `filename` |
| `UnicodeSecurityError` | Dangerous Unicode characters | `dangerous_chars` |
| `ExtensionSecurityError` | Blocked/disallowed extension | `extension`, `extension_type` |
| `WindowsReservedNameError` | Windows reserved device name | `reserved_name` |
| `FileTooLargeError` | File exceeds size limit | `file_size`, `max_size` |
| `EmptyFileError` | Zero-byte file | `filename` |
| `MimeTypeNotAllowedError` | MIME type not in allow list | `detected_mime`, `allowed_mimes` |
| `MimeTypeMismatchError` | MIME doesn't match extension | `detected_mime`, `expected_type` |
| `InvalidImageSignatureError` | Not a valid image file | `filename` |
| `CorruptedImageError` | Image file corrupted | `filename` |
| `ZipBombError` | Excessive compression ratio | `compression_ratio`, `max_ratio` |
| `TooManyEntriesError` | Too many files in ZIP | `entry_count`, `max_entries` |
| `ZipContentError` | Dangerous ZIP content | `threats` (list of strings) |
| `FileProcessingError` | Unexpected processing error | `message` |

See [Exception Hierarchy](#exception-hierarchy) for complete documentation.

---

### Error Code Constants

All error codes from the `ErrorCode` class:

**Filename Security:**
```python
FILENAME_EMPTY = "FILENAME_EMPTY"
UNICODE_SECURITY_ERROR = "UNICODE_SECURITY_ERROR"
EXTENSION_BLOCKED = "EXTENSION_BLOCKED"
COMPOUND_EXTENSION_BLOCKED = "COMPOUND_EXTENSION_BLOCKED"
EXTENSION_NOT_ALLOWED = "EXTENSION_NOT_ALLOWED"
WINDOWS_RESERVED_NAME = "WINDOWS_RESERVED_NAME"
```

**File Size:**
```python
FILE_EMPTY = "FILE_EMPTY"
FILE_TOO_LARGE = "FILE_TOO_LARGE"
IMAGE_TOO_LARGE = "IMAGE_TOO_LARGE"
```

**MIME Type:**
```python
MIME_NOT_ALLOWED = "MIME_NOT_ALLOWED"
MIME_MISMATCH = "MIME_MISMATCH"
MIME_DETECTION_FAILED = "MIME_DETECTION_FAILED"
```

**File Signature:**
```python
INVALID_IMAGE_SIGNATURE = "INVALID_IMAGE_SIGNATURE"
CORRUPTED_IMAGE = "CORRUPTED_IMAGE"
IMAGE_FORMAT_MISMATCH = "IMAGE_FORMAT_MISMATCH"
```

**Compression & ZIP:**
```python
ZIP_BOMB_DETECTED = "ZIP_BOMB_DETECTED"
ZIP_ENTRY_TOO_LARGE = "ZIP_ENTRY_TOO_LARGE"
ZIP_TOO_MANY_ENTRIES = "ZIP_TOO_MANY_ENTRIES"
ZIP_OVERALL_RATIO_HIGH = "ZIP_OVERALL_RATIO_HIGH"
ZIP_TIMEOUT = "ZIP_TIMEOUT"
ZIP_MEMORY_ERROR = "ZIP_MEMORY_ERROR"
ZIP_CONTENT_SECURITY_ERROR = "ZIP_CONTENT_SECURITY_ERROR"
ZIP_NESTED_ARCHIVE = "ZIP_NESTED_ARCHIVE"
ZIP_DIRECTORY_TRAVERSAL = "ZIP_DIRECTORY_TRAVERSAL"
ZIP_ABSOLUTE_PATH = "ZIP_ABSOLUTE_PATH"
ZIP_SYMLINK = "ZIP_SYMLINK"
ZIP_EXECUTABLE = "ZIP_EXECUTABLE"
```

**Processing:**
```python
FILE_READ_ERROR = "FILE_READ_ERROR"
PROCESSING_TIMEOUT = "PROCESSING_TIMEOUT"
UNEXPECTED_ERROR = "UNEXPECTED_ERROR"
```

---

## Exception Hierarchy

All validation exceptions inherit from `FileValidationError`, allowing you to catch all validation failures or handle specific cases:

```python
from safeuploads.exceptions import (
    FileValidationError,          # Base for all validation errors
    FilenameSecurityError,         # Filename security issues
    UnicodeSecurityError,          # Dangerous Unicode characters
    ExtensionSecurityError,        # Blocked or disallowed extensions
    WindowsReservedNameError,      # Windows reserved device names
    FileSizeError,                 # File size violations
    MimeTypeError,                 # MIME type issues
    FileSignatureError,            # File signature mismatches
    CompressionSecurityError,      # ZIP compression issues
    ZipBombError,                  # Potential zip bombs
    ZipContentError,               # Dangerous ZIP content
    FileProcessingError,           # Unexpected processing errors
)
```

### Exception Hierarchy Diagram

```
Exception
└── FileValidationError (base for all validation errors)
    ├── FilenameSecurityError (filename validation failures)
    │   ├── UnicodeSecurityError (dangerous Unicode characters)
    │   ├── ExtensionSecurityError (blocked extensions)
    │   └── WindowsReservedNameError (Windows reserved names)
    ├── FileSizeError (size limit violations)
    │   ├── FileTooLargeError (exceeds max size)
    │   └── EmptyFileError (zero-byte file)
    ├── MimeTypeError (MIME type validation)
    │   ├── MimeTypeNotAllowedError (not in allow list)
    │   └── MimeTypeMismatchError (doesn't match expected type)
    ├── FileSignatureError (file signature issues)
    │   ├── InvalidImageSignatureError (not a valid image)
    │   └── CorruptedImageError (corrupted image file)
    ├── CompressionSecurityError (compression attacks)
    │   ├── ZipBombError (excessive compression ratio)
    │   ├── TooManyEntriesError (too many files in archive)
    │   └── ZipContentError (dangerous ZIP content)
    └── FileProcessingError (unexpected errors)
```

### Exception Attributes Reference

**All exceptions include:**
- `message: str` - Human-readable error description
- `error_code: str` - Machine-readable code from `ErrorCode` enum
- `filename: str | None` - Name of the file that failed validation

**Specific exception attributes:**

| Exception | Additional Attributes | Description |
|-----------|----------------------|-------------|
| `UnicodeSecurityError` | `dangerous_chars: list[str]` | Detected dangerous Unicode characters |
| `ExtensionSecurityError` | `extension: str`<br>`extension_type: str` | Blocked extension and type (compound/blocked) |
| `WindowsReservedNameError` | `reserved_name: str` | Windows reserved name that was detected |
| `FileTooLargeError` | `file_size: int`<br>`max_size: int` | Actual and maximum allowed size in bytes |
| `MimeTypeNotAllowedError` | `detected_mime: str`<br>`allowed_mimes: list[str]` | Detected MIME type and allowed list |
| `MimeTypeMismatchError` | `detected_mime: str`<br>`expected_type: str` | Detected vs expected MIME type |
| `ZipBombError` | `compression_ratio: float`<br>`max_ratio: int` | Actual and maximum allowed compression ratio |
| `TooManyEntriesError` | `entry_count: int`<br>`max_entries: int` | Actual and maximum allowed entry count |
| `ZipContentError` | `threats: list[str]` | List of detected security threats |

### Error Code Reference

All exceptions include an `error_code` attribute from the `ErrorCode` enum. Use these for building user-friendly error messages or API responses:

**Filename Security Codes:**
- `FILENAME_EMPTY` - Empty or whitespace-only filename
- `UNICODE_SECURITY_ERROR` - Dangerous Unicode characters detected
- `EXTENSION_BLOCKED` - Extension in block list
- `COMPOUND_EXTENSION_BLOCKED` - Compound extension blocked (e.g., `.tar.gz`)
- `EXTENSION_NOT_ALLOWED` - Extension not in allow list
- `WINDOWS_RESERVED_NAME` - Windows reserved device name

**File Size Codes:**
- `FILE_EMPTY` - Zero-byte file
- `FILE_TOO_LARGE` - Exceeds maximum size
- `IMAGE_TOO_LARGE` - Image exceeds image-specific limit

**MIME Type Codes:**
- `MIME_NOT_ALLOWED` - MIME type not in allow list
- `MIME_MISMATCH` - MIME type doesn't match expected type
- `MIME_DETECTION_FAILED` - Failed to detect MIME type

**File Signature Codes:**
- `INVALID_IMAGE_SIGNATURE` - Not a valid image file
- `CORRUPTED_IMAGE` - Image file is corrupted
- `IMAGE_FORMAT_MISMATCH` - Image format doesn't match extension

**Compression & ZIP Codes:**
- `ZIP_BOMB_DETECTED` - Excessive compression ratio
- `ZIP_ENTRY_TOO_LARGE` - Single file in ZIP too large
- `ZIP_TOO_MANY_ENTRIES` - Too many files in archive
- `ZIP_OVERALL_RATIO_HIGH` - Overall ZIP compression ratio too high
- `ZIP_TIMEOUT` - ZIP analysis timed out
- `ZIP_MEMORY_ERROR` - Memory limit exceeded during ZIP analysis
- `ZIP_CONTENT_SECURITY_ERROR` - Dangerous content in ZIP (path traversal, symlinks, etc.)
- `ZIP_NESTED_ARCHIVE` - Nested archive detected
- `ZIP_DIRECTORY_TRAVERSAL` - Path traversal attempt
- `ZIP_ABSOLUTE_PATH` - Absolute path in ZIP entry
- `ZIP_SYMLINK` - Symlink detected
- `ZIP_EXECUTABLE` - Executable file detected

**Processing Error Codes:**
- `FILE_READ_ERROR` - Failed to read file
- `PROCESSING_TIMEOUT` - Validation timeout
- `UNEXPECTED_ERROR` - Unexpected error during validation

### Exception Handling Patterns

**Pattern 1: Catch All Validation Errors**

```python
from safeuploads.exceptions import FileValidationError

try:
    await validator.validate_image_file(file)
except FileValidationError as e:
    logger.warning("Validation failed", extra={
        "filename": e.filename,
        "error_code": e.error_code,
    })
    return {"error": str(e), "code": e.error_code}
```

**Pattern 2: Handle Specific Error Types**

```python
from safeuploads.exceptions import (
    FileSizeError,
    ExtensionSecurityError,
    UnicodeSecurityError,
    FileValidationError,
)

try:
    await validator.validate_image_file(file)
except FileSizeError as e:
    return {"error": "File too large", "max_size": e.max_size}
except ExtensionSecurityError as e:
    return {"error": "File type not allowed", "extension": e.extension}
except UnicodeSecurityError as e:
    return {"error": "Invalid filename characters"}
except FileValidationError as e:
    return {"error": "Validation failed", "code": e.error_code}
```

**Pattern 3: Different Handling for User vs System Errors**

```python
from safeuploads.exceptions import (
    FileValidationError,
    FileProcessingError,
)

try:
    await validator.validate_image_file(file)
except FileProcessingError as e:
    # System error - log but don't expose details
    logger.error("Processing error", exc_info=True)
    return {"error": "Unable to process file"}
except FileValidationError as e:
    # User error - safe to show
    return {"error": str(e), "code": e.error_code}
```

**Pattern 4: Build Custom Error Messages by Code**

```python
from safeuploads.exceptions import FileValidationError

ERROR_MESSAGES = {
    "FILE_TOO_LARGE": "Your file is too big. Maximum size is 5MB.",
    "EXTENSION_BLOCKED": "This file type is not allowed for security reasons.",
    "ZIP_BOMB_DETECTED": "This file was rejected for security reasons.",
    "UNICODE_SECURITY_ERROR": "Filename contains invalid characters.",
}

try:
    await validator.validate_image_file(file)
except FileValidationError as e:
    user_message = ERROR_MESSAGES.get(
        e.error_code,
        "File validation failed. Please try a different file."
    )
    logger.warning("Validation failed", extra={
        "error_code": e.error_code,
        "filename": file.filename,
    })
    return {"error": user_message}
```

**Pattern 5: Access Rich Context for Logging**

```python
from safeuploads.exceptions import ZipBombError, ZipContentError

try:
    await validator.validate_zip_file(file)
except ZipBombError as e:
    logger.warning("Zip bomb detected", extra={
        "filename": e.filename,
        "compression_ratio": e.compression_ratio,
        "max_ratio": e.max_ratio,
    })
    return {"error": "File rejected for security reasons"}
except ZipContentError as e:
    logger.warning("Dangerous ZIP content", extra={
        "filename": e.filename,
        "threats": e.threats,
        "threat_count": len(e.threats),
    })
    return {"error": f"File contains {len(e.threats)} security violations"}
```

## Validators & Inspectors

- `UnicodeSecurityValidator` removes null bytes, control characters, and Unicode confusables
- `ExtensionSecurityValidator` rejects compound or blocked extensions defined by `DangerousExtensionCategory` and `CompoundExtensionCategory` enums
- `WindowsSecurityValidator` prevents reserved device names and path traversal tricks
- `CompressionSecurityValidator` enforces size and ratio limits to detect zip bombs
- `ZipContentInspector` optionally walks ZIP members to catch nested archives, symlinks, and path traversal attempts

## Advanced Usage

### Custom Configuration

Create multiple validator instances with different security profiles:

```python
from safeuploads import FileValidator, FileSecurityConfig
from safeuploads.enums import DangerousExtensionCategory

# Strict validator for public uploads
strict_config = FileSecurityConfig()
strict_config.limits.max_image_size = 2 * 1024 * 1024  # 2MB
strict_config.limits.max_compression_ratio = 50  # Conservative
strict_validator = FileValidator(config=strict_config)

# Permissive validator for internal use
permissive_config = FileSecurityConfig()
permissive_config.limits.max_image_size = 50 * 1024 * 1024  # 50MB
permissive_config.limits.max_compression_ratio = 200
# Allow specific extensions for internal use
permissive_config.remove_blocked_extensions(
    DangerousExtensionCategory.ARCHIVES
)
permissive_validator = FileValidator(config=permissive_config)

@app.post("/public/upload")
async def public_upload(file: UploadFile):
    await strict_validator.validate_image_file(file)
    # ...

@app.post("/admin/upload")
async def admin_upload(file: UploadFile):
    await permissive_validator.validate_zip_file(file)
    # ...
```

### Dynamic Configuration Based on User Role

```python
from safeuploads import FileValidator, FileSecurityConfig

def get_validator_for_user(user_role: str) -> FileValidator:
    config = FileSecurityConfig()
    
    if user_role == "admin":
        config.limits.max_image_size = 20 * 1024 * 1024
        config.limits.max_zip_size = 100 * 1024 * 1024
    elif user_role == "premium":
        config.limits.max_image_size = 10 * 1024 * 1024
        config.limits.max_zip_size = 50 * 1024 * 1024
    else:  # free users
        config.limits.max_image_size = 2 * 1024 * 1024
        config.limits.max_zip_size = 10 * 1024 * 1024
    
    return FileValidator(config=config)

@app.post("/upload")
async def upload(file: UploadFile, current_user: User):
    validator = get_validator_for_user(current_user.role)
    await validator.validate_image_file(file)
    # ...
```

### Batch Validation with Progress Tracking

```python
import asyncio
from typing import List
from safeuploads import FileValidator
from safeuploads.exceptions import FileValidationError

async def validate_batch_with_results(
    files: List[UploadFile]
) -> dict:
    validator = FileValidator()
    results = {"success": [], "failed": []}
    
    async def validate_one(file: UploadFile):
        try:
            await validator.validate_image_file(file)
            results["success"].append(file.filename)
        except FileValidationError as e:
            results["failed"].append({
                "filename": file.filename,
                "error": str(e),
                "code": e.error_code,
            })
    
    # Validate all files concurrently
    await asyncio.gather(*[validate_one(f) for f in files])
    return results

@app.post("/batch-upload")
async def batch_upload(files: List[UploadFile]):
    results = await validate_batch_with_results(files)
    return {
        "total": len(files),
        "successful": len(results["success"]),
        "failed": len(results["failed"]),
        "details": results,
    }
```

### Integration with Dependency Injection (FastAPI)

```python
from typing import Annotated
from fastapi import Depends, FastAPI
from safeuploads import FileValidator, FileSecurityConfig

def get_validator() -> FileValidator:
    """Dependency that provides a configured validator."""
    config = FileSecurityConfig()
    # Configure from environment or settings
    return FileValidator(config=config)

ValidatorDep = Annotated[FileValidator, Depends(get_validator)]

@app.post("/upload")
async def upload(file: UploadFile, validator: ValidatorDep):
    await validator.validate_image_file(file)
    return {"status": "accepted"}
```

### Custom Allowed Extensions

```python
from safeuploads import FileSecurityConfig
from safeuploads.enums import ImageExtensionCategory

config = FileSecurityConfig()

# Start with standard image extensions
allowed = set(ImageExtensionCategory.STANDARD_IMAGE.extensions())

# Add WebP and AVIF for modern browsers
allowed.update([".webp", ".avif"])

# Remove TIFF (too large, rarely needed)
allowed.discard(".tiff")
allowed.discard(".tif")

config.ALLOWED_EXTENSIONS = frozenset(allowed)
```

### Validation with File Type Detection

```python
from safeuploads import FileValidator
from safeuploads.exceptions import MimeTypeMismatchError

@app.post("/upload")
async def upload(file: UploadFile):
    validator = FileValidator()
    
    try:
        # Will detect actual MIME type and verify it's an image
        await validator.validate_image_file(file)
    except MimeTypeMismatchError as e:
        # Someone tried to upload a .exe renamed as .jpg
        logger.warning(
            "MIME type mismatch",
            extra={
                "filename": file.filename,
                "detected": e.detected_mime,
                "expected": e.expected_type,
            }
        )
        raise HTTPException(
            status_code=400,
            detail="File type doesn't match extension"
        )
```

### Pre-validation Filename Sanitization

```python
from safeuploads import FileValidator

@app.post("/upload")
async def upload(file: UploadFile):
    validator = FileValidator()
    
    # Sanitize filename before validation
    # This removes dangerous characters but doesn't raise errors
    sanitized_filename = await validator.sanitize_filename(file.filename)
    
    # Replace original filename with sanitized version
    file.filename = sanitized_filename
    
    # Now validate with sanitized name
    await validator.validate_image_file(file)
    
    # Save with safe filename
    save_path = f"uploads/{sanitized_filename}"
    # ...
```

### Conditional ZIP Content Inspection

```python
from safeuploads import FileSecurityConfig

# Skip deep content inspection for performance
fast_config = FileSecurityConfig()
# Only basic compression checks, no content inspection
validator_fast = FileValidator(config=fast_config)

# Enable thorough content inspection for untrusted sources
secure_config = FileSecurityConfig()
# ZipContentInspector will scan for path traversal, symlinks, etc.
validator_secure = FileValidator(config=secure_config)

@app.post("/trusted/upload")
async def trusted_upload(file: UploadFile):
    # Faster validation for trusted users
    await validator_fast.validate_zip_file(file)
    # ...

@app.post("/public/upload")
async def public_upload(file: UploadFile):
    # Thorough validation for public uploads
    await validator_secure.validate_zip_file(file)
    # ...
```

### Logging Configuration

```python
import logging
from safeuploads import FileValidator

# Configure safeuploads logger
logger = logging.getLogger("safeuploads")
logger.setLevel(logging.WARNING)  # Only warnings and errors

# Add structured logging handler
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
))
logger.addHandler(handler)

# For development: enable debug logging
if app.config["DEBUG"]:
    logger.setLevel(logging.DEBUG)
```

## Performance

### Benchmark Results

Performance tests are included in `tests/test_performance.py`. Run with:
```bash
pytest tests/test_performance.py -v -m performance
```

**Typical performance on modern hardware:**

| Operation | File Size | Time | Throughput |
|-----------|-----------|------|------------|
| Filename sanitization | N/A | < 0.1ms | ~10,000 files/s |
| Image validation | 100KB | ~50-100ms | ~20 files/s |
| Image validation | 1MB | ~100-200ms | ~10 files/s |
| ZIP validation | 10 files | ~100ms | ~10 archives/s |
| ZIP validation | 50 files | ~300ms | ~3 archives/s |
| Concurrent (10 images) | 100KB each | ~500ms | ~20 files/s |

*Note: Performance varies by hardware, file content, and compression ratios.*

### Memory Usage

- **Streaming validation**: Files are not loaded entirely into memory
- **10MB image**: Validates in < 1s with minimal memory overhead
- **Large ZIPs**: Content inspection uses streaming to avoid memory spikes
- **Concurrent validation**: Multiple files can be validated simultaneously using `asyncio.gather()`

### Optimization Tips

**1. Adjust Security Limits Based on Use Case**

For high-throughput scenarios, tune limits to your needs:

```python
from safeuploads.config import SecurityLimits, FileSecurityConfig

# Faster validation with stricter limits
fast_limits = SecurityLimits(
    max_image_size=2 * 1024 * 1024,  # 2MB max
    max_zip_size=10 * 1024 * 1024,   # 10MB max
    max_zip_entries=100,              # Fewer entries
    zip_analysis_timeout=2.0,         # Faster timeout
    max_compression_ratio=20,         # Lower ratio
)

config = FileSecurityConfig()
config.limits = fast_limits
validator = FileValidator(config=config)
```

**2. Use Concurrent Validation for Batch Uploads**

```python
import asyncio

async def validate_batch(files: list[UploadFile]):
    validator = FileValidator()
    tasks = [validator.validate_image_file(f) for f in files]
    await asyncio.gather(*tasks)  # Validate concurrently
```

**3. Profile Your Specific Workload**

Different file types and sizes have different performance characteristics:
- Small files (< 100KB): Overhead dominated, very fast
- Large files (> 10MB): I/O dominated, slower
- High compression ratios: ZIP inspection takes longer
- Many ZIP entries (> 100): Linear time per entry

**4. Recommended File Size Limits**

Based on performance testing and security considerations:

| File Type | Recommended Max | Conservative Max | Notes |
|-----------|-----------------|------------------|-------|
| Profile images | 2-5MB | 1MB | Most images < 2MB |
| General images | 10-20MB | 5MB | Balance usability/security |
| ZIP archives | 50-100MB | 20MB | Depends on use case |
| Individual files in ZIP | 50MB | 10MB | Prevents huge single files |

**5. Performance vs. Security Trade-offs**

Tighter limits = faster validation:
- Lower `max_compression_ratio`: Faster zip bomb detection
- Fewer `max_zip_entries`: Less inspection time
- Smaller `max_zip_size`: Less data to process
- Shorter `zip_analysis_timeout`: Fail faster on slow operations

However, overly strict limits may reject legitimate files. Test with your actual workload to find the right balance.

### Monitoring Performance

Enable timing logs to monitor validation performance:

```python
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("safeuploads")
logger.setLevel(logging.DEBUG)  # Shows detailed timing info
```

### Performance Regression Tests

The test suite includes baseline performance tests that fail if performance degrades significantly:
- `test_baseline_image_validation_speed`: 1MB image < 200ms avg
- `test_baseline_zip_validation_speed`: 50-file ZIP < 300ms avg

Run these regularly to catch performance regressions:
```bash
pytest tests/test_performance.py::TestPerformanceRegression -v
```

## Troubleshooting

### Common Issues and Solutions

#### 1. `python-magic` Installation Issues

**Problem**: ImportError or MagicException when using MIME detection

**Solution on macOS**:
```bash
brew install libmagic
pip install python-magic
```

**Solution on Ubuntu/Debian**:
```bash
sudo apt-get install libmagic1
pip install python-magic
```

**Solution on Windows**:
```bash
pip install python-magic-bin  # Includes libmagic binary
```

**Fallback**: If you can't install libmagic, safeuploads will fall back to Python's built-in `mimetypes` module with reduced accuracy.

---

#### 2. Windows Reserved Name Errors

**Problem**: `WindowsReservedNameError` for filenames like "COM1.txt" or "CON.zip"

**Explanation**: Windows reserves certain device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9) that cannot be used as filenames. safeuploads blocks these to prevent issues when deploying cross-platform.

**Solution**: 
- Reject the file and ask user to rename
- Or use `sanitize_filename()` to automatically remove reserved names:

```python
from safeuploads import FileValidator

validator = FileValidator()
safe_name = await validator.sanitize_filename("CON.txt")  # Returns "attachment.txt"
```

---

#### 3. ZIP Bomb Detection False Positives

**Problem**: Legitimate ZIPs rejected with `ZipBombError`

**Explanation**: Text files and code often compress at high ratios (100:1 or more). Default limit is 100:1.

**Solution**: Increase the compression ratio limit for your use case:

```python
from safeuploads import FileSecurityConfig

config = FileSecurityConfig()
config.limits.max_compression_ratio = 200  # Allow higher ratios
validator = FileValidator(config=config)
```

**Security Note**: Higher ratios increase zip bomb risk. Consider also limiting `max_individual_file_size` and `max_zip_entries`.

---

#### 4. Performance Issues with Large Files

**Problem**: Validation takes too long for large files or many files

**Solutions**:

**Reduce file size limits**:
```python
config.limits.max_image_size = 5 * 1024 * 1024  # 5MB max
config.limits.max_zip_entries = 100  # Fewer entries
```

**Use concurrent validation** for batches:
```python
import asyncio
results = await asyncio.gather(*[validator.validate_image_file(f) for f in files])
```

**Skip content inspection** for trusted sources:
```python
# CompressionSecurityValidator runs, but ZipContentInspector is optional
# Check your configuration if content inspection is needed
```

**Profile your workload**:
```python
import time

start = time.time()
await validator.validate_image_file(file)
print(f"Validation took {time.time() - start:.2f}s")
```

---

#### 5. Unicode Filename Issues

**Problem**: `UnicodeSecurityError` for filenames with emoji or international characters

**Explanation**: safeuploads blocks dangerous Unicode like:
- Right-to-left override (U+202E) - used to disguise extensions
- Zero-width characters (U+200B, U+200C, U+200D)
- Bidirectional control characters

Safe Unicode (emoji, international characters) is allowed.

**Solution**: If you're getting false positives, file an issue with example filename.

---

#### 6. MIME Type Mismatches

**Problem**: `MimeTypeMismatchError` even though file seems correct

**Explanation**: Extension doesn't match actual file content (e.g., .jpg file is actually a .png)

**Debug**:
```python
import magic

mime = magic.Magic(mime=True)
detected = mime.from_buffer(await file.read(2048))
print(f"Detected MIME: {detected}")
await file.seek(0)  # Reset for validation
```

**Solution**: 
- Accept the detected type if it's safe
- Or reject and ask user to re-export with correct format

---

#### 7. Empty File Errors

**Problem**: `EmptyFileError` for files that aren't empty

**Cause**: File pointer not at beginning, or `size` attribute is 0

**Solution**: Ensure file pointer is at start before validation:
```python
await file.seek(0)
await validator.validate_image_file(file)
```

---

#### 8. Memory Issues with Large ZIPs

**Problem**: MemoryError or excessive memory usage during ZIP validation

**Solution**: 
- Reduce `max_zip_size` limit
- Reduce `max_individual_file_size` 
- Enable `zip_analysis_timeout` to fail fast:

```python
config.limits.max_zip_size = 50 * 1024 * 1024  # 50MB max
config.limits.max_individual_file_size = 20 * 1024 * 1024
config.limits.zip_analysis_timeout = 5.0  # 5 second timeout
```

---

### FAQ

**Q: Can I use safeuploads with synchronous frameworks like Flask?**

A: The API is async-first, but you can use `asyncio.run()`:
```python
import asyncio

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]
    try:
        asyncio.run(validator.validate_image_file(file))
    except FileValidationError as e:
        return {"error": str(e)}, 400
```

**Q: Does safeuploads scan for viruses/malware?**

A: No. safeuploads focuses on structural security (filenames, compression, file types). For malware scanning, integrate with ClamAV or similar.

**Q: Can I validate files without reading content?**

A: Filename validation (`sanitize_filename`) works without reading. Full validation requires reading file content for MIME detection and signature verification.

**Q: How do I allow additional MIME types?**

A: Modify `ALLOWED_IMAGE_MIMES` or configure your own allow list:
```python
config.ALLOWED_IMAGE_MIMES = frozenset([
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/avif",  # Add new type
])
```

**Q: What's the difference between `validate_image_file()` and `validate_zip_file()`?**

A: 
- `validate_image_file()`: Checks filename, size, extension, MIME type, and image signature
- `validate_zip_file()`: Checks filename, size, compression ratio, entry count, and optionally inspects ZIP content for security threats

**Q: Can I disable specific validators?**

A: Validators are internal to `FileValidator`. To skip certain checks, modify the configuration:
```python
# Remove blocked extensions to allow all types
config.BLOCKED_EXTENSIONS = frozenset()

# Increase limits to effectively disable checks
config.limits.max_compression_ratio = 10000
```

**Q: How do I test that my configuration is working?**

A: Use the test suite as examples:
```python
from safeuploads.exceptions import ExtensionSecurityError
import pytest

async def test_my_config():
    config = FileSecurityConfig()
    config.BLOCKED_EXTENSIONS = frozenset([".exe"])
    validator = FileValidator(config=config)
    
    # Should raise ExtensionSecurityError
    with pytest.raises(ExtensionSecurityError):
        await validator.validate_image_file(exe_file)
```

**Q: Is safeuploads production-ready?**

A: safeuploads v0.1.0 is pre-release. It has comprehensive test coverage (87.89%), performance testing, and security auditing. v1.0.0 will be the production-stable release.

**Q: How do I report security vulnerabilities?**

A: Email security issues privately to the maintainers. Do not open public issues for security vulnerabilities.

---

## Security Best Practices

safeuploads is designed with security in mind, but proper deployment requires following best practices for error handling, logging, and monitoring.

### 1. Sanitize User-Facing Error Messages

While safeuploads exceptions are safe, **production APIs should use generic messages** to avoid information disclosure:

```python
from safeuploads.exceptions import (
    FileValidationError,
    ZipBombError,
    ZipContentError,
)

@app.post("/upload")
async def upload(file: UploadFile):
    try:
        await validator.validate_image_file(file)
    except ZipBombError as e:
        # Log full details internally
        logger.warning("Zip bomb detected", extra={
            "filename": e.filename,
            "ratio": e.compression_ratio,
            "user_id": get_current_user_id(),
        })
        # Return generic message to user
        return JSONResponse(
            status_code=400,
            content={
                "error": "file_rejected",
                "message": "File failed security validation",
                "code": e.error_code
            }
        )
    except ZipContentError as e:
        # Log all threats
        logger.warning("Malicious ZIP content", extra={
            "filename": e.filename,
            "threats": e.threats,
        })
        # Return sanitized count
        return JSONResponse(
            status_code=400,
            content={
                "error": "file_rejected",
                "message": f"File contains {len(e.threats)} security violations",
                "code": e.error_code
            }
        )
    except FileValidationError as e:
        # Generic validation errors can use default message
        return JSONResponse(
            status_code=400,
            content={
                "error": "validation_failed",
                "message": str(e),
                "code": e.error_code
            }
        )
```

### 2. Never Expose Stack Traces to Users

Use global exception handlers to catch unexpected errors:

```python
from fastapi import Request
from fastapi.responses import JSONResponse

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Log full error internally
    logger.error(
        "Unexpected error during request",
        exc_info=True,
        extra={"path": request.url.path}
    )
    # Return generic message
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"}
    )
```

### 3. Implement Rate Limiting

Prevent security enumeration and DoS attacks:

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/upload")
@limiter.limit("10/minute")  # Max 10 uploads per minute per IP
async def upload(file: UploadFile):
    await validator.validate_image_file(file)
    # ...
```

**Why**: Rate limiting prevents:
- Systematic probing of compression ratio limits
- Error message harvesting
- ZIP bomb attempts
- Brute-force filename attacks

### 4. Monitor Security Events

Configure structured logging and send to SIEM:

```python
import logging.handlers

# Configure safeuploads logger
logger = logging.getLogger("safeuploads")
logger.setLevel(logging.WARNING)  # Capture security events

# Send to syslog/SIEM
siem_handler = logging.handlers.SysLogHandler(
    address=('siem.example.com', 514)
)
siem_handler.setFormatter(logging.Formatter(
    '%(name)s - %(levelname)s - %(message)s'
))
logger.addHandler(siem_handler)
```

**Monitor these security events:**
- Repeated validation failures from same IP
- Zip bomb detection attempts
- Path traversal patterns in filenames
- Windows reserved name abuse
- Unusual compression ratios
- Executable uploads

**SIEM Query Example** (Splunk):
```
source="safeuploads" 
(error_type="zip_bomb_detected" OR 
 error_type="unicode_security" OR 
 error_type="windows_reserved_name")
| stats count by src_ip, filename
| where count > 10
```

### 5. Use Error Codes, Not Messages

Build user interfaces around error codes for consistency:

```python
# Define user-friendly messages
ERROR_MESSAGES = {
    "FILE_TOO_LARGE": "Please upload a smaller file (maximum 5MB)",
    "EXTENSION_BLOCKED": "This file type is not allowed",
    "ZIP_BOMB_DETECTED": "File rejected for security reasons",
    "UNICODE_SECURITY_ERROR": "Filename contains invalid characters",
    "WINDOWS_RESERVED_NAME": "Please rename the file",
}

@app.post("/upload")
async def upload(file: UploadFile):
    try:
        await validator.validate_image_file(file)
    except FileValidationError as e:
        user_message = ERROR_MESSAGES.get(
            e.error_code,
            "File validation failed. Please try a different file."
        )
        logger.warning("Validation failed", extra={
            "error_code": e.error_code,
            "filename": file.filename,
        })
        return {"error": user_message, "code": e.error_code}
```

### 6. Secure File Storage

safeuploads validates files, but **you must also secure storage**:

```python
import secrets
from pathlib import Path

@app.post("/upload")
async def upload(file: UploadFile):
    await validator.validate_image_file(file)
    
    # Generate random filename to prevent path traversal
    random_name = secrets.token_urlsafe(16)
    extension = Path(file.filename).suffix.lower()
    safe_filename = f"{random_name}{extension}"
    
    # Store in dedicated uploads directory (outside web root)
    upload_dir = Path("/var/uploads")
    save_path = upload_dir / safe_filename
    
    # Ensure path is within upload directory
    if not save_path.resolve().is_relative_to(upload_dir.resolve()):
        raise ValueError("Invalid file path")
    
    # Save file
    with open(save_path, "wb") as f:
        content = await file.read()
        f.write(content)
    
    return {"filename": safe_filename}
```

### 7. Set Appropriate Security Limits

Tune limits based on your use case:

**Public-facing applications:**
```python
config = FileSecurityConfig()
config.limits.max_image_size = 2 * 1024 * 1024      # Conservative 2MB
config.limits.max_compression_ratio = 50             # Lower ratio
config.limits.max_zip_entries = 100                  # Fewer entries
config.limits.zip_analysis_timeout = 5.0             # Fail fast
```

**Internal/trusted applications:**
```python
config = FileSecurityConfig()
config.limits.max_image_size = 20 * 1024 * 1024     # Larger files OK
config.limits.max_compression_ratio = 200            # Higher ratios
config.limits.max_zip_entries = 1000                 # More entries
```

### 8. Regular Security Audits

Periodically review:
- Upload logs for suspicious patterns
- Failed validation attempts
- Unusual file sizes or compression ratios
- Performance metrics (could indicate DoS)

```python
# Example: Daily security report
@app.get("/admin/security-report")
async def security_report():
    # Query logs for security events in last 24h
    events = query_logs({
        "logger": "safeuploads",
        "level": "WARNING",
        "time_range": "24h",
    })
    
    return {
        "total_events": len(events),
        "zip_bombs": count_by_type(events, "zip_bomb_detected"),
        "unicode_attacks": count_by_type(events, "unicode_security"),
        "top_ips": get_top_ips(events, limit=10),
    }
```

### 9. Defense in Depth

safeuploads is **one layer** of defense. Also implement:

**Network Security:**
- WAF (Web Application Firewall)
- DDoS protection
- IP reputation filtering

**Application Security:**
- Content Security Policy (CSP)
- CORS restrictions
- Authentication & authorization

**File Security:**
- Virus/malware scanning (ClamAV)
- Image re-encoding (prevents steganography)
- Metadata stripping (privacy)

**Example with antivirus:**
```python
import subprocess

@app.post("/upload")
async def upload(file: UploadFile):
    # Step 1: Validate with safeuploads
    await validator.validate_image_file(file)
    
    # Step 2: Save to temporary location
    temp_path = f"/tmp/{secrets.token_urlsafe(16)}"
    with open(temp_path, "wb") as f:
        f.write(await file.read())
    
    # Step 3: Scan with ClamAV
    result = subprocess.run(
        ["clamscan", "--no-summary", temp_path],
        capture_output=True
    )
    if result.returncode != 0:
        os.remove(temp_path)
        raise HTTPException(400, "File rejected by antivirus")
    
    # Step 4: Move to final location
    final_path = f"/var/uploads/{safe_filename}"
    shutil.move(temp_path, final_path)
```

### 10. Incident Response Plan

Prepare for security incidents:

**Detection:**
- Monitor safeuploads warnings
- Track failed upload patterns
- Alert on threshold breaches

**Response:**
- Block offending IPs
- Review uploaded files
- Check for successful attacks
- Investigate user accounts

**Recovery:**
- Quarantine suspicious files
- Restore from backups if needed
- Update security rules
- Patch vulnerabilities

**Example alert:**
```python
# Alert if >10 zip bombs from same IP in 1 hour
@app.middleware("http")
async def security_monitor(request: Request, call_next):
    ip = request.client.host
    
    # Check recent failures
    failures = redis.get(f"failures:{ip}")
    if failures and int(failures) > 10:
        logger.critical(f"Possible attack from {ip}")
        send_alert_to_security_team(ip, failures)
        return JSONResponse(
            status_code=429,
            content={"error": "Too many requests"}
        )
    
    response = await call_next(request)
    return response
```

---

## Current Status (v0.1.0)

- **Framework-agnostic design**: Works with any async web framework
- **Exception-based API**: Rich error context with specific exception types
- Image and ZIP validation paths fully implemented
- Configuration validation runs on import to surface misconfigurations early
- Structured logging with Python's `logging` package - enable the `safeuploads` logger to capture debug details
- FastAPI is an optional dependency - install with `pip install safeuploads[fastapi]` for direct integration

## Contributing

1. Clone the repository and install dependencies with Poetry or pip.
2. Add or adapt validators in `safeuploads/validators/` and inspectors in `safeuploads/inspectors/`.
3. Keep security checks isolated per class and update `FileSecurityConfig` when adding new knobs.
4. Include unit tests demonstrating both safe and malicious payload handling before opening a PR.

