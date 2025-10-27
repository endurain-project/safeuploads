"""
FastAPI Integration Example for safeuploads.

Complete working example showing how to integrate safeuploads with FastAPI,
including exception handling, custom error responses, and configuration.
"""

import uvicorn

from fastapi import FastAPI, HTTPException, UploadFile, status
from fastapi.responses import JSONResponse

from safeuploads import FileValidator
from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.exceptions import (
    ExtensionSecurityError,
    FileSizeError,
    FileValidationError,
    MimeTypeError,
    UnicodeSecurityError,
    WindowsReservedNameError,
    ZipBombError,
    ZipContentError,
)

# Initialize FastAPI app
app = FastAPI(
    title="SafeUploads FastAPI Example",
    description="Example API demonstrating safeuploads integration",
    version="1.0.0",
)

# Create custom security limits for stricter validation
strict_limits = SecurityLimits(
    max_image_size=2 * 1024 * 1024,  # 2MB for images
    max_zip_size=5 * 1024 * 1024,  # 5MB for ZIPs
    max_compression_ratio=50,  # Lower ratio for safety
    max_zip_entries=50,  # Fewer entries allowed
    zip_analysis_timeout=3.0,  # Faster timeout
)

# Create custom configuration with strict limits
strict_config = FileSecurityConfig()
strict_config.limits = strict_limits

# Initialize validators
default_validator = FileValidator()  # Uses default config
strict_validator = FileValidator(config=strict_config)


@app.exception_handler(FileValidationError)
async def file_validation_exception_handler(request, exc: FileValidationError):
    """
    Global exception handler for all file validation errors.

    Converts safeuploads exceptions to HTTP responses with appropriate
    status codes and detailed error information.
    """
    # Map exception types to HTTP status codes
    status_code = status.HTTP_400_BAD_REQUEST

    # Special handling for different exception types
    if isinstance(exc, FileSizeError):
        detail = {
            "error": "file_too_large",
            "message": str(exc),
            "size": exc.size,
            "max_size": exc.max_size,
            "error_code": exc.error_code,
        }
    elif isinstance(exc, MimeTypeError):
        detail = {
            "error": "invalid_mime_type",
            "message": str(exc),
            "detected_mime": exc.detected_mime,
            "allowed_mimes": list(exc.allowed_mimes),
            "error_code": exc.error_code,
        }
    elif isinstance(exc, ZipBombError):
        detail = {
            "error": "zip_bomb_detected",
            "message": str(exc),
            "compression_ratio": exc.compression_ratio,
            "error_code": exc.error_code,
        }
    elif isinstance(exc, ZipContentError):
        detail = {
            "error": "dangerous_zip_content",
            "message": str(exc),
            "threats": exc.threats,
            "error_code": exc.error_code,
        }
    elif isinstance(
        exc, (UnicodeSecurityError, ExtensionSecurityError, WindowsReservedNameError)
    ):
        detail = {
            "error": "filename_security_violation",
            "message": str(exc),
            "filename": exc.filename,
            "error_code": exc.error_code,
        }
    else:
        # Generic file validation error
        detail = {
            "error": "validation_failed",
            "message": str(exc),
            "error_code": getattr(exc, "error_code", None),
        }

    return JSONResponse(status_code=status_code, content=detail)


@app.post("/upload/image")
async def upload_image(file: UploadFile):
    """
    Upload and validate an image file.

    Uses default validator configuration.
    """
    # Validate the uploaded file
    await default_validator.validate_image_file(file)

    # If we get here, validation passed
    return {
        "status": "success",
        "message": "Image uploaded successfully",
        "filename": file.filename,
        "size": file.size,
    }


@app.post("/upload/image/strict")
async def upload_image_strict(file: UploadFile):
    """
    Upload and validate an image file with strict limits.

    Uses strict validator with tighter size limits.
    """
    try:
        await strict_validator.validate_image_file(file)
    except FileSizeError as e:
        # Custom handling for size errors with helpful message
        if e.max_size and e.size:
            message = (
                f"Image exceeds {e.max_size / 1024 / 1024:.1f}MB "
                f"limit (got {e.size / 1024 / 1024:.1f}MB)"
            )
            max_size_mb = e.max_size / 1024 / 1024
        else:
            message = str(e)
            max_size_mb = None

        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={
                "error": "file_too_large",
                "message": message,
                "max_size_mb": max_size_mb,
            },
        ) from e

    return {
        "status": "success",
        "message": "Image uploaded successfully with strict validation",
        "filename": file.filename,
        "size": file.size,
    }


@app.post("/upload/zip")
async def upload_zip(file: UploadFile):
    """
    Upload and validate a ZIP archive.

    Performs comprehensive security checks including zip bomb detection
    and content inspection.
    """
    await default_validator.validate_zip_file(file)

    return {
        "status": "success",
        "message": "ZIP file uploaded and validated successfully",
        "filename": file.filename,
        "size": file.size,
    }


@app.post("/upload/multiple")
async def upload_multiple(files: list[UploadFile]):
    """
    Upload multiple files with individual validation.

    Shows how to handle batch uploads with per-file error reporting.
    """
    results = []

    for file in files:
        try:
            # Determine file type and validate accordingly
            if file.filename and file.filename.lower().endswith(".zip"):
                await default_validator.validate_zip_file(file)
                file_type = "zip"
            else:
                await default_validator.validate_image_file(file)
                file_type = "image"

            results.append(
                {
                    "filename": file.filename,
                    "status": "success",
                    "type": file_type,
                    "size": file.size,
                }
            )
        except FileValidationError as e:
            # Continue processing other files even if one fails
            results.append(
                {
                    "filename": file.filename,
                    "status": "failed",
                    "error": str(e),
                    "error_code": getattr(e, "error_code", None),
                }
            )

    # Check if any files succeeded
    successful = [r for r in results if r["status"] == "success"]
    failed = [r for r in results if r["status"] == "failed"]

    return {
        "status": "partial" if failed else "success",
        "total": len(files),
        "successful": len(successful),
        "failed": len(failed),
        "results": results,
    }


@app.get("/config")
async def get_config():
    """
    Get current validator configuration.

    Shows how to expose configuration for debugging or documentation.
    """
    return {
        "default": {
            "max_image_size": default_validator.config.limits.max_image_size,
            "max_zip_size": default_validator.config.limits.max_zip_size,
            "max_compression_ratio": default_validator.config.limits.max_compression_ratio,
            "max_zip_entries": default_validator.config.limits.max_zip_entries,
        },
        "strict": {
            "max_image_size": strict_validator.config.limits.max_image_size,
            "max_zip_size": strict_validator.config.limits.max_zip_size,
            "max_compression_ratio": strict_validator.config.limits.max_compression_ratio,
            "max_zip_entries": strict_validator.config.limits.max_zip_entries,
        },
    }


@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "SafeUploads FastAPI Example",
        "version": "1.0.0",
        "endpoints": {
            "POST /upload/image": "Upload image with default validation",
            "POST /upload/image/strict": "Upload image with strict validation",
            "POST /upload/zip": "Upload and validate ZIP archive",
            "POST /upload/multiple": "Upload multiple files",
            "GET /config": "View validator configurations",
        },
    }


if __name__ == "__main__":
    print("Starting SafeUploads FastAPI Example Server...")
    print("API Documentation: http://localhost:8000/docs")
    print("Example endpoints:")
    print("  POST http://localhost:8000/upload/image")
    print("  POST http://localhost:8000/upload/zip")
    print("\nPress CTRL+C to stop")

    uvicorn.run(app, host="0.0.0.0", port=8000)
