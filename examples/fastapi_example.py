"""
FastAPI Integration Example for safeuploads.

Complete working example showing how to integrate safeuploads with FastAPI,
including exception handling, custom error responses, rate limiting,
and configuration.

Rate limiting requires ``slowapi``::

    pip install slowapi
"""

import logging
from concurrent.futures import ThreadPoolExecutor

import uvicorn
from fastapi import FastAPI, HTTPException, Request, UploadFile, status
from fastapi.responses import JSONResponse

try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
    from slowapi.util import get_remote_address

    SLOWAPI_AVAILABLE = True
except ImportError:
    SLOWAPI_AVAILABLE = False

from safeuploads import FileValidator
from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.exceptions import (
    ExtensionSecurityError,
    FileProcessingError,
    FileSizeError,
    FileValidationError,
    ImageSecurityError,
    MimeTypeError,
    ResourceLimitError,
    UnicodeSecurityError,
    WindowsReservedNameError,
    ZipBombError,
    ZipContentError,
)

logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="SafeUploads FastAPI Example",
    description="Example API demonstrating safeuploads integration",
    version="1.1.0",
)

# Optional: configure rate limiting if slowapi is installed
if SLOWAPI_AVAILABLE:
    limiter = Limiter(key_func=get_remote_address)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Create custom security limits for stricter validation
strict_limits = SecurityLimits(
    max_image_size=2 * 1024 * 1024,  # 2MB for images
    max_zip_size=5 * 1024 * 1024,  # 5MB for ZIPs
    max_compression_ratio=50,  # Lower ratio for safety
    max_zip_entries=50,  # Fewer entries allowed
    zip_analysis_timeout=3.0,  # Faster timeout
)

# Create custom configuration with strict limits
strict_config = FileSecurityConfig(strict_limits)

# Initialize validators
default_validator = FileValidator()  # Uses default config
strict_validator = FileValidator(config=strict_config)

# Hardened validator: decompress every ZIP entry to reject
# forged central-directory metadata, and offload blocking
# inspection to a bounded thread pool so large uploads never
# starve the event loop.
hardened_config = FileSecurityConfig(
    SecurityLimits(verify_zip_decompression=True)
)
hardened_validator = FileValidator(
    config=hardened_config,
    executor=ThreadPoolExecutor(max_workers=4),
)


@app.exception_handler(FileValidationError)
async def file_validation_exception_handler(request, exc: FileValidationError):
    """
    Global exception handler for all file validation errors.

    Converts safeuploads exceptions to HTTP responses with appropriate
    status codes and detailed error information.

    Exception messages embed the client-supplied filename, so they are
    logged rather than returned. Clients receive a static message plus
    the machine-readable ``error_code``.
    """
    logger.warning("Upload rejected: %r", exc)

    # Map exception types to HTTP status codes
    status_code = status.HTTP_400_BAD_REQUEST

    # Special handling for different exception types
    if isinstance(exc, FileSizeError):
        detail = {
            "error": "file_too_large",
            "message": "File exceeds the configured size limit.",
            "size": exc.size,
            "max_size": exc.max_size,
            "error_code": exc.error_code,
        }
    elif isinstance(exc, ImageSecurityError):
        detail = {
            "error": "image_too_large",
            "message": "Image is too large once decoded.",
            "width": exc.width,
            "height": exc.height,
            "max_pixels": exc.max_pixels,
            "error_code": exc.error_code,
        }
    elif isinstance(exc, MimeTypeError):
        detail = {
            "error": "invalid_mime_type",
            "message": "File content type is not allowed.",
            "detected_mime": exc.detected_mime,
            "allowed_mimes": list(exc.allowed_mimes),
            "error_code": exc.error_code,
        }
    elif isinstance(exc, ZipBombError):
        detail = {
            "error": "zip_bomb_detected",
            "message": "Archive expands beyond the allowed limits.",
            "compression_ratio": exc.compression_ratio,
            "error_code": exc.error_code,
        }
    elif isinstance(exc, ZipContentError):
        detail = {
            "error": "dangerous_zip_content",
            "message": "Archive contains disallowed entries.",
            "error_code": exc.error_code,
        }
    elif isinstance(
        exc,
        (
            UnicodeSecurityError,
            ExtensionSecurityError,
            WindowsReservedNameError,
        ),
    ):
        detail = {
            "error": "filename_security_violation",
            "message": "Filename failed security validation.",
            "error_code": exc.error_code,
        }
    else:
        # Generic file validation error
        detail = {
            "error": "validation_failed",
            "message": "Upload failed validation.",
            "error_code": getattr(exc, "error_code", None),
        }

    return JSONResponse(status_code=status_code, content=detail)


@app.exception_handler(FileProcessingError)
async def file_processing_exception_handler(request, exc: FileProcessingError):
    """
    Handle processing and resource errors.

    XML parsing failures and resource-limit breaches derive
    from FileProcessingError rather than FileValidationError,
    so they need their own handler.
    """
    logger.warning("Upload processing failed: %r", exc)

    if isinstance(exc, ResourceLimitError):
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "error": "resource_limit_exceeded",
                "message": "Validation exceeded its resource budget.",
                "error_code": exc.error_code,
            },
        )

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "processing_error",
            "message": "File could not be processed.",
            "error_code": exc.error_code,
        },
    )


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
            message = "Image exceeds the configured size limit."
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


@app.post("/upload/zip/verified")
async def upload_zip_verified(file: UploadFile):
    """
    Upload a ZIP validated with strict decompression checking.

    Uses the hardened validator (``verify_zip_decompression``
    enabled), which decompresses every entry to reject archives
    whose real content does not match their declared metadata.
    Inspection runs on a dedicated thread pool.
    """
    await hardened_validator.validate_zip_file(file)

    return {
        "status": "success",
        "message": "ZIP verified with strict decompression checking",
        "filename": file.filename,
        "size": file.size,
    }


@app.post("/upload/activity")
async def upload_activity(file: UploadFile):
    """
    Upload and validate an activity file (GPX, TCX, or FIT).

    XML formats (GPX/TCX) are parsed with XXE protections;
    FIT files are validated by their binary signature.
    """
    await default_validator.validate_activity_file(file)

    return {
        "status": "success",
        "message": "Activity file uploaded and validated successfully",
        "filename": file.filename,
        "size": file.size,
    }


@app.post("/upload/gzip")
async def upload_gzip(file: UploadFile):
    """
    Upload and validate a gzip archive.

    Streams decompression to detect decompression bombs.
    """
    await default_validator.validate_gzip_file(file)

    return {
        "status": "success",
        "message": "Gzip file uploaded and validated successfully",
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
            name = (file.filename or "").lower()
            if name.endswith(".zip"):
                await default_validator.validate_zip_file(file)
                file_type = "zip"
            elif name.endswith(".gz"):
                await default_validator.validate_gzip_file(file)
                file_type = "gzip"
            elif name.endswith((".gpx", ".tcx", ".fit")):
                await default_validator.validate_activity_file(file)
                file_type = "activity"
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
            logger.warning("Upload rejected in batch: %r", e)
            results.append(
                {
                    "filename": file.filename,
                    "status": "failed",
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
            "max_activity_file_size": (
                default_validator.config.limits.max_activity_file_size
            ),
            "max_gzip_size": (default_validator.config.limits.max_gzip_size),
            "max_compression_ratio": (
                default_validator.config.limits.max_compression_ratio
            ),
            "max_zip_entries": default_validator.config.limits.max_zip_entries,
        },
        "strict": {
            "max_image_size": strict_validator.config.limits.max_image_size,
            "max_zip_size": strict_validator.config.limits.max_zip_size,
            "max_compression_ratio": (
                strict_validator.config.limits.max_compression_ratio
            ),
            "max_zip_entries": strict_validator.config.limits.max_zip_entries,
        },
        "hardened": {
            "verify_zip_decompression": (
                hardened_validator.config.limits.verify_zip_decompression
            ),
        },
    }


@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "SafeUploads FastAPI Example",
        "version": "1.1.0",
        "endpoints": {
            "POST /upload/image": "Upload image with default validation",
            "POST /upload/image/strict": "Upload image with strict validation",
            "POST /upload/zip": "Upload and validate ZIP archive",
            "POST /upload/zip/verified": (
                "Upload ZIP with strict decompression verification"
            ),
            "POST /upload/activity": "Upload GPX/TCX/FIT activity file",
            "POST /upload/gzip": "Upload and validate gzip archive",
            "POST /upload/multiple": "Upload multiple files",
            "POST /upload/image/rate-limited": (
                "Rate-limited image upload (requires slowapi)"
            ),
            "GET /config": "View validator configurations",
        },
    }


# ------------------------------------------------------------------ #
# Rate-limited upload endpoint (requires slowapi)
# ------------------------------------------------------------------ #
if SLOWAPI_AVAILABLE:

    @app.post("/upload/image/rate-limited")
    @limiter.limit("10/minute")
    async def upload_image_rate_limited(request: Request, file: UploadFile):
        """
        Upload image with per-IP rate limiting.

        Limited to 10 requests per minute per client IP.
        Returns HTTP 429 when the limit is exceeded.
        Requires ``slowapi`` to be installed.
        """
        await default_validator.validate_image_file(file)

        return {
            "status": "success",
            "message": "Rate-limited image upload succeeded",
            "filename": file.filename,
            "size": file.size,
        }


if __name__ == "__main__":
    print("Starting SafeUploads FastAPI Example Server...")
    print("API Documentation: http://localhost:8000/docs")
    print("Example endpoints:")
    print("  POST http://localhost:8000/upload/image")
    print("  POST http://localhost:8000/upload/zip")
    print("  POST http://localhost:8000/upload/activity")
    print("  POST http://localhost:8000/upload/gzip")
    print("\nPress CTRL+C to stop")

    uvicorn.run(app, host="127.0.0.1", port=8000)
