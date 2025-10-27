"""
File Security Utilities Module

Contains utility functions for file security operations.
"""

import logging

from fastapi import HTTPException, status, UploadFile

from .file_validator import FileValidator
from .config import FileSecurityConfig
from .exceptions import FileValidationError

# Global validator instance
file_validator = FileValidator()

logger = logging.getLogger(__name__)


async def validate_profile_image_upload(file: UploadFile) -> None:
    """
    Validate an uploaded profile image and raise an HTTP 400 error if the file is invalid.

    Args:
        file: The uploaded image file to validate.

    Raises:
        HTTPException: If the image file fails validation, indicating the specific reason.
    """
    try:
        await file_validator.validate_image_file(file)
    except FileValidationError as err:
        logger.warning("Profile image upload validation failed: %s", str(err))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid image file: {err}",
        ) from err


async def validate_profile_data_upload(file: UploadFile) -> None:
    """
    Validate the uploaded profile data ZIP file.

    Args:
        file: The uploaded ZIP archive to validate.

    Raises:
        HTTPException: If the provided file fails ZIP validation.
    """
    try:
        await file_validator.validate_zip_file(file)
    except FileValidationError as err:
        logger.warning("Profile data upload validation failed: %s", str(err))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid ZIP file: {err}",
        ) from err


def get_secure_filename(original_filename: str) -> str:
    """
    Sanitize a filename using the shared file validator.

    Parameters:
        original_filename (str): The untrusted filename supplied by the client.

    Returns:
        str: A sanitized filename safe for storage.

    Raises:
        ValueError: If the provided filename fails validation checks.
        HTTPException: If an unexpected error occurs during sanitization.
    """
    try:
        return file_validator._sanitize_filename(original_filename)
    except ValueError as err:
        raise err
    except Exception as err:
        logger.exception("Error during filename sanitization: %s", err)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Server Error during filename sanitization",
        ) from err


def validate_configuration(strict: bool = False) -> None:
    """
    Validate file security configuration settings, reporting findings to the logger.

    Args:
        strict (bool, optional): When True, enables stricter validation rules that may
            raise additional errors or warnings. Defaults to False.

    Raises:
        Exception: Propagates any unexpected errors encountered during validation.
    """
    try:
        FileSecurityConfig.validate_and_report(strict=strict)
        logger.info("File security configuration validation completed successfully")
    except Exception as err:
        logger.warning(
            "File security configuration validation encountered issues: %s",
            err,
        )
