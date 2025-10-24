"""
File Validator Module

Main validator class that coordinates all file security validations.
"""

import logging
import os
import time
import mimetypes
from typing import Set, Tuple

import magic
from fastapi import UploadFile
from .config import FileSecurityConfig
from .validators import (
    UnicodeSecurityValidator,
    ExtensionSecurityValidator,
    WindowsSecurityValidator,
    CompressionSecurityValidator,
)
from .inspectors import ZipContentInspector


logger = logging.getLogger(__name__)


class FileValidator:
    """
    Provides coordinated security validation for uploaded files, including Unicode- and extension-aware
    filename sanitization, MIME and signature verification, size enforcement, compression safeguards,
    and optional ZIP-content inspection. The validator combines specialized components configured
    through `FileSecurityConfig` to ensure both images and ZIP archives comply with strict security rules.
    """

    def __init__(self, config: FileSecurityConfig | None = None):
        """
        Initialize the file validator with configuration and detection utilities.

        Args:
            config (FileSecurityConfig | None): Optional configuration object that
                defines file security rules. Defaults to a new `FileSecurityConfig`
                instance when not provided.

        Attributes:
            config (FileSecurityConfig): Active security configuration.
            unicode_validator (UnicodeSecurityValidator): Validator for Unicode-related checks.
            extension_validator (ExtensionSecurityValidator): Validator for file extension rules.
            windows_validator (WindowsSecurityValidator): Validator enforcing Windows-specific constraints.
            compression_validator (CompressionSecurityValidator): Validator handling compressed file limits.
            zip_inspector (ZipContentInspector): Inspector for ZIP archive contents.
            magic_mime (magic.Magic | None): MIME type detector based on python-magic, when available.
            magic_available (bool): Indicates whether python-magic was successfully initialized.
        """
        self.config = config or FileSecurityConfig()

        # Initialize specialized validators
        self.unicode_validator = UnicodeSecurityValidator(self.config)
        self.extension_validator = ExtensionSecurityValidator(self.config)
        self.windows_validator = WindowsSecurityValidator(self.config)
        self.compression_validator = CompressionSecurityValidator(self.config)
        self.zip_inspector = ZipContentInspector(self.config)

        # Initialize python-magic for content-based detection
        try:
            self.magic_mime = magic.Magic(mime=True)
            self.magic_available = True
            logger.debug("File content detection (python-magic) initialized")
        except Exception as err:
            self.magic_available = False
            logger.warning(
                "python-magic not available for content detection: %s",
                err,
            )

    def _detect_mime_type(self, file_content: bytes, filename: str) -> str:
        """
        Determine the MIME type for the provided file content, preferring content-aware detection with python-magic and falling back to filename-based detection.

        Args:
            file_content (bytes): The raw bytes of the file to inspect.
            filename (str): The original filename, used for fallback MIME detection.

        Returns:
            str: The detected MIME type or "application/octet-stream" if detection fails.
        """
        detected_mime = None

        # Content-based detection using python-magic (most reliable)
        if self.magic_available:
            try:
                detected_mime = self.magic_mime.from_buffer(file_content)
            except Exception as err:
                logger.warning("Magic MIME detection failed: %s", err)

        # Fallback to filename-based detection
        if not detected_mime:
            logger.info("Fallback to filename-based MIME detection")
            detected_mime, _ = mimetypes.guess_type(filename)

        return detected_mime or "application/octet-stream"

    def _validate_file_signature(self, file_content: bytes, expected_type: str) -> bool:
        """
        Return True if the file content begins with a known signature for the expected type.

        Args:
            file_content (bytes): Raw bytes of the uploaded file.
            expected_type (str): Logical file category, such as "image" or "zip", whose signatures to match.

        Returns:
            bool: True when the file header matches one of the allowed signatures; otherwise, False.
        """
        if len(file_content) < 4:
            return False

        # Common file signatures
        signatures = {
            "image": [
                b"\xff\xd8\xff",  # JPEG
                b"\xff\xd8\xff\xe1",  # JPEG EXIF (additional JPEG variant)
                b"\x89PNG\r\n\x1a\n",  # PNG
            ],
            "zip": [
                b"PK\x03\x04",  # ZIP file
                b"PK\x05\x06",  # Empty ZIP
                b"PK\x07\x08",  # ZIP with spanning
            ],
        }

        expected_signatures = signatures.get(expected_type, [])

        for signature in expected_signatures:
            if file_content.startswith(signature):
                return True

        return False

    def _sanitize_filename(self, filename: str) -> str:
        """
        Sanitize a user-provided filename to prevent security risks.

        This applies Unicode security validation, strips path traversal components,
        removes control and dangerous characters, enforces Windows reserved name rules,
        validates compound extensions, and limits the length of the filename while
        preserving its extension.

        Args:
            filename (str): Original filename supplied by the user.

        Returns:
            str: A sanitized filename safe for storage and further processing.

        Raises:
            ValueError: If the filename is empty or fails Unicode security checks.
        """
        if not filename:
            raise ValueError("Filename cannot be empty")

        # Unicode security validation (must be first)
        # This detects and blocks Unicode-based attacks before any other processing
        try:
            filename = self.unicode_validator.validate_unicode_security(filename)
        except ValueError as err:
            raise err

        # Remove path components to prevent directory traversal
        filename = os.path.basename(filename)

        # Remove null bytes and control characters
        filename = "".join(
            char for char in filename if ord(char) >= 32 and char != "\x7f"
        )

        # Remove dangerous characters that could be used for path traversal or command injection
        dangerous_chars = '<>:"/\\|?*\x00'
        for char in dangerous_chars:
            filename = filename.replace(char, "_")

        # Check for Windows reserved names before any other processing
        # This must be done early to prevent reserved names from being created
        self.windows_validator.validate_windows_reserved_names(filename)

        # Handle compound and double extensions security risk
        # This also checks all dangerous extensions
        self.extension_validator.validate_extensions(filename)

        # Limit filename length (preserve extension)
        name_part, ext_part = os.path.splitext(filename)
        if len(name_part) > 100:
            name_part = name_part[:100]
            filename = name_part + ext_part

        # Ensure we don't end up with just an extension or empty name
        if not name_part or name_part.strip() == "":
            filename = f"file_{int(time.time())}{ext_part}"

        # Final check: ensure the sanitized filename doesn't become a reserved name
        self.windows_validator.validate_windows_reserved_names(filename)

        logger.debug(
            "Filename sanitized: original='%s' -> sanitized='%s'",
            os.path.basename(filename if filename else "None"),
            filename,
        )

        return filename

    def _validate_filename(self, file: UploadFile) -> Tuple[bool, str] | None:
        """
        Validate the filename of an uploaded file, sanitize it, and update the file object in place.

        Args:
            file (UploadFile): The uploaded file whose filename should be validated and sanitized.

        Returns:
            Optional[tuple[bool, str]]: A tuple containing a boolean status and an error message when validation fails,
            or ``None`` if the filename passes all checks.
        """
        # Check filename
        if not file.filename:
            return False, "Filename is required"

        # Sanitize the filename to prevent security issues
        try:
            sanitized_filename = self._sanitize_filename(file.filename)

            # Update the file object with sanitized filename
            file.filename = sanitized_filename

            # Additional validation after sanitization
            if not sanitized_filename or sanitized_filename.strip() == "":
                return False, "Invalid filename after sanitization"
        except ValueError as err:
            # Dangerous extension detected - reject the file
            return False, str(err)
        except Exception as err:
            logger.exception("Unexpected error during filename validation: %s", err)
            return False, "Filename validation failed due to internal error"

    def _validate_file_extension(
        self, file: UploadFile, allowed_extensions: Set[str]
    ) -> Tuple[bool, str] | None:
        """
        Validate the extension of an uploaded file against allowed and blocked lists.

        Args:
            file (UploadFile): The file whose extension will be validated.
            allowed_extensions (Set[str]): A set of allowed file extensions.

        Returns:
            Tuple[bool, str] | None: Returns a tuple with the validation result and a message
            when the filename is missing, the extension is not allowed, or is blocked.
        """
        # Check file extension
        if not file.filename:
            return False, "Filename is required for extension validation"

        _, ext = os.path.splitext(file.filename.lower())
        if ext not in allowed_extensions:
            return (
                False,
                f"Invalid file extension. Allowed: {', '.join(allowed_extensions)}",
            )

        # Check for blocked extensions
        if ext in self.config.BLOCKED_EXTENSIONS:
            return False, f"File extension {ext} is blocked for security reasons"

    async def _validate_file_size(
        self, file: UploadFile, max_file_size: int
    ) -> Tuple[bytes | None, int | None, bool, str]:
        """
        Validate an uploaded file’s size by sampling its initial content and determining the total byte length.

        Args:
            file (UploadFile): Uploaded file-like object that supports asynchronous read and seek operations.
            max_file_size (int): Maximum allowed file size in bytes.

        Returns:
            Tuple[Optional[bytes], Optional[int], bool, str]: A tuple containing the first 8 KB of file content (or None),
            the detected file size in bytes (or None), a boolean indicating whether the size validation passed, and a message
            describing the validation outcome.
        """
        # Read first chunk for content analysis
        file_content = await file.read(8192)  # Read first 8KB

        # Reset file position
        await file.seek(0)

        # Check file size
        file_size = len(file_content)
        if hasattr(file, "size") and file.size:
            file_size = file.size
        else:
            # Estimate size by reading the rest
            remaining = await file.read()
            file_size = len(file_content) + len(remaining)
            await file.seek(0)

        if file_size > max_file_size:
            return (
                None,
                None,
                False,
                f"File too large. File size: {file_size // (1024*1024)}MB, maximum: {max_file_size // (1024*1024)}MB",
            )

        if file_size == 0:
            return None, None, False, "Empty file not allowed"

        return file_content, file_size, True, "Passed"

    async def validate_image_file(self, file: UploadFile) -> Tuple[bool, str]:
        """
        Asynchronously validate an uploaded image by checking its filename, extension, size, MIME type, and binary signature.

        Args:
            file (UploadFile): The uploaded file to validate.

        Returns:
            Tuple[bool, str]: A tuple containing a success flag and a descriptive message
            explaining the validation outcome.
        """
        try:
            # Validate filename
            filename_validation = self._validate_filename(file)
            if filename_validation is not None:
                return filename_validation

            # Validate file extension
            extension_validation = self._validate_file_extension(
                file, self.config.ALLOWED_IMAGE_EXTENSIONS
            )
            if extension_validation is not None:
                return extension_validation

            # Validate file size
            size_validation = await self._validate_file_size(
                file, self.config.limits.max_image_size
            )
            if size_validation[0] is None:
                return size_validation[2], size_validation[3]

            # Detect MIME type
            filename = file.filename or "unknown"
            detected_mime = self._detect_mime_type(size_validation[0], filename)

            if detected_mime not in self.config.ALLOWED_IMAGE_MIMES:
                return (
                    False,
                    f"Invalid file type. Detected: {detected_mime}. Allowed: {', '.join(self.config.ALLOWED_IMAGE_MIMES)}",
                )

            # Validate file signature
            if not self._validate_file_signature(size_validation[0], "image"):
                return False, "File content does not match expected image format"

            logger.debug(
                "Image file validation passed: %s (%s, %s bytes)",
                filename,
                detected_mime,
                size_validation[1],
            )

            return True, "Validation successful"
        except Exception as err:
            logger.exception("Error during image file validation: %s", err)
            return False, "File validation failed due to internal error"

    async def validate_zip_file(self, file: UploadFile) -> Tuple[bool, str]:
        """
        Asynchronously validate the uploaded ZIP archive against the service configuration.

        The validation pipeline:
        1. Verifies filename conventions.
        2. Confirms allowed ZIP extension and size limits.
        3. Detects MIME type from the file header and enforces ZIP signatures.
        4. Reads the full payload to evaluate compression ratio (zip bomb protection).
        5. Optionally inspects ZIP contents for disallowed files.

        Args:
            file (UploadFile): The incoming ZIP file-like object to validate.

        Returns:
            Tuple[bool, str]: A pair where the first element signals success and the second
            provides a human-readable status or error message.

        Raises:
            ValueError: Propagated when a prohibited file extension is detected.
        """
        try:
            # Validate filename
            filename_validation = self._validate_filename(file)
            if filename_validation is not None:
                return filename_validation

            # Validate file extension
            extension_validation = self._validate_file_extension(
                file, self.config.ALLOWED_ZIP_EXTENSIONS
            )
            if extension_validation is not None:
                return extension_validation

            # Validate file size
            size_validation = await self._validate_file_size(
                file, self.config.limits.max_zip_size
            )
            if size_validation[0] is None:
                return size_validation[2], size_validation[3]

            # Detect MIME type using first 8KB
            filename = file.filename or "unknown"
            detected_mime = self._detect_mime_type(size_validation[0], filename)

            # Validate ZIP file signature first (most reliable check)
            has_zip_signature = self._validate_file_signature(size_validation[0], "zip")

            if not has_zip_signature:
                return False, "File content does not match ZIP format"

            # Check MIME type, but allow application/octet-stream if signature is valid
            # Some ZIP files are detected as octet-stream, but signature check ensures it's really a ZIP
            if detected_mime not in self.config.ALLOWED_ZIP_MIMES:
                if detected_mime == "application/octet-stream" and has_zip_signature:
                    # Valid ZIP file, just detected as generic binary
                    logger.debug(
                        "ZIP file detected as application/octet-stream, but signature is valid: %s",
                        filename,
                    )
                else:
                    return (
                        False,
                        f"Invalid file type. Detected: {detected_mime}. Expected ZIP file.",
                    )

            # For ZIP validation (compression ratio and content inspection), we need the full file
            # Read the entire file content for proper ZIP analysis
            await file.seek(0)
            full_file_content = await file.read()
            file_size = len(full_file_content)

            # Reset file position for any subsequent operations
            await file.seek(0)

            # Validate ZIP compression ratio to detect zip bombs
            if file_size is not None:
                compression_validation = (
                    self.compression_validator.validate_zip_compression_ratio(
                        full_file_content, file_size
                    )
                )
                if not compression_validation[0]:
                    return (
                        False,
                        f"ZIP compression validation failed: {compression_validation[1]}",
                    )

            # Perform ZIP content inspection if enabled
            if self.config.limits.scan_zip_content:
                content_inspection = self.zip_inspector.inspect_zip_content(
                    full_file_content
                )
                if not content_inspection[0]:
                    return (
                        False,
                        f"ZIP content inspection failed: {content_inspection[1]}",
                    )

            logger.debug(
                "ZIP file validation passed: %s (%s, %s bytes)",
                filename,
                detected_mime,
                file_size,
            )

            return True, "Validation successful"
        except ValueError as err:
            # Dangerous extension detected - reject the file
            return False, str(err)
        except Exception as err:
            logger.exception("Error during ZIP file validation: %s", err)
            return False, "File validation failed due to internal error"
