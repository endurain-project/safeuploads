"""Main file validator coordinating all security validations."""

import functools
import logging
import mimetypes
import os
import tempfile
import time

import magic

# Optional FastAPI integration - fallback to protocol if not available
try:
    from fastapi import UploadFile
except ImportError:
    from .protocols import UploadFileProtocol as UploadFile

from .audit import (
    SecurityAuditLogger,
    reset_correlation_id,
    set_correlation_id,
)
from .config import FileSecurityConfig
from .exceptions import (
    ErrorCode,
    ExtensionSecurityError,
    FilenameSecurityError,
    FileProcessingError,
    FileSignatureError,
    FileSizeError,
    FileValidationError,
    MimeTypeError,
    ResourceLimitError,
)
from .inspectors import ZipContentInspector
from .inspectors.content_inspector import ContentSecurityInspector
from .inspectors.gzip_inspector import GzipContentInspector
from .utils import ResourceMonitor
from .validators import (
    CompressionSecurityValidator,
    ExtensionSecurityValidator,
    UnicodeSecurityValidator,
    WindowsSecurityValidator,
)
from .validators.xml_validator import XmlSecurityValidator

logger = logging.getLogger(__name__)


class FileValidator:
    """
    Coordinated security validation for uploaded files.

    Attributes:
        config: Active security configuration.
        unicode_validator: Validator for Unicode-related checks.
        extension_validator: Validator for file extension rules.
        windows_validator: Validator enforcing Windows-specific constraints.
        compression_validator: Validator handling compressed file limits.
        zip_inspector: Inspector for ZIP archive contents.
        magic_mime: MIME type detector based on python-magic.
        magic_available: Whether python-magic was successfully initialized.
    """

    def __init__(self, config: FileSecurityConfig | None = None):
        """
        Initialize file validator with configuration and detection utilities.

        Args:
            config: Optional configuration object defining file security
                rules. Defaults to new FileSecurityConfig instance.

        Attributes:
            config: Active security configuration.
            unicode_validator: Validator for Unicode-related checks.
            extension_validator: Validator for file extension rules.
            windows_validator: Validator enforcing Windows constraints.
            compression_validator: Validator for compressed file limits.
            zip_inspector: Inspector for ZIP archive contents.
            magic_mime: MIME type detector based on python-magic.
            magic_available: Whether python-magic initialized successfully.
        """
        self.config = config or FileSecurityConfig()

        # Initialize specialized validators
        self.unicode_validator = UnicodeSecurityValidator(self.config)
        self.extension_validator = ExtensionSecurityValidator(self.config)
        self.windows_validator = WindowsSecurityValidator(self.config)
        self.compression_validator = CompressionSecurityValidator(self.config)
        self.zip_inspector = ZipContentInspector(self.config)
        self.xml_validator = XmlSecurityValidator(self.config)
        self.gzip_inspector = GzipContentInspector(self.config)
        self.content_inspector = ContentSecurityInspector(self.config)

        # Initialize audit logger
        self._audit = SecurityAuditLogger(
            enabled=self.config.limits.enable_audit_logging
        )

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
        Determine MIME type for file content.

        Args:
            file_content: Raw bytes of the file to inspect.
            filename: Original filename for fallback MIME detection.

        Returns:
            Detected MIME type or "application/octet-stream" if detection
            fails.
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
            detected_mime = self._guess_mime_by_name(filename)

        return detected_mime or "application/octet-stream"

    @staticmethod
    @functools.lru_cache(maxsize=256)
    def _guess_mime_by_name(filename: str) -> str | None:
        """
        Guess MIME type from filename with caching.

        Args:
            filename: Filename to guess MIME type for.

        Returns:
            Guessed MIME type or None.
        """
        mime, _ = mimetypes.guess_type(filename)
        return mime

    def _validate_file_signature(
        self, file_content: bytes, expected_type: str
    ) -> None:
        """
        Verify file content begins with known signature for expected type.

        Args:
            file_content: Raw bytes of the uploaded file.
            expected_type: Logical file category ("image" or "zip").

        Raises:
            FileSignatureError: File header doesn't match expected type
                signatures.
        """
        if len(file_content) < 4:
            raise FileSignatureError(
                f"File too small to verify {expected_type} signature",
                expected_type=expected_type,
            )

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
            "gzip": [
                b"\x1f\x8b",  # gzip magic number
            ],
            "activity": [
                b"<?xml",  # XML header (GPX/TCX)
                b"\xef\xbb\xbf<?xml",  # XML with BOM
            ],
            "fit": [
                # FIT header: size byte, protocol, profile,
                # data size (4 bytes), then ".FIT" at byte 8
            ],
        }

        expected_signatures = signatures.get(expected_type, [])

        for signature in expected_signatures:
            if file_content.startswith(signature):
                return  # Signature matched

        # FIT files: ".FIT" at bytes 8-11
        if (
            expected_type == "fit"
            and len(file_content) >= 12
            and file_content[8:12] == b".FIT"
        ):
            return

        # No matching signature found
        raise FileSignatureError(
            f"File content does not match expected {expected_type} format",
            expected_type=expected_type,
        )

    def _sanitize_filename(self, filename: str) -> str:
        """
        Sanitize user-provided filename to prevent security risks.

        Args:
            filename: Original filename supplied by the user.

        Returns:
            Sanitized filename safe for storage and processing.

        Raises:
            UnicodeSecurityError: Filename contains dangerous Unicode
                characters or fails normalization checks.
            WindowsReservedNameError: Filename uses Windows reserved
                device names.
            ExtensionSecurityError: Filename contains blocked or
                dangerous file extensions.
            ValueError: Filename is empty string.
        """
        if not filename:
            raise ValueError("Filename cannot be empty")

        # Unicode security validation (must be first)
        # This detects and blocks Unicode-based attacks
        # before any other processing
        filename = self.unicode_validator.validate_unicode_security(filename)

        # Remove path components to prevent directory traversal
        filename = os.path.basename(filename)

        # Remove null bytes and control characters
        filename = "".join(
            char for char in filename if ord(char) >= 32 and char != "\x7f"
        )

        # Remove dangerous characters that could be used
        # for path traversal or command injection
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

        # Final check: ensure the sanitized filename
        # doesn't become a reserved name
        self.windows_validator.validate_windows_reserved_names(filename)

        logger.debug(
            "Filename sanitized: original='%s' -> sanitized='%s'",
            os.path.basename(filename if filename else "None"),
            filename,
        )

        return filename

    def _validate_filename(self, file: UploadFile) -> None:
        """
        Validate filename of uploaded file and sanitize it in place.

        Args:
            file: Uploaded file whose filename should be validated and
                sanitized.

        Raises:
            FilenameSecurityError: Filename is empty, invalid, or fails
                sanitization.
            FileProcessingError: Unexpected error during filename
                validation.
        """
        # Check filename
        if not file.filename:
            raise FilenameSecurityError(
                "Filename is required",
                error_code=ErrorCode.FILENAME_EMPTY,
            )

        # Sanitize the filename to prevent security issues
        try:
            sanitized_filename = self._sanitize_filename(file.filename)

            # Update the file object with sanitized filename
            file.filename = sanitized_filename

            # Additional validation after sanitization
            if not sanitized_filename or sanitized_filename.strip() == "":
                raise FilenameSecurityError(
                    "Invalid filename after sanitization",
                    filename=file.filename,
                    error_code=ErrorCode.FILENAME_INVALID,
                )
        except FileValidationError:
            # Let FileValidationError and subclasses propagate
            raise
        except Exception as err:
            logger.exception(
                "Unexpected error during filename validation: %s", err
            )
            raise FileProcessingError(
                "Filename validation failed due to internal error",
                original_error=err,
            ) from err

    def _validate_file_extension(
        self, file: UploadFile, allowed_extensions: set[str]
    ) -> None:
        """
        Validate extension of uploaded file against allowed and blocked lists.

        Args:
            file: File whose extension will be validated.
            allowed_extensions: Set of allowed file extensions.

        Raises:
            FilenameSecurityError: Filename is missing.
            ExtensionSecurityError: Extension is not allowed or is blocked.
        """
        # Check file extension
        if not file.filename:
            raise FilenameSecurityError(
                "Filename is required for extension validation",
                error_code=ErrorCode.FILENAME_EMPTY,
            )

        _, ext = os.path.splitext(file.filename.lower())
        if ext not in allowed_extensions:
            raise ExtensionSecurityError(
                (
                    "Invalid file extension."
                    " Allowed:"
                    f" {', '.join(allowed_extensions)}"
                ),
                filename=file.filename,
                extension=ext,
                error_code=ErrorCode.EXTENSION_NOT_ALLOWED,
            )

        # Check for blocked extensions
        if ext in self.config.BLOCKED_EXTENSIONS:
            raise ExtensionSecurityError(
                f"File extension {ext} is blocked for security reasons",
                filename=file.filename,
                extension=ext,
                error_code=ErrorCode.EXTENSION_BLOCKED,
            )

    async def _validate_file_size(
        self, file: UploadFile, max_file_size: int
    ) -> tuple[bytes, int]:
        """
        Validate uploaded file size by sampling content.

        Determine total bytes from the uploaded file.

        Args:
            file: Uploaded file supporting asynchronous read and seek.
            max_file_size: Maximum allowed file size in bytes.

        Returns:
            Tuple containing first 8 KB of file content and detected file
            size in bytes.

        Raises:
            FileSizeError: File size exceeds maximum or file is empty.
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
            # Determine size via chunked reads to prevent
            # memory exhaustion when Content-Length is absent
            chunk_size = self.config.limits.chunk_size
            file_size = 0
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                file_size += len(chunk)
                if file_size > max_file_size:
                    await file.seek(0)
                    raise FileSizeError(
                        f"File too large. "
                        f"Maximum: "
                        f"{max_file_size // (1024 * 1024)}MB",
                        size=file_size,
                        max_size=max_file_size,
                    )
            await file.seek(0)

        if file_size > max_file_size:
            raise FileSizeError(
                (
                    f"File too large. File size:"
                    f" {file_size // (1024 * 1024)}MB,"
                    f" maximum:"
                    f" {max_file_size // (1024 * 1024)}MB"
                ),
                size=file_size,
                max_size=max_file_size,
            )

        if file_size == 0:
            raise FileSizeError(
                "Empty file not allowed",
                size=0,
                max_size=max_file_size,
            )

        return file_content, file_size

    async def _stream_to_temp_file(
        self, file: UploadFile, max_file_size: int
    ) -> tuple[tempfile.SpooledTemporaryFile, int]:
        """
        Stream uploaded file to a SpooledTemporaryFile with size validation.

        Reads the upload in chunks to avoid loading the entire file
        into memory. The SpooledTemporaryFile stays in memory for
        files smaller than max_memory_buffer_size and spills to
        disk for larger files.

        Args:
            file: Uploaded file supporting asynchronous read/seek.
            max_file_size: Maximum allowed file size in bytes.

        Returns:
            Tuple of SpooledTemporaryFile positioned at start and
            total bytes written.

        Raises:
            FileSizeError: File exceeds maximum or is empty.
        """
        temp = tempfile.SpooledTemporaryFile(  # noqa: SIM115
            max_size=self.config.limits.max_memory_buffer_size
        )
        total_bytes = 0
        chunk_size = self.config.limits.chunk_size

        await file.seek(0)

        try:
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > max_file_size:
                    temp.close()
                    raise FileSizeError(
                        f"File too large. "
                        f"Maximum: "
                        f"{max_file_size // (1024 * 1024)}MB",
                        size=total_bytes,
                        max_size=max_file_size,
                    )
                temp.write(chunk)

            if total_bytes == 0:
                temp.close()
                raise FileSizeError(
                    "Empty file not allowed",
                    size=0,
                    max_size=max_file_size,
                )

            temp.seek(0)
            return temp, total_bytes
        except FileSizeError:
            raise
        except Exception:
            temp.close()
            raise

    async def validate_image_file(self, file: UploadFile) -> None:
        """
        Validate uploaded image by checking filename.

        Check extension, size, MIME type, and signature.

        Args:
            file: Uploaded file to validate.

        Raises:
            FilenameSecurityError: Filename is empty, invalid, or fails
                security checks.
            ExtensionSecurityError: File extension is not allowed or is
                blocked.
            FileSizeError: File size exceeds maximum or file is empty.
            MimeTypeError: MIME type is not in allowed image types.
            FileSignatureError: File signature doesn't match expected image
                format.
            FileProcessingError: Unexpected error during validation.
        """
        cid = set_correlation_id()
        filename = file.filename or "unknown"
        self._audit.start(filename, cid)
        t0 = time.monotonic()
        try:
            # Validate filename (raises exceptions on failure)
            self._validate_filename(file)

            # Validate file extension (raises exceptions on failure)
            self._validate_file_extension(
                file, self.config.ALLOWED_IMAGE_EXTENSIONS
            )

            with ResourceMonitor(
                max_time_seconds=(
                    self.config.limits.max_validation_time_seconds
                ),
                max_memory_mb=(self.config.limits.max_validation_memory_mb),
            ):
                # Validate file size (raises on failure,
                # returns content and size on success)
                file_content, file_size = await self._validate_file_size(
                    file, self.config.limits.max_image_size
                )

                # Detect MIME type
                filename = file.filename or "unknown"
                detected_mime = self._detect_mime_type(file_content, filename)

                if detected_mime not in self.config.ALLOWED_IMAGE_MIMES:
                    raise MimeTypeError(
                        (
                            "Invalid file type."
                            f" Detected: {detected_mime}."
                            " Allowed:"
                            f" {', '.join(self.config.ALLOWED_IMAGE_MIMES)}"
                        ),
                        filename=filename,
                        detected_mime=detected_mime,
                        allowed_mimes=list(self.config.ALLOWED_IMAGE_MIMES),
                    )

                # Validate file signature (raises exceptions on failure)
                self._validate_file_signature(file_content, "image")

                # Optional content analysis
                if self.config.limits.enable_content_analysis:
                    scan_size = self.config.limits.content_scan_max_size
                    sample = file_content[:scan_size]
                    threats = self.content_inspector.scan_content(
                        sample,
                        filename,
                        "image",
                    )
                    if threats:
                        raise FileProcessingError(
                            "Content analysis threats"
                            " detected:"
                            f" {'; '.join(threats)}"
                        )

                logger.debug(
                    "Image file validation passed: %s (%s, %s bytes)",
                    filename,
                    detected_mime,
                    file_size,
                )
            ms = (time.monotonic() - t0) * 1000
            self._audit.success(filename, cid, ms)
        except (
            FileValidationError,
            ResourceLimitError,
            FileProcessingError,
        ) as exc:
            ms = (time.monotonic() - t0) * 1000
            self._audit.failure(
                filename,
                cid,
                ms,
                str(exc),
            )
            raise
        except Exception as err:
            ms = (time.monotonic() - t0) * 1000
            self._audit.failure(
                filename,
                cid,
                ms,
                "internal_error",
            )
            logger.exception("Error during image file validation: %s", err)
            raise FileProcessingError(
                "File validation failed due to internal error",
                original_error=err,
            ) from err
        finally:
            reset_correlation_id()

    async def validate_zip_file(self, file: UploadFile) -> None:
        """
        Validate uploaded ZIP archive against service configuration.

        Args:
            file: Incoming ZIP file-like object to validate.

        Raises:
            FilenameSecurityError: Filename is empty, invalid, or fails
                security checks.
            ExtensionSecurityError: File extension is not allowed or is
                blocked.
            FileSizeError: File size exceeds maximum or file is empty.
            MimeTypeError: MIME type is not in allowed ZIP types.
            FileSignatureError: File signature doesn't match expected ZIP
                format.
            CompressionSecurityError: ZIP compression validation failed
                (zip bomb detected).
            FileProcessingError: Unexpected error during validation.
        """
        cid = set_correlation_id()
        filename = file.filename or "unknown"
        self._audit.start(filename, cid)
        t0 = time.monotonic()
        try:
            # Validate filename (raises exceptions on failure)
            self._validate_filename(file)

            # Validate file extension (raises exceptions on failure)
            self._validate_file_extension(
                file, self.config.ALLOWED_ZIP_EXTENSIONS
            )

            with ResourceMonitor(
                max_time_seconds=(
                    self.config.limits.max_validation_time_seconds
                ),
                max_memory_mb=(self.config.limits.max_validation_memory_mb),
            ):
                # Stream file to SpooledTemporaryFile with size validation
                temp_file, file_size = await self._stream_to_temp_file(
                    file, self.config.limits.max_zip_size
                )

                try:
                    # Read header for MIME/signature checks
                    header = temp_file.read(8192)
                    temp_file.seek(0)

                    # Detect MIME type using header bytes
                    filename = file.filename or "unknown"
                    detected_mime = self._detect_mime_type(header, filename)

                    # Validate ZIP file signature first
                    try:
                        self._validate_file_signature(header, "zip")
                    except FileSignatureError as err:
                        raise FileSignatureError(
                            "File content does not match ZIP format",
                            filename=filename,
                            expected_type="zip",
                        ) from err

                    # Check MIME type, allow octet-stream if signature valid
                    if detected_mime not in self.config.ALLOWED_ZIP_MIMES:
                        if detected_mime == "application/octet-stream":
                            logger.debug(
                                "ZIP file detected as "
                                "application/octet-stream, "
                                "but signature is valid: %s",
                                filename,
                            )
                        else:
                            raise MimeTypeError(
                                f"Invalid file type. "
                                f"Detected: {detected_mime}. "
                                f"Expected ZIP file.",
                                filename=filename,
                                detected_mime=detected_mime,
                                allowed_mimes=list(
                                    self.config.ALLOWED_ZIP_MIMES
                                ),
                            )

                    # Validate ZIP compression ratio
                    self.compression_validator.validate_zip_compression_ratio(
                        temp_file, file_size
                    )

                    # Perform ZIP content inspection if enabled
                    if self.config.limits.scan_zip_content:
                        temp_file.seek(0)
                        self.zip_inspector.inspect_zip_content(temp_file)

                    # Optional content analysis
                    if self.config.limits.enable_content_analysis:
                        temp_file.seek(0)
                        scan_size = self.config.limits.content_scan_max_size
                        sample = temp_file.read(scan_size)
                        temp_file.seek(0)
                        threats = self.content_inspector.scan_content(
                            sample,
                            filename,
                            "zip",
                        )
                        if threats:
                            raise FileProcessingError(
                                "Content analysis"
                                " threats detected:"
                                f" {'; '.join(threats)}"
                            )

                    logger.debug(
                        "ZIP file validation passed: %s (%s, %s bytes)",
                        filename,
                        detected_mime,
                        file_size,
                    )
                finally:
                    temp_file.close()
            ms = (time.monotonic() - t0) * 1000
            self._audit.success(filename, cid, ms)
        except (
            FileValidationError,
            ResourceLimitError,
            FileProcessingError,
        ) as exc:
            ms = (time.monotonic() - t0) * 1000
            self._audit.failure(
                filename,
                cid,
                ms,
                str(exc),
            )
            raise
        except Exception as err:
            ms = (time.monotonic() - t0) * 1000
            self._audit.failure(
                filename,
                cid,
                ms,
                "internal_error",
            )
            logger.exception("Error during ZIP file validation: %s", err)
            raise FileProcessingError(
                "File validation failed due to internal error",
                original_error=err,
            ) from err
        finally:
            reset_correlation_id()

    async def validate_activity_file(self, file: UploadFile) -> None:
        """
        Validate uploaded activity file (GPX, TCX, FIT).

        For XML-based formats (GPX/TCX) performs XXE-safe
        parsing via ``defusedxml``. For FIT files validates
        the binary signature.

        Args:
            file: Uploaded activity file to validate.

        Raises:
            FilenameSecurityError: Filename fails security.
            ExtensionSecurityError: Extension not allowed.
            FileSizeError: File exceeds size limit or empty.
            MimeTypeError: MIME type not allowed.
            FileSignatureError: Signature mismatch.
            FileProcessingError: XML parsing or other error.
        """
        cid = set_correlation_id()
        filename = file.filename or "unknown"
        self._audit.start(filename, cid)
        t0 = time.monotonic()
        try:
            self._validate_filename(file)
            self._validate_file_extension(
                file,
                self.config.ALLOWED_ACTIVITY_EXTENSIONS,
            )

            with ResourceMonitor(
                max_time_seconds=(
                    self.config.limits.max_validation_time_seconds
                ),
                max_memory_mb=(self.config.limits.max_validation_memory_mb),
            ):
                temp_file, file_size = await self._stream_to_temp_file(
                    file,
                    self.config.limits.max_activity_file_size,
                )

                try:
                    header = temp_file.read(8192)
                    temp_file.seek(0)

                    filename = file.filename or "unknown"
                    detected_mime = self._detect_mime_type(header, filename)

                    _, ext = os.path.splitext(filename.lower())
                    is_fit = ext == ".fit"

                    # Signature check
                    sig_type = "fit" if is_fit else "activity"
                    try:
                        self._validate_file_signature(header, sig_type)
                    except FileSignatureError as err:
                        raise FileSignatureError(
                            "File content does not match"
                            f" expected {sig_type} format",
                            filename=filename,
                            expected_type=sig_type,
                        ) from err

                    # MIME check — be lenient for FIT
                    if not is_fit:
                        allowed = self.config.ALLOWED_ACTIVITY_MIMES
                        if detected_mime not in allowed:
                            raise MimeTypeError(
                                "Invalid file type."
                                f" Detected: {detected_mime}."
                                " Expected activity file.",
                                filename=filename,
                                detected_mime=detected_mime,
                                allowed_mimes=list(allowed),
                            )

                    # XXE-safe XML validation for GPX/TCX
                    if not is_fit:
                        self.xml_validator.validate_xml_safety(temp_file)

                    logger.debug(
                        "Activity file validation passed: %s (%s, %s bytes)",
                        filename,
                        detected_mime,
                        file_size,
                    )
                finally:
                    temp_file.close()
            ms = (time.monotonic() - t0) * 1000
            self._audit.success(filename, cid, ms)
        except (FileValidationError, ResourceLimitError) as exc:
            ms = (time.monotonic() - t0) * 1000
            self._audit.failure(
                filename,
                cid,
                ms,
                str(exc),
            )
            raise
        except Exception as err:
            ms = (time.monotonic() - t0) * 1000
            self._audit.failure(
                filename,
                cid,
                ms,
                "internal_error",
            )
            logger.exception(
                "Error during activity file validation: %s",
                err,
            )
            raise FileProcessingError(
                "File validation failed due to internal error",
                original_error=err,
            ) from err
        finally:
            reset_correlation_id()

    async def validate_gzip_file(self, file: UploadFile) -> None:
        """
        Validate uploaded gzip archive.

        Checks filename, extension, size, MIME type,
        signature, and performs decompression bomb detection.

        Args:
            file: Uploaded gzip file to validate.

        Raises:
            FilenameSecurityError: Filename fails security.
            ExtensionSecurityError: Extension not allowed.
            FileSizeError: File exceeds size limit or empty.
            MimeTypeError: MIME type not allowed.
            FileSignatureError: Signature mismatch.
            ZipBombError: Decompression bomb detected.
            CompressionSecurityError: Invalid gzip structure.
            FileProcessingError: Unexpected error.
        """
        cid = set_correlation_id()
        filename = file.filename or "unknown"
        self._audit.start(filename, cid)
        t0 = time.monotonic()
        try:
            self._validate_filename(file)
            self._validate_file_extension(
                file,
                self.config.ALLOWED_GZIP_EXTENSIONS,
            )

            with ResourceMonitor(
                max_time_seconds=(
                    self.config.limits.max_validation_time_seconds
                ),
                max_memory_mb=(self.config.limits.max_validation_memory_mb),
            ):
                temp_file, file_size = await self._stream_to_temp_file(
                    file,
                    self.config.limits.max_gzip_size,
                )

                try:
                    header = temp_file.read(8192)
                    temp_file.seek(0)

                    filename = file.filename or "unknown"
                    detected_mime = self._detect_mime_type(header, filename)

                    # Signature check
                    try:
                        self._validate_file_signature(header, "gzip")
                    except FileSignatureError as err:
                        raise FileSignatureError(
                            "File content does not match gzip format",
                            filename=filename,
                            expected_type="gzip",
                        ) from err

                    # MIME check — allow octet-stream
                    allowed = self.config.ALLOWED_GZIP_MIMES
                    if (
                        detected_mime not in allowed
                        and detected_mime != "application/octet-stream"
                    ):
                        raise MimeTypeError(
                            "Invalid file type."
                            f" Detected:"
                            f" {detected_mime}."
                            " Expected gzip file.",
                            filename=filename,
                            detected_mime=detected_mime,
                            allowed_mimes=list(allowed),
                        )

                    # Decompression bomb check
                    self.gzip_inspector.inspect_gzip_content(
                        temp_file, file_size
                    )

                    logger.debug(
                        "Gzip file validation passed: %s (%s, %s bytes)",
                        filename,
                        detected_mime,
                        file_size,
                    )
                finally:
                    temp_file.close()
            ms = (time.monotonic() - t0) * 1000
            self._audit.success(filename, cid, ms)
        except (FileValidationError, ResourceLimitError) as exc:
            ms = (time.monotonic() - t0) * 1000
            self._audit.failure(
                filename,
                cid,
                ms,
                str(exc),
            )
            raise
        except Exception as err:
            ms = (time.monotonic() - t0) * 1000
            self._audit.failure(
                filename,
                cid,
                ms,
                "internal_error",
            )
            logger.exception(
                "Error during gzip file validation: %s",
                err,
            )
            raise FileProcessingError(
                "File validation failed due to internal error",
                original_error=err,
            ) from err
        finally:
            reset_correlation_id()
