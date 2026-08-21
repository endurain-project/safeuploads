"""Main file validator coordinating all security validations."""

import asyncio
import contextvars
import functools
import logging
import mimetypes
import os
import secrets
import tempfile
import threading
import time
from collections.abc import Awaitable, Callable
from concurrent.futures import Executor
from typing import TYPE_CHECKING, TypeVar

import magic

# Optional FastAPI integration - fallback to protocol if not available.
# For type checking we always bind to the protocol so the interface is
# consistent regardless of whether FastAPI is installed; at runtime we
# prefer FastAPI's UploadFile when present.
if TYPE_CHECKING:
    from .protocols import UploadFileProtocol as UploadFile
else:
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
    ImageSecurityError,
    MimeTypeError,
    ResourceLimitError,
)
from .inspectors import ZipContentInspector
from .inspectors.content_inspector import ContentSecurityInspector
from .inspectors.gzip_inspector import GzipContentInspector
from .utils import (
    ResourceMonitor,
    bytes_to_mb,
    parse_image_dimensions,
    safe_label,
)
from .validators import (
    CompressionSecurityValidator,
    ExtensionSecurityValidator,
    UnicodeSecurityValidator,
    WindowsSecurityValidator,
)
from .validators.xml_validator import XmlSecurityValidator

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

# A large EXIF or preview block can push a JPEG frame header
# well past the 8 KB MIME sample. Anything beyond this window
# is treated as malformed rather than scanned indefinitely.
_IMAGE_DIMENSION_SCAN_BYTES = 1024 * 1024


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

    def __init__(
        self,
        config: FileSecurityConfig | None = None,
        executor: Executor | None = None,
    ):
        """
        Initialize file validator with configuration and detection utilities.

        Args:
            config: Optional configuration object defining file security
                rules. Defaults to new FileSecurityConfig instance.
            executor: Optional executor used to run blocking
                inspection off the event loop. Defaults to the
                asyncio default thread pool.

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
        self._executor = executor

        # Validate the actual (possibly custom) config in use;
        # log any issues by severity without raising so
        # construction still succeeds. A valid config logs nothing.
        for issue in self.config.validate_instance(strict=False):
            log = logger.error if issue.severity == "error" else logger.warning
            log(
                "Configuration %s: %s. %s",
                issue.component,
                issue.message,
                issue.recommendation,
            )

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

        # Serialize access to the shared python-magic instance;
        # libmagic cookies are not thread-safe and validation may
        # run in worker threads via asyncio.to_thread.
        self._magic_lock = threading.Lock()

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

    def _monitor(self) -> ResourceMonitor:
        """
        Build a resource monitor from the active configuration.

        Returns:
            Monitor carrying the configured time budget and the
            opt-in memory enforcement flag.
        """
        return ResourceMonitor(
            max_time_seconds=self.config.limits.max_validation_time_seconds,
            max_memory_mb=self.config.limits.max_validation_memory_mb,
            enforce_memory=self.config.limits.enforce_memory_limit,
        )

    async def _to_thread(self, func: Callable[..., _T], *args: object) -> _T:
        """
        Run a blocking callable in a worker thread.

        Uses the configured executor when one was supplied,
        otherwise the default ``asyncio.to_thread`` pool. The
        current context (including the correlation ID) is
        propagated to the worker thread in both cases.

        Args:
            func: Blocking callable to execute.
            *args: Positional arguments passed to ``func``.

        Returns:
            The value returned by ``func``.
        """
        if self._executor is None:
            return await asyncio.to_thread(func, *args)

        loop = asyncio.get_running_loop()
        ctx = contextvars.copy_context()

        def _call() -> _T:
            return ctx.run(func, *args)

        return await loop.run_in_executor(self._executor, _call)

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

        # Content-based detection using python-magic (most reliable).
        # Guarded by a lock because libmagic is not thread-safe and
        # detection may run concurrently in worker threads.
        if self.magic_available:
            try:
                with self._magic_lock:
                    detected_mime = self.magic_mime.from_buffer(file_content)
            except Exception as err:
                logger.warning("Magic MIME detection failed: %s", err)

        # Fallback to filename-based detection
        if not detected_mime:
            logger.info("Fallback to filename-based MIME detection")
            ext = os.path.splitext(filename)[1].lower()
            detected_mime = self._guess_mime_by_ext(ext)

        return detected_mime or "application/octet-stream"

    @staticmethod
    @functools.lru_cache(maxsize=64)
    def _guess_mime_by_ext(ext: str) -> str | None:
        """
        Guess MIME type from a file extension with caching.

        Keyed solely on the lower-cased extension so the LRU
        cache stays small and attacker-controlled filenames
        cannot bloat it.

        Args:
            ext: Lower-cased extension including the leading dot
                (e.g. ".jpg"), or an empty string.

        Returns:
            Guessed MIME type or None.
        """
        if not ext:
            return None
        mime, _ = mimetypes.guess_type(f"file{ext}")
        return mime

    def _enforce_mime(
        self,
        detected_mime: str,
        allowed_mimes: frozenset[str],
        filename: str,
        *,
        allow_octet_stream: bool = False,
        error_code: str | None = None,
    ) -> None:
        """
        Raise if a detected MIME type is not permitted.

        Args:
            detected_mime: MIME type reported for the content.
            allowed_mimes: Permitted MIME types for the category.
            filename: Sanitized filename for error context.
            allow_octet_stream: Accept ``application/octet-stream``
                when a valid magic signature already passed.
            error_code: Optional error code for the raised error.

        Raises:
            MimeTypeError: If the MIME type is not allowed.
        """
        if detected_mime in allowed_mimes:
            return
        if allow_octet_stream and detected_mime == "application/octet-stream":
            logger.debug(
                "Accepting application/octet-stream for '%s'"
                " on a valid signature",
                filename,
            )
            return
        raise MimeTypeError(
            "Invalid file type."
            f" Detected: {detected_mime}."
            f" Allowed: {', '.join(sorted(allowed_mimes))}",
            filename=filename,
            detected_mime=detected_mime,
            allowed_mimes=list(allowed_mimes),
            error_code=error_code,
        )

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
                error_code=ErrorCode.FILE_SIGNATURE_MISSING,
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
        }

        expected_signatures = signatures.get(expected_type, [])

        for signature in expected_signatures:
            if file_content.startswith(signature):
                logger.debug(
                    "File signature matched for type '%s'", expected_type
                )
                return  # Signature matched

        # FIT files: ".FIT" at bytes 8-11
        if (
            expected_type == "fit"
            and len(file_content) >= 12
            and file_content[8:12] == b".FIT"
        ):
            return

        # Activity XML files may carry a UTF-8 BOM and/or leading
        # whitespace before the XML declaration; tolerate both.
        if expected_type == "activity":
            head = file_content
            if head.startswith(b"\xef\xbb\xbf"):
                head = head[3:]
            if head.lstrip().startswith(b"<?xml"):
                return

        # No matching signature found
        raise FileSignatureError(
            f"File content does not match expected {expected_type} format",
            expected_type=expected_type,
        )

    def _enforce_image_dimensions(
        self, dimensions: tuple[int, int] | None, filename: str
    ) -> None:
        """
        Reject images whose decoded pixel count is unsafe.

        Byte-size limits do not bound decoded size: a small
        PNG or JPEG can declare dimensions that expand to
        gigabytes in any downstream decoder.

        Args:
            dimensions: Parsed ``(width, height)`` pair, or None
                if the header could not be read.
            filename: Sanitized filename for error context.

        Raises:
            ImageSecurityError: If the dimensions are unreadable,
                non-positive, or exceed ``max_image_pixels``.
        """
        if dimensions is None:
            logger.warning("Image dimensions unreadable for '%s'", filename)
            raise ImageSecurityError(
                "Image dimensions could not be read from the file header",
                filename=filename,
                error_code=ErrorCode.IMAGE_DIMENSIONS_UNREADABLE,
            )

        width, height = dimensions
        if width <= 0 or height <= 0:
            raise ImageSecurityError(
                f"Image declares invalid dimensions: {width}x{height}",
                filename=filename,
                width=width,
                height=height,
                error_code=ErrorCode.IMAGE_DIMENSIONS_UNREADABLE,
            )

        max_pixels = self.config.limits.max_image_pixels
        pixels = width * height
        if pixels > max_pixels:
            logger.warning(
                "Image decompression bomb rejected: %dx%d = %d pixels"
                " (max %d)",
                width,
                height,
                pixels,
                max_pixels,
            )
            raise ImageSecurityError(
                (
                    "Image too large when decoded:"
                    f" {width}x{height} = {pixels} pixels."
                    f" Maximum: {max_pixels} pixels"
                ),
                filename=filename,
                width=width,
                height=height,
                max_pixels=max_pixels,
            )

        logger.debug("Image dimensions accepted: %dx%d", width, height)

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

        # Preserve the raw input for truthful logging; every step
        # below reassigns ``filename`` as it sanitizes.
        original_filename = filename

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
        max_name_len = self.config.limits.max_sanitized_name_length
        if len(name_part) > max_name_len:
            logger.debug(
                "Truncating sanitized name from %d to %d chars",
                len(name_part),
                max_name_len,
            )
            name_part = name_part[:max_name_len]
            filename = name_part + ext_part

        # Ensure we don't end up with just an extension or empty name
        if not name_part or name_part.strip() == "":
            filename = f"file_{secrets.token_hex(8)}{ext_part}"

        # Final check: ensure the sanitized filename
        # doesn't become a reserved name
        self.windows_validator.validate_windows_reserved_names(filename)

        # Log with %r so control characters in the raw input are
        # escaped rather than injected into the log stream.
        logger.debug(
            "Filename sanitized: original=%r -> sanitized=%r",
            os.path.basename(original_filename),
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
        self, file: UploadFile, allowed_extensions: frozenset[str]
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
        if not ext:
            raise ExtensionSecurityError(
                "File has no extension",
                filename=file.filename,
                extension="",
                error_code=ErrorCode.EXTENSION_MISSING,
            )
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

        logger.debug("File extension '%s' accepted", ext)

    async def _validate_file_size(
        self,
        file: UploadFile,
        max_file_size: int,
        monitor: ResourceMonitor | None = None,
    ) -> tuple[bytes, int]:
        """
        Validate uploaded file size by sampling content.

        Determine total bytes from the uploaded file.

        Args:
            file: Uploaded file supporting asynchronous read and seek.
            max_file_size: Maximum allowed file size in bytes.
            monitor: Optional resource monitor checked once per
                chunk so a slow upload is aborted mid-read.

        Returns:
            Tuple containing first 8 KB of file content and detected file
            size in bytes.

        Raises:
            FileSizeError: File size exceeds maximum or file is empty.
            ResourceLimitError: If the monitor's time or memory
                limit is exceeded while reading.
        """
        # Read first chunk for content analysis
        file_content = await file.read(8192)  # Read first 8KB

        # Reset file position
        await file.seek(0)

        # Fail closed: if the client declares a size that already
        # exceeds the limit, reject immediately without reading.
        declared_size = getattr(file, "size", None)
        if declared_size and declared_size > max_file_size:
            raise FileSizeError(
                (
                    f"File too large. File size:"
                    f" {bytes_to_mb(declared_size)}MB,"
                    f" maximum:"
                    f" {bytes_to_mb(max_file_size)}MB"
                ),
                size=declared_size,
                max_size=max_file_size,
            )

        # Never trust a small or absent declared size: verify the
        # real byte count by streaming so an under-reported size
        # cannot bypass the limit.
        chunk_size = self.config.limits.chunk_size
        file_size = 0
        while True:
            if monitor is not None:
                monitor.check()
            chunk = await file.read(chunk_size)
            if not chunk:
                break
            file_size += len(chunk)
            if file_size > max_file_size:
                await file.seek(0)
                raise FileSizeError(
                    f"File too large. Maximum: {bytes_to_mb(max_file_size)}MB",
                    size=file_size,
                    max_size=max_file_size,
                )
        await file.seek(0)

        if file_size == 0:
            raise FileSizeError(
                "Empty file not allowed",
                size=0,
                max_size=max_file_size,
                error_code=ErrorCode.FILE_EMPTY,
            )

        return file_content, file_size

    async def _stream_to_temp_file(
        self,
        file: UploadFile,
        max_file_size: int,
        monitor: ResourceMonitor | None = None,
    ) -> tuple[tempfile.SpooledTemporaryFile[bytes], int]:
        """
        Stream uploaded file to a SpooledTemporaryFile with size validation.

        Reads the upload in chunks to avoid loading the entire file
        into memory. The SpooledTemporaryFile stays in memory for
        files smaller than max_memory_buffer_size and spills to
        disk for larger files.

        Args:
            file: Uploaded file supporting asynchronous read/seek.
            max_file_size: Maximum allowed file size in bytes.
            monitor: Optional resource monitor checked once per
                chunk so a slow upload is aborted mid-read.

        Returns:
            Tuple of SpooledTemporaryFile positioned at start and
            total bytes written. The original file is also seeked
            back to position 0 so callers can re-read it.

        Raises:
            FileSizeError: File exceeds maximum or is empty.
            ResourceLimitError: If the monitor's time or memory
                limit is exceeded while reading.
        """
        temp = tempfile.SpooledTemporaryFile(  # noqa: SIM115
            max_size=self.config.limits.max_memory_buffer_size,
            dir=self.config.limits.temp_dir,
        )
        total_bytes = 0
        chunk_size = self.config.limits.chunk_size

        await file.seek(0)

        try:
            while True:
                if monitor is not None:
                    monitor.check()
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > max_file_size:
                    temp.close()
                    raise FileSizeError(
                        f"File too large. "
                        f"Maximum: "
                        f"{bytes_to_mb(max_file_size)}MB",
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
                    error_code=ErrorCode.FILE_EMPTY,
                )

            temp.seek(0)
            await file.seek(0)
            return temp, total_bytes
        except FileSizeError:
            raise
        except Exception:
            temp.close()
            raise

    def _read_header_and_detect(
        self,
        temp_file: tempfile.SpooledTemporaryFile[bytes],
        filename: str,
        sig_type: str,
    ) -> tuple[bytes, str]:
        """
        Read the header, detect MIME, and verify the signature.

        Reads the first 8 KB of a streamed temp file, resets
        its position to the start, detects the MIME type, and
        validates the magic signature against the expected type.

        Args:
            temp_file: Spooled temp file; reset to start on
                return.
            filename: Sanitized filename for error context.
            sig_type: Expected signature category (e.g. "zip",
                "gzip", "activity", "fit").

        Returns:
            Tuple of the header bytes and the detected MIME type.

        Raises:
            FileSignatureError: If the header does not match the
                expected signature type.
        """
        header = temp_file.read(8192)
        temp_file.seek(0)
        detected_mime = self._detect_mime_type(header, filename)
        try:
            self._validate_file_signature(header, sig_type)
        except FileSignatureError as err:
            raise FileSignatureError(
                f"File content does not match expected {sig_type} format",
                filename=filename,
                expected_type=sig_type,
            ) from err
        return header, detected_mime

    def _raise_on_content_threats(
        self, sample: bytes, filename: str, kind: str
    ) -> None:
        """
        Scan a content sample and raise if threats are found.

        Args:
            sample: Raw bytes to scan (typically up to
                ``content_scan_max_size``).
            filename: Sanitized filename for error context.
            kind: Logical file type passed to the scanner
                (e.g. "image", "zip").

        Raises:
            FileProcessingError: If the content scan reports one
                or more threats.
        """
        threats = self.content_inspector.scan_content(sample, filename, kind)
        if threats:
            raise FileProcessingError(
                f"Content analysis threats detected: {'; '.join(threats)}"
            )

    async def _run_validation(
        self,
        file: UploadFile,
        file_type: str,
        body: Callable[[UploadFile], Awaitable[None]],
    ) -> None:
        """
        Run a validation body with audit logging and error mapping.

        Wraps a format-specific validation callback with
        correlation-ID setup, audit start/success/failure
        events, resource-error propagation, and internal-error
        wrapping.

        Args:
            file: Uploaded file being validated.
            file_type: Label used in log messages.
            body: Async callback performing the format-specific
                validation.

        Raises:
            FileValidationError: Propagated from the body.
            ResourceLimitError: Propagated from the body.
            FileProcessingError: Propagated as-is or wrapping an
                unexpected internal error.
        """
        cid = set_correlation_id()
        # The raw client filename reaches the log before any
        # sanitization has run, so escape it here.
        filename = safe_label(file.filename or "unknown")
        self._audit.start(filename, cid)
        logger.debug("Starting %s file validation: %s", file_type, filename)
        t0 = time.monotonic()
        try:
            await body(file)
            ms = (time.monotonic() - t0) * 1000
            self._audit.success(safe_label(file.filename or filename), cid, ms)
        except (
            FileValidationError,
            ResourceLimitError,
            FileProcessingError,
        ) as exc:
            ms = (time.monotonic() - t0) * 1000
            self._audit.failure(
                safe_label(file.filename or filename),
                cid,
                ms,
                safe_label(str(exc), max_length=512),
            )
            raise
        except Exception as err:
            ms = (time.monotonic() - t0) * 1000
            self._audit.failure(
                safe_label(file.filename or filename),
                cid,
                ms,
                "internal_error",
            )
            logger.exception(
                "Error during %s file validation: %s", file_type, err
            )
            raise FileProcessingError(
                "File validation failed due to internal error",
                original_error=err,
            ) from err
        finally:
            reset_correlation_id()

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
            ImageSecurityError: Decoded pixel count exceeds
                ``max_image_pixels`` or the header dimensions cannot
                be read.
            FileProcessingError: Unexpected error during validation.
        """
        await self._run_validation(file, "image", self._validate_image_body)

    async def _validate_image_body(self, file: UploadFile) -> None:
        """
        Run image-specific validation steps.

        Args:
            file: Uploaded image file to validate.

        Raises:
            FileValidationError: If an image validation check fails.
            FileProcessingError: If content analysis finds threats.
        """
        # Validate filename (raises exceptions on failure)
        self._validate_filename(file)

        # Validate file extension (raises exceptions on failure)
        self._validate_file_extension(
            file, self.config.ALLOWED_IMAGE_EXTENSIONS
        )

        with self._monitor() as monitor:
            # Validate file size (raises on failure,
            # returns content and size on success)
            file_content, file_size = await self._validate_file_size(
                file, self.config.limits.max_image_size, monitor
            )

            # Detect MIME type
            filename = file.filename or "unknown"
            detected_mime = self._detect_mime_type(file_content, filename)

            self._enforce_mime(
                detected_mime,
                self.config.ALLOWED_IMAGE_MIMES,
                filename,
            )

            # Validate file signature (raises exceptions on failure)
            self._validate_file_signature(file_content, "image")

            # Reject decompression bombs: a small file can declare
            # dimensions that expand to gigabytes once decoded.
            dimensions = parse_image_dimensions(file_content)
            if dimensions is None and file_size > len(file_content):
                await file.seek(0)
                wider = await file.read(_IMAGE_DIMENSION_SCAN_BYTES)
                await file.seek(0)
                dimensions = parse_image_dimensions(wider)
            self._enforce_image_dimensions(dimensions, filename)

            # Optional content analysis (offloaded — scans up to
            # content_scan_max_size bytes and is CPU-bound)
            if self.config.limits.enable_content_analysis:
                scan_size = self.config.limits.content_scan_max_size
                # file_content holds only the 8 KB header;
                # re-read up to scan_size bytes so threats
                # past the header (e.g. polyglots) are seen.
                await file.seek(0)
                sample = await file.read(scan_size)
                await file.seek(0)
                await self._to_thread(
                    self._raise_on_content_threats,
                    sample,
                    filename,
                    "image",
                )

            logger.debug(
                "Image file validation passed: %s (%s, %s bytes)",
                filename,
                detected_mime,
                file_size,
            )

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
        await self._run_validation(file, "ZIP", self._validate_zip_body)

    async def _validate_zip_body(self, file: UploadFile) -> None:
        """
        Run ZIP-specific validation steps.

        Args:
            file: Uploaded ZIP file to validate.

        Raises:
            FileValidationError: If a ZIP validation check fails.
            FileProcessingError: If content analysis finds threats.
        """
        # Validate filename (raises exceptions on failure)
        self._validate_filename(file)

        # Validate file extension (raises exceptions on failure)
        self._validate_file_extension(file, self.config.ALLOWED_ZIP_EXTENSIONS)

        with self._monitor() as monitor:
            # Stream file to SpooledTemporaryFile with size validation
            temp_file, file_size = await self._stream_to_temp_file(
                file, self.config.limits.max_zip_size, monitor
            )

            try:
                # Offload the CPU/IO-bound ZIP inspection off the loop
                filename = file.filename or "unknown"
                await self._to_thread(
                    self._inspect_zip_sync,
                    temp_file,
                    file_size,
                    filename,
                    monitor,
                )
            finally:
                temp_file.close()

    def _inspect_zip_sync(
        self,
        temp_file: tempfile.SpooledTemporaryFile[bytes],
        file_size: int,
        filename: str,
        monitor: ResourceMonitor | None = None,
    ) -> None:
        """
        Run synchronous ZIP inspection off the event loop.

        Args:
            temp_file: Spooled temp file holding the ZIP data.
            file_size: Compressed archive size in bytes.
            filename: Sanitized filename for context.
            monitor: Optional resource monitor checked once per
                entry so a runaway archive is aborted mid-scan.

        Raises:
            MimeTypeError: If the MIME type is not allowed.
            FileSignatureError: If the signature mismatches.
            CompressionSecurityError: If a zip bomb is detected.
            ResourceLimitError: If the monitor's time or memory
                limit is exceeded during inspection.
            FileProcessingError: If content analysis finds threats.
        """
        # Read header for MIME/signature checks
        _, detected_mime = self._read_header_and_detect(
            temp_file, filename, "zip"
        )

        # Check MIME type, allow octet-stream if signature valid
        self._enforce_mime(
            detected_mime,
            self.config.ALLOWED_ZIP_MIMES,
            filename,
            allow_octet_stream=True,
            error_code=ErrorCode.MIME_TYPE_MISMATCH,
        )

        # Validate ZIP compression ratio
        self.compression_validator.validate_zip_compression_ratio(
            temp_file, file_size, monitor
        )

        # Perform ZIP content inspection if enabled
        if self.config.limits.scan_zip_content:
            temp_file.seek(0)
            self.zip_inspector.inspect_zip_content(temp_file, monitor)

        # Optional content analysis
        if self.config.limits.enable_content_analysis:
            temp_file.seek(0)
            scan_size = self.config.limits.content_scan_max_size
            sample = temp_file.read(scan_size)
            temp_file.seek(0)
            self._raise_on_content_threats(sample, filename, "zip")

        logger.debug(
            "ZIP file validation passed: %s (%s, %s bytes)",
            filename,
            detected_mime,
            file_size,
        )

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
        await self._run_validation(
            file, "activity", self._validate_activity_body
        )

    async def _validate_activity_body(self, file: UploadFile) -> None:
        """
        Run activity-file-specific validation steps.

        Handles XXE-safe XML parsing for GPX/TCX and binary
        signature validation for FIT files.

        Args:
            file: Uploaded activity file to validate.

        Raises:
            FileValidationError: If an activity check fails.
            FileProcessingError: If XML parsing fails.
        """
        self._validate_filename(file)
        self._validate_file_extension(
            file,
            self.config.ALLOWED_ACTIVITY_EXTENSIONS,
        )

        with self._monitor() as monitor:
            temp_file, file_size = await self._stream_to_temp_file(
                file,
                self.config.limits.max_activity_file_size,
                monitor,
            )

            try:
                filename = file.filename or "unknown"
                await self._to_thread(
                    self._inspect_activity_sync,
                    temp_file,
                    file_size,
                    filename,
                )
            finally:
                temp_file.close()

    def _inspect_activity_sync(
        self,
        temp_file: tempfile.SpooledTemporaryFile[bytes],
        file_size: int,
        filename: str,
    ) -> None:
        """
        Run synchronous activity-file inspection off the loop.

        Handles XXE-safe XML parsing for GPX/TCX and binary
        signature validation for FIT files.

        Args:
            temp_file: Spooled temp file holding the data.
            file_size: File size in bytes.
            filename: Sanitized filename for context.

        Raises:
            MimeTypeError: If the MIME type is not allowed.
            FileSignatureError: If the signature mismatches.
            FileProcessingError: If XML parsing fails.
        """
        _, ext = os.path.splitext(filename.lower())
        is_fit = ext == ".fit"
        sig_type = "fit" if is_fit else "activity"

        _, detected_mime = self._read_header_and_detect(
            temp_file, filename, sig_type
        )

        # MIME check — be lenient for FIT
        if not is_fit:
            self._enforce_mime(
                detected_mime,
                self.config.ALLOWED_ACTIVITY_MIMES,
                filename,
                error_code=ErrorCode.MIME_TYPE_MISMATCH,
            )

        # XXE-safe XML validation for GPX/TCX. The root element
        # must match the extension, so an arbitrary XML document
        # cannot be accepted under a .gpx name.
        if not is_fit:
            self.xml_validator.validate_xml_safety(
                temp_file, self.config.ACTIVITY_XML_ROOTS.get(ext)
            )

        logger.debug(
            "Activity file validation passed: %s (%s, %s bytes)",
            filename,
            detected_mime,
            file_size,
        )

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
        await self._run_validation(file, "gzip", self._validate_gzip_body)

    async def _validate_gzip_body(self, file: UploadFile) -> None:
        """
        Run gzip-specific validation steps.

        Args:
            file: Uploaded gzip file to validate.

        Raises:
            FileValidationError: If a gzip check fails.
            ZipBombError: If a decompression bomb is detected.
        """
        self._validate_filename(file)
        self._validate_file_extension(
            file,
            self.config.ALLOWED_GZIP_EXTENSIONS,
        )

        with self._monitor() as monitor:
            temp_file, file_size = await self._stream_to_temp_file(
                file,
                self.config.limits.max_gzip_size,
                monitor,
            )

            try:
                filename = file.filename or "unknown"
                await self._to_thread(
                    self._inspect_gzip_sync,
                    temp_file,
                    file_size,
                    filename,
                    monitor,
                )
            finally:
                temp_file.close()

    def _inspect_gzip_sync(
        self,
        temp_file: tempfile.SpooledTemporaryFile[bytes],
        file_size: int,
        filename: str,
        monitor: ResourceMonitor | None = None,
    ) -> None:
        """
        Run synchronous gzip inspection off the event loop.

        Args:
            temp_file: Spooled temp file holding the gzip data.
            file_size: Compressed size in bytes.
            filename: Sanitized filename for context.
            monitor: Optional resource monitor checked once per
                chunk so a slow stream is aborted mid-inflation.

        Raises:
            MimeTypeError: If the MIME type is not allowed.
            FileSignatureError: If the signature mismatches.
            ZipBombError: If a decompression bomb is detected.
            ResourceLimitError: If the monitor's time or memory
                limit is exceeded during inspection.
            CompressionSecurityError: If the gzip is invalid.
        """
        _, detected_mime = self._read_header_and_detect(
            temp_file, filename, "gzip"
        )

        # MIME check — allow octet-stream
        self._enforce_mime(
            detected_mime,
            self.config.ALLOWED_GZIP_MIMES,
            filename,
            allow_octet_stream=True,
            error_code=ErrorCode.MIME_TYPE_MISMATCH,
        )

        # Decompression bomb check
        self.gzip_inspector.inspect_gzip_content(temp_file, file_size, monitor)

        logger.debug(
            "Gzip file validation passed: %s (%s, %s bytes)",
            filename,
            detected_mime,
            file_size,
        )
