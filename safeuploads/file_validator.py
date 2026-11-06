"""Main file validator coordinating all security validations."""

import asyncio
import contextlib
import contextvars
import logging
import os
import tempfile
import time
from collections.abc import Callable, Generator, Mapping
from concurrent.futures import Executor
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypeVar

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
    bind_correlation_id,
    correlation_id_var,
)
from .config import FileSecurityConfig
from .exceptions import (
    ContentThreatError,
    ErrorCode,
    FilenameSecurityError,
    FileProcessingError,
    FileSecurityConfigurationError,
    FileSignatureError,
    FileSizeError,
    FileValidationError,
    ResourceLimitError,
)
from .inspectors import ZipContentInspector
from .inspectors.content_inspector import ContentSecurityInspector
from .inspectors.gzip_inspector import GzipContentInspector
from .protocols import SeekableFile
from .utils import (
    ResourceMonitor,
    allowed_extensions,
    bytes_to_mb,
    check_resource_limits,
)
from .validators import (
    CompressionSecurityValidator,
    ExtensionSecurityValidator,
    FilenameSecurityValidator,
    FileSignatureValidator,
    FitSecurityValidator,
    ImageDimensionValidator,
    MimeTypeValidator,
    UnicodeSecurityValidator,
    WindowsSecurityValidator,
)
from .validators.xml_validator import XmlSecurityValidator

logger = logging.getLogger(__name__)

_T = TypeVar("_T")


@dataclass
class _ValidationRun:
    """
    Mutable state of one validation call.

    Attributes:
        filename: Name used in terminal audit events; the raw name
            at first, the sanitized name once sanitization passed.
    """

    filename: str


@dataclass(frozen=True)
class ValidationResult:
    """
    What a successful validation verified about an upload.

    Attributes:
        filename: Sanitized filename. Its extension is one the
            configuration lists for ``mime_type``.
        mime_type: MIME type libmagic detected from the content,
            for the ``Content-Type`` of a stored or served copy. A
            ZIP or gzip that libmagic reports only as
            ``application/octet-stream`` carries the type its magic
            signature confirmed (``application/zip`` or
            ``application/gzip``).
    """

    filename: str
    mime_type: str


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
        filename_validator: Validator for path and length rules.
        signature_validator: Validator for file header signatures.
        mime_validator: Validator for content MIME detection.
        magic_mime: MIME type detector of the MIME validator.
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
            executor: Optional executor used by the async
                ``validate_*_file`` methods to run blocking
                inspection off the event loop. Defaults to the
                asyncio default thread pool. The ``*_sync`` methods
                never use it.

        Raises:
            FileSecurityConfigurationError: If the configuration
                has any error-severity issue.

        Attributes:
            config: Active security configuration.
            unicode_validator: Validator for Unicode-related checks.
            extension_validator: Validator for file extension rules.
            windows_validator: Validator enforcing Windows constraints.
            compression_validator: Validator for compressed file limits.
            zip_inspector: Inspector for ZIP archive contents.
            filename_validator: Validator for path and length rules.
            signature_validator: Validator for file header signatures.
            mime_validator: Validator for content MIME detection.
            magic_mime: MIME type detector of the MIME validator.
            magic_available: Whether python-magic initialized successfully.
        """
        self.config = config or FileSecurityConfig()
        self._executor = executor

        # Validate the actual (possibly custom) config in use and
        # log every issue by severity. Warnings never block
        # construction; any error-severity issue does.
        issues = self.config.validate_instance()
        for issue in issues:
            log = logger.error if issue.severity == "error" else logger.warning
            log(
                "Configuration %s: %s. %s",
                issue.component,
                issue.message,
                issue.recommendation,
            )
        config_errors = [i for i in issues if i.severity == "error"]
        if config_errors:
            raise FileSecurityConfigurationError(config_errors)

        # Initialize specialized validators
        self.unicode_validator = UnicodeSecurityValidator(self.config)
        self.extension_validator = ExtensionSecurityValidator(self.config)
        self.windows_validator = WindowsSecurityValidator(self.config)
        self.compression_validator = CompressionSecurityValidator(self.config)
        self.zip_inspector = ZipContentInspector(self.config)
        self.xml_validator = XmlSecurityValidator(self.config)
        self.fit_validator = FitSecurityValidator(self.config)
        self.image_dimension_validator = ImageDimensionValidator(self.config)
        self.gzip_inspector = GzipContentInspector(self.config)
        self.content_inspector = ContentSecurityInspector(self.config)
        self.filename_validator = FilenameSecurityValidator(self.config)
        self.signature_validator = FileSignatureValidator(self.config)
        self.mime_validator = MimeTypeValidator(self.config)

        # Initialize audit logger
        self._audit = SecurityAuditLogger(
            enabled=self.config.limits.enable_audit_logging
        )

    @property
    def magic_mime(self) -> magic.Magic:
        """MIME type detector owned by the MIME validator."""
        return self.mime_validator.magic_mime

    @magic_mime.setter
    def magic_mime(self, detector: magic.Magic) -> None:
        self.mime_validator.magic_mime = detector

    @property
    def magic_available(self) -> bool:
        """Whether python-magic initialized successfully."""
        return self.mime_validator.magic_available

    @magic_available.setter
    def magic_available(self, available: bool) -> None:
        self.mime_validator.magic_available = available

    def _submit(
        self, func: Callable[..., _T], *args: object
    ) -> asyncio.Future[_T]:
        """
        Schedule a blocking callable in a worker thread.

        Uses the configured executor when one was supplied,
        otherwise the default ``asyncio`` pool. The current context
        (including the correlation ID) is propagated to the worker
        thread in both cases.

        Args:
            func: Blocking callable to execute.
            *args: Positional arguments passed to ``func``.

        Returns:
            Future resolving to the value returned by ``func``.
        """
        ctx = contextvars.copy_context()

        def _call() -> _T:
            return ctx.run(func, *args)

        return asyncio.get_running_loop().run_in_executor(
            self._executor, _call
        )

    async def _to_thread(self, func: Callable[..., _T], *args: object) -> _T:
        """
        Run a blocking callable in a worker thread.

        Args:
            func: Blocking callable to execute.
            *args: Positional arguments passed to ``func``.

        Returns:
            The value returned by ``func``.
        """
        return await self._submit(func, *args)

    @staticmethod
    def _close_when_idle(
        temp_file: tempfile.SpooledTemporaryFile[bytes],
        worker: asyncio.Future[Any] | None,
    ) -> None:
        """
        Close a temp file once no worker thread is using it.

        A cancelled await leaves the worker thread running, so
        closing right away would race with its reads or writes.

        Args:
            temp_file: Temp file to close.
            worker: Future of the worker that may still use the
                file, or None when none was started.
        """
        if worker is None or worker.done():
            temp_file.close()
            return

        def _close(done: asyncio.Future[Any]) -> None:
            temp_file.close()
            if not done.cancelled():
                done.exception()  # mark retrieved

        worker.add_done_callback(_close)

    async def _inspect_temp_file(
        self,
        temp_file: tempfile.SpooledTemporaryFile[bytes],
        func: Callable[..., _T],
        *args: object,
    ) -> _T:
        """
        Run ``func(temp_file, *args)`` off the loop, then close the file.

        The worker future is shielded so that cancelling the
        caller closes the file only after the worker finished, and
        the cancellation propagates.

        Args:
            temp_file: Temp file handed to ``func`` and closed
                afterwards.
            func: Blocking inspection taking the temp file first.
            *args: Further positional arguments for ``func``.

        Returns:
            The value returned by ``func``.
        """
        worker: asyncio.Future[_T] | None = None
        try:
            worker = self._submit(func, temp_file, *args)
            return await asyncio.shield(worker)
        finally:
            self._close_when_idle(temp_file, worker)

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
        """
        # Preserve the raw input for truthful logging; every step
        # below reassigns ``filename`` as it sanitizes.
        original_filename = filename

        # Unicode security validation (must be first)
        # This detects and blocks Unicode-based attacks
        # before any other processing
        filename = self.unicode_validator.validate_unicode_security(filename)

        # Compatibility characters must not hide a path component
        # from basename (e.g. a fullwidth solidus)
        self.unicode_validator.compatibility_form(filename)

        # Remove path components and dangerous characters that could
        # be used for path traversal or command injection
        filename = self.filename_validator.replace_dangerous_characters(
            filename
        )

        # Name checks run on the NFC name and on its NFKC form, so
        # compatibility characters (fullwidth letters, superscript
        # digits) cannot disguise a reserved name or extension
        def check_name(name: str) -> None:
            for form in (
                name,
                self.unicode_validator.compatibility_form(name),
            ):
                # Windows reserved names come before any other check
                self.windows_validator.validate_windows_reserved_names(form)
                # Compound, double and every dangerous extension
                self.extension_validator.validate_extensions(form)

        check_name(filename)

        # Limit filename length (preserve extension) and avoid an
        # empty name
        filename = self.filename_validator.limit_length(filename)

        # Final checks on the returned name: truncation can expose a
        # blocked extension or a reserved name that the earlier checks
        # never saw, so both run again on the final filename
        check_name(filename)

        # Log with %r so control characters in the raw input are
        # escaped rather than injected into the log stream.
        logger.debug(
            "Filename sanitized: original=%r -> sanitized=%r",
            os.path.basename(original_filename),
            filename,
        )

        return filename

    def _validated_filename(self, filename: str | None) -> str:
        """
        Validate a filename and return its sanitized form.

        Args:
            filename: Filename supplied by the client.

        Returns:
            Sanitized filename.

        Raises:
            FilenameSecurityError: Filename is empty, invalid, or fails
                sanitization.
            FileProcessingError: Unexpected error during filename
                validation.
        """
        # Check filename
        if not filename:
            raise FilenameSecurityError(
                "Filename is required",
                error_code=ErrorCode.FILENAME_EMPTY,
            )

        # Sanitize the filename to prevent security issues
        try:
            return self._sanitize_filename(filename)
        except FileValidationError:
            # Let FileValidationError and subclasses propagate
            raise
        except Exception as err:
            logger.exception(
                "Unexpected error during filename validation: %r", err
            )
            raise FileProcessingError(
                "Filename validation failed due to internal error",
                original_error=err,
            ) from err

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
        file.filename = self._validated_filename(file.filename)

    @staticmethod
    def _raise_if_too_large(total_bytes: int, max_file_size: int) -> None:
        """
        Raise when the bytes read so far exceed the size limit.

        Args:
            total_bytes: Bytes read so far.
            max_file_size: Maximum allowed file size in bytes.

        Raises:
            FileSizeError: ``total_bytes`` exceeds ``max_file_size``.
        """
        if total_bytes > max_file_size:
            raise FileSizeError(
                f"File too large. Maximum: {bytes_to_mb(max_file_size)}MB",
                size=total_bytes,
                max_size=max_file_size,
            )

    @staticmethod
    def _raise_if_empty(total_bytes: int, max_file_size: int) -> None:
        """
        Raise when no bytes were read.

        Args:
            total_bytes: Total bytes read.
            max_file_size: Maximum allowed file size in bytes.

        Raises:
            FileSizeError: ``total_bytes`` is zero.
        """
        if total_bytes == 0:
            raise FileSizeError(
                "Empty file not allowed",
                size=0,
                max_size=max_file_size,
                error_code=ErrorCode.FILE_EMPTY,
            )

    def _new_spool(self) -> tempfile.SpooledTemporaryFile[bytes]:
        """
        Create the temp file that receives a streamed upload.

        Returns:
            Spooled temp file that spills to disk past
            ``max_memory_buffer_size``.
        """
        return tempfile.SpooledTemporaryFile(
            max_size=self.config.limits.max_memory_buffer_size
        )

    async def _stream_to_temp_file(
        self, file: UploadFile, max_file_size: int
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

        Returns:
            Tuple of SpooledTemporaryFile positioned at start and
            total bytes written. The original file is also seeked
            back to position 0 so callers can re-read it.

        Raises:
            FileSizeError: File exceeds maximum or is empty.

        On any failure, including cancellation, the temp file is
        closed (after an in-flight offloaded write finished) and
        the error propagates.
        """
        temp = self._new_spool()
        total_bytes = 0
        write_worker: asyncio.Future[int] | None = None
        spill_threshold = self.config.limits.max_memory_buffer_size
        chunk_size = self.config.limits.chunk_size

        await file.seek(0)

        try:
            while True:
                chunk = await file.read(chunk_size)
                check_resource_limits()
                if not chunk:
                    break
                total_bytes += len(chunk)
                self._raise_if_too_large(total_bytes, max_file_size)
                if total_bytes > spill_threshold:
                    # Past the in-memory buffer the write is disk I/O
                    write_worker = self._submit(temp.write, chunk)
                    await asyncio.shield(write_worker)
                else:
                    temp.write(chunk)

            self._raise_if_empty(total_bytes, max_file_size)

            temp.seek(0)
            await file.seek(0)
            return temp, total_bytes
        except BaseException:
            self._close_when_idle(temp, write_worker)
            raise

    def _stream_to_temp_file_sync(
        self, file: SeekableFile, max_file_size: int
    ) -> tuple[tempfile.SpooledTemporaryFile[bytes], int]:
        """
        Stream a seekable file to a SpooledTemporaryFile with size checks.

        Same rules as ``_stream_to_temp_file``; every write happens
        in the calling thread.

        Args:
            file: Seekable binary file.
            max_file_size: Maximum allowed file size in bytes.

        Returns:
            Tuple of SpooledTemporaryFile positioned at start and
            total bytes written. The original file is also seeked
            back to position 0.

        Raises:
            FileSizeError: File exceeds maximum or is empty.

        On any failure the temp file is closed and the error
        propagates.
        """
        temp = self._new_spool()
        total_bytes = 0
        chunk_size = self.config.limits.chunk_size

        file.seek(0)

        try:
            while True:
                chunk = file.read(chunk_size)
                check_resource_limits()
                if not chunk:
                    break
                total_bytes += len(chunk)
                self._raise_if_too_large(total_bytes, max_file_size)
                temp.write(chunk)

            self._raise_if_empty(total_bytes, max_file_size)

            temp.seek(0)
            file.seek(0)
            return temp, total_bytes
        except BaseException:
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
            MimeTypeError: If MIME detection fails.
            FileSignatureError: If the header does not match the
                expected signature type.
        """
        header = temp_file.read(8192)
        temp_file.seek(0)
        detected_mime = self.mime_validator.detect(header, filename)
        try:
            self.signature_validator.validate(header, sig_type)
        except FileSignatureError as err:
            raise FileSignatureError(
                f"File content does not match expected {sig_type} format",
                filename=filename,
                expected_type=sig_type,
                error_code=err.error_code,
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
            ContentThreatError: If the content scan reports one
                or more threats.
        """
        threats = self.content_inspector.scan_content(sample, filename, kind)
        if threats:
            raise ContentThreatError(
                f"Content analysis threats detected: {'; '.join(threats)}",
                filename=filename,
                threats=threats,
                error_code=ErrorCode.CONTENT_THREAT_DETECTED,
            )

    @contextlib.contextmanager
    def _validation_run(
        self, filename: str | None, file_type: str
    ) -> Generator[_ValidationRun]:
        """
        Wrap a validation with audit logging and error mapping.

        Binds a correlation ID, emits an audit start event and one
        terminal success, failure or resource-limit event, wraps
        unexpected errors in ``FileProcessingError`` and restores
        the correlation ID on exit.

        Args:
            filename: Raw filename supplied by the client.
            file_type: Label used in log messages.

        Yields:
            Run state whose ``filename`` the body sets to the
            sanitized name for the terminal audit event.

        Raises:
            FileValidationError: Propagated from the body.
            ResourceLimitError: Propagated from the body.
            FileProcessingError: Propagated as-is or wrapping an
                unexpected internal error.
        """
        cid, cid_token = bind_correlation_id()
        run = _ValidationRun(filename or "unknown")
        t0 = time.monotonic()
        try:
            self._audit.start(run.filename, cid)
            logger.debug(
                "Starting %s file validation: %r", file_type, run.filename
            )
            yield run
            ms = (time.monotonic() - t0) * 1000
            self._audit.success(run.filename, cid, ms)
        except ResourceLimitError as exc:
            ms = (time.monotonic() - t0) * 1000
            self._audit.resource_limit(run.filename, cid, ms, str(exc))
            raise
        except (
            FileValidationError,
            FileProcessingError,
        ) as exc:
            ms = (time.monotonic() - t0) * 1000
            self._audit.failure(run.filename, cid, ms, str(exc))
            raise
        except Exception as err:
            ms = (time.monotonic() - t0) * 1000
            self._audit.failure(run.filename, cid, ms, "internal_error")
            logger.exception(
                "Error during %s file validation: %r", file_type, err
            )
            raise FileProcessingError(
                "File validation failed due to internal error",
                original_error=err,
            ) from err
        finally:
            correlation_id_var.reset(cid_token)

    @staticmethod
    def _refuse_on_event_loop(sync_name: str, async_name: str) -> None:
        """
        Refuse a blocking call made on an event loop thread.

        Args:
            sync_name: Name of the blocking method being called.
            async_name: Name of its async counterpart.

        Raises:
            RuntimeError: The calling thread runs an event loop.
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return
        raise RuntimeError(
            f"{sync_name}() blocks and cannot run on an event loop "
            f"thread; await {async_name}() or run it in a worker thread"
        )

    def _inspect_image_sync(
        self,
        temp_file: tempfile.SpooledTemporaryFile[bytes],
        file_size: int,
        filename: str,
    ) -> str:
        """
        Run blocking image inspection on a temp file.

        Checks, in order, MIME type, signature, the dimensions the
        header declares and content threats.

        Args:
            temp_file: Spooled temp file holding the image.
            file_size: Image size in bytes.
            filename: Sanitized filename for context.

        Returns:
            Detected MIME type.

        Raises:
            MimeTypeError: If the MIME type is not allowed or does
                not permit the extension.
            FileSignatureError: If the signature mismatches or the
                dimension header is missing or invalid.
            ImageDimensionError: If the header declares more than
                ``max_image_pixels`` pixels.
            ContentThreatError: If content analysis finds threats.
        """
        header = temp_file.read(8192)
        temp_file.seek(0)
        detected_mime = self.mime_validator.detect(header, filename)
        self.mime_validator.enforce(
            detected_mime,
            self.config.ALLOWED_IMAGE_TYPES,
            filename,
            error_code=ErrorCode.MIME_TYPE_MISMATCH,
        )
        self.signature_validator.validate(header, "image")
        self.image_dimension_validator.validate(temp_file, filename=filename)

        if self.config.limits.enable_content_analysis:
            sample = temp_file.read(self.config.limits.content_scan_max_size)
            temp_file.seek(0)
            self._raise_on_content_threats(sample, filename, "image")

        logger.debug(
            "Image file validation passed: %r (%s, %s bytes)",
            filename,
            detected_mime,
            file_size,
        )
        return detected_mime

    def _resource_monitor(self) -> ResourceMonitor:
        """
        Create the resource monitor configured for one validation.

        Returns:
            Monitor with the configured time and memory budgets.
        """
        return ResourceMonitor(
            max_time_seconds=self.config.limits.max_validation_time_seconds,
            max_memory_mb=self.config.limits.max_validation_memory_mb,
        )

    async def validate_image_file(self, file: UploadFile) -> ValidationResult:
        """
        Validate an uploaded PNG, JPEG or WebP image.

        Checks filename, extension, size, MIME type, signature and
        the pixel count the image header declares, then runs the
        optional content scan.

        Args:
            file: Uploaded file to validate.

        Returns:
            Sanitized filename and detected MIME type.

        Raises:
            FilenameSecurityError: Filename is empty, invalid, or fails
                security checks.
            ExtensionSecurityError: File extension is not allowed or is
                blocked.
            FileSizeError: File size exceeds maximum or file is empty.
            MimeTypeError: MIME type is not in allowed image types, or
                the extension is not one listed for it.
            FileSignatureError: File signature doesn't match expected image
                format, or the dimension header is missing or invalid.
            ImageDimensionError: The image header declares more than
                ``max_image_pixels`` pixels.
            ContentThreatError: Content analysis found threats.
            FileProcessingError: Unexpected error during validation.
        """
        with self._validation_run(file.filename, "image") as run:
            return await self._validate_streamed(
                file,
                run,
                self.config.ALLOWED_IMAGE_TYPES,
                self.config.limits.max_image_size,
                self._inspect_image_sync,
            )

    def validate_image_file_sync(
        self, file: SeekableFile, filename: str
    ) -> ValidationResult:
        """
        Validate an image from a seekable file in the calling thread.

        Runs the same checks, in the same order, as
        ``validate_image_file``. It blocks, so it cannot run on an
        event loop thread; await ``validate_image_file()`` or run
        this in a worker thread. The file is rewound to position 0
        on success and is never closed.

        Args:
            file: Seekable binary file to validate.
            filename: Filename supplied by the client.

        Returns:
            Sanitized filename and detected MIME type.

        Raises:
            RuntimeError: Called on a thread running an event loop.
            FilenameSecurityError: Filename is empty, invalid, or fails
                security checks.
            ExtensionSecurityError: File extension is not allowed or is
                blocked.
            FileSizeError: File size exceeds maximum or file is empty.
            MimeTypeError: MIME type is not in allowed image types, or
                the extension is not one listed for it.
            FileSignatureError: File signature doesn't match expected image
                format, or the dimension header is missing or invalid.
            ImageDimensionError: The image header declares more than
                ``max_image_pixels`` pixels.
            ContentThreatError: Content analysis found threats.
            FileProcessingError: Unexpected error during validation.
        """
        self._refuse_on_event_loop(
            "validate_image_file_sync", "validate_image_file"
        )
        with self._validation_run(filename, "image") as run:
            return self._validate_streamed_sync(
                file,
                filename,
                run,
                self.config.ALLOWED_IMAGE_TYPES,
                self.config.limits.max_image_size,
                self._inspect_image_sync,
            )

    async def _validate_streamed(
        self,
        file: UploadFile,
        run: _ValidationRun,
        allowed_types: Mapping[str, frozenset[str]],
        max_file_size: int,
        inspect: Callable[
            [tempfile.SpooledTemporaryFile[bytes], int, str], str
        ],
    ) -> ValidationResult:
        """
        Validate an upload that is streamed to a temp file.

        Sanitizes the filename, checks its extension, streams the
        upload under the size limit and runs ``inspect`` in a worker
        thread.

        Args:
            file: Uploaded file to validate.
            run: Run state; its ``filename`` is set to the
                sanitized name.
            allowed_types: Allowed MIME types mapped to the
                extensions each one permits.
            max_file_size: Maximum allowed file size in bytes.
            inspect: Blocking inspection of the temp file, taking
                the temp file, its size and the sanitized name and
                returning the detected MIME type.

        Returns:
            Sanitized filename and detected MIME type.

        Raises:
            FileValidationError: If a validation check fails.
        """
        self._validate_filename(file)
        filename = file.filename or "unknown"
        run.filename = filename
        self.extension_validator.validate_allowed(
            filename, allowed_extensions(allowed_types)
        )

        with self._resource_monitor():
            temp_file, file_size = await self._stream_to_temp_file(
                file, max_file_size
            )
            detected_mime = await self._inspect_temp_file(
                temp_file, inspect, file_size, filename
            )
        return ValidationResult(filename, detected_mime)

    def _validate_streamed_sync(
        self,
        file: SeekableFile,
        filename: str,
        run: _ValidationRun,
        allowed_types: Mapping[str, frozenset[str]],
        max_file_size: int,
        inspect: Callable[
            [tempfile.SpooledTemporaryFile[bytes], int, str], str
        ],
    ) -> ValidationResult:
        """
        Validate a seekable file by streaming it to a temp file.

        Same steps as ``_validate_streamed`` with every step in the
        calling thread.

        Args:
            file: Seekable binary file to validate.
            filename: Filename supplied by the client.
            run: Run state; its ``filename`` is set to the
                sanitized name.
            allowed_types: Allowed MIME types mapped to the
                extensions each one permits.
            max_file_size: Maximum allowed file size in bytes.
            inspect: Blocking inspection of the temp file, taking
                the temp file, its size and the sanitized name and
                returning the detected MIME type.

        Returns:
            Sanitized filename and detected MIME type.

        Raises:
            FileValidationError: If a validation check fails.
        """
        name = self._validated_filename(filename)
        run.filename = name
        self.extension_validator.validate_allowed(
            name, allowed_extensions(allowed_types)
        )

        with self._resource_monitor():
            temp_file, file_size = self._stream_to_temp_file_sync(
                file, max_file_size
            )
            try:
                detected_mime = inspect(temp_file, file_size, name)
            finally:
                temp_file.close()
        return ValidationResult(name, detected_mime)

    async def validate_zip_file(self, file: UploadFile) -> ValidationResult:
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
            MimeTypeError: MIME type is not in allowed ZIP types, or
                the extension is not one listed for it.
            FileSignatureError: File signature doesn't match expected ZIP
                format.
            CompressionSecurityError: ZIP compression validation failed
                (zip bomb detected).
            ContentThreatError: Content analysis found threats.
            FileProcessingError: Unexpected error during validation.
        """
        with self._validation_run(file.filename, "ZIP") as run:
            return await self._validate_streamed(
                file,
                run,
                self.config.ALLOWED_ZIP_TYPES,
                self.config.limits.max_zip_size,
                self._inspect_zip_sync,
            )

    def validate_zip_file_sync(
        self, file: SeekableFile, filename: str
    ) -> ValidationResult:
        """
        Validate a ZIP archive from a seekable file in the calling thread.

        Runs the same checks, in the same order, as
        ``validate_zip_file``. It blocks, so it cannot run on an
        event loop thread; await ``validate_zip_file()`` or run
        this in a worker thread. The file is rewound to position 0
        on success and is never closed.

        Args:
            file: Seekable binary file to validate.
            filename: Filename supplied by the client.

        Returns:
            Sanitized filename and detected MIME type.

        Raises:
            RuntimeError: Called on a thread running an event loop.
            FilenameSecurityError: Filename is empty, invalid, or fails
                security checks.
            ExtensionSecurityError: File extension is not allowed or is
                blocked.
            FileSizeError: File size exceeds maximum or file is empty.
            MimeTypeError: MIME type is not in allowed ZIP types, or
                the extension is not one listed for it.
            FileSignatureError: File signature doesn't match expected ZIP
                format.
            CompressionSecurityError: ZIP compression validation failed
                (zip bomb detected).
            ContentThreatError: Content analysis found threats.
            FileProcessingError: Unexpected error during validation.
        """
        self._refuse_on_event_loop(
            "validate_zip_file_sync", "validate_zip_file"
        )
        with self._validation_run(filename, "ZIP") as run:
            return self._validate_streamed_sync(
                file,
                filename,
                run,
                self.config.ALLOWED_ZIP_TYPES,
                self.config.limits.max_zip_size,
                self._inspect_zip_sync,
            )

    def _inspect_zip_sync(
        self,
        temp_file: tempfile.SpooledTemporaryFile[bytes],
        file_size: int,
        filename: str,
    ) -> str:
        """
        Run blocking ZIP inspection on a temp file.

        Args:
            temp_file: Spooled temp file holding the ZIP data.
            file_size: Compressed archive size in bytes.
            filename: Sanitized filename for context.

        Returns:
            Detected MIME type, or ``application/zip`` when libmagic
            reports only ``application/octet-stream``.

        Raises:
            MimeTypeError: If the MIME type is not allowed or does
                not permit the extension.
            FileSignatureError: If the signature mismatches.
            CompressionSecurityError: If a zip bomb is detected.
            ContentThreatError: If content analysis finds threats.
        """
        # Read header for MIME/signature checks
        _, detected_mime = self._read_header_and_detect(
            temp_file, filename, "zip"
        )

        # Check MIME type, allow octet-stream if signature valid
        self.mime_validator.enforce(
            detected_mime,
            self.config.ALLOWED_ZIP_TYPES,
            filename,
            allow_octet_stream=True,
            error_code=ErrorCode.MIME_TYPE_MISMATCH,
        )
        # The signature confirmed the type libmagic left generic
        if detected_mime == "application/octet-stream":
            detected_mime = "application/zip"

        # Validate ZIP compression ratio
        self.compression_validator.validate_zip_compression_ratio(
            temp_file, file_size
        )

        # Perform ZIP content inspection if enabled
        if self.config.limits.scan_zip_content:
            temp_file.seek(0)
            self.zip_inspector.inspect_zip_content(temp_file)

        logger.debug(
            "ZIP file validation passed: %r (%s, %s bytes)",
            filename,
            detected_mime,
            file_size,
        )
        return detected_mime

    async def validate_activity_file(
        self, file: UploadFile
    ) -> ValidationResult:
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
            MimeTypeError: MIME type not allowed, or the extension
                is not one listed for it.
            FileSignatureError: Signature mismatch.
            XmlSecurityError: The XML is forbidden or malformed.
            FileProcessingError: Unexpected error during validation.
        """
        with self._validation_run(file.filename, "activity") as run:
            return await self._validate_streamed(
                file,
                run,
                self.config.ALLOWED_ACTIVITY_TYPES,
                self.config.limits.max_activity_file_size,
                self._inspect_activity_sync,
            )

    def validate_activity_file_sync(
        self, file: SeekableFile, filename: str
    ) -> ValidationResult:
        """
        Validate an activity file from a seekable file in this thread.

        Runs the same checks, in the same order, as
        ``validate_activity_file``. It blocks, so it cannot run on an
        event loop thread; await ``validate_activity_file()`` or run
        this in a worker thread. The file is rewound to position 0
        on success and is never closed.

        Args:
            file: Seekable binary file to validate.
            filename: Filename supplied by the client.

        Returns:
            Sanitized filename and detected MIME type.

        Raises:
            RuntimeError: Called on a thread running an event loop.
            FilenameSecurityError: Filename fails security.
            ExtensionSecurityError: Extension not allowed.
            FileSizeError: File exceeds size limit or empty.
            MimeTypeError: MIME type not allowed, or the extension
                is not one listed for it.
            FileSignatureError: Signature mismatch.
            XmlSecurityError: The XML is forbidden or malformed.
            FileProcessingError: Unexpected error during validation.
        """
        self._refuse_on_event_loop(
            "validate_activity_file_sync", "validate_activity_file"
        )
        with self._validation_run(filename, "activity") as run:
            return self._validate_streamed_sync(
                file,
                filename,
                run,
                self.config.ALLOWED_ACTIVITY_TYPES,
                self.config.limits.max_activity_file_size,
                self._inspect_activity_sync,
            )

    def _inspect_activity_sync(
        self,
        temp_file: tempfile.SpooledTemporaryFile[bytes],
        file_size: int,
        filename: str,
    ) -> str:
        """
        Run blocking activity-file inspection on a temp file.

        Handles XXE-safe XML parsing for GPX/TCX and binary
        signature validation for FIT files.

        Args:
            temp_file: Spooled temp file holding the data.
            file_size: File size in bytes.
            filename: Sanitized filename for context.

        Returns:
            Detected MIME type.

        Raises:
            MimeTypeError: If the MIME type is not allowed or does
                not permit the extension.
            FileSignatureError: If the signature mismatches or the
                FIT structure is invalid.
            XmlSecurityError: If the XML is forbidden or malformed.
            ContentThreatError: If optional content analysis finds
                a threat.
        """
        _, ext = os.path.splitext(filename.lower())
        is_fit = ext == ".fit"
        sig_type = "fit" if is_fit else "activity"

        _, detected_mime = self._read_header_and_detect(
            temp_file, filename, sig_type
        )

        self.mime_validator.enforce(
            detected_mime,
            self.config.ALLOWED_ACTIVITY_TYPES,
            filename,
            error_code=ErrorCode.MIME_TYPE_MISMATCH,
        )

        if is_fit:
            self.fit_validator.validate(temp_file, filename=filename)
        else:
            # XXE-safe XML validation for GPX/TCX
            self.xml_validator.validate_xml_safety(
                temp_file, filename=filename
            )

        # Optional content analysis
        if self.config.limits.enable_content_analysis:
            temp_file.seek(0)
            scan_size = self.config.limits.content_scan_max_size
            sample = temp_file.read(scan_size)
            temp_file.seek(0)
            self._raise_on_content_threats(sample, filename, "activity")

        logger.debug(
            "Activity file validation passed: %r (%s, %s bytes)",
            filename,
            detected_mime,
            file_size,
        )
        return detected_mime

    async def validate_gzip_file(self, file: UploadFile) -> ValidationResult:
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
            MimeTypeError: MIME type not allowed, or the extension
                is not one listed for it.
            FileSignatureError: Signature mismatch.
            ZipBombError: Decompression bomb detected.
            CompressionSecurityError: Invalid gzip structure.
            FileProcessingError: Unexpected error.
        """
        with self._validation_run(file.filename, "gzip") as run:
            return await self._validate_streamed(
                file,
                run,
                self.config.ALLOWED_GZIP_TYPES,
                self.config.limits.max_gzip_size,
                self._inspect_gzip_sync,
            )

    def validate_gzip_file_sync(
        self, file: SeekableFile, filename: str
    ) -> ValidationResult:
        """
        Validate a gzip archive from a seekable file in this thread.

        Runs the same checks, in the same order, as
        ``validate_gzip_file``. It blocks, so it cannot run on an
        event loop thread; await ``validate_gzip_file()`` or run
        this in a worker thread. The file is rewound to position 0
        on success and is never closed.

        Args:
            file: Seekable binary file to validate.
            filename: Filename supplied by the client.

        Returns:
            Sanitized filename and detected MIME type.

        Raises:
            RuntimeError: Called on a thread running an event loop.
            FilenameSecurityError: Filename fails security.
            ExtensionSecurityError: Extension not allowed.
            FileSizeError: File exceeds size limit or empty.
            MimeTypeError: MIME type not allowed, or the extension
                is not one listed for it.
            FileSignatureError: Signature mismatch.
            ZipBombError: Decompression bomb detected.
            CompressionSecurityError: Invalid gzip structure.
            FileProcessingError: Unexpected error during validation.
        """
        self._refuse_on_event_loop(
            "validate_gzip_file_sync", "validate_gzip_file"
        )
        with self._validation_run(filename, "gzip") as run:
            return self._validate_streamed_sync(
                file,
                filename,
                run,
                self.config.ALLOWED_GZIP_TYPES,
                self.config.limits.max_gzip_size,
                self._inspect_gzip_sync,
            )

    def _inspect_gzip_sync(
        self,
        temp_file: tempfile.SpooledTemporaryFile[bytes],
        file_size: int,
        filename: str,
    ) -> str:
        """
        Run blocking gzip inspection on a temp file.

        Args:
            temp_file: Spooled temp file holding the gzip data.
            file_size: Compressed size in bytes.
            filename: Sanitized filename for context.

        Returns:
            Detected MIME type, or ``application/gzip`` when libmagic
            reports only ``application/octet-stream``.

        Raises:
            MimeTypeError: If the MIME type is not allowed or does
                not permit the extension.
            FileSignatureError: If the signature mismatches.
            ZipBombError: If a decompression bomb is detected.
            CompressionSecurityError: If the gzip is invalid.
        """
        _, detected_mime = self._read_header_and_detect(
            temp_file, filename, "gzip"
        )

        # MIME check — allow octet-stream
        self.mime_validator.enforce(
            detected_mime,
            self.config.ALLOWED_GZIP_TYPES,
            filename,
            allow_octet_stream=True,
            error_code=ErrorCode.MIME_TYPE_MISMATCH,
        )
        # The signature confirmed the type libmagic left generic
        if detected_mime == "application/octet-stream":
            detected_mime = "application/gzip"

        # Decompression bomb check
        self.gzip_inspector.inspect_gzip_content(temp_file, file_size)

        logger.debug(
            "Gzip file validation passed: %r (%s, %s bytes)",
            filename,
            detected_mime,
            file_size,
        )
        return detected_mime
