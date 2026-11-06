"""Detect and enforce MIME types from file content using libmagic."""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Mapping
from typing import TYPE_CHECKING

import magic

from ..exceptions import ErrorCode, MimeTypeError
from ..utils import allowed_extensions
from .base import BaseValidator

if TYPE_CHECKING:
    from ..config import FileSecurityConfig


logger = logging.getLogger(__name__)


class MimeTypeValidator(BaseValidator):
    """
    Detects content MIME types and checks them against extensions.

    Attributes:
        config: File security configuration settings.
        magic_mime: python-magic detector; unset when initialization
            failed.
        magic_available: Whether python-magic initialized successfully.
    """

    def __init__(self, config: FileSecurityConfig):
        """
        Initialize the validator and the libmagic detector.

        Initialization failure is logged and leaves
        ``magic_available`` False, so every detection is rejected.

        Args:
            config: File security configuration settings.
        """
        super().__init__(config)

        # libmagic cookies are not thread-safe and detection may run
        # in worker threads, so access to the shared instance is
        # serialized.
        self._magic_lock = threading.Lock()

        try:
            self.magic_mime = magic.Magic(mime=True)
            self.magic_available = True
            logger.debug("File content detection (python-magic) initialized")
        except Exception as err:
            self.magic_available = False
            logger.error(
                "python-magic not available for content detection;"
                " uploads will be rejected: %s",
                err,
            )

    def detect(self, content: bytes, filename: str) -> str:
        """
        Determine MIME type for file content using libmagic.

        Detection never falls back to the filename: the extension
        is already allow-listed, so a guess from it would let the
        MIME check pass for any content.

        Args:
            content: Raw bytes of the file to inspect.
            filename: Filename used for error context.

        Returns:
            Detected MIME type.

        Raises:
            MimeTypeError: If libmagic is unavailable, raises, or
                returns an empty result
                (``ErrorCode.MIME_DETECTION_FAILED``).
        """
        if not self.magic_available:
            raise MimeTypeError(
                "File type could not be determined",
                filename=filename,
                error_code=ErrorCode.MIME_DETECTION_FAILED,
            )

        try:
            with self._magic_lock:
                detected_mime = self.magic_mime.from_buffer(content)
        except Exception as err:
            logger.error("Magic MIME detection failed: %s", err)
            raise MimeTypeError(
                "File type could not be determined",
                filename=filename,
                error_code=ErrorCode.MIME_DETECTION_FAILED,
            ) from err

        if not detected_mime:
            raise MimeTypeError(
                "File type could not be determined",
                filename=filename,
                error_code=ErrorCode.MIME_DETECTION_FAILED,
            )

        return detected_mime

    def enforce(
        self,
        detected: str,
        allowed_types: Mapping[str, frozenset[str]],
        filename: str,
        *,
        allow_octet_stream: bool = False,
        error_code: str | None = None,
    ) -> None:
        """
        Raise unless the detected MIME type permits the extension.

        The detected type must be allowed, and the filename's
        extension must be one listed for it, so the name never
        claims a format other than the content's.

        Args:
            detected: MIME type reported for the content.
            allowed_types: Allowed MIME types for the category, each
                mapped to the extensions its content may carry.
            filename: Sanitized filename whose extension is checked.
            allow_octet_stream: Accept ``application/octet-stream``
                under any extension of the category when a valid
                magic signature already passed.
            error_code: Optional error code for a MIME type that is
                not allowed.

        Raises:
            MimeTypeError: If the MIME type is not allowed, or with
                ``ErrorCode.EXTENSION_MIME_MISMATCH`` if the
                extension is not one listed for it.
        """
        _, ext = os.path.splitext(filename.lower())
        extensions = allowed_types.get(detected)
        if extensions is None:
            if not (
                allow_octet_stream and detected == "application/octet-stream"
            ):
                raise MimeTypeError(
                    "Invalid file type."
                    f" Detected: {detected}."
                    f" Allowed: {', '.join(sorted(allowed_types))}",
                    filename=filename,
                    detected_mime=detected,
                    allowed_mimes=list(allowed_types),
                    error_code=error_code,
                )
            logger.debug(
                "Accepting application/octet-stream for %r"
                " on a valid signature",
                filename,
            )
            extensions = allowed_extensions(allowed_types)
        if ext in extensions:
            return
        matching = sorted(
            mime for mime, exts in allowed_types.items() if ext in exts
        )
        raise MimeTypeError(
            "File content does not match its extension."
            f" Detected: {detected}."
            f" Allowed for '{ext}': {', '.join(matching) or 'none'}",
            filename=filename,
            detected_mime=detected,
            allowed_mimes=matching,
            error_code=ErrorCode.EXTENSION_MIME_MISMATCH,
        )

    def validate(self, content: bytes, filename: str) -> str:
        """
        Detect the MIME type of the given content.

        Args:
            content: Raw bytes of the file to inspect.
            filename: Filename used for error context.

        Returns:
            Detected MIME type.

        Raises:
            MimeTypeError: If detection fails.
        """
        return self.detect(content, filename)
