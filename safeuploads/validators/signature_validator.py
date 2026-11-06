"""Verify that file content starts with the expected signature."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ..exceptions import ErrorCode, FileSignatureError
from .base import BaseValidator

if TYPE_CHECKING:
    from ..config import FileSecurityConfig


logger = logging.getLogger(__name__)

_SIGNATURES: dict[str, list[bytes]] = {
    "image": [
        b"\xff\xd8\xff",  # JPEG
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


class FileSignatureValidator(BaseValidator):
    """
    Checks the leading bytes of a file against its expected type.

    Attributes:
        config: File security configuration settings.
    """

    def __init__(self, config: FileSecurityConfig):
        """
        Initialize the validator.

        Args:
            config: File security configuration settings.
        """
        super().__init__(config)

    def validate(
        self,
        content: bytes,
        expected_type: str,
        *,
        filename: str | None = None,
    ) -> None:
        """
        Verify content begins with a known signature for the type.

        Args:
            content: Leading bytes of the uploaded file.
            expected_type: Logical file category ("image", "zip",
                "gzip", "activity" or "fit").
            filename: Optional sanitized filename for error context.

        Raises:
            FileSignatureError: Content is too short or its header
                does not match the expected type.
        """
        if len(content) < 4:
            raise FileSignatureError(
                f"File too small to verify {expected_type} signature",
                filename=filename,
                expected_type=expected_type,
                error_code=ErrorCode.FILE_SIGNATURE_MISSING,
            )

        for signature in _SIGNATURES.get(expected_type, []):
            if content.startswith(signature):
                logger.debug(
                    "File signature matched for type '%s'", expected_type
                )
                return

        # WebP: a RIFF container whose form type at bytes 8-11 is
        # "WEBP"; WAV and AVI share the "RIFF" prefix.
        if (
            expected_type == "image"
            and content[:4] == b"RIFF"
            and content[8:12] == b"WEBP"
        ):
            return

        # FIT files: ".FIT" at bytes 8-11
        if (
            expected_type == "fit"
            and len(content) >= 12
            and content[8:12] == b".FIT"
        ):
            return

        # Activity XML files may carry a UTF-8 BOM and/or leading
        # whitespace before the XML declaration; tolerate both.
        if expected_type == "activity":
            head = content
            if head.startswith(b"\xef\xbb\xbf"):
                head = head[3:]
            if head.lstrip().startswith(b"<?xml"):
                return

        raise FileSignatureError(
            f"File content does not match expected {expected_type} format",
            filename=filename,
            expected_type=expected_type,
        )
