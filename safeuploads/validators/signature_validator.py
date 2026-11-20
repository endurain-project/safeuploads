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
    # Readers accept the header anywhere in the first 1024 bytes;
    # requiring it at offset 0 rejects files that are another
    # format first (HTML, JPEG or ZIP polyglots).
    "pdf": [
        b"%PDF-",
    ],
}


# An XML declaration is "<?xml" followed by XML whitespace; without
# the whitespace it is another processing instruction, such as
# "<?xml-stylesheet".
_XML_DECLARATION = b"<?xml"
_XML_WHITESPACE = frozenset(b" \t\r\n")


def _starts_with_xml_declaration(content: bytes) -> bool:
    """
    Report whether content opens with an XML declaration.

    A UTF-8 BOM and leading whitespace before the declaration are
    tolerated.

    Args:
        content: Leading bytes of the uploaded file.

    Returns:
        Whether ``<?xml`` followed by a space, tab, CR or LF opens
        the content.
    """
    head = content.removeprefix(b"\xef\xbb\xbf").lstrip()
    end = len(_XML_DECLARATION)
    return (
        head.startswith(_XML_DECLARATION)
        and len(head) > end
        and head[end] in _XML_WHITESPACE
    )


# ISOBMFF brands of HEVC-coded still images (HEIF Main and Main 10
# profiles); AVIF, image sequences and other codecs carry others.
_HEIC_BRANDS = frozenset({b"heic", b"heix"})
# ftyp box header (8), major brand (4) and minor version (4)
_FTYP_MIN_SIZE = 16


def _is_heic(content: bytes) -> bool:
    """
    Report whether content starts with a HEIC file type box.

    Args:
        content: Leading bytes of the uploaded file.

    Returns:
        Whether an ftyp box opens the file and lists an HEVC
        still-image brand as its major or a compatible brand.
    """
    if content[4:8] != b"ftyp":
        return False
    size = int.from_bytes(content[:4], "big")
    if not _FTYP_MIN_SIZE <= size <= len(content):
        return False
    brands = {content[8:12]}
    brands.update(
        content[i : i + 4] for i in range(_FTYP_MIN_SIZE, size - 3, 4)
    )
    return not _HEIC_BRANDS.isdisjoint(brands)


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
                "gzip", "activity", "fit" or "pdf").
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

        # HEIC: an ISOBMFF ftyp box naming an HEVC still-image brand
        if expected_type == "image" and _is_heic(content):
            return

        # FIT files: ".FIT" at bytes 8-11
        if (
            expected_type == "fit"
            and len(content) >= 12
            and content[8:12] == b".FIT"
        ):
            return

        # GPX/TCX: an XML declaration, optionally after a UTF-8 BOM
        # and whitespace
        if expected_type == "activity" and _starts_with_xml_declaration(
            content
        ):
            return

        raise FileSignatureError(
            f"File content does not match expected {expected_type} format",
            filename=filename,
            expected_type=expected_type,
        )
