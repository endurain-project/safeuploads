"""Neutralize path components and unsafe characters in filenames."""

from __future__ import annotations

import logging
import os
import secrets
from typing import TYPE_CHECKING

from .base import BaseValidator

if TYPE_CHECKING:
    from ..config import FileSecurityConfig


logger = logging.getLogger(__name__)

_DANGEROUS_CHARS = '<>:"/\\|?*'


def _truncate_utf8(text: str, max_bytes: int) -> str:
    """
    Cut text to at most ``max_bytes`` UTF-8 bytes on a code point.

    Args:
        text: Text to shorten.
        max_bytes: Maximum UTF-8 length of the result.

    Returns:
        ``text`` unchanged when it fits, otherwise its longest
        prefix of whole characters that fits.
    """
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    # UTF-8 continuation bytes are 0b10xxxxxx; step back from the
    # first byte past the limit to the start of its character, so
    # a character that crosses the limit is dropped whole.
    end = max_bytes
    while end > 0 and encoded[end] & 0xC0 == 0x80:
        end -= 1
    return encoded[:end].decode("utf-8")


class FilenameSecurityValidator(BaseValidator):
    """
    Reduces filenames to a bounded, path-free form.

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

    def replace_dangerous_characters(self, filename: str) -> str:
        r"""
        Drop path components and replace characters unsafe in paths.

        Args:
            filename: Filename that already passed Unicode checks.

        Returns:
            Basename of ``filename`` with each of ``<>:"/\|?*``
            replaced by an underscore.
        """
        filename = os.path.basename(filename)
        for char in _DANGEROUS_CHARS:
            filename = filename.replace(char, "_")
        return filename

    def limit_length(self, filename: str) -> str:
        """
        Truncate the base name and replace an empty one.

        The base name is limited in UTF-8 bytes, the unit filesystem
        name limits use, and is cut between characters. The extension
        is preserved. A blank base name is replaced by a random
        ``file_<hex>`` name so no upload ends up as just an extension.

        Args:
            filename: Filename returned by
                :meth:`replace_dangerous_characters`.

        Returns:
            Filename whose base name is at most
            ``max_sanitized_name_length`` UTF-8 bytes and not blank.
        """
        name_part, ext_part = os.path.splitext(filename)
        max_name_bytes = self.config.limits.max_sanitized_name_length
        truncated = _truncate_utf8(name_part, max_name_bytes)
        if truncated != name_part:
            logger.debug(
                "Truncating sanitized name to %d bytes", max_name_bytes
            )
            name_part = truncated
            filename = name_part + ext_part

        if not name_part or name_part.strip() == "":
            filename = f"file_{secrets.token_hex(8)}{ext_part}"

        return filename

    def validate(self, filename: str) -> str:
        """
        Replace path components and dangerous characters.

        Args:
            filename: Filename that already passed Unicode checks.

        Returns:
            Basename of ``filename`` with dangerous characters
            replaced.
        """
        return self.replace_dangerous_characters(filename)
