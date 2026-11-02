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

        The extension is preserved. A blank base name is replaced by
        a random ``file_<hex>`` name so no upload ends up as just an
        extension.

        Args:
            filename: Filename returned by
                :meth:`replace_dangerous_characters`.

        Returns:
            Filename whose base name is at most
            ``max_sanitized_name_length`` characters and not blank.
        """
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
