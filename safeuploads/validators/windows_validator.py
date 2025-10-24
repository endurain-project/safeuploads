"""Windows security validator for filename validation."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from .base import BaseValidator

if TYPE_CHECKING:
    from ..config import FileSecurityConfig


class WindowsSecurityValidator(BaseValidator):
    """
    Validator for Windows reserved device names.

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

    def validate_windows_reserved_names(self, filename: str) -> None:
        """
        Validate filename against Windows reserved device names.

        Args:
            filename: The filename to validate.

        Raises:
            ValueError: If filename matches a Windows reserved name.
        """
        name_without_ext = os.path.splitext(filename)[0].lower().strip()
        # Remove leading dots to handle hidden files like ".CON.jpg"
        name_without_ext = name_without_ext.lstrip(".")
        # Remove trailing dots to handle cases like "con." or "con.."
        name_without_ext = name_without_ext.rstrip(".")

        if name_without_ext in self.config.WINDOWS_RESERVED_NAMES:
            raise ValueError(
                f"Filename '{filename}' uses Windows reserved name '{name_without_ext.upper()}'. "
                f"Reserved names: {', '.join(sorted(self.config.WINDOWS_RESERVED_NAMES)).upper()}"
            )

    def validate(self, filename: str) -> None:
        """
        Validate filename against Windows reserved naming rules.

        Args:
            filename: The filename to validate.

        Raises:
            ValueError: If filename matches a Windows reserved name.
        """
        return self.validate_windows_reserved_names(filename)
