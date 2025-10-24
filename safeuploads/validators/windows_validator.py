"""
Windows Security Validator Module

Handles validation of Windows-specific security threats.
"""

import os
from typing import TYPE_CHECKING

from .base import BaseValidator

if TYPE_CHECKING:
    from ..config import FileSecurityConfig


class WindowsSecurityValidator(BaseValidator):
    """
    Validator that ensures filenames do not use Windows reserved device names
    by stripping extensions and dots before comparison.
    """

    def __init__(self, config: "FileSecurityConfig"):
        """
        Initialize the validator with the provided file security configuration.

        Args:
            config (FileSecurityConfig): Application-wide file security settings
            used to enforce validation rules.
        """
        super().__init__(config)

    def validate_windows_reserved_names(self, filename: str) -> None:
        """
        Validate the given filename against Windows reserved device names.

        Args:
            filename (str): The original filename, potentially including an extension.

        Raises:
            ValueError: If the filename (ignoring leading and trailing dots as well as file extension)
                matches one of the Windows reserved device names.
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
        Validate a filename against Windows reserved naming rules.

        Args:
            filename (str): Name of the file to validate.

        Raises:
            ValueError: If the filename matches a Windows reserved name.
        """
        return self.validate_windows_reserved_names(filename)
