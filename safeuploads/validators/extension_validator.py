from __future__ import annotations

from typing import TYPE_CHECKING

from .base import BaseValidator

if TYPE_CHECKING:
    from ..config import FileSecurityConfig


class ExtensionSecurityValidator(BaseValidator):
    """
    Validates filenames against configured forbidden extensions.

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

    def validate_extensions(self, filename: str) -> None:
        """
        Validate filename against blocked extensions.

        Args:
            filename: Name of the file to validate.

        Raises:
            ValueError: If blocked compound or single extension detected.
        """
        # Check for compound dangerous extensions first (e.g., .tar.xz, .user.js)
        filename_lower = filename.lower()
        for compound_ext in self.config.COMPOUND_BLOCKED_EXTENSIONS:
            if filename_lower.endswith(compound_ext):
                raise ValueError(
                    f"Dangerous compound file extension '{compound_ext}' detected in filename. Upload rejected for security."
                )

        # Check ALL extensions in the filename for dangerous ones
        parts = filename.split(".")
        if len(parts) > 1:
            for i in range(1, len(parts)):
                if f".{parts[i].lower()}" in self.config.BLOCKED_EXTENSIONS:
                    raise ValueError(
                        f"Dangerous file extension '.{parts[i].lower()}' detected in filename. Upload rejected for security."
                    )

    def validate(self, filename: str) -> None:
        """
        Validate the given filename.

        Args:
            filename: Name of the file to validate.

        Raises:
            ValueError: If filename extension is not permitted.
        """
        return self.validate_extensions(filename)
