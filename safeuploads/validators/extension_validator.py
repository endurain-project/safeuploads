"""
Extension Security Validator Module

Handles validation of file extensions for security threats.
"""

from typing import TYPE_CHECKING

from .base import BaseValidator

if TYPE_CHECKING:
    from ..config import FileSecurityConfig


class ExtensionSecurityValidator(BaseValidator):
    """
    Validates filenames against configured forbidden extensions to guard against risky uploads.
    This validator checks for both compound extensions (e.g., ".tar.gz") and any
    individual blocked extension segments within a filename. If a prohibited
    extension is detected, a descriptive ValueError is raised to prevent the upload.
        config (FileSecurityConfig): Configuration providing lists of blocked and compound blocked extensions.
    """

    def __init__(self, config: "FileSecurityConfig"):
        """
        Initialize the validator with the provided file security configuration.

        Args:
            config (FileSecurityConfig): The file security settings that control how file extensions are validated.
        """
        super().__init__(config)

    def validate_extensions(self, filename: str) -> None:
        """
        Validate a filename against blocked extensions to prevent unsafe uploads.

        Args:
            filename (str): Name of the file being validated, including its extension(s).

        Raises:
            ValueError: If the filename ends with a blocked compound extension or contains
                any blocked single extension segment.
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
        Validate the given filename by delegating to :meth:`validate_extensions`.

        Args:
            filename (str): Name of the file whose extension should be validated.

        Raises:
            ValidationError: If the filename extension is not permitted.
        """
        return self.validate_extensions(filename)
