"""Validate file extensions against security policies."""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

from ..exceptions import (
    ErrorCode,
    ExtensionSecurityError,
    FilenameSecurityError,
)
from .base import BaseValidator

if TYPE_CHECKING:
    from ..config import FileSecurityConfig


logger = logging.getLogger(__name__)


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
        # Pre-compile as frozensets for O(1) lookup
        self._blocked: frozenset[str] = frozenset(config.BLOCKED_EXTENSIONS)
        self._compound_blocked: tuple[str, ...] = tuple(
            config.COMPOUND_BLOCKED_EXTENSIONS
        )

    def validate_extensions(self, filename: str) -> None:
        """
        Validate filename against blocked extensions.

        Args:
            filename: Name of the file to validate.

        Raises:
            ExtensionSecurityError: If blocked compound or single
                extension detected in filename.
        """
        # Check for compound dangerous extensions first
        # (e.g., .tar.xz, .user.js)
        filename_lower = filename.lower()
        logger.debug("Validating extensions in filename")
        for compound_ext in self._compound_blocked:
            if filename_lower.endswith(compound_ext):
                logger.warning(
                    "Dangerous compound extension detected",
                    extra={
                        "error_type": "compound_extension_blocked",
                        "file_name": filename,
                        "extension": compound_ext,
                    },
                )
                raise ExtensionSecurityError(
                    message=(
                        f"Dangerous compound file extension"
                        f" '{compound_ext}' detected"
                        f" in filename."
                        f" Upload rejected for security."
                    ),
                    filename=filename,
                    extension=compound_ext,
                    error_code=ErrorCode.COMPOUND_EXTENSION_BLOCKED,
                )

        # Check ALL extensions in the filename for dangerous ones
        parts = filename.split(".")
        if len(parts) > 1:
            for i in range(1, len(parts)):
                ext = f".{parts[i].lower()}"
                if ext in self._blocked:
                    logger.warning(
                        "Dangerous extension detected",
                        extra={
                            "error_type": "extension_blocked",
                            "file_name": filename,
                            "extension": ext,
                        },
                    )
                    raise ExtensionSecurityError(
                        message=(
                            f"Dangerous file extension"
                            f" '{ext}' detected"
                            f" in filename."
                            f" Upload rejected for security."
                        ),
                        filename=filename,
                        extension=ext,
                        error_code=ErrorCode.EXTENSION_BLOCKED,
                    )

        logger.debug("Extension validation passed")

    def validate_allowed(
        self, filename: str | None, allowed_extensions: frozenset[str]
    ) -> None:
        """
        Validate a filename extension against allowed and blocked lists.

        Args:
            filename: Name of the file whose extension is checked.
            allowed_extensions: Set of allowed file extensions.

        Raises:
            FilenameSecurityError: Filename is missing.
            ExtensionSecurityError: Extension is missing, not allowed
                or blocked.
        """
        if not filename:
            raise FilenameSecurityError(
                "Filename is required for extension validation",
                error_code=ErrorCode.FILENAME_EMPTY,
            )

        _, ext = os.path.splitext(filename.lower())
        if not ext:
            raise ExtensionSecurityError(
                "File has no extension",
                filename=filename,
                extension="",
                error_code=ErrorCode.EXTENSION_MISSING,
            )
        if ext not in allowed_extensions:
            raise ExtensionSecurityError(
                (
                    "Invalid file extension."
                    " Allowed:"
                    f" {', '.join(sorted(allowed_extensions))}"
                ),
                filename=filename,
                extension=ext,
                error_code=ErrorCode.EXTENSION_NOT_ALLOWED,
            )

        if ext in self.config.BLOCKED_EXTENSIONS:
            raise ExtensionSecurityError(
                f"File extension {ext} is blocked for security reasons",
                filename=filename,
                extension=ext,
                error_code=ErrorCode.EXTENSION_BLOCKED,
            )

        logger.debug("File extension '%s' accepted", ext)

    def validate(self, filename: str) -> None:
        """
        Validate the given filename.

        Args:
            filename: Name of the file to validate.

        Raises:
            ExtensionSecurityError: If filename extension is not
                permitted.
        """
        return self.validate_extensions(filename)
