"""Unicode Security Validator Module."""

from __future__ import annotations

import logging
import unicodedata
from typing import TYPE_CHECKING

from ..exceptions import ErrorCode, FilenameSecurityError, UnicodeSecurityError
from .base import BaseValidator

if TYPE_CHECKING:
    from ..config import FileSecurityConfig


logger = logging.getLogger(__name__)

# Unicode general categories rejected outright: controls (Cc), format
# characters (Cf), private use (Co), unassigned (Cn), surrogates (Cs),
# line separators (Zl) and paragraph separators (Zp).
_REJECTED_CATEGORIES: frozenset[str] = frozenset(
    {"Cc", "Cf", "Co", "Cn", "Cs", "Zl", "Zp"}
)


class UnicodeSecurityValidator(BaseValidator):
    """
    Validates filenames for Unicode security threats.

    Attributes:
        config: Runtime configuration for file security rules.
    """

    def __init__(self, config: FileSecurityConfig):
        """
        Initialize the Unicode validator.

        Args:
            config: Runtime configuration that controls
                file security rules.
        """
        super().__init__(config)
        # Pre-compile as frozenset for O(1) code point lookup
        self._dangerous_chars: frozenset[int] = frozenset(
            config.DANGEROUS_UNICODE_CHARS
        )

    def validate_unicode_security(self, filename: str) -> str:
        """
        Validate filename for unsafe Unicode characters.

        Args:
            filename: The filename to validate and normalize.

        Returns:
            The NFC-normalized filename.

        Raises:
            UnicodeSecurityError: If dangerous Unicode characters are
                detected in the filename or result from normalization.
        """
        if not filename:
            return filename

        logger.debug("Validating Unicode safety of filename")

        # Check for dangerous Unicode characters
        dangerous_chars_found = []
        for i, char in enumerate(filename):
            char_code = ord(char)
            if (
                char_code in self._dangerous_chars
                or unicodedata.category(char) in _REJECTED_CATEGORIES
            ):
                dangerous_chars_found.append((char, char_code, i))

        # If dangerous characters found, reject the file entirely
        if dangerous_chars_found:
            char_details = []
            for char, code, pos in dangerous_chars_found:
                char_name = unicodedata.name(char, f"U+{code:04X}")
                char_details.append(
                    f"{char!r} (U+{code:04X}: {char_name}) at position {pos}"
                )

            logger.warning(
                "Dangerous Unicode characters detected",
                extra={
                    "error_type": "unicode_security",
                    "file_name": filename,
                    "char_codes": [
                        code for _, code, _ in dangerous_chars_found
                    ],
                    "positions": [pos for _, _, pos in dangerous_chars_found],
                },
            )
            raise UnicodeSecurityError(
                message=(
                    "Dangerous Unicode characters"
                    " detected in filename:"
                    f" {', '.join(char_details)}."
                    " These characters can be used"
                    " to disguise file extensions"
                    " or create security"
                    " vulnerabilities."
                ),
                filename=filename,
                dangerous_chars=dangerous_chars_found,
            )

        # Normalize Unicode to prevent normalization attacks
        # Use NFC (Canonical Decomposition, then
        # Canonical Composition). This prevents attacks
        # where different Unicode representations of
        # the same text are used.
        normalized_filename = unicodedata.normalize("NFC", filename)

        # Check if normalization changed the filename significantly
        if normalized_filename != filename:
            logger.info(
                "Unicode normalization applied: %r -> %r",
                filename,
                normalized_filename,
            )

        # Additional check: ensure normalized filename
        # doesn't contain dangerous chars
        # (some normalization attacks might introduce
        # them)
        for char in normalized_filename:
            char_code = ord(char)
            if char_code in self._dangerous_chars:
                char_name = unicodedata.name(char, f"U+{char_code:04X}")
                logger.error(
                    "Unicode normalization resulted in dangerous character",
                    extra={
                        "error_type": "unicode_normalization_error",
                        "file_name": filename,
                        "normalized_filename": normalized_filename,
                        "char_code": char_code,
                    },
                )
                raise UnicodeSecurityError(
                    message=(
                        "Unicode normalization resulted"
                        " in dangerous character:"
                        f" '{char}'"
                        f" (U+{char_code:04X}:"
                        f" {char_name})"
                    ),
                    filename=filename,
                    dangerous_chars=[(char, char_code, 0)],
                    error_code=ErrorCode.UNICODE_NORMALIZATION_ERROR,
                )

        logger.debug("Unicode validation passed")
        return normalized_filename

    def compatibility_form(self, filename: str) -> str:
        """
        Return the NFKC form of a filename for security checks.

        The NFKC form folds compatibility characters (fullwidth
        letters, superscript digits) onto the ASCII text they
        impersonate. It is only used to run name checks; callers keep
        the NFC name.

        Args:
            filename: The NFC-normalized filename.

        Returns:
            The NFKC-normalized filename.

        Raises:
            FilenameSecurityError: If NFKC folding introduces a path
                separator or ``..`` that the NFC form does not
                contain.
        """
        folded = unicodedata.normalize("NFKC", filename)
        hidden = [
            token
            for token in ("/", "\\", "..")
            if token in folded and token not in filename
        ]
        if hidden:
            logger.warning(
                "Compatibility characters hide a path component",
                extra={
                    "error_type": "unicode_path_hiding",
                    "file_name": filename,
                },
            )
            raise FilenameSecurityError(
                message=(
                    "Filename contains compatibility characters that"
                    " normalize to a path separator or parent"
                    " directory reference."
                ),
                filename=filename,
                error_code=ErrorCode.FILENAME_INVALID,
            )
        return folded

    def validate(self, filename: str) -> str:
        """
        Validate a filename for Unicode security issues.

        Args:
            filename: The name of the file to assess.

        Returns:
            The validated and normalized filename.
        """
        return self.validate_unicode_security(filename)
