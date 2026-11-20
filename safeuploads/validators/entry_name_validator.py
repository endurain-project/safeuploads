"""Validate names stored in archives the way extractors write them."""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, NamedTuple

from ..audit import get_correlation_id, log_extra
from ..enums import SuspiciousFilePattern, ZipThreatCategory
from ..exceptions import ErrorCode, FilenameSecurityError, ZipContentError
from .base import BaseValidator
from .compression_validator import (
    PERMITTED_NESTED_ARCHIVE_EXTS,
    effective_entry_name,
    entry_extension,
)
from .extension_validator import ExtensionSecurityValidator
from .unicode_validator import UnicodeSecurityValidator
from .windows_validator import WindowsSecurityValidator

if TYPE_CHECKING:
    from ..audit import SecurityAuditLogger
    from ..config import FileSecurityConfig


logger = logging.getLogger(__name__)


class EntryThreat(NamedTuple):
    """
    One threat found in an archive.

    Attributes:
        code: ``ErrorCode`` raised when this threat is the first found.
        message: Human-readable description.
    """

    code: str
    message: str


def content_threat(message: str) -> EntryThreat:
    """Return a threat reported as ``ZIP_CONTENT_THREAT``."""
    return EntryThreat(ErrorCode.ZIP_CONTENT_THREAT, message)


def raise_threats(
    threats: list[EntryThreat], audit: SecurityAuditLogger, subject: str
) -> None:
    """
    Log, audit and raise the threats found, if there are any.

    Args:
        threats: Threats found, in the order they were found.
        audit: Audit logger the threat summary is recorded with.
        subject: What was inspected, leading the error message
            (``ZIP content``).

    Raises:
        ZipContentError: If ``threats`` is not empty, with the code
            of its first threat.
    """
    if not threats:
        return
    messages = [threat.message for threat in threats]
    summary = "; ".join(messages)
    logger.warning(
        "%s threats detected",
        subject,
        extra=log_extra(
            {
                "error_type": "zip_content_threat",
                "threats": messages,
                "threat_count": len(messages),
            }
        ),
    )
    cid = get_correlation_id()
    if cid:
        audit.threat("", cid, summary)
    raise ZipContentError(
        message=f"{subject} threats detected: {summary}",
        threats=messages,
        error_code=threats[0].code,
    )


class EntryNameValidator(BaseValidator):
    """
    Checks a name stored in an archive before anything is extracted.

    ZIP entry names and gzip member names (FNAME) get the same
    checks: traversal, absolute paths, length limits, suspicious
    names, nested archive names, the top-level filename checks and
    dangerous extensions. Extension and base-name checks run on the
    name as extractors write it (``effective_entry_name``), so
    ``evil.exe/.`` is checked as ``evil.exe``.

    Attributes:
        config: File security configuration.
    """

    def __init__(self, config: FileSecurityConfig):
        """
        Initialize the validator with configuration.

        Args:
            config: File security configuration.
        """
        super().__init__(config)
        self._traversal_patterns: tuple[str, ...] = tuple(
            p.lower() for p in SuspiciousFilePattern.DIRECTORY_TRAVERSAL.value
        )
        self._suspicious_names: frozenset[str] = frozenset(
            n.lower() for n in SuspiciousFilePattern.SUSPICIOUS_NAMES.value
        )
        self._suspicious_paths: tuple[str, ...] = tuple(
            p.lower() for p in SuspiciousFilePattern.SUSPICIOUS_PATHS.value
        )
        self._nested_archive_exts: frozenset[str] = frozenset(
            ZipThreatCategory.NESTED_ARCHIVES.value
        )
        self._dangerous_exts: frozenset[str] = frozenset(
            ZipThreatCategory.EXECUTABLE_FILES.value
            | ZipThreatCategory.SCRIPT_FILES.value
            | ZipThreatCategory.SYSTEM_FILES.value
        )
        self._unicode = UnicodeSecurityValidator(config)
        self._windows = WindowsSecurityValidator(config)
        self._extensions = ExtensionSecurityValidator(config)

    def name_threats(self, name: str, *, is_dir: bool) -> list[EntryThreat]:
        """
        Return the threats a stored name carries.

        A directory has no base name or extension, so only its path
        is checked.

        Args:
            name: Name as stored in the archive.
            is_dir: Whether the name is a directory entry's.

        Returns:
            Threats found, each with the code it is reported as.
        """
        threats: list[EntryThreat] = []
        limits = self.config.limits
        base = "" if is_dir else effective_entry_name(name).rpartition("/")[2]
        extension = "" if is_dir else entry_extension(name)

        if self._has_directory_traversal(name):
            threats.append(
                EntryThreat(
                    ErrorCode.ZIP_DIRECTORY_TRAVERSAL,
                    f"Directory traversal attack in '{name}'",
                )
            )

        if not limits.allow_absolute_paths and self._has_absolute_path(name):
            threats.append(
                EntryThreat(
                    ErrorCode.ZIP_ABSOLUTE_PATH,
                    f"Absolute path detected in '{name}'",
                )
            )

        last = os.path.basename(name)
        if len(last) > limits.max_filename_length:
            threats.append(
                content_threat(
                    f"Filename too long: '{name}' ({len(last)} chars)"
                )
            )

        if len(name) > limits.max_path_length:
            threats.append(
                content_threat(f"Path too long: '{name}' ({len(name)} chars)")
            )

        threats.extend(
            content_threat(message)
            for message in self._check_suspicious_patterns(name, base)
        )

        if self._archive_extension_rejected(extension):
            threats.append(
                EntryThreat(
                    ErrorCode.ZIP_NESTED_ARCHIVE,
                    f"Nested archive detected: '{name}'",
                )
            )

        threats.extend(self._check_name(name, is_dir))

        if extension in self._dangerous_exts:
            threats.append(
                content_threat(f"Dangerous file type detected: '{name}'")
            )

        return threats

    def unicode_threats(self, name: str) -> list[EntryThreat]:
        """
        Return a threat if a name fails the Unicode checks.

        Args:
            name: Name to check.

        Returns:
            One threat if the name holds a dangerous character or
            compatibility characters that fold to a path separator,
            otherwise none.
        """
        try:
            self._unicode.compatibility_form(
                self._unicode.validate_unicode_security(name)
            )
        except FilenameSecurityError as err:
            return [self._unsafe_name(name, err)]
        return []

    def archive_name_rejected(self, name: str) -> bool:
        """
        Check if a file name names a nested archive that is rejected.

        Every archive extension is rejected, except a ZIP archive's
        or a gzip stream's when ``allow_nested_archives`` is enabled.

        Args:
            name: File name to check.

        Returns:
            True if the name is a rejected nested archive.
        """
        return self._archive_extension_rejected(entry_extension(name))

    def validate(self, name: str) -> None:
        """
        Validate a stored file name.

        Args:
            name: File name as stored in the archive.

        Raises:
            ZipContentError: If the name carries a threat, with the
                code of the first threat found.
        """
        raise_threats(
            self.name_threats(name, is_dir=False),
            self._audit,
            "Archive entry name",
        )

    def _archive_extension_rejected(self, extension: str) -> bool:
        """Check if an extension is a nested archive's that is rejected."""
        return extension in self._nested_archive_exts and not (
            self.config.limits.allow_nested_archives
            and extension in PERMITTED_NESTED_ARCHIVE_EXTS
        )

    def _has_directory_traversal(self, name: str) -> bool:
        """
        Check for directory traversal indicators.

        A component of only dots and spaces with at least two dots
        (``..``, ``. .``, ``.. ``) is a traversal wherever it appears,
        including at the end of the name.

        Args:
            name: Name to check.

        Returns:
            True if traversal detected.
        """
        name_lower = name.lower()

        for pattern in self._traversal_patterns:
            if pattern in name_lower:
                return True

        # Windows drops trailing dots and spaces from a component, so
        # one of only dots and spaces with two or more dots is ``..``
        for component in name.replace("\\", "/").split("/"):
            if component.count(".") > 1 and not component.strip(". "):
                return True

        # Additional checks for normalized paths
        normalized = os.path.normpath(name)
        return (
            normalized.startswith("..")
            or "/.." in normalized
            or "\\.." in normalized
        )

    @staticmethod
    def _has_absolute_path(name: str) -> bool:
        """
        Check if a name is an absolute path.

        Args:
            name: Path to check.

        Returns:
            True if absolute path detected.
        """
        return (
            name.startswith(("/", "\\"))  # Unix/Windows path
            or (len(name) > 1 and name[1] == ":")  # Windows drive path
        )

    def _check_suspicious_patterns(self, name: str, base: str) -> list[str]:
        """
        Check a name for suspicious patterns.

        Args:
            name: Name to check.
            base: Base name as extracted; empty for a directory.

        Returns:
            List of pattern warnings.
        """
        threats = []
        name_lower = name.lower()

        if base.lower() in self._suspicious_names:
            threats.append(f"Suspicious filename pattern: '{name}'")

        for pattern in self._suspicious_paths:
            if pattern in name_lower:
                threats.append(
                    f"Suspicious path component: '{name}' contains '{pattern}'"
                )
                break

        return threats

    def _check_name(self, name: str, is_dir: bool) -> list[EntryThreat]:
        """
        Apply the top-level filename checks to a stored name.

        The whole name gets the Unicode checks and must not contain
        ``:``, which NTFS reads as an alternate data stream or device
        separator (``run.exe::$DATA``, ``CON:``); every component of
        the name as extracted gets the Windows reserved-name check
        and a file's base name the blocked and compound extension
        checks, all driven by the configuration. Name checks run on
        the NFC name and on its NFKC form.

        Args:
            name: Name to check.
            is_dir: Whether the name is a directory entry's.

        Returns:
            One threat if the name fails a check, otherwise none.
        """
        try:
            normalized = self._unicode.validate_unicode_security(name)
            if ":" in normalized or ":" in self._unicode.compatibility_form(
                normalized
            ):
                return [
                    content_threat(
                        f"Unsafe file name {name!r}:"
                        " ':' is not allowed in entry names"
                    )
                ]
            components = effective_entry_name(normalized).split("/")
            for component in components:
                for form in (
                    component,
                    self._unicode.compatibility_form(component),
                ):
                    self._windows.validate_windows_reserved_names(form)
            if not is_dir:
                base = components[-1]
                for form in (base, self._unicode.compatibility_form(base)):
                    self._extensions.validate_extensions(form)
        except FilenameSecurityError as err:
            return [self._unsafe_name(name, err)]
        return []

    @staticmethod
    def _unsafe_name(name: str, err: FilenameSecurityError) -> EntryThreat:
        """Return the threat for a name a filename check rejected."""
        # repr escapes control and bidi characters in the message
        return content_threat(f"Unsafe file name {name!r}: {err.message}")
