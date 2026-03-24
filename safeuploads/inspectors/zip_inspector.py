"""ZIP content inspector for security threat detection."""

from __future__ import annotations

import hashlib
import io
import logging
import os
import time
import zipfile
from typing import TYPE_CHECKING

from ..enums import (
    BinaryFileCategory,
    SuspiciousFilePattern,
    ZipThreatCategory,
)
from ..exceptions import ErrorCode, FileProcessingError, ZipContentError
from ..audit import SecurityAuditLogger, get_correlation_id, log_extra

if TYPE_CHECKING:
    from ..config import FileSecurityConfig
    from ..protocols import SeekableFile


logger = logging.getLogger(__name__)


class ZipContentInspector:
    """
    Inspects ZIP archive contents for security threats.

    Attributes:
        config: File security configuration.
    """

    def __init__(self, config: FileSecurityConfig):
        """
        Initialize ZIP inspector with configuration.

        Args:
            config: File security configuration.
        """
        self.config = config
        self._audit = SecurityAuditLogger(
            enabled=config.limits.enable_audit_logging
        )

    def inspect_zip_content(self, file_obj: SeekableFile) -> None:
        """
        Inspect ZIP archive for potential security threats.

        Args:
            file_obj: Seekable file-like object containing ZIP data.

        Raises:
            ZipContentError: If security threats are detected in ZIP
                content such as directory traversal, symlinks, nested
                archives, or suspicious patterns.
            FileProcessingError: If ZIP structure is invalid or
                unexpected error occurs during inspection.
        """
        try:
            file_obj.seek(0)
            threats_found = []

            # Start analysis timer
            start_time = time.monotonic()

            with zipfile.ZipFile(file_obj, "r") as zip_file:
                zip_entries = zip_file.infolist()

                # Analyze each entry in the ZIP
                for entry in zip_entries:
                    # Check for timeout
                    if (
                        time.monotonic() - start_time
                        > self.config.limits.zip_analysis_timeout
                    ):
                        logger.error(
                            "ZIP content inspection timeout",
                            extra=log_extra({
                                "error_type": "zip_analysis_timeout",
                                "timeout": (
                                    self.config.limits.zip_analysis_timeout
                                ),
                            }),
                        )
                        raise ZipContentError(
                            message=(
                                "ZIP content inspection"
                                " timeout after"
                                f" {self.config.limits.zip_analysis_timeout}s"
                            ),
                            threats=["Analysis timeout - potential zip bomb"],
                            error_code=ErrorCode.ZIP_ANALYSIS_TIMEOUT,
                        )

                    # Inspect individual entry
                    entry_threats = self._inspect_zip_entry(entry, zip_file)
                    threats_found.extend(entry_threats)

                # Check for ZIP structure threats
                structure_threats = self._inspect_zip_structure(zip_entries)
                threats_found.extend(structure_threats)

                # Return results
                if threats_found:
                    logger.warning(
                        "ZIP content threats detected",
                        extra=log_extra({
                            "error_type": "zip_content_threat",
                            "threats": threats_found,
                            "threat_count": len(threats_found),
                        }),
                    )
                    cid = get_correlation_id()
                    if cid:
                        self._audit.threat(
                            "",
                            cid,
                            "; ".join(threats_found),
                        )
                    raise ZipContentError(
                        message=(
                            "ZIP content threats"
                            " detected:"
                            f" {'; '.join(threats_found)}"
                        ),
                        threats=threats_found,
                    )

                logger.debug(
                    "ZIP content inspection passed: %s entries analyzed",
                    len(zip_entries),
                )

            # Recursive nested archive inspection
            # when nested archives are allowed
            if self.config.limits.allow_nested_archives:
                file_obj.seek(0)
                self.inspect_nested_archives(file_obj)

        except ZipContentError:
            # Re-raise our own exceptions
            raise
        except zipfile.BadZipFile as err:
            logger.error(
                "Invalid or corrupted ZIP file structure", exc_info=True
            )
            raise FileProcessingError(
                message="Invalid or corrupted ZIP file structure",
                original_error=err,
            ) from err
        except Exception as err:
            logger.error(
                "Unexpected error during ZIP content inspection",
                exc_info=True,
            )
            raise FileProcessingError(
                message="ZIP content inspection failed "
                "due to an internal error",
                original_error=err,
            ) from err

    def _inspect_zip_entry(
        self, entry: zipfile.ZipInfo, zip_file: zipfile.ZipFile
    ) -> list[str]:
        """
        Inspect single ZIP entry for security threats.

        Args:
            entry: ZIP entry metadata.
            zip_file: Parent ZIP archive.

        Returns:
            List of threat descriptions.
        """
        threats = []
        filename = entry.filename

        # 1. Check for null bytes (truncation attacks)
        if "\x00" in filename:
            threats.append(f"Null byte in filename: '{filename}'")

        # 2. Check for directory traversal attacks
        if self._has_directory_traversal(filename):
            threats.append(f"Directory traversal attack in '{filename}'")

        # 3. Check for absolute paths
        if (
            not self.config.limits.allow_absolute_paths
            and self._has_absolute_path(filename)
        ):
            threats.append(f"Absolute path detected in '{filename}'")

        # 4. Check for symbolic links
        if not self.config.limits.allow_symlinks and self._is_symlink(entry):
            threats.append(f"Symbolic link detected: '{filename}'")

        # 5. Check filename length limits
        if (
            len(os.path.basename(filename))
            > self.config.limits.max_filename_length
        ):
            threats.append(
                f"Filename too long: '{filename}'"
                f" ({len(os.path.basename(filename))}"
                " chars)"
            )

        # 6. Check path length limits
        if len(filename) > self.config.limits.max_path_length:
            threats.append(
                f"Path too long: '{filename}' ({len(filename)} chars)"
            )

        # 7. Check for suspicious filename patterns
        suspicious_patterns = self._check_suspicious_patterns(filename)
        threats.extend(suspicious_patterns)

        # 8. Check for nested archives
        if (
            not self.config.limits.allow_nested_archives
            and self._is_nested_archive(filename)
        ):
            threats.append(f"Nested archive detected: '{filename}'")

        # 9. Check file content if enabled and entry is small enough
        if (
            self.config.limits.scan_zip_content
            and not entry.is_dir()
            and entry.file_size < 1024 * 1024
        ):  # 1MB limit for content scan
            content_threats = self._inspect_entry_content(entry, zip_file)
            threats.extend(content_threats)

        return threats

    def _inspect_zip_structure(
        self, entries: list[zipfile.ZipInfo]
    ) -> list[str]:
        """
        Inspect ZIP structure for anomalies.

        Args:
            entries: All ZIP entries to analyze.

        Returns:
            List of structural threat descriptions.
        """
        threats = []

        # Check directory depth
        max_depth = 0
        for entry in entries:
            depth = entry.filename.count("/") + entry.filename.count("\\")
            max_depth = max(max_depth, depth)

        if max_depth > self.config.limits.max_zip_depth:
            threats.append(
                f"Excessive directory depth: {max_depth}"
                f" (max: {self.config.limits.max_zip_depth})"
            )

        # Check for suspicious file distribution
        file_types = {}
        for entry in entries:
            if not entry.is_dir():
                ext = os.path.splitext(entry.filename)[1].lower()
                file_types[ext] = file_types.get(ext, 0) + 1

        # Check for excessive number of same-type files (potential spam/bomb)
        for ext, count in file_types.items():
            if count > self.config.limits.max_number_files_same_type:
                threats.append(
                    f"Excessive number of {ext} files:"
                    f" {self.config.limits.max_number_files_same_type}"
                )

        return threats

    def _has_directory_traversal(self, filename: str) -> bool:
        """
        Check for directory traversal indicators.

        Args:
            filename: Filename to check.

        Returns:
            True if traversal detected.
        """
        filename_lower = filename.lower()

        for category in SuspiciousFilePattern:
            if category == SuspiciousFilePattern.DIRECTORY_TRAVERSAL:
                for pattern in category.value:
                    if pattern.lower() in filename_lower:
                        return True

        # Additional checks for normalized paths
        normalized = os.path.normpath(filename)
        return (
            normalized.startswith("..")
            or "/.." in normalized
            or "\\.." in normalized
        )

    def _has_absolute_path(self, filename: str) -> bool:
        """
        Check if filename is an absolute path.

        Args:
            filename: Path to check.

        Returns:
            True if absolute path detected.
        """
        return (
            filename.startswith(("/", "\\"))  # Unix/Windows path
            or (len(filename) > 1 and filename[1] == ":")  # Windows drive path
        )

    def _is_symlink(self, entry: zipfile.ZipInfo) -> bool:
        """
        Check if entry is a symbolic link.

        Args:
            entry: ZIP entry to check.

        Returns:
            True if entry is a symlink.
        """
        # Check if entry has symlink attributes
        return (entry.external_attr >> 16) & 0o120000 == 0o120000

    def _check_suspicious_patterns(self, filename: str) -> list[str]:
        """
        Check filename for suspicious patterns.

        Args:
            filename: Filename to check.

        Returns:
            List of pattern warnings.
        """
        threats = []
        filename_lower = filename.lower()
        basename = os.path.basename(filename_lower)

        # Check suspicious names
        for pattern in SuspiciousFilePattern.SUSPICIOUS_NAMES.value:
            if basename == pattern.lower():
                threats.append(f"Suspicious filename pattern: '{filename}'")
                break

        # Check suspicious path components
        for pattern in SuspiciousFilePattern.SUSPICIOUS_PATHS.value:
            if pattern.lower() in filename_lower:
                threats.append(
                    "Suspicious path component:"
                    f" '{filename}' contains"
                    f" '{pattern}'"
                )
                break

        return threats

    def _is_nested_archive(self, filename: str) -> bool:
        """
        Check if filename represents a nested archive.

        Args:
            filename: Filename to check.

        Returns:
            True if nested archive detected.
        """
        ext = os.path.splitext(filename)[1].lower()

        for category in ZipThreatCategory:
            if category == ZipThreatCategory.NESTED_ARCHIVES:
                return ext in category.value

        return False

    def _inspect_entry_content(
        self, entry: zipfile.ZipInfo, zip_file: zipfile.ZipFile
    ) -> list[str]:
        """
        Inspect ZIP entry content for malicious signatures.

        Args:
            entry: ZIP entry to inspect.
            zip_file: Parent ZIP archive.

        Returns:
            List of content threat descriptions.
        """
        threats = []

        try:
            # Read first few bytes to check for executable signatures
            with zip_file.open(entry, "r") as file:
                content_sample = file.read(512)  # Read first 512 bytes

                # Check for executable signatures
                for (
                    signature
                ) in SuspiciousFilePattern.EXECUTABLE_SIGNATURES.value:
                    if content_sample.startswith(signature):
                        threats.append(
                            "Executable content"
                            f" detected in"
                            f" '{entry.filename}'"
                        )
                        break

                binary_exts = set()
                for category in BinaryFileCategory:
                    binary_exts.update(category.value)

                ext = os.path.splitext(entry.filename)[1].lower()
                if ext not in binary_exts and self._contains_script_patterns(
                    content_sample, entry.filename
                ):
                    threats.append(
                        f"Script content detected in '{entry.filename}'"
                    )

        except Exception as err:
            logger.warning(
                "Could not inspect content of '%s': %s",
                entry.filename,
                err,
            )

        return threats

    def _contains_script_patterns(self, content: bytes, filename: str) -> bool:
        """
        Check content for malicious script patterns.

        Args:
            content: Raw bytes to inspect.
            filename: Filename for context.

        Returns:
            True if script patterns found.
        """
        try:
            # Try to decode as text
            text_content = content.decode("utf-8", errors="ignore").lower()

            # Check for common script patterns
            script_patterns = [
                "#!/bin/",
                "#!/usr/bin/",
                "powershell",
                "cmd.exe",
                "eval(",
                "exec(",
                "system(",
                "shell_exec(",
                "<script",
                "<?php",
                "<%",
                "import os",
                "import subprocess",
            ]

            for pattern in script_patterns:
                if pattern in text_content:
                    return True

        except Exception:
            # If we can't decode as text, it's probably binary
            logger.debug(
                "Could not decode content of '%s' as text",
                filename,
            )

        return False

    # ----------------------------------------------------------------
    # Recursive / quine / complexity detection
    # ----------------------------------------------------------------

    def _compute_archive_hash(
        self, file_obj: SeekableFile
    ) -> str:
        """
        Compute SHA-256 hash of archive content.

        Args:
            file_obj: Seekable file containing the archive.

        Returns:
            Hex digest string.
        """
        file_obj.seek(0)
        h = hashlib.sha256()
        while True:
            chunk = file_obj.read(65536)
            if not chunk:
                break
            h.update(chunk)
        file_obj.seek(0)
        return h.hexdigest()

    def inspect_nested_archives(
        self,
        file_obj: SeekableFile,
        *,
        depth: int = 0,
        seen_hashes: set[str] | None = None,
        total_entries: int = 0,
        start_time: float | None = None,
    ) -> None:
        """
        Recursively inspect nested archives.

        Only called when ``allow_nested_archives`` is True.
        Tracks depth, cumulative entry count, elapsed time,
        and archive hashes to detect recursive/quine
        structures.

        Args:
            file_obj: Seekable file containing ZIP data.
            depth: Current nesting depth (0 = outermost).
            seen_hashes: Set of SHA-256 hashes already seen.
            total_entries: Cumulative entry count so far.
            start_time: Monotonic timestamp of initial call.

        Raises:
            ZipContentError: If recursive structure, quine,
                or complexity attack is detected.
        """
        if seen_hashes is None:
            seen_hashes = set()
        if start_time is None:
            start_time = time.monotonic()

        max_depth = self.config.limits.max_zip_depth
        timeout = self.config.limits.zip_analysis_timeout
        max_entries = (
            self.config.limits.max_total_entries_recursive
        )

        # Depth check
        if depth > max_depth:
            raise ZipContentError(
                message=(
                    "Excessive nesting depth:"
                    f" {depth} (max {max_depth})"
                ),
                threats=[
                    f"Nesting depth {depth}"
                    f" exceeds limit {max_depth}"
                ],
                error_code=(
                    ErrorCode.ZIP_RECURSIVE_STRUCTURE
                ),
            )

        # Quine / recursive check via hash
        archive_hash = self._compute_archive_hash(
            file_obj
        )
        if archive_hash in seen_hashes:
            raise ZipContentError(
                message=(
                    "Recursive ZIP structure detected"
                    " — archive contains itself"
                ),
                threats=[
                    "Quine/recursive ZIP detected"
                ],
                error_code=ErrorCode.ZIP_QUINE_DETECTED,
            )
        seen_hashes.add(archive_hash)

        file_obj.seek(0)

        try:
            with zipfile.ZipFile(file_obj, "r") as zf:
                entries = zf.infolist()
                total_entries += len(entries)

                # Complexity check
                if total_entries > max_entries:
                    raise ZipContentError(
                        message=(
                            "Total recursive entries"
                            f" ({total_entries})"
                            " exceeds limit"
                            f" ({max_entries})"
                        ),
                        threats=[
                            "Complexity attack:"
                            f" {total_entries} entries"
                        ],
                        error_code=(
                            ErrorCode.ZIP_COMPLEXITY_ATTACK
                        ),
                    )

                for entry in entries:
                    # Timeout
                    elapsed = (
                        time.monotonic() - start_time
                    )
                    if elapsed > timeout:
                        raise ZipContentError(
                            message=(
                                "Recursive inspection"
                                " timeout after"
                                f" {timeout}s"
                            ),
                            threats=[
                                "Recursive inspection"
                                " timeout"
                            ],
                            error_code=(
                                ErrorCode
                                .ZIP_ANALYSIS_TIMEOUT
                            ),
                        )

                    if entry.is_dir():
                        continue

                    ext = os.path.splitext(
                        entry.filename
                    )[1].lower()
                    is_archive = any(
                        ext == a
                        for a in (
                            ".zip",
                            ".jar",
                            ".war",
                            ".ear",
                        )
                    )
                    if not is_archive:
                        continue

                    # Size guard for nested archive
                    if (
                        entry.file_size
                        > self.config.limits
                        .max_individual_file_size
                    ):
                        continue

                    try:
                        data = zf.read(entry.filename)
                    except Exception:
                        logger.warning(
                            "Could not read nested"
                            " archive '%s'",
                            entry.filename,
                        )
                        continue

                    nested_buf = io.BytesIO(data)
                    if not zipfile.is_zipfile(nested_buf):
                        continue

                    # Recurse
                    self.inspect_nested_archives(
                        nested_buf,
                        depth=depth + 1,
                        seen_hashes=seen_hashes,
                        total_entries=total_entries,
                        start_time=start_time,
                    )

        except ZipContentError:
            raise
        except zipfile.BadZipFile:
            pass  # Let outer handler deal with it
        except Exception as err:
            logger.warning(
                "Error during recursive inspection"
                " at depth %d: %s",
                depth,
                err,
            )
