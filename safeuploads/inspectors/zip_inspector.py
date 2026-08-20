"""ZIP content inspector for security threat detection."""

from __future__ import annotations

import hashlib
import io
import logging
import os
import time
import zipfile
from typing import TYPE_CHECKING

from ..audit import get_correlation_id, log_extra
from ..enums import (
    BinaryFileCategory,
    SuspiciousFilePattern,
    ZipThreatCategory,
)
from ..exceptions import (
    ErrorCode,
    FileProcessingError,
    ResourceLimitError,
    ZipContentError,
)
from ..utils import find_text_pattern, matches_signature_prefix
from .base import BaseInspector

if TYPE_CHECKING:
    from ..config import FileSecurityConfig
    from ..protocols import SeekableFile
    from ..utils import ResourceMonitor


logger = logging.getLogger(__name__)

# Entry extensions that must never appear inside an accepted
# archive, keyed by the threat category they belong to so the
# rejection message names the category.
_DANGEROUS_ENTRY_CATEGORIES: tuple[ZipThreatCategory, ...] = (
    ZipThreatCategory.EXECUTABLE_FILES,
    ZipThreatCategory.SCRIPT_FILES,
    ZipThreatCategory.SYSTEM_FILES,
)


class ZipContentInspector(BaseInspector):
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
        super().__init__(config)

        # Pre-compile pattern sets for O(1) lookups
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
        self._binary_exts: frozenset[str] = frozenset(
            ext for cat in BinaryFileCategory for ext in cat.value
        )
        self._exec_signatures: tuple[bytes, ...] = tuple(
            SuspiciousFilePattern.EXECUTABLE_SIGNATURES.value
        )
        self._script_patterns: tuple[str, ...] = tuple(
            SuspiciousFilePattern.SCRIPT_PATTERNS.value
        )
        self._recursable_exts: frozenset[str] = frozenset(
            ZipThreatCategory.RECURSABLE_ARCHIVES.value
        )
        self._dangerous_entry_exts: dict[str, str] = {
            ext.lower(): category.name
            for category in _DANGEROUS_ENTRY_CATEGORIES
            for ext in category.value
        }

    def inspect_zip_content(
        self,
        file_obj: SeekableFile,
        monitor: ResourceMonitor | None = None,
    ) -> None:
        """
        Inspect ZIP archive for potential security threats.

        Args:
            file_obj: Seekable file-like object containing ZIP data.
            monitor: Optional resource monitor checked once per
                entry so a runaway archive is aborted mid-scan.

        Raises:
            ZipContentError: If security threats are detected in ZIP
                content such as directory traversal, symlinks, nested
                archives, or suspicious patterns.
            ResourceLimitError: If the monitor's time or memory
                limit is exceeded during inspection.
            FileProcessingError: If ZIP structure is invalid or
                unexpected error occurs during inspection.
        """
        try:
            file_obj.seek(0)
            threats_found = []
            logger.debug("Starting ZIP content inspection")

            # Start analysis timer
            start_time = time.monotonic()

            with zipfile.ZipFile(file_obj, "r") as zip_file:
                zip_entries = zip_file.infolist()

                # Analyze each entry in the ZIP
                for entry in zip_entries:
                    if monitor is not None:
                        monitor.check()

                    # Check for timeout
                    if (
                        time.monotonic() - start_time
                        > self.config.limits.zip_analysis_timeout
                    ):
                        logger.error(
                            "ZIP content inspection timeout",
                            extra=log_extra(
                                {
                                    "error_type": "zip_analysis_timeout",
                                    "timeout": (
                                        self.config.limits.zip_analysis_timeout
                                    ),
                                }
                            ),
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
                        extra=log_extra(
                            {
                                "error_type": "zip_content_threat",
                                "threats": threats_found,
                                "threat_count": len(threats_found),
                            }
                        ),
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
                self.inspect_nested_archives(file_obj, monitor=monitor)

        except ZipContentError:
            # Re-raise our own exceptions
            raise
        except ResourceLimitError:
            # A breached time/memory budget must abort the request,
            # not be reported as an internal processing failure.
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

        # 9. Check for dangerous entry extensions
        threats.extend(self._check_dangerous_extension(filename))

        # 10. Check file content if enabled
        # Only first 512 bytes are read, so no size gate needed
        if self.config.limits.scan_zip_content and not entry.is_dir():
            content_threats = self._inspect_entry_content(entry, zip_file)
            threats.extend(content_threats)

        return threats

    def _check_dangerous_extension(self, filename: str) -> list[str]:
        """
        Check an entry name for dangerous file extensions.

        Every dot-separated suffix is checked, so a disguised
        name such as ``shell.php.txt`` is still rejected.

        Args:
            filename: ZIP entry name to check.

        Returns:
            List of threat descriptions.
        """
        basename = os.path.basename(filename).lower()
        parts = basename.split(".")
        for part in parts[1:]:
            category = self._dangerous_entry_exts.get(f".{part}")
            if category is not None:
                return [
                    f"Dangerous entry extension '.{part}'"
                    f" ({category}) in '{filename}'"
                ]
        return []

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
        file_types: dict[str, int] = {}
        for entry in entries:
            if not entry.is_dir():
                ext = os.path.splitext(entry.filename)[1].lower()
                file_types[ext] = file_types.get(ext, 0) + 1

        # Check for excessive number of same-type files (potential spam/bomb)
        for ext, count in file_types.items():
            if count > self.config.limits.max_number_files_same_type:
                threats.append(
                    f"Excessive number of {ext} files: {count}"
                    f" (max: {self.config.limits.max_number_files_same_type})"
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

        for pattern in self._traversal_patterns:
            if pattern in filename_lower:
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
        for pattern in self._suspicious_names:
            if basename == pattern:
                threats.append(f"Suspicious filename pattern: '{filename}'")
                break

        # Check suspicious path components
        for pattern in self._suspicious_paths:
            if pattern in filename_lower:
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
        return ext in self._nested_archive_exts

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

                # Executable signatures are matched against the
                # entry header (anchored): the entry either is or
                # is not an executable.
                if matches_signature_prefix(
                    content_sample, self._exec_signatures
                ):
                    threats.append(
                        f"Executable content detected in '{entry.filename}'"
                    )

                ext = os.path.splitext(entry.filename)[1].lower()
                if (
                    ext not in self._binary_exts
                    and self._contains_script_patterns(
                        content_sample, entry.filename
                    )
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
        return find_text_pattern(content, self._script_patterns) is not None

    # ----------------------------------------------------------------
    # Recursive / quine / complexity detection
    # ----------------------------------------------------------------

    def _compute_archive_hash(self, file_obj: SeekableFile) -> str:
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
        entry_counter: list[int] | None = None,
        start_time: float | None = None,
        monitor: ResourceMonitor | None = None,
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
            entry_counter: Single-element list holding the
                cumulative entry count shared across all
                recursion branches.
            start_time: Monotonic timestamp of initial call.
            monitor: Optional resource monitor checked once per
                entry so a runaway archive is aborted mid-scan.

        Raises:
            ZipContentError: If recursive structure, quine,
                or complexity attack is detected.
            ResourceLimitError: If the monitor's time or memory
                limit is exceeded during inspection.
        """
        if seen_hashes is None:
            seen_hashes = set()
        if entry_counter is None:
            entry_counter = [0]
        if start_time is None:
            start_time = time.monotonic()

        max_depth = self.config.limits.max_zip_depth
        timeout = self.config.limits.zip_analysis_timeout
        max_entries = self.config.limits.max_total_entries_recursive

        # Depth check
        if depth > max_depth:
            raise ZipContentError(
                message=(
                    f"Excessive nesting depth: {depth} (max {max_depth})"
                ),
                threats=[f"Nesting depth {depth} exceeds limit {max_depth}"],
                error_code=(ErrorCode.ZIP_RECURSIVE_STRUCTURE),
            )

        # Quine / recursive check via hash
        archive_hash = self._compute_archive_hash(file_obj)
        if archive_hash in seen_hashes:
            raise ZipContentError(
                message=(
                    "Recursive ZIP structure detected"
                    " — archive contains itself"
                ),
                threats=["Quine/recursive ZIP detected"],
                error_code=ErrorCode.ZIP_QUINE_DETECTED,
            )
        seen_hashes.add(archive_hash)

        file_obj.seek(0)

        try:
            with zipfile.ZipFile(file_obj, "r") as zf:
                entries = zf.infolist()
                entry_counter[0] += len(entries)

                # Complexity check
                if entry_counter[0] > max_entries:
                    raise ZipContentError(
                        message=(
                            "Total recursive entries"
                            f" ({entry_counter[0]})"
                            " exceeds limit"
                            f" ({max_entries})"
                        ),
                        threats=[
                            f"Complexity attack: {entry_counter[0]} entries"
                        ],
                        error_code=(ErrorCode.ZIP_COMPLEXITY_ATTACK),
                    )

                for entry in entries:
                    if monitor is not None:
                        monitor.check()

                    # Timeout
                    elapsed = time.monotonic() - start_time
                    if elapsed > timeout:
                        raise ZipContentError(
                            message=(
                                "Recursive inspection"
                                " timeout after"
                                f" {timeout}s"
                            ),
                            threats=["Recursive inspection timeout"],
                            error_code=(ErrorCode.ZIP_ANALYSIS_TIMEOUT),
                        )

                    if entry.is_dir():
                        continue

                    ext = os.path.splitext(entry.filename)[1].lower()
                    if ext not in self._recursable_exts:
                        continue

                    # Size guard for nested archive
                    if (
                        entry.file_size
                        > self.config.limits.max_individual_file_size
                    ):
                        continue

                    try:
                        data = zf.read(entry.filename)
                    except Exception:
                        logger.warning(
                            "Could not read nested archive '%s'",
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
                        entry_counter=entry_counter,
                        start_time=start_time,
                        monitor=monitor,
                    )

        except ZipContentError:
            raise
        except ResourceLimitError:
            # A breached time/memory budget must abort the request,
            # not be downgraded to a skipped branch.
            raise
        except zipfile.BadZipFile:
            # A corrupt archive at this nesting level is not itself a
            # threat signal; log for traceability and stop descending
            # this branch rather than failing the whole inspection.
            logger.debug(
                "Skipping corrupt nested archive at depth %d",
                depth,
            )
        except Exception as err:
            logger.warning(
                "Error during recursive inspection at depth %d: %s",
                depth,
                err,
            )
