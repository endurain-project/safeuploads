"""ZIP content inspector for security threat detection."""

from __future__ import annotations

import hashlib
import logging
import os
import stat
import tempfile
import time
import zipfile
from typing import TYPE_CHECKING, NamedTuple

from ..audit import get_correlation_id, log_extra
from ..enums import (
    BinaryFileCategory,
    SuspiciousFilePattern,
    ZipThreatCategory,
)
from ..exceptions import (
    CompressionSecurityError,
    ErrorCode,
    FileProcessingError,
    ResourceLimitError,
    ZipBombError,
    ZipContentError,
)
from ..utils import (
    check_resource_limits,
    find_text_pattern,
    iter_gzip_chunks,
    matches_signature_prefix,
)
from ..validators.compression_validator import CompressionSecurityValidator
from .base import BaseInspector

if TYPE_CHECKING:
    from ..config import FileSecurityConfig
    from ..protocols import SeekableFile


logger = logging.getLogger(__name__)

_GZIP_MAGIC = b"\x1f\x8b"
_ZIP_MAGIC = b"PK"


class _Threat(NamedTuple):
    """
    One threat found in an archive.

    Attributes:
        code: ``ErrorCode`` raised when this threat is the first found.
        message: Human-readable description.
    """

    code: str
    message: str


def _content_threat(message: str) -> _Threat:
    """Return a threat reported as ``ZIP_CONTENT_THREAT``."""
    return _Threat(ErrorCode.ZIP_CONTENT_THREAT, message)


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
        self._nested_archive_signatures: tuple[bytes, ...] = tuple(
            ZipThreatCategory.NESTED_ARCHIVE_SIGNATURES.value
        )
        self._dangerous_exts: frozenset[str] = frozenset(
            ZipThreatCategory.EXECUTABLE_FILES.value
            | ZipThreatCategory.SCRIPT_FILES.value
            | ZipThreatCategory.SYSTEM_FILES.value
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
        # ZIP signatures among the archive signatures; content
        # starting with one is recursed into under any name
        self._zip_signatures: tuple[bytes, ...] = tuple(
            sig
            for sig in self._nested_archive_signatures
            if sig.startswith(_ZIP_MAGIC)
        )
        self._zip_signature_size: int = max(map(len, self._zip_signatures))
        # Nested archives get the same compression checks as the
        # top-level archive
        self._compression = CompressionSecurityValidator(config)

    def inspect_zip_content(self, file_obj: SeekableFile) -> None:
        """
        Inspect ZIP archive for potential security threats.

        When ``allow_nested_archives`` is enabled, every nested ZIP
        archive is then inspected as well (see
        ``inspect_nested_archives``).

        Args:
            file_obj: Seekable file-like object containing ZIP data.

        Raises:
            ZipBombError: If a nested archive is a zip bomb.
            ZipContentError: If security threats are detected in ZIP
                content such as directory traversal, symlinks, nested
                archives, or suspicious patterns, or a nested archive
                fails any check. Its ``error_code`` is that of the
                first threat found.
            CompressionSecurityError: With ``ZIP_CORRUPT`` if the
                ZIP structure is invalid.
            ResourceLimitError: If the active resource monitor's
                time or memory limit is exceeded.
            FileProcessingError: If an unexpected error occurs during
                inspection.
        """
        try:
            logger.debug("Starting ZIP content inspection")
            self._inspect_archive(file_obj, time.monotonic())

            if self.config.limits.allow_nested_archives:
                self.inspect_nested_archives(file_obj)

        except (ZipBombError, ZipContentError, ResourceLimitError):
            # Re-raise our own exceptions
            raise
        except zipfile.BadZipFile as err:
            logger.error(
                "Invalid or corrupted ZIP file structure", exc_info=True
            )
            raise CompressionSecurityError(
                message="Invalid or corrupted ZIP file structure",
                error_code=ErrorCode.ZIP_CORRUPT,
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

    def _inspect_archive(
        self, file_obj: SeekableFile, start_time: float
    ) -> None:
        """
        Inspect the entries and structure of one ZIP archive.

        Nested archives are not opened here.

        Args:
            file_obj: Seekable file containing ZIP data.
            start_time: Monotonic timestamp the analysis timeout
                counts from.

        Raises:
            ZipContentError: If any entry or the structure is a
                threat, or the analysis timeout is exceeded. The
                error code is that of the first threat found.
            ResourceLimitError: If the active resource monitor's
                time or memory limit is exceeded.
            zipfile.BadZipFile: If the archive cannot be parsed.
        """
        file_obj.seek(0)
        threats_found: list[_Threat] = []
        timeout = self.config.limits.zip_analysis_timeout

        with zipfile.ZipFile(file_obj, "r") as zip_file:
            zip_entries = zip_file.infolist()

            # Analyze each entry in the ZIP
            for entry in zip_entries:
                check_resource_limits()

                # Check for timeout
                if time.monotonic() - start_time > timeout:
                    logger.error(
                        "ZIP content inspection timeout",
                        extra=log_extra(
                            {
                                "error_type": "zip_analysis_timeout",
                                "timeout": timeout,
                            }
                        ),
                    )
                    raise ZipContentError(
                        message=(
                            f"ZIP content inspection timeout after {timeout}s"
                        ),
                        threats=["Analysis timeout - potential zip bomb"],
                        error_code=ErrorCode.ZIP_ANALYSIS_TIMEOUT,
                    )

                # Inspect individual entry
                threats_found.extend(self._inspect_zip_entry(entry, zip_file))

            # Check for ZIP structure threats
            threats_found.extend(self._inspect_zip_structure(zip_entries))

        if threats_found:
            messages = [threat.message for threat in threats_found]
            summary = "; ".join(messages)
            logger.warning(
                "ZIP content threats detected",
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
                self._audit.threat("", cid, summary)
            raise ZipContentError(
                message=f"ZIP content threats detected: {summary}",
                threats=messages,
                error_code=threats_found[0].code,
            )

        logger.debug(
            "ZIP content inspection passed: %s entries analyzed",
            len(zip_entries),
        )

    def _inspect_zip_entry(
        self, entry: zipfile.ZipInfo, zip_file: zipfile.ZipFile
    ) -> list[_Threat]:
        """
        Inspect single ZIP entry for security threats.

        Checks the raw name for null bytes, then the name for traversal,
        absolute paths, symlinks, length limits, suspicious patterns,
        nested archive extensions and dangerous file extensions. The
        content is inspected when ``scan_zip_content`` is enabled.

        Args:
            entry: ZIP entry metadata.
            zip_file: Parent ZIP archive.

        Returns:
            List of threats, each with the code it is reported as.
        """
        threats: list[_Threat] = []
        filename = entry.filename

        # 1. Check for null bytes (truncation attacks); zipfile
        # truncates ``filename`` at the first NUL, so check the raw name
        if "\x00" in entry.orig_filename:
            threats.append(
                _content_threat(f"Null byte in filename: '{filename}'")
            )

        # 2. Check for directory traversal attacks
        if self._has_directory_traversal(filename):
            threats.append(
                _Threat(
                    ErrorCode.ZIP_DIRECTORY_TRAVERSAL,
                    f"Directory traversal attack in '{filename}'",
                )
            )

        # 3. Check for absolute paths
        if (
            not self.config.limits.allow_absolute_paths
            and self._has_absolute_path(filename)
        ):
            threats.append(
                _Threat(
                    ErrorCode.ZIP_ABSOLUTE_PATH,
                    f"Absolute path detected in '{filename}'",
                )
            )

        # 4. Check for symbolic links
        if not self.config.limits.allow_symlinks and self._is_symlink(entry):
            threats.append(
                _Threat(
                    ErrorCode.ZIP_SYMLINK_DETECTED,
                    f"Symbolic link detected: '{filename}'",
                )
            )

        # 5. Check filename length limits
        if (
            len(os.path.basename(filename))
            > self.config.limits.max_filename_length
        ):
            threats.append(
                _content_threat(
                    f"Filename too long: '{filename}'"
                    f" ({len(os.path.basename(filename))}"
                    " chars)"
                )
            )

        # 6. Check path length limits
        if len(filename) > self.config.limits.max_path_length:
            threats.append(
                _content_threat(
                    f"Path too long: '{filename}' ({len(filename)} chars)"
                )
            )

        # 7. Check for suspicious filename patterns
        threats.extend(
            _content_threat(message)
            for message in self._check_suspicious_patterns(filename)
        )

        # 8. Check for nested archives
        if (
            not self.config.limits.allow_nested_archives
            and self._is_nested_archive(filename)
        ):
            threats.append(
                _Threat(
                    ErrorCode.ZIP_NESTED_ARCHIVE,
                    f"Nested archive detected: '{filename}'",
                )
            )

        # 9. Check for executable, script and system file extensions
        if self._extension(filename) in self._dangerous_exts:
            threats.append(
                _content_threat(f"Dangerous file type detected: '{filename}'")
            )

        # 10. Check file content if enabled
        # Only first 512 bytes are read, so no size gate needed
        if self.config.limits.scan_zip_content and not entry.is_dir():
            content_threats = self._inspect_entry_content(entry, zip_file)
            threats.extend(content_threats)

        return threats

    def _inspect_zip_structure(
        self, entries: list[zipfile.ZipInfo]
    ) -> list[_Threat]:
        """
        Inspect ZIP structure for anomalies.

        Args:
            entries: All ZIP entries to analyze.

        Returns:
            List of structural threats.
        """
        threats: list[_Threat] = []

        # Check directory depth
        max_depth = 0
        for entry in entries:
            depth = entry.filename.count("/") + entry.filename.count("\\")
            max_depth = max(max_depth, depth)

        if max_depth > self.config.limits.max_zip_depth:
            threats.append(
                _content_threat(
                    f"Excessive directory depth: {max_depth}"
                    f" (max: {self.config.limits.max_zip_depth})"
                )
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
                    _content_threat(
                        f"Excessive number of {ext} files: {count}"
                        " (max:"
                        f" {self.config.limits.max_number_files_same_type})"
                    )
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
        return stat.S_ISLNK(entry.external_attr >> 16)

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

        Trailing dots and spaces are ignored, as Windows drops them on
        extraction.

        Args:
            filename: Filename to check.

        Returns:
            True if nested archive detected.
        """
        return self._extension(filename) in self._nested_archive_exts

    @staticmethod
    def _extension(filename: str) -> str:
        """
        Return the final extension as a Windows extractor sees it.

        Trailing dots and spaces are stripped from the base name because
        Windows drops them on extraction.

        Args:
            filename: Entry name to check.

        Returns:
            Lowercase extension including the dot, or an empty string.
        """
        base = os.path.basename(filename).rstrip(". ")
        return os.path.splitext(base)[1].lower()

    def _inspect_entry_content(
        self, entry: zipfile.ZipInfo, zip_file: zipfile.ZipFile
    ) -> list[_Threat]:
        """
        Inspect ZIP entry content for malicious signatures.

        An entry that cannot be opened or read is reported as a threat,
        because its content was not scanned.

        Args:
            entry: ZIP entry to inspect.
            zip_file: Parent ZIP archive.

        Returns:
            List of content threats.
        """
        threats: list[_Threat] = []

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
                        _content_threat(
                            "Executable content detected in"
                            f" '{entry.filename}'"
                        )
                    )

                if (
                    not self.config.limits.allow_nested_archives
                    and not self._is_nested_archive(entry.filename)
                    and matches_signature_prefix(
                        content_sample, self._nested_archive_signatures
                    )
                ):
                    threats.append(
                        _Threat(
                            ErrorCode.ZIP_NESTED_ARCHIVE,
                            f"Nested archive detected: '{entry.filename}'",
                        )
                    )

                ext = os.path.splitext(entry.filename)[1].lower()
                if content_sample.startswith(_GZIP_MAGIC):
                    # Compressed bytes only match script patterns by
                    # chance; scan the decompressed start instead
                    threats.extend(self._inspect_gzip_entry(entry, zip_file))
                elif (
                    ext not in self._binary_exts
                    and self._contains_script_patterns(
                        content_sample, entry.filename
                    )
                ):
                    threats.append(
                        _content_threat(
                            f"Script content detected in '{entry.filename}'"
                        )
                    )

        except ResourceLimitError:
            raise
        except Exception as err:
            logger.warning(
                "Could not inspect content of '%s': %s",
                entry.filename,
                err,
            )
            threats.append(
                _content_threat(
                    f"Entry content could not be inspected: '{entry.filename}'"
                )
            )

        return threats

    def _inspect_gzip_entry(
        self, entry: zipfile.ZipInfo, zip_file: zipfile.ZipFile
    ) -> list[_Threat]:
        """
        Inspect the decompressed start of a gzip ZIP entry.

        At most 512 decompressed bytes are read, so the cost does not
        depend on the stream's expansion. The script scan is skipped
        when the name without its ``.gz`` suffix has a binary
        extension (``x.fit.gz``). A gzip stream inside the gzip stream
        is reported as uninspectable, since its content cannot be
        scanned at this depth.

        Args:
            entry: ZIP entry whose content starts with the gzip magic.
            zip_file: Parent ZIP archive.

        Returns:
            List of content threats.

        Raises:
            ResourceLimitError: If the active resource monitor's time or
                memory limit is exceeded.
            zlib.error: If the entry is not a valid gzip stream.
            EOFError: If the stream ends before the sample is read.
        """
        sample = b""
        with zip_file.open(entry, "r") as file:
            for chunk in iter_gzip_chunks(file, 512):
                sample += chunk
                if len(sample) >= 512:
                    break
        sample = sample[:512]

        if sample.startswith(_GZIP_MAGIC):
            return [
                _content_threat(
                    f"Entry content could not be inspected: '{entry.filename}'"
                )
            ]

        threats: list[_Threat] = []
        if matches_signature_prefix(sample, self._exec_signatures):
            threats.append(
                _content_threat(
                    f"Executable content detected in '{entry.filename}'"
                )
            )

        name, ext = os.path.splitext(entry.filename)
        if ext.lower() == ".gz":
            ext = os.path.splitext(name)[1]
        if (
            ext.lower() not in self._binary_exts
            and self._contains_script_patterns(sample, entry.filename)
        ):
            threats.append(
                _content_threat(
                    f"Script content detected in '{entry.filename}'"
                )
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
    ) -> None:
        """
        Recursively inspect nested archives.

        Only called when ``allow_nested_archives`` is True. The
        archive in ``file_obj`` is not itself checked here when
        ``depth`` is 0; the caller checks it. Every nested ZIP
        archive (an entry with a recursable archive extension or
        starting with a ZIP signature) is streamed into a spooled
        temporary file, checked like a top-level archive (the
        compression checks of ``CompressionSecurityValidator`` and
        the entry and structure checks of this inspector) and then
        recursed into. Depth, cumulative entry count and elapsed time are
        tracked across all levels, and the hashes of an archive's
        ancestors to detect recursive and quine structures. Sibling
        archives with identical content are not a quine. An inner archive that
        cannot be read, parsed or fully inspected is rejected.

        Args:
            file_obj: Seekable file containing ZIP data.
            depth: Current nesting depth (0 = outermost).
            seen_hashes: SHA-256 hashes of ancestor archives of
                ``file_obj``; an archive matching one is a quine.
                Not modified.
            entry_counter: Single-element list holding the
                cumulative entry count shared across all
                recursion branches.
            start_time: Monotonic timestamp of initial call.

        Raises:
            ZipBombError: If a nested archive is a zip bomb.
            ZipContentError: If recursive structure, quine,
                or complexity attack is detected, a nested archive
                fails a check, or an archive cannot be read or
                parsed. Threats in a nested archive name its
                nesting path.
            ResourceLimitError: If the active resource monitor's
                time or memory limit is exceeded.
        """
        self._inspect_nested(
            file_obj,
            "",
            depth,
            frozenset() if seen_hashes is None else frozenset(seen_hashes),
            [0] if entry_counter is None else entry_counter,
            time.monotonic() if start_time is None else start_time,
        )

    def _inspect_nested(
        self,
        file_obj: SeekableFile,
        path: str,
        depth: int,
        ancestors: frozenset[str],
        entry_counter: list[int],
        start_time: float,
    ) -> None:
        """
        Check one archive level and recurse into its nested archives.

        Args:
            file_obj: Seekable file containing ZIP data.
            path: Nesting path of this archive, entry names joined
                by ``/``; empty for the outermost archive.
            depth: Nesting depth of this archive (0 = outermost).
            ancestors: SHA-256 hashes of the ancestor archives.
            entry_counter: Single-element list holding the
                cumulative entry count across all levels.
            start_time: Monotonic timestamp of the initial call.

        Raises:
            ZipBombError: If a nested archive is a zip bomb.
            ZipContentError: If this archive or a nested one fails
                a check or cannot be read or parsed.
            ResourceLimitError: If the active resource monitor's
                time or memory limit is exceeded.
        """
        limits = self.config.limits
        location = f"nested archive '{path}'" if depth else "ZIP archive"
        try:
            # Depth check
            if depth > limits.max_zip_depth:
                raise ZipContentError(
                    message=(
                        f"Excessive nesting depth: {depth}"
                        f" (max {limits.max_zip_depth})"
                    ),
                    threats=[
                        f"Nesting depth {depth} exceeds limit"
                        f" {limits.max_zip_depth}"
                    ],
                    error_code=ErrorCode.ZIP_RECURSIVE_STRUCTURE,
                )

            # Quine / recursive check via hash
            archive_hash = self._compute_archive_hash(file_obj)
            if archive_hash in ancestors:
                raise ZipContentError(
                    message=(
                        "Recursive ZIP structure detected"
                        " — archive contains itself"
                    ),
                    threats=["Quine/recursive ZIP detected"],
                    error_code=ErrorCode.ZIP_QUINE_DETECTED,
                )
            chain = ancestors | {archive_hash}

            if depth:
                self._check_nested_level(file_obj, path, start_time)

            file_obj.seek(0)
            with zipfile.ZipFile(file_obj, "r") as zf:
                self._recurse_entries(
                    zf, path, depth, chain, entry_counter, start_time
                )

        except (ZipBombError, ZipContentError, ResourceLimitError):
            raise
        except zipfile.BadZipFile as err:
            logger.warning("Corrupt %s at depth %d", location, depth)
            raise ZipContentError(
                message=f"Invalid or corrupted {location}",
                threats=[f"Corrupt {location}"],
                error_code=ErrorCode.ZIP_CORRUPT,
            ) from err
        except Exception as err:
            logger.warning(
                "Error during recursive inspection at depth %d: %s",
                depth,
                err,
            )
            raise ZipContentError(
                message=f"Could not inspect {location}",
                threats=[f"Uninspectable {location}"],
            ) from err

    def _recurse_entries(
        self,
        zf: zipfile.ZipFile,
        path: str,
        depth: int,
        ancestors: frozenset[str],
        entry_counter: list[int],
        start_time: float,
    ) -> None:
        """
        Count an archive's entries and recurse into nested archives.

        Each nested archive is copied into a spooled temporary file
        that is closed once its subtree has been inspected.

        Args:
            zf: Open archive at this level.
            path: Nesting path of the archive; empty when outermost.
            depth: Nesting depth of the archive.
            ancestors: SHA-256 hashes of this archive and its
                ancestors.
            entry_counter: Single-element list holding the
                cumulative entry count across all levels.
            start_time: Monotonic timestamp of the initial call.

        Raises:
            ZipContentError: If the cumulative entry count or the
                analysis timeout is exceeded, or a nested archive
                fails a check or cannot be read.
            ResourceLimitError: If the active resource monitor's
                time or memory limit is exceeded.
        """
        limits = self.config.limits
        entries = zf.infolist()
        entry_counter[0] += len(entries)

        # Complexity check
        if entry_counter[0] > limits.max_total_entries_recursive:
            raise ZipContentError(
                message=(
                    f"Total recursive entries ({entry_counter[0]})"
                    f" exceeds limit ({limits.max_total_entries_recursive})"
                ),
                threats=[f"Complexity attack: {entry_counter[0]} entries"],
                error_code=ErrorCode.ZIP_COMPLEXITY_ATTACK,
            )

        for entry in entries:
            check_resource_limits()

            # Timeout
            if time.monotonic() - start_time > limits.zip_analysis_timeout:
                raise ZipContentError(
                    message=(
                        "Recursive inspection timeout after"
                        f" {limits.zip_analysis_timeout}s"
                    ),
                    threats=["Recursive inspection timeout"],
                    error_code=ErrorCode.ZIP_ANALYSIS_TIMEOUT,
                )

            if entry.is_dir():
                continue

            entry_path = f"{path}/{entry.filename}" if path else entry.filename
            with tempfile.SpooledTemporaryFile(
                max_size=limits.max_memory_buffer_size
            ) as inner:
                if self._copy_nested_archive(zf, entry, entry_path, inner):
                    self._inspect_nested(
                        inner,
                        entry_path,
                        depth + 1,
                        ancestors,
                        entry_counter,
                        start_time,
                    )

    def _copy_nested_archive(
        self,
        zf: zipfile.ZipFile,
        entry: zipfile.ZipInfo,
        path: str,
        dest: tempfile.SpooledTemporaryFile[bytes],
    ) -> bool:
        """
        Copy an entry into ``dest`` if it is a nested ZIP archive.

        An entry is a nested ZIP archive when its extension is a
        recursable archive type or its content starts with a ZIP
        signature. The entry is read through its ``ZipInfo`` in
        ``chunk_size`` pieces, so duplicate names cannot select a
        different entry and no more than one chunk is held in
        memory beyond the spooled file.

        Args:
            zf: Archive holding the entry.
            entry: Entry to copy.
            path: Nesting path of the entry, for messages.
            dest: Empty spooled file receiving the archive bytes;
                left at offset 0 when the entry was copied.

        Returns:
            True if the entry is a nested ZIP archive and was
            copied, False if it is not a ZIP archive.

        Raises:
            ZipContentError: If the entry cannot be read or its
                content exceeds ``max_individual_file_size``.
            ResourceLimitError: If the active resource monitor's
                time or memory limit is exceeded.
        """
        limits = self.config.limits
        try:
            with zf.open(entry, "r") as stream:
                chunk = stream.read(self._zip_signature_size)
                if self._extension(
                    entry.filename
                ) not in self._recursable_exts and not (
                    matches_signature_prefix(chunk, self._zip_signatures)
                ):
                    return False

                size = 0
                while chunk:
                    check_resource_limits()
                    size += len(chunk)
                    if size > limits.max_individual_file_size:
                        raise ZipContentError(
                            message=(
                                f"Nested archive too large: '{path}'"
                                " exceeds the individual file size limit"
                            ),
                            threats=[f"Nested archive too large: '{path}'"],
                            error_code=ErrorCode.FILE_TOO_LARGE,
                        )
                    dest.write(chunk)
                    chunk = stream.read(limits.chunk_size)
        except (ZipContentError, ResourceLimitError):
            raise
        except Exception as err:
            logger.warning("Could not read nested entry '%s': %s", path, err)
            raise ZipContentError(
                message=f"Nested entry could not be read: '{path}'",
                threats=[f"Nested entry could not be read: '{path}'"],
            ) from err

        dest.seek(0)
        return True

    def _check_nested_level(
        self, file_obj: SeekableFile, path: str, start_time: float
    ) -> None:
        """
        Run the top-level archive checks on a nested archive.

        Applies the compression, size, entry-count and layout
        checks of ``CompressionSecurityValidator`` and this
        inspector's entry and structure checks. A zip bomb is
        re-raised as ``ZipBombError`` with its details and
        ``path`` prefixed to the message; other failures are
        raised as ``ZipContentError`` with the original error
        code, and their threats are prefixed with ``path``.

        Args:
            file_obj: Seekable file containing the nested archive.
            path: Nesting path of the archive.
            start_time: Monotonic timestamp the analysis timeout
                counts from.

        Raises:
            ZipBombError: If the nested archive exceeds a
                compression ratio or size limit.
            ZipContentError: If the nested archive fails a check.
            ResourceLimitError: If the active resource monitor's
                time or memory limit is exceeded.
            FileProcessingError: If the compression check fails
                unexpectedly.
        """
        try:
            size = file_obj.seek(0, os.SEEK_END)
            self._compression.validate_zip_compression_ratio(file_obj, size)
            self._inspect_archive(file_obj, start_time)
        except ZipBombError as err:
            raise ZipBombError(
                message=f"{path}: {err.message}",
                filename=err.filename,
                compression_ratio=err.compression_ratio,
                uncompressed_size=err.uncompressed_size,
                max_ratio=err.max_ratio,
                max_size=err.max_size,
                error_code=err.error_code,
            ) from err
        except CompressionSecurityError as err:
            threats = [
                f"{path}: {threat}"
                for threat in (
                    err.threats
                    if isinstance(err, ZipContentError)
                    else [err.message]
                )
            ]
            summary = "; ".join(threats)
            raise ZipContentError(
                message=f"Nested archive threats detected: {summary}",
                threats=threats,
                error_code=err.error_code,
            ) from err
