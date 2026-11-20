"""ZIP content inspector for security threat detection."""

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import stat
import tempfile
import time
import zipfile
from collections.abc import Iterator
from typing import IO, TYPE_CHECKING, Literal, NamedTuple

from ..audit import get_correlation_id, log_extra
from ..enums import (
    BinaryFileCategory,
    SuspiciousFilePattern,
    ZipThreatCategory,
)
from ..exceptions import (
    CompressionSecurityError,
    ErrorCode,
    FilenameSecurityError,
    FileProcessingError,
    ResourceLimitError,
    ZipBombError,
    ZipContentError,
)
from ..utils import (
    check_resource_limits,
    find_text_pattern,
    matches_signature_prefix,
)
from ..validators.compression_validator import (
    PERMITTED_NESTED_ARCHIVE_EXTS,
    SUPPORTED_COMPRESSION_METHODS,
    ZIP_PARSE_ERRORS,
    CompressionSecurityValidator,
)
from ..validators.extension_validator import ExtensionSecurityValidator
from ..validators.unicode_validator import UnicodeSecurityValidator
from ..validators.windows_validator import WindowsSecurityValidator
from .base import BaseInspector
from .gzip_inspector import GzipContentInspector

if TYPE_CHECKING:
    from ..config import FileSecurityConfig
    from ..protocols import SeekableFile


logger = logging.getLogger(__name__)

_ZIP_MAGIC = b"PK"
_GZIP_MAGIC = b"\x1f\x8b"
_GZIP_SUFFIX = ".gz"
# Bytes of an entry's start checked for signatures and scripts
_SAMPLE_SIZE = 512
# zipfile and unzip find an archive by its end record, which starts
# within the last 22 + 65535 (maximum comment) bytes
_END_RECORD_SIGNATURE = b"PK\x05\x06"
# USTAR and GNU tar headers carry this magic at offset 257, within
# the content sample; tar has no signature at the start
_TAR_MAGIC = b"ustar"
_TAR_MAGIC_OFFSET = 257
_END_RECORD_SPAN = 22 + 0xFFFF


# How a nested entry is inspected further
_NestedKind = Literal["zip", "gzip"]


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
        # Archive formats rejected even with nesting allowed: all
        # but ZIP and gzip
        self._unpermitted_archive_signatures: tuple[bytes, ...] = tuple(
            sig
            for sig in self._nested_archive_signatures
            if sig not in self._zip_signatures and sig != _GZIP_MAGIC
        )
        # Nested archives get the same compression checks as the
        # top-level archive
        self._compression = CompressionSecurityValidator(config)
        # Nested gzip streams get the top-level gzip limits
        self._gzip = GzipContentInspector(config)
        # Entry names get the filename checks a top-level upload gets
        self._unicode = UnicodeSecurityValidator(config)
        self._windows = WindowsSecurityValidator(config)
        self._extensions = ExtensionSecurityValidator(config)

    def inspect_zip_content(self, file_obj: SeekableFile) -> None:
        """
        Inspect ZIP archive for potential security threats.

        Entry names and metadata are always checked, and an entry
        compressed with a method other than stored or deflated is
        rejected without being opened; entry contents are read only
        when ``scan_zip_content`` is enabled. When
        ``allow_nested_archives`` is enabled, every nested ZIP
        archive and gzip stream is then inspected as well (see
        ``inspect_nested_archives``).

        Args:
            file_obj: Seekable file-like object containing ZIP data.

        Raises:
            ZipBombError: If a nested archive or gzip stream is a
                decompression bomb.
            ZipContentError: If security threats are detected in ZIP
                content such as directory traversal, symlinks, nested
                archives, unsupported compression methods or
                suspicious patterns, or a nested archive fails any
                check. Its ``error_code`` is that of the first threat
                found.
            CompressionSecurityError: With ``ZIP_CORRUPT`` if the
                ZIP structure is invalid or ``zipfile`` cannot parse
                it (see ``ZIP_PARSE_ERRORS``).
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
        except ZIP_PARSE_ERRORS as err:
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
            UnicodeDecodeError: If an entry name is not valid UTF-8.
            NotImplementedError: If the archive needs a ZIP feature
                ``zipfile`` does not support.
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

        self._raise_threats(threats_found)
        logger.debug(
            "ZIP content inspection passed: %s entries analyzed",
            len(zip_entries),
        )

    def _raise_threats(self, threats: list[_Threat]) -> None:
        """
        Log, audit and raise the threats found, if there are any.

        Args:
            threats: Threats found, in the order they were found.

        Raises:
            ZipContentError: If ``threats`` is not empty, with the
                code of its first threat.
        """
        if not threats:
            return
        messages = [threat.message for threat in threats]
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
            error_code=threats[0].code,
        )

    @staticmethod
    def _unsupported_method(entry: zipfile.ZipInfo) -> _Threat | None:
        """
        Return a threat if an entry is neither stored nor deflated.

        ``zipfile`` inflates other methods (bzip2, LZMA) without an
        output bound, so such an entry is never opened.

        Args:
            entry: Entry to check.

        Returns:
            A ``ZIP_UNSUPPORTED_COMPRESSION`` threat, or None.
        """
        if entry.compress_type in SUPPORTED_COMPRESSION_METHODS:
            return None
        return _Threat(
            ErrorCode.ZIP_UNSUPPORTED_COMPRESSION,
            f"Unsupported compression method {entry.compress_type}"
            f" for '{entry.filename}'",
        )

    def _inspect_zip_entry(
        self, entry: zipfile.ZipInfo, zip_file: zipfile.ZipFile
    ) -> list[_Threat]:
        """
        Inspect single ZIP entry for security threats.

        Checks the raw name for null bytes, then the name for traversal,
        absolute paths, symlinks, length limits, suspicious patterns,
        nested archive extensions, the top-level filename checks and
        dangerous file extensions. These checks read no entry data.
        An entry compressed with a method other than stored or
        deflated is a threat and is never opened; otherwise the
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
        if self._archive_name_rejected(filename):
            threats.append(
                _Threat(
                    ErrorCode.ZIP_NESTED_ARCHIVE,
                    f"Nested archive detected: '{filename}'",
                )
            )

        # 9. Check the name as a top-level filename is checked
        threats.extend(self._check_entry_name(entry))

        # 10. Check for executable, script and system file extensions
        if self._extension(filename) in self._dangerous_exts:
            threats.append(
                _content_threat(f"Dangerous file type detected: '{filename}'")
            )

        # 11. Never open an entry zipfile inflates without bound
        unsupported = self._unsupported_method(entry)
        if unsupported:
            threats.append(unsupported)

        # 12. Check file content if enabled; reads are bounded by
        # the declared sizes the compression validator checked
        elif self.config.limits.scan_zip_content and not entry.is_dir():
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

        A component of only dots and spaces with at least two dots
        (``..``, ``. .``, ``.. ``) is a traversal wherever it appears,
        including at the end of the name.

        Args:
            filename: Filename to check.

        Returns:
            True if traversal detected.
        """
        filename_lower = filename.lower()

        for pattern in self._traversal_patterns:
            if pattern in filename_lower:
                return True

        # Windows drops trailing dots and spaces from a component, so
        # one of only dots and spaces with two or more dots is ``..``
        for component in filename.replace("\\", "/").split("/"):
            if component.count(".") > 1 and not component.strip(". "):
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

    def _archive_name_rejected(self, filename: str) -> bool:
        """
        Check if a filename names a nested archive that is rejected.

        Every archive extension is rejected, except a ZIP archive's
        or a gzip stream's when ``allow_nested_archives`` is enabled.
        Trailing dots and spaces are ignored, as Windows drops them
        on extraction.

        Args:
            filename: Filename to check.

        Returns:
            True if the name is a rejected nested archive.
        """
        ext = self._extension(filename)
        return ext in self._nested_archive_exts and not (
            self.config.limits.allow_nested_archives
            and ext in PERMITTED_NESTED_ARCHIVE_EXTS
        )

    def _check_entry_name(self, entry: zipfile.ZipInfo) -> list[_Threat]:
        """
        Apply the top-level filename checks to an entry name.

        The whole name gets the Unicode checks and must not contain
        ``:``, which NTFS reads as an alternate data stream or device
        separator (``run.exe::$DATA``, ``CON:``); every path
        component gets the Windows reserved-name check and a file's
        base name the blocked and compound extension checks, all
        driven by the configuration. Name checks run on the NFC name
        and on its NFKC form; both validators ignore the trailing
        dots and spaces that Windows drops on extraction.

        Args:
            entry: ZIP entry whose name is checked.

        Returns:
            One threat if the name fails a check, otherwise none.
        """
        try:
            name = self._unicode.validate_unicode_security(entry.filename)
            if ":" in name or ":" in self._unicode.compatibility_form(name):
                return [
                    _content_threat(
                        f"Unsafe file name {entry.filename!r}:"
                        " ':' is not allowed in entry names"
                    )
                ]
            components = name.replace("\\", "/").split("/")
            for component in components:
                for form in (
                    component,
                    self._unicode.compatibility_form(component),
                ):
                    self._windows.validate_windows_reserved_names(form)
            if not entry.is_dir():
                base = components[-1]
                for form in (base, self._unicode.compatibility_form(base)):
                    self._extensions.validate_extensions(form)
        except FilenameSecurityError as err:
            # repr escapes control and bidi characters in the message
            return [
                _content_threat(
                    f"Unsafe file name {entry.filename!r}: {err.message}"
                )
            ]
        return []

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

        The content is checked by ``_scan_content``. An entry that
        cannot be opened or read is reported as a threat, because
        its content was not scanned.

        Args:
            entry: ZIP entry to inspect.
            zip_file: Parent ZIP archive.

        Returns:
            List of content threats.

        Raises:
            ResourceLimitError: If the active resource monitor's time or
                memory limit is exceeded.
        """
        try:
            with zip_file.open(entry, "r") as file:
                return self._scan_content(entry.filename, file)
        except ResourceLimitError:
            raise
        except Exception as err:
            logger.warning(
                "Could not inspect content of %r: %s",
                entry.filename,
                err,
            )
            return [
                _content_threat(
                    f"Entry content could not be inspected: '{entry.filename}'"
                )
            ]

    def _scan_content(self, name: str, stream: IO[bytes]) -> list[_Threat]:
        """
        Scan content for executable, archive and script threats.

        The first 512 bytes are checked for executable signatures,
        archive signatures and script patterns; the script scan is
        skipped for a binary extension and for gzip data, whose
        compressed bytes match a pattern only by chance. An archive
        other than ZIP or gzip (bzip2, xz, 7z, RAR, tar) is always a
        threat. Unless ``allow_nested_archives`` is enabled, so is a
        gzip stream or a ZIP archive, found by a ZIP signature at
        the start or by an end record signature in the last 65,557
        bytes, where ``zipfile`` and ``unzip`` look for it, so
        prepended bytes do not hide it; finding the end record reads
        the content to its end.

        Args:
            name: Name the content is reported under; its extension
                decides the script scan.
            stream: Content, read from its current position.

        Returns:
            List of content threats.

        Raises:
            ResourceLimitError: If the active resource monitor's time or
                memory limit is exceeded.
        """
        threats: list[_Threat] = []
        sample = stream.read(_SAMPLE_SIZE)

        # Executable signatures are matched against the content
        # header (anchored): the content either is or is not an
        # executable.
        if matches_signature_prefix(sample, self._exec_signatures):
            threats.append(
                _content_threat(f"Executable content detected in '{name}'")
            )

        # A name check already reported a rejected archive
        if not self._archive_name_rejected(name) and self._is_rejected_archive(
            stream, sample
        ):
            threats.append(
                _Threat(
                    ErrorCode.ZIP_NESTED_ARCHIVE,
                    f"Nested archive detected: '{name}'",
                )
            )

        ext = os.path.splitext(name)[1].lower()
        if (
            not sample.startswith(_GZIP_MAGIC)
            and ext not in self._binary_exts
            and self._contains_script_patterns(sample, name)
        ):
            threats.append(
                _content_threat(f"Script content detected in '{name}'")
            )

        return threats

    def _is_rejected_archive(self, stream: IO[bytes], sample: bytes) -> bool:
        """
        Check if content is an archive that is rejected.

        An archive signature other than ZIP or gzip at the start, or
        a tar header's ``ustar`` magic at offset 257 (USTAR and GNU
        tar; a pre-POSIX tar has no magic), is always rejected.
        Unless ``allow_nested_archives`` is
        enabled, a ZIP or gzip signature at the start is rejected,
        and otherwise the rest of ``stream`` is read in
        ``chunk_size`` pieces, keeping only its last 65,557 bytes,
        to look for an end record signature.

        Args:
            stream: Content, positioned after ``sample``.
            sample: The first bytes of the content.

        Returns:
            True if the content is a rejected archive.

        Raises:
            ResourceLimitError: If the active resource monitor's time or
                memory limit is exceeded.
        """
        if (
            matches_signature_prefix(
                sample, self._unpermitted_archive_signatures
            )
            or sample[_TAR_MAGIC_OFFSET : _TAR_MAGIC_OFFSET + len(_TAR_MAGIC)]
            == _TAR_MAGIC
        ):
            return True
        if self.config.limits.allow_nested_archives:
            return False
        if sample.startswith(_GZIP_MAGIC) or matches_signature_prefix(
            sample, self._zip_signatures
        ):
            return True
        tail = sample
        while chunk := stream.read(self.config.limits.chunk_size):
            check_resource_limits()
            tail = tail[-_END_RECORD_SPAN:] + chunk
        return _END_RECORD_SIGNATURE in tail[-_END_RECORD_SPAN:]

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
        ``depth`` is 0; the caller checks it. Every file entry is
        streamed into a spooled temporary file. A nested ZIP archive
        (an entry with a recursable archive extension, starting with
        a ZIP signature or with an end record signature in its last
        65,557 bytes) is checked like a top-level archive (the
        compression checks of ``CompressionSecurityValidator`` and
        the entry and structure checks of this inspector) and then
        recursed into. A gzip stream (content starting with the gzip
        magic) is a level of its own: it is inflated under the
        limits of ``GzipContentInspector`` into another spooled
        file, counted as one entry, and its content is scanned like
        an entry's and recursed into one level deeper if it is
        itself a ZIP archive or gzip stream. Depth, cumulative entry
        count and elapsed time are tracked across all levels, and the
        hashes of a ZIP archive's ancestors to detect recursive and
        quine structures. Sibling archives with identical content are
        not a quine. An inner archive that cannot be read, parsed or
        fully inspected is rejected, and so is an entry compressed
        with a method other than stored or deflated, before it is
        opened. Other archive formats are never recursed into; the
        entry checks reject them.

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
            ZipBombError: If a nested archive or gzip stream is a
                decompression bomb.
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
        location = f"nested archive '{path}'" if depth else "ZIP archive"
        try:
            self._check_depth(depth)

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
        except ZIP_PARSE_ERRORS as err:
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

    def _check_depth(self, depth: int) -> None:
        """
        Raise if a nesting level is deeper than ``max_zip_depth``.

        Args:
            depth: Nesting depth of the level.

        Raises:
            ZipContentError: With ``ZIP_RECURSIVE_STRUCTURE`` if
                ``depth`` exceeds the limit.
        """
        max_depth = self.config.limits.max_zip_depth
        if depth <= max_depth:
            return
        raise ZipContentError(
            message=f"Excessive nesting depth: {depth} (max {max_depth})",
            threats=[f"Nesting depth {depth} exceeds limit {max_depth}"],
            error_code=ErrorCode.ZIP_RECURSIVE_STRUCTURE,
        )

    def _count_entries(self, entry_counter: list[int], count: int) -> None:
        """
        Add entries to the cumulative count and check its limit.

        Args:
            entry_counter: Single-element list holding the
                cumulative entry count across all levels.
            count: Entries to add.

        Raises:
            ZipContentError: With ``ZIP_COMPLEXITY_ATTACK`` if the
                count exceeds ``max_total_entries_recursive``.
        """
        entry_counter[0] += count
        limit = self.config.limits.max_total_entries_recursive
        if entry_counter[0] <= limit:
            return
        raise ZipContentError(
            message=(
                f"Total recursive entries ({entry_counter[0]})"
                f" exceeds limit ({limit})"
            ),
            threats=[f"Complexity attack: {entry_counter[0]} entries"],
            error_code=ErrorCode.ZIP_COMPLEXITY_ATTACK,
        )

    def _check_timeout(self, start_time: float) -> None:
        """
        Raise if the recursive inspection has run out of time.

        Args:
            start_time: Monotonic timestamp of the initial call.

        Raises:
            ZipContentError: With ``ZIP_ANALYSIS_TIMEOUT`` if more
                than ``zip_analysis_timeout`` seconds have passed.
        """
        timeout = self.config.limits.zip_analysis_timeout
        if time.monotonic() - start_time <= timeout:
            return
        raise ZipContentError(
            message=f"Recursive inspection timeout after {timeout}s",
            threats=["Recursive inspection timeout"],
            error_code=ErrorCode.ZIP_ANALYSIS_TIMEOUT,
        )

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

        Each file entry is copied into a spooled temporary file,
        which is inspected if the entry is a nested ZIP archive or
        gzip stream and closed once its subtree has been inspected.
        An entry compressed with a method other than stored or
        deflated is rejected before it is opened.

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
            ZipBombError: If a nested gzip stream is a
                decompression bomb.
            ZipContentError: If the cumulative entry count or the
                analysis timeout is exceeded, an entry uses an
                unsupported compression method, or a nested archive
                fails a check or cannot be read.
            ResourceLimitError: If the active resource monitor's
                time or memory limit is exceeded.
        """
        entries = zf.infolist()
        self._count_entries(entry_counter, len(entries))

        for entry in entries:
            check_resource_limits()
            self._check_timeout(start_time)

            if entry.is_dir():
                continue

            entry_path = f"{path}/{entry.filename}" if path else entry.filename
            unsupported = self._unsupported_method(entry)
            if unsupported:
                raise ZipContentError(
                    message=f"{entry_path}: {unsupported.message}",
                    threats=[f"{entry_path}: {unsupported.message}"],
                    error_code=unsupported.code,
                )
            with tempfile.SpooledTemporaryFile(
                max_size=self.config.limits.max_memory_buffer_size
            ) as inner:
                self._copy_entry(zf, entry, entry_path, inner)
                self._inspect_kind(
                    inner,
                    entry.filename,
                    entry_path,
                    depth + 1,
                    ancestors,
                    entry_counter,
                    start_time,
                )

    def _inspect_kind(
        self,
        file_obj: tempfile.SpooledTemporaryFile[bytes],
        name: str,
        path: str,
        depth: int,
        ancestors: frozenset[str],
        entry_counter: list[int],
        start_time: float,
    ) -> None:
        """
        Inspect content as a nested level if it is an archive.

        Gzip data (the gzip magic at the start) is inspected as a
        gzip level. Other content is a ZIP archive when ``name`` has
        a recursable archive extension, it starts with a ZIP
        signature, or an end record signature lies in its last
        65,557 bytes, where ``zipfile`` and ``unzip`` find an
        archive behind prepended bytes. Anything else is left alone.

        Args:
            file_obj: Spooled file holding the content.
            name: Name of the content, for its extension.
            path: Nesting path of the content.
            depth: Nesting depth the content would have.
            ancestors: SHA-256 hashes of the enclosing ZIP archives.
            entry_counter: Single-element list holding the
                cumulative entry count across all levels.
            start_time: Monotonic timestamp of the initial call.

        Raises:
            ZipBombError: If a nested gzip stream is a
                decompression bomb.
            ZipContentError: If the nested level fails a check.
            ResourceLimitError: If the active resource monitor's
                time or memory limit is exceeded.
        """
        size = file_obj.seek(0, os.SEEK_END)
        file_obj.seek(0)
        head = file_obj.read(self._zip_signature_size)
        file_obj.seek(max(size - _END_RECORD_SPAN, 0))
        tail = file_obj.read()
        file_obj.seek(0)
        if head.startswith(_GZIP_MAGIC):
            self._inspect_gzip(
                file_obj,
                name,
                path,
                depth,
                ancestors,
                entry_counter,
                start_time,
            )
        elif (
            self._extension(name) in self._recursable_exts
            or matches_signature_prefix(head, self._zip_signatures)
            or _END_RECORD_SIGNATURE in tail
        ):
            self._inspect_nested(
                file_obj, path, depth, ancestors, entry_counter, start_time
            )

    def _inspect_gzip(
        self,
        file_obj: SeekableFile,
        name: str,
        path: str,
        depth: int,
        ancestors: frozenset[str],
        entry_counter: list[int],
        start_time: float,
    ) -> None:
        """
        Inflate one nested gzip stream and inspect its content.

        The stream is inflated by ``GzipContentInspector`` in
        ``chunk_size`` steps, under ``max_uncompressed_size`` and
        ``max_compression_ratio`` relative to the stream's size,
        into a spooled temporary file. Concatenated members and
        zero padding are accepted; trailing data, a bad CRC-32 or
        size and truncation are corrupt (``ZIP_CORRUPT``). The
        content counts as one entry, is scanned like an entry's
        content under ``name`` without its ``.gz`` suffix, and is
        inspected one level deeper if it is a ZIP archive or gzip
        stream.

        Args:
            file_obj: Seekable file containing the gzip stream.
            name: Name of the stream, for its inner name.
            path: Nesting path of the stream.
            depth: Nesting depth of the stream.
            ancestors: SHA-256 hashes of the enclosing ZIP archives.
            entry_counter: Single-element list holding the
                cumulative entry count across all levels.
            start_time: Monotonic timestamp of the initial call.

        Raises:
            ZipBombError: If the stream exceeds a ratio or size
                limit, with ``path`` prefixed to the message.
            ZipContentError: If the stream is corrupt, its content
                fails a check, or a limit on depth, entries or time
                is exceeded.
            ResourceLimitError: If the active resource monitor's
                time or memory limit is exceeded.
        """
        inner_name = name
        if name.lower().endswith(_GZIP_SUFFIX):
            inner_name = name[: -len(_GZIP_SUFFIX)]
        try:
            self._check_depth(depth)
            self._count_entries(entry_counter, 1)
            self._check_timeout(start_time)
            with tempfile.SpooledTemporaryFile(
                max_size=self.config.limits.max_memory_buffer_size
            ) as inner:
                size = file_obj.seek(0, os.SEEK_END)
                with self._prefixed_errors(path):
                    for chunk in self._gzip.iter_decompressed_chunks(
                        file_obj, size
                    ):
                        inner.write(chunk)
                    inner.seek(0)
                    self._raise_threats(self._scan_content(inner_name, inner))
                self._inspect_kind(
                    inner,
                    inner_name,
                    f"{path}/{os.path.basename(inner_name)}",
                    depth + 1,
                    ancestors,
                    entry_counter,
                    start_time,
                )
        except (ZipBombError, ZipContentError, ResourceLimitError):
            raise
        except Exception as err:
            logger.warning("Could not inspect gzip stream %r: %s", path, err)
            raise ZipContentError(
                message=f"Could not inspect gzip stream '{path}'",
                threats=[f"Uninspectable gzip stream '{path}'"],
            ) from err

    def _copy_entry(
        self,
        zf: zipfile.ZipFile,
        entry: zipfile.ZipInfo,
        path: str,
        dest: tempfile.SpooledTemporaryFile[bytes],
    ) -> None:
        """
        Copy an entry's content into ``dest``.

        The entry is read through its ``ZipInfo`` in ``chunk_size``
        pieces, so duplicate names cannot select a different entry
        and no more than one chunk is held in memory beyond the
        spooled file.

        Args:
            zf: Archive holding the entry.
            entry: Entry to copy.
            path: Nesting path of the entry, for messages.
            dest: Empty spooled file receiving the entry bytes.

        Raises:
            ZipContentError: If the entry cannot be read or its
                content exceeds ``max_individual_file_size``.
            ResourceLimitError: If the active resource monitor's
                time or memory limit is exceeded.
        """
        limits = self.config.limits
        size = 0
        try:
            with zf.open(entry, "r") as stream:
                while chunk := stream.read(limits.chunk_size):
                    check_resource_limits()
                    size += len(chunk)
                    if size > limits.max_individual_file_size:
                        raise ZipContentError(
                            message=(
                                f"Nested entry too large: '{path}'"
                                " exceeds the individual file size limit"
                            ),
                            threats=[f"Nested entry too large: '{path}'"],
                            error_code=ErrorCode.FILE_TOO_LARGE,
                        )
                    dest.write(chunk)
        except (ZipContentError, ResourceLimitError):
            raise
        except Exception as err:
            logger.warning("Could not read nested entry %r: %s", path, err)
            raise ZipContentError(
                message=f"Nested entry could not be read: '{path}'",
                threats=[f"Nested entry could not be read: '{path}'"],
            ) from err

    @contextlib.contextmanager
    def _prefixed_errors(self, path: str) -> Iterator[None]:
        """
        Re-raise a nested level's failure under its nesting path.

        A decompression bomb is re-raised as ``ZipBombError`` with
        its details and ``path`` prefixed to the message; other
        ``CompressionSecurityError`` failures are raised as
        ``ZipContentError`` with the original error code, and their
        threats are prefixed with ``path``.

        Args:
            path: Nesting path of the level.

        Yields:
            None, while the level is checked.

        Raises:
            ZipBombError: If the level is a decompression bomb.
            ZipContentError: If the level fails another check.
        """
        try:
            yield
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

    def _check_nested_level(
        self, file_obj: SeekableFile, path: str, start_time: float
    ) -> None:
        """
        Run the top-level archive checks on a nested archive.

        Applies the compression, size, entry-count and layout
        checks of ``CompressionSecurityValidator`` and this
        inspector's entry and structure checks, with failures
        re-raised under ``path`` (see ``_prefixed_errors``).

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
        with self._prefixed_errors(path):
            size = file_obj.seek(0, os.SEEK_END)
            self._compression.validate_zip_compression_ratio(file_obj, size)
            self._inspect_archive(file_obj, start_time)
