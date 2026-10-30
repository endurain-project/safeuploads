"""Validate ZIP compression ratios and detect zip bombs."""

from __future__ import annotations

import logging
import struct
import time
import zipfile
from typing import TYPE_CHECKING

from ..audit import get_correlation_id, log_extra
from ..enums import ZipThreatCategory
from ..exceptions import (
    CompressionSecurityError,
    ErrorCode,
    FileProcessingError,
    ResourceLimitError,
    ZipBombError,
)
from ..utils import bytes_to_mb, check_resource_limits
from .base import BaseValidator

if TYPE_CHECKING:
    from ..config import FileSecurityConfig
    from ..protocols import SeekableFile


logger = logging.getLogger(__name__)

# ZIP record layouts and limits, as zipfile reads them
_EOCD_STRUCT = "<4s4H2LH"
_EOCD_SIGNATURE = b"PK\x05\x06"
_EOCD_SIZE = struct.calcsize(_EOCD_STRUCT)
_ZIP64_LOCATOR_STRUCT = "<4sLQL"
_ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
_ZIP64_LOCATOR_SIZE = struct.calcsize(_ZIP64_LOCATOR_STRUCT)
_ZIP64_EOCD_STRUCT = "<4sQ2H2L4Q"
_ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
_ZIP64_EOCD_SIZE = struct.calcsize(_ZIP64_EOCD_STRUCT)
_MAX_COMMENT_SIZE = (1 << 16) - 1
_CD_HEADER_STRUCT = "<4s4B4HL2L5H2L"
_CD_HEADER_SIGNATURE = b"PK\x01\x02"
_CD_HEADER_SIZE = struct.calcsize(_CD_HEADER_STRUCT)


def _central_directory_span(file_obj: SeekableFile) -> tuple[int, int] | None:
    """
    Locate the central directory the way ``zipfile`` does.

    Selects the EOCD record as ``zipfile`` does (the record that
    ends the file when there is no comment, otherwise the last
    signature in the trailing comment area) and, when a ZIP64
    locator precedes it, the ZIP64 record ``zipfile`` would use.
    The directory starts ``size`` bytes before the record that
    supplied its size; this is ``zipfile``'s ``offset + concat``,
    which absorbs data prepended to the archive.

    Args:
        file_obj: Seekable file containing ZIP data.

    Returns:
        Tuple of the directory's start offset and size in bytes,
        or None where ``zipfile`` raises ``BadZipFile``.
    """
    file_size = file_obj.seek(0, 2)
    if file_size < _EOCD_SIZE:
        return None
    location = file_size - _EOCD_SIZE
    file_obj.seek(location)
    record = file_obj.read(_EOCD_SIZE)
    if not (record[:4] == _EOCD_SIGNATURE and record[-2:] == b"\x00\x00"):
        search_start = max(location - _MAX_COMMENT_SIZE, 0)
        file_obj.seek(search_start)
        tail = file_obj.read(_MAX_COMMENT_SIZE + _EOCD_SIZE)
        start = tail.rfind(_EOCD_SIGNATURE)
        record = tail[start : start + _EOCD_SIZE]
        if start < 0 or len(record) != _EOCD_SIZE:
            return None
        location = search_start + start
    size: int = struct.unpack(_EOCD_STRUCT, record)[5]

    locator_offset = location - _ZIP64_LOCATOR_SIZE
    if locator_offset >= 0:
        file_obj.seek(locator_offset)
        signature, disk, zip64_offset, disks = struct.unpack(
            _ZIP64_LOCATOR_STRUCT, file_obj.read(_ZIP64_LOCATOR_SIZE)
        )
        if signature == _ZIP64_LOCATOR_SIGNATURE:
            # zipfile then takes the directory from the ZIP64 record,
            # read where the locator points or, if no record is
            # there, right before the locator (prepended data)
            record_offset = locator_offset - _ZIP64_EOCD_SIZE
            if disk != 0 or disks > 1 or zip64_offset > record_offset:
                return None
            location = zip64_offset
            file_obj.seek(location)
            record = file_obj.read(_ZIP64_EOCD_SIZE)
            if (
                not record.startswith(_ZIP64_EOCD_SIGNATURE)
                and location != record_offset
            ):
                location = record_offset
                file_obj.seek(location)
                record = file_obj.read(_ZIP64_EOCD_SIZE)
            if len(record) != _ZIP64_EOCD_SIZE or not record.startswith(
                _ZIP64_EOCD_SIGNATURE
            ):
                return None
            fields = struct.unpack(_ZIP64_EOCD_STRUCT, record)
            record_size, size, offset = fields[1], fields[8], fields[9]
            extra_size = record_offset - location
            if (
                offset + size != zip64_offset
                or record_size + 12 != _ZIP64_EOCD_SIZE + extra_size
            ):
                return None

    start_dir = location - size
    if start_dir < 0:
        return None
    return start_dir, size


def _count_zip_entries(file_obj: SeekableFile, limit: int) -> int | None:
    """
    Count central-directory records without parsing the archive.

    Walks the records ``zipfile`` would read, using the same loop
    and size accounting but reading only each 46-byte header and
    building no ``ZipInfo``, and stops once the count exceeds
    ``limit``. The declared EOCD entry count is ignored, as
    ``zipfile`` ignores it.

    Args:
        file_obj: Seekable file containing ZIP data.
        limit: Count above which the walk stops.

    Returns:
        The number of records, at most ``limit + 1``, or None
        where ``zipfile`` raises ``BadZipFile`` before that.
    """
    span = _central_directory_span(file_obj)
    if span is None:
        return None
    start_dir, size = span
    count = 0
    total = 0
    while total < size:
        # zipfile reads exactly ``size`` bytes, all present in the
        # file, so only a header crossing that end is truncated
        if total + _CD_HEADER_SIZE > size:
            return None
        file_obj.seek(start_dir + total)
        fields = struct.unpack(
            _CD_HEADER_STRUCT, file_obj.read(_CD_HEADER_SIZE)
        )
        if fields[0] != _CD_HEADER_SIGNATURE:
            return None
        count += 1
        if count > limit:
            break
        total += _CD_HEADER_SIZE + fields[12] + fields[13] + fields[14]
    return count


class CompressionSecurityValidator(BaseValidator):
    """
    Validates ZIP uploads against zip bombs and compression attacks.

    Attributes:
        config: Security configuration for validation limits.
    """

    def __init__(self, config: FileSecurityConfig):
        """
        Initialize the compression validator.

        Args:
            config: Security configuration with compression limits.
        """
        super().__init__(config)
        self._nested_archive_exts: tuple[str, ...] = tuple(
            ZipThreatCategory.NESTED_ARCHIVES.value
        )

    def validate_zip_compression_ratio(
        self, file_obj: SeekableFile, compressed_size: int
    ) -> None:
        """
        Validate ZIP archive against security limits.

        The central-directory records are counted, reading only
        their fixed headers, before ``zipfile`` parses them, so an
        archive with too many entries is rejected at bounded cost;
        the parsed count is checked again after parsing.
        Size and ratio checks read the declared ``file_size`` and
        ``compress_size`` from the archive's central directory,
        which an attacker can forge. Enable
        ``limits.verify_zip_decompression`` to additionally
        decompress every entry and reject archives whose real
        content does not match the declared metadata.

        Args:
            file_obj: Seekable file-like object containing ZIP data.
            compressed_size: Size of the compressed archive in bytes.

        Raises:
            ZipBombError: If compression ratio exceeds maximum allowed
                or total uncompressed size is too large.
            CompressionSecurityError: If ZIP structure is invalid
                (including a directory entry that declares file data),
                too many entries, nested archives detected, or
                individual file too large.
            ResourceLimitError: If the active resource monitor's
                time or memory limit is exceeded.
            FileProcessingError: If unexpected error occurs during
                validation such as memory errors or I/O errors.
        """
        try:
            # Seek to start for zipfile analysis
            file_obj.seek(0)
            logger.debug(
                "Analyzing ZIP compression (compressed size %d bytes)",
                compressed_size,
            )

            # Track analysis metrics
            total_uncompressed_size = 0
            total_compressed_size = compressed_size
            file_count = 0
            nested_archives = []
            max_compression_ratio = 0.0
            overall_compression_ratio = (
                0.0  # Initialize to avoid unbound variable
            )

            # Count the central-directory records before zipfile
            # parses every one of them into a ZipInfo
            entry_count = _count_zip_entries(
                file_obj, self.config.limits.max_zip_entries
            )
            if entry_count is not None:
                self._check_entry_count(entry_count)
            file_obj.seek(0)

            # Analyze ZIP file structure with timeout protection
            start_time = time.monotonic()

            with zipfile.ZipFile(file_obj, "r") as zip_file:
                zip_entries = zip_file.infolist()
                file_count = len(zip_entries)
                self._check_entry_count(file_count)

                # Analyze each entry in the ZIP
                for entry in zip_entries:
                    check_resource_limits()

                    # Check for timeout
                    if (
                        time.monotonic() - start_time
                        > self.config.limits.zip_analysis_timeout
                    ):
                        logger.error(
                            "ZIP analysis timeout",
                            extra=log_extra(
                                {
                                    "error_type": "zip_analysis_timeout",
                                    "timeout": (
                                        self.config.limits.zip_analysis_timeout
                                    ),
                                }
                            ),
                        )
                        raise ZipBombError(
                            message=(
                                "ZIP analysis timeout"
                                " after"
                                f" {self.config.limits.zip_analysis_timeout}s"
                                " - potential zip bomb"
                            ),
                            compression_ratio=0,
                        )

                    # Directory entries hold no data; a declared
                    # file_size means the name hides file content.
                    # compress_size is not checked because some
                    # writers store 2 bytes for empty directories.
                    if entry.is_dir():
                        if entry.file_size > 0:
                            logger.warning(
                                "Directory entry carries data",
                                extra=log_extra(
                                    {
                                        "error_type": "zip_dir_with_data",
                                        "file_name": entry.filename,
                                        "file_size": entry.file_size,
                                    }
                                ),
                            )
                            raise CompressionSecurityError(
                                message=(
                                    "Directory entry carries data:"
                                    f" '{entry.filename}'"
                                ),
                                error_code=ErrorCode.ZIP_INVALID_STRUCTURE,
                            )
                        continue

                    # Track uncompressed size
                    uncompressed_size = entry.file_size
                    compressed_size_entry = entry.compress_size
                    total_uncompressed_size += uncompressed_size

                    # Check individual file compression ratio
                    if compressed_size_entry > 0:  # Avoid division by zero
                        compression_ratio = (
                            uncompressed_size / compressed_size_entry
                        )
                        max_compression_ratio = max(
                            max_compression_ratio, compression_ratio
                        )

                        if (
                            compression_ratio
                            > self.config.limits.max_compression_ratio
                        ):
                            logger.error(
                                "Excessive compression ratio",
                                extra=log_extra(
                                    {
                                        "error_type": (
                                            "compression_ratio_exceeded"
                                        ),
                                        "file_name": entry.filename,
                                        "compression_ratio": (
                                            compression_ratio
                                        ),
                                        "max_ratio": (
                                            self.config.limits.max_compression_ratio
                                        ),
                                    }
                                ),
                            )
                            cid = get_correlation_id()
                            if cid:
                                self._audit.threat(
                                    entry.filename,
                                    cid,
                                    "Zip bomb — excessive compression ratio",
                                )
                            max_ratio = (
                                self.config.limits.max_compression_ratio
                            )
                            raise ZipBombError(
                                message=(
                                    "Excessive compression"
                                    " ratio detected:"
                                    f" {compression_ratio:.1f}:1"
                                    f" for '{entry.filename}'."
                                    " Maximum allowed:"
                                    f" {max_ratio}:1"
                                ),
                                compression_ratio=compression_ratio,
                                error_code=(
                                    ErrorCode.COMPRESSION_RATIO_EXCEEDED
                                ),
                            )

                    # Check for nested archive files
                    filename_lower = entry.filename.lower()
                    if any(
                        filename_lower.endswith(ext)
                        for ext in self._nested_archive_exts
                    ):
                        nested_archives.append(entry.filename)

                    # Check for excessively large individual files
                    # Use the configurable max_individual_file_size limit
                    if (
                        uncompressed_size
                        > self.config.limits.max_individual_file_size
                    ):
                        logger.warning(
                            "Individual file too large",
                            extra=log_extra(
                                {
                                    "error_type": "file_too_large",
                                    "file_name": entry.filename,
                                    "size_mb": bytes_to_mb(uncompressed_size),
                                    "max_size_mb": bytes_to_mb(
                                        self.config.limits.max_individual_file_size
                                    ),
                                }
                            ),
                        )
                        max_file_mb = bytes_to_mb(
                            self.config.limits.max_individual_file_size
                        )
                        raise CompressionSecurityError(
                            message=(
                                "Individual file too"
                                f" large: '{entry.filename}'"
                                " would expand to"
                                f" {bytes_to_mb(uncompressed_size)}MB."
                                " Maximum allowed:"
                                f" {max_file_mb}MB"
                            ),
                            error_code=ErrorCode.FILE_TOO_LARGE,
                        )

                # Check total uncompressed size
                if (
                    total_uncompressed_size
                    > self.config.limits.max_uncompressed_size
                ):
                    logger.warning(
                        "Total uncompressed size too large",
                        extra=log_extra(
                            {
                                "error_type": "zip_too_large",
                                "total_size_mb": bytes_to_mb(
                                    total_uncompressed_size
                                ),
                                "max_size_mb": bytes_to_mb(
                                    self.config.limits.max_uncompressed_size
                                ),
                            }
                        ),
                    )
                    max_uncomp_mb = bytes_to_mb(
                        self.config.limits.max_uncompressed_size
                    )
                    raise ZipBombError(
                        message=(
                            "Total uncompressed size"
                            " too large:"
                            f" {bytes_to_mb(total_uncompressed_size)}MB."
                            " Maximum allowed:"
                            f" {max_uncomp_mb}MB"
                        ),
                        compression_ratio=0,
                        uncompressed_size=total_uncompressed_size,
                        max_size=self.config.limits.max_uncompressed_size,
                    )

                # Check overall compression ratio
                if total_compressed_size > 0:
                    overall_compression_ratio = (
                        total_uncompressed_size / total_compressed_size
                    )
                    if (
                        overall_compression_ratio
                        > self.config.limits.max_compression_ratio
                    ):
                        logger.error(
                            "Overall compression ratio too high",
                            extra=log_extra(
                                {
                                    "error_type": (
                                        "compression_ratio_exceeded"
                                    ),
                                    "overall_ratio": (
                                        overall_compression_ratio
                                    ),
                                    "max_ratio": (
                                        self.config.limits.max_compression_ratio
                                    ),
                                }
                            ),
                        )
                        raise ZipBombError(
                            message=(
                                "Overall compression ratio"
                                " too high:"
                                f" {overall_compression_ratio:.1f}:1."
                                " Maximum allowed:"
                                f" {self.config.limits.max_compression_ratio}"
                                ":1"
                            ),
                            compression_ratio=(overall_compression_ratio),
                            max_ratio=(
                                self.config.limits.max_compression_ratio
                            ),
                            error_code=(ErrorCode.COMPRESSION_RATIO_EXCEEDED),
                        )

                # Reject nested archives (potential security risk)
                if (
                    nested_archives
                    and not self.config.limits.allow_nested_archives
                ):
                    logger.warning(
                        "Nested archives detected",
                        extra=log_extra(
                            {
                                "error_type": "zip_nested_archive",
                                "nested_archives": nested_archives,
                            }
                        ),
                    )
                    raise CompressionSecurityError(
                        message=(
                            "Nested archives are not"
                            " allowed:"
                            f" {', '.join(nested_archives)}"
                        ),
                        error_code=ErrorCode.ZIP_NESTED_ARCHIVE,
                    )

                # Cumulative entry count check for
                # complexity attack prevention
                max_recursive = self.config.limits.max_total_entries_recursive
                if file_count > max_recursive:
                    logger.error(
                        "ZIP entry count exceeds recursive limit",
                        extra=log_extra(
                            {
                                "file_count": file_count,
                                "max_recursive": max_recursive,
                            }
                        ),
                    )
                    raise CompressionSecurityError(
                        message=(
                            "ZIP entry count"
                            f" ({file_count})"
                            " exceeds recursive limit"
                            f" ({max_recursive})"
                        ),
                        error_code=(ErrorCode.ZIP_COMPLEXITY_ATTACK),
                    )

                # Optional: read every entry through zipfile to
                # confirm the declared metadata is not forged.
                if self.config.limits.verify_zip_decompression:
                    self._verify_entries_decompress(zip_file, zip_entries)

                # Log analysis results
                logger.debug(
                    "ZIP analysis: %s files, %sMB uncompressed,"
                    " max ratio: %.1f:1,"
                    " overall ratio: %.1f:1",
                    file_count,
                    bytes_to_mb(total_uncompressed_size),
                    max_compression_ratio,
                    overall_compression_ratio,
                )

        except zipfile.BadZipFile as err:
            logger.error("Invalid or corrupted ZIP file", exc_info=True)
            raise CompressionSecurityError(
                message="Invalid or corrupted ZIP file",
                error_code=ErrorCode.ZIP_CORRUPT,
            ) from err
        except zipfile.LargeZipFile as err:
            logger.error("ZIP file too large to process", exc_info=True)
            raise CompressionSecurityError(
                message="ZIP file too large to process safely",
                error_code=ErrorCode.ZIP_TOO_LARGE,
            ) from err
        except MemoryError as err:
            logger.error("ZIP requires excessive memory", exc_info=True)
            raise ZipBombError(
                message=(
                    "ZIP file requires too much"
                    " memory to process"
                    " - potential zip bomb"
                ),
                compression_ratio=0,
            ) from err
        except (ZipBombError, CompressionSecurityError, ResourceLimitError):
            # Re-raise our own exceptions
            raise
        except Exception as err:
            logger.error(
                "Unexpected error during ZIP compression validation",
                exc_info=True,
            )
            raise FileProcessingError(
                message="ZIP validation failed due to an internal error",
            ) from err

    def _check_entry_count(self, file_count: int) -> None:
        """
        Raise if a ZIP holds more entries than allowed.

        Args:
            file_count: Counted or parsed number of entries.

        Raises:
            CompressionSecurityError: If ``file_count`` exceeds
                ``limits.max_zip_entries``.
        """
        max_entries = self.config.limits.max_zip_entries
        if file_count <= max_entries:
            return
        logger.warning(
            "ZIP contains too many files",
            extra=log_extra(
                {
                    "error_type": "zip_too_many_entries",
                    "file_count": file_count,
                    "max_entries": max_entries,
                }
            ),
        )
        raise CompressionSecurityError(
            message=(
                "ZIP contains too many"
                f" files: {file_count}."
                f" Maximum allowed: {max_entries}"
            ),
            error_code=ErrorCode.ZIP_TOO_MANY_ENTRIES,
        )

    def _verify_entries_decompress(
        self,
        zip_file: zipfile.ZipFile,
        zip_entries: list[zipfile.ZipInfo],
    ) -> None:
        """
        Decompress every entry to detect forged metadata.

        The size checks above trust the central-directory
        ``file_size``. Reading each entry forces ``zipfile`` to
        validate the CRC and decompression, so an archive whose
        real content does not match its declared sizes raises
        ``zipfile.BadZipFile`` (surfaced by the caller as a
        corrupt archive). Reads are bounded by the already-
        validated declared sizes, and resource limits are checked
        after every chunk.

        Args:
            zip_file: Open ZIP archive to verify.
            zip_entries: Entries listed in the archive.

        Raises:
            ResourceLimitError: If the active resource monitor's
                time or memory limit is exceeded.
        """
        chunk_size = self.config.limits.chunk_size
        for entry in zip_entries:
            if entry.is_dir():
                continue
            with zip_file.open(entry, "r") as stream:
                while stream.read(chunk_size):
                    check_resource_limits()

    def validate(self, file_obj: SeekableFile, compressed_size: int) -> None:
        """
        Validate the compression ratio of a ZIP file.

        Args:
            file_obj: Seekable file-like object of the ZIP.
            compressed_size: Size of the file after compression
                in bytes.

        Raises:
            ZipBombError: If compression ratio exceeds maximum.
            CompressionSecurityError: If ZIP structure is invalid.
            FileProcessingError: If unexpected error occurs.
        """
        return self.validate_zip_compression_ratio(file_obj, compressed_size)
