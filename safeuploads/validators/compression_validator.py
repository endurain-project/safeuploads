"""Validate ZIP compression ratios and detect zip bombs."""

from __future__ import annotations

import logging
import struct
import time
import zipfile
import zlib
from typing import TYPE_CHECKING, Any, NamedTuple

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
_LOCAL_HEADER_STRUCT = "<4s2B4HL2L2H"
_LOCAL_HEADER_SIGNATURE = b"PK\x03\x04"
_LOCAL_HEADER_SIZE = struct.calcsize(_LOCAL_HEADER_STRUCT)
_DATA_DESCRIPTOR_FLAG = 0x08
_UTF8_NAME_FLAG = 0x800
_ZIP64_EXTRA_ID = 0x0001
_DATA_DESCRIPTOR_SIGNATURE = b"PK\x07\x08"
_DATA_DESCRIPTOR_MAX_SIZE = 24
_UINT32_MAX = 0xFFFF_FFFF


class _CentralDirectory(NamedTuple):
    """
    Central directory location as ``zipfile`` reads it.

    Attributes:
        start: File offset ``zipfile`` reads the directory from.
        size: Directory size in bytes.
        offset: Directory offset declared by the end record.
        end: File offset where the EOCD record and its declared
            comment end.
    """

    start: int
    size: int
    offset: int
    end: int


def _central_directory_span(
    file_obj: SeekableFile,
) -> _CentralDirectory | None:
    """
    Locate the central directory the way ``zipfile`` does.

    Selects the EOCD record as ``zipfile`` does (the record that
    ends the file when there is no comment, otherwise the last
    signature in the trailing comment area) and, when a ZIP64
    locator precedes it, the ZIP64 record ``zipfile`` would use.
    The directory starts ``size`` bytes before the record that
    supplied its size; this is ``zipfile``'s ``offset + concat``,
    which absorbs data prepended to the archive. As in
    ``zipfile``, a ZIP64 record (with any extensible data) ends
    at its locator, which ends at the EOCD record.

    Args:
        file_obj: Seekable file containing ZIP data.

    Returns:
        The directory's location, or None where ``zipfile``
        raises ``BadZipFile``.
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
    eocd = struct.unpack(_EOCD_STRUCT, record)
    size: int = eocd[5]
    offset: int = eocd[6]
    end = location + _EOCD_SIZE + eocd[7]

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
    return _CentralDirectory(start_dir, size, offset, end)


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
    start_dir, size = span.start, span.size
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


def _descriptor_matches(
    file_obj: SeekableFile,
    offset: int,
    length: int,
    entry: zipfile.ZipInfo,
    signed: bool,
) -> bool:
    """
    Check that ``length`` bytes at ``offset`` are the entry's descriptor.

    A data descriptor holds an optional signature, the CRC-32 and
    the compressed and uncompressed sizes, as 4-byte values or as
    ZIP64 8-byte values. Each form has a distinct length, so the
    length selects the form and its values must equal those in
    the central directory.

    Args:
        file_obj: Seekable file containing ZIP data.
        offset: File offset where the entry's data ends.
        length: Bytes between the data and the next record.
        entry: Central-directory entry the descriptor belongs to.
        signed: Whether only the forms with a signature match.

    Returns:
        True if the bytes are a descriptor matching ``entry``.
    """
    if not 0 < length <= _DATA_DESCRIPTOR_MAX_SIZE:
        return False
    values = (entry.CRC, entry.compress_size, entry.file_size)
    bodies = [struct.pack("<L2Q", *values)]
    if max(entry.compress_size, entry.file_size) <= _UINT32_MAX:
        bodies.append(struct.pack("<3L", *values))
    file_obj.seek(offset)
    data = file_obj.read(length)
    return any(
        data == _DATA_DESCRIPTOR_SIGNATURE + body
        or (not signed and data == body)
        for body in bodies
    )


def _local_sizes(
    fields: tuple[Any, ...], extra: bytes
) -> tuple[int, int] | None:
    """
    Read the sizes a local header declares.

    A size field of 0xFFFFFFFF is taken from the local ZIP64
    extra field, uncompressed size first, as ``zipfile`` reads
    the central directory's.

    Args:
        fields: Unpacked fixed local header.
        extra: The local header's extra field.

    Returns:
        The compressed and uncompressed sizes, or None if a size
        field defers to a ZIP64 extra field that does not hold it.
    """
    compress_size: int = fields[8]
    file_size: int = fields[9]
    if _UINT32_MAX not in (compress_size, file_size):
        return compress_size, file_size
    zip64 = b""
    while len(extra) >= 4:
        tag, length = struct.unpack_from("<2H", extra)
        if tag == _ZIP64_EXTRA_ID:
            zip64 = extra[4 : 4 + length]
            break
        extra = extra[4 + length :]
    sizes = []
    for size in (file_size, compress_size):
        if size == _UINT32_MAX:
            if len(zip64) < 8:
                return None
            (size,) = struct.unpack_from("<Q", zip64)
            zip64 = zip64[8:]
        sizes.append(size)
    return sizes[1], sizes[0]


def _local_header_matches(
    fields: tuple[Any, ...],
    name: bytes,
    extra: bytes,
    entry: zipfile.ZipInfo,
) -> bool:
    """
    Check that a local header describes its central-directory entry.

    Readers that walk local headers trust them instead of the
    central directory, so both must name the same entry with the
    same name encoding, flag bit 3 and compression method. Without
    bit 3 the local CRC-32 and sizes must also agree; with it,
    the data descriptor carries them and the local fields, which
    writers usually leave zero, are not compared.

    Args:
        fields: Unpacked fixed local header.
        name: The local header's file name bytes.
        extra: The local header's extra field.
        entry: Central-directory entry for this header.

    Returns:
        True if the local header agrees with ``entry``.
    """
    # zipfile decoded the central name as cp437 or, with bit 11,
    # UTF-8; encoding it back gives the central name's bytes
    encoding = "utf-8" if entry.flag_bits & _UTF8_NAME_FLAG else "cp437"
    if (
        fields[0] != _LOCAL_HEADER_SIGNATURE
        or (fields[3] ^ entry.flag_bits)
        & (_DATA_DESCRIPTOR_FLAG | _UTF8_NAME_FLAG)
        or fields[4] != entry.compress_type
        or name != entry.orig_filename.encode(encoding)
    ):
        return False
    if entry.flag_bits & _DATA_DESCRIPTOR_FLAG:
        return True
    return fields[7] == entry.CRC and _local_sizes(fields, extra) == (
        entry.compress_size,
        entry.file_size,
    )


def _deflate_fills_entry(
    file_obj: SeekableFile,
    offset: int,
    entry: zipfile.ZipInfo,
    chunk_size: int,
) -> bool:
    """
    Check that an entry's deflate stream ends at its compressed size.

    ``zipfile`` stops reading an entry once the deflate stream
    ends, so bytes after that point within ``compress_size`` are
    never read, while a streaming reader resumes there looking for
    the data descriptor. The data is inflated in chunks, never
    producing more than ``file_size`` bytes in total or
    ``chunk_size`` bytes per call.

    Args:
        file_obj: Seekable file containing ZIP data.
        offset: File offset where the entry's data starts.
        entry: Central-directory entry for the data.
        chunk_size: Bytes read, and at most inflated, per step.

    Returns:
        True if the stream is valid deflate data that ends exactly
        at ``compress_size`` and inflates to ``file_size`` bytes.

    Raises:
        ResourceLimitError: If the active resource monitor's
            time or memory limit is exceeded.
    """
    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
    remaining = entry.compress_size
    produced = 0
    file_obj.seek(offset)
    try:
        while not decompressor.eof:
            check_resource_limits()
            data = decompressor.unconsumed_tail
            if not data and remaining:
                data = file_obj.read(min(chunk_size, remaining))
                remaining -= len(data)
            output = decompressor.decompress(data, chunk_size)
            produced += len(output)
            # No input and no output left means the stream is cut
            if produced > entry.file_size or not (data or output):
                return False
    except zlib.error:
        return False
    return (
        remaining == 0
        and not decompressor.unused_data
        and produced == entry.file_size
    )


def _layout_is_exact(
    file_obj: SeekableFile,
    entries: list[zipfile.ZipInfo],
    chunk_size: int,
) -> bool:
    """
    Check that the listed entries and end records fill the file.

    Readers that walk local headers from the start of the file
    see every entry stored there, while ``zipfile`` sees only the
    entries its central directory lists. The two agree only when
    the listed entries start at offset 0 and follow one another
    without gaps or overlaps up to the central directory, the
    directory sits at its declared offset, and the end records
    and their declared comment end the file. Each local header
    must agree with its central-directory entry. An entry spans
    its local header (with the local name and extra lengths), its
    compressed data and, when flag bit 3 is set, a data
    descriptor matching its central-directory values. Bit 3 is
    allowed only where a streaming reader finds the descriptor
    without trusting it: a deflated entry whose deflate stream
    ends exactly where the descriptor starts, or an empty stored
    entry whose signed descriptor follows its header directly.
    Stored data, or data of other methods this check does not
    inflate, has no end such a reader can find.

    ``header_offset`` already includes ``zipfile``'s ``concat``
    adjustment, so offsets compared here are file offsets.

    Args:
        file_obj: Seekable file containing ZIP data.
        entries: Entries ``zipfile`` lists for the file.
        chunk_size: Bytes read, and at most inflated, per step.

    Returns:
        True if every byte of the file belongs to a listed entry,
        the central directory or the end records.

    Raises:
        ResourceLimitError: If the active resource monitor's
            time or memory limit is exceeded.
    """
    directory = _central_directory_span(file_obj)
    if (
        directory is None
        or directory.start != directory.offset
        or directory.end != file_obj.seek(0, 2)
    ):
        return False
    entries = sorted(entries, key=lambda entry: entry.header_offset)
    offsets = [entry.header_offset for entry in entries]
    offsets.append(directory.start)
    if offsets[0] != 0:
        return False
    for entry, next_offset in zip(entries, offsets[1:], strict=True):
        check_resource_limits()
        file_obj.seek(entry.header_offset)
        header = file_obj.read(_LOCAL_HEADER_SIZE)
        if len(header) != _LOCAL_HEADER_SIZE:
            return False
        fields = struct.unpack(_LOCAL_HEADER_STRUCT, header)
        # A short read here leaves the data running past the
        # directory, which the offset comparison below rejects
        name = file_obj.read(fields[10])
        extra = file_obj.read(fields[11])
        if not _local_header_matches(fields, name, extra, entry):
            return False
        data_start = entry.header_offset + _LOCAL_HEADER_SIZE
        data_start += fields[10] + fields[11]
        data_end = data_start + entry.compress_size
        if not entry.flag_bits & _DATA_DESCRIPTOR_FLAG:
            if data_end != next_offset:
                return False
            continue
        stored = entry.compress_type == zipfile.ZIP_STORED
        if stored:
            # A reader scanning for the descriptor signature finds
            # it right after the header only when there is no data
            delimited = (
                entry.CRC == entry.compress_size == entry.file_size == 0
            )
        else:
            delimited = (
                entry.compress_type == zipfile.ZIP_DEFLATED
                and _deflate_fills_entry(
                    file_obj, data_start, entry, chunk_size
                )
            )
        if not delimited or not _descriptor_matches(
            file_obj, data_end, next_offset - data_end, entry, stored
        ):
            return False
    return True


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
        Once the declared sizes pass, the listed entries, the
        central directory and the end records must fill the file
        exactly, with no gap, overlap, prepended or trailing bytes,
        and each local header must agree with its directory entry.
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
                (including bytes outside the listed entries and a
                directory entry that declares file data), too many
                entries, nested archives detected, or individual
                file too large.
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

                # Runs once the declared sizes are within limits,
                # because it inflates entries with data descriptors
                self._check_layout(file_obj, zip_entries)

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

    def _check_layout(
        self, file_obj: SeekableFile, entries: list[zipfile.ZipInfo]
    ) -> None:
        """
        Raise unless the listed entries fill the ZIP file exactly.

        Args:
            file_obj: Seekable file containing ZIP data.
            entries: Entries ``zipfile`` lists for the file.

        Raises:
            CompressionSecurityError: If any byte of the file lies
                outside the listed entries, the central directory
                and the end records.
            ResourceLimitError: If the active resource monitor's
                time or memory limit is exceeded.
        """
        if _layout_is_exact(file_obj, entries, self.config.limits.chunk_size):
            return
        logger.warning(
            "ZIP layout does not match its central directory",
            extra=log_extra({"error_type": "zip_layout_mismatch"}),
        )
        raise CompressionSecurityError(
            message="ZIP archive contains data outside its listed entries",
            error_code=ErrorCode.ZIP_INVALID_STRUCTURE,
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
