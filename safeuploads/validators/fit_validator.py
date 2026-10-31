"""Structure validator for FIT binary activity files."""

from __future__ import annotations

import logging
import struct
from typing import TYPE_CHECKING

from ..exceptions import ErrorCode, FileSignatureError
from ..utils import check_resource_limits
from .base import BaseValidator

if TYPE_CHECKING:
    from ..config import FileSecurityConfig
    from ..protocols import SeekableFile


logger = logging.getLogger(__name__)

_FIT_MAGIC = b".FIT"
_HEADER_SIZES = (12, 14)
_CRC_SIZE = 2
_HEADER_CRC_COVERS = 12

# Garmin FIT SDK CRC-16 nibble table.
_NIBBLE_TABLE = (
    0x0000,
    0xCC01,
    0xD801,
    0x1400,
    0xF001,
    0x3C00,
    0x2800,
    0xE401,
    0xA001,
    0x6C00,
    0x7800,
    0xB401,
    0x5000,
    0x9C01,
    0x8801,
    0x4400,
)


def _update_crc_byte(crc: int, byte: int) -> int:
    """
    Advance the FIT CRC-16 by one byte (Garmin FIT SDK algorithm).

    Args:
        crc: Running CRC value.
        byte: Next input byte.

    Returns:
        The updated CRC value.
    """
    crc = (crc >> 4) & 0x0FFF ^ _NIBBLE_TABLE[crc & 0xF]
    crc ^= _NIBBLE_TABLE[byte & 0xF]
    crc = (crc >> 4) & 0x0FFF ^ _NIBBLE_TABLE[crc & 0xF]
    return crc ^ _NIBBLE_TABLE[(byte >> 4) & 0xF]


def _build_byte_table() -> tuple[int, ...]:
    """
    Precompute the CRC-16 state change for every input byte.

    Returns:
        A 256-entry table where entry ``b`` is the CRC reached by
        feeding byte ``b`` from a zero CRC.
    """
    return tuple(_update_crc_byte(0, b) for b in range(256))


_BYTE_TABLE = _build_byte_table()


def fit_crc16(data: bytes, crc: int = 0) -> int:
    """
    Compute the FIT CRC-16 over data.

    Args:
        data: Bytes to add to the checksum.
        crc: Running CRC from earlier chunks (0 to start).

    Returns:
        The CRC value after consuming ``data``.
    """
    for byte in data:
        crc = (crc >> 8) ^ _BYTE_TABLE[(crc ^ byte) & 0xFF]
    return crc


class FitSecurityValidator(BaseValidator):
    """
    Validates the container structure of FIT activity files.

    A FIT file is one or more sections back to back. Each section
    is a 12 or 14 byte header, ``data_size`` bytes of records and a
    CRC-16 over the header and records. The sections must cover the
    file exactly, so nothing can hide before, between or after
    them. Record contents are not interpreted.

    Attributes:
        config: Security configuration for validation limits.
    """

    def __init__(self, config: FileSecurityConfig):
        """
        Initialize the FIT structure validator.

        Args:
            config: Security configuration with file limits.
        """
        super().__init__(config)

    def validate(
        self, file_obj: SeekableFile, *, filename: str | None = None
    ) -> None:
        """
        Validate the FIT container structure of a file.

        The file is read in chunks of ``limits.chunk_size`` and
        resource limits are checked after every chunk.

        Args:
            file_obj: Seekable file containing FIT data.
            filename: Optional sanitized filename for error context.

        Raises:
            FileSignatureError: If a header, data size or CRC is
                invalid, or bytes are left outside the sections
                (FIT_INVALID_STRUCTURE).
            ResourceLimitError: If the active resource monitor's
                time or memory limit is exceeded.
        """
        file_obj.seek(0, 2)
        total = file_obj.tell()
        file_obj.seek(0)
        if total == 0:
            raise self._invalid("FIT file is empty", filename)
        offset = 0
        while offset < total:
            offset += self._validate_section(
                file_obj, total - offset, filename
            )
        file_obj.seek(0)

    def _validate_section(
        self,
        file_obj: SeekableFile,
        remaining: int,
        filename: str | None,
    ) -> int:
        """
        Validate one FIT section starting at the current position.

        Args:
            file_obj: Seekable file positioned at a section start.
            remaining: Bytes left in the file from this position.
            filename: Optional sanitized filename for error context.

        Returns:
            The total size in bytes of the section.

        Raises:
            FileSignatureError: If the section is invalid.
        """
        first = file_obj.read(1)
        if not first or first[0] not in _HEADER_SIZES:
            raise self._invalid("Invalid FIT header size", filename)
        header_size: int = first[0]
        if remaining < header_size:
            raise self._invalid("Truncated FIT header", filename)
        header = first + file_obj.read(header_size - 1)
        if header[8:12] != _FIT_MAGIC:
            raise self._invalid("Invalid FIT header signature", filename)
        if header_size == 14:
            (header_crc,) = struct.unpack_from("<H", header, 12)
            if header_crc and header_crc != fit_crc16(
                header[:_HEADER_CRC_COVERS]
            ):
                raise self._invalid("Invalid FIT header CRC", filename)
        data_size: int = struct.unpack_from("<I", header, 4)[0]
        if data_size == 0:
            raise self._invalid("FIT section has no data", filename)
        if remaining < header_size + data_size + _CRC_SIZE:
            raise self._invalid("FIT data size exceeds file", filename)

        crc = fit_crc16(header)
        left = data_size
        chunk_size = self.config.limits.chunk_size
        while left:
            chunk = file_obj.read(min(chunk_size, left))
            if not chunk:
                raise self._invalid("Truncated FIT data", filename)
            crc = fit_crc16(chunk, crc)
            left -= len(chunk)
            check_resource_limits()
        if file_obj.read(_CRC_SIZE) != struct.pack("<H", crc):
            raise self._invalid("Invalid FIT CRC", filename)
        return header_size + data_size + _CRC_SIZE

    @staticmethod
    def _invalid(message: str, filename: str | None) -> FileSignatureError:
        """
        Build the error for an invalid FIT structure.

        Args:
            message: Client-safe description of the failure.
            filename: Optional sanitized filename for error context.

        Returns:
            A FileSignatureError carrying FIT_INVALID_STRUCTURE.
        """
        logger.warning("Invalid FIT structure: %s", message)
        return FileSignatureError(
            message,
            filename=filename,
            expected_type="fit",
            error_code=ErrorCode.FIT_INVALID_STRUCTURE,
        )
