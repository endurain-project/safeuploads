"""Tests for FitSecurityValidator."""

import io
import struct

import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.exceptions import (
    ErrorCode,
    FileSignatureError,
    FileValidationError,
    ResourceLimitError,
)
from safeuploads.validators.fit_validator import (
    FitSecurityValidator,
    fit_crc16,
)

_RECORDS = b"\x40\x00\x00\x15\x00\x01\x00\x00\x00\x00\x00\x00"


def _reference_crc(data: bytes) -> int:
    """Bitwise CRC-16/ARC (poly 0xA001 reflected, init 0)."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def build_fit(
    records: bytes = _RECORDS,
    *,
    header_size: int = 12,
    header_crc: int | None = None,
) -> bytes:
    """
    Build one structurally valid FIT section in memory.

    Args:
        records: Record bytes placed after the header.
        header_size: 12 or 14.
        header_crc: Header CRC for a 14-byte header; None computes
            the correct value.

    Returns:
        Header, records and the file CRC.
    """
    head = (
        struct.pack("<BBHI", header_size, 0x10, 2132, len(records)) + b".FIT"
    )
    if header_size == 14:
        if header_crc is None:
            header_crc = fit_crc16(head)
        head += struct.pack("<H", header_crc)
    body = head + records
    return body + struct.pack("<H", fit_crc16(body))


def _validate(data: bytes, config: FileSecurityConfig | None = None) -> None:
    FitSecurityValidator(config or FileSecurityConfig()).validate(
        io.BytesIO(data)
    )


def _assert_rejected(data: bytes) -> None:
    with pytest.raises(FileSignatureError) as exc_info:
        _validate(data)
    assert exc_info.value.error_code == ErrorCode.FIT_INVALID_STRUCTURE


class TestFitCrc:
    """The CRC matches the published CRC-16/ARC definition."""

    def test_check_value(self):
        assert fit_crc16(b"123456789") == 0xBB3D

    def test_matches_bitwise_reference(self):
        data = bytes(range(256)) * 3
        assert fit_crc16(data) == _reference_crc(data)

    def test_chunked_equals_whole(self):
        data = bytes(range(200))
        assert fit_crc16(data[100:], fit_crc16(data[:100])) == fit_crc16(data)


class TestFitSecurityValidatorAccepts:
    """Structurally valid FIT files pass."""

    def test_initialization(self, default_config):
        assert FitSecurityValidator(default_config).config == default_config

    def test_twelve_byte_header(self):
        _validate(build_fit())

    def test_fourteen_byte_header_with_crc(self):
        _validate(build_fit(header_size=14))

    def test_fourteen_byte_header_zero_crc(self):
        _validate(build_fit(header_size=14, header_crc=0))

    def test_chained_sections(self):
        _validate(build_fit() + build_fit(header_size=14))

    def test_multi_chunk_data(self):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(chunk_size=16)
        _validate(build_fit(bytes(range(256)) * 4), config)

    def test_file_position_reset(self):
        buf = io.BytesIO(build_fit())
        FitSecurityValidator(FileSecurityConfig()).validate(buf)
        assert buf.tell() == 0


class TestFitSecurityValidatorRejects:
    """Malformed or padded FIT files are rejected."""

    def test_wrong_file_crc(self):
        data = bytearray(build_fit())
        data[-1] ^= 0xFF
        _assert_rejected(bytes(data))

    def test_corrupt_record_byte(self):
        data = bytearray(build_fit())
        data[14] ^= 0x01
        _assert_rejected(bytes(data))

    def test_wrong_header_crc(self):
        _assert_rejected(build_fit(header_size=14, header_crc=0x1234))

    @pytest.mark.parametrize("size", [0, 11, 13, 15, 255])
    def test_bad_header_size(self, size):
        data = bytearray(build_fit())
        data[0] = size
        _assert_rejected(bytes(data))

    def test_data_size_larger_than_file(self):
        data = bytearray(build_fit())
        data[4:8] = struct.pack("<I", 10_000)
        _assert_rejected(bytes(data))

    def test_zero_data_size(self):
        _assert_rejected(build_fit(b""))

    def test_trailing_junk(self):
        _assert_rejected(build_fit() + b"<?php evil ?>")

    def test_trailing_partial_section(self):
        _assert_rejected(build_fit() + build_fit()[:5])

    def test_junk_between_sections(self):
        _assert_rejected(build_fit() + b"\x00" + build_fit())

    def test_truncated_crc(self):
        _assert_rejected(build_fit()[:-1])

    def test_truncated_header(self):
        _assert_rejected(build_fit()[:8])

    def test_empty(self):
        _assert_rejected(b"")

    def test_fake_fit_with_php(self):
        _assert_rejected(
            b"\x0e\x10" + b"\0" * 6 + b".FIT" + b"<?php evil ?>" * 10
        )

    def test_missing_magic(self):
        data = bytearray(build_fit())
        data[8:12] = b"XXXX"
        _assert_rejected(bytes(data))

    def test_error_is_file_validation_error(self):
        with pytest.raises(FileValidationError) as exc_info:
            _validate(b"\x0c")
        assert exc_info.value.error_code == ErrorCode.FIT_INVALID_STRUCTURE

    def test_filename_carried(self):
        with pytest.raises(FileSignatureError) as exc_info:
            FitSecurityValidator(FileSecurityConfig()).validate(
                io.BytesIO(b""), filename="a.fit"
            )
        assert exc_info.value.error_code == ErrorCode.FIT_INVALID_STRUCTURE
        assert exc_info.value.filename == "a.fit"

    def test_resource_limit_enforced_per_chunk(self, monkeypatch):
        def boom() -> None:
            raise ResourceLimitError("limit")

        monkeypatch.setattr(
            "safeuploads.validators.fit_validator.check_resource_limits",
            boom,
        )
        with pytest.raises(ResourceLimitError) as exc_info:
            _validate(build_fit())
        assert exc_info.value.error_code == ErrorCode.RESOURCE_LIMIT_EXCEEDED

    def test_file_shorter_than_reported_is_rejected(self):
        class _Shrinking(io.BytesIO):
            def read(self, size: int = -1, /) -> bytes:
                return super().read(size) if self.tell() < 12 else b""

        with pytest.raises(FileSignatureError) as exc_info:
            FitSecurityValidator(FileSecurityConfig()).validate(
                _Shrinking(build_fit())
            )
        assert exc_info.value.error_code == ErrorCode.FIT_INVALID_STRUCTURE
