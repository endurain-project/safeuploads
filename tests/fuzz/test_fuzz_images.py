"""Fuzz tests for image validation."""

import contextlib

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from safeuploads.exceptions import (
    FileProcessingError,
    FileValidationError,
)
from safeuploads.file_validator import FileValidator


class _MockFile:
    """Minimal mock upload file for fuzz tests."""

    def __init__(self, filename, content):
        self.filename = filename
        self.content = content
        self.size = len(content)
        self._pos = 0

    async def read(self, size=-1):
        if size == -1:
            data = self.content[self._pos :]
            self._pos = len(self.content)
        else:
            data = self.content[self._pos : self._pos + size]
            self._pos += len(data)
        return data

    async def seek(self, offset):
        self._pos = offset
        return self._pos


# JPEG header prefix
_JPEG_HDR = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
)

# PNG header prefix
_PNG_HDR = b"\x89PNG\r\n\x1a\n"


@pytest.mark.fuzz
class TestFuzzImageValidation:
    """Property tests for image validation."""

    @given(padding=st.binary(min_size=0, max_size=2000))
    @settings(max_examples=200, deadline=3000)
    @pytest.mark.asyncio
    async def test_mutated_jpeg_never_crashes(self, padding):
        """Mutated JPEG content must not crash."""
        validator = FileValidator()
        content = _JPEG_HDR + padding + b"\xff\xd9"
        file = _MockFile("fuzz.jpg", content)
        with contextlib.suppress(FileValidationError, FileProcessingError):
            await validator.validate_image_file(file)

    @given(padding=st.binary(min_size=0, max_size=2000))
    @settings(max_examples=200, deadline=3000)
    @pytest.mark.asyncio
    async def test_mutated_png_never_crashes(self, padding):
        """Mutated PNG content must not crash."""
        validator = FileValidator()
        content = _PNG_HDR + padding
        file = _MockFile("fuzz.png", content)
        with contextlib.suppress(FileValidationError, FileProcessingError):
            await validator.validate_image_file(file)

    @given(data=st.binary(min_size=1, max_size=500))
    @settings(max_examples=200, deadline=3000)
    @pytest.mark.asyncio
    async def test_random_bytes_as_image(self, data):
        """Arbitrary bytes as .jpg must not crash."""
        validator = FileValidator()
        file = _MockFile("random.jpg", data)
        with contextlib.suppress(FileValidationError, FileProcessingError):
            await validator.validate_image_file(file)

    @given(
        width=st.integers(min_value=0, max_value=65535),
        height=st.integers(min_value=0, max_value=65535),
    )
    @settings(max_examples=100, deadline=3000)
    @pytest.mark.asyncio
    async def test_png_extreme_dimensions(self, width, height):
        """PNG with extreme dimensions must not crash."""
        validator = FileValidator()
        # Construct PNG IHDR with given dimensions
        w = width.to_bytes(4, "big")
        h = height.to_bytes(4, "big")
        ihdr_data = (
            w
            + h
            + b"\x08\x02"  # 8-bit RGB
            + b"\x00\x00\x00"
        )
        # Minimal PNG: signature + IHDR + IEND
        content = (
            _PNG_HDR
            + b"\x00\x00\x00\x0d"
            + b"IHDR"
            + ihdr_data
            + b"\x00\x00\x00\x00"  # fake CRC
            + b"\x00\x00\x00\x00"
            + b"IEND"
            + b"\x00\x00\x00\x00"
        )
        file = _MockFile("dims.png", content)
        with contextlib.suppress(FileValidationError, FileProcessingError):
            await validator.validate_image_file(file)
