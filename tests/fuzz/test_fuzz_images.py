"""Fuzz tests for image validation."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from safeuploads.file_validator import FileValidator
from tests.fuzz.helpers import MockFile, accepted_async

_IMAGE_SIGNATURES = (b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n")


async def _assert_accepts_only_images(filename, content):
    """Validate and check the accepted upload is a known image."""
    validator = FileValidator()
    file = MockFile(filename, content)
    if await accepted_async(validator.validate_image_file(file)):
        assert content.startswith(_IMAGE_SIGNATURES)
        assert len(content) <= validator.config.limits.max_image_size


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
        content = _JPEG_HDR + padding + b"\xff\xd9"
        await _assert_accepts_only_images("fuzz.jpg", content)

    @given(padding=st.binary(min_size=0, max_size=2000))
    @settings(max_examples=200, deadline=3000)
    @pytest.mark.asyncio
    async def test_mutated_png_never_crashes(self, padding):
        """Mutated PNG content must not crash."""
        content = _PNG_HDR + padding
        await _assert_accepts_only_images("fuzz.png", content)

    @given(data=st.binary(min_size=1, max_size=500))
    @settings(max_examples=200, deadline=3000)
    @pytest.mark.asyncio
    async def test_random_bytes_as_image(self, data):
        """Arbitrary bytes as .jpg must not crash."""
        await _assert_accepts_only_images("random.jpg", data)

    @given(
        width=st.integers(min_value=0, max_value=65535),
        height=st.integers(min_value=0, max_value=65535),
    )
    @settings(max_examples=100, deadline=3000)
    @pytest.mark.asyncio
    async def test_png_extreme_dimensions(self, width, height):
        """PNG with extreme dimensions must not crash."""
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
        await _assert_accepts_only_images("dims.png", content)
