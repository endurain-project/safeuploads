"""Fuzz tests for image validation."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from safeuploads.file_validator import FileValidator
from tests import images
from tests.fuzz.helpers import MockFile, accepted_async

_IMAGE_SIGNATURES = (b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n")


def _is_known_image(content):
    """Return whether content starts like a JPEG, PNG, WebP or HEIC."""
    if content.startswith(_IMAGE_SIGNATURES):
        return True
    if content[4:8] == b"ftyp":
        return True
    return content[:4] == b"RIFF" and content[8:12] == b"WEBP"


async def _assert_accepts_only_images(filename, content):
    """Validate and check the accepted upload is a known image."""
    validator = FileValidator()
    file = MockFile(filename, content)
    if await accepted_async(validator.validate_image_file(file)):
        assert _is_known_image(content)
        assert len(content) <= validator.config.limits.max_image_size


# JPEG header prefix
_JPEG_HDR = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
)

# PNG header prefix
_PNG_HDR = b"\x89PNG\r\n\x1a\n"

# WebP header prefix: RIFF container, WEBP form, VP8L chunk
_WEBP_HDR = b"RIFF\x00\x00\x00\x00WEBPVP8L"


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

    @given(padding=st.binary(min_size=0, max_size=2000))
    @settings(max_examples=200, deadline=3000)
    @pytest.mark.asyncio
    async def test_mutated_webp_never_crashes(self, padding):
        """Mutated WebP content must not crash."""
        content = _WEBP_HDR + padding
        await _assert_accepts_only_images("fuzz.webp", content)

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

    @given(
        build=st.sampled_from(
            [
                ("a.png", images.png, 2**31 - 1),
                ("a.jpg", images.jpeg, 2**16 - 1),
                ("a.webp", images.webp, 2**14),
                ("a.heic", images.heic, 2**32 - 1),
            ]
        ),
        data=st.data(),
    )
    @settings(max_examples=200, deadline=3000)
    @pytest.mark.asyncio
    async def test_accepted_iff_within_pixel_limit(self, build, data):
        """An image passes exactly when it fits max_image_pixels."""
        filename, builder, max_side = build
        side = st.integers(min_value=1, max_value=max_side)
        width, height = data.draw(side), data.draw(side)
        validator = FileValidator()
        file = MockFile(filename, builder(width, height))
        limit = validator.config.limits.max_image_pixels
        assert await accepted_async(validator.validate_image_file(file)) == (
            width * height <= limit
        )

    @given(segments=st.binary(min_size=0, max_size=2000))
    @settings(max_examples=200, deadline=3000)
    @pytest.mark.asyncio
    async def test_mutated_segments_before_frame_never_crash(self, segments):
        """Arbitrary bytes between APP0 and the frame must not crash."""
        content = images.jpeg(8, 8, before_frame=segments)
        await _assert_accepts_only_images("fuzz.jpg", content)

    @given(meta=st.binary(min_size=0, max_size=2000))
    @settings(max_examples=200, deadline=3000)
    @pytest.mark.asyncio
    async def test_mutated_heic_meta_never_crashes(self, meta):
        """Arbitrary bytes in a HEIC meta box must not crash."""
        content = images.heif_file(images.heif_box(b"meta", meta))
        await _assert_accepts_only_images("fuzz.heic", content)

    @given(data=st.data())
    @settings(max_examples=200, deadline=3000)
    @pytest.mark.asyncio
    async def test_mutated_heic_grid_never_crashes(self, data):
        """Flipping bytes of a grid HEIC's meta box must not crash."""
        content = bytearray(
            images.heic_grid(64, 48, rows=2, columns=2, tile=(32, 24))
        )
        start = len(images.heif_ftyp())
        for _ in range(data.draw(st.integers(min_value=1, max_value=8))):
            index = data.draw(
                st.integers(min_value=start, max_value=len(content) - 1)
            )
            content[index] = data.draw(st.integers(0, 255))
        await _assert_accepts_only_images("fuzz.heic", bytes(content))
