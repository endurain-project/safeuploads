"""Tests for ImageDimensionValidator."""

import io
import struct

import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.exceptions import (
    ErrorCode,
    FileSignatureError,
    ImageDimensionError,
    ResourceLimitError,
)
from safeuploads.validators.image_dimension_validator import (
    ImageDimensionValidator,
)
from tests.images import (
    JPEG_EOI,
    JPEG_PREFIX,
    PNG_SIGNATURE,
    jpeg,
    jpeg_segment,
    png,
    png_chunk,
    riff_webp,
    vp8_chunk,
    vp8l_chunk,
    vp8x_chunk,
    webp,
    webp_chunk,
)

_DEFAULT_MAX = SecurityLimits().max_image_pixels

# SOF markers carrying frame dimensions (DHT, JPG and DAC excluded)
_SOF_MARKERS = (
    0xC0,
    0xC1,
    0xC2,
    0xC3,
    0xC5,
    0xC6,
    0xC7,
    0xC9,
    0xCA,
    0xCB,
    0xCD,
    0xCE,
    0xCF,
)


def _config(max_image_pixels: int = _DEFAULT_MAX) -> FileSecurityConfig:
    config = FileSecurityConfig()
    config.limits = SecurityLimits(max_image_pixels=max_image_pixels)
    return config


def _validate(data: bytes, max_image_pixels: int = _DEFAULT_MAX) -> None:
    ImageDimensionValidator(_config(max_image_pixels)).validate(
        io.BytesIO(data), filename="photo"
    )


def _assert_invalid(data: bytes) -> None:
    with pytest.raises(FileSignatureError) as exc_info:
        _validate(data)
    assert exc_info.value.error_code == ErrorCode.IMAGE_INVALID_STRUCTURE
    assert exc_info.value.expected_type == "image"
    assert exc_info.value.filename == "photo"


def _assert_too_large(
    data: bytes, width: int, height: int, max_image_pixels: int
) -> None:
    with pytest.raises(ImageDimensionError) as exc_info:
        _validate(data, max_image_pixels)
    err = exc_info.value
    assert err.error_code == ErrorCode.IMAGE_DIMENSIONS_EXCEEDED
    assert (err.width, err.height) == (width, height)
    assert err.max_pixels == max_image_pixels
    assert err.filename == "photo"


class TestLimitBoundary:
    """The pixel limit is inclusive for every format."""

    @pytest.mark.parametrize("build", [png, jpeg, webp])
    def test_at_limit_accepted(self, build):
        _validate(build(100, 50), max_image_pixels=5000)

    @pytest.mark.parametrize("build", [png, jpeg, webp])
    def test_one_pixel_over_limit_rejected(self, build):
        _assert_too_large(build(100, 50), 100, 50, max_image_pixels=4999)

    def test_default_limit_applies(self):
        _assert_too_large(png(60000, 60000), 60000, 60000, _DEFAULT_MAX)

    def test_file_rewound_after_success(self):
        file = io.BytesIO(jpeg(4, 4))
        ImageDimensionValidator(_config()).validate(file)
        assert file.tell() == 0


class TestPng:
    """Dimensions come from the IHDR chunk."""

    def test_small_png_accepted(self):
        _validate(png(640, 480))

    @pytest.mark.parametrize(("width", "height"), [(0, 1), (1, 0)])
    def test_zero_dimension_rejected(self, width, height):
        _assert_invalid(png(width, height))

    def test_dimension_above_spec_maximum_rejected(self):
        _assert_invalid(png(2**31, 1))

    def test_first_chunk_not_ihdr_rejected(self):
        data = PNG_SIGNATURE + png_chunk(b"tEXt", b"x" * 13)
        _assert_invalid(data)

    def test_ihdr_with_wrong_length_rejected(self):
        ihdr = struct.pack(">II", 1, 1) + b"\x08\x02\x00\x00"
        _assert_invalid(PNG_SIGNATURE + png_chunk(b"IHDR", ihdr))

    def test_truncated_ihdr_rejected(self):
        _assert_invalid(png(1, 1)[:20])


class TestJpeg:
    """Dimensions come from the first frame header (SOF)."""

    def test_small_jpeg_accepted(self):
        _validate(jpeg(640, 480))

    @pytest.mark.parametrize("marker", _SOF_MARKERS)
    def test_every_frame_type_read(self, marker):
        _assert_too_large(
            jpeg(10, 10, frame_marker=marker), 10, 10, max_image_pixels=99
        )

    def test_frame_after_large_app_segments_found(self):
        # EXIF and ICC segments push the SOF far past the 8 KB header
        exif = jpeg_segment(0xE1, b"Exif\x00\x00" + b"\x00" * 30000)
        icc = jpeg_segment(0xE2, b"ICC_PROFILE\x00" + b"\x00" * 20000)
        data = jpeg(5000, 60000, before_frame=exif + icc)
        assert data.index(b"\xff\xc0") > 8192
        _assert_too_large(data, 5000, 60000, _DEFAULT_MAX)

    def test_tables_before_frame_skipped(self):
        tables = jpeg_segment(0xDB, b"\x00" * 65) + jpeg_segment(
            0xC4, b"\x00" * 29
        )
        _validate(jpeg(8, 8, before_frame=tables))

    def test_fill_bytes_before_marker_accepted(self):
        _validate(jpeg(8, 8, before_frame=b"\xff" * 20000))

    def test_frame_inside_app_payload_ignored(self):
        # A SOF-like byte pair inside a skipped segment is data
        decoy = jpeg_segment(0xE1, b"\xff\xc0\x00\x0b\x08\x00\x01\x00\x01")
        _assert_too_large(
            jpeg(9000, 9000, before_frame=decoy), 9000, 9000, _DEFAULT_MAX // 2
        )

    @pytest.mark.parametrize(("width", "height"), [(0, 8), (8, 0)])
    def test_zero_dimension_rejected(self, width, height):
        _assert_invalid(jpeg(width, height))

    @pytest.mark.parametrize("marker", [0xDA, 0xD9])
    def test_scan_or_end_before_frame_rejected(self, marker):
        _assert_invalid(JPEG_PREFIX + bytes((0xFF, marker)) + b"\x00" * 16)

    @pytest.mark.parametrize("marker", [0x00, 0x01, 0xD0, 0xD7, 0xD8])
    def test_standalone_marker_before_frame_rejected(self, marker):
        _assert_invalid(JPEG_PREFIX + bytes((0xFF, marker)) + jpeg(8, 8)[2:])

    def test_missing_marker_prefix_rejected(self):
        _assert_invalid(JPEG_PREFIX + b"\x00" * 32)

    def test_segment_length_below_two_rejected(self):
        _assert_invalid(JPEG_PREFIX + b"\xff\xe1\x00\x01" + b"\x00" * 16)

    def test_end_of_file_after_marker_rejected(self):
        _assert_invalid(JPEG_PREFIX + b"\xff\xe1")

    def test_segment_past_end_of_file_rejected(self):
        _assert_invalid(JPEG_PREFIX + b"\xff\xe1\xff\xff" + b"\x00" * 16)

    def test_end_of_file_before_frame_rejected(self):
        _assert_invalid(JPEG_PREFIX)

    def test_end_of_file_in_fill_bytes_rejected(self):
        _assert_invalid(JPEG_PREFIX + b"\xff" * 100)

    def test_truncated_frame_header_rejected(self):
        _assert_invalid(JPEG_PREFIX + b"\xff\xc0\x00\x0b\x08\x00")

    def test_frame_length_below_minimum_rejected(self):
        frame = b"\xff\xc0\x00\x07\x08\x00\x08\x00\x08"
        _assert_invalid(JPEG_PREFIX + frame + b"\x00" * 8 + JPEG_EOI)

    def test_resource_limit_enforced_per_segment(self, monkeypatch):
        def boom() -> None:
            raise ResourceLimitError("limit")

        monkeypatch.setattr(
            "safeuploads.validators.image_dimension_validator"
            ".check_resource_limits",
            boom,
        )
        with pytest.raises(ResourceLimitError):
            _validate(jpeg(8, 8))


class TestWebp:
    """Dimensions come from the first chunk after the WEBP form."""

    def test_lossless_accepted(self):
        _validate(webp(16384, 16384), max_image_pixels=16384 * 16384)

    def test_lossless_over_limit_rejected(self):
        _assert_too_large(webp(16384, 16384), 16384, 16384, _DEFAULT_MAX)

    def test_lossy_accepted(self):
        _validate(riff_webp(vp8_chunk(1920, 1080)))

    def test_lossy_over_limit_rejected(self):
        data = riff_webp(vp8_chunk(16383, 16383))
        _assert_too_large(data, 16383, 16383, _DEFAULT_MAX)

    def test_lossy_scale_bits_ignored(self):
        # The top two bits of each dimension are an upscaling hint
        data = riff_webp(vp8_chunk(0xC000 | 100, 0x4000 | 50))
        _assert_too_large(data, 100, 50, max_image_pixels=4999)

    @pytest.mark.parametrize(("width", "height"), [(0, 8), (8, 0)])
    def test_lossy_zero_dimension_rejected(self, width, height):
        _assert_invalid(riff_webp(vp8_chunk(width, height)))

    def test_lossy_bad_start_code_rejected(self):
        chunk = bytearray(vp8_chunk(8, 8))
        chunk[11] = 0x00
        _assert_invalid(riff_webp(bytes(chunk)))

    def test_lossy_interframe_rejected(self):
        chunk = bytearray(vp8_chunk(8, 8))
        chunk[8] |= 0x01
        _assert_invalid(riff_webp(bytes(chunk)))

    def test_extended_canvas_accepted(self):
        _validate(riff_webp(vp8x_chunk(4000, 3000) + vp8l_chunk(1, 1)))

    def test_extended_canvas_over_limit_rejected(self):
        data = riff_webp(vp8x_chunk(2**24, 2**24) + vp8l_chunk(1, 1))
        _assert_too_large(data, 2**24, 2**24, _DEFAULT_MAX)

    def test_lossless_bad_signature_rejected(self):
        chunk = bytearray(vp8l_chunk(8, 8))
        chunk[8] = 0x00
        _assert_invalid(riff_webp(bytes(chunk)))

    def test_lossless_unknown_version_rejected(self):
        bits = 7 | 7 << 14 | 1 << 29
        chunk = webp_chunk(b"VP8L", b"\x2f" + struct.pack("<I", bits))
        _assert_invalid(riff_webp(chunk))

    def test_unknown_first_chunk_rejected(self):
        _assert_invalid(riff_webp(webp_chunk(b"ALPH", b"\x00" * 16)))

    @pytest.mark.parametrize(
        "chunk", [vp8_chunk(8, 8), vp8l_chunk(8, 8), vp8x_chunk(8, 8)]
    )
    def test_truncated_chunk_rejected(self, chunk):
        _assert_invalid(riff_webp(chunk)[:24])


class TestUnknownFormat:
    """Content that is not PNG, JPEG or WebP is rejected."""

    @pytest.mark.parametrize(
        "data",
        [
            b"GIF89a\x01\x00\x01\x00" + b"\x00" * 20,
            b"RIFF\x00\x00\x00\x00WAVEfmt " + b"\x00" * 20,
            b"",
        ],
    )
    def test_rejected(self, data):
        _assert_invalid(data)
