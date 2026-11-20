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
    heic,
    heic_grid,
    heif_box,
    heif_dimg,
    heif_file,
    heif_ftyp,
    heif_full_box,
    heif_grid_descriptor,
    heif_iinf,
    heif_iloc,
    heif_infe,
    heif_ipma,
    heif_iprp,
    heif_ispe,
    heif_meta,
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

    @pytest.mark.parametrize("build", [png, jpeg, webp, heic])
    def test_at_limit_accepted(self, build):
        _validate(build(100, 50), max_image_pixels=5000)

    @pytest.mark.parametrize("build", [png, jpeg, webp, heic])
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


_HDLR = heif_full_box(b"hdlr", b"\x00" * 4 + b"pict" + b"\x00" * 13)
_PITM = heif_full_box(b"pitm", struct.pack(">H", 1))
_ILOC = heif_iloc([(1, 0, [(0, 16)])])
_IINF = heif_iinf([heif_infe(1, b"hvc1")])
_IPRP = heif_iprp([heif_ispe(64, 48)], heif_ipma([(1, (1,))]))
_MDAT = heif_box(b"mdat", b"\x00" * 16)

_DESCRIPTOR = heif_grid_descriptor(1, 1, 64, 48)
_GRID_ILOC = heif_iloc([(1, 1, [(0, len(_DESCRIPTOR))])])
_GRID_IINF = heif_iinf([heif_infe(1, b"grid"), heif_infe(2, b"hvc1")])
_GRID_IREF = heif_dimg(1, [2])
_GRID_IPRP = heif_iprp([heif_ispe(64, 48)], heif_ipma([(1, (1,)), (2, (1,))]))
_GRID_IDAT = heif_box(b"idat", _DESCRIPTOR)


def _meta(*children: bytes) -> bytes:
    """Return a HEIC file whose meta box holds exactly ``children``."""
    return heif_ftyp() + heif_full_box(b"meta", b"".join(children)) + _MDAT


def _single(
    *, iloc: bytes = _ILOC, iinf: bytes = _IINF, iprp: bytes = _IPRP
) -> bytes:
    """Return a 64x48 single-image HEIC with the given boxes."""
    return _meta(_HDLR, _PITM, iloc, iinf, iprp)


def _grid(
    *,
    iloc: bytes = _GRID_ILOC,
    iinf: bytes = _GRID_IINF,
    iref: bytes = _GRID_IREF,
    iprp: bytes = _GRID_IPRP,
    idat: bytes = _GRID_IDAT,
) -> bytes:
    """Return a 64x48 one-tile grid HEIC with the given boxes."""
    return _meta(_HDLR, _PITM, iloc, iinf, iref, iprp, idat)


def _grid_in_mdat(offset_shift: int = 0) -> bytes:
    """Return a grid HEIC whose descriptor is stored in mdat."""

    def meta(offset: int) -> bytes:
        iloc = heif_iloc([(1, 0, [(offset, len(_DESCRIPTOR))])])
        return heif_meta([iloc, _GRID_IINF, _GRID_IREF, _GRID_IPRP])

    # The iloc fields have a fixed size, so the offset is known
    # from a first build with offset 0.
    offset = len(heif_ftyp() + meta(0)) + 8
    return (
        heif_ftyp()
        + meta(offset + offset_shift)
        + heif_box(b"mdat", _DESCRIPTOR)
    )


class TestHeic:
    """HEIC dimensions come from the primary item's ispe property."""

    def test_single_image_accepted(self):
        _validate(heic(4032, 3024))

    def test_single_image_over_limit_rejected(self):
        _assert_too_large(heic(60000, 60000), 60000, 60000, _DEFAULT_MAX)

    def test_mif1_brand_accepted(self):
        data = heif_file(
            heif_meta([_ILOC, _IINF, _IPRP]),
            ftyp=heif_ftyp(b"mif1", (b"mif1", b"heic")),
        )
        _validate(data)

    def test_64_bit_and_open_ended_top_level_boxes_accepted(self):
        large = b"\x00\x00\x00\x01mdat" + struct.pack(">Q", 24) + b"\x00" * 8
        open_ended = b"\x00\x00\x00\x00mdat" + b"\x00" * 8
        _validate(heic(64, 48) + large + open_ended)

    def test_wide_field_versions_accepted(self):
        pitm = heif_full_box(b"pitm", struct.pack(">I", 1), version=1)
        infe = heif_full_box(
            b"infe", struct.pack(">IH", 1, 0) + b"hvc1\x00", version=3
        )
        iinf = heif_full_box(b"iinf", struct.pack(">I", 1) + infe, version=1)
        ipma = heif_full_box(
            b"ipma",
            struct.pack(">IIBH", 1, 1, 1, 0x8001),
            version=1,
            flags=1,
        )
        iprp = heif_iprp([heif_ispe(64, 48)], ipma)
        _validate(_meta(_HDLR, pitm, _ILOC, iinf, iprp))

    def test_unassociated_property_index_zero_accepted(self):
        iprp = heif_iprp([heif_ispe(64, 48)], heif_ipma([(1, (0, 1))]))
        _validate(_single(iprp=iprp))

    def test_unknown_meta_children_ignored(self):
        free = heif_box(b"free", b"\x00" * 4)
        _validate(_meta(_HDLR, _PITM, free, _ILOC, _IINF, _IPRP))

    def test_every_ispe_bounded(self):
        # A thumbnail or auxiliary image larger than the primary
        iinf = heif_iinf([heif_infe(1, b"hvc1"), heif_infe(2, b"hvc1")])
        iprp = heif_iprp(
            [heif_ispe(64, 48), heif_ispe(60000, 60000)],
            heif_ipma([(1, (1,)), (2, (2,))]),
        )
        _assert_too_large(
            _single(iinf=iinf, iprp=iprp), 60000, 60000, _DEFAULT_MAX
        )

    def test_unassociated_ispe_bounded(self):
        iprp = heif_iprp(
            [heif_ispe(64, 48), heif_ispe(60000, 60000)],
            heif_ipma([(1, (1,))]),
        )
        _assert_too_large(_single(iprp=iprp), 60000, 60000, _DEFAULT_MAX)

    def test_primary_not_hevc_rejected(self):
        for item_type in (b"av01", b"iovl", b"iden", b"Exif"):
            _assert_invalid(_single(iinf=heif_iinf([heif_infe(1, item_type)])))

    def test_primary_not_declared_rejected(self):
        _assert_invalid(_single(iinf=heif_iinf([heif_infe(2, b"hvc1")])))

    def test_primary_without_ispe_rejected(self):
        iprp = heif_iprp([heif_ispe(64, 48)], heif_ipma([(2, (1,))]))
        _assert_invalid(_single(iprp=iprp))

    def test_primary_with_two_ispe_rejected(self):
        iprp = heif_iprp(
            [heif_ispe(64, 48), heif_ispe(8, 8)], heif_ipma([(1, (1, 2))])
        )
        _assert_invalid(_single(iprp=iprp))

    @pytest.mark.parametrize(("width", "height"), [(0, 48), (64, 0)])
    def test_zero_dimension_rejected(self, width, height):
        _assert_invalid(heic(width, height))

    def test_property_index_out_of_range_rejected(self):
        iprp = heif_iprp([heif_ispe(64, 48)], heif_ipma([(1, (2,))]))
        _assert_invalid(_single(iprp=iprp))

    def test_item_listed_twice_in_ipma_rejected(self):
        iprp = heif_iprp(
            [heif_ispe(64, 48)], heif_ipma([(1, (1,)), (1, (1,))])
        )
        _assert_invalid(_single(iprp=iprp))

    def test_two_ipma_boxes_rejected(self):
        ipma = heif_ipma([(1, (1,))])
        iprp = heif_box(
            b"iprp", heif_box(b"ipco", heif_ispe(64, 48)) + ipma + ipma
        )
        _assert_invalid(_single(iprp=iprp))

    @pytest.mark.parametrize(
        "iprp",
        [
            heif_box(b"iprp", heif_ipma([(1, (1,))])),
            heif_box(b"iprp", heif_box(b"ipco", heif_ispe(64, 48))),
        ],
        ids=["no-ipco", "no-ipma"],
    )
    def test_incomplete_iprp_rejected(self, iprp):
        _assert_invalid(_single(iprp=iprp))

    @pytest.mark.parametrize(
        "drop", [b"hdlr", b"pitm", b"iloc", b"iinf", b"iprp"]
    )
    def test_missing_meta_box_rejected(self, drop):
        boxes = [_HDLR, _PITM, _ILOC, _IINF, _IPRP]
        _assert_invalid(_meta(*(b for b in boxes if b[4:8] != drop)))

    def test_duplicate_meta_box_rejected(self):
        _assert_invalid(_meta(_HDLR, _PITM, _ILOC, _IINF, _IINF, _IPRP))

    def test_handler_not_pict_rejected(self):
        _assert_invalid(
            heif_file(heif_meta([_ILOC, _IINF, _IPRP], handler=b"vide"))
        )

    def test_entry_count_mismatch_rejected(self):
        _assert_invalid(
            _single(iinf=heif_iinf([heif_infe(1, b"hvc1")], count=2))
        )

    def test_non_infe_entry_rejected(self):
        iinf = heif_iinf([heif_infe(1, b"hvc1"), heif_box(b"free", b"")])
        _assert_invalid(_single(iinf=iinf))

    def test_duplicate_item_id_rejected(self):
        iinf = heif_iinf([heif_infe(1, b"hvc1"), heif_infe(1, b"hvc1")])
        _assert_invalid(_single(iinf=iinf))

    def test_protected_item_rejected(self):
        infe = heif_infe(1, b"hvc1", protection=1)
        _assert_invalid(_single(iinf=heif_iinf([infe])))

    @pytest.mark.parametrize(
        "data",
        [
            _meta(
                _HDLR,
                heif_full_box(b"pitm", b"\x00\x01", version=2),
                _ILOC,
                _IINF,
                _IPRP,
            ),
            _single(
                iinf=heif_iinf(
                    [heif_full_box(b"infe", b"\x00\x01\x00\x00", version=1)]
                )
            ),
            _single(
                iinf=heif_full_box(b"iinf", b"\x00\x00\x00\x00", version=2)
            ),
            _single(
                iprp=heif_iprp(
                    [heif_full_box(b"ispe", b"\x00" * 8, version=1)],
                    heif_ipma([(1, (1,))]),
                )
            ),
            _single(
                iprp=heif_iprp(
                    [heif_ispe(64, 48)],
                    heif_full_box(b"ipma", b"\x00" * 4, version=2),
                )
            ),
            heif_ftyp()
            + heif_full_box(
                b"meta", _HDLR + _PITM + _ILOC + _IINF + _IPRP, version=1
            )
            + _MDAT,
        ],
        ids=["pitm", "infe", "iinf", "ispe", "ipma", "meta"],
    )
    def test_unsupported_box_version_rejected(self, data):
        _assert_invalid(data)

    def test_no_meta_box_rejected(self):
        _assert_invalid(heif_ftyp() + _MDAT)

    def test_two_meta_boxes_rejected(self):
        meta = heif_meta([_ILOC, _IINF, _IPRP])
        _assert_invalid(heif_ftyp() + meta + meta)

    @pytest.mark.parametrize(
        "tail",
        [
            b"\x00\x00\x00\x40mdat",
            b"\x00\x00\x00\x04mdat",
            b"\x00\x00\x00\x01mdat\x00\x00",
            b"\x00\x00\x00\x01mdat" + struct.pack(">Q", 8),
            b"\x00\x00",
        ],
        ids=[
            "overruns-file",
            "below-header",
            "truncated-largesize",
            "largesize-below-header",
            "truncated-header",
        ],
    )
    def test_malformed_top_level_box_rejected(self, tail):
        _assert_invalid(heic(64, 48) + tail)

    @pytest.mark.parametrize(
        "ipco",
        [
            struct.pack(">I", 64) + b"ipco" + heif_ispe(64, 48),
            struct.pack(">I", 0) + b"ipco" + heif_ispe(64, 48),
            struct.pack(">I", 1) + b"ipco" + b"\x00" * 4,
            b"\x00\x00\x00",
        ],
        ids=["overruns-parent", "size-zero", "truncated-largesize", "short"],
    )
    def test_malformed_nested_box_rejected(self, ipco):
        iprp = heif_box(b"iprp", ipco)
        _assert_invalid(_single(iprp=iprp))

    def test_truncated_ispe_rejected(self):
        iprp = heif_iprp(
            [heif_full_box(b"ispe", b"\x00" * 6)], heif_ipma([(1, (1,))])
        )
        _assert_invalid(_single(iprp=iprp))

    def test_file_rewound_after_success(self):
        file = io.BytesIO(heic(4, 4))
        ImageDimensionValidator(_config()).validate(file)
        assert file.tell() == 0

    def test_resource_limit_enforced_per_box(self, monkeypatch):
        def boom() -> None:
            raise ResourceLimitError("limit")

        monkeypatch.setattr(
            "safeuploads.validators.image_dimension_validator"
            ".check_resource_limits",
            boom,
        )
        with pytest.raises(ResourceLimitError):
            _validate(heic(8, 8))


class TestHeicGrid:
    """A grid's descriptor and tiles must agree with its ispe."""

    def test_tiled_photo_accepted(self):
        # The layout phone cameras write: 512x512 tiles, trimmed
        _validate(heic_grid(4032, 3024, rows=6, columns=8, tile=(512, 512)))

    def test_tiled_photo_over_limit_rejected(self):
        data = heic_grid(9984, 9984, rows=20, columns=20, tile=(512, 512))
        _assert_too_large(data, 9984, 9984, _DEFAULT_MAX)

    def test_32_bit_descriptor_accepted(self):
        data = heic_grid(70000, 100, rows=1, columns=2, tile=(35000, 100))
        _validate(data, max_image_pixels=7_000_000)

    def test_descriptor_in_mdat_accepted(self):
        _validate(_grid_in_mdat())

    def test_descriptor_past_end_of_file_rejected(self):
        _assert_invalid(_grid_in_mdat(offset_shift=1))

    def test_version_2_iloc_with_base_offset_accepted(self):
        body = b"\x44\x44" + struct.pack(">I", 1)
        body += struct.pack(">IHHIH", 1, 1, 0, 2, 1)
        body += struct.pack(">III", 0, 2, len(_DESCRIPTOR))
        iloc = heif_full_box(b"iloc", body, version=2)
        idat = heif_box(b"idat", b"\x00" * 4 + _DESCRIPTOR)
        _validate(_grid(iloc=iloc, idat=idat))

    def test_descriptor_split_across_extents_accepted(self):
        iloc = heif_iloc([(1, 1, [(0, 4), (4, len(_DESCRIPTOR) - 4)])])
        _validate(_grid(iloc=iloc))

    def test_other_items_in_iloc_skipped(self):
        iloc = heif_iloc(
            [(2, 0, [(0, 16), (16, 16)]), (1, 1, [(0, len(_DESCRIPTOR))])]
        )
        _validate(_grid(iloc=iloc))

    def test_output_larger_than_ispe_rejected(self):
        data = heic_grid(
            4032,
            3024,
            rows=6,
            columns=8,
            tile=(512, 512),
            grid_size=(60000, 60000),
        )
        _assert_invalid(data)

    def test_output_smaller_than_ispe_rejected(self):
        idat = heif_box(b"idat", heif_grid_descriptor(1, 1, 64, 47))
        _assert_invalid(_grid(idat=idat))

    def test_tile_over_limit_rejected(self):
        data = heic_grid(100, 100, rows=1, columns=1, tile=(512, 512))
        _assert_too_large(data, 512, 512, max_image_pixels=10_000)

    @pytest.mark.parametrize(
        ("rows", "columns", "tile"),
        [
            (6, 8, (256, 512)),
            (6, 8, (512, 256)),
            (6, 9, (512, 512)),
            (7, 8, (512, 512)),
        ],
        ids=["too-narrow", "too-short", "extra-column", "extra-row"],
    )
    def test_tiles_not_covering_grid_exactly_rejected(
        self, rows, columns, tile
    ):
        data = heic_grid(4032, 3024, rows=rows, columns=columns, tile=tile)
        _assert_invalid(data)

    def test_tile_count_mismatch_rejected(self):
        idat = heif_box(b"idat", heif_grid_descriptor(2, 1, 64, 48))
        _assert_invalid(_grid(idat=idat))

    def test_tile_not_hevc_rejected(self):
        iinf = heif_iinf([heif_infe(1, b"grid"), heif_infe(2, b"grid")])
        _assert_invalid(_grid(iinf=iinf))

    def test_tile_without_ispe_rejected(self):
        iprp = heif_iprp([heif_ispe(64, 48)], heif_ipma([(1, (1,))]))
        _assert_invalid(_grid(iprp=iprp))

    def test_tiles_of_different_sizes_rejected(self):
        descriptor = heif_grid_descriptor(1, 2, 64, 48)
        iinf = heif_iinf(
            [
                heif_infe(1, b"grid"),
                heif_infe(2, b"hvc1"),
                heif_infe(3, b"hvc1"),
            ]
        )
        iprp = heif_iprp(
            [heif_ispe(64, 48), heif_ispe(32, 48), heif_ispe(40, 48)],
            heif_ipma([(1, (1,)), (2, (2,)), (3, (3,))]),
        )
        _assert_invalid(
            _grid(
                iloc=heif_iloc([(1, 1, [(0, len(descriptor))])]),
                iinf=iinf,
                iref=heif_dimg(1, [2, 3]),
                iprp=iprp,
                idat=heif_box(b"idat", descriptor),
            )
        )

    @pytest.mark.parametrize(
        "descriptor",
        [
            b"\x01" + _DESCRIPTOR[1:],
            b"\x00\x02" + _DESCRIPTOR[2:],
            _DESCRIPTOR + b"\x00",
            _DESCRIPTOR[:6],
            b"\x00\x01" + _DESCRIPTOR[2:],
        ],
        ids=[
            "version",
            "unknown-flag",
            "trailing-byte",
            "truncated",
            "32-bit-flag-short",
        ],
    )
    def test_malformed_descriptor_rejected(self, descriptor):
        _assert_invalid(
            _grid(
                iloc=heif_iloc([(1, 1, [(0, len(descriptor))])]),
                idat=heif_box(b"idat", descriptor),
            )
        )

    def test_descriptor_over_maximum_size_rejected(self):
        idat = heif_box(b"idat", _DESCRIPTOR + b"\x00" * 8)
        _assert_invalid(_grid(iloc=heif_iloc([(1, 1, [(0, 16)])]), idat=idat))

    @pytest.mark.parametrize(
        "iloc",
        [
            heif_iloc([(2, 1, [(0, 8)])]),
            heif_iloc([(1, 1, [(0, 8)]), (1, 1, [(0, 8)])]),
            heif_iloc([(1, 2, [(0, 8)])]),
            heif_iloc([(1, 1, [(0, 0)])]),
            heif_iloc([(1, 1, [(1, 8)])]),
            heif_full_box(
                b"iloc",
                b"\x44\x00\x00\x01"
                + struct.pack(">HHHH", 1, 1, 1, 1)
                + struct.pack(">II", 0, 8),
                version=1,
            ),
            heif_full_box(b"iloc", b"\x34\x00\x00\x00", version=1),
            heif_full_box(b"iloc", b"\x44\x00\x00\x00", version=3),
            heif_full_box(b"iloc", b"\x44\x00\x00\x01", version=1),
        ],
        ids=[
            "no-entry",
            "duplicate-entry",
            "item-offset-method",
            "zero-length",
            "past-idat",
            "external-data",
            "field-size",
            "version",
            "truncated",
        ],
    )
    def test_invalid_location_rejected(self, iloc):
        _assert_invalid(_grid(iloc=iloc))

    def test_descriptor_in_idat_without_idat_rejected(self):
        _assert_invalid(_grid(idat=b""))

    @pytest.mark.parametrize(
        "iref",
        [
            b"",
            heif_full_box(
                b"iref", heif_box(b"thmb", b"\x00\x02\x00\x01\x00\x01")
            ),
            heif_dimg(2, [1]),
            heif_full_box(
                b"iref",
                heif_box(b"dimg", b"\x00\x01\x00\x01\x00\x02") * 2,
            ),
            heif_full_box(b"iref", b"", version=2),
        ],
        ids=["missing", "no-dimg", "other-item", "duplicate", "version"],
    )
    def test_invalid_tile_references_rejected(self, iref):
        _assert_invalid(_grid(iref=iref))

    def test_version_1_iref_accepted(self):
        ref = heif_box(b"dimg", struct.pack(">IHI", 1, 1, 2))
        _validate(_grid(iref=heif_full_box(b"iref", ref, version=1)))


class TestUnknownFormat:
    """Content that is not PNG, JPEG, WebP or HEIC is rejected."""

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
