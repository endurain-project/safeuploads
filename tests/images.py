"""In-memory builders for image headers used across the tests."""

import struct
import zlib

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

# JPEG start of image followed by a JFIF APP0 segment
JPEG_PREFIX = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
)
JPEG_EOI = b"\xff\xd9"


def jpeg_segment(marker: int, payload: bytes) -> bytes:
    """
    Build one JPEG marker segment with its length field.

    Args:
        marker: Marker byte following 0xFF.
        payload: Segment payload after the length field.

    Returns:
        Marker, big-endian length and payload.
    """
    return (
        bytes((0xFF, marker)) + struct.pack(">H", len(payload) + 2) + payload
    )


def jpeg(
    width: int = 1,
    height: int = 1,
    *,
    before_frame: bytes = b"",
    body: bytes = b"",
    frame_marker: int = 0xC0,
) -> bytes:
    """
    Build a JPEG header with one frame header (SOF).

    Args:
        width: Frame width in the SOF segment.
        height: Frame height in the SOF segment.
        before_frame: Raw bytes placed between APP0 and the SOF.
        body: Raw bytes placed after the SOF, before EOI.
        frame_marker: SOF marker byte (0xC0 is baseline).

    Returns:
        SOI, APP0, ``before_frame``, SOF, ``body`` and EOI.
    """
    frame = jpeg_segment(
        frame_marker,
        struct.pack(">BHHB", 8, height, width, 1) + b"\x01\x11\x00",
    )
    return JPEG_PREFIX + before_frame + frame + body + JPEG_EOI


def png_chunk(kind: bytes, data: bytes) -> bytes:
    """
    Build one PNG chunk with a valid CRC.

    Args:
        kind: Four-byte chunk type.
        data: Chunk data.

    Returns:
        Length, type, data and CRC.
    """
    crc = zlib.crc32(kind + data)
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)


def png(width: int = 1, height: int = 1, *, body: bytes = b"") -> bytes:
    """
    Build a PNG with an IHDR chunk.

    Args:
        width: Width in the IHDR chunk.
        height: Height in the IHDR chunk.
        body: Raw bytes placed after IHDR, before IEND.

    Returns:
        Signature, IHDR, ``body`` and IEND.
    """
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        PNG_SIGNATURE
        + png_chunk(b"IHDR", ihdr)
        + body
        + png_chunk(b"IEND", b"")
    )


def riff_webp(chunks: bytes) -> bytes:
    """
    Wrap WebP chunks in a RIFF container.

    Args:
        chunks: Chunk bytes following the WEBP form type.

    Returns:
        RIFF header, WEBP form type and ``chunks``.
    """
    return b"RIFF" + struct.pack("<I", 4 + len(chunks)) + b"WEBP" + chunks


def webp_chunk(kind: bytes, payload: bytes) -> bytes:
    """
    Build one RIFF chunk, padded to an even size.

    Args:
        kind: Four-byte chunk FourCC.
        payload: Chunk payload.

    Returns:
        FourCC, little-endian size, payload and padding.
    """
    pad = b"\x00" if len(payload) % 2 else b""
    return kind + struct.pack("<I", len(payload)) + payload + pad


def vp8l_chunk(width: int = 1, height: int = 1) -> bytes:
    """
    Build a lossless VP8L chunk header for the given size.

    Args:
        width: Image width, 1 to 16384.
        height: Image height, 1 to 16384.

    Returns:
        The VP8L chunk.
    """
    bits = (width - 1) | (height - 1) << 14 | 1 << 28
    return webp_chunk(
        b"VP8L", b"\x2f" + struct.pack("<I", bits) + b"\x07\x10\x11\x11"
    )


def vp8_chunk(width: int = 1, height: int = 1) -> bytes:
    """
    Build a lossy VP8 key frame header for the given size.

    Args:
        width: Image width, 0 to 16383.
        height: Image height, 0 to 16383.

    Returns:
        The VP8 chunk.
    """
    # Frame tag: key frame, version 0, shown, partition size 0
    tag = b"\x10\x00\x00"
    return webp_chunk(
        b"VP8 ",
        tag + b"\x9d\x01\x2a" + struct.pack("<HH", width, height) + b"\x00",
    )


def vp8x_chunk(width: int = 1, height: int = 1) -> bytes:
    """
    Build an extended-format VP8X chunk for the given canvas.

    Args:
        width: Canvas width, 1 to 2**24.
        height: Canvas height, 1 to 2**24.

    Returns:
        The VP8X chunk.
    """
    canvas = (width - 1).to_bytes(3, "little") + (height - 1).to_bytes(
        3, "little"
    )
    return webp_chunk(b"VP8X", b"\x00\x00\x00\x00" + canvas)


def webp(width: int = 1, height: int = 1, *, body: bytes = b"") -> bytes:
    """
    Build a lossless WebP of the given size.

    Args:
        width: Image width, 1 to 16384.
        height: Image height, 1 to 16384.
        body: Raw bytes appended after the VP8L chunk.

    Returns:
        A RIFF container holding one VP8L chunk and ``body``.
    """
    return riff_webp(vp8l_chunk(width, height) + body)
