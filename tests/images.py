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


def jpeg_frame(width: int = 1, height: int = 1, marker: int = 0xC0) -> bytes:
    """
    Build a one-component JPEG frame header (SOF) segment.

    Args:
        width: Frame width.
        height: Frame height.
        marker: SOF marker byte (0xC0 is baseline).

    Returns:
        The frame header segment.
    """
    return jpeg_segment(
        marker, struct.pack(">BHHB", 8, height, width, 1) + b"\x01\x11\x00"
    )


# Scan header for the one component of ``jpeg_frame``
JPEG_SOS = jpeg_segment(0xDA, b"\x01\x01\x00\x00\x3f\x00")


def jpeg(
    width: int = 1,
    height: int = 1,
    *,
    before_frame: bytes = b"",
    body: bytes = b"",
    frame_marker: int = 0xC0,
) -> bytes:
    """
    Build a JPEG header with one frame header (SOF) and a scan.

    Args:
        width: Frame width in the SOF segment.
        height: Frame height in the SOF segment.
        before_frame: Raw bytes placed between APP0 and the SOF.
        body: Raw bytes placed after the scan header, before EOI.
        frame_marker: SOF marker byte (0xC0 is baseline).

    Returns:
        SOI, APP0, ``before_frame``, SOF, SOS, ``body`` and EOI.
    """
    frame = jpeg_frame(width, height, frame_marker)
    return JPEG_PREFIX + before_frame + frame + JPEG_SOS + body + JPEG_EOI


# Offset of the MPF TIFF header in a JPEG whose MPF segment
# directly follows ``JPEG_PREFIX``: marker, length and "MPF\0"
MPF_TIFF_START = len(JPEG_PREFIX) + 8


def mpf_segment(
    tags: list[tuple[int, int, int, bytes]], *, order: str = ">"
) -> bytes:
    """
    Build an APP2 MPF segment holding one TIFF IFD.

    Values longer than 4 bytes are placed after the IFD and the
    entry holds their offset from the TIFF header.

    Args:
        tags: Tag, type, count and value bytes of each entry.
        order: Byte order, ``">"`` (MM) or ``"<"`` (II).

    Returns:
        The APP2 segment.
    """
    header = b"MM\x00\x2a" if order == ">" else b"II\x2a\x00"
    header += struct.pack(order + "I", 8)
    data_at = 8 + 2 + 12 * len(tags) + 4
    entries, values = b"", b""
    for tag, kind, count, value in tags:
        if len(value) > 4:
            field = struct.pack(order + "I", data_at + len(values))
            values += value
        else:
            field = value.ljust(4, b"\x00")
        entries += struct.pack(order + "HHI", tag, kind, count) + field
    ifd = struct.pack(order + "H", len(tags)) + entries + b"\x00" * 4
    return jpeg_segment(0xE2, b"MPF\x00" + header + ifd + values)


def mpf_tags(
    images: list[tuple[int, int]], *, order: str = ">"
) -> list[tuple[int, int, int, bytes]]:
    """
    Build the MP Index IFD entries listing the given images.

    Args:
        images: Size and data offset of each image.
        order: Byte order, ``">"`` or ``"<"``.

    Returns:
        Version (0xB000), number of images (0xB001) and MP Entry
        (0xB002) tags.
    """
    entries = b"".join(
        struct.pack(order + "IIIHH", 0, size, offset, 0, 0)
        for size, offset in images
    )
    return [
        (0xB000, 7, 4, b"0100"),
        (0xB001, 4, 1, struct.pack(order + "I", len(images))),
        (0xB002, 7, len(entries), entries),
    ]


def mpo(
    *frames: bytes, width: int = 1, height: int = 1, order: str = ">"
) -> bytes:
    """
    Build a multi-picture JPEG whose MPF index lists every image.

    Args:
        frames: Images appended after the primary image.
        width: Primary image width.
        height: Primary image height.
        order: MPF byte order, ``">"`` or ``"<"``.

    Returns:
        The primary image, with its MPF segment, and ``frames``.
    """
    count = 1 + len(frames)
    placeholder = mpf_segment(mpf_tags([(0, 0)] * count, order=order))
    offset = len(jpeg(width, height, before_frame=placeholder))
    images = [(offset, 0)]
    for frame in frames:
        images.append((len(frame), offset - MPF_TIFF_START))
        offset += len(frame)
    segment = mpf_segment(mpf_tags(images, order=order), order=order)
    return jpeg(width, height, before_frame=segment) + b"".join(frames)


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


def png(
    width: int = 1,
    height: int = 1,
    *,
    before_data: bytes = b"",
    body: bytes = b"",
) -> bytes:
    """
    Build a PNG with an IHDR chunk and one IDAT chunk.

    Args:
        width: Width in the IHDR chunk.
        height: Height in the IHDR chunk.
        before_data: Raw bytes placed between IHDR and IDAT.
        body: Raw bytes placed after IDAT, before IEND.

    Returns:
        Signature, IHDR, ``before_data``, IDAT, ``body`` and IEND.
    """
    return (
        PNG_SIGNATURE
        + png_ihdr(width, height)
        + before_data
        + _PNG_IDAT
        + body
        + png_chunk(b"IEND", b"")
    )


def png_ihdr(width: int = 1, height: int = 1) -> bytes:
    """
    Build an 8-bit RGB IHDR chunk.

    Args:
        width: Image width.
        height: Image height.

    Returns:
        The IHDR chunk.
    """
    return png_chunk(
        b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    )


# Stands in for compressed pixel data, which the checks never read
_PNG_IDAT = png_chunk(b"IDAT", zlib.compress(b"\x00" * 4))


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


def heif_box(kind: bytes, payload: bytes) -> bytes:
    """
    Build one ISOBMFF box with a 32-bit size.

    Args:
        kind: Four-byte box type.
        payload: Box payload.

    Returns:
        Size, type and payload.
    """
    return struct.pack(">I", 8 + len(payload)) + kind + payload


def heif_full_box(
    kind: bytes, payload: bytes, *, version: int = 0, flags: int = 0
) -> bytes:
    """
    Build one ISOBMFF full box.

    Args:
        kind: Four-byte box type.
        payload: Payload after the version and flags.
        version: Box version.
        flags: 24-bit box flags.

    Returns:
        The box.
    """
    return heif_box(
        kind, bytes((version,)) + flags.to_bytes(3, "big") + payload
    )


def heif_ftyp(
    major: bytes = b"heic", compatible: tuple[bytes, ...] = (b"mif1", b"heic")
) -> bytes:
    """
    Build a file type box.

    Args:
        major: Major brand.
        compatible: Compatible brands.

    Returns:
        The ftyp box.
    """
    return heif_box(
        b"ftyp", major + b"\x00\x00\x00\x00" + b"".join(compatible)
    )


def heif_infe(item_id: int, item_type: bytes, *, protection: int = 0) -> bytes:
    """
    Build a version 2 item info entry.

    Args:
        item_id: Item ID.
        item_type: Four-byte item type.
        protection: Item protection index (0 when unprotected).

    Returns:
        The infe box.
    """
    return heif_full_box(
        b"infe",
        struct.pack(">HH", item_id, protection) + item_type + b"\x00",
        version=2,
    )


def heif_iinf(entries: list[bytes], *, count: int | None = None) -> bytes:
    """
    Build an item info box.

    Args:
        entries: infe boxes.
        count: Declared entry count; ``len(entries)`` when omitted.

    Returns:
        The iinf box.
    """
    declared = len(entries) if count is None else count
    return heif_full_box(
        b"iinf", struct.pack(">H", declared) + b"".join(entries)
    )


def heif_ispe(width: int, height: int) -> bytes:
    """
    Build an image spatial extents property.

    Args:
        width: Image width.
        height: Image height.

    Returns:
        The ispe box.
    """
    return heif_full_box(b"ispe", struct.pack(">II", width, height))


def heif_ipma(associations: list[tuple[int, tuple[int, ...]]]) -> bytes:
    """
    Build a version 0 property association box with 8-bit indices.

    Args:
        associations: Item ID and its 1-based ipco property indices.

    Returns:
        The ipma box.
    """
    body = struct.pack(">I", len(associations))
    for item_id, indices in associations:
        body += struct.pack(">HB", item_id, len(indices)) + bytes(indices)
    return heif_full_box(b"ipma", body)


def heif_iprp(properties: list[bytes], ipma: bytes) -> bytes:
    """
    Build an item properties box.

    Args:
        properties: Property boxes placed in ipco, in index order.
        ipma: The ipma box.

    Returns:
        The iprp box.
    """
    return heif_box(b"iprp", heif_box(b"ipco", b"".join(properties)) + ipma)


def heif_iloc(items: list[tuple[int, int, list[tuple[int, int]]]]) -> bytes:
    """
    Build a version 1 item location box with 32-bit fields.

    Args:
        items: Item ID, construction method and (offset, length)
            extents of each item.

    Returns:
        The iloc box.
    """
    body = b"\x44\x00" + struct.pack(">H", len(items))
    for item_id, method, extents in items:
        body += struct.pack(">HHHH", item_id, method, 0, len(extents))
        for offset, length in extents:
            body += struct.pack(">II", offset, length)
    return heif_full_box(b"iloc", body, version=1)


def heif_dimg(from_id: int, to_ids: list[int]) -> bytes:
    """
    Build a version 0 item reference box with one dimg reference.

    Args:
        from_id: Derived item ID (the grid).
        to_ids: Input item IDs (the tiles), in grid order.

    Returns:
        The iref box.
    """
    ref = struct.pack(">HH", from_id, len(to_ids))
    ref += b"".join(struct.pack(">H", i) for i in to_ids)
    return heif_full_box(b"iref", heif_box(b"dimg", ref))


def heif_grid_descriptor(
    rows: int, columns: int, width: int, height: int
) -> bytes:
    """
    Build an ImageGrid descriptor, 32-bit fields above 65535.

    Args:
        rows: Tile rows, 1 to 256.
        columns: Tile columns, 1 to 256.
        width: Output width.
        height: Output height.

    Returns:
        Version, flags, rows, columns and output size.
    """
    if width > 0xFFFF or height > 0xFFFF:
        return struct.pack(
            ">BBBBII", 0, 1, rows - 1, columns - 1, width, height
        )
    return struct.pack(">BBBBHH", 0, 0, rows - 1, columns - 1, width, height)


def heif_meta(
    children: list[bytes], *, handler: bytes = b"pict", primary: int = 1
) -> bytes:
    """
    Build a meta box with hdlr and pitm before ``children``.

    Args:
        children: Remaining meta child boxes.
        handler: Handler type in hdlr.
        primary: Primary item ID in pitm.

    Returns:
        The meta box.
    """
    hdlr = heif_full_box(b"hdlr", b"\x00" * 4 + handler + b"\x00" * 13)
    pitm = heif_full_box(b"pitm", struct.pack(">H", primary))
    return heif_full_box(b"meta", hdlr + pitm + b"".join(children))


def heif_file(meta: bytes, *, ftyp: bytes | None = None) -> bytes:
    """
    Place a meta box between ftyp and a small mdat.

    Args:
        meta: The meta box.
        ftyp: File type box; a HEIC one when omitted.

    Returns:
        The file.
    """
    return (heif_ftyp() if ftyp is None else ftyp) + meta + _HEIF_MDAT


# Stands in for coded image data, which the checks never read
_HEIF_MDAT = heif_box(b"mdat", b"\x00" * 16)


def heic(width: int = 1, height: int = 1) -> bytes:
    """
    Build a HEIC holding one HEVC image item.

    Args:
        width: Image width in ispe.
        height: Image height in ispe.

    Returns:
        The file.
    """
    return heif_file(
        heif_meta(
            [
                heif_iloc([(1, 0, [(0, 16)])]),
                heif_iinf([heif_infe(1, b"hvc1")]),
                heif_iprp([heif_ispe(width, height)], heif_ipma([(1, (1,))])),
            ]
        )
    )


def heic_grid(
    width: int,
    height: int,
    *,
    rows: int,
    columns: int,
    tile: tuple[int, int],
    grid_size: tuple[int, int] | None = None,
) -> bytes:
    """
    Build a HEIC whose primary item is a grid of HEVC tiles.

    Item 1 is the grid, items 2 onward its tiles; the grid
    descriptor is stored in idat.

    Args:
        width: Grid width in its ispe.
        height: Grid height in its ispe.
        rows: Tile rows.
        columns: Tile columns.
        tile: Width and height in every tile's ispe.
        grid_size: Output size in the grid descriptor; the ispe
            size when omitted.

    Returns:
        The file.
    """
    out_width, out_height = grid_size or (width, height)
    descriptor = heif_grid_descriptor(rows, columns, out_width, out_height)
    tiles = list(range(2, 2 + rows * columns))
    return heif_file(
        heif_meta(
            [
                heif_iloc(
                    [(1, 1, [(0, len(descriptor))])]
                    + [(t, 0, [(0, 16)]) for t in tiles]
                ),
                heif_iinf(
                    [heif_infe(1, b"grid")]
                    + [heif_infe(t, b"hvc1") for t in tiles]
                ),
                heif_dimg(1, tiles),
                heif_iprp(
                    [heif_ispe(width, height), heif_ispe(*tile)],
                    heif_ipma([(1, (1,))] + [(t, (2,)) for t in tiles]),
                ),
                heif_box(b"idat", descriptor),
            ]
        )
    )
