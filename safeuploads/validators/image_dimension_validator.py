"""Header-only dimension check for PNG, JPEG, WebP and HEIC images."""

from __future__ import annotations

import logging
import struct
from typing import TYPE_CHECKING

from ..exceptions import ErrorCode, FileSignatureError, ImageDimensionError
from ..utils import check_resource_limits
from .base import BaseValidator

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from ..config import FileSecurityConfig
    from ..protocols import SeekableFile


logger = logging.getLogger(__name__)

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
# The first chunk must be IHDR with 13 bytes of data
_PNG_IHDR = b"\x00\x00\x00\x0dIHDR"
# PNG width and height are at most 2**31 - 1
_PNG_MAX_DIMENSION = 2**31 - 1

_JPEG_SOI = b"\xff\xd8"
# Start-of-frame markers; 0xC4 (DHT), 0xC8 (JPG) and 0xCC (DAC)
# share the range but carry no frame
_JPEG_SOF = frozenset(range(0xC0, 0xD0)) - {0xC4, 0xC8, 0xCC}
_JPEG_SOS = 0xDA
_JPEG_EOI = 0xD9
# Byte values after 0xFF that have no length field: 0x00 (stuffed
# byte, not a marker), TEM, RST0-RST7 and SOI
_JPEG_STANDALONE = frozenset({0x00, 0x01, *range(0xD0, 0xD9)})
# Frame header length for one component (8 + 3 per component)
_JPEG_MIN_FRAME_LENGTH = 11

# RIFF header (12) + chunk header (8) + the largest dimension
# field read from a chunk (VP8 and VP8X, 10)
_WEBP_HEADER_SIZE = 30
_VP8_START_CODE = b"\x9d\x01\x2a"
_VP8L_SIGNATURE = 0x2F

# HEIF (ISO/IEC 23008-12) meta boxes the check reads; each may
# appear once
_HEIF_META_BOXES = frozenset(
    {b"hdlr", b"pitm", b"iloc", b"iinf", b"iprp", b"iref", b"idat"}
)
_HEIF_REQUIRED_BOXES = (b"hdlr", b"pitm", b"iloc", b"iinf", b"iprp")
_HEIF_HEVC_ITEM = b"hvc1"
_HEIF_GRID_ITEM = b"grid"
# ImageGrid descriptor: version, flags, rows - 1 and columns - 1,
# then the output size in 16-bit fields, or 32-bit fields when
# flag bit 0 is set
_HEIF_GRID_WIDE_FIELDS = 0x01
_HEIF_GRID_MAX_SIZE = 12
_HEIF_ILOC_FIELD_SIZES = frozenset({0, 4, 8})


class ImageDimensionValidator(BaseValidator):
    """
    Rejects images whose header declares too many pixels.

    Width and height are read from the PNG IHDR chunk, the first
    JPEG frame header (SOF), the first WebP chunk (VP8, VP8L or
    VP8X canvas) or the HEIC primary item's ispe property, after
    every ispe property in the file is checked and, for a grid,
    its descriptor and tiles are matched to it. No pixel data is
    decoded. A small file can declare a huge image that exhausts
    memory when decoded, so the pixel count is bounded before a
    host decodes the upload.

    Attributes:
        config: Security configuration with ``max_image_pixels``.
    """

    def __init__(self, config: FileSecurityConfig):
        """
        Initialize the image dimension validator.

        Args:
            config: Security configuration with image limits.
        """
        super().__init__(config)

    def validate(
        self, file_obj: SeekableFile, *, filename: str | None = None
    ) -> None:
        """
        Check the pixel count an image header declares.

        The format is taken from the leading bytes; content that is
        not PNG, JPEG, WebP or HEIC is rejected.

        Args:
            file_obj: Seekable file containing the image.
            filename: Optional sanitized filename for error context.

        Raises:
            FileSignatureError: If the format is not PNG, JPEG,
                WebP or HEIC, or its dimension header or HEIF item
                structure is missing, truncated or invalid
                (IMAGE_INVALID_STRUCTURE).
            ImageDimensionError: If width times height exceeds
                ``limits.max_image_pixels``, for a HEIC that of any
                ispe property.
            ResourceLimitError: If the active resource monitor's
                time or memory limit is exceeded.
        """
        file_obj.seek(0)
        head = file_obj.read(_WEBP_HEADER_SIZE)
        if head.startswith(_PNG_SIGNATURE):
            width, height = self._png_dimensions(head, filename)
        elif head.startswith(_JPEG_SOI):
            width, height = self._jpeg_dimensions(file_obj, filename)
        elif head[:4] == b"RIFF" and head[8:12] == b"WEBP":
            width, height = self._webp_dimensions(head, filename)
        elif head[4:8] == b"ftyp":
            width, height = _heif_dimensions(
                file_obj,
                filename,
                lambda w, h: self._check_pixels(w, h, filename),
            )
        else:
            raise _invalid("Unsupported image format", filename)
        file_obj.seek(0)
        self._check_pixels(width, height, filename)

    def _check_pixels(
        self, width: int, height: int, filename: str | None
    ) -> None:
        """
        Reject a size whose pixel count exceeds the limit.

        Args:
            width: Declared width.
            height: Declared height.
            filename: Optional sanitized filename for error context.

        Raises:
            ImageDimensionError: If width times height exceeds
                ``limits.max_image_pixels``.
        """
        max_pixels = self.config.limits.max_image_pixels
        if width * height > max_pixels:
            logger.warning(
                "Image dimensions exceed limit: %sx%s", width, height
            )
            raise ImageDimensionError(
                (
                    f"Image is {width}x{height} pixels, more than the"
                    f" maximum of {max_pixels} pixels"
                ),
                filename=filename,
                width=width,
                height=height,
                max_pixels=max_pixels,
            )

    @staticmethod
    def _png_dimensions(head: bytes, filename: str | None) -> tuple[int, int]:
        """
        Read width and height from the PNG IHDR chunk.

        Args:
            head: Leading bytes of the file.
            filename: Optional sanitized filename for error context.

        Returns:
            Width and height.

        Raises:
            FileSignatureError: If IHDR is missing or invalid.
        """
        if len(head) < 24 or head[8:16] != _PNG_IHDR:
            raise _invalid("PNG does not start with an IHDR chunk", filename)
        width, height = struct.unpack_from(">II", head, 16)
        if not (
            0 < width <= _PNG_MAX_DIMENSION
            and 0 < height <= _PNG_MAX_DIMENSION
        ):
            raise _invalid("PNG dimensions are invalid", filename)
        return width, height

    def _jpeg_dimensions(
        self, file_obj: SeekableFile, filename: str | None
    ) -> tuple[int, int]:
        """
        Walk the JPEG marker segments to the first frame header.

        Each segment before the frame is skipped by its length
        without reading its payload, so EXIF, ICC and other
        segments of any size cost one seek each.

        Args:
            file_obj: Seekable file positioned anywhere.
            filename: Optional sanitized filename for error context.

        Returns:
            Width and height from the frame header.

        Raises:
            FileSignatureError: If the segments are malformed or
                end before a frame header.
            ResourceLimitError: If a resource limit is exceeded.
        """
        end = file_obj.seek(0, 2)
        pos = len(_JPEG_SOI)
        while True:
            check_resource_limits()
            marker, pos = self._jpeg_marker(file_obj, pos, filename)
            if marker in _JPEG_SOF:
                return self._jpeg_frame(file_obj, pos, filename)
            if marker in (_JPEG_SOS, _JPEG_EOI):
                raise _invalid(
                    "JPEG has no frame header before its image data",
                    filename,
                )
            if marker in _JPEG_STANDALONE:
                raise _invalid(
                    "Unexpected JPEG marker before the frame header",
                    filename,
                )
            file_obj.seek(pos)
            field = file_obj.read(2)
            if len(field) < 2:
                raise _invalid("Truncated JPEG segment", filename)
            (length,) = struct.unpack(">H", field)
            if length < 2:
                raise _invalid("Invalid JPEG segment length", filename)
            pos += length
            if pos > end:
                raise _invalid("Truncated JPEG segment", filename)

    def _jpeg_marker(
        self, file_obj: SeekableFile, pos: int, filename: str | None
    ) -> tuple[int, int]:
        """
        Read the marker at ``pos``, skipping 0xFF fill bytes.

        Args:
            file_obj: Seekable file containing the JPEG.
            pos: Offset where a marker must start.
            filename: Optional sanitized filename for error context.

        Returns:
            The marker byte and the offset just past it.

        Raises:
            FileSignatureError: If no marker starts at ``pos`` or
                the file ends before one.
            ResourceLimitError: If a resource limit is exceeded.
        """
        file_obj.seek(pos)
        pair = file_obj.read(2)
        if len(pair) < 2:
            raise _invalid("JPEG ends before the frame header", filename)
        if pair[0] != 0xFF:
            raise _invalid(
                "JPEG segment does not start with a marker", filename
            )
        pos += 1
        if pair[1] != 0xFF:
            return pair[1], pos + 1

        # Any number of 0xFF fill bytes may precede a marker; skip
        # the run a chunk at a time.
        chunk_size = self.config.limits.chunk_size
        file_obj.seek(pos)
        while True:
            chunk = file_obj.read(chunk_size)
            if not chunk:
                raise _invalid("JPEG ends before the frame header", filename)
            rest = chunk.lstrip(b"\xff")
            pos += len(chunk) - len(rest)
            if rest:
                return rest[0], pos + 1
            check_resource_limits()

    @staticmethod
    def _jpeg_frame(
        file_obj: SeekableFile, pos: int, filename: str | None
    ) -> tuple[int, int]:
        """
        Read width and height from a JPEG frame header.

        Args:
            file_obj: Seekable file containing the JPEG.
            pos: Offset just past the SOF marker.
            filename: Optional sanitized filename for error context.

        Returns:
            Width and height.

        Raises:
            FileSignatureError: If the frame header is truncated or
                declares a zero dimension.
        """
        file_obj.seek(pos)
        frame = file_obj.read(7)
        if len(frame) < 7:
            raise _invalid("Truncated JPEG frame header", filename)
        length, _precision, height, width = struct.unpack(">HBHH", frame)
        if length < _JPEG_MIN_FRAME_LENGTH:
            raise _invalid("Invalid JPEG frame header length", filename)
        # A zero height is deferred to a DNL segment after the first
        # scan; it is rejected rather than searched for.
        if not width or not height:
            raise _invalid("JPEG dimensions are invalid", filename)
        return width, height

    @staticmethod
    def _webp_dimensions(head: bytes, filename: str | None) -> tuple[int, int]:
        """
        Read width and height from the first WebP chunk.

        Args:
            head: Leading bytes of the file.
            filename: Optional sanitized filename for error context.

        Returns:
            Width and height; the canvas size for VP8X.

        Raises:
            FileSignatureError: If the first chunk is not VP8, VP8L
                or VP8X, or its header is truncated or invalid.
        """
        chunk = head[12:16]
        if chunk == b"VP8 ":
            # Frame tag bit 0 is 0 for a key frame, which carries
            # the dimensions after the start code
            if (
                len(head) < 30
                or head[20] & 0x01
                or head[23:26] != _VP8_START_CODE
            ):
                raise _invalid("Invalid WebP VP8 header", filename)
            width, height = struct.unpack_from("<HH", head, 26)
            # The top two bits of each field are an upscaling hint
            width &= 0x3FFF
            height &= 0x3FFF
            if not width or not height:
                raise _invalid("WebP dimensions are invalid", filename)
            return width, height
        if chunk == b"VP8L":
            if len(head) < 25 or head[20] != _VP8L_SIGNATURE:
                raise _invalid("Invalid WebP VP8L header", filename)
            (bits,) = struct.unpack_from("<I", head, 21)
            if bits >> 29:
                raise _invalid("Unsupported WebP VP8L version", filename)
            return (bits & 0x3FFF) + 1, (bits >> 14 & 0x3FFF) + 1
        if chunk == b"VP8X":
            if len(head) < 30:
                raise _invalid("Invalid WebP VP8X header", filename)
            width = int.from_bytes(head[24:27], "little") + 1
            height = int.from_bytes(head[27:30], "little") + 1
            return width, height
        raise _invalid("WebP has no image header chunk", filename)


def _heif_dimensions(
    file_obj: SeekableFile,
    filename: str | None,
    check_pixels: Callable[[int, int], None],
) -> tuple[int, int]:
    """
    Read the primary image size of a HEIC from its meta box.

    Args:
        file_obj: Seekable file containing the HEIF.
        filename: Optional sanitized filename for error context.
        check_pixels: Called with the size in every ispe property.

    Returns:
        Width and height of the primary item.

    Raises:
        FileSignatureError: If the box or item structure is
            missing, truncated or invalid.
        ImageDimensionError: If ``check_pixels`` rejects a size.
        ResourceLimitError: If a resource limit is exceeded.
    """
    file_end = file_obj.seek(0, 2)
    start, end = _heif_meta_span(file_obj, file_end, filename)
    file_obj.seek(start)
    meta = _HeifMeta(file_obj.read(end - start), file_obj, file_end, filename)
    return meta.dimensions(check_pixels)


def _heif_meta_span(
    file_obj: SeekableFile, file_end: int, filename: str | None
) -> tuple[int, int]:
    """
    Walk the top-level boxes to the payload of the one meta box.

    Each box is skipped by its size without reading its payload.
    A size of 0 extends the box to the end of the file.

    Args:
        file_obj: Seekable file containing the HEIF.
        file_end: Size of the file.
        filename: Optional sanitized filename for error context.

    Returns:
        Start and end offsets of the meta box payload.

    Raises:
        FileSignatureError: If a box header is truncated, a box
            size is invalid, or there is not exactly one meta box.
        ResourceLimitError: If a resource limit is exceeded.
    """
    meta: tuple[int, int] | None = None
    pos = 0
    while pos < file_end:
        check_resource_limits()
        file_obj.seek(pos)
        header = file_obj.read(16)
        cursor = _Cursor(header, 0, len(header), filename)
        size = cursor.uint(4)
        kind = cursor.take(4)
        if size == 1:
            size = cursor.uint(8)
        elif size == 0:
            size = file_end - pos
        if size < cursor.pos or size > file_end - pos:
            raise _invalid("Invalid HEIF box size", filename)
        if kind == b"meta":
            if meta is not None:
                raise _invalid(
                    "HEIF file has more than one meta box", filename
                )
            meta = (pos + cursor.pos, pos + size)
        pos += size
    if meta is None:
        raise _invalid("HEIF file has no meta box", filename)
    return meta


def _heif_boxes(
    data: bytes, start: int, end: int, filename: str | None
) -> Iterator[tuple[bytes, int, int]]:
    """
    Yield each box in a span of an in-memory HEIF box payload.

    Args:
        data: Bytes holding the span.
        start: Offset of the first box.
        end: Offset just past the last box.
        filename: Optional sanitized filename for error context.

    Yields:
        Box type and the start and end offsets of its payload.

    Raises:
        FileSignatureError: If a box header is truncated or a box
            size is below its header or past the end of the span.
        ResourceLimitError: If a resource limit is exceeded.
    """
    pos = start
    while pos < end:
        check_resource_limits()
        cursor = _Cursor(data, pos, end, filename)
        size = cursor.uint(4)
        kind = cursor.take(4)
        if size == 1:
            size = cursor.uint(8)
        # A size of 0, valid only for a top-level box, is below the
        # header size and so rejected here.
        header = cursor.pos - pos
        if size < header or size > end - pos:
            raise _invalid("Invalid HEIF box size", filename)
        yield kind, cursor.pos, pos + size
        pos += size


def _heif_children(
    data: bytes,
    start: int,
    end: int,
    kinds: frozenset[bytes],
    filename: str | None,
) -> dict[bytes, tuple[int, int]]:
    """
    Find the payload span of each box of the given types.

    Args:
        data: Bytes holding the span.
        start: Offset of the first box.
        end: Offset just past the last box.
        kinds: Box types to find; other boxes are skipped.
        filename: Optional sanitized filename for error context.

    Returns:
        Payload start and end offsets by box type.

    Raises:
        FileSignatureError: If a box is malformed or one of
            ``kinds`` appears more than once.
        ResourceLimitError: If a resource limit is exceeded.
    """
    found: dict[bytes, tuple[int, int]] = {}
    for kind, child_start, child_end in _heif_boxes(
        data, start, end, filename
    ):
        if kind in kinds:
            if kind in found:
                raise _invalid(
                    f"HEIF has more than one {kind.decode()} box", filename
                )
            found[kind] = (child_start, child_end)
    return found


class _Cursor:
    """
    Bounds-checked big-endian reader over a span of bytes.

    Attributes:
        pos: Offset of the next byte to read.
        end: Offset just past the span.
    """

    __slots__ = ("_data", "_filename", "end", "pos")

    def __init__(
        self, data: bytes, start: int, end: int, filename: str | None
    ) -> None:
        """
        Initialize the cursor at the start of the span.

        Args:
            data: Bytes holding the span.
            start: Offset of the span.
            end: Offset just past the span.
            filename: Optional sanitized filename for error context.
        """
        self._data = data
        self._filename = filename
        self.pos = start
        self.end = end

    @property
    def at_end(self) -> bool:
        """Whether every byte of the span has been read."""
        return self.pos == self.end

    def skip(self, size: int) -> None:
        """
        Move past ``size`` bytes.

        Raises:
            FileSignatureError: If the span ends first.
        """
        if size > self.end - self.pos:
            raise _invalid("Truncated HEIF box", self._filename)
        self.pos += size

    def take(self, size: int) -> bytes:
        """
        Read the next ``size`` bytes.

        Returns:
            The bytes.

        Raises:
            FileSignatureError: If the span ends first.
        """
        start = self.pos
        self.skip(size)
        return self._data[start : self.pos]

    def uint(self, size: int) -> int:
        """
        Read a big-endian unsigned integer of ``size`` bytes.

        Returns:
            The integer; 0 when ``size`` is 0.

        Raises:
            FileSignatureError: If the span ends first.
        """
        return int.from_bytes(self.take(size), "big")

    def full_box(
        self, versions: tuple[int, ...], kind: bytes
    ) -> tuple[int, int]:
        """
        Read the version and flags that open a full box.

        Args:
            versions: Versions the reader supports.
            kind: Box type, for the error message.

        Returns:
            Version and flags.

        Raises:
            FileSignatureError: If the span ends first or the
                version is not one of ``versions``.
        """
        version = self.uint(1)
        flags = self.uint(3)
        if version not in versions:
            raise _invalid(
                f"Unsupported HEIF {kind.decode()} box version",
                self._filename,
            )
        return version, flags


class _HeifMeta:
    """
    Item structure of a HEIF meta box held in memory.

    The meta box describes each image as an item: its type (iinf),
    its properties such as the ispe size (iprp), where its data is
    stored (iloc) and the items it is derived from (iref). The coded
    image data itself is never read.
    """

    def __init__(
        self,
        data: bytes,
        file_obj: SeekableFile,
        file_end: int,
        filename: str | None,
    ) -> None:
        """
        Index the child boxes of a meta box payload.

        Args:
            data: Payload of the meta box.
            file_obj: Seekable file containing the HEIF, for item
                data stored outside the meta box.
            file_end: Size of the file.
            filename: Optional sanitized filename for error context.

        Raises:
            FileSignatureError: If the meta box is malformed or
                lacks a box the check needs.
            ResourceLimitError: If a resource limit is exceeded.
        """
        self._data = data
        self._file_obj = file_obj
        self._file_end = file_end
        self._filename = filename
        cursor = _Cursor(data, 0, len(data), filename)
        cursor.full_box((0,), b"meta")
        self._boxes = _heif_children(
            data, cursor.pos, len(data), _HEIF_META_BOXES, filename
        )
        for kind in _HEIF_REQUIRED_BOXES:
            if kind not in self._boxes:
                raise _invalid(
                    f"HEIF meta box has no {kind.decode()} box", filename
                )

    def dimensions(
        self, check_pixels: Callable[[int, int], None]
    ) -> tuple[int, int]:
        """
        Read the primary item's size after checking every ispe.

        The primary item must be an HEVC image or a grid of HEVC
        tiles; other codecs and derivations are rejected.

        Args:
            check_pixels: Called with the size in every ispe
                property.

        Returns:
            Width and height of the primary item.

        Raises:
            FileSignatureError: If the item structure is invalid.
            ImageDimensionError: If ``check_pixels`` rejects a size.
            ResourceLimitError: If a resource limit is exceeded.
        """
        self._check_handler()
        primary = self._primary_item()
        types = self._item_types()
        sizes = self._item_sizes(check_pixels)
        item_type = types.get(primary)
        if item_type == _HEIF_HEVC_ITEM:
            return self._item_size(sizes, primary)
        if item_type == _HEIF_GRID_ITEM:
            return self._grid_dimensions(primary, types, sizes)
        raise _invalid(
            "HEIF primary item is not an HEVC image or grid", self._filename
        )

    def _cursor(self, kind: bytes) -> _Cursor:
        """Return a cursor over the payload of a meta child box."""
        start, end = self._boxes[kind]
        return _Cursor(self._data, start, end, self._filename)

    def _check_handler(self) -> None:
        """
        Require the pict handler that marks an image collection.

        Raises:
            FileSignatureError: If the handler is not pict.
        """
        cursor = self._cursor(b"hdlr")
        cursor.full_box((0,), b"hdlr")
        cursor.skip(4)  # pre_defined
        if cursor.take(4) != b"pict":
            raise _invalid(
                "HEIF meta box does not describe an image", self._filename
            )

    def _primary_item(self) -> int:
        """
        Read the primary item ID.

        Returns:
            The item ID in pitm.

        Raises:
            FileSignatureError: If pitm is malformed.
        """
        cursor = self._cursor(b"pitm")
        version, _ = cursor.full_box((0, 1), b"pitm")
        return cursor.uint(2 if version == 0 else 4)

    def _item_types(self) -> dict[int, bytes]:
        """
        Read the type of every item.

        Returns:
            Item type by item ID.

        Raises:
            FileSignatureError: If iinf or an entry is malformed,
                the entry count is wrong, an item is declared twice
                or an item is protected (encrypted).
            ResourceLimitError: If a resource limit is exceeded.
        """
        cursor = self._cursor(b"iinf")
        version, _ = cursor.full_box((0, 1), b"iinf")
        count = cursor.uint(2 if version == 0 else 4)
        types: dict[int, bytes] = {}
        for kind, start, end in _heif_boxes(
            self._data, cursor.pos, cursor.end, self._filename
        ):
            if kind != b"infe":
                raise _invalid(
                    "Unexpected box in HEIF item info", self._filename
                )
            entry = _Cursor(self._data, start, end, self._filename)
            # Versions 0 and 1 carry no item type
            entry_version, _ = entry.full_box((2, 3), b"infe")
            item_id = entry.uint(2 if entry_version == 2 else 4)
            if entry.uint(2):
                raise _invalid(
                    "Protected HEIF items are not supported", self._filename
                )
            if item_id in types:
                raise _invalid("HEIF item is declared twice", self._filename)
            types[item_id] = entry.take(4)
        if len(types) != count:
            raise _invalid(
                "HEIF item info count does not match its entries",
                self._filename,
            )
        return types

    def _item_sizes(
        self, check_pixels: Callable[[int, int], None]
    ) -> dict[int, tuple[int, int]]:
        """
        Check every ispe property and map items to their size.

        Every ispe in ipco is checked, whichever item it belongs to
        (tiles, thumbnails, alpha or depth images) or none.

        Args:
            check_pixels: Called with the size in every ispe
                property.

        Returns:
            Width and height by item ID, for items with an ispe.

        Raises:
            FileSignatureError: If iprp, ipco or ipma is missing or
                malformed, an ispe declares a zero dimension, a
                property index is out of range, or an item has two
                association entries or two ispe properties.
            ImageDimensionError: If ``check_pixels`` rejects a size.
            ResourceLimitError: If a resource limit is exceeded.
        """
        start, end = self._boxes[b"iprp"]
        iprp = _heif_children(
            self._data,
            start,
            end,
            frozenset({b"ipco", b"ipma"}),
            self._filename,
        )
        if b"ipco" not in iprp or b"ipma" not in iprp:
            raise _invalid(
                "HEIF item properties are incomplete", self._filename
            )

        # Spatial extents by 0-based property index, None for
        # properties of other types
        extents: list[tuple[int, int] | None] = []
        start, end = iprp[b"ipco"]
        for kind, prop_start, prop_end in _heif_boxes(
            self._data, start, end, self._filename
        ):
            if kind != b"ispe":
                extents.append(None)
                continue
            prop = _Cursor(self._data, prop_start, prop_end, self._filename)
            prop.full_box((0,), b"ispe")
            width, height = prop.uint(4), prop.uint(4)
            if not width or not height:
                raise _invalid(
                    "HEIF image dimensions are invalid", self._filename
                )
            check_pixels(width, height)
            extents.append((width, height))

        start, end = iprp[b"ipma"]
        ipma = _Cursor(self._data, start, end, self._filename)
        version, flags = ipma.full_box((0, 1), b"ipma")
        id_size = 2 if version == 0 else 4
        # Each index carries an "essential" bit above it
        index_size, index_mask = (2, 0x7FFF) if flags & 1 else (1, 0x7F)
        listed: set[int] = set()
        sizes: dict[int, tuple[int, int]] = {}
        for _ in range(ipma.uint(4)):
            check_resource_limits()
            item_id = ipma.uint(id_size)
            if item_id in listed:
                raise _invalid(
                    "HEIF item has two property associations",
                    self._filename,
                )
            listed.add(item_id)
            for _ in range(ipma.uint(1)):
                index = ipma.uint(index_size) & index_mask
                if index > len(extents):
                    raise _invalid(
                        "HEIF property index is out of range", self._filename
                    )
                # Index 0 associates no property
                size = extents[index - 1] if index else None
                if size is None:
                    continue
                if item_id in sizes:
                    raise _invalid(
                        "HEIF item has more than one ispe property",
                        self._filename,
                    )
                sizes[item_id] = size
        return sizes

    def _item_size(
        self, sizes: dict[int, tuple[int, int]], item_id: int
    ) -> tuple[int, int]:
        """
        Return the ispe size of an image item.

        Raises:
            FileSignatureError: If the item has no ispe property.
        """
        size = sizes.get(item_id)
        if size is None:
            raise _invalid("HEIF image has no ispe property", self._filename)
        return size

    def _grid_dimensions(
        self,
        grid_id: int,
        types: dict[int, bytes],
        sizes: dict[int, tuple[int, int]],
    ) -> tuple[int, int]:
        """
        Match a grid's descriptor and tiles to its ispe size.

        A decoder sizes the output from the descriptor and decodes
        every tile, so the descriptor must declare the ispe size
        and the tiles must cover it exactly, trimmed only at the
        right and bottom edges.

        Args:
            grid_id: Item ID of the grid.
            types: Item type by item ID.
            sizes: ispe width and height by item ID.

        Returns:
            Width and height of the grid.

        Raises:
            FileSignatureError: If the descriptor, its location,
                the tile references or the tiles are invalid or do
                not match the grid's ispe.
            ResourceLimitError: If a resource limit is exceeded.
        """
        width, height = self._item_size(sizes, grid_id)
        descriptor = self._grid_descriptor(grid_id)
        cursor = _Cursor(descriptor, 0, len(descriptor), self._filename)
        version, flags = cursor.uint(1), cursor.uint(1)
        if version != 0 or flags & ~_HEIF_GRID_WIDE_FIELDS:
            raise _invalid("Unsupported HEIF grid descriptor", self._filename)
        rows, columns = cursor.uint(1) + 1, cursor.uint(1) + 1
        field = 4 if flags & _HEIF_GRID_WIDE_FIELDS else 2
        output = (cursor.uint(field), cursor.uint(field))
        if not cursor.at_end:
            raise _invalid("Invalid HEIF grid descriptor size", self._filename)
        if output != (width, height):
            raise _invalid(
                "HEIF grid size does not match its ispe property",
                self._filename,
            )

        tiles = self._grid_tiles(grid_id)
        if len(tiles) != rows * columns:
            raise _invalid(
                "HEIF grid tile count does not match its layout",
                self._filename,
            )
        tile_sizes: set[tuple[int, int]] = set()
        for tile in tiles:
            if types.get(tile) != _HEIF_HEVC_ITEM:
                raise _invalid(
                    "HEIF grid tile is not an HEVC image", self._filename
                )
            tile_sizes.add(self._item_size(sizes, tile))
        if len(tile_sizes) != 1:
            raise _invalid("HEIF grid tiles differ in size", self._filename)
        ((tile_width, tile_height),) = tile_sizes
        if not (
            (columns - 1) * tile_width < width <= columns * tile_width
            and (rows - 1) * tile_height < height <= rows * tile_height
        ):
            raise _invalid(
                "HEIF grid tiles do not match the grid size", self._filename
            )
        return width, height

    def _grid_tiles(self, grid_id: int) -> list[int]:
        """
        Read the tile item IDs a grid references (dimg).

        Args:
            grid_id: Item ID of the grid.

        Returns:
            Tile item IDs in grid order.

        Raises:
            FileSignatureError: If iref is missing or malformed, or
                the grid does not have exactly one dimg reference.
            ResourceLimitError: If a resource limit is exceeded.
        """
        if b"iref" not in self._boxes:
            raise _invalid("HEIF grid has no tile references", self._filename)
        cursor = self._cursor(b"iref")
        version, _ = cursor.full_box((0, 1), b"iref")
        id_size = 2 if version == 0 else 4
        tiles: list[int] | None = None
        for kind, start, end in _heif_boxes(
            self._data, cursor.pos, cursor.end, self._filename
        ):
            if kind != b"dimg":
                continue
            ref = _Cursor(self._data, start, end, self._filename)
            if ref.uint(id_size) != grid_id:
                continue
            if tiles is not None:
                raise _invalid(
                    "HEIF grid has more than one tile reference",
                    self._filename,
                )
            tiles = [ref.uint(id_size) for _ in range(ref.uint(2))]
        if tiles is None:
            raise _invalid("HEIF grid has no tile references", self._filename)
        return tiles

    def _grid_descriptor(self, grid_id: int) -> bytes:
        """
        Read a grid's descriptor from the location iloc gives.

        Only the grid's entry is read in full; other entries are
        skipped by their size. The descriptor must be stored in
        this file, in idat or at a file offset, in at most
        ``_HEIF_GRID_MAX_SIZE`` bytes.

        Args:
            grid_id: Item ID of the grid.

        Returns:
            The descriptor bytes.

        Raises:
            FileSignatureError: If iloc is malformed, the grid has
                no single location, or the location is unsupported
                or lies outside its data.
            ResourceLimitError: If a resource limit is exceeded.
        """
        cursor = self._cursor(b"iloc")
        version, _ = cursor.full_box((0, 1, 2), b"iloc")
        sizes, more_sizes = cursor.uint(1), cursor.uint(1)
        offset_size, length_size = sizes >> 4, sizes & 0x0F
        base_size = more_sizes >> 4
        index_size = more_sizes & 0x0F if version else 0
        if (
            not {
                offset_size,
                length_size,
                base_size,
                index_size,
            }
            <= _HEIF_ILOC_FIELD_SIZES
        ):
            raise _invalid("Invalid HEIF item location", self._filename)
        id_size = 2 if version < 2 else 4
        extent_size = index_size + offset_size + length_size

        location: tuple[int, int, list[tuple[int, int]]] | None = None
        for _ in range(cursor.uint(id_size)):
            check_resource_limits()
            item_id = cursor.uint(id_size)
            method = cursor.uint(2) & 0x0F if version else 0
            data_reference = cursor.uint(2)
            base = cursor.uint(base_size)
            extent_count = cursor.uint(2)
            if item_id != grid_id:
                cursor.skip(extent_count * extent_size)
                continue
            if location is not None:
                raise _invalid(
                    "HEIF grid has more than one location", self._filename
                )
            extents: list[tuple[int, int]] = []
            total = 0
            for _ in range(extent_count):
                cursor.skip(index_size)
                offset = base + cursor.uint(offset_size)
                length = cursor.uint(length_size)
                total += length
                # A length of 0 means "to the end of the data"
                if not length or total > _HEIF_GRID_MAX_SIZE:
                    raise _invalid(
                        "Invalid HEIF grid descriptor size", self._filename
                    )
                extents.append((offset, length))
            location = (method, data_reference, extents)
        if location is None:
            raise _invalid("HEIF grid has no item location", self._filename)

        method, data_reference, extents = location
        # Construction method 0 is a file offset, 1 an idat offset;
        # a non-zero data reference points outside the file
        if data_reference or method not in (0, 1):
            raise _invalid("Unsupported HEIF item location", self._filename)
        return b"".join(
            self._extent(method, offset, length) for offset, length in extents
        )

    def _extent(self, method: int, offset: int, length: int) -> bytes:
        """
        Read one item data extent from the file or from idat.

        Args:
            method: Construction method, 0 (file) or 1 (idat).
            offset: Offset of the extent.
            length: Length of the extent.

        Returns:
            The extent bytes.

        Raises:
            FileSignatureError: If the extent lies outside the file
                or idat, or idat is missing.
        """
        if method == 0:
            if offset + length > self._file_end:
                raise _invalid(
                    "HEIF item data lies outside the file", self._filename
                )
            self._file_obj.seek(offset)
            return self._file_obj.read(length)
        start, end = self._boxes.get(b"idat", (0, 0))
        if start + offset + length > end:
            raise _invalid(
                "HEIF item data lies outside its idat box", self._filename
            )
        return self._data[start + offset : start + offset + length]


def _invalid(message: str, filename: str | None) -> FileSignatureError:
    """
    Build the error for a missing or invalid dimension header.

    Args:
        message: Client-safe description of the failure.
        filename: Optional sanitized filename for error context.

    Returns:
        A FileSignatureError carrying IMAGE_INVALID_STRUCTURE.
    """
    logger.warning("Invalid image structure: %s", message)
    return FileSignatureError(
        message,
        filename=filename,
        expected_type="image",
        error_code=ErrorCode.IMAGE_INVALID_STRUCTURE,
    )
