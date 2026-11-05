"""Header-only dimension check for PNG, JPEG and WebP images."""

from __future__ import annotations

import logging
import struct
from typing import TYPE_CHECKING

from ..exceptions import ErrorCode, FileSignatureError, ImageDimensionError
from ..utils import check_resource_limits
from .base import BaseValidator

if TYPE_CHECKING:
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


class ImageDimensionValidator(BaseValidator):
    """
    Rejects images whose header declares too many pixels.

    Width and height are read from the PNG IHDR chunk, the first
    JPEG frame header (SOF) or the first WebP chunk (VP8, VP8L or
    VP8X canvas). No pixel data is decoded. A small file can
    declare a huge image that exhausts memory when decoded, so
    the pixel count is bounded before a host decodes the upload.

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
        not PNG, JPEG or WebP is rejected.

        Args:
            file_obj: Seekable file containing the image.
            filename: Optional sanitized filename for error context.

        Raises:
            FileSignatureError: If the format is not PNG, JPEG or
                WebP, or its dimension header is missing, truncated
                or invalid (IMAGE_INVALID_STRUCTURE).
            ImageDimensionError: If width times height exceeds
                ``limits.max_image_pixels``.
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
        else:
            raise _invalid("Unsupported image format", filename)
        file_obj.seek(0)

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
