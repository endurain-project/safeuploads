"""Gzip archive inspector for decompression bomb detection."""

from __future__ import annotations

import logging
import zlib
from collections.abc import Iterator
from typing import TYPE_CHECKING

from ..audit import get_correlation_id, log_extra
from ..exceptions import (
    CompressionSecurityError,
    ErrorCode,
    FileProcessingError,
    ResourceLimitError,
    ZipBombError,
)
from ..utils import bytes_to_mb, iter_gzip_chunks
from ..validators.compression_validator import has_zip_end_record
from ..validators.entry_name_validator import EntryNameValidator
from .base import BaseInspector

if TYPE_CHECKING:
    from ..config import FileSecurityConfig
    from ..protocols import SeekableFile


logger = logging.getLogger(__name__)


class GzipContentInspector(BaseInspector):
    """
    Inspects gzip archives for decompression bomb attacks.

    Reads the compressed stream in chunks, tracking the
    compression ratio and total uncompressed size against
    configurable limits. A file ``zipfile`` would also open as a ZIP
    archive is rejected, and every member's stored name (FNAME) gets
    the archive entry-name checks.

    Attributes:
        config: File security configuration.
    """

    def __init__(self, config: FileSecurityConfig) -> None:
        """
        Initialize the inspector with configuration.

        Args:
            config: File security configuration.
        """
        super().__init__(config)
        # Stored member names get the checks ZIP entry names get
        self._names = EntryNameValidator(config)

    def inspect_gzip_content(
        self,
        file_obj: SeekableFile,
        compressed_size: int,
    ) -> None:
        """
        Inspect gzip archive for decompression bombs.

        Args:
            file_obj: Seekable file containing gzip data.
            compressed_size: Size of the compressed file in bytes.

        Raises:
            ZipBombError: If compression ratio or uncompressed
                size exceeds configured limits.
            ZipContentError: If a member's stored name fails the
                entry-name checks.
            CompressionSecurityError: If the gzip structure is
                invalid or corrupted, or the file is also a ZIP
                archive (``GZIP_ZIP_POLYGLOT``).
            ResourceLimitError: If the active resource monitor's
                time or memory limit is exceeded.
            FileProcessingError: If an unexpected error occurs.
        """
        for _ in self.iter_decompressed_chunks(file_obj, compressed_size):
            pass
        file_obj.seek(0)

    def iter_decompressed_chunks(
        self,
        file_obj: SeekableFile,
        compressed_size: int,
    ) -> Iterator[bytes]:
        """
        Decompress a gzip stream under the decompression bomb limits.

        A file in which ``zipfile`` finds a ZIP end record and
        central directory (a ZIP hidden in the FEXTRA field or in a
        stored deflate block) is rejected first, since ZIP readers
        would extract content the gzip checks never see. The stream
        is then inflated in ``chunk_size`` steps with
        ``iter_gzip_chunks`` (concatenated members and zero padding
        accepted, anything else after a member rejected), every
        member's FNAME gets the ``EntryNameValidator`` checks before
        the member is inflated, and the running total is checked
        against ``max_uncompressed_size`` and, relative to
        ``compressed_size``, ``max_compression_ratio`` before each
        chunk is yielded.

        Args:
            file_obj: Seekable file containing gzip data; it is read
                from offset 0.
            compressed_size: Size of the compressed stream in bytes.

        Yields:
            Non-empty chunks of decompressed data.

        Raises:
            ZipBombError: If compression ratio or uncompressed
                size exceeds configured limits.
            ZipContentError: If a member's stored name fails the
                entry-name checks.
            CompressionSecurityError: With ``GZIP_ZIP_POLYGLOT`` if
                ``zipfile`` would also open the file as a ZIP archive,
                or ``ZIP_CORRUPT`` if the gzip structure (including a
                header field), CRC-32 or size is invalid or the
                stream is truncated.
            ResourceLimitError: If the active resource monitor's
                time or memory limit is exceeded.
            FileProcessingError: If an unexpected error occurs.
        """
        file_obj.seek(0)
        total_uncompressed = 0
        chunk_size = self.config.limits.chunk_size
        max_ratio = self.config.limits.max_compression_ratio
        max_uncompressed = self.config.limits.max_uncompressed_size
        logger.debug(
            "Inspecting gzip stream (compressed size %d bytes)",
            compressed_size,
        )

        try:
            self._reject_zip_polyglot(file_obj)
            file_obj.seek(0)
            for chunk in iter_gzip_chunks(
                file_obj, chunk_size, self._names.validate
            ):
                total_uncompressed += len(chunk)

                # Check uncompressed size limit
                if total_uncompressed > max_uncompressed:
                    logger.error(
                        "Gzip uncompressed size exceeded: %dMB > %dMB",
                        bytes_to_mb(total_uncompressed),
                        bytes_to_mb(max_uncompressed),
                        extra=log_extra(),
                    )
                    cid = get_correlation_id()
                    if cid:
                        self._audit.threat(
                            "",
                            cid,
                            "Gzip decompression bomb — size exceeded",
                        )
                    raise ZipBombError(
                        message=(
                            "Gzip uncompressed size too"
                            " large:"
                            f" {bytes_to_mb(total_uncompressed)}MB."
                            " Maximum:"
                            f" {bytes_to_mb(max_uncompressed)}MB"
                        ),
                        compression_ratio=0,
                        uncompressed_size=(total_uncompressed),
                        max_size=max_uncompressed,
                    )

                # Check ratio progressively
                if compressed_size > 0:
                    ratio = total_uncompressed / compressed_size
                    if ratio > max_ratio:
                        logger.error(
                            "Gzip compression ratio exceeded: %.1f:1 > %d:1",
                            ratio,
                            max_ratio,
                            extra=log_extra(),
                        )
                        cid = get_correlation_id()
                        if cid:
                            self._audit.threat(
                                "",
                                cid,
                                "Gzip decompression bomb — ratio exceeded",
                            )
                        raise ZipBombError(
                            message=(
                                "Gzip compression ratio"
                                " too high:"
                                f" {ratio:.1f}:1."
                                " Maximum:"
                                f" {max_ratio}:1"
                            ),
                            compression_ratio=ratio,
                            max_ratio=float(max_ratio),
                            error_code=(ErrorCode.COMPRESSION_RATIO_EXCEEDED),
                        )

                yield chunk

        except (CompressionSecurityError, ResourceLimitError):
            raise
        except zlib.error as err:
            logger.error(
                "Invalid or corrupted gzip file",
                exc_info=True,
            )
            raise CompressionSecurityError(
                message=("Invalid or corrupted gzip file"),
                error_code=ErrorCode.ZIP_CORRUPT,
            ) from err
        except EOFError as err:
            logger.error("Truncated gzip file", exc_info=True)
            raise CompressionSecurityError(
                message="Truncated gzip file",
                error_code=ErrorCode.ZIP_CORRUPT,
            ) from err
        except MemoryError as err:
            logger.error(
                "Gzip requires excessive memory",
                exc_info=True,
            )
            raise ZipBombError(
                message=(
                    "Gzip requires too much memory"
                    " — potential decompression bomb"
                ),
                compression_ratio=0,
            ) from err
        except Exception as err:
            logger.error(
                "Unexpected error during gzip inspection",
                exc_info=True,
            )
            raise FileProcessingError(
                message="Gzip inspection failed",
                original_error=err,
            ) from err

        # Final overall ratio check
        if compressed_size > 0 and total_uncompressed > 0:
            overall_ratio = total_uncompressed / compressed_size
            logger.debug(
                "Gzip analysis: %dMB uncompressed, ratio %.1f:1",
                bytes_to_mb(total_uncompressed),
                overall_ratio,
            )

    def _reject_zip_polyglot(self, file_obj: SeekableFile) -> None:
        """
        Raise if ``zipfile`` would also open the file as a ZIP archive.

        Args:
            file_obj: Seekable file containing gzip data.

        Raises:
            CompressionSecurityError: With ``GZIP_ZIP_POLYGLOT`` if a
                ZIP end record and central directory are found.
        """
        if not has_zip_end_record(file_obj):
            return
        logger.warning(
            "Gzip file is also a ZIP archive",
            extra=log_extra({"error_type": "gzip_zip_polyglot"}),
        )
        cid = get_correlation_id()
        if cid:
            self._audit.threat("", cid, "Gzip file is also a ZIP archive")
        raise CompressionSecurityError(
            message=(
                "Gzip file is also a ZIP archive: ZIP readers would"
                " extract content the gzip checks do not see"
            ),
            error_code=ErrorCode.GZIP_ZIP_POLYGLOT,
        )
