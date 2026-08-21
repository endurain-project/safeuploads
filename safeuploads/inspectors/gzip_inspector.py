"""Gzip archive inspector for decompression bomb detection."""

from __future__ import annotations

import gzip
import logging
import time
from typing import TYPE_CHECKING

from ..audit import get_correlation_id, log_extra
from ..exceptions import (
    CompressionSecurityError,
    ErrorCode,
    FileProcessingError,
    ResourceLimitError,
    ZipBombError,
)
from ..utils import bytes_to_mb
from .base import BaseInspector

if TYPE_CHECKING:
    from ..protocols import SeekableFile
    from ..utils import ResourceMonitor


logger = logging.getLogger(__name__)


class GzipContentInspector(BaseInspector):
    """
    Inspects gzip archives for decompression bomb attacks.

    Reads the compressed stream in chunks, tracking the
    compression ratio and total uncompressed size against
    configurable limits.

    Attributes:
        config: File security configuration.
    """

    def inspect_gzip_content(
        self,
        file_obj: SeekableFile,
        compressed_size: int,
        monitor: ResourceMonitor | None = None,
        filename: str = "",
    ) -> None:
        """
        Inspect gzip archive for decompression bombs.

        Args:
            file_obj: Seekable file containing gzip data.
            compressed_size: Size of the compressed file in bytes.
            monitor: Optional resource monitor checked once per
                chunk so a slow stream is aborted mid-inflation.
            filename: Sanitized filename recorded on audit events.

        Raises:
            ZipBombError: If compression ratio or uncompressed
                size exceeds configured limits, or inflation
                exceeds ``gzip_analysis_timeout``.
            CompressionSecurityError: If the gzip structure is
                invalid or corrupted.
            ResourceLimitError: If the monitor's time or memory
                limit is exceeded during inspection.
            FileProcessingError: If an unexpected error occurs.
        """
        file_obj.seek(0)
        total_uncompressed = 0
        chunk_size = self.config.limits.chunk_size
        max_ratio = self.config.limits.max_compression_ratio
        max_uncompressed = self.config.limits.max_uncompressed_size
        timeout = self.config.limits.gzip_analysis_timeout
        start_time = time.monotonic()
        logger.debug(
            "Inspecting gzip stream (compressed size %d bytes)",
            compressed_size,
        )

        try:
            with gzip.open(file_obj, "rb") as gz:
                while True:
                    if monitor is not None:
                        monitor.check()

                    if time.monotonic() - start_time > timeout:
                        logger.error(
                            "Gzip inflation timeout after %.1fs",
                            timeout,
                            extra=log_extra(),
                        )
                        cid = get_correlation_id()
                        if cid:
                            self._audit.threat(
                                filename,
                                cid,
                                "Gzip inflation timeout",
                            )
                        raise ZipBombError(
                            message=(
                                "Gzip inflation timeout after"
                                f" {timeout}s"
                                " - potential decompression bomb"
                            ),
                            compression_ratio=0,
                            error_code=ErrorCode.ZIP_ANALYSIS_TIMEOUT,
                        )

                    chunk = gz.read(chunk_size)
                    if not chunk:
                        break
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
                                filename,
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
                                "Gzip compression ratio"
                                " exceeded:"
                                " %.1f:1 > %d:1",
                                ratio,
                                max_ratio,
                                extra=log_extra(),
                            )
                            cid = get_correlation_id()
                            if cid:
                                self._audit.threat(
                                    filename,
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
                                error_code=(
                                    ErrorCode.COMPRESSION_RATIO_EXCEEDED
                                ),
                            )

        except ZipBombError:
            raise
        except ResourceLimitError:
            # A breached time/memory budget must abort the request,
            # not be reported as an internal processing failure.
            raise
        except gzip.BadGzipFile as err:
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

        file_obj.seek(0)
