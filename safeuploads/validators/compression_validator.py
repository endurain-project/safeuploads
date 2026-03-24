"""Validate ZIP compression ratios and detect zip bombs."""

from __future__ import annotations

import logging
import time
import zipfile
from typing import TYPE_CHECKING

from ..exceptions import (
    CompressionSecurityError,
    ErrorCode,
    FileProcessingError,
    ZipBombError,
)
from ..audit import SecurityAuditLogger, get_correlation_id, log_extra
from .base import BaseValidator

if TYPE_CHECKING:
    from ..config import FileSecurityConfig
    from ..protocols import SeekableFile


logger = logging.getLogger(__name__)


class CompressionSecurityValidator(BaseValidator):
    """
    Validates ZIP uploads against zip bombs and compression attacks.

    Attributes:
        config: Security configuration for validation limits.
    """

    def __init__(self, config: FileSecurityConfig):
        """
        Initialize the compression validator.

        Args:
            config: Security configuration with compression limits.
        """
        super().__init__(config)
        self._audit = SecurityAuditLogger(
            enabled=config.limits.enable_audit_logging
        )

    def validate_zip_compression_ratio(
        self, file_obj: SeekableFile, compressed_size: int
    ) -> None:
        """
        Validate ZIP archive against security limits.

        Args:
            file_obj: Seekable file-like object containing ZIP data.
            compressed_size: Size of the compressed archive in bytes.

        Raises:
            ZipBombError: If compression ratio exceeds maximum allowed
                or total uncompressed size is too large.
            CompressionSecurityError: If ZIP structure is invalid, too
                many entries, nested archives detected, or individual
                file too large.
            FileProcessingError: If unexpected error occurs during
                validation such as memory errors or I/O errors.
        """
        try:
            # Seek to start for zipfile analysis
            file_obj.seek(0)

            # Track analysis metrics
            total_uncompressed_size = 0
            total_compressed_size = compressed_size
            file_count = 0
            nested_archives = []
            max_compression_ratio = 0
            overall_compression_ratio = (
                0  # Initialize to avoid unbound variable
            )

            # Analyze ZIP file structure with timeout protection
            start_time = time.monotonic()

            with zipfile.ZipFile(file_obj, "r") as zip_file:
                # Check for excessive number of files
                zip_entries = zip_file.infolist()
                file_count = len(zip_entries)

                if file_count > self.config.limits.max_zip_entries:
                    logger.warning(
                        "ZIP contains too many files",
                        extra=log_extra({
                            "error_type": "zip_too_many_entries",
                            "file_count": file_count,
                            "max_entries": self.config.limits.max_zip_entries,
                        }),
                    )
                    raise CompressionSecurityError(
                        message=(
                            "ZIP contains too many"
                            f" files: {file_count}."
                            " Maximum allowed:"
                            f" {self.config.limits.max_zip_entries}"
                        ),
                        error_code=ErrorCode.ZIP_TOO_MANY_ENTRIES,
                    )

                # Analyze each entry in the ZIP
                for entry in zip_entries:
                    # Check for timeout
                    if (
                        time.monotonic() - start_time
                        > self.config.limits.zip_analysis_timeout
                    ):
                        logger.error(
                            "ZIP analysis timeout",
                            extra=log_extra({
                                "error_type": "zip_analysis_timeout",
                                "timeout": (
                                    self.config.limits.zip_analysis_timeout
                                ),
                            }),
                        )
                        raise ZipBombError(
                            message=(
                                "ZIP analysis timeout"
                                " after"
                                f" {self.config.limits.zip_analysis_timeout}s"
                                " - potential zip bomb"
                            ),
                            compression_ratio=0,
                        )

                    # Skip directories
                    if entry.is_dir():
                        continue

                    # Track uncompressed size
                    uncompressed_size = entry.file_size
                    compressed_size_entry = entry.compress_size
                    total_uncompressed_size += uncompressed_size

                    # Check individual file compression ratio
                    if compressed_size_entry > 0:  # Avoid division by zero
                        compression_ratio = (
                            uncompressed_size / compressed_size_entry
                        )
                        max_compression_ratio = max(
                            max_compression_ratio, compression_ratio
                        )

                        if (
                            compression_ratio
                            > self.config.limits.max_compression_ratio
                        ):
                            logger.error(
                                "Excessive compression ratio detected",
                                extra=log_extra({
                                    "error_type": "compression_ratio_exceeded",
                                    "file_name": entry.filename,
                                    "compression_ratio": compression_ratio,
                                    "max_ratio": (
                                        self.config.limits.max_compression_ratio
                                    ),
                                }),
                            )
                            cid = get_correlation_id()
                            if cid:
                                self._audit.threat(
                                    entry.filename, cid,
                                    "Zip bomb — excessive"
                                    " compression ratio",
                                )
                            max_ratio = (
                                self.config.limits.max_compression_ratio
                            )
                            raise ZipBombError(
                                message=(
                                    "Excessive compression"
                                    " ratio detected:"
                                    f" {compression_ratio:.1f}:1"
                                    f" for '{entry.filename}'."
                                    " Maximum allowed:"
                                    f" {max_ratio}:1"
                                ),
                                compression_ratio=compression_ratio,
                            )

                    # Check for nested archive files
                    filename_lower = entry.filename.lower()
                    if any(
                        filename_lower.endswith(ext)
                        for ext in [
                            ".zip",
                            ".rar",
                            ".7z",
                            ".tar",
                            ".gz",
                            ".bz2",
                        ]
                    ):
                        nested_archives.append(entry.filename)

                    # Check for excessively large individual files
                    # Use the configurable max_individual_file_size limit
                    if (
                        uncompressed_size
                        > self.config.limits.max_individual_file_size
                    ):
                        logger.warning(
                            "Individual file too large",
                            extra=log_extra({
                                "error_type": "file_too_large",
                                "file_name": entry.filename,
                                "size_mb": uncompressed_size // (1024 * 1024),
                                "max_size_mb": (
                                    self.config.limits.max_individual_file_size
                                    // (1024 * 1024)
                                ),
                            }),
                        )
                        max_file_mb = (
                            self.config.limits.max_individual_file_size
                            // (1024 * 1024)
                        )
                        raise CompressionSecurityError(
                            message=(
                                "Individual file too"
                                f" large: '{entry.filename}'"
                                " would expand to"
                                f" {uncompressed_size // (1024 * 1024)}MB."
                                " Maximum allowed:"
                                f" {max_file_mb}MB"
                            ),
                            error_code=ErrorCode.FILE_TOO_LARGE,
                        )

                # Check total uncompressed size
                if (
                    total_uncompressed_size
                    > self.config.limits.max_uncompressed_size
                ):
                    logger.warning(
                        "Total uncompressed size too large",
                        extra=log_extra({
                            "error_type": "zip_too_large",
                            "total_size_mb": total_uncompressed_size
                            // (1024 * 1024),
                            "max_size_mb": (
                                self.config.limits.max_uncompressed_size
                                // (1024 * 1024)
                            ),
                        }),
                    )
                    max_uncomp_mb = (
                        self.config.limits.max_uncompressed_size
                        // (1024 * 1024)
                    )
                    raise ZipBombError(
                        message=(
                            "Total uncompressed size"
                            " too large:"
                            f" {total_uncompressed_size // (1024 * 1024)}MB."
                            " Maximum allowed:"
                            f" {max_uncomp_mb}MB"
                        ),
                        compression_ratio=0,
                        uncompressed_size=total_uncompressed_size,
                        max_size=self.config.limits.max_uncompressed_size,
                    )

                # Check overall compression ratio
                if total_compressed_size > 0:
                    overall_compression_ratio = (
                        total_uncompressed_size / total_compressed_size
                    )
                    if (
                        overall_compression_ratio
                        > self.config.limits.max_compression_ratio
                    ):
                        logger.error(
                            "Overall compression ratio too high",
                            extra=log_extra({
                                "error_type": ("compression_ratio_exceeded"),
                                "overall_ratio": (overall_compression_ratio),
                                "max_ratio": (
                                    self.config.limits.max_compression_ratio
                                ),
                            }),
                        )
                        raise ZipBombError(
                            message=(
                                "Overall compression ratio"
                                " too high:"
                                f" {overall_compression_ratio:.1f}:1."
                                " Maximum allowed:"
                                f" {self.config.limits.max_compression_ratio}"
                                ":1"
                            ),
                            compression_ratio=(overall_compression_ratio),
                            max_ratio=(
                                self.config.limits.max_compression_ratio
                            ),
                        )

                # Reject nested archives (potential security risk)
                if (
                    nested_archives
                    and not self.config.limits.allow_nested_archives
                ):
                    logger.warning(
                        "Nested archives detected",
                        extra=log_extra({
                            "error_type": "zip_nested_archive",
                            "nested_archives": nested_archives,
                        }),
                    )
                    raise CompressionSecurityError(
                        message=(
                            "Nested archives are not"
                            " allowed:"
                            f" {', '.join(nested_archives)}"
                        ),
                        error_code=ErrorCode.ZIP_NESTED_ARCHIVE,
                    )

                # Cumulative entry count check for
                # complexity attack prevention
                max_recursive = (
                    self.config.limits
                    .max_total_entries_recursive
                )
                if file_count > max_recursive:
                    logger.error(
                        "ZIP entry count exceeds"
                        " recursive limit",
                        extra=log_extra({
                            "file_count": file_count,
                            "max_recursive": max_recursive,
                        }),
                    )
                    raise CompressionSecurityError(
                        message=(
                            "ZIP entry count"
                            f" ({file_count})"
                            " exceeds recursive limit"
                            f" ({max_recursive})"
                        ),
                        error_code=(
                            ErrorCode
                            .ZIP_COMPLEXITY_ATTACK
                        ),
                    )

                # Log analysis results
                logger.debug(
                    "ZIP analysis: %s files, %sMB uncompressed,"
                    " max ratio: %.1f:1,"
                    " overall ratio: %.1f:1",
                    file_count,
                    total_uncompressed_size // (1024 * 1024),
                    max_compression_ratio,
                    overall_compression_ratio,
                )

        except zipfile.BadZipFile as err:
            logger.error("Invalid or corrupted ZIP file", exc_info=True)
            raise CompressionSecurityError(
                message="Invalid or corrupted ZIP file",
                error_code=ErrorCode.ZIP_CORRUPT,
            ) from err
        except zipfile.LargeZipFile as err:
            logger.error("ZIP file too large to process", exc_info=True)
            raise CompressionSecurityError(
                message="ZIP file too large to process safely",
                error_code=ErrorCode.ZIP_TOO_LARGE,
            ) from err
        except MemoryError as err:
            logger.error("ZIP requires excessive memory", exc_info=True)
            raise ZipBombError(
                message=(
                    "ZIP file requires too much"
                    " memory to process"
                    " - potential zip bomb"
                ),
                compression_ratio=0,
            ) from err
        except (ZipBombError, CompressionSecurityError):
            # Re-raise our own exceptions
            raise
        except Exception as err:
            logger.error(
                "Unexpected error during ZIP compression validation",
                exc_info=True,
            )
            raise FileProcessingError(
                message="ZIP validation failed due to an internal error",
            ) from err

    def validate(self, file_obj: SeekableFile, compressed_size: int) -> None:
        """
        Validate the compression ratio of a ZIP file.

        Args:
            file_obj: Seekable file-like object of the ZIP.
            compressed_size: Size of the file after compression
                in bytes.

        Raises:
            ZipBombError: If compression ratio exceeds maximum.
            CompressionSecurityError: If ZIP structure is invalid.
            FileProcessingError: If unexpected error occurs.
        """
        return self.validate_zip_compression_ratio(file_obj, compressed_size)
