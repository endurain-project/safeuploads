"""Tests for GzipContentInspector."""

import gzip
import io

import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.exceptions import (
    CompressionSecurityError,
    FileProcessingError,
    ZipBombError,
)
from safeuploads.inspectors.gzip_inspector import GzipContentInspector


class TestGzipContentInspector:
    """Test suite for GzipContentInspector."""

    def test_initialization(self, default_config):
        """Test inspector initialization."""
        inspector = GzipContentInspector(default_config)
        assert inspector.config == default_config

    def test_valid_gzip_passes(self, default_config):
        """Test inspection of safe gzip file passes."""
        inspector = GzipContentInspector(default_config)
        content = b"Hello, World! " * 100
        buf = io.BytesIO()
        with gzip.open(buf, "wb") as gz:
            gz.write(content)
        compressed = buf.getvalue()
        file_obj = io.BytesIO(compressed)
        inspector.inspect_gzip_content(
            file_obj, len(compressed)
        )

    def test_reject_excessive_compression_ratio(self):
        """Test rejection of high compression ratio."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            max_compression_ratio=5,
            max_uncompressed_size=100 * 1024 * 1024,
        )
        inspector = GzipContentInspector(config)

        # Highly compressible data
        content = b"\x00" * (1024 * 1024)  # 1MB of zeros
        buf = io.BytesIO()
        with gzip.open(buf, "wb") as gz:
            gz.write(content)
        compressed = buf.getvalue()
        file_obj = io.BytesIO(compressed)

        with pytest.raises(ZipBombError) as exc_info:
            inspector.inspect_gzip_content(
                file_obj, len(compressed)
            )
        assert "ratio" in str(exc_info.value).lower()

    def test_reject_excessive_uncompressed_size(self):
        """Test rejection of oversized uncompressed output."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            max_compression_ratio=10000,
            max_uncompressed_size=1024,  # 1KB limit
        )
        inspector = GzipContentInspector(config)

        content = b"A" * 2048  # 2KB
        buf = io.BytesIO()
        with gzip.open(buf, "wb") as gz:
            gz.write(content)
        compressed = buf.getvalue()
        file_obj = io.BytesIO(compressed)

        with pytest.raises(ZipBombError) as exc_info:
            inspector.inspect_gzip_content(
                file_obj, len(compressed)
            )
        assert "size" in str(exc_info.value).lower()

    def test_reject_corrupted_gzip(self, default_config):
        """Test rejection of corrupted gzip file."""
        inspector = GzipContentInspector(default_config)
        # Valid gzip header but corrupted body
        corrupted = b"\x1f\x8b\x08\x00" + b"corrupted"
        file_obj = io.BytesIO(corrupted)

        with pytest.raises(
            (CompressionSecurityError, FileProcessingError)
        ):
            inspector.inspect_gzip_content(
                file_obj, len(corrupted)
            )

    def test_file_position_reset_after_inspection(
        self, default_config
    ):
        """Test file position is reset after inspection."""
        inspector = GzipContentInspector(default_config)
        content = b"test data"
        buf = io.BytesIO()
        with gzip.open(buf, "wb") as gz:
            gz.write(content)
        compressed = buf.getvalue()
        file_obj = io.BytesIO(compressed)
        inspector.inspect_gzip_content(
            file_obj, len(compressed)
        )
        assert file_obj.tell() == 0

    def test_small_gzip_within_limits(self, default_config):
        """Test small gzip file passes all checks."""
        inspector = GzipContentInspector(default_config)
        content = b"small content"
        buf = io.BytesIO()
        with gzip.open(buf, "wb") as gz:
            gz.write(content)
        compressed = buf.getvalue()
        file_obj = io.BytesIO(compressed)
        inspector.inspect_gzip_content(
            file_obj, len(compressed)
        )

    def test_memory_error_handling(
        self, default_config, monkeypatch
    ):
        """Test handling of MemoryError during decompression."""
        inspector = GzipContentInspector(default_config)

        original_open = gzip.open

        def mock_open(*args, **kwargs):
            raise MemoryError("Simulated memory error")

        monkeypatch.setattr(gzip, "open", mock_open)

        file_obj = io.BytesIO(b"\x1f\x8b")
        with pytest.raises(ZipBombError) as exc_info:
            inspector.inspect_gzip_content(file_obj, 100)
        assert "memory" in str(exc_info.value).lower()
