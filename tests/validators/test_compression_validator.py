"""Tests for CompressionSecurityValidator."""

import io
import struct
import types
import zipfile
import zlib

import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.exceptions import (
    CompressionSecurityError,
    ErrorCode,
    FileProcessingError,
    ResourceLimitError,
    ZipBombError,
)
from safeuploads.file_validator import FileValidator
from safeuploads.validators import compression_validator
from safeuploads.validators.compression_validator import (
    CompressionSecurityValidator,
)


class TestCompressionSecurityValidator:
    """Test suite for CompressionSecurityValidator."""

    def test_initialization(self, default_config):
        """Test validator initialization."""
        validator = CompressionSecurityValidator(default_config)
        assert validator.config == default_config

    def test_validate_normal_zip(self, default_config, create_zip_file):
        """Test validation of a normal safe ZIP file."""
        validator = CompressionSecurityValidator(default_config)

        # Create a simple ZIP with small files
        zip_bytes = create_zip_file(
            files={
                "file1.txt": b"Hello, World!",
                "file2.txt": b"Another file",
                "file3.txt": b"Yet another file",
            }
        )

        # Should not raise any exception
        validator.validate_zip_compression_ratio(
            io.BytesIO(zip_bytes), len(zip_bytes)
        )

    def test_validate_method_delegates_correctly(
        self, default_config, create_zip_file
    ):
        """
        Test that validate() method delegates to
        validate_zip_compression_ratio().
        """
        validator = CompressionSecurityValidator(default_config)
        zip_bytes = create_zip_file()

        # Both methods should work identically
        validator.validate(io.BytesIO(zip_bytes), len(zip_bytes))
        validator.validate_zip_compression_ratio(
            io.BytesIO(zip_bytes), len(zip_bytes)
        )

    def test_reject_corrupted_zip(self, default_config):
        """Test rejection of corrupted ZIP files."""
        validator = CompressionSecurityValidator(default_config)

        # Create invalid ZIP data
        corrupted_zip = b"PK\x03\x04corrupted data"

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(corrupted_zip), len(corrupted_zip)
            )

        assert exc_info.value.error_code == ErrorCode.ZIP_CORRUPT
        assert "Invalid or corrupted" in str(exc_info.value)

    def test_reject_excessive_compression_ratio_individual_file(
        self, default_config
    ):
        """
        Test rejection of individual file with
        excessive compression ratio.
        """
        validator = CompressionSecurityValidator(default_config)

        # Create a highly compressible file (repeated zeros)
        highly_compressible = b"\x00" * (20 * 1024 * 1024)  # 20MB of zeros

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(
            zip_buffer, "w", compression=zipfile.ZIP_DEFLATED
        ) as zf:
            zf.writestr("zeros.bin", highly_compressible)

        zip_bytes = zip_buffer.getvalue()

        with pytest.raises(ZipBombError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(zip_bytes), len(zip_bytes)
            )

        assert "Excessive compression ratio" in str(exc_info.value)
        assert exc_info.value.compression_ratio > 0
        assert (
            exc_info.value.error_code == ErrorCode.COMPRESSION_RATIO_EXCEEDED
        )

    def test_reject_excessive_overall_compression_ratio(self):
        """Test rejection of overall compression ratio exceeding limits."""
        # Use custom config with low compression ratio limit
        config = FileSecurityConfig()
        config.limits = SecurityLimits(max_compression_ratio=10)
        validator = CompressionSecurityValidator(config)

        # Create multiple highly compressible files
        highly_compressible = b"\x00" * (5 * 1024 * 1024)  # 5MB of zeros

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(
            zip_buffer, "w", compression=zipfile.ZIP_DEFLATED
        ) as zf:
            zf.writestr("zeros1.bin", highly_compressible)
            zf.writestr("zeros2.bin", highly_compressible)

        zip_bytes = zip_buffer.getvalue()

        with pytest.raises(ZipBombError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(zip_bytes), len(zip_bytes)
            )

        assert "compression ratio" in str(exc_info.value).lower()

    def test_reject_excessive_uncompressed_size(self):
        """Test rejection of ZIP with excessive total uncompressed size."""
        # Use custom config with low max uncompressed size
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            max_uncompressed_size=1 * 1024 * 1024,  # 1MB
            max_compression_ratio=1000,  # Allow high compression for this test
        )
        validator = CompressionSecurityValidator(config)

        # Create file that exceeds uncompressed size limit
        large_file = b"A" * (2 * 1024 * 1024)  # 2MB uncompressed

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(
            zip_buffer, "w", compression=zipfile.ZIP_STORED
        ) as zf:
            zf.writestr("large.bin", large_file)

        zip_bytes = zip_buffer.getvalue()

        with pytest.raises(ZipBombError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(zip_bytes), len(zip_bytes)
            )

        assert "Total uncompressed size too large" in str(exc_info.value)
        assert exc_info.value.uncompressed_size is not None
        assert exc_info.value.max_size is not None

    def test_reject_too_many_entries(self):
        """Test rejection of ZIP with too many files."""
        # Use custom config with low entry limit
        config = FileSecurityConfig()
        config.limits = SecurityLimits(max_zip_entries=5)
        validator = CompressionSecurityValidator(config)

        # Create ZIP with many files
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            for i in range(10):  # More than limit
                zf.writestr(f"file{i}.txt", f"Content {i}".encode())

        zip_bytes = zip_buffer.getvalue()

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(zip_bytes), len(zip_bytes)
            )

        assert exc_info.value.error_code == ErrorCode.ZIP_TOO_MANY_ENTRIES
        assert "too many files" in str(exc_info.value)

    def test_reject_nested_archives_zip(self, default_config):
        """Test rejection of ZIP containing nested ZIP files."""
        validator = CompressionSecurityValidator(default_config)

        # Create inner ZIP
        inner_zip = io.BytesIO()
        with zipfile.ZipFile(inner_zip, "w") as zf:
            zf.writestr("inner.txt", b"Inner content")

        # Create outer ZIP containing inner ZIP
        outer_zip = io.BytesIO()
        with zipfile.ZipFile(outer_zip, "w") as zf:
            zf.writestr("nested.zip", inner_zip.getvalue())

        zip_bytes = outer_zip.getvalue()

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(zip_bytes), len(zip_bytes)
            )

        assert exc_info.value.error_code == ErrorCode.ZIP_NESTED_ARCHIVE
        assert "Nested archives" in str(exc_info.value)

    def test_reject_nested_archives_tar(self, default_config):
        """Test rejection of ZIP containing TAR files."""
        validator = CompressionSecurityValidator(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("archive.tar", b"fake tar content")

        zip_bytes = zip_buffer.getvalue()

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(zip_bytes), len(zip_bytes)
            )

        assert exc_info.value.error_code == ErrorCode.ZIP_NESTED_ARCHIVE

    def test_reject_nested_archives_gz(self, default_config):
        """Test rejection of ZIP containing gzip files."""
        validator = CompressionSecurityValidator(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("data.gz", b"fake gzip content")

        zip_bytes = zip_buffer.getvalue()

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(zip_bytes), len(zip_bytes)
            )

        assert exc_info.value.error_code == ErrorCode.ZIP_NESTED_ARCHIVE

    def test_reject_nested_archives_tgz(self, default_config):
        """Test rejection of ZIP containing .tgz files."""
        validator = CompressionSecurityValidator(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("backup.tgz", b"fake tgz content")

        zip_bytes = zip_buffer.getvalue()

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(zip_bytes), len(zip_bytes)
            )

        assert exc_info.value.error_code == ErrorCode.ZIP_NESTED_ARCHIVE

    def test_reject_nested_archives_rar(self, default_config):
        """Test rejection of ZIP containing RAR files."""
        validator = CompressionSecurityValidator(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("archive.rar", b"fake rar content")

        zip_bytes = zip_buffer.getvalue()

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(zip_bytes), len(zip_bytes)
            )

        assert exc_info.value.error_code == ErrorCode.ZIP_NESTED_ARCHIVE

    def test_reject_nested_archives_7z(self, default_config):
        """Test rejection of ZIP containing 7z files."""
        validator = CompressionSecurityValidator(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("archive.7z", b"fake 7z content")

        zip_bytes = zip_buffer.getvalue()

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(zip_bytes), len(zip_bytes)
            )

        assert exc_info.value.error_code == ErrorCode.ZIP_NESTED_ARCHIVE

    def test_reject_individual_file_too_large(self):
        """
        Test rejection of ZIP containing individual
        file exceeding size limit.
        """
        # Use custom config with low individual file size limit
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            max_individual_file_size=512 * 1024,  # 512KB
            max_uncompressed_size=100 * 1024 * 1024,  # 100MB total allowed
            max_compression_ratio=1000,  # Allow high compression
        )
        validator = CompressionSecurityValidator(config)

        # Create file that exceeds individual size limit
        large_file = b"X" * (1024 * 1024)  # 1MB file

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(
            zip_buffer, "w", compression=zipfile.ZIP_STORED
        ) as zf:
            zf.writestr("large.bin", large_file)

        zip_bytes = zip_buffer.getvalue()

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(zip_bytes), len(zip_bytes)
            )

        assert exc_info.value.error_code == ErrorCode.FILE_TOO_LARGE
        assert "Individual file too large" in str(exc_info.value)

    def test_allow_directories_in_zip(self, default_config):
        """Test that directories in ZIP are properly handled."""
        validator = CompressionSecurityValidator(default_config)

        # Create ZIP with directories
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            # Add directory entries
            zf.writestr("folder/", "")
            zf.writestr("folder/file.txt", b"Content")
            zf.writestr("another_folder/", "")

        zip_bytes = zip_buffer.getvalue()

        # Should not raise - directories should be skipped in size calculations
        validator.validate_zip_compression_ratio(
            io.BytesIO(zip_bytes), len(zip_bytes)
        )

    def test_handle_zero_compressed_size(self, default_config):
        """Test handling of entries with zero compressed size."""
        validator = CompressionSecurityValidator(default_config)

        # Create ZIP with stored (uncompressed) small file
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(
            zip_buffer, "w", compression=zipfile.ZIP_STORED
        ) as zf:
            zf.writestr("empty.txt", b"")

        zip_bytes = zip_buffer.getvalue()

        # Should handle gracefully without division by zero
        validator.validate_zip_compression_ratio(
            io.BytesIO(zip_bytes), len(zip_bytes)
        )

    def test_case_insensitive_nested_archive_detection(self, default_config):
        """Test nested archive detection is case-insensitive."""
        validator = CompressionSecurityValidator(default_config)

        # Test various case combinations
        for filename in [
            "ARCHIVE.ZIP",
            "File.RAR",
            "data.Tar.Gz",
            "backup.7Z",
        ]:
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w") as zf:
                zf.writestr(filename, b"fake content")

            zip_bytes = zip_buffer.getvalue()

            with pytest.raises(CompressionSecurityError) as exc_info:
                validator.validate_zip_compression_ratio(
                    io.BytesIO(zip_bytes), len(zip_bytes)
                )

            assert exc_info.value.error_code == ErrorCode.ZIP_NESTED_ARCHIVE

    def test_timeout_protection_raises_zip_bomb_error(self):
        """
        Test timeout protection raises ZipBombError via mocked time.

        Uses unittest.mock.patch to make time.monotonic()
        immediately report that the timeout has been exceeded,
        so the result is deterministic regardless of host speed.

        Returns:
            None
        """
        from unittest.mock import patch

        config = FileSecurityConfig()
        config.limits = SecurityLimits(zip_analysis_timeout=5.0)
        validator = CompressionSecurityValidator(config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            for i in range(5):
                zf.writestr(f"file{i}.txt", b"content")
        zip_bytes = zip_buffer.getvalue()

        # First call returns start_time; subsequent calls
        # return a value that already exceeds the timeout.
        _start = 1_000_000.0
        _calls = {"n": 0}

        def _mock_monotonic() -> float:
            _calls["n"] += 1
            if _calls["n"] == 1:
                return _start
            return _start + config.limits.zip_analysis_timeout + 1.0

        target = "safeuploads.validators.compression_validator.time.monotonic"
        with (
            patch(target, side_effect=_mock_monotonic),
            pytest.raises(ZipBombError) as exc_info,
        ):
            validator.validate_zip_compression_ratio(
                io.BytesIO(zip_bytes),
                len(zip_bytes),
            )

        assert "timeout" in str(exc_info.value).lower()

    def test_memory_error_handling(self, default_config, monkeypatch):
        """Test handling of MemoryError during ZIP processing."""
        validator = CompressionSecurityValidator(default_config)

        # Mock zipfile.ZipFile to raise MemoryError
        def mock_zipfile(*args, **kwargs):
            raise MemoryError("Simulated memory error")

        monkeypatch.setattr(zipfile, "ZipFile", mock_zipfile)

        with pytest.raises(ZipBombError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(b"fake zip"), 100
            )

        assert "memory" in str(exc_info.value).lower()

    def test_exception_preservation(self, default_config):
        """
        Test that ZipBombError and
        CompressionSecurityError are re-raised.
        """
        validator = CompressionSecurityValidator(default_config)

        # Create a ZIP that will trigger too many entries error
        config = FileSecurityConfig()
        config.limits = SecurityLimits(max_zip_entries=1)
        validator = CompressionSecurityValidator(config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("file1.txt", b"Content 1")
            zf.writestr("file2.txt", b"Content 2")

        zip_bytes = zip_buffer.getvalue()

        # Should raise CompressionSecurityError, not FileProcessingError
        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(zip_bytes), len(zip_bytes)
            )

        assert exc_info.value.error_code == ErrorCode.ZIP_TOO_MANY_ENTRIES

    def test_multiple_files_within_limits(self, default_config):
        """Test ZIP with multiple files all within limits."""
        validator = CompressionSecurityValidator(default_config)

        # Create ZIP with multiple reasonable files
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(
            zip_buffer, "w", compression=zipfile.ZIP_DEFLATED
        ) as zf:
            for i in range(10):
                # Small files with some repetition but not extreme
                content = f"File {i} content. " * 100
                zf.writestr(f"file{i}.txt", content.encode())

        zip_bytes = zip_buffer.getvalue()

        # Should pass validation
        validator.validate_zip_compression_ratio(
            io.BytesIO(zip_bytes), len(zip_bytes)
        )

    def test_mixed_compression_methods(self, default_config):
        """Test ZIP with mixed compression methods."""
        validator = CompressionSecurityValidator(default_config)

        # Create ZIP with different compression methods
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            # Stored (no compression)
            zf.writestr(
                "stored.txt",
                b"Stored content",
                compress_type=zipfile.ZIP_STORED,
            )
            # Deflated (compressed)
            zf.writestr(
                "deflated.txt",
                b"Deflated content",
                compress_type=zipfile.ZIP_DEFLATED,
            )

        zip_bytes = zip_buffer.getvalue()

        # Should handle mixed compression gracefully
        validator.validate_zip_compression_ratio(
            io.BytesIO(zip_bytes), len(zip_bytes)
        )

    def test_error_includes_details(self):
        """Test that errors include helpful details."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(max_zip_entries=2)
        validator = CompressionSecurityValidator(config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("file1.txt", b"1")
            zf.writestr("file2.txt", b"2")
            zf.writestr("file3.txt", b"3")

        zip_bytes = zip_buffer.getvalue()

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(zip_bytes), len(zip_bytes)
            )

        error_msg = str(exc_info.value)
        # Should include both actual count and limit
        assert "3" in error_msg  # Actual count
        assert "2" in error_msg  # Limit

    def test_bz2_nested_archive_detection(self, default_config):
        """Test detection of bz2 compressed files as nested archives."""
        validator = CompressionSecurityValidator(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("data.bz2", b"fake bz2 content")

        zip_bytes = zip_buffer.getvalue()

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(zip_bytes), len(zip_bytes)
            )

        assert exc_info.value.error_code == ErrorCode.ZIP_NESTED_ARCHIVE
        assert "data.bz2" in str(exc_info.value)

    def test_corrupted_zip_file_badzipfile_exception(
        self, default_config
    ) -> None:
        """
        Test handling of corrupted ZIP file (BadZipFile exception).

        Tests lines 245-249 in compression_validator.py.
        """
        validator = CompressionSecurityValidator(default_config)

        # Create invalid ZIP data
        invalid_zip = b"PK\x03\x04" + b"corrupted data not valid zip"

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(invalid_zip), len(invalid_zip)
            )

        assert exc_info.value.error_code == ErrorCode.ZIP_CORRUPT
        assert "corrupted" in str(exc_info.value).lower()

    def test_large_zip_file_exception(self, default_config) -> None:
        """
        Test handling of ZIP file too large (LargeZipFile exception).

        Tests lines 250-254 in compression_validator.py.
        This is tricky to test as LargeZipFile is raised when
        ZIP64 extensions are needed but allowZip64=False.
        """
        validator = CompressionSecurityValidator(default_config)

        # Create a ZIP that would require ZIP64 but with allowZip64=False
        # LargeZipFile is raised when file size exceeds 4GB limit
        # We'll mock this by creating a ZIP with a fake large size
        from unittest.mock import patch

        # Create a minimal valid ZIP
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("test.txt", b"content")
        zip_bytes = zip_buffer.getvalue()

        # Mock ZipFile to raise LargeZipFile
        with patch("zipfile.ZipFile") as mock_zipfile:
            mock_zipfile.side_effect = zipfile.LargeZipFile("File too large")

            with pytest.raises(CompressionSecurityError) as exc_info:
                validator.validate_zip_compression_ratio(
                    io.BytesIO(zip_bytes), len(zip_bytes)
                )

            assert exc_info.value.error_code == ErrorCode.ZIP_TOO_LARGE
            assert "too large" in str(exc_info.value).lower()

    def test_memory_error_during_zip_processing(self, default_config) -> None:
        """
        Test handling of memory exhaustion (MemoryError exception).

        Tests lines 256-259 in compression_validator.py.
        """
        validator = CompressionSecurityValidator(default_config)

        from unittest.mock import patch

        # Create a minimal valid ZIP
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("test.txt", b"content")
        zip_bytes = zip_buffer.getvalue()

        # Mock ZipFile to raise MemoryError
        with patch("zipfile.ZipFile") as mock_zipfile:
            mock_zipfile.side_effect = MemoryError("Out of memory")

            with pytest.raises(ZipBombError) as exc_info:
                validator.validate_zip_compression_ratio(
                    io.BytesIO(zip_bytes), len(zip_bytes)
                )

            assert "memory" in str(exc_info.value).lower()
            assert "zip bomb" in str(exc_info.value).lower()

    def test_generic_exception_during_zip_validation(
        self, default_config
    ) -> None:
        """
        Test handling of unexpected exceptions during validation.

        Tests lines 264-269 in compression_validator.py.
        """
        validator = CompressionSecurityValidator(default_config)

        from unittest.mock import patch

        # Create a minimal valid ZIP
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("test.txt", b"content")
        zip_bytes = zip_buffer.getvalue()

        # Mock ZipFile to raise an unexpected exception
        with patch("zipfile.ZipFile") as mock_zipfile:
            mock_zipfile.side_effect = RuntimeError("Unexpected error")

            with pytest.raises(FileProcessingError) as exc_info:
                validator.validate_zip_compression_ratio(
                    io.BytesIO(zip_bytes), len(zip_bytes)
                )

            assert "validation failed" in str(exc_info.value).lower()

    def test_overall_compression_ratio_exceeded(self) -> None:
        """
        Test overall compression ratio check triggers ZipBombError.

        The overall ratio is ``total_uncompressed / compressed_size``
        where ``compressed_size`` is the archive-level parameter
        passed by the caller. By passing a deliberately small
        ``compressed_size`` we can trigger the overall ratio
        check without triggering the per-entry check.

        Returns:
            None
        """
        # Use stored files so per-entry compress_size == file_size.
        # An individual ratio of 1:1 will not trigger the per-entry
        # check, but the overall ratio can be made to exceed the
        # limit by passing a tiny ``compressed_size`` to the method.
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            max_compression_ratio=10,
            max_uncompressed_size=100 * 1024 * 1024,
            max_individual_file_size=50 * 1024 * 1024,
        )
        validator = CompressionSecurityValidator(config)

        content = b"A" * 10_000  # 10 KB stored uncompressed

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("data.txt", content)

        zip_bytes = zip_buffer.getvalue()

        # Pass a fake tiny compressed_size so overall ratio
        # is 10_000 / 100 = 100 > max_compression_ratio (10).
        with pytest.raises(ZipBombError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(zip_bytes), 100
            )

        error_msg = str(exc_info.value).lower()
        assert "overall compression ratio" in error_msg

    def test_complexity_attack_entry_count(self):
        """Test rejection when entries exceed recursive limit."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            max_zip_entries=100000,
            max_total_entries_recursive=5,
        )
        validator = CompressionSecurityValidator(config)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for i in range(10):
                zf.writestr(f"f{i}.txt", b"x")
        zip_bytes = buf.getvalue()

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(zip_bytes), len(zip_bytes)
            )
        assert exc_info.value.error_code == ErrorCode.ZIP_COMPLEXITY_ATTACK


class TestCompressionValidatorNestedAllowed:
    def test_nested_zip_allowed_when_configured_passes(
        self,
    ):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            allow_nested_archives=True,
        )
        validator = CompressionSecurityValidator(config)

        inner_zip = io.BytesIO()
        with zipfile.ZipFile(inner_zip, "w") as zf:
            zf.writestr("inner.txt", b"Inner content")

        outer_zip = io.BytesIO()
        with zipfile.ZipFile(outer_zip, "w") as zf:
            zf.writestr("nested.zip", inner_zip.getvalue())

        zip_bytes = outer_zip.getvalue()

        # Nested archive detected but not rejected
        # because allow_nested_archives=True covers
        # the False branch at line 272->306.
        validator.validate_zip_compression_ratio(
            io.BytesIO(zip_bytes), len(zip_bytes)
        )

    def test_empty_entry_skips_ratio_check_nested_allowed(
        self,
    ):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            allow_nested_archives=True,
        )
        validator = CompressionSecurityValidator(config)

        # A .zip entry that is in nested_archives.
        outer_zip = io.BytesIO()
        with zipfile.ZipFile(outer_zip, "w") as zf:
            zf.writestr("nested.zip", b"small content")

        zip_bytes = outer_zip.getvalue()

        # Passing compressed_size=0 makes total_compressed_size=0,
        # so line 272 "if total_compressed_size > 0:" is False
        # and the branch jumps to line 306 (272->306).
        # allow_nested_archives=True prevents the raise at 306.
        validator.validate_zip_compression_ratio(io.BytesIO(zip_bytes), 0)


def _forge_small_file_size(zip_bytes: bytes, lie: int = 100) -> bytes:
    """Rewrite the declared uncompressed size to understate it.

    Patches the uncompressed-size field in both the local header
    and the central directory so the archive metadata lies about
    how large the single entry expands to.
    """
    data = bytearray(zip_bytes)
    central = data.find(b"PK\x01\x02")
    struct.pack_into("<I", data, central + 24, lie)
    local = data.find(b"PK\x03\x04")
    struct.pack_into("<I", data, local + 22, lie)
    return bytes(data)


class TestVerifyZipDecompression:
    """Tests for the opt-in verify_zip_decompression mode."""

    @staticmethod
    def _bomb_zip() -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.bin", b"\x00" * (1024 * 1024))
        return buf.getvalue()

    def test_forged_metadata_passes_when_verify_disabled(self):
        """A forged small file_size passes when verification is off."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(verify_zip_decompression=False)
        validator = CompressionSecurityValidator(config)
        forged = _forge_small_file_size(self._bomb_zip())

        # Metadata is trusted, so the understated size passes.
        validator.validate_zip_compression_ratio(
            io.BytesIO(forged), len(forged)
        )

    def test_forged_metadata_rejected_when_verify_enabled(self):
        """Verification rejects forged metadata as a corrupt ZIP."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(verify_zip_decompression=True)
        validator = CompressionSecurityValidator(config)
        forged = _forge_small_file_size(self._bomb_zip())

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(forged), len(forged)
            )
        assert exc_info.value.error_code == ErrorCode.ZIP_CORRUPT

    def test_valid_zip_passes_with_verify_enabled(self):
        """A well-formed ZIP (with a dir entry) passes verification."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(verify_zip_decompression=True)
        validator = CompressionSecurityValidator(config)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("subdir/", b"")  # directory entry is skipped
            zf.writestr("subdir/a.txt", b"hello")
            zf.writestr("b.txt", b"world")
        zip_bytes = buf.getvalue()

        validator.validate_zip_compression_ratio(
            io.BytesIO(zip_bytes), len(zip_bytes)
        )


class TestDirectoryEntryWithData:
    """Tests that directory-named entries cannot carry file data."""

    @staticmethod
    def _zip_with_entry(name: str, data: bytes, compression: int) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=compression) as zf:
            zf.writestr(name, data)
        return buf.getvalue()

    def test_reject_directory_entry_with_compressed_zeros(self):
        """A 'd/' entry holding 20MB of zeros is rejected as invalid."""
        config = FileSecurityConfig()
        validator = CompressionSecurityValidator(config)
        zip_bytes = self._zip_with_entry(
            "d/", b"\x00" * (20 * 1024 * 1024), zipfile.ZIP_DEFLATED
        )

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(zip_bytes), len(zip_bytes)
            )

        assert exc_info.value.error_code == ErrorCode.ZIP_INVALID_STRUCTURE

    def test_reject_directory_entry_with_one_stored_byte(self):
        """A 'd/' entry declaring a single stored byte is rejected."""
        config = FileSecurityConfig()
        validator = CompressionSecurityValidator(config)
        zip_bytes = self._zip_with_entry("d/", b"x", zipfile.ZIP_STORED)

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(zip_bytes), len(zip_bytes)
            )

        assert exc_info.value.error_code == ErrorCode.ZIP_INVALID_STRUCTURE

    def test_accept_empty_stored_directory_entry(self):
        """An empty stored 'd/' entry is a valid directory."""
        config = FileSecurityConfig()
        validator = CompressionSecurityValidator(config)
        zip_bytes = self._zip_with_entry("d/", b"", zipfile.ZIP_STORED)

        validator.validate_zip_compression_ratio(
            io.BytesIO(zip_bytes), len(zip_bytes)
        )

    def test_accept_empty_deflated_directory_entry(self):
        """
        An empty deflated 'd/' entry is valid even though zipfile
        records a 2-byte compressed size for it.
        """
        config = FileSecurityConfig()
        validator = CompressionSecurityValidator(config)
        zip_bytes = self._zip_with_entry("d/", b"", zipfile.ZIP_DEFLATED)

        validator.validate_zip_compression_ratio(
            io.BytesIO(zip_bytes), len(zip_bytes)
        )

    def test_accept_mkdir_directory_entry(self):
        """A directory created with ZipFile.mkdir is valid."""
        config = FileSecurityConfig()
        validator = CompressionSecurityValidator(config)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.mkdir("d")
        zip_bytes = buf.getvalue()

        validator.validate_zip_compression_ratio(
            io.BytesIO(zip_bytes), len(zip_bytes)
        )


_EOCD = "<4s4H2LH"
_ZIP64_EOCD = "<4sQ2H2L4Q"
_ZIP64_LOCATOR = "<4sLQL"
_EOCD_SIZE = struct.calcsize(_EOCD)
# Bytes placed before an archive, like a self-extractor stub
_STUB = b"MZ" + b"\x00" * 62


def _zip_with_entries(count: int, comment: bytes = b"") -> bytes:
    """Build a stored ZIP with ``count`` small text entries."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for i in range(count):
            zf.writestr(f"f{i}.txt", b"x")
        zf.comment = comment
    return buf.getvalue()


def _eocd_fields(zip_bytes: bytes) -> tuple:
    """Unpack the comment-free EOCD record ending ``zip_bytes``."""
    return struct.unpack(_EOCD, zip_bytes[-_EOCD_SIZE:])


def _with_eocd(zip_bytes: bytes, count: int, cd_size: int) -> bytes:
    """Rewrite the EOCD entry counts and central-directory size."""
    fields = list(_eocd_fields(zip_bytes))
    fields[3] = fields[4] = count
    fields[5] = cd_size
    return zip_bytes[:-_EOCD_SIZE] + struct.pack(_EOCD, *fields)


def _under_reported(zip_bytes: bytes) -> bytes:
    """Make the EOCD declare a single entry."""
    return _with_eocd(zip_bytes, 1, _eocd_fields(zip_bytes)[5])


def _over_reported(zip_bytes: bytes) -> bytes:
    """Make the EOCD declare 500 entries."""
    return _with_eocd(zip_bytes, 500, _eocd_fields(zip_bytes)[5])


def _with_truncated_header(zip_bytes: bytes) -> bytes:
    """End the central directory with 10 bytes of a cut header."""
    fields = _eocd_fields(zip_bytes)
    cd_end = fields[6] + fields[5]
    padded = zip_bytes[:cd_end] + b"PK\x01\x02" + b"\x00" * 6
    return _with_eocd(padded + zip_bytes[cd_end:], fields[3], fields[5] + 10)


def _with_bad_header_signature(zip_bytes: bytes) -> bytes:
    """Corrupt the signature of the first central-directory header."""
    data = bytearray(zip_bytes)
    data[_eocd_fields(zip_bytes)[6] + 3] = 0
    return bytes(data)


def _as_zip64(
    zip_bytes: bytes,
    declared: int,
    eocd_count: int,
    extensible: bytes = b"",
) -> bytes:
    """
    Rewrite a comment-free ZIP to end in ZIP64 records.

    The ZIP64 record declares ``declared`` entries and the classic
    record ``eocd_count`` (0xFFFF is the usual ZIP64 marker);
    ``extensible`` is the ZIP64 extensible data sector.
    """
    fields = _eocd_fields(zip_bytes)
    cd_size, cd_offset = fields[5], fields[6]
    cd_end = cd_offset + cd_size
    zip64 = struct.pack(
        _ZIP64_EOCD,
        b"PK\x06\x06",
        44 + len(extensible),
        45,
        45,
        0,
        0,
        declared,
        declared,
        cd_size,
        cd_offset,
    )
    locator = struct.pack(_ZIP64_LOCATOR, b"PK\x06\x07", 0, cd_end, 1)
    eocd = struct.pack(
        _EOCD,
        b"PK\x05\x06",
        0,
        0,
        eocd_count,
        eocd_count,
        cd_size,
        cd_offset,
        0,
    )
    return zip_bytes[:cd_end] + zip64 + extensible + locator + eocd


def _patch_zip64(zip64_bytes: bytes, offset: int, value: int) -> bytes:
    """Overwrite one byte of the trailing ZIP64 records."""
    data = bytearray(zip64_bytes)
    data[len(data) + offset] = value
    return bytes(data)


def _with_fake_eocd_in_comment(zip_bytes: bytes, declared: int) -> bytes:
    """Append a comment holding a forged EOCD record."""
    fake = struct.pack(_EOCD, b"PK\x05\x06", 0, 0, declared, declared, 0, 0, 0)
    buf = io.BytesIO(zip_bytes)
    with zipfile.ZipFile(buf, "a") as zf:
        zf.comment = b"note " + fake
    return buf.getvalue()


def _entry_limit_validator(limit: int) -> CompressionSecurityValidator:
    """Return a validator allowing at most ``limit`` ZIP entries."""
    config = FileSecurityConfig()
    config.limits = SecurityLimits(max_zip_entries=limit)
    return CompressionSecurityValidator(config)


def _spy_zipfile(monkeypatch) -> list[int]:
    """Record every ``zipfile.ZipFile`` construction."""
    calls: list[int] = []
    real = zipfile.ZipFile

    def _spy(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(compression_validator.zipfile, "ZipFile", _spy)
    return calls


def _zipfile_entry_count(data: bytes) -> int | None:
    """Return how many entries zipfile lists, None if it rejects."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return len(zf.infolist())
    except zipfile.BadZipFile:
        return None


_ZIP64_3 = _as_zip64(_zip_with_entries(3), 7, 0xFFFF)

_CORPUS = [
    pytest.param(_zip_with_entries(3), id="plain"),
    pytest.param(_zip_with_entries(3, b"hello"), id="comment"),
    pytest.param(_zip_with_entries(0), id="empty-archive"),
    pytest.param(_under_reported(_zip_with_entries(21)), id="under-reported"),
    pytest.param(_over_reported(_zip_with_entries(3)), id="over-reported"),
    pytest.param(
        _with_fake_eocd_in_comment(_zip_with_entries(3), 50),
        id="fake-eocd-in-comment",
    ),
    pytest.param(_STUB + _zip_with_entries(3), id="prefixed"),
    pytest.param(
        _STUB + _under_reported(_zip_with_entries(21)),
        id="prefixed-under-reported",
    ),
    pytest.param(_ZIP64_3, id="zip64"),
    pytest.param(_as_zip64(_zip_with_entries(3), 3, 1), id="zip64-eocd-1"),
    pytest.param(
        _as_zip64(_zip_with_entries(3), 3, 0xFFFF, b"\x00" * 8),
        id="zip64-extensible",
    ),
    pytest.param(_STUB + _ZIP64_3, id="zip64-prefixed"),
    pytest.param(_patch_zip64(_ZIP64_3, -26, 2), id="zip64-multi-disk"),
    pytest.param(_patch_zip64(_ZIP64_3, -98, 0), id="zip64-no-signature"),
    pytest.param(_patch_zip64(_ZIP64_3, -94, 9), id="zip64-inconsistent"),
    pytest.param(
        _with_truncated_header(_zip_with_entries(3)), id="truncated-header"
    ),
    pytest.param(
        _with_bad_header_signature(_zip_with_entries(3)),
        id="bad-header-signature",
    ),
    pytest.param(
        _with_eocd(_zip_with_entries(3), 3, 1 << 20), id="negative-start"
    ),
    pytest.param(_zip_with_entries(3)[:-30], id="no-eocd"),
    pytest.param(b"PK\x05\x06", id="tiny"),
    pytest.param(b"", id="empty"),
]


class TestCentralDirectoryEntryCount:
    """Tests that ZIP entries are counted before zipfile parses them."""

    def test_exactly_max_entries_accepted(self):
        """An archive at the entry limit passes."""
        data = _zip_with_entries(20)
        _entry_limit_validator(20).validate_zip_compression_ratio(
            io.BytesIO(data), len(data)
        )

    @pytest.mark.parametrize(
        "data",
        [
            pytest.param(_zip_with_entries(21), id="honest-eocd"),
            pytest.param(
                _under_reported(_zip_with_entries(21)), id="under-reported"
            ),
            pytest.param(_STUB + _zip_with_entries(21), id="prefixed"),
            pytest.param(
                _as_zip64(_zip_with_entries(21), 1, 0xFFFF), id="zip64"
            ),
        ],
    )
    def test_one_over_max_rejected_before_parsing(self, monkeypatch, data):
        """One record over the limit is rejected without zipfile."""
        calls = _spy_zipfile(monkeypatch)

        with pytest.raises(CompressionSecurityError) as exc_info:
            _entry_limit_validator(20).validate_zip_compression_ratio(
                io.BytesIO(data), len(data)
            )

        assert exc_info.value.error_code == ErrorCode.ZIP_TOO_MANY_ENTRIES
        assert calls == []

    def test_prefixed_archive_at_limit_rejected_as_layout(self):
        """
        Data before the archive does not change its count, so the
        archive passes the entry limit and fails the layout check.
        """
        data = _STUB + _zip_with_entries(20)

        with pytest.raises(CompressionSecurityError) as exc_info:
            _entry_limit_validator(20).validate_zip_compression_ratio(
                io.BytesIO(data), len(data)
            )

        assert exc_info.value.error_code == ErrorCode.ZIP_INVALID_STRUCTURE

    def test_over_reported_count_within_limit_accepted(self):
        """A count only declared in the EOCD is not what is checked."""
        data = _over_reported(_zip_with_entries(3))
        assert _zipfile_entry_count(data) == 3
        _entry_limit_validator(20).validate_zip_compression_ratio(
            io.BytesIO(data), len(data)
        )

    def test_zip64_at_limit_accepted(self):
        """A ZIP64 archive at the entry limit passes."""
        data = _as_zip64(_zip_with_entries(20), 20, 0xFFFF)
        _entry_limit_validator(20).validate_zip_compression_ratio(
            io.BytesIO(data), len(data)
        )

    def test_real_zip64_archive_rejected_before_parsing(self, monkeypatch):
        """A zipfile-written ZIP64 archive is walked like any other."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", allowZip64=True) as zf:
            for i in range(0x10000):
                zf.writestr(zipfile.ZipInfo(f"{i}"), b"")
        data = buf.getvalue()
        assert data.rfind(b"PK\x06\x06") > 0
        calls = _spy_zipfile(monkeypatch)

        with pytest.raises(CompressionSecurityError) as exc_info:
            _entry_limit_validator(20).validate_zip_compression_ratio(
                io.BytesIO(data), len(data)
            )

        assert exc_info.value.error_code == ErrorCode.ZIP_TOO_MANY_ENTRIES
        assert calls == []

    @pytest.mark.parametrize(
        "data",
        [
            pytest.param(
                _with_truncated_header(_zip_with_entries(3)),
                id="truncated-header",
            ),
            pytest.param(
                _with_bad_header_signature(_zip_with_entries(3)),
                id="bad-header-signature",
            ),
            pytest.param(_zip_with_entries(3)[:-30], id="no-eocd"),
        ],
    )
    def test_malformed_directory_left_to_zipfile(self, data):
        """A directory zipfile cannot read is reported as corrupt."""
        with pytest.raises(CompressionSecurityError) as exc_info:
            _entry_limit_validator(20).validate_zip_compression_ratio(
                io.BytesIO(data), len(data)
            )

        assert exc_info.value.error_code == ErrorCode.ZIP_CORRUPT

    @pytest.mark.parametrize("data", _CORPUS)
    def test_count_matches_zipfile(self, data):
        """The walk counts exactly the entries zipfile lists."""
        expected = _zipfile_entry_count(data)

        assert (
            compression_validator._count_zip_entries(io.BytesIO(data), 10**6)
            == expected
        )

    @pytest.mark.parametrize("data", _CORPUS)
    def test_low_limit_never_rejects_what_zipfile_accepts(self, data):
        """With limit 1 the walk stops at 2 or defers to zipfile."""
        expected = _zipfile_entry_count(data)
        count = compression_validator._count_zip_entries(io.BytesIO(data), 1)

        if expected is None:
            assert count in (None, 2)
        else:
            assert count == min(expected, 2)


class TestCompressionResourceLimits:
    """Tests that the active resource monitor stops ZIP analysis."""

    def test_entry_loop_over_budget_raises(self, fake_clock):
        """A slow entry loop raises ResourceLimitError unchanged."""
        data = _zip_with_entries(50)
        validator = CompressionSecurityValidator(FileSecurityConfig())

        with pytest.raises(ResourceLimitError) as exc_info:
            fake_clock.run_monitored(
                lambda: validator.validate_zip_compression_ratio(
                    io.BytesIO(data), len(data)
                )
            )

        assert exc_info.value.error_code == ErrorCode.RESOURCE_TIME_EXCEEDED
        assert "validate_zip_compression_ratio" in {
            entry.name for entry in exc_info.traceback
        }

    def test_entry_loop_within_budget_passes(self, fake_clock):
        """The same archive passes when the loop stays in budget."""
        data = _zip_with_entries(50)
        validator = CompressionSecurityValidator(FileSecurityConfig())
        fake_clock.step = 0.01

        fake_clock.run_monitored(
            lambda: validator.validate_zip_compression_ratio(
                io.BytesIO(data), len(data)
            )
        )

    def test_verify_read_loop_over_budget_raises(self, fake_clock):
        """A slow decompression check stops inside its read loop."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("big.bin", b"\x01" * (20 * 65536))
        data = buf.getvalue()
        config = FileSecurityConfig()
        config.limits = SecurityLimits(verify_zip_decompression=True)
        validator = CompressionSecurityValidator(config)

        with pytest.raises(ResourceLimitError) as exc_info:
            fake_clock.run_monitored(
                lambda: validator.validate_zip_compression_ratio(
                    io.BytesIO(data), len(data)
                )
            )

        assert exc_info.value.error_code == ErrorCode.RESOURCE_TIME_EXCEEDED
        assert "_verify_entries_decompress" in {
            entry.name for entry in exc_info.traceback
        }


def _declared_zip(entries: list[tuple[str, int, int]]) -> bytes:
    """
    Build a stored ZIP whose entries declare the given sizes.

    Each ``(name, compress_size, file_size)`` entry stores
    ``compress_size`` bytes, so the layout is exact, and its local
    and central headers declare ``file_size`` as its uncompressed
    size.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for name, compress_size, _ in entries:
            zf.writestr(name, b"x" * compress_size)
    data = bytearray(buf.getvalue())
    central = data.find(b"PK\x01\x02")
    for info, (_, _, file_size) in zip(
        _infos(bytes(data)), entries, strict=True
    ):
        struct.pack_into("<L", data, info.header_offset + 22, file_size)
        struct.pack_into("<L", data, central + 24, file_size)
        central = data.find(b"PK\x01\x02", central + 4)
    return bytes(data)


def _stored_zip(names: list[str]) -> bytes:
    """Build a stored ZIP with one one-byte entry per name."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for name in names:
            zf.writestr(name, b"x")
    return buf.getvalue()


def _limits_validator(**limits) -> CompressionSecurityValidator:
    """Return a validator with the given limit overrides."""
    config = FileSecurityConfig()
    config.limits = SecurityLimits(**limits)
    return CompressionSecurityValidator(config)


class TestCompressionLimitBoundaries:
    """Tests that each limit accepts its value and rejects the next."""

    def test_entry_ratio_at_limit_accepted(self):
        """A declared 1000:100 entry is exactly 10:1 and passes."""
        data = _declared_zip([("a.bin", 100, 1000)])
        validator = _limits_validator(max_compression_ratio=10)

        validator.validate_zip_compression_ratio(io.BytesIO(data), 10_000)

    def test_entry_ratio_over_limit_rejected(self):
        """A declared 1001:100 entry is above 10:1 and is rejected."""
        data = _declared_zip([("a.bin", 100, 1001)])
        validator = _limits_validator(max_compression_ratio=10)

        with pytest.raises(ZipBombError) as exc_info:
            validator.validate_zip_compression_ratio(io.BytesIO(data), 10_000)

        assert (
            exc_info.value.error_code == ErrorCode.COMPRESSION_RATIO_EXCEEDED
        )
        assert "for 'a.bin'" in str(exc_info.value)

    def test_overall_ratio_at_limit_accepted(self):
        """1000 bytes over a 100-byte archive is exactly 10:1."""
        data = _declared_zip([("a.bin", 1000, 1000)])
        validator = _limits_validator(max_compression_ratio=10)

        validator.validate_zip_compression_ratio(io.BytesIO(data), 100)

    def test_overall_ratio_over_limit_rejected(self):
        """1000 bytes over a 99-byte archive is above 10:1."""
        data = _declared_zip([("a.bin", 1000, 1000)])
        validator = _limits_validator(max_compression_ratio=10)

        with pytest.raises(ZipBombError) as exc_info:
            validator.validate_zip_compression_ratio(io.BytesIO(data), 99)

        assert (
            exc_info.value.error_code == ErrorCode.COMPRESSION_RATIO_EXCEEDED
        )
        assert "Overall" in str(exc_info.value)

    def test_individual_size_at_limit_accepted(self):
        """An entry declaring exactly the individual limit passes."""
        data = _declared_zip([("a.bin", 1000, 1000)])
        validator = _limits_validator(max_individual_file_size=1000)

        validator.validate_zip_compression_ratio(io.BytesIO(data), 1000)

    def test_individual_size_over_limit_rejected(self):
        """An entry declaring one byte over the limit is rejected."""
        data = _declared_zip([("a.bin", 1001, 1001)])
        validator = _limits_validator(max_individual_file_size=1000)

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(io.BytesIO(data), 1001)

        assert exc_info.value.error_code == ErrorCode.FILE_TOO_LARGE

    def test_total_uncompressed_at_limit_accepted(self):
        """Two 500-byte entries total exactly the 1000-byte limit."""
        data = _declared_zip([("a.bin", 500, 500), ("b.bin", 500, 500)])
        validator = _limits_validator(
            max_uncompressed_size=1000, max_individual_file_size=600
        )

        validator.validate_zip_compression_ratio(io.BytesIO(data), 1000)

    def test_total_uncompressed_over_limit_rejected(self):
        """Entries totalling 1001 bytes exceed a 1000-byte limit."""
        data = _declared_zip([("a.bin", 500, 500), ("b.bin", 501, 501)])
        validator = _limits_validator(
            max_uncompressed_size=1000, max_individual_file_size=600
        )

        with pytest.raises(ZipBombError) as exc_info:
            validator.validate_zip_compression_ratio(io.BytesIO(data), 1001)

        assert exc_info.value.error_code == ErrorCode.ZIP_BOMB_DETECTED
        assert exc_info.value.uncompressed_size == 1001

    def test_recursive_entry_limit_at_limit_accepted(self):
        """An archive with exactly the recursive entry limit passes."""
        data = _zip_with_entries(3)
        validator = _limits_validator(max_total_entries_recursive=3)

        validator.validate_zip_compression_ratio(io.BytesIO(data), len(data))

    def test_recursive_entry_limit_over_limit_rejected(self):
        """One entry over the recursive entry limit is rejected."""
        data = _zip_with_entries(4)
        validator = _limits_validator(max_total_entries_recursive=3)

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(data), len(data)
            )

        assert exc_info.value.error_code == ErrorCode.ZIP_COMPLEXITY_ATTACK

    @staticmethod
    def _clock(monkeypatch, elapsed: float) -> None:
        """Make the second clock reading ``elapsed`` seconds late."""
        readings = iter([100.0, 100.0 + elapsed])
        monkeypatch.setattr(
            compression_validator,
            "time",
            types.SimpleNamespace(
                monotonic=lambda: next(readings, 100.0 + elapsed)
            ),
        )

    def test_analysis_timeout_at_limit_accepted(self, monkeypatch):
        """An entry reached exactly at the timeout is still analysed."""
        data = _zip_with_entries(1)
        validator = _limits_validator(zip_analysis_timeout=5.0)
        self._clock(monkeypatch, 5.0)

        validator.validate_zip_compression_ratio(io.BytesIO(data), len(data))

    def test_analysis_timeout_over_limit_rejected(self, monkeypatch):
        """An entry reached after the timeout aborts the analysis."""
        data = _zip_with_entries(1)
        validator = _limits_validator(zip_analysis_timeout=5.0)
        self._clock(monkeypatch, 5.5)

        with pytest.raises(ZipBombError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(data), len(data)
            )

        assert "timeout" in str(exc_info.value).lower()


class _Unseekable(io.RawIOBase):
    """Write-only stream without seek, so zipfile adds descriptors."""

    def __init__(self) -> None:
        super().__init__()
        self.data = bytearray()

    def writable(self) -> bool:
        return True

    def write(self, data) -> int:
        self.data += data
        return len(data)


def _descriptor_zip(
    force_zip64: bool = False,
    compression: int = zipfile.ZIP_DEFLATED,
    entries: tuple[tuple[str, bytes], ...] = (
        ("a.txt", b"hello " * 20),
        ("b.txt", b""),
    ),
) -> bytes:
    """Build a ZIP whose entries are followed by data descriptors."""
    stream = _Unseekable()
    with zipfile.ZipFile(stream, "w", compression) as zf:
        for name, content in entries:
            with zf.open(name, "w", force_zip64=force_zip64) as entry:
                entry.write(content)
    assert all(
        info.flag_bits & 0x08
        for info in zipfile.ZipFile(io.BytesIO(stream.data)).infolist()
    )
    return bytes(stream.data)


def _deflated_zip() -> bytes:
    """Build a deflated ZIP with two compressible entries."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", b"hello " * 50)
        zf.writestr("b.txt", b"world " * 50)
    return buf.getvalue()


def _zip_with_directories() -> bytes:
    """Build a ZIP holding directory entries and a file."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.mkdir("d")
        zf.writestr("e/", b"")
        zf.writestr("d/a.txt", b"hello")
    return buf.getvalue()


def _forced_zip64_zip() -> bytes:
    """Build a ZIP whose local headers carry ZIP64 extra fields."""
    buf = io.BytesIO()
    with (
        zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf,
        zf.open("a.txt", "w", force_zip64=True) as entry,
    ):
        entry.write(b"hello " * 20)
    return buf.getvalue()


_EVIL = [("payload.sh", b"#!/bin/sh\necho owned\n")]
_BENIGN = [("ok.gpx", b'<?xml version="1.0"?><gpx></gpx>')]


def _build(entries: list[tuple[str, bytes]]) -> bytes:
    """Build a deflated comment-free ZIP from name/content pairs."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries:
            zf.writestr(name, content)
    return buf.getvalue()


def _infos(data: bytes) -> list[zipfile.ZipInfo]:
    """Return the entries zipfile lists, in central-directory order."""
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return zf.infolist()


def _data_end(data: bytes, info: zipfile.ZipInfo) -> int:
    """Return where an entry's compressed data ends."""
    name_len, extra_len = struct.unpack_from(
        "<2H", data, info.header_offset + 26
    )
    return info.header_offset + 30 + name_len + extra_len + info.compress_size


def _directory_records(data: bytes) -> list[bytes]:
    """Split the central directory of a comment-free ZIP."""
    fields = _eocd_fields(data)
    directory = data[fields[6] : fields[6] + fields[5]]
    records = []
    while directory:
        name, extra, comment = struct.unpack_from("<3H", directory, 28)
        size = 46 + name + extra + comment
        records.append(directory[:size])
        directory = directory[size:]
    return records


def _with_directory(data: bytes, records: list[bytes], shift: int) -> bytes:
    """
    Replace the central directory of a comment-free ZIP.

    Every local-header offset in ``records`` and the declared
    directory offset move by ``shift``; the directory stays where
    it is.
    """
    fields = list(_eocd_fields(data))
    moved = []
    for record in records:
        record = bytearray(record)
        (offset,) = struct.unpack_from("<L", record, 42)
        struct.pack_into("<L", record, 42, offset + shift)
        moved.append(bytes(record))
    directory = b"".join(moved)
    start = fields[6]
    fields[3] = fields[4] = len(records)
    fields[5] = len(directory)
    fields[6] += shift
    return data[:start] + directory + struct.pack(_EOCD, *fields)


def _splice(data: bytes, at: int, blob: bytes, remove: int = 0) -> bytes:
    """
    Replace ``remove`` bytes at ``at`` with ``blob`` in a ZIP.

    Offsets of local headers at or after the replaced bytes, and
    of the central directory, move so zipfile still lists every
    entry where it now is.
    """
    fields = list(_eocd_fields(data))
    delta = len(blob) - remove
    records = []
    for record in _directory_records(data):
        record = bytearray(record)
        (offset,) = struct.unpack_from("<L", record, 42)
        if offset >= at + remove:
            struct.pack_into("<L", record, 42, offset + delta)
        records.append(bytes(record))
    start = fields[6]
    fields[6] += delta
    return (
        data[:at]
        + blob
        + data[at + remove : start]
        + b"".join(records)
        + struct.pack(_EOCD, *fields)
    )


def _without_descriptor_signatures(data: bytes) -> bytes:
    """Drop the optional signature from every data descriptor."""
    for info in sorted(_infos(data), key=lambda i: -i.header_offset):
        end = _data_end(data, info)
        assert data[end : end + 4] == b"PK\x07\x08"
        data = _splice(data, end, b"", remove=4)
    return data


def _second_entry_offset(data: bytes) -> int:
    """Return the local-header offset of the second listed entry."""
    return _infos(data)[1].header_offset


def _local_entry(name: str, content: bytes) -> bytes:
    """Return one local header and its data, without a directory."""
    data = _build([(name, content)])
    return data[: _eocd_fields(data)[6]]


def _shifted(data: bytes, shift: int) -> bytes:
    """Move every declared offset of a ZIP by ``shift`` bytes."""
    return _with_directory(data, _directory_records(data), shift)


def _archive_in_comment(outer: bytes, inner: bytes) -> bytes:
    """Hide ``inner`` in the comment of a comment-free ``outer``."""
    return (
        outer[:-2]
        + struct.pack("<H", len(inner))
        + _shifted(inner, len(outer))
    )


def _with_compress_size(data: bytes, compress_size: int) -> bytes:
    """Declare ``compress_size`` in the first central record only."""
    buf = bytearray(data)
    struct.pack_into("<L", buf, buf.find(b"PK\x01\x02") + 20, compress_size)
    return bytes(buf)


def _with_header_past_end(data: bytes) -> bytes:
    """
    Point the second record past the end of the file.

    The first entry's compressed size grows, in its local header
    and its record, so its data ends where the second record's
    local header is said to start.
    """
    first, second = _directory_records(data)
    first, second = bytearray(first), bytearray(second)
    struct.pack_into("<L", second, 42, 1 << 20)
    name_len = struct.unpack_from("<H", first, 28)[0]
    compress_size = (1 << 20) - 30 - name_len
    struct.pack_into("<L", first, 20, compress_size)
    data = _patch_first_local(data, 18, "<L", compress_size)
    return _with_directory(data, [bytes(first), bytes(second)], 0)


def _patch_descriptor(data: bytes, value: int) -> bytes:
    """Overwrite the CRC-32 in the first entry's data descriptor."""
    buf = bytearray(data)
    struct.pack_into("<L", buf, _data_end(data, _infos(data)[0]) + 4, value)
    return bytes(buf)


def _without_first_descriptor(data: bytes) -> bytes:
    """Remove the first entry's data descriptor entirely."""
    return _splice(data, _data_end(data, _infos(data)[0]), b"", remove=16)


def _clear_local_descriptor_flag(data: bytes) -> bytes:
    """Clear flag bit 3 in the first local header only."""
    buf = bytearray(data)
    buf[6] &= ~0x08
    return bytes(buf)


def _patch_first_local(data: bytes, offset: int, fmt: str, value) -> bytes:
    """Overwrite one field of the first local header only."""
    buf = bytearray(data)
    struct.pack_into(fmt, buf, offset, value)
    return bytes(buf)


def _clear_local_utf8_flag(data: bytes) -> bytes:
    """Clear the UTF-8 name flag (bit 11) in the first local header."""
    (flags,) = struct.unpack_from("<H", data, 6)
    return _patch_first_local(data, 6, "<H", flags & ~0x800)


def _understated_local_sizes() -> bytes:
    """
    Hide an entry in stored data behind zeroed local sizes.

    The central directory lists the stored entry at its real size,
    while its local header declares no data, so a reader trusting
    the local header finds the hidden entry inside that data.
    """
    data = bytearray(_build_stored([("ok.gpx", _local_entry(*_EVIL[0]))]))
    struct.pack_into("<3L", data, 14, 0, 0, 0)
    return bytes(data)


def _build_stored(entries: list[tuple[str, bytes]]) -> bytes:
    """Build a stored comment-free ZIP from name/content pairs."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for name, content in entries:
            zf.writestr(name, content)
    return buf.getvalue()


def _raw_deflate(content: bytes, mode: int = zlib.Z_FINISH) -> bytes:
    """Deflate ``content`` without a zlib header, as ZIP stores it."""
    compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
    return compressor.compress(content) + compressor.flush(mode)


def _hand_built_descriptor_zip(compressed: bytes, content: bytes) -> bytes:
    """
    Build a one-entry deflated ZIP with a data descriptor by hand.

    ``compressed`` is the entry's compressed data; the descriptor
    and central directory declare its length together with the
    CRC-32 and length of ``content``.
    """
    name = b"ok.gpx"
    values = (zlib.crc32(content), len(compressed), len(content))
    local = (
        struct.pack(
            "<4s2B4HL2L2H",
            b"PK\x03\x04",
            20,
            0,
            0x08,
            zipfile.ZIP_DEFLATED,
            0,
            0x21,
            0,
            0,
            0,
            len(name),
            0,
        )
        + name
    )
    descriptor = struct.pack("<4s3L", b"PK\x07\x08", *values)
    central = (
        struct.pack(
            "<4s4B4HL2L5H2L",
            b"PK\x01\x02",
            20,
            3,
            20,
            0,
            0x08,
            zipfile.ZIP_DEFLATED,
            0,
            0x21,
            *values,
            len(name),
            0,
            0,
            0,
            0,
            0o100644 << 16,
            0,
        )
        + name
    )
    offset = len(local) + len(compressed) + len(descriptor)
    eocd = struct.pack(
        _EOCD, b"PK\x05\x06", 0, 0, 1, 1, len(central), offset, 0
    )
    return local + compressed + descriptor + central + eocd


def _deflate_ending_early() -> bytes:
    """
    Hide an entry after the end of a descriptor entry's deflate data.

    The deflate stream ends early and is followed, inside the
    declared compressed size, by a forged descriptor and a hidden
    local entry that a streaming reader resumes at.
    """
    content = b"<gpx></gpx>"
    compressed = _raw_deflate(content)
    forged = struct.pack(
        "<4s3L",
        b"PK\x07\x08",
        zlib.crc32(content),
        len(compressed),
        len(content),
    )
    return _hand_built_descriptor_zip(
        compressed + forged + _local_entry(*_EVIL[0]), content
    )


def _empty_stored_descriptor_zip() -> bytes:
    """
    Stream an empty stored entry between deflated ones.

    Every entry carries a signed data descriptor, as bsdtar and
    streamed Info-ZIP archives store empty files.
    """
    stream = _Unseekable()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content, method in (
            ("a.gpx", _GPX, zipfile.ZIP_DEFLATED),
            ("empty.txt", b"", zipfile.ZIP_STORED),
            ("b.gpx", _GPX, zipfile.ZIP_DEFLATED),
        ):
            info = zipfile.ZipInfo(name)
            info.compress_type = method
            with zf.open(info, "w") as entry:
                entry.write(content)
    data = bytes(stream.data)
    empty = _infos(data)[1]
    assert empty.flag_bits & 0x08
    assert empty.compress_type == zipfile.ZIP_STORED
    assert data[_data_end(data, empty) :].startswith(b"PK\x07\x08")
    return data


def _with_empty_entry_crc(data: bytes, crc: int) -> bytes:
    """Declare ``crc`` for the empty entry in its record and descriptor."""
    empty = _infos(data)[1]
    buf = bytearray(data)
    struct.pack_into("<L", buf, _data_end(data, empty) + 4, crc)
    central = buf.find(b"PK\x01\x02")
    central = buf.find(b"PK\x01\x02", central + 4)
    struct.pack_into("<L", buf, central + 16, crc)
    return bytes(buf)


_GPX = b"".join(b"<trkpt n='%d'/>" % i for i in range(5000))
_STORED_AB = _stored_zip(["a.txt", "b.txt"])
_DESCRIPTOR_ZIP = _descriptor_zip()

_LAYOUT_VALID = [
    pytest.param(_STORED_AB, id="stored"),
    pytest.param(_deflated_zip(), id="deflated"),
    pytest.param(_zip_with_entries(3, b"hello"), id="comment"),
    pytest.param(_zip_with_directories(), id="directories"),
    pytest.param(_zip_with_entries(0), id="empty-archive"),
    pytest.param(_DESCRIPTOR_ZIP, id="descriptors"),
    pytest.param(_descriptor_zip(force_zip64=True), id="descriptors-zip64"),
    pytest.param(
        _without_descriptor_signatures(_DESCRIPTOR_ZIP),
        id="descriptors-unsigned",
    ),
    pytest.param(
        _without_descriptor_signatures(_descriptor_zip(force_zip64=True)),
        id="descriptors-zip64-unsigned",
    ),
    pytest.param(_forced_zip64_zip(), id="zip64-local-extra"),
    pytest.param(_ZIP64_3, id="zip64-end-records"),
    pytest.param(
        _as_zip64(_zip_with_entries(3), 3, 0xFFFF, b"\x00" * 8),
        id="zip64-extensible",
    ),
    pytest.param(
        _with_directory(
            _zip_with_entries(3),
            _directory_records(_zip_with_entries(3))[::-1],
            0,
        ),
        id="directory-out-of-order",
    ),
    pytest.param(_build([("é.txt", b"x")]), id="utf8-name"),
    pytest.param(
        _stored_zip(["aa.txt"]).replace(b"aa.txt", b"a\x82.txt"),
        id="cp437-name",
    ),
    pytest.param(
        _descriptor_zip(entries=(("e/", b""), ("e/a.gpx", _GPX))),
        id="descriptors-directory",
    ),
    pytest.param(
        _hand_built_descriptor_zip(_raw_deflate(_GPX), _GPX),
        id="descriptor-hand-built",
    ),
    pytest.param(
        _empty_stored_descriptor_zip(), id="empty-stored-with-descriptor"
    ),
]

_LAYOUT_INVALID = [
    pytest.param(
        _with_fake_eocd_in_comment(_build(_EVIL), 0),
        id="fake-empty-eocd-in-comment",
    ),
    pytest.param(
        _archive_in_comment(_build(_EVIL), _build(_BENIGN)),
        id="archive-in-comment",
    ),
    pytest.param(_build(_EVIL) + _build(_BENIGN), id="concatenated"),
    pytest.param(
        _splice(
            _STORED_AB,
            _second_entry_offset(_STORED_AB),
            _local_entry("payload.sh", b"!"),
        ),
        id="unlisted-entry",
    ),
    pytest.param(
        _splice(_STORED_AB, _second_entry_offset(_STORED_AB), b"\x00" * 16),
        id="gap-between-entries",
    ),
    pytest.param(_STORED_AB + b"junk", id="trailing-bytes"),
    pytest.param(
        _zip_with_entries(3, b"hello") + b"junk",
        id="trailing-after-comment",
    ),
    pytest.param(b"PK\x03\x04" + b"\x00" * 12 + _STORED_AB, id="prepended"),
    pytest.param(
        _splice(_STORED_AB, 0, b"PK\x03\x04" + b"\x00" * 12),
        id="prepended-offsets-adjusted",
    ),
    pytest.param(_STUB + _ZIP64_3, id="zip64-prepended"),
    pytest.param(
        _with_directory(
            _STORED_AB,
            [_directory_records(_STORED_AB)[0]] * 2,
            0,
        ),
        id="shared-local-header",
    ),
    pytest.param(_shifted(_STORED_AB, 4), id="declared-offsets-shifted"),
    pytest.param(_with_compress_size(_STORED_AB, 2), id="size-past-data"),
    pytest.param(_with_header_past_end(_STORED_AB), id="header-past-end"),
    pytest.param(
        _patch_descriptor(_DESCRIPTOR_ZIP, 0), id="descriptor-wrong-crc"
    ),
    pytest.param(
        _without_first_descriptor(_DESCRIPTOR_ZIP), id="descriptor-missing"
    ),
    pytest.param(
        _clear_local_descriptor_flag(_DESCRIPTOR_ZIP),
        id="descriptor-flag-mismatch",
    ),
    pytest.param(_understated_local_sizes(), id="local-sizes-understated"),
    pytest.param(
        _patch_first_local(_STORED_AB, 14, "<L", 0), id="local-crc-differs"
    ),
    pytest.param(
        _patch_first_local(_deflated_zip(), 8, "<H", zipfile.ZIP_STORED),
        id="local-method-differs",
    ),
    pytest.param(
        _patch_first_local(_STORED_AB, 30, "<B", ord("z")),
        id="local-name-differs",
    ),
    pytest.param(
        _clear_local_utf8_flag(_build([("é.txt", b"x")])),
        id="local-utf8-flag-differs",
    ),
    pytest.param(
        _patch_first_local(_forced_zip64_zip(), 47, "<Q", 1),
        id="local-zip64-size-differs",
    ),
    pytest.param(
        _patch_first_local(_forced_zip64_zip(), 35, "<H", 0x9999),
        id="local-zip64-extra-missing",
    ),
    pytest.param(
        _descriptor_zip(compression=zipfile.ZIP_STORED),
        id="stored-with-descriptor",
    ),
    pytest.param(
        _without_descriptor_signatures(_empty_stored_descriptor_zip()),
        id="empty-stored-unsigned-descriptor",
    ),
    pytest.param(
        _with_empty_entry_crc(_empty_stored_descriptor_zip(), 1),
        id="empty-stored-nonzero-crc",
    ),
    pytest.param(
        _descriptor_zip(compression=zipfile.ZIP_BZIP2),
        id="bzip2-with-descriptor",
    ),
    pytest.param(
        _descriptor_zip(compression=zipfile.ZIP_LZMA),
        id="lzma-with-descriptor",
    ),
    pytest.param(_deflate_ending_early(), id="deflate-ends-early"),
    pytest.param(
        _hand_built_descriptor_zip(
            _raw_deflate(_GPX, zlib.Z_SYNC_FLUSH), _GPX
        ),
        id="deflate-unterminated",
    ),
    pytest.param(
        _hand_built_descriptor_zip(b"\xff" * 16, b"x" * 16),
        id="deflate-corrupt",
    ),
    pytest.param(
        _hand_built_descriptor_zip(_raw_deflate(_GPX), _GPX[:-1]),
        id="deflate-longer-than-declared",
    ),
    pytest.param(
        _hand_built_descriptor_zip(_raw_deflate(_GPX), _GPX + b"x"),
        id="deflate-shorter-than-declared",
    ),
]


class TestZipLayout:
    """Tests that listed entries must cover the whole ZIP file."""

    @pytest.mark.parametrize("data", _LAYOUT_VALID)
    def test_exact_layout_accepted(self, data):
        """An archive made only of its listed entries passes."""
        validator = CompressionSecurityValidator(FileSecurityConfig())

        validator.validate_zip_compression_ratio(io.BytesIO(data), len(data))

    @pytest.mark.parametrize("data", _LAYOUT_INVALID)
    def test_unlisted_bytes_rejected(self, data):
        """Bytes no listed entry or end record accounts for fail."""
        assert _zipfile_entry_count(data) is not None
        validator = CompressionSecurityValidator(FileSecurityConfig())

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(data), len(data)
            )

        assert exc_info.value.error_code == ErrorCode.ZIP_INVALID_STRUCTURE

    @pytest.mark.parametrize("chunk_size", [1, 7, 1024, 65536])
    def test_descriptor_inflated_in_any_chunk_size(self, chunk_size):
        """Descriptor entries pass whatever the read chunk size."""
        data = _descriptor_zip(entries=(("a.gpx", _GPX), ("b.gpx", _GPX)))
        validator = _limits_validator(chunk_size=chunk_size)

        validator.validate_zip_compression_ratio(io.BytesIO(data), len(data))

    def test_zip64_descriptor_for_large_size_accepted(self):
        """A size above 4 GiB matches only an 8-byte descriptor."""
        entry = zipfile.ZipInfo("big.bin")
        entry.CRC, entry.compress_size, entry.file_size = 7, 10, 1 << 32
        descriptor = struct.pack("<L2Q", 7, 10, 1 << 32)

        assert compression_validator._descriptor_matches(
            io.BytesIO(descriptor), 0, len(descriptor), entry, False
        )

    def test_truncated_descriptor_for_large_size_rejected(self):
        """A 4-byte descriptor cannot stand for a size above 4 GiB."""
        entry = zipfile.ZipInfo("big.bin")
        entry.CRC, entry.compress_size, entry.file_size = 7, 10, 1 << 32
        descriptor = struct.pack("<3L", 7, 10, 0)

        assert not compression_validator._descriptor_matches(
            io.BytesIO(descriptor), 0, len(descriptor), entry, False
        )

    @pytest.mark.parametrize(
        "data",
        [
            pytest.param(
                _with_fake_eocd_in_comment(_build(_EVIL), 0),
                id="fake-empty-eocd-in-comment",
            ),
            pytest.param(
                _archive_in_comment(_build(_EVIL), _build(_BENIGN)),
                id="archive-in-comment",
            ),
            pytest.param(_build(_EVIL) + _build(_BENIGN), id="concatenated"),
        ],
    )
    async def test_hidden_archive_rejected_end_to_end(
        self, mock_upload_file, data
    ):
        """FileValidator rejects an archive hiding other entries."""
        validator = FileValidator()
        upload = mock_upload_file(filename="track.zip", content=data)

        with pytest.raises(CompressionSecurityError) as exc_info:
            await validator.validate_zip_file(upload)

        assert exc_info.value.error_code == ErrorCode.ZIP_INVALID_STRUCTURE

    async def test_descriptor_archive_accepted_end_to_end(
        self, mock_upload_file
    ):
        """FileValidator accepts a streamed archive with descriptors."""
        validator = FileValidator()
        upload = mock_upload_file(
            filename="track.zip", content=_DESCRIPTOR_ZIP
        )

        await validator.validate_zip_file(upload)
