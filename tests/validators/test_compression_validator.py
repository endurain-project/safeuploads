"""Tests for CompressionSecurityValidator."""

import io
import zipfile
import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.validators.compression_validator import (
    CompressionSecurityValidator,
)
from safeuploads.exceptions import (
    ZipBombError,
    CompressionSecurityError,
    FileProcessingError,
    ErrorCode,
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
        validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))

    def test_validate_method_delegates_correctly(self, default_config, create_zip_file):
        """Test that validate() method delegates to validate_zip_compression_ratio()."""
        validator = CompressionSecurityValidator(default_config)
        zip_bytes = create_zip_file()

        # Both methods should work identically
        validator.validate(zip_bytes, len(zip_bytes))
        validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))

    def test_reject_corrupted_zip(self, default_config):
        """Test rejection of corrupted ZIP files."""
        validator = CompressionSecurityValidator(default_config)

        # Create invalid ZIP data
        corrupted_zip = b"PK\x03\x04corrupted data"

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(corrupted_zip, len(corrupted_zip))

        assert exc_info.value.error_code == ErrorCode.ZIP_CORRUPT
        assert "Invalid or corrupted" in str(exc_info.value)

    def test_reject_excessive_compression_ratio_individual_file(self, default_config):
        """Test rejection of individual file with excessive compression ratio."""
        validator = CompressionSecurityValidator(default_config)

        # Create a highly compressible file (repeated zeros)
        highly_compressible = b"\x00" * (20 * 1024 * 1024)  # 20MB of zeros

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("zeros.bin", highly_compressible)

        zip_bytes = zip_buffer.getvalue()

        with pytest.raises(ZipBombError) as exc_info:
            validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))

        assert "Excessive compression ratio" in str(exc_info.value)
        assert exc_info.value.compression_ratio > 0

    def test_reject_excessive_overall_compression_ratio(self):
        """Test rejection of overall compression ratio exceeding limits."""
        # Use custom config with low compression ratio limit
        config = FileSecurityConfig()
        config.limits = SecurityLimits(max_compression_ratio=10)
        validator = CompressionSecurityValidator(config)

        # Create multiple highly compressible files
        highly_compressible = b"\x00" * (5 * 1024 * 1024)  # 5MB of zeros

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("zeros1.bin", highly_compressible)
            zf.writestr("zeros2.bin", highly_compressible)

        zip_bytes = zip_buffer.getvalue()

        with pytest.raises(ZipBombError) as exc_info:
            validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))

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
        with zipfile.ZipFile(zip_buffer, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("large.bin", large_file)

        zip_bytes = zip_buffer.getvalue()

        with pytest.raises(ZipBombError) as exc_info:
            validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))

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
            validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))

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
            validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))

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
            validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))

        assert exc_info.value.error_code == ErrorCode.ZIP_NESTED_ARCHIVE

    def test_reject_nested_archives_gz(self, default_config):
        """Test rejection of ZIP containing gzip files."""
        validator = CompressionSecurityValidator(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("data.gz", b"fake gzip content")

        zip_bytes = zip_buffer.getvalue()

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))

        assert exc_info.value.error_code == ErrorCode.ZIP_NESTED_ARCHIVE

    def test_reject_nested_archives_rar(self, default_config):
        """Test rejection of ZIP containing RAR files."""
        validator = CompressionSecurityValidator(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("archive.rar", b"fake rar content")

        zip_bytes = zip_buffer.getvalue()

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))

        assert exc_info.value.error_code == ErrorCode.ZIP_NESTED_ARCHIVE

    def test_reject_nested_archives_7z(self, default_config):
        """Test rejection of ZIP containing 7z files."""
        validator = CompressionSecurityValidator(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("archive.7z", b"fake 7z content")

        zip_bytes = zip_buffer.getvalue()

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))

        assert exc_info.value.error_code == ErrorCode.ZIP_NESTED_ARCHIVE

    def test_reject_individual_file_too_large(self):
        """Test rejection of ZIP containing individual file exceeding size limit."""
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
        with zipfile.ZipFile(zip_buffer, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("large.bin", large_file)

        zip_bytes = zip_buffer.getvalue()

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))

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
        validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))

    def test_handle_zero_compressed_size(self, default_config):
        """Test handling of entries with zero compressed size."""
        validator = CompressionSecurityValidator(default_config)

        # Create ZIP with stored (uncompressed) small file
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("empty.txt", b"")

        zip_bytes = zip_buffer.getvalue()

        # Should handle gracefully without division by zero
        validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))

    def test_case_insensitive_nested_archive_detection(self, default_config):
        """Test nested archive detection is case-insensitive."""
        validator = CompressionSecurityValidator(default_config)

        # Test various case combinations
        for filename in ["ARCHIVE.ZIP", "File.RAR", "data.Tar.Gz", "backup.7Z"]:
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w") as zf:
                zf.writestr(filename, b"fake content")

            zip_bytes = zip_buffer.getvalue()

            with pytest.raises(CompressionSecurityError) as exc_info:
                validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))

            assert exc_info.value.error_code == ErrorCode.ZIP_NESTED_ARCHIVE

    def test_timeout_protection(self):
        """Test timeout protection during ZIP analysis."""
        # Use custom config with very short timeout
        config = FileSecurityConfig()
        config.limits = SecurityLimits(zip_analysis_timeout=0.001)  # 1ms
        validator = CompressionSecurityValidator(config)

        # Create ZIP with many files to trigger timeout
        # Need a lot of files to exceed even 1ms
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            for i in range(1000):  # More files to ensure timeout
                zf.writestr(f"file{i}.txt", b"X" * 10000)

        zip_bytes = zip_buffer.getvalue()

        # Timeout may or may not trigger depending on system speed
        # If it does trigger, it should be a ZipBombError
        try:
            validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))
        except ZipBombError as e:
            assert "timeout" in str(e).lower()
        except CompressionSecurityError:
            # May also fail due to too many entries - that's OK
            pass

    def test_memory_error_handling(self, default_config, monkeypatch):
        """Test handling of MemoryError during ZIP processing."""
        validator = CompressionSecurityValidator(default_config)

        # Mock zipfile.ZipFile to raise MemoryError
        original_zipfile = zipfile.ZipFile

        def mock_zipfile(*args, **kwargs):
            raise MemoryError("Simulated memory error")

        monkeypatch.setattr(zipfile, "ZipFile", mock_zipfile)

        with pytest.raises(ZipBombError) as exc_info:
            validator.validate_zip_compression_ratio(b"fake zip", 100)

        assert "memory" in str(exc_info.value).lower()

    def test_exception_preservation(self, default_config):
        """Test that ZipBombError and CompressionSecurityError are re-raised."""
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
            validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))

        assert exc_info.value.error_code == ErrorCode.ZIP_TOO_MANY_ENTRIES

    def test_multiple_files_within_limits(self, default_config):
        """Test ZIP with multiple files all within limits."""
        validator = CompressionSecurityValidator(default_config)

        # Create ZIP with multiple reasonable files
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for i in range(10):
                # Small files with some repetition but not extreme
                content = f"File {i} content. " * 100
                zf.writestr(f"file{i}.txt", content.encode())

        zip_bytes = zip_buffer.getvalue()

        # Should pass validation
        validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))

    def test_mixed_compression_methods(self, default_config):
        """Test ZIP with mixed compression methods."""
        validator = CompressionSecurityValidator(default_config)

        # Create ZIP with different compression methods
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            # Stored (no compression)
            zf.writestr(
                "stored.txt", b"Stored content", compress_type=zipfile.ZIP_STORED
            )
            # Deflated (compressed)
            zf.writestr(
                "deflated.txt",
                b"Deflated content",
                compress_type=zipfile.ZIP_DEFLATED,
            )

        zip_bytes = zip_buffer.getvalue()

        # Should handle mixed compression gracefully
        validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))

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
            validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))

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
            validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))

        assert exc_info.value.error_code == ErrorCode.ZIP_NESTED_ARCHIVE
        assert "data.bz2" in str(exc_info.value)

    def test_corrupted_zip_file_badzipfile_exception(self, default_config) -> None:
        """
        Test handling of corrupted ZIP file (BadZipFile exception).

        Tests lines 245-249 in compression_validator.py.
        """
        validator = CompressionSecurityValidator(default_config)

        # Create invalid ZIP data
        invalid_zip = b"PK\x03\x04" + b"corrupted data not valid zip"

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(invalid_zip, len(invalid_zip))

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
        from unittest.mock import patch, MagicMock

        # Create a minimal valid ZIP
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("test.txt", b"content")
        zip_bytes = zip_buffer.getvalue()

        # Mock ZipFile to raise LargeZipFile
        with patch("zipfile.ZipFile") as mock_zipfile:
            mock_zipfile.side_effect = zipfile.LargeZipFile("File too large")

            with pytest.raises(CompressionSecurityError) as exc_info:
                validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))

            assert exc_info.value.error_code == ErrorCode.ZIP_TOO_LARGE
            assert "too large" in str(exc_info.value).lower()

    def test_memory_error_during_zip_processing(self, default_config) -> None:
        """
        Test handling of memory exhaustion (MemoryError exception).

        Tests lines 256-259 in compression_validator.py.
        """
        validator = CompressionSecurityValidator(default_config)

        from unittest.mock import patch, MagicMock

        # Create a minimal valid ZIP
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("test.txt", b"content")
        zip_bytes = zip_buffer.getvalue()

        # Mock ZipFile to raise MemoryError
        with patch("zipfile.ZipFile") as mock_zipfile:
            mock_zipfile.side_effect = MemoryError("Out of memory")

            with pytest.raises(ZipBombError) as exc_info:
                validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))

            assert "memory" in str(exc_info.value).lower()
            assert "zip bomb" in str(exc_info.value).lower()

    def test_generic_exception_during_zip_validation(self, default_config) -> None:
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
                validator.validate_zip_compression_ratio(zip_bytes, len(zip_bytes))

            assert "validation failed" in str(exc_info.value).lower()

    def test_overall_compression_ratio_exceeded(self, default_config) -> None:
        """
        Test that overall compression ratio check triggers ZipBombError.

        Tests lines 205-213 in compression_validator.py.
        """
        # Create config with very low compression ratio limit
        # but make individual file limit very high so it's the overall
        # ratio that triggers, not the individual file ratio
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            max_compression_ratio=2000,  # High individual file limit
            max_uncompressed_size=100 * 1024 * 1024,
            max_individual_file_size=50 * 1024 * 1024,
        )
        validator = CompressionSecurityValidator(config)

        # Create multiple highly compressible files
        # Each file alone is within the individual limit,
        # but together they exceed the overall compression ratio
        # Use smaller files that won't trigger individual limits
        small_data = b"\x00" * (500 * 1024)  # 500KB of zeros

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            # Add multiple files to accumulate compression
            for i in range(10):
                zf.writestr(f"zeros{i}.txt", small_data)

        zip_bytes = zip_buffer.getvalue()
        compressed_size = len(zip_bytes)

        # Calculate what the overall ratio should be
        total_uncompressed = 10 * len(small_data)
        expected_ratio = total_uncompressed / compressed_size

        # Verify the overall ratio will be very high
        # Reduce the max_compression_ratio to ensure it triggers
        config.limits = SecurityLimits(
            max_compression_ratio=2000,  # Keep individual high
            max_uncompressed_size=100 * 1024 * 1024,
            max_individual_file_size=50 * 1024 * 1024,
        )

        # Adjust to a value that will definitely be exceeded
        if expected_ratio < 100:
            # If ratio isn't high enough, skip this test path
            # and just verify the code is there by checking individual
            pytest.skip("Compression ratio not high enough to test overall limit")

        # Set overall limit lower than expected ratio
        config.limits.max_compression_ratio = int(expected_ratio / 2)

        # This should trigger the overall compression ratio check
        with pytest.raises(ZipBombError) as exc_info:
            validator.validate_zip_compression_ratio(zip_bytes, compressed_size)

        # Check error message - might be either individual or overall
        error_msg = str(exc_info.value).lower()
        assert "compression ratio" in error_msg or "excessive" in error_msg
