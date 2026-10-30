"""Tests for CompressionSecurityValidator."""

import io
import struct
import types
import zipfile

import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.exceptions import (
    CompressionSecurityError,
    ErrorCode,
    FileProcessingError,
    ResourceLimitError,
    ZipBombError,
)
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

    def test_prefixed_archive_at_limit_accepted(self):
        """Data before the archive does not change its count."""
        data = _STUB + _zip_with_entries(20)
        _entry_limit_validator(20).validate_zip_compression_ratio(
            io.BytesIO(data), len(data)
        )

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


def _with_declared_sizes(
    data: bytes, compress_size: int, file_size: int
) -> bytes:
    """Rewrite the sizes declared by every central-directory record."""
    buf = bytearray(data)
    pos = buf.find(b"PK\x01\x02")
    while pos != -1:
        struct.pack_into("<LL", buf, pos + 20, compress_size, file_size)
        pos = buf.find(b"PK\x01\x02", pos + 4)
    return bytes(buf)


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
        data = _with_declared_sizes(_stored_zip(["a.bin"]), 100, 1000)
        validator = _limits_validator(max_compression_ratio=10)

        validator.validate_zip_compression_ratio(io.BytesIO(data), 10_000)

    def test_entry_ratio_over_limit_rejected(self):
        """A declared 1001:100 entry is above 10:1 and is rejected."""
        data = _with_declared_sizes(_stored_zip(["a.bin"]), 100, 1001)
        validator = _limits_validator(max_compression_ratio=10)

        with pytest.raises(ZipBombError) as exc_info:
            validator.validate_zip_compression_ratio(io.BytesIO(data), 10_000)

        assert (
            exc_info.value.error_code == ErrorCode.COMPRESSION_RATIO_EXCEEDED
        )
        assert "for 'a.bin'" in str(exc_info.value)

    def test_overall_ratio_at_limit_accepted(self):
        """1000 bytes over a 100-byte archive is exactly 10:1."""
        data = _with_declared_sizes(_stored_zip(["a.bin"]), 1000, 1000)
        validator = _limits_validator(max_compression_ratio=10)

        validator.validate_zip_compression_ratio(io.BytesIO(data), 100)

    def test_overall_ratio_over_limit_rejected(self):
        """1000 bytes over a 99-byte archive is above 10:1."""
        data = _with_declared_sizes(_stored_zip(["a.bin"]), 1000, 1000)
        validator = _limits_validator(max_compression_ratio=10)

        with pytest.raises(ZipBombError) as exc_info:
            validator.validate_zip_compression_ratio(io.BytesIO(data), 99)

        assert (
            exc_info.value.error_code == ErrorCode.COMPRESSION_RATIO_EXCEEDED
        )
        assert "Overall" in str(exc_info.value)

    def test_individual_size_at_limit_accepted(self):
        """An entry declaring exactly the individual limit passes."""
        data = _with_declared_sizes(_stored_zip(["a.bin"]), 1000, 1000)
        validator = _limits_validator(max_individual_file_size=1000)

        validator.validate_zip_compression_ratio(io.BytesIO(data), 1000)

    def test_individual_size_over_limit_rejected(self):
        """An entry declaring one byte over the limit is rejected."""
        data = _with_declared_sizes(_stored_zip(["a.bin"]), 1001, 1001)
        validator = _limits_validator(max_individual_file_size=1000)

        with pytest.raises(CompressionSecurityError) as exc_info:
            validator.validate_zip_compression_ratio(io.BytesIO(data), 1001)

        assert exc_info.value.error_code == ErrorCode.FILE_TOO_LARGE

    def test_total_uncompressed_at_limit_accepted(self):
        """Two 500-byte entries total exactly the 1000-byte limit."""
        data = _with_declared_sizes(_stored_zip(["a.bin", "b.bin"]), 500, 500)
        validator = _limits_validator(
            max_uncompressed_size=1000, max_individual_file_size=600
        )

        validator.validate_zip_compression_ratio(io.BytesIO(data), 1000)

    def test_total_uncompressed_over_limit_rejected(self):
        """Entries totalling 1001 bytes exceed a 1000-byte limit."""
        data = _stored_zip(["a.bin", "b.bin"])
        first = _with_declared_sizes(data, 500, 500)
        second = bytearray(first)
        # Raise only the second record's declared sizes to 501
        pos = second.rfind(b"PK\x01\x02")
        struct.pack_into("<LL", second, pos + 20, 501, 501)
        validator = _limits_validator(
            max_uncompressed_size=1000, max_individual_file_size=600
        )

        with pytest.raises(ZipBombError) as exc_info:
            validator.validate_zip_compression_ratio(
                io.BytesIO(bytes(second)), 1001
            )

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
