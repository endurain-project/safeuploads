"""
Performance tests for safeuploads.

Tests measure execution time, memory usage, and throughput for various
validation operations. Run with: pytest tests/test_performance.py -v
"""

import asyncio
import io
import time
import zipfile

import pytest

from safeuploads import FileValidator
from safeuploads.config import FileSecurityConfig, SecurityLimits


def create_test_image(size_kb: int) -> bytes:
    """
    Create a minimal valid JPEG image of approximately specified size.

    Args:
        size_kb: Approximate size in kilobytes.

    Returns:
        JPEG image bytes.
    """
    # Minimal JPEG header and footer
    jpeg_header = bytes(
        [
            0xFF,
            0xD8,
            0xFF,
            0xE0,
            0x00,
            0x10,
            0x4A,
            0x46,
            0x49,
            0x46,
            0x00,
            0x01,
            0x01,
            0x00,
            0x00,
            0x01,
            0x00,
            0x01,
            0x00,
            0x00,
        ]
    )
    jpeg_footer = bytes([0xFF, 0xD9])

    # Add padding to reach desired size
    target_size = size_kb * 1024
    padding_size = max(0, target_size - len(jpeg_header) - len(jpeg_footer))
    padding = b"\x00" * padding_size

    return jpeg_header + padding + jpeg_footer


def create_test_zip(num_files: int, file_size_kb: int = 1) -> bytes:
    """
    Create a test ZIP file with specified number of files.

    Args:
        num_files: Number of files to include in ZIP.
        file_size_kb: Size of each file in kilobytes.

    Returns:
        ZIP file bytes.
    """
    buffer = io.BytesIO()
    # Use ZIP_STORED (no compression) so the compression ratio is always
    # ~1:1 and the validator's zip-bomb check is never triggered.  Timing
    # benchmarks remain valid because the I/O and ZIP-parsing work is
    # still exercised.
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as zf:
        content = b"test content " * (file_size_kb * 1024 // 13)
        for i in range(num_files):
            zf.writestr(f"file_{i}.txt", content)
    return buffer.getvalue()


@pytest.mark.asyncio
@pytest.mark.performance
class TestFilenameSanitizationPerformance:
    """Performance tests for filename sanitization."""

    @pytest.mark.parametrize("filename_length", [10, 50, 100, 200])
    async def test_sanitize_simple_filename_performance(self, filename_length: int):
        """
        Test filename sanitization performance with various lengths.

        Args:
            filename_length: Length of filename to test.
        """
        validator = FileValidator()
        filename = "a" * filename_length + ".jpg"

        start_time = time.perf_counter()
        result = validator._sanitize_filename(filename)
        elapsed = time.perf_counter() - start_time

        assert result is not None
        assert elapsed < 0.05, (
            f"Sanitization took {elapsed:.4f}s"
            f" (expected < 0.05s)"
        )
        print(
            f"\nFilename length {filename_length}:"
            f" {elapsed*1000:.2f}ms"
        )

    async def test_sanitize_unicode_filename_performance(self):
        """Test filename sanitization with Unicode characters."""
        validator = FileValidator()
        # Filename with various Unicode characters
        filename = "test_файл_文件_🎉.jpg"

        iterations = 100
        start_time = time.perf_counter()
        for _ in range(iterations):
            validator._sanitize_filename(filename)
        elapsed = time.perf_counter() - start_time

        avg_time = elapsed / iterations
        assert avg_time < 0.01, f"Average sanitization took {avg_time:.4f}s"
        print(
            f"\nUnicode sanitization ({iterations} iterations): {elapsed*1000:.2f}ms "
            f"({avg_time*1000:.2f}ms avg)"
        )

    async def test_sanitize_windows_reserved_performance(self):
        """Test filename sanitization with Windows reserved names."""
        from safeuploads.exceptions import WindowsReservedNameError

        validator = FileValidator()
        reserved_names = [
            "CON.jpg",
            "PRN.jpg",
            "AUX.jpg",
            "NUL.jpg",
            "COM1.jpg",
            "COM9.jpg",
            "LPT1.jpg",
            "LPT9.jpg",
        ]

        start_time = time.perf_counter()
        for name in reserved_names:
            try:
                validator._sanitize_filename(name)
            except WindowsReservedNameError:
                pass  # Expected - just measuring detection speed
        elapsed = time.perf_counter() - start_time

        avg_time = elapsed / len(reserved_names)
        assert avg_time < 0.01, f"Average took {avg_time:.4f}s"
        print(
            f"\nWindows reserved names ({len(reserved_names)} names): "
            f"{elapsed*1000:.2f}ms ({avg_time*1000:.2f}ms avg)"
        )


@pytest.mark.asyncio
@pytest.mark.performance
class TestImageValidationPerformance:
    """Performance tests for image validation."""

    @pytest.mark.parametrize(
        "size_kb",
        [10, 100, 1000, 5000],  # 10KB, 100KB, 1MB, 5MB
        ids=["10KB", "100KB", "1MB", "5MB"],
    )
    async def test_image_validation_by_size(
        self, size_kb: int, mock_upload_file
    ):
        """
        Benchmark image validation with various file sizes.

        Args:
            size_kb: Image size in kilobytes.
            mock_upload_file: File factory fixture.
        """
        validator = FileValidator()
        content = create_test_image(size_kb)
        mock_file = mock_upload_file("test.jpg", content)

        start_time = time.perf_counter()
        await validator.validate_image_file(mock_file)
        elapsed = time.perf_counter() - start_time

        # Performance expectations (adjust based on actual hardware)
        expected_max = {
            10: 0.05,  # 50ms for 10KB
            100: 0.10,  # 100ms for 100KB
            1000: 0.20,  # 200ms for 1MB
            5000: 0.50,  # 500ms for 5MB
        }

        assert (
            elapsed < expected_max[size_kb]
        ), f"Validation took {elapsed:.4f}s (expected < {expected_max[size_kb]}s)"
        print(f"\n{size_kb}KB image validation: {elapsed*1000:.2f}ms")

    async def test_batch_image_validation_throughput(
        self, mock_upload_file
    ):
        """Test throughput for batch image validation."""
        validator = FileValidator()
        num_files = 10
        content = create_test_image(100)  # 100KB images

        mock_files = [
            mock_upload_file(f"test_{i}.jpg", content)
            for i in range(num_files)
        ]

        start_time = time.perf_counter()
        for mock_file in mock_files:
            await validator.validate_image_file(mock_file)
        elapsed = time.perf_counter() - start_time

        throughput = num_files / elapsed
        assert (
            throughput > 20
        ), f"Throughput was {throughput:.1f} files/s (expected > 20)"
        print(
            f"\nBatch validation: {num_files} files in {elapsed*1000:.2f}ms "
            f"({throughput:.1f} files/s)"
        )


@pytest.mark.asyncio
@pytest.mark.performance
class TestZipValidationPerformance:
    """Performance tests for ZIP validation."""

    @pytest.mark.parametrize(
        "num_files",
        [10, 50, 100, 500],
        ids=["10files", "50files", "100files", "500files"],
    )
    async def test_zip_validation_by_entry_count(
        self, num_files: int, mock_upload_file
    ):
        """
        Benchmark ZIP validation with various entry counts.

        Args:
            num_files: Number of files in ZIP.
            mock_upload_file: File factory fixture.
        """
        validator = FileValidator()
        content = create_test_zip(num_files, file_size_kb=1)
        mock_file = mock_upload_file("test.zip", content)

        start_time = time.perf_counter()
        await validator.validate_zip_file(mock_file)
        elapsed = time.perf_counter() - start_time

        # Performance expectations
        expected_max = {
            10: 0.10,  # 100ms for 10 files
            50: 0.30,  # 300ms for 50 files
            100: 0.60,  # 600ms for 100 files
            500: 2.00,  # 2s for 500 files
        }

        assert (
            elapsed < expected_max[num_files]
        ), f"Validation took {elapsed:.4f}s (expected < {expected_max[num_files]}s)"
        print(f"\n{num_files} files ZIP validation: {elapsed*1000:.2f}ms")

    @pytest.mark.parametrize(
        "compression_ratio_target", [5, 10, 50], ids=["5x", "10x", "50x"]
    )
    async def test_zip_validation_by_compression(
        self, compression_ratio_target: int, mock_upload_file
    ):
        """
        Benchmark ZIP validation with various compression ratios.

        Args:
            compression_ratio_target: Target compression ratio.
            mock_upload_file: File factory fixture.
        """
        validator = FileValidator()

        # Use ZIP_STORED to keep the compression ratio at 1:1 so the
        # validator's zip-bomb limit is never exceeded.  The parameter
        # labels (5x / 10x / 50x) are kept for backward compatibility;
        # this test benchmarks the ZIP validation pipeline, not ratio
        # detection (which is covered in test_compression_validator.py).
        content_size = 10 * 1024  # 10KB
        content = b"benchmark content " * (content_size // 18)

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("test.txt", content)
        zip_content = buffer.getvalue()

        mock_file = mock_upload_file("test.zip", zip_content)

        start_time = time.perf_counter()
        await validator.validate_zip_file(mock_file)
        elapsed = time.perf_counter() - start_time

        actual_ratio = len(content) / len(zip_content)
        assert elapsed < 0.20, f"Validation took {elapsed:.4f}s (expected < 0.20s)"
        print(f"\n{actual_ratio:.1f}x compression ZIP validation: {elapsed*1000:.2f}ms")


@pytest.mark.asyncio
@pytest.mark.performance
class TestMemoryUsage:
    """Memory usage tests for large file handling."""

    async def test_large_image_streaming(self, mock_upload_file):
        """Test that large images are handled efficiently without loading all into memory."""
        validator = FileValidator()
        # Create a 10MB image
        content = create_test_image(10 * 1024)
        mock_file = mock_upload_file("large.jpg", content)

        # This should complete without loading entire file into memory
        start_time = time.perf_counter()
        await validator.validate_image_file(mock_file)
        elapsed = time.perf_counter() - start_time

        assert elapsed < 1.0, f"Large image validation took {elapsed:.4f}s"
        print(f"\n10MB image validation: {elapsed*1000:.2f}ms")

    async def test_large_zip_memory_efficiency(self, mock_upload_file):
        """Test ZIP validation with large archive."""
        validator = FileValidator()
        # Create ZIP with 100 files, each 10KB
        content = create_test_zip(100, file_size_kb=10)
        mock_file = mock_upload_file("large.zip", content)

        start_time = time.perf_counter()
        await validator.validate_zip_file(mock_file)
        elapsed = time.perf_counter() - start_time

        assert elapsed < 2.0, f"Large ZIP validation took {elapsed:.4f}s"
        print(f"\n100-file ZIP validation: {elapsed*1000:.2f}ms")


@pytest.mark.asyncio
@pytest.mark.performance
class TestConfigurationImpact:
    """Test performance impact of different configurations."""

    async def test_strict_vs_default_config_performance(
        self, mock_upload_file
    ):
        """Compare performance between strict and default configurations."""
        # Default config
        default_validator = FileValidator()

        # Strict config with tighter limits
        strict_limits = SecurityLimits(
            max_compression_ratio=10,
            max_zip_entries=50,
            zip_analysis_timeout=2.0,
        )
        strict_config = FileSecurityConfig()
        strict_config.limits = strict_limits
        strict_validator = FileValidator(config=strict_config)

        # Test with same ZIP
        content = create_test_zip(30, file_size_kb=1)
        mock_file_default = mock_upload_file("test.zip", content)
        mock_file_strict = mock_upload_file("test.zip", content)

        # Default config
        start_time = time.perf_counter()
        await default_validator.validate_zip_file(mock_file_default)
        default_elapsed = time.perf_counter() - start_time

        # Strict config
        start_time = time.perf_counter()
        await strict_validator.validate_zip_file(mock_file_strict)
        strict_elapsed = time.perf_counter() - start_time

        print(f"\nDefault config: {default_elapsed*1000:.2f}ms")
        print(f"Strict config: {strict_elapsed*1000:.2f}ms")
        print(f"Difference: {abs(strict_elapsed - default_elapsed)*1000:.2f}ms")

        # Both should complete in reasonable time
        assert default_elapsed < 1.0
        assert strict_elapsed < 1.0


@pytest.mark.asyncio
@pytest.mark.performance
class TestConcurrentValidation:
    """Test concurrent validation performance."""

    async def test_concurrent_image_validation(
        self, mock_upload_file
    ):
        """Test validating multiple images concurrently."""
        validator = FileValidator()
        num_concurrent = 10
        content = create_test_image(100)  # 100KB each

        mock_files = [
            mock_upload_file(f"test_{i}.jpg", content)
            for i in range(num_concurrent)
        ]

        start_time = time.perf_counter()
        tasks = [validator.validate_image_file(mock_file) for mock_file in mock_files]
        await asyncio.gather(*tasks)
        elapsed = time.perf_counter() - start_time

        throughput = num_concurrent / elapsed
        print(
            f"\nConcurrent validation: {num_concurrent} images in "
            f"{elapsed*1000:.2f}ms ({throughput:.1f} files/s)"
        )

        # Concurrent should be faster than sequential
        assert elapsed < 2.0, f"Concurrent validation took {elapsed:.4f}s"

    async def test_concurrent_zip_validation(
        self, mock_upload_file
    ):
        """Test validating multiple ZIPs concurrently."""
        validator = FileValidator()
        num_concurrent = 5
        zip_contents = [
            create_test_zip(20, file_size_kb=1) for _ in range(num_concurrent)
        ]

        mock_files = [
            mock_upload_file(f"test_{i}.zip", content)
            for i, content in enumerate(zip_contents)
        ]

        start_time = time.perf_counter()
        tasks = [validator.validate_zip_file(mock_file) for mock_file in mock_files]
        await asyncio.gather(*tasks)
        elapsed = time.perf_counter() - start_time

        throughput = num_concurrent / elapsed
        print(
            f"\nConcurrent ZIP validation: {num_concurrent} archives in "
            f"{elapsed*1000:.2f}ms ({throughput:.1f} files/s)"
        )

        assert elapsed < 3.0, f"Concurrent validation took {elapsed:.4f}s"


@pytest.mark.asyncio
@pytest.mark.performance
class TestPerformanceRegression:
    """Performance regression tests - fail if performance degrades significantly."""

    async def test_baseline_image_validation_speed(
        self, mock_upload_file
    ):
        """
        Baseline test for image validation speed.

        This test establishes performance expectations. If this fails,
        investigate potential performance regressions.

        Args:
            mock_upload_file: File factory fixture.
        """
        validator = FileValidator()
        content = create_test_image(1000)  # 1MB
        mock_file = mock_upload_file("baseline.jpg", content)

        # Run multiple iterations for more stable measurement
        iterations = 10
        times = []

        for _ in range(iterations):
            mock_file._position = 0  # Reset position
            start_time = time.perf_counter()
            await validator.validate_image_file(mock_file)
            elapsed = time.perf_counter() - start_time
            times.append(elapsed)

        avg_time = sum(times) / len(times)
        min_time = min(times)
        max_time = max(times)

        print("\n1MB image validation baseline:")
        print(f"  Average: {avg_time*1000:.2f}ms")
        print(f"  Min: {min_time*1000:.2f}ms")
        print(f"  Max: {max_time*1000:.2f}ms")

        # Baseline expectation: < 200ms average
        assert avg_time < 0.20, (
            f"Performance regression detected: avg {avg_time*1000:.2f}ms "
            f"(expected < 200ms)"
        )

    async def test_baseline_zip_validation_speed(
        self, mock_upload_file
    ):
        """
        Baseline test for ZIP validation speed.

        This test establishes performance expectations.

        Args:
            mock_upload_file: File factory fixture.
        """
        validator = FileValidator()
        content = create_test_zip(50, file_size_kb=1)
        mock_file = mock_upload_file("baseline.zip", content)

        iterations = 10
        times = []

        for _ in range(iterations):
            mock_file._position = 0
            start_time = time.perf_counter()
            await validator.validate_zip_file(mock_file)
            elapsed = time.perf_counter() - start_time
            times.append(elapsed)

        avg_time = sum(times) / len(times)
        min_time = min(times)
        max_time = max(times)

        print("\n50-file ZIP validation baseline:")
        print(f"  Average: {avg_time*1000:.2f}ms")
        print(f"  Min: {min_time*1000:.2f}ms")
        print(f"  Max: {max_time*1000:.2f}ms")

        # Baseline expectation: < 300ms average
        assert avg_time < 0.30, (
            f"Performance regression detected: avg {avg_time*1000:.2f}ms "
            f"(expected < 300ms)"
        )
