"""Shared pytest fixtures for safeuploads tests."""

import io
import zipfile
from collections.abc import Callable

import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.utils import ResourceMonitor
from tests import images


@pytest.fixture
def default_config() -> FileSecurityConfig:
    """
    Provide default FileSecurityConfig for testing.

    Returns:
        Default FileSecurityConfig instance.
    """
    return FileSecurityConfig()


@pytest.fixture
def custom_config() -> FileSecurityConfig:
    """
    Provide custom FileSecurityConfig for testing edge cases.

    Returns:
        FileSecurityConfig with custom limits.
    """
    config = FileSecurityConfig()
    config.limits = SecurityLimits(
        max_image_size=5 * 1024 * 1024,  # 5MB
        max_zip_size=10 * 1024 * 1024,  # 10MB
        max_compression_ratio=50,
        max_uncompressed_size=50 * 1024 * 1024,  # 50MB
        max_zip_entries=100,
        max_zip_depth=5,
    )
    return config


@pytest.fixture
def mock_upload_file():
    """
    Create a mock UploadFile-like object for testing.

    Returns:
        Mock file object with required attributes and methods.
    """

    class MockUploadFile:
        """Mock implementation of UploadFile protocol."""

        def __init__(
            self, filename: str, content: bytes, size: int | None = None
        ):
            self.filename = filename
            self.content = content
            self.size = size or len(content)
            self._position = 0

        async def read(self, size: int = -1) -> bytes:
            """
            Read file content.

            Args:
                size: Number of bytes to read (-1 for all).

            Returns:
                File content bytes.
            """
            if size == -1:
                result = self.content[self._position :]
                self._position = len(self.content)
            else:
                result = self.content[self._position : self._position + size]
                self._position += len(result)
            return result

        async def seek(self, offset: int) -> int:
            """
            Seek to position in file.

            Args:
                offset: Position to seek to.

            Returns:
                New position.
            """
            self._position = offset
            return self._position

    return MockUploadFile


@pytest.fixture
def valid_jpeg_bytes() -> bytes:
    """
    Provide valid JPEG file bytes.

    Returns:
        SOI, APP0, a 1x1 frame header and EOI.
    """
    return images.jpeg()


@pytest.fixture
def valid_png_bytes() -> bytes:
    """
    Provide valid PNG file bytes.

    Returns:
        Signature, a 1x1 IHDR chunk and IEND.
    """
    return images.png()


@pytest.fixture
def valid_webp_bytes() -> bytes:
    """
    Provide valid WebP file bytes.

    Returns:
        RIFF header and a 1x1 lossless VP8L chunk.
    """
    return images.webp()


@pytest.fixture
def create_zip_file():
    """
    Factory fixture to create ZIP files with custom content.

    Returns:
        Function to create ZIP bytes with specified files.
    """

    def _create_zip(
        files: dict[str, bytes] | None = None,
        compression: int = zipfile.ZIP_STORED,
    ) -> bytes:
        """
        Create a ZIP file with specified content.

        Args:
            files: Dict mapping filenames to content bytes.
            compression: ZIP compression method.

        Returns:
            ZIP file as bytes.
        """
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(
            zip_buffer, "w", compression=compression
        ) as zip_file:
            if files:
                for filename, content in files.items():
                    zip_file.writestr(filename, content)
            else:
                # Create a minimal valid ZIP with one file
                zip_file.writestr("test.txt", b"Hello, World!")
        return zip_buffer.getvalue()

    return _create_zip


@pytest.fixture
def dangerous_unicode_filename() -> str:
    """
    Provide filename with dangerous Unicode characters.

    Returns:
        Filename containing right-to-left override character.
    """
    # Right-to-left override (U+202E) - can disguise file extensions
    return "document\u202etxt.exe"


class FakeClock:
    """
    Monotonic clock for ``safeuploads.utils`` that tests drive.

    Time stands still until ``advancing`` is set; from then on
    every reading moves the clock forward by ``step`` seconds.

    Attributes:
        now: Current clock reading in seconds.
        step: Seconds added per reading while advancing.
        advancing: Whether readings move the clock forward.
    """

    def __init__(self, step: float = 1.0) -> None:
        self.now = 1000.0
        self.step = step
        self.advancing = False

    def monotonic(self) -> float:
        """
        Return the clock reading, advancing it when enabled.

        Returns:
            The current reading in seconds.
        """
        if self.advancing:
            self.now += self.step
        return self.now

    def run_monitored(
        self, work: Callable[[], object], max_time_seconds: float = 10.0
    ) -> None:
        """
        Run ``work`` in a ResourceMonitor while the clock advances.

        Args:
            work: Callable doing the monitored work.
            max_time_seconds: Time limit of the monitor.
        """
        with ResourceMonitor(max_time_seconds=max_time_seconds):
            self.advancing = True
            work()


@pytest.fixture
def fake_clock(monkeypatch) -> FakeClock:
    """
    Replace the clock ``ResourceMonitor`` reads with a FakeClock.

    Only ``safeuploads.utils`` sees the fake clock; asyncio and
    the rest of the package keep the real one.

    Args:
        monkeypatch: pytest monkeypatch fixture.

    Returns:
        The installed FakeClock.
    """
    clock = FakeClock()
    monkeypatch.setattr("safeuploads.utils.time", clock)
    return clock
