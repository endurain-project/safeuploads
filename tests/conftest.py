"""Shared pytest fixtures for safeuploads tests."""

import io
import zipfile
from typing import AsyncIterator

import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits


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
        Minimal valid JPEG file content.
    """
    # Minimal valid JPEG: SOI marker + APP0 segment + EOI marker
    return (
        b"\xff\xd8\xff\xe0"  # JPEG SOI + APP0
        b"\x00\x10"  # APP0 length
        b"JFIF\x00"  # JFIF identifier
        b"\x01\x01"  # Version 1.1
        b"\x00"  # Density units
        b"\x00\x01\x00\x01"  # X and Y density
        b"\x00\x00"  # Thumbnail dimensions
        b"\xff\xd9"  # JPEG EOI
    )


@pytest.fixture
def valid_png_bytes() -> bytes:
    """
    Provide valid PNG file bytes.

    Returns:
        Minimal valid PNG file content.
    """
    # Minimal valid PNG: signature + IHDR + IEND
    return (
        b"\x89PNG\r\n\x1a\n"  # PNG signature
        b"\x00\x00\x00\x0d"  # IHDR chunk length
        b"IHDR"  # IHDR chunk type
        b"\x00\x00\x00\x01"  # Width: 1
        b"\x00\x00\x00\x01"  # Height: 1
        b"\x08\x02"  # Bit depth: 8, Color type: 2 (RGB)
        b"\x00\x00\x00"  # Compression, filter, interlace
        b"\x90\x77\x53\xde"  # IHDR CRC
        b"\x00\x00\x00\x00"  # IEND chunk length
        b"IEND"  # IEND chunk type
        b"\xae\x42\x60\x82"  # IEND CRC
    )


@pytest.fixture
def create_zip_file():
    """
    Factory fixture to create ZIP files with custom content.

    Returns:
        Function to create ZIP bytes with specified files.
    """

    def _create_zip(
        files: dict[str, bytes] | None = None, compression: int = zipfile.ZIP_STORED
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
    return "document\u202Etxt.exe"


@pytest.fixture
def windows_reserved_filenames() -> list[str]:
    """
    Provide list of Windows reserved device names.

    Returns:
        List of reserved Windows filenames.
    """
    return [
        "CON.jpg",
        "PRN.txt",
        "AUX.png",
        "NUL.zip",
        "COM1.doc",
        "LPT1.pdf",
    ]


@pytest.fixture
def dangerous_extensions() -> list[str]:
    """
    Provide list of dangerous file extensions.

    Returns:
        List of extensions that should be blocked.
    """
    return [
        ".exe",
        ".bat",
        ".cmd",
        ".sh",
        ".js",
        ".vbs",
        ".dll",
        ".scr",
        ".msi",
    ]


@pytest.fixture
def compound_dangerous_extensions() -> list[str]:
    """
    Provide list of compound dangerous extensions.

    Returns:
        List of compound extensions that should be blocked.
    """
    return [".tar.gz", ".tar.xz", ".user.js", ".html.js"]
