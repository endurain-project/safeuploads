"""Shared pytest fixtures for safeuploads tests."""

import io
import random
import zipfile

import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits

# Baseline SOF0 frame header declaring a 16x16 image. Real JPEGs
# always carry a start-of-frame segment; without one the decoded
# dimensions are unknown and validation rejects the file.
JPEG_SOF0 = (
    b"\xff\xc0"  # SOF0 marker
    b"\x00\x11"  # Segment length (17)
    b"\x08"  # Sample precision
    b"\x00\x10"  # Height
    b"\x00\x10"  # Width
    b"\x03"  # Component count
    b"\x01\x11\x00\x02\x11\x01\x03\x11\x01"  # Component specs
)

# Structurally valid payload headers. Content analysis only
# reports a short magic when the header it introduces is well
# formed, so a bare `MZ` or `\x7fELF` is not a usable fixture.
PE_EXECUTABLE = (
    b"MZ"
    + b"\x00" * 0x3A
    + (0x40).to_bytes(4, "little")  # e_lfanew -> PE header
    + b"PE\x00\x00"
    + (0x8664).to_bytes(2, "little")  # Machine: x86-64
    + b"\x00" * 18
)

ELF_EXECUTABLE = (
    b"\x7fELF"
    b"\x02"  # EI_CLASS: 64-bit
    b"\x01"  # EI_DATA: little-endian
    b"\x01" + b"\x00" * 25  # EI_VERSION
)

MACHO_EXECUTABLE = (
    b"\xcf\xfa\xed\xfe"  # MH_CIGAM_64
    + (0x0100000C).to_bytes(4, "little")  # cputype: ARM64
    + (0).to_bytes(4, "little")  # cpusubtype
    + (2).to_bytes(4, "little")  # filetype: MH_EXECUTE
    + b"\x00" * 16
)

JAVA_CLASS = (
    b"\xca\xfe\xba\xbe"
    + (0).to_bytes(2, "big")  # minor version
    + (61).to_bytes(2, "big")  # major version: Java 17
    + b"\x00" * 16
)

WINDOWS_SHORTCUT = (
    b"L\x00\x00\x00"  # ShellLinkHeader size
    b"\x01\x14\x02\x00\x00\x00\x00\x00"
    b"\xc0\x00\x00\x00\x00\x00\x00\x46" + b"\x00" * 16  # LinkCLSID
)

ZIP_LOCAL_HEADER = (
    b"PK\x03\x04"
    + (20).to_bytes(2, "little")  # Version needed
    + b"\x00\x00"  # Flags
    + (8).to_bytes(2, "little")  # Method: deflate
    + b"\x00" * 16
)


def entropy_bytes(size: int, seed: int = 0) -> bytes:
    """
    Build reproducible high-entropy filler.

    Models the entropy-coded body of a real photo, where every
    two-byte sequence occurs roughly once per 64 KB.

    Args:
        size: Number of bytes to produce.
        seed: Seed making the output reproducible.

    Returns:
        Pseudo-random bytes of the requested length.
    """
    return random.Random(seed).randbytes(size)


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
            self.size = size if size is not None else len(content)
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
    # Minimal valid JPEG: SOI marker + APP0 segment + SOF0 frame
    # header + EOI marker
    return (
        b"\xff\xd8\xff\xe0"  # JPEG SOI + APP0
        b"\x00\x10"  # APP0 length
        b"JFIF\x00"  # JFIF identifier
        b"\x01\x01"  # Version 1.1
        b"\x00"  # Density units
        b"\x00\x01\x00\x01"  # X and Y density
        b"\x00\x00"  # Thumbnail dimensions
        + JPEG_SOF0
        + b"\xff\xd9"  # JPEG EOI
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
