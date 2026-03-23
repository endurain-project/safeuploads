"""
Framework-agnostic protocols for file upload handling.

This module defines protocols that allow safeuploads to work with any
web framework's file upload implementation without depending on specific
framework packages.
"""

from typing import Protocol, runtime_checkable


@runtime_checkable
class SeekableFile(Protocol):
    """
    Protocol for seekable binary file-like objects.

    Implemented by BytesIO, SpooledTemporaryFile, and regular
    file objects opened in binary mode.

    Attributes:
        read: Read bytes from the file.
        seek: Move file pointer to specified position.
        tell: Return current file pointer position.
    """

    def read(self, size: int = -1) -> bytes:
        """
        Read bytes from the file.

        Args:
            size: Number of bytes to read. -1 reads all.

        Returns:
            Bytes read from the file.
        """
        ...

    def seek(self, offset: int, whence: int = 0) -> int:
        """
        Move file pointer to specified position.

        Args:
            offset: Position offset in bytes.
            whence: Reference point for offset (0=start,
                1=current, 2=end).

        Returns:
            New absolute position in the file.
        """
        ...

    def tell(self) -> int:
        """
        Return current file pointer position.

        Returns:
            Current position in the file.
        """
        ...


@runtime_checkable
class UploadFileProtocol(Protocol):
    """
    Protocol for file upload objects from any web framework.

    This protocol defines the minimal interface required for file
    validation. Any object with these attributes and methods can be
    validated, regardless of the web framework being used.

    Attributes:
        filename: Original filename from the client.
        size: Size of the uploaded file in bytes.
    """

    filename: str | None
    size: int | None

    async def read(self, size: int = -1) -> bytes:
        """
        Read bytes from the uploaded file.

        Args:
            size: Number of bytes to read. -1 reads entire file.

        Returns:
            Bytes read from the file.
        """
        ...

    async def seek(self, offset: int) -> int:
        """
        Move file pointer to specified position.

        Args:
            offset: Position to move to in bytes.

        Returns:
            New position in the file.
        """
        ...
