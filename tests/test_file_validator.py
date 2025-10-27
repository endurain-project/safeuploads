"""Tests for FileValidator integration."""

import io
import pytest

from safeuploads.file_validator import FileValidator
from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.exceptions import (
    FilenameSecurityError,
    ExtensionSecurityError,
    FileSizeError,
    MimeTypeError,
    FileSignatureError,
    FileProcessingError,
    UnicodeSecurityError,
    WindowsReservedNameError,
    ZipBombError,
    ZipContentError,
    CompressionSecurityError,
    ErrorCode,
)


class TestFileValidatorInitialization:
    """Test FileValidator initialization."""

    def test_initialization_with_default_config(self):
        """Test validator initialization with default configuration."""
        validator = FileValidator()

        assert validator.config is not None
        assert isinstance(validator.config, FileSecurityConfig)
        assert validator.unicode_validator is not None
        assert validator.extension_validator is not None
        assert validator.windows_validator is not None
        assert validator.compression_validator is not None
        assert validator.zip_inspector is not None

    def test_initialization_with_custom_config(self):
        """Test validator initialization with custom configuration."""
        custom_limits = SecurityLimits(
            max_image_size=5 * 1024 * 1024,
            max_zip_size=50 * 1024 * 1024,
        )
        custom_config = FileSecurityConfig()
        custom_config.limits = custom_limits
        validator = FileValidator(config=custom_config)

        assert validator.config == custom_config
        assert validator.config.limits.max_image_size == 5 * 1024 * 1024

    def test_magic_available_flag(self):
        """Test that magic_available flag is set correctly."""
        validator = FileValidator()

        # python-magic should be available in test environment
        assert validator.magic_available is True
        assert validator.magic_mime is not None


class TestSanitizeFilename:
    """Test filename sanitization."""

    def test_sanitize_normal_filename(self):
        """Test sanitization of normal filename."""
        validator = FileValidator()
        result = validator._sanitize_filename("document.pdf")

        assert result == "document.pdf"

    def test_sanitize_removes_path_components(self):
        """Test that path components are removed."""
        validator = FileValidator()
        result = validator._sanitize_filename("../../../etc/passwd")

        assert "/" not in result
        assert ".." not in result
        assert "passwd" in result

    def test_sanitize_removes_dangerous_characters(self):
        """Test that dangerous characters are replaced."""
        validator = FileValidator()
        result = validator._sanitize_filename('file<>:"|?*.txt')

        assert "<" not in result
        assert ">" not in result
        assert ":" not in result
        assert '"' not in result
        assert "|" not in result
        assert "?" not in result
        assert "*" not in result
        assert "_" in result  # Replaced with underscore

    def test_sanitize_removes_control_characters(self):
        """Test that control characters are removed."""
        validator = FileValidator()
        result = validator._sanitize_filename("file\x00\x01\x1f\x7f.txt")

        assert "\x00" not in result
        assert "\x01" not in result
        assert "\x1f" not in result
        assert "\x7f" not in result
        assert result == "file.txt"

    def test_sanitize_limits_filename_length(self):
        """Test that filename length is limited."""
        validator = FileValidator()
        long_name = "a" * 200 + ".txt"
        result = validator._sanitize_filename(long_name)

        # Name part should be limited to 100 chars
        assert len(result) <= 104  # 100 + ".txt"
        assert result.endswith(".txt")

    def test_sanitize_handles_empty_name_part(self):
        """Test that empty name part generates timestamp."""
        validator = FileValidator()
        result = validator._sanitize_filename(".hidden")

        # Should keep the hidden file name (. prefix is allowed for extensions)
        assert ".hidden" in result or result.startswith("file_")

    def test_sanitize_rejects_empty_filename(self):
        """Test that empty filename raises ValueError."""
        validator = FileValidator()

        with pytest.raises(ValueError, match="Filename cannot be empty"):
            validator._sanitize_filename("")

    def test_sanitize_rejects_windows_reserved_names(self):
        """Test that Windows reserved names are rejected."""
        validator = FileValidator()

        with pytest.raises(WindowsReservedNameError):
            validator._sanitize_filename("CON.txt")

    def test_sanitize_rejects_dangerous_unicode(self):
        """Test that dangerous Unicode characters are rejected."""
        validator = FileValidator()

        with pytest.raises(UnicodeSecurityError):
            validator._sanitize_filename("file\u202e.txt")  # Right-to-left override

    def test_sanitize_rejects_dangerous_extensions(self):
        """Test that dangerous extensions are rejected."""
        validator = FileValidator()

        with pytest.raises(ExtensionSecurityError):
            validator._sanitize_filename("malware.exe")


class TestValidateFilename:
    """Test filename validation."""

    @pytest.mark.asyncio
    async def test_validate_filename_success(self, mock_upload_file):
        """Test successful filename validation."""
        validator = FileValidator()
        file = mock_upload_file(filename="document.pdf", content=b"test")

        # Should not raise
        validator._validate_filename(file)
        assert file.filename == "document.pdf"

    @pytest.mark.asyncio
    async def test_validate_filename_missing(self, mock_upload_file):
        """Test validation fails with missing filename."""
        validator = FileValidator()
        file = mock_upload_file(filename=None, content=b"test")

        with pytest.raises(FilenameSecurityError, match="Filename is required"):
            validator._validate_filename(file)

    @pytest.mark.asyncio
    async def test_validate_filename_sanitizes_in_place(self, mock_upload_file):
        """Test that filename is sanitized in place."""
        validator = FileValidator()
        file = mock_upload_file(filename="file<>.txt", content=b"test")

        validator._validate_filename(file)
        assert file.filename == "file__.txt"  # Dangerous chars replaced


class TestValidateFileExtension:
    """Test file extension validation."""

    @pytest.mark.asyncio
    async def test_validate_image_extension_allowed(self, mock_upload_file):
        """Test that allowed image extensions pass."""
        validator = FileValidator()

        # Should not raise - .gif is not in default allowed extensions
        file1 = mock_upload_file(filename="photo.jpg", content=b"test")
        validator._validate_file_extension(
            file1, validator.config.ALLOWED_IMAGE_EXTENSIONS
        )

        file2 = mock_upload_file(filename="image.png", content=b"test")
        validator._validate_file_extension(
            file2, validator.config.ALLOWED_IMAGE_EXTENSIONS
        )

    @pytest.mark.asyncio
    async def test_validate_zip_extension_allowed(self, mock_upload_file):
        """Test that allowed ZIP extension passes."""
        validator = FileValidator()

        # Should not raise
        file = mock_upload_file(filename="archive.zip", content=b"test")
        validator._validate_file_extension(
            file, validator.config.ALLOWED_ZIP_EXTENSIONS
        )

    @pytest.mark.asyncio
    async def test_validate_image_extension_not_allowed(self, mock_upload_file):
        """Test that non-image extensions are rejected for images."""
        validator = FileValidator()

        file = mock_upload_file(filename="document.pdf", content=b"test")
        with pytest.raises(ExtensionSecurityError) as exc_info:
            validator._validate_file_extension(
                file, validator.config.ALLOWED_IMAGE_EXTENSIONS
            )

        assert exc_info.value.error_code == ErrorCode.EXTENSION_NOT_ALLOWED

    @pytest.mark.asyncio
    async def test_validate_zip_extension_not_allowed(self, mock_upload_file):
        """Test that non-ZIP extensions are rejected for ZIPs."""
        validator = FileValidator()

        file = mock_upload_file(filename="archive.rar", content=b"test")
        with pytest.raises(ExtensionSecurityError) as exc_info:
            validator._validate_file_extension(
                file, validator.config.ALLOWED_ZIP_EXTENSIONS
            )

        assert exc_info.value.error_code == ErrorCode.EXTENSION_NOT_ALLOWED

    @pytest.mark.asyncio
    async def test_validate_dangerous_extension_blocked(self, mock_upload_file):
        """Test that dangerous extensions are always blocked."""
        validator = FileValidator()

        file = mock_upload_file(filename="malware.exe", content=b"test")
        with pytest.raises(ExtensionSecurityError):
            # Extension not in allowed list, so will raise EXTENSION_NOT_ALLOWED first
            validator._validate_file_extension(
                file, validator.config.ALLOWED_IMAGE_EXTENSIONS
            )


class TestValidateFileSize:
    """Test file size validation."""

    @pytest.mark.asyncio
    async def test_validate_size_within_limit(self, mock_upload_file):
        """Test that file within size limit passes."""
        validator = FileValidator()
        content = b"x" * 1024  # 1KB
        file = mock_upload_file(filename="small.jpg", content=content)

        file_content, file_size = await validator._validate_file_size(
            file, max_file_size=10 * 1024
        )

        assert file_size == 1024
        assert file_content == content[:8192]  # First 8KB

    @pytest.mark.asyncio
    async def test_validate_size_empty_file(self, mock_upload_file):
        """Test that empty file is rejected."""
        validator = FileValidator()
        file = mock_upload_file(filename="empty.jpg", content=b"")

        with pytest.raises(FileSizeError, match="Empty file"):
            await validator._validate_file_size(file, max_file_size=10 * 1024)

    @pytest.mark.asyncio
    async def test_validate_size_exceeds_limit(self, mock_upload_file):
        """Test that file exceeding limit is rejected."""
        validator = FileValidator()
        content = b"x" * 10 * 1024 * 1024  # 10MB
        file = mock_upload_file(filename="large.jpg", content=content)

        with pytest.raises(FileSizeError) as exc_info:
            await validator._validate_file_size(file, max_file_size=5 * 1024 * 1024)

        assert exc_info.value.size == 10 * 1024 * 1024
        assert exc_info.value.max_size == 5 * 1024 * 1024


class TestDetectMimeType:
    """Test MIME type detection."""

    def test_detect_mime_with_magic_available(self, valid_jpeg_bytes):
        """Test MIME detection when python-magic is available."""
        validator = FileValidator()

        mime_type = validator._detect_mime_type(valid_jpeg_bytes, "photo.jpg")

        assert mime_type == "image/jpeg"

    def test_detect_mime_fallback_to_mimetypes(self):
        """Test MIME detection falls back to mimetypes module."""
        validator = FileValidator()
        # Temporarily disable magic
        original_magic_available = validator.magic_available
        validator.magic_available = False

        try:
            mime_type = validator._detect_mime_type(b"fake content", "document.pdf")
            assert mime_type == "application/pdf"
        finally:
            validator.magic_available = original_magic_available

    def test_detect_mime_unknown_fallback(self):
        """Test MIME detection returns octet-stream for unknown."""
        validator = FileValidator()
        validator.magic_available = False

        mime_type = validator._detect_mime_type(b"fake", "unknown.xyz123")

        assert mime_type == "application/octet-stream"


class TestValidateFileSignature:
    """Test file signature validation."""

    def test_validate_jpeg_signature(self, valid_jpeg_bytes):
        """Test JPEG signature validation."""
        validator = FileValidator()

        # Should not raise
        validator._validate_file_signature(valid_jpeg_bytes, expected_type="image")

    def test_validate_png_signature(self, valid_png_bytes):
        """Test PNG signature validation."""
        validator = FileValidator()

        # Should not raise
        validator._validate_file_signature(valid_png_bytes, expected_type="image")

    def test_validate_gif_signature(self):
        """Test GIF signature validation - GIF not in allowed signatures."""
        validator = FileValidator()
        gif_bytes = b"GIF89a" + b"\x00" * 100

        # GIF signature is not in the allowed image signatures (only JPEG, PNG)
        with pytest.raises(FileSignatureError):
            validator._validate_file_signature(gif_bytes, expected_type="image")

    def test_validate_zip_signature(self, create_zip_file):
        """Test ZIP signature validation."""
        validator = FileValidator()
        zip_bytes = create_zip_file(files={"test.txt": b"content"})

        # Should not raise
        validator._validate_file_signature(zip_bytes, expected_type="zip")

    def test_validate_invalid_image_signature(self):
        """Test that invalid image signature is rejected."""
        validator = FileValidator()
        invalid_bytes = b"This is not an image"

        with pytest.raises(
            FileSignatureError, match="File content does not match expected image"
        ):
            validator._validate_file_signature(invalid_bytes, expected_type="image")

    def test_validate_invalid_zip_signature(self):
        """Test that invalid ZIP signature is rejected."""
        validator = FileValidator()
        invalid_bytes = b"This is not a ZIP"

        with pytest.raises(
            FileSignatureError, match="File content does not match expected zip"
        ):
            validator._validate_file_signature(invalid_bytes, expected_type="zip")


class TestValidateImageFile:
    """Test complete image file validation."""

    @pytest.mark.asyncio
    async def test_validate_valid_jpeg(self, mock_upload_file, valid_jpeg_bytes):
        """Test validation of valid JPEG image."""
        validator = FileValidator()
        file = mock_upload_file(filename="photo.jpg", content=valid_jpeg_bytes)

        # Should not raise
        await validator.validate_image_file(file)

    @pytest.mark.asyncio
    async def test_validate_valid_png(self, mock_upload_file, valid_png_bytes):
        """Test validation of valid PNG image."""
        validator = FileValidator()
        file = mock_upload_file(filename="image.png", content=valid_png_bytes)

        # Should not raise
        await validator.validate_image_file(file)

    @pytest.mark.asyncio
    async def test_validate_image_missing_filename(
        self, mock_upload_file, valid_jpeg_bytes
    ):
        """Test validation fails with missing filename."""
        validator = FileValidator()
        file = mock_upload_file(filename=None, content=valid_jpeg_bytes)

        with pytest.raises(FilenameSecurityError):
            await validator.validate_image_file(file)

    @pytest.mark.asyncio
    async def test_validate_image_dangerous_filename(
        self, mock_upload_file, valid_jpeg_bytes
    ):
        """Test validation fails with dangerous filename."""
        validator = FileValidator()
        file = mock_upload_file(filename="image\u202e.jpg", content=valid_jpeg_bytes)

        with pytest.raises(UnicodeSecurityError):
            await validator.validate_image_file(file)

    @pytest.mark.asyncio
    async def test_validate_image_wrong_extension(
        self, mock_upload_file, valid_jpeg_bytes
    ):
        """Test validation fails with wrong extension."""
        validator = FileValidator()
        file = mock_upload_file(filename="photo.txt", content=valid_jpeg_bytes)

        with pytest.raises(ExtensionSecurityError):
            await validator.validate_image_file(file)

    @pytest.mark.asyncio
    async def test_validate_image_dangerous_extension(
        self, mock_upload_file, valid_jpeg_bytes
    ):
        """Test validation fails with dangerous extension."""
        validator = FileValidator()
        file = mock_upload_file(filename="malware.exe", content=valid_jpeg_bytes)

        with pytest.raises(ExtensionSecurityError):
            await validator.validate_image_file(file)

    @pytest.mark.asyncio
    async def test_validate_image_empty_file(self, mock_upload_file):
        """Test validation fails with empty file."""
        validator = FileValidator()
        file = mock_upload_file(filename="empty.jpg", content=b"")

        with pytest.raises(FileSizeError):
            await validator.validate_image_file(file)

    @pytest.mark.asyncio
    async def test_validate_image_exceeds_size_limit(self, mock_upload_file):
        """Test validation fails when file exceeds size limit."""
        validator = FileValidator()
        large_content = b"\xff\xd8\xff\xe0" + b"x" * (25 * 1024 * 1024)  # 25MB JPEG
        file = mock_upload_file(filename="huge.jpg", content=large_content)

        with pytest.raises(FileSizeError):
            await validator.validate_image_file(file)

    @pytest.mark.asyncio
    async def test_validate_image_wrong_mime_type(self, mock_upload_file):
        """Test validation fails with wrong MIME type."""
        validator = FileValidator()
        # PDF signature but .jpg extension
        pdf_content = b"%PDF-1.4" + b"\x00" * 100
        file = mock_upload_file(filename="fake.jpg", content=pdf_content)

        with pytest.raises(MimeTypeError):
            await validator.validate_image_file(file)

    @pytest.mark.asyncio
    async def test_validate_image_wrong_signature(self, mock_upload_file):
        """Test validation fails with wrong file signature."""
        validator = FileValidator()
        # Text content with image extension - MIME type will catch this first
        file = mock_upload_file(filename="fake.jpg", content=b"This is just text")

        with pytest.raises(MimeTypeError):
            await validator.validate_image_file(file)


class TestValidateZipFile:
    """Test complete ZIP file validation."""

    @pytest.mark.asyncio
    async def test_validate_valid_zip(self, mock_upload_file, create_zip_file):
        """Test validation of valid ZIP archive."""
        validator = FileValidator()
        zip_bytes = create_zip_file(
            files={
                "file1.txt": b"Content 1",
                "file2.txt": b"Content 2",
            }
        )
        file = mock_upload_file(filename="archive.zip", content=zip_bytes)

        # Should not raise
        await validator.validate_zip_file(file)

    @pytest.mark.asyncio
    async def test_validate_zip_missing_filename(
        self, mock_upload_file, create_zip_file
    ):
        """Test validation fails with missing filename."""
        validator = FileValidator()
        zip_bytes = create_zip_file()
        file = mock_upload_file(filename=None, content=zip_bytes)

        with pytest.raises(FilenameSecurityError):
            await validator.validate_zip_file(file)

    @pytest.mark.asyncio
    async def test_validate_zip_wrong_extension(
        self, mock_upload_file, create_zip_file
    ):
        """Test validation fails with wrong extension."""
        validator = FileValidator()
        zip_bytes = create_zip_file()
        file = mock_upload_file(filename="archive.rar", content=zip_bytes)

        with pytest.raises(ExtensionSecurityError):
            await validator.validate_zip_file(file)

    @pytest.mark.asyncio
    async def test_validate_zip_empty_file(self, mock_upload_file):
        """Test validation fails with empty file."""
        validator = FileValidator()
        file = mock_upload_file(filename="empty.zip", content=b"")

        with pytest.raises(FileSizeError):
            await validator.validate_zip_file(file)

    @pytest.mark.asyncio
    async def test_validate_zip_exceeds_size_limit(
        self, mock_upload_file, create_zip_file
    ):
        """Test validation fails when ZIP exceeds size limit."""
        # Create ZIP with large content
        large_content = b"x" * (10 * 1024 * 1024)  # 10MB
        zip_bytes = create_zip_file(files={"large.bin": large_content})

        # Use custom config with small limit
        custom_limits = SecurityLimits(max_zip_size=1 * 1024 * 1024)  # 1MB limit
        custom_config = FileSecurityConfig()
        custom_config.limits = custom_limits
        validator = FileValidator(config=custom_config)
        file = mock_upload_file(filename="large.zip", content=zip_bytes)

        with pytest.raises(FileSizeError):
            await validator.validate_zip_file(file)

    @pytest.mark.asyncio
    async def test_validate_zip_directory_traversal(self, mock_upload_file):
        """Test validation detects directory traversal."""
        validator = FileValidator()

        import zipfile

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("../../../etc/passwd", b"malicious")

        file = mock_upload_file(filename="malicious.zip", content=zip_buffer.getvalue())

        with pytest.raises(ZipContentError):
            await validator.validate_zip_file(file)

    @pytest.mark.asyncio
    async def test_validate_zip_nested_archive(self, mock_upload_file, create_zip_file):
        """Test validation detects nested archives."""
        validator = FileValidator()

        # Create nested ZIP
        inner_zip = create_zip_file(files={"inner.txt": b"content"})
        outer_zip = create_zip_file(files={"nested.zip": inner_zip})

        file = mock_upload_file(filename="nested.zip", content=outer_zip)

        # Nested archives raise CompressionSecurityError
        with pytest.raises(CompressionSecurityError, match="Nested archives"):
            await validator.validate_zip_file(file)

    @pytest.mark.asyncio
    async def test_validate_zip_wrong_signature(self, mock_upload_file):
        """Test validation fails with wrong file signature."""
        validator = FileValidator()
        file = mock_upload_file(filename="fake.zip", content=b"This is not a ZIP")

        with pytest.raises(FileSignatureError):
            await validator.validate_zip_file(file)

    @pytest.mark.asyncio
    async def test_validate_zip_handles_octet_stream_mime(
        self, mock_upload_file, create_zip_file
    ):
        """Test validation handles application/octet-stream MIME for valid ZIPs."""
        validator = FileValidator()
        zip_bytes = create_zip_file(files={"test.txt": b"content"})
        file = mock_upload_file(filename="archive.zip", content=zip_bytes)

        # Even if MIME is detected as octet-stream, should pass if ZIP is valid
        await validator.validate_zip_file(file)
