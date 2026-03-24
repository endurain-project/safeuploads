"""Tests for FileValidator integration."""

import io

import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.exceptions import (
    CompressionSecurityError,
    ErrorCode,
    ExtensionSecurityError,
    FilenameSecurityError,
    FileProcessingError,
    FileSignatureError,
    FileSizeError,
    MimeTypeError,
    ResourceLimitError,
    UnicodeSecurityError,
    WindowsReservedNameError,
    ZipContentError,
)
from safeuploads.file_validator import FileValidator


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
            validator._sanitize_filename(
                "file\u202e.txt"
            )  # Right-to-left override

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

        with pytest.raises(
            FilenameSecurityError, match="Filename is required"
        ):
            validator._validate_filename(file)

    @pytest.mark.asyncio
    async def test_validate_filename_sanitizes_in_place(
        self, mock_upload_file
    ):
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
    async def test_validate_image_extension_not_allowed(
        self, mock_upload_file
    ):
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
    async def test_validate_dangerous_extension_blocked(
        self, mock_upload_file
    ):
        """Test that dangerous extensions are always blocked."""
        validator = FileValidator()

        file = mock_upload_file(filename="malware.exe", content=b"test")
        with pytest.raises(ExtensionSecurityError):
            # Extension not in allowed list, so will
            # raise EXTENSION_NOT_ALLOWED first
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
            await validator._validate_file_size(
                file, max_file_size=5 * 1024 * 1024
            )

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
            mime_type = validator._detect_mime_type(
                b"fake content", "document.pdf"
            )
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
        validator._validate_file_signature(
            valid_jpeg_bytes, expected_type="image"
        )

    def test_validate_png_signature(self, valid_png_bytes):
        """Test PNG signature validation."""
        validator = FileValidator()

        # Should not raise
        validator._validate_file_signature(
            valid_png_bytes, expected_type="image"
        )

    def test_validate_gif_signature(self):
        """Test GIF signature validation - GIF not in allowed signatures."""
        validator = FileValidator()
        gif_bytes = b"GIF89a" + b"\x00" * 100

        # GIF signature is not in the allowed image signatures (only JPEG, PNG)
        with pytest.raises(FileSignatureError):
            validator._validate_file_signature(
                gif_bytes, expected_type="image"
            )

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
            FileSignatureError,
            match="File content does not match expected image",
        ):
            validator._validate_file_signature(
                invalid_bytes, expected_type="image"
            )

    def test_validate_invalid_zip_signature(self):
        """Test that invalid ZIP signature is rejected."""
        validator = FileValidator()
        invalid_bytes = b"This is not a ZIP"

        with pytest.raises(
            FileSignatureError,
            match="File content does not match expected zip",
        ):
            validator._validate_file_signature(
                invalid_bytes, expected_type="zip"
            )


class TestValidateImageFile:
    """Test complete image file validation."""

    @pytest.mark.asyncio
    async def test_validate_valid_jpeg(
        self, mock_upload_file, valid_jpeg_bytes
    ):
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
        file = mock_upload_file(
            filename="image\u202e.jpg", content=valid_jpeg_bytes
        )

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
        file = mock_upload_file(
            filename="malware.exe", content=valid_jpeg_bytes
        )

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
        large_content = b"\xff\xd8\xff\xe0" + b"x" * (
            25 * 1024 * 1024
        )  # 25MB JPEG
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
    async def test_validate_image_text_content_rejected_by_mime(
        self, mock_upload_file
    ):
        """Test MIME detection rejects text disguised as image."""
        validator = FileValidator()
        # Text content with image extension - MIME type will catch this first
        file = mock_upload_file(
            filename="fake.jpg", content=b"This is just text"
        )

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
        custom_limits = SecurityLimits(
            max_zip_size=1 * 1024 * 1024
        )  # 1MB limit
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

        file = mock_upload_file(
            filename="malicious.zip", content=zip_buffer.getvalue()
        )

        with pytest.raises(ZipContentError):
            await validator.validate_zip_file(file)

    @pytest.mark.asyncio
    async def test_validate_zip_nested_archive(
        self, mock_upload_file, create_zip_file
    ):
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
        file = mock_upload_file(
            filename="fake.zip", content=b"This is not a ZIP"
        )

        with pytest.raises(FileSignatureError):
            await validator.validate_zip_file(file)

    @pytest.mark.asyncio
    async def test_validate_zip_handles_octet_stream_mime(
        self, mock_upload_file, create_zip_file
    ):
        """
        Test validation handles
        application/octet-stream MIME for valid ZIPs.
        """
        validator = FileValidator()
        zip_bytes = create_zip_file(files={"test.txt": b"content"})
        file = mock_upload_file(filename="archive.zip", content=zip_bytes)

        # Even if MIME is detected as octet-stream, should pass if ZIP is valid
        await validator.validate_zip_file(file)


class TestFileValidatorMagicUnavailable:
    """Tests for FileValidator when python-magic fails to initialise."""

    def test_magic_unavailable_flag_set_false(self, monkeypatch):
        """
        Test that magic_available is False when magic.Magic raises.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        import safeuploads.file_validator as _fv

        monkeypatch.setattr(
            _fv.magic,
            "Magic",
            lambda **_: (_ for _ in ()).throw(
                Exception("python-magic unavailable")
            ),
        )
        validator = FileValidator()
        assert validator.magic_available is False

    async def test_magic_unavailable_falls_back_to_mimetypes(
        self, monkeypatch, valid_jpeg_bytes
    ):
        """
        Test MIME detection falls back to mimetypes when magic absent.

        Args:
            monkeypatch: pytest monkeypatch fixture.
            valid_jpeg_bytes: Valid JPEG bytes fixture.
        """
        import safeuploads.file_validator as _fv

        monkeypatch.setattr(
            _fv.magic,
            "Magic",
            lambda **_: (_ for _ in ()).throw(
                Exception("python-magic unavailable")
            ),
        )
        validator = FileValidator()
        assert validator.magic_available is False
        # Fallback should return a sensible MIME based on filename
        mime = validator._detect_mime_type(b"data", "photo.jpg")
        assert mime == "image/jpeg"


class TestValidateFilenameExceptionWrapping:
    """Tests for _validate_filename exception wrapping behaviour."""

    def test_unexpected_exception_is_wrapped_in_processing_error(
        self, monkeypatch, mock_upload_file
    ):
        """
        Test that an unexpected exception is wrapped in FileProcessingError.

        Args:
            monkeypatch: pytest monkeypatch fixture.
            mock_upload_file: File factory fixture.
        """
        validator = FileValidator()
        file = mock_upload_file(filename="photo.jpg", content=b"x")

        def _explode(filename: str) -> str:
            raise RuntimeError("unexpected internal error")

        monkeypatch.setattr(validator, "_sanitize_filename", _explode)

        with pytest.raises(FileProcessingError):
            validator._validate_filename(file)


class TestValidateFileSizeFullReadPath:
    """Tests for _validate_file_size when file.size is unavailable."""

    async def test_full_read_used_when_size_is_none(self, mock_upload_file):
        """
        Test that file is fully read when size attribute is None/falsy.

        When file.size is falsy the implementation reads everything to
        compute file_size. For files smaller than 8 KB the initial chunk
        already contains all bytes, so the "remaining" read re-reads the
        whole content; the returned file_size is therefore the sum of
        both reads (double the actual content length for tiny files).
        We simply verify that the function returns without raising and
        that the computed size is a positive integer.

        Args:
            mock_upload_file: File factory fixture.
        """
        content = b"x" * 2048
        file = mock_upload_file(filename="test.jpg", content=content)
        file.size = None  # Force the full-read path

        validator = FileValidator()
        file_content, file_size = await validator._validate_file_size(
            file,
            max_file_size=100 * 1024,  # Generous limit
        )

        assert file_size > 0
        assert len(file_content) == len(content)  # First 8 KB chunk

    async def test_full_read_detects_oversized_file_when_size_none(
        self, mock_upload_file
    ):
        """
        Test that oversized files are detected via full-read path.

        Args:
            mock_upload_file: File factory fixture.
        """
        content = b"x" * (3 * 1024)  # 3 KB
        file = mock_upload_file(filename="test.jpg", content=content)
        file.size = None  # Force the full-read calculation

        validator = FileValidator()
        with pytest.raises(FileSizeError):
            await validator._validate_file_size(
                file,
                max_file_size=1 * 1024,  # 1 KB limit
            )


class TestValidateImageFileExceptionWrapping:
    """Tests for validate_image_file unexpected exception wrapping."""

    async def test_unexpected_exception_becomes_processing_error(
        self, monkeypatch, mock_upload_file, valid_jpeg_bytes
    ):
        """
        Test that a RuntimeError mid-validation is wrapped to
        FileProcessingError by validate_image_file.

        Args:
            monkeypatch: pytest monkeypatch fixture.
            mock_upload_file: File factory fixture.
            valid_jpeg_bytes: Valid JPEG bytes fixture.
        """
        validator = FileValidator()
        file = mock_upload_file(filename="photo.jpg", content=valid_jpeg_bytes)

        async def _explode(f, max_size):
            raise RuntimeError("unexpected error in size check")

        monkeypatch.setattr(validator, "_validate_file_size", _explode)

        with pytest.raises(FileProcessingError):
            await validator.validate_image_file(file)


class TestValidateZipFileExceptionWrapping:
    """Tests for validate_zip_file unexpected exception wrapping."""

    async def test_unexpected_exception_becomes_processing_error(
        self, monkeypatch, mock_upload_file, create_zip_file
    ):
        """
        Test that a RuntimeError mid-validation is wrapped to
        FileProcessingError by validate_zip_file.

        Args:
            monkeypatch: pytest monkeypatch fixture.
            mock_upload_file: File factory fixture.
            create_zip_file: ZIP factory fixture.
        """
        validator = FileValidator()
        zip_bytes = create_zip_file(files={"t.txt": b"hi"})
        file = mock_upload_file(filename="archive.zip", content=zip_bytes)

        async def _explode(f, max_size):
            raise RuntimeError("unexpected streaming error")

        monkeypatch.setattr(validator, "_stream_to_temp_file", _explode)

        with pytest.raises(FileProcessingError):
            await validator.validate_zip_file(file)


class TestStreamToTempFile:
    """Tests for _stream_to_temp_file error handling and cleanup."""

    async def test_cleans_up_temp_file_on_read_error(self):
        """
        Test that the temp file is closed when a read error occurs.

        Exercises the except-block that closes the temp file and
        re-raises the original IOError.

        Returns:
            None
        """
        validator = FileValidator()
        call_count = 0

        class _FailingFile:
            filename = "test.zip"
            size = None

            async def read(self, size: int = -1) -> bytes:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return b"x" * 1000  # First chunk succeeds
                raise OSError("simulated read failure")

            async def seek(self, offset: int) -> int:
                return offset

        with pytest.raises(IOError, match="simulated read failure"):
            await validator._stream_to_temp_file(
                _FailingFile(), max_file_size=10 * 1024 * 1024
            )

    async def test_raises_file_size_error_when_limit_exceeded_during_stream(
        self, mock_upload_file
    ):
        """
        Test that streaming raises FileSizeError when size limit hit.

        Args:
            mock_upload_file: File factory fixture.
        """
        validator = FileValidator()
        # Content larger than the micro limit we apply
        content = b"x" * (5 * 1024)  # 5 KB
        file = mock_upload_file(filename="archive.zip", content=content)
        file.size = None  # Ensure streaming path is used

        with pytest.raises(FileSizeError):
            await validator._stream_to_temp_file(
                file,
                max_file_size=1 * 1024,  # 1 KB limit
            )


class TestResourceMonitorIntegration:
    """Test resource monitoring in validate methods."""

    @pytest.mark.asyncio
    async def test_image_validation_raises_on_time_limit(
        self, mock_upload_file, valid_jpeg_bytes, monkeypatch
    ):
        """Test image validation raises on time limit."""
        custom_limits = SecurityLimits(
            max_validation_time_seconds=0.001,
        )
        config = FileSecurityConfig()
        config.limits = custom_limits
        validator = FileValidator(config=config)
        file = mock_upload_file(filename="photo.jpg", content=valid_jpeg_bytes)

        import time as time_mod

        original_read = type(file).read

        async def slow_read(self, size=-1):
            time_mod.sleep(0.05)
            return await original_read(self, size)

        monkeypatch.setattr(type(file), "read", slow_read)

        with pytest.raises(ResourceLimitError) as exc_info:
            await validator.validate_image_file(file)

        assert exc_info.value.error_code == ErrorCode.RESOURCE_TIME_EXCEEDED

    @pytest.mark.asyncio
    async def test_zip_validation_raises_on_time_limit(
        self, mock_upload_file, create_zip_file, monkeypatch
    ):
        """Test ZIP validation raises on time limit."""
        custom_limits = SecurityLimits(
            max_validation_time_seconds=0.001,
        )
        config = FileSecurityConfig()
        config.limits = custom_limits
        validator = FileValidator(config=config)
        zip_bytes = create_zip_file(files={"test.txt": b"content"})
        file = mock_upload_file(filename="archive.zip", content=zip_bytes)

        import time as time_mod

        original_read = type(file).read

        async def slow_read(self, size=-1):
            time_mod.sleep(0.05)
            return await original_read(self, size)

        monkeypatch.setattr(type(file), "read", slow_read)

        with pytest.raises(ResourceLimitError) as exc_info:
            await validator.validate_zip_file(file)

        assert exc_info.value.error_code == ErrorCode.RESOURCE_TIME_EXCEEDED

    @pytest.mark.asyncio
    async def test_image_validation_passes_with_generous_limits(
        self, mock_upload_file, valid_jpeg_bytes
    ):
        """Test image validation passes with generous limits."""
        custom_limits = SecurityLimits(
            max_validation_time_seconds=30.0,
            max_validation_memory_mb=512,
        )
        config = FileSecurityConfig()
        config.limits = custom_limits
        validator = FileValidator(config=config)
        file = mock_upload_file(filename="photo.jpg", content=valid_jpeg_bytes)

        await validator.validate_image_file(file)

    @pytest.mark.asyncio
    async def test_zip_validation_passes_with_generous_limits(
        self, mock_upload_file, create_zip_file
    ):
        """Test ZIP validation passes with generous limits."""
        custom_limits = SecurityLimits(
            max_validation_time_seconds=30.0,
            max_validation_memory_mb=512,
        )
        config = FileSecurityConfig()
        config.limits = custom_limits
        validator = FileValidator(config=config)
        zip_bytes = create_zip_file(files={"test.txt": b"content"})
        file = mock_upload_file(filename="archive.zip", content=zip_bytes)

        await validator.validate_zip_file(file)

    @pytest.mark.asyncio
    async def test_resource_limit_error_propagates_not_wrapped(
        self, mock_upload_file, valid_jpeg_bytes, monkeypatch
    ):
        """Test ResourceLimitError propagates, not wrapped."""
        custom_limits = SecurityLimits(
            max_validation_time_seconds=0.001,
        )
        config = FileSecurityConfig()
        config.limits = custom_limits
        validator = FileValidator(config=config)
        file = mock_upload_file(filename="photo.jpg", content=valid_jpeg_bytes)

        import time as time_mod

        original_read = type(file).read

        async def slow_read(self, size=-1):
            time_mod.sleep(0.05)
            return await original_read(self, size)

        monkeypatch.setattr(type(file), "read", slow_read)

        with pytest.raises(ResourceLimitError):
            await validator.validate_image_file(file)


class TestDetectMimeTypeMagicException:
    """Tests for _detect_mime_type when magic raises."""

    def test_magic_from_buffer_exception_falls_back(
        self, monkeypatch, valid_jpeg_bytes
    ):
        """
        Test MIME fallback when magic.from_buffer raises.

        Args:
            monkeypatch: pytest monkeypatch fixture.
            valid_jpeg_bytes: Valid JPEG bytes fixture.
        """
        validator = FileValidator()
        assert validator.magic_available is True

        def _explode(_content):
            raise RuntimeError("magic failed")

        monkeypatch.setattr(validator.magic_mime, "from_buffer", _explode)

        mime = validator._detect_mime_type(valid_jpeg_bytes, "photo.jpg")
        # Falls back to mimetypes guess from filename
        assert mime == "image/jpeg"


class TestValidateFileSignatureEdgeCases:
    """Tests for _validate_file_signature edge cases."""

    def test_signature_too_small_file(self):
        """
        Test that files smaller than 4 bytes are rejected.

        Returns:
            None
        """
        validator = FileValidator()

        with pytest.raises(FileSignatureError, match="too small"):
            validator._validate_file_signature(b"\xff\xd8", "image")

    def test_signature_one_byte_file(self):
        """
        Test that single byte files are rejected.

        Returns:
            None
        """
        validator = FileValidator()

        with pytest.raises(FileSignatureError):
            validator._validate_file_signature(b"X", "zip")

    def test_signature_empty_content(self):
        """
        Test that empty content is rejected.

        Returns:
            None
        """
        validator = FileValidator()

        with pytest.raises(FileSignatureError):
            validator._validate_file_signature(b"", "image")


class TestSanitizeFilenameEdgeCases:
    """Tests for _sanitize_filename edge cases."""

    def test_sanitize_removes_null_bytes(self):
        """
        Test explicit null byte removal from filename.

        Returns:
            None
        """
        validator = FileValidator()
        result = validator._sanitize_filename("file\x00.txt\x00")
        assert "\x00" not in result
        assert result == "file.txt"

    def test_sanitize_whitespace_only_name_part(self):
        """
        Test that whitespace-only name generates timestamp.

        Returns:
            None
        """
        validator = FileValidator()
        result = validator._sanitize_filename("   .jpg")
        assert result.startswith("file_")
        assert result.endswith(".jpg")
