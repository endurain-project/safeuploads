"""Tests for exception classes and error codes."""

import pytest

from safeuploads.exceptions import (
    ErrorCode,
    FileSecurityError,
    FileValidationError,
    FilenameSecurityError,
    UnicodeSecurityError,
    ExtensionSecurityError,
    WindowsReservedNameError,
    FileSizeError,
    MimeTypeError,
    FileSignatureError,
    CompressionSecurityError,
    ZipBombError,
    ZipContentError,
    FileProcessingError,
    FileSecurityConfigurationError,
    ConfigValidationError,
)


class TestErrorCode:
    """Test ErrorCode class constants."""

    def test_error_code_constants_exist(self):
        """Verify all expected error code constants are defined."""
        # Filename errors
        assert hasattr(ErrorCode, "FILENAME_EMPTY")
        assert hasattr(ErrorCode, "FILENAME_INVALID")
        assert hasattr(ErrorCode, "FILENAME_TOO_LONG")

        # Unicode errors
        assert hasattr(ErrorCode, "UNICODE_SECURITY")
        assert hasattr(ErrorCode, "UNICODE_DANGEROUS_CHARS")
        assert hasattr(ErrorCode, "UNICODE_NORMALIZATION_ERROR")

        # Extension errors
        assert hasattr(ErrorCode, "EXTENSION_BLOCKED")
        assert hasattr(ErrorCode, "EXTENSION_NOT_ALLOWED")
        assert hasattr(ErrorCode, "COMPOUND_EXTENSION_BLOCKED")
        assert hasattr(ErrorCode, "EXTENSION_MISSING")

        # Windows errors
        assert hasattr(ErrorCode, "WINDOWS_RESERVED_NAME")

        # File size errors
        assert hasattr(ErrorCode, "FILE_TOO_LARGE")
        assert hasattr(ErrorCode, "FILE_EMPTY")
        assert hasattr(ErrorCode, "FILE_SIZE_UNKNOWN")

        # MIME type errors
        assert hasattr(ErrorCode, "MIME_TYPE_INVALID")
        assert hasattr(ErrorCode, "MIME_TYPE_MISMATCH")
        assert hasattr(ErrorCode, "MIME_DETECTION_FAILED")

        # File signature errors
        assert hasattr(ErrorCode, "FILE_SIGNATURE_INVALID")
        assert hasattr(ErrorCode, "FILE_SIGNATURE_MISSING")
        assert hasattr(ErrorCode, "FILE_SIGNATURE_MISMATCH")

        # ZIP errors
        assert hasattr(ErrorCode, "ZIP_BOMB_DETECTED")
        assert hasattr(ErrorCode, "ZIP_CONTENT_THREAT")
        assert hasattr(ErrorCode, "COMPRESSION_RATIO_EXCEEDED")
        assert hasattr(ErrorCode, "ZIP_TOO_MANY_ENTRIES")
        assert hasattr(ErrorCode, "ZIP_INVALID_STRUCTURE")
        assert hasattr(ErrorCode, "ZIP_CORRUPT")

        # Processing errors
        assert hasattr(ErrorCode, "PROCESSING_ERROR")
        assert hasattr(ErrorCode, "IO_ERROR")
        assert hasattr(ErrorCode, "MEMORY_ERROR")

    def test_error_codes_are_strings(self):
        """Verify error codes are string values."""
        assert isinstance(ErrorCode.FILENAME_EMPTY, str)
        assert isinstance(ErrorCode.EXTENSION_BLOCKED, str)
        assert isinstance(ErrorCode.ZIP_BOMB_DETECTED, str)

    def test_error_codes_are_uppercase(self):
        """Verify error codes follow naming convention."""
        assert ErrorCode.FILENAME_EMPTY == "FILENAME_EMPTY"
        assert ErrorCode.EXTENSION_BLOCKED == "EXTENSION_BLOCKED"
        assert ErrorCode.ZIP_BOMB_DETECTED == "ZIP_BOMB_DETECTED"


class TestFileSecurityError:
    """Test FileSecurityError base exception."""

    def test_initialization(self):
        """Test basic initialization."""
        error = FileSecurityError("Test error")
        assert str(error) == "Test error"
        assert error.message == "Test error"
        assert error.error_code is None

    def test_initialization_with_error_code(self):
        """Test initialization with error code."""
        error = FileSecurityError("Test error", error_code="TEST_CODE")
        assert error.message == "Test error"
        assert error.error_code == "TEST_CODE"

    def test_inheritance(self):
        """Test exception inheritance."""
        error = FileSecurityError("Test")
        assert isinstance(error, Exception)


class TestFileValidationError:
    """Test FileValidationError exception."""

    def test_initialization(self):
        """Test basic initialization."""
        error = FileValidationError("Validation failed")
        assert str(error) == "Validation failed"
        assert error.filename is None

    def test_initialization_with_filename(self):
        """Test initialization with filename."""
        error = FileValidationError("Validation failed", filename="test.jpg")
        assert error.filename == "test.jpg"
        assert error.message == "Validation failed"

    def test_initialization_with_error_code(self):
        """Test initialization with error code."""
        error = FileValidationError(
            "Validation failed", filename="test.jpg", error_code="VAL_ERROR"
        )
        assert error.error_code == "VAL_ERROR"

    def test_inheritance(self):
        """Test exception inheritance."""
        error = FileValidationError("Test")
        assert isinstance(error, FileSecurityError)


class TestFilenameSecurityError:
    """Test FilenameSecurityError exception."""

    def test_initialization(self):
        """Test basic initialization."""
        error = FilenameSecurityError("Invalid filename")
        assert str(error) == "Invalid filename"

    def test_inheritance(self):
        """Test exception inheritance."""
        error = FilenameSecurityError("Test")
        assert isinstance(error, FileValidationError)


class TestUnicodeSecurityError:
    """Test UnicodeSecurityError exception."""

    def test_initialization_without_dangerous_chars(self):
        """Test initialization without dangerous chars."""
        error = UnicodeSecurityError("Unicode threat")
        assert error.message == "Unicode threat"
        assert error.dangerous_chars == []

    def test_initialization_with_dangerous_chars(self):
        """Test initialization with dangerous chars list."""
        dangerous_chars = [("→", 0x202E, 5), ("‮", 0x202E, 10)]
        error = UnicodeSecurityError(
            "Unicode threat",
            filename="test.txt",
            dangerous_chars=dangerous_chars,
        )
        assert error.dangerous_chars == dangerous_chars
        assert error.filename == "test.txt"

    def test_default_error_code(self):
        """Test default error code is set."""
        error = UnicodeSecurityError("Unicode threat")
        assert error.error_code == ErrorCode.UNICODE_DANGEROUS_CHARS

    def test_inheritance(self):
        """Test exception inheritance."""
        error = UnicodeSecurityError("Test")
        assert isinstance(error, FilenameSecurityError)


class TestExtensionSecurityError:
    """Test ExtensionSecurityError exception."""

    def test_initialization(self):
        """Test basic initialization."""
        error = ExtensionSecurityError("Extension blocked")
        assert error.message == "Extension blocked"
        assert error.extension is None

    def test_initialization_with_extension(self):
        """Test initialization with extension."""
        error = ExtensionSecurityError(
            "Extension blocked", filename="file.exe", extension=".exe"
        )
        assert error.extension == ".exe"
        assert error.filename == "file.exe"

    def test_default_error_code(self):
        """Test default error code."""
        error = ExtensionSecurityError("Extension blocked")
        assert error.error_code == ErrorCode.EXTENSION_BLOCKED

    def test_custom_error_code(self):
        """Test custom error code."""
        error = ExtensionSecurityError(
            "Extension not allowed",
            error_code=ErrorCode.EXTENSION_NOT_ALLOWED,
        )
        assert error.error_code == ErrorCode.EXTENSION_NOT_ALLOWED

    def test_inheritance(self):
        """Test exception inheritance."""
        error = ExtensionSecurityError("Test")
        assert isinstance(error, FilenameSecurityError)


class TestWindowsReservedNameError:
    """Test WindowsReservedNameError exception."""

    def test_initialization(self):
        """Test basic initialization."""
        error = WindowsReservedNameError("Reserved name")
        assert error.message == "Reserved name"
        assert error.reserved_name is None

    def test_initialization_with_reserved_name(self):
        """Test initialization with reserved name."""
        error = WindowsReservedNameError(
            "Reserved name", filename="CON.txt", reserved_name="CON"
        )
        assert error.reserved_name == "CON"
        assert error.filename == "CON.txt"

    def test_error_code(self):
        """Test error code is set."""
        error = WindowsReservedNameError("Reserved name")
        assert error.error_code == ErrorCode.WINDOWS_RESERVED_NAME

    def test_inheritance(self):
        """Test exception inheritance."""
        error = WindowsReservedNameError("Test")
        assert isinstance(error, FilenameSecurityError)


class TestFileSizeError:
    """Test FileSizeError exception."""

    def test_initialization(self):
        """Test basic initialization."""
        error = FileSizeError("File too large")
        assert error.message == "File too large"
        assert error.size is None
        assert error.max_size is None

    def test_initialization_with_sizes(self):
        """Test initialization with size information."""
        error = FileSizeError(
            "File too large",
            filename="big.jpg",
            size=50 * 1024 * 1024,
            max_size=20 * 1024 * 1024,
        )
        assert error.size == 50 * 1024 * 1024
        assert error.max_size == 20 * 1024 * 1024
        assert error.filename == "big.jpg"

    def test_error_code(self):
        """Test error code is set."""
        error = FileSizeError("File too large")
        assert error.error_code == ErrorCode.FILE_TOO_LARGE

    def test_inheritance(self):
        """Test exception inheritance."""
        error = FileSizeError("Test")
        assert isinstance(error, FileValidationError)


class TestMimeTypeError:
    """Test MimeTypeError exception."""

    def test_initialization(self):
        """Test basic initialization."""
        error = MimeTypeError("Invalid MIME type")
        assert error.message == "Invalid MIME type"
        assert error.detected_mime is None
        assert error.allowed_mimes == []

    def test_initialization_with_mime_info(self):
        """Test initialization with MIME type information."""
        error = MimeTypeError(
            "Invalid MIME type",
            filename="file.exe",
            detected_mime="application/x-msdownload",
            allowed_mimes=["image/jpeg", "image/png"],
        )
        assert error.detected_mime == "application/x-msdownload"
        assert error.allowed_mimes == ["image/jpeg", "image/png"]

    def test_default_error_code(self):
        """Test default error code."""
        error = MimeTypeError("Invalid MIME type")
        assert error.error_code == ErrorCode.MIME_TYPE_INVALID

    def test_custom_error_code(self):
        """Test custom error code."""
        error = MimeTypeError("MIME mismatch", error_code=ErrorCode.MIME_TYPE_MISMATCH)
        assert error.error_code == ErrorCode.MIME_TYPE_MISMATCH

    def test_inheritance(self):
        """Test exception inheritance."""
        error = MimeTypeError("Test")
        assert isinstance(error, FileValidationError)


class TestFileSignatureError:
    """Test FileSignatureError exception."""

    def test_initialization(self):
        """Test basic initialization."""
        error = FileSignatureError("Invalid signature")
        assert error.message == "Invalid signature"
        assert error.expected_type is None

    def test_initialization_with_expected_type(self):
        """Test initialization with expected type."""
        error = FileSignatureError(
            "Invalid signature", filename="fake.jpg", expected_type="image"
        )
        assert error.expected_type == "image"
        assert error.filename == "fake.jpg"

    def test_error_code(self):
        """Test error code is set."""
        error = FileSignatureError("Invalid signature")
        assert error.error_code == ErrorCode.FILE_SIGNATURE_MISMATCH

    def test_inheritance(self):
        """Test exception inheritance."""
        error = FileSignatureError("Test")
        assert isinstance(error, FileValidationError)


class TestCompressionSecurityError:
    """Test CompressionSecurityError exception."""

    def test_initialization(self):
        """Test basic initialization."""
        error = CompressionSecurityError("Compression issue")
        assert error.message == "Compression issue"

    def test_inheritance(self):
        """Test exception inheritance."""
        error = CompressionSecurityError("Test")
        assert isinstance(error, FileValidationError)


class TestZipBombError:
    """Test ZipBombError exception."""

    def test_initialization(self):
        """Test basic initialization."""
        error = ZipBombError("Zip bomb detected")
        assert error.message == "Zip bomb detected"
        assert error.compression_ratio is None
        assert error.uncompressed_size is None

    def test_initialization_with_details(self):
        """Test initialization with compression details."""
        error = ZipBombError(
            "Zip bomb detected",
            filename="bomb.zip",
            compression_ratio=1000.0,
            uncompressed_size=10 * 1024 * 1024 * 1024,
            max_ratio=100.0,
            max_size=1 * 1024 * 1024 * 1024,
        )
        assert error.compression_ratio == 1000.0
        assert error.uncompressed_size == 10 * 1024 * 1024 * 1024
        assert error.max_ratio == 100.0
        assert error.max_size == 1 * 1024 * 1024 * 1024

    def test_error_code(self):
        """Test error code is set."""
        error = ZipBombError("Zip bomb detected")
        assert error.error_code == ErrorCode.ZIP_BOMB_DETECTED

    def test_inheritance(self):
        """Test exception inheritance."""
        error = ZipBombError("Test")
        assert isinstance(error, CompressionSecurityError)


class TestZipContentError:
    """Test ZipContentError exception."""

    def test_initialization(self):
        """Test basic initialization."""
        error = ZipContentError("ZIP content threat")
        assert error.message == "ZIP content threat"
        assert error.threats == []

    def test_initialization_with_threats(self):
        """Test initialization with threat list."""
        threats = [
            "Directory traversal detected",
            "Symlink detected",
        ]
        error = ZipContentError(
            "ZIP content threat", filename="bad.zip", threats=threats
        )
        assert error.threats == threats
        assert error.filename == "bad.zip"

    def test_default_error_code(self):
        """Test default error code."""
        error = ZipContentError("ZIP content threat")
        assert error.error_code == ErrorCode.ZIP_CONTENT_THREAT

    def test_custom_error_code(self):
        """Test custom error code."""
        error = ZipContentError(
            "Nested archive", error_code=ErrorCode.ZIP_NESTED_ARCHIVE
        )
        assert error.error_code == ErrorCode.ZIP_NESTED_ARCHIVE

    def test_inheritance(self):
        """Test exception inheritance."""
        error = ZipContentError("Test")
        assert isinstance(error, CompressionSecurityError)


class TestFileProcessingError:
    """Test FileProcessingError exception."""

    def test_initialization(self):
        """Test basic initialization."""
        error = FileProcessingError("Processing failed")
        assert error.message == "Processing failed"
        assert error.original_error is None

    def test_initialization_with_original_error(self):
        """Test initialization with original error."""
        original = ValueError("Original error")
        error = FileProcessingError("Processing failed", original_error=original)
        assert error.original_error == original

    def test_error_code(self):
        """Test error code is set."""
        error = FileProcessingError("Processing failed")
        assert error.error_code == ErrorCode.PROCESSING_ERROR

    def test_inheritance(self):
        """Test exception inheritance."""
        error = FileProcessingError("Test")
        assert isinstance(error, FileSecurityError)


class TestConfigValidationError:
    """Test ConfigValidationError dataclass."""

    def test_initialization(self):
        """Test dataclass initialization."""
        error = ConfigValidationError(
            error_type="invalid_config",
            message="Config is invalid",
            severity="error",
            component="test_component",
            recommendation="Fix the config",
        )
        assert error.error_type == "invalid_config"
        assert error.message == "Config is invalid"
        assert error.severity == "error"
        assert error.component == "test_component"
        assert error.recommendation == "Fix the config"

    def test_default_recommendation(self):
        """Test default empty recommendation."""
        error = ConfigValidationError(
            error_type="test",
            message="Test message",
            severity="warning",
            component="test",
        )
        assert error.recommendation == ""


class TestFileSecurityConfigurationError:
    """Test FileSecurityConfigurationError exception."""

    def test_initialization_with_errors(self):
        """Test initialization with error list."""
        errors = [
            ConfigValidationError(
                error_type="test1",
                message="Error 1",
                severity="error",
                component="comp1",
            ),
            ConfigValidationError(
                error_type="test2",
                message="Error 2",
                severity="warning",
                component="comp2",
            ),
        ]
        error = FileSecurityConfigurationError(errors)
        assert error.errors == errors
        assert "Configuration validation failed" in str(error)
        assert "ERROR: Error 1" in str(error)
        assert "WARNING: Error 2" in str(error)

    def test_inheritance(self):
        """Test exception inheritance."""
        errors = []
        error = FileSecurityConfigurationError(errors)
        assert isinstance(error, Exception)
