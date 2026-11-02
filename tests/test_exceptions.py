"""Tests for exception classes and error codes."""

import copy
import importlib
import importlib.metadata
import inspect
from concurrent.futures import ProcessPoolExecutor
from importlib.metadata import PackageNotFoundError, version

import pytest

import safeuploads
from safeuploads import exceptions as exceptions_module
from safeuploads.exceptions import (
    CompressionSecurityError,
    ConfigValidationError,
    ContentThreatError,
    ErrorCode,
    ExtensionSecurityError,
    FilenameSecurityError,
    FileProcessingError,
    FileSecurityConfigurationError,
    FileSecurityError,
    FileSignatureError,
    FileSizeError,
    FileValidationError,
    MimeTypeError,
    ResourceLimitError,
    UnicodeSecurityError,
    WindowsReservedNameError,
    XmlSecurityError,
    ZipBombError,
    ZipContentError,
)


class TestErrorCode:
    """Test ErrorCode class constants."""

    def test_error_code_constants_exist(self):
        """Verify all expected error code constants are defined."""
        # Filename errors
        assert hasattr(ErrorCode, "FILENAME_EMPTY")
        assert hasattr(ErrorCode, "FILENAME_INVALID")

        # Unicode errors
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

        # MIME type errors
        assert hasattr(ErrorCode, "MIME_TYPE_INVALID")
        assert hasattr(ErrorCode, "MIME_TYPE_MISMATCH")
        assert hasattr(ErrorCode, "MIME_DETECTION_FAILED")

        # File signature errors
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
        assert error.error_code == ErrorCode.PROCESSING_ERROR

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
        error = MimeTypeError(
            "MIME mismatch", error_code=ErrorCode.MIME_TYPE_MISMATCH
        )
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
        error = FileProcessingError(
            "Processing failed", original_error=original
        )
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


_DEFAULT_CODES = {
    FileSecurityError: ErrorCode.PROCESSING_ERROR,
    FileValidationError: ErrorCode.VALIDATION_FAILED,
    FilenameSecurityError: ErrorCode.FILENAME_INVALID,
    UnicodeSecurityError: ErrorCode.UNICODE_DANGEROUS_CHARS,
    ExtensionSecurityError: ErrorCode.EXTENSION_BLOCKED,
    WindowsReservedNameError: ErrorCode.WINDOWS_RESERVED_NAME,
    FileSizeError: ErrorCode.FILE_TOO_LARGE,
    MimeTypeError: ErrorCode.MIME_TYPE_INVALID,
    FileSignatureError: ErrorCode.FILE_SIGNATURE_MISMATCH,
    CompressionSecurityError: ErrorCode.ZIP_INVALID_STRUCTURE,
    ZipBombError: ErrorCode.ZIP_BOMB_DETECTED,
    ZipContentError: ErrorCode.ZIP_CONTENT_THREAT,
    XmlSecurityError: ErrorCode.XML_MALFORMED,
    ContentThreatError: ErrorCode.CONTENT_THREAT_DETECTED,
    FileProcessingError: ErrorCode.PROCESSING_ERROR,
    ResourceLimitError: ErrorCode.RESOURCE_LIMIT_EXCEEDED,
}


def _file_exception_classes() -> list[type[FileSecurityError]]:
    """Return every FileSecurityError subclass in the module."""
    return [
        cls
        for _, cls in inspect.getmembers(exceptions_module, inspect.isclass)
        if issubclass(cls, FileSecurityError)
    ]


class TestDefaultErrorCodes:
    """Every exception class has a default ErrorCode."""

    def test_table_covers_every_exception_class(self):
        """The expected-defaults table lists all classes."""
        assert set(_file_exception_classes()) == set(_DEFAULT_CODES)

    @pytest.mark.parametrize(
        ("cls", "code"),
        list(_DEFAULT_CODES.items()),
        ids=lambda v: getattr(v, "__name__", str(v)),
    )
    def test_message_only_construction_has_default_code(self, cls, code):
        """A message-only instance has its class's default code."""
        error = cls("boom")
        assert isinstance(error.error_code, ErrorCode)
        assert error.error_code == code

    def test_explicit_code_overrides_default(self):
        """An explicit code is kept."""
        error = FileValidationError("x", error_code=ErrorCode.FILE_EMPTY)
        assert error.error_code == ErrorCode.FILE_EMPTY


class TestXmlAndContentThreatErrors:
    """XmlSecurityError and ContentThreatError."""

    def test_xml_security_error_attributes(self):
        """Filename and code are stored."""
        error = XmlSecurityError(
            "bad",
            filename="a.gpx",
            error_code=ErrorCode.XML_DTD_FORBIDDEN,
        )
        assert isinstance(error, FileValidationError)
        assert error.filename == "a.gpx"
        assert error.error_code == ErrorCode.XML_DTD_FORBIDDEN

    def test_content_threat_error_attributes(self):
        """Threats list and filename are stored."""
        error = ContentThreatError("bad", filename="a.jpg", threats=["x"])
        assert isinstance(error, FileValidationError)
        assert error.threats == ["x"]
        assert error.filename == "a.jpg"

    def test_content_threat_error_threats_default_empty(self):
        """Threats default to an empty list."""
        assert ContentThreatError("bad").threats == []


class TestResourceLimitErrorKeywordOnly:
    """ResourceLimitError parameters after message are keyword-only."""

    def test_positional_extra_argument_rejected(self):
        """A second positional argument is a TypeError."""
        with pytest.raises(TypeError):
            ResourceLimitError("m", ErrorCode.RESOURCE_TIME_EXCEEDED)

    def test_keywords_accepted(self):
        """All options work as keywords."""
        original = ValueError("o")
        error = ResourceLimitError(
            "m",
            error_code=ErrorCode.RESOURCE_MEMORY_EXCEEDED,
            elapsed_seconds=1.5,
            memory_bytes=10,
            original_error=original,
        )
        assert error.error_code == ErrorCode.RESOURCE_MEMORY_EXCEEDED
        assert error.elapsed_seconds == 1.5
        assert error.memory_bytes == 10
        assert error.original_error is original


def _sample_instances() -> list[FileSecurityError]:
    """Build one fully populated instance of each exception."""
    return [
        FileSecurityError("m", error_code=ErrorCode.PROCESSING_ERROR),
        FileValidationError("m", "f.txt", ErrorCode.FILE_EMPTY),
        FilenameSecurityError("m", "f.txt"),
        UnicodeSecurityError("m", "f.txt", [("\u202e", 8238, 0)]),
        ExtensionSecurityError("m", "f.exe", ".exe"),
        WindowsReservedNameError("m", "con.txt", "CON"),
        FileSizeError("m", "f", 10, 5),
        MimeTypeError("m", "f", "text/plain", ["image/png"]),
        FileSignatureError("m", "f", "png"),
        CompressionSecurityError("m", "f.zip"),
        ZipBombError("m", "f.zip", 99.5, 1000, 50.0, 500),
        ZipContentError("m", "f.zip", ["t1", "t2"]),
        XmlSecurityError("m", "f.gpx", ErrorCode.XML_DTD_FORBIDDEN),
        ContentThreatError("m", "f.jpg", ["t1"]),
        FileProcessingError("m", original_error=None),
        ResourceLimitError(
            "m",
            error_code=ErrorCode.RESOURCE_TIME_EXCEEDED,
            elapsed_seconds=2.5,
            memory_bytes=7,
        ),
    ]


@pytest.fixture(scope="module")
def round_trip():
    """Send objects through a process pool and return the copies."""
    with ProcessPoolExecutor(max_workers=1) as pool:
        yield lambda *objs: list(pool.map(copy.copy, objs))


class TestPickling:
    """Exceptions survive pickling (process-pool executors)."""

    def test_samples_cover_every_exception_class(self):
        """The sample list has one instance per class."""
        assert {type(e) for e in _sample_instances()} == set(
            _file_exception_classes()
        )

    def test_round_trip_keeps_attributes(self, round_trip):
        """Type, message, code and attributes survive."""
        errors = _sample_instances()
        for clone, error in zip(round_trip(*errors), errors, strict=True):
            assert type(clone) is type(error)
            assert clone.error_code == error.error_code
            assert str(clone) == str(error)
            assert vars(clone) == vars(error)

    def test_configuration_error_round_trip(self, round_trip):
        """FileSecurityConfigurationError keeps its errors."""
        errors = [
            ConfigValidationError("t", "msg", "error", "comp", "fix"),
            ConfigValidationError("t2", "msg2", "warning", "comp2"),
        ]
        (clone,) = round_trip(FileSecurityConfigurationError(errors))
        assert isinstance(clone, FileSecurityConfigurationError)
        assert clone.errors == errors
        assert str(clone) == str(FileSecurityConfigurationError(errors))

    def test_empty_configuration_error_round_trip(self, round_trip):
        """An empty error list also round-trips."""
        (clone,) = round_trip(FileSecurityConfigurationError([]))
        assert clone.errors == []

    def test_config_validation_error_round_trip(self, round_trip):
        """The ConfigValidationError dataclass pickles."""
        item = ConfigValidationError("t", "msg", "info", "comp", "fix")
        assert round_trip(item) == [item]


class TestPackageExports:
    """Public package attributes."""

    def test_version_matches_distribution_metadata(self):
        """__version__ equals the installed distribution version."""
        assert safeuploads.__version__ == version("safeuploads")
        assert "__version__" in safeuploads.__all__

    def test_version_falls_back_without_distribution_metadata(
        self, monkeypatch
    ):
        """An uninstalled source tree still imports."""

        def missing(name):
            raise PackageNotFoundError(name)

        monkeypatch.setattr(importlib.metadata, "version", missing)
        try:
            importlib.reload(safeuploads)
            assert safeuploads.__version__ == "0+unknown"
        finally:
            monkeypatch.undo()
            importlib.reload(safeuploads)
        assert safeuploads.__version__ == version("safeuploads")

    @pytest.mark.parametrize(
        "name",
        [
            "XmlSecurityError",
            "ContentThreatError",
            "UploadFileProtocol",
            "SeekableFile",
        ],
    )
    def test_names_exported(self, name):
        """New public names are importable and listed."""
        assert name in safeuploads.__all__
        assert getattr(safeuploads, name) is not None

    @pytest.mark.parametrize("name", ["log_extra", "reset_correlation_id"])
    def test_internal_names_not_exported(self, name):
        """Internal helpers stay out of ``__all__``."""
        assert name not in safeuploads.__all__
