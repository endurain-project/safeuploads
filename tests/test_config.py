"""Tests for FileSecurityConfig and SecurityLimits."""

import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.exceptions import (
    ConfigValidationError,
    FileSecurityConfigurationError,
)


class TestSecurityLimits:
    """Test suite for SecurityLimits dataclass."""

    def test_default_initialization(self):
        """Test SecurityLimits with default values."""
        limits = SecurityLimits()

        assert limits.max_image_size == 20 * 1024 * 1024
        assert limits.max_zip_size == 500 * 1024 * 1024
        assert limits.max_compression_ratio == 100
        assert limits.max_uncompressed_size == 1024 * 1024 * 1024
        assert limits.max_individual_file_size == 500 * 1024 * 1024
        assert limits.max_zip_entries == 10000
        assert limits.zip_analysis_timeout == 5.0
        assert limits.max_zip_depth == 10
        assert limits.max_filename_length == 255
        assert limits.max_path_length == 1024
        assert limits.allow_nested_archives is False
        assert limits.allow_symlinks is False
        assert limits.allow_absolute_paths is False
        assert limits.scan_zip_content is True

    def test_custom_initialization(self):
        """Test SecurityLimits with custom values."""
        limits = SecurityLimits(
            max_image_size=10 * 1024 * 1024,
            max_zip_size=100 * 1024 * 1024,
            max_compression_ratio=50,
            max_zip_entries=1000,
            allow_nested_archives=True,
        )

        assert limits.max_image_size == 10 * 1024 * 1024
        assert limits.max_zip_size == 100 * 1024 * 1024
        assert limits.max_compression_ratio == 50
        assert limits.max_zip_entries == 1000
        assert limits.allow_nested_archives is True

    def test_boolean_flags(self):
        """Test all boolean configuration flags."""
        limits = SecurityLimits(
            allow_nested_archives=True,
            allow_symlinks=True,
            allow_absolute_paths=True,
            scan_zip_content=False,
        )

        assert limits.allow_nested_archives is True
        assert limits.allow_symlinks is True
        assert limits.allow_absolute_paths is True
        assert limits.scan_zip_content is False


class TestFileSecurityConfig:
    """Test suite for FileSecurityConfig class."""

    def test_default_configuration(self):
        """Test FileSecurityConfig with defaults."""
        config = FileSecurityConfig()

        assert isinstance(config.limits, SecurityLimits)
        assert len(config.ALLOWED_IMAGE_MIMES) > 0
        assert len(config.ALLOWED_ZIP_MIMES) > 0
        assert len(config.ALLOWED_IMAGE_EXTENSIONS) > 0
        assert len(config.ALLOWED_ZIP_EXTENSIONS) > 0

    def test_allowed_image_mimes(self):
        """Test allowed image MIME types."""
        config = FileSecurityConfig()

        assert "image/jpeg" in config.ALLOWED_IMAGE_MIMES
        assert "image/jpg" in config.ALLOWED_IMAGE_MIMES
        assert "image/png" in config.ALLOWED_IMAGE_MIMES

    def test_allowed_zip_mimes(self):
        """Test allowed ZIP MIME types."""
        config = FileSecurityConfig()

        assert "application/zip" in config.ALLOWED_ZIP_MIMES
        assert "application/x-zip-compressed" in config.ALLOWED_ZIP_MIMES

    def test_allowed_image_extensions(self):
        """Test allowed image extensions."""
        config = FileSecurityConfig()

        assert ".jpg" in config.ALLOWED_IMAGE_EXTENSIONS
        assert ".jpeg" in config.ALLOWED_IMAGE_EXTENSIONS
        assert ".png" in config.ALLOWED_IMAGE_EXTENSIONS

    def test_allowed_zip_extensions(self):
        """Test allowed ZIP extensions."""
        config = FileSecurityConfig()

        assert ".zip" in config.ALLOWED_ZIP_EXTENSIONS

    def test_blocked_extensions_generated(self):
        """Test that blocked extensions are generated from enums."""
        config = FileSecurityConfig()
        blocked = config.BLOCKED_EXTENSIONS

        # Should contain various dangerous extensions
        assert ".exe" in blocked
        assert ".bat" in blocked
        assert ".sh" in blocked
        assert ".dll" in blocked
        assert ".vbs" in blocked

    def test_compound_blocked_extensions_generated(self):
        """Test that compound blocked extensions are generated."""
        config = FileSecurityConfig()
        compound = config.COMPOUND_BLOCKED_EXTENSIONS

        # Should contain compound extensions
        assert ".tar.gz" in compound
        assert ".user.js" in compound

    def test_dangerous_unicode_chars_generated(self):
        """Test that dangerous Unicode characters are generated."""
        config = FileSecurityConfig()
        dangerous = config.DANGEROUS_UNICODE_CHARS

        # Should contain various dangerous Unicode characters (as integers)
        assert len(dangerous) > 0
        # Contains bidirectional override characters (as int values)
        assert 0x202E in dangerous or 0x202D in dangerous or 8206 in dangerous

    def test_windows_reserved_names_generated(self):
        """Test that Windows reserved names are generated."""
        config = FileSecurityConfig()
        reserved = config.WINDOWS_RESERVED_NAMES

        # Should contain Windows device names
        assert "con" in reserved
        assert "prn" in reserved
        assert "aux" in reserved
        assert "nul" in reserved
        assert "com1" in reserved
        assert "lpt1" in reserved


class TestConfigurationValidation:
    """Test suite for configuration validation."""

    def test_valid_default_configuration(self):
        """Test that default configuration passes validation."""
        errors = FileSecurityConfig.validate_configuration()

        # Default config should have no critical errors
        critical_errors = [e for e in errors if e.severity == "error"]
        assert len(critical_errors) == 0

    def test_validate_and_report_success(self):
        """Test validate_and_report with valid configuration."""
        # Should not raise with valid default configuration
        try:
            FileSecurityConfig.validate_and_report(strict=False)
        except FileSecurityConfigurationError:
            pytest.fail("Should not raise for valid configuration")

    def test_config_validation_error_attributes(self):
        """Test ConfigValidationError attributes."""
        error = ConfigValidationError(
            error_type="test_error",
            message="Test message",
            severity="error",
            component="test_component",
            recommendation="Test recommendation",
        )

        assert error.error_type == "test_error"
        assert error.message == "Test message"
        assert error.severity == "error"
        assert error.component == "test_component"
        assert error.recommendation == "Test recommendation"

    def test_config_validation_error_string_representation(self):
        """Test ConfigValidationError string representation."""
        error = ConfigValidationError(
            error_type="test_error",
            message="Test message",
            severity="error",
            component="test_component",
        )

        error_str = str(error)
        assert "test_error" in error_str
        assert "Test message" in error_str

    def test_custom_limits_configuration(self):
        """Test configuration with completely custom limits."""
        custom_limits = SecurityLimits(
            max_image_size=5 * 1024 * 1024,
            max_zip_size=50 * 1024 * 1024,
            max_compression_ratio=50,
            max_uncompressed_size=100 * 1024 * 1024,
            max_zip_entries=1000,
            zip_analysis_timeout=10.0,
            max_zip_depth=5,
            allow_nested_archives=True,
            scan_zip_content=False,
        )

        config = FileSecurityConfig()
        config.limits = custom_limits

        # Verify custom settings
        assert config.limits.max_image_size == 5 * 1024 * 1024
        assert config.limits.max_zip_entries == 1000
        assert config.limits.allow_nested_archives is True
        assert config.limits.scan_zip_content is False

    def test_limits_can_be_modified(self):
        """Test that SecurityLimits can be modified after creation."""
        limits = SecurityLimits()

        # Modify limits
        limits.max_image_size = 30 * 1024 * 1024
        limits.allow_symlinks = True

        assert limits.max_image_size == 30 * 1024 * 1024
        assert limits.allow_symlinks is True

    def test_config_class_attributes_accessible(self):
        """Test that class-level attributes are accessible."""
        # Can access without instantiation
        assert hasattr(FileSecurityConfig, "ALLOWED_IMAGE_MIMES")
        assert hasattr(FileSecurityConfig, "BLOCKED_EXTENSIONS")
        assert hasattr(FileSecurityConfig, "WINDOWS_RESERVED_NAMES")

    def test_multiple_config_instances_independent(self):
        """Test that multiple config instances are independent."""
        config1 = FileSecurityConfig()
        config2 = FileSecurityConfig()

        # Modify one
        config1.limits = SecurityLimits(max_image_size=10 * 1024 * 1024)

        # Other should retain defaults
        assert config2.limits.max_image_size == 20 * 1024 * 1024

    def test_security_limits_immutability_via_dataclass(self):
        """Test SecurityLimits dataclass behavior."""
        limits = SecurityLimits()

        # Should be able to create new instance with different values
        limits2 = SecurityLimits(max_image_size=10 * 1024 * 1024)

        # Original unchanged
        assert limits.max_image_size == 20 * 1024 * 1024
        assert limits2.max_image_size == 10 * 1024 * 1024

    def test_config_validation_returns_list(self):
        """Test that validation returns a list."""
        errors = FileSecurityConfig.validate_configuration()
        assert isinstance(errors, list)

    def test_file_security_configuration_error_with_errors(self):
        """Test FileSecurityConfigurationError with error list."""
        error1 = ConfigValidationError(
            error_type="test1",
            message="Error 1",
            severity="error",
            component="test",
        )
        error2 = ConfigValidationError(
            error_type="test2",
            message="Error 2",
            severity="warning",
            component="test",
        )

        exc = FileSecurityConfigurationError(errors=[error1, error2])

        assert exc.errors is not None
        assert len(exc.errors) == 2
        assert exc.errors[0].error_type == "test1"
        assert exc.errors[1].error_type == "test2"

    def test_allowed_sets_not_empty_by_default(self):
        """Test that all allowed sets have default values."""
        assert len(FileSecurityConfig.ALLOWED_IMAGE_MIMES) > 0
        assert len(FileSecurityConfig.ALLOWED_ZIP_MIMES) > 0
        assert len(FileSecurityConfig.ALLOWED_IMAGE_EXTENSIONS) > 0
        assert len(FileSecurityConfig.ALLOWED_ZIP_EXTENSIONS) > 0

    def test_blocked_sets_not_empty_by_default(self):
        """Test that blocked extension sets are populated."""
        assert len(FileSecurityConfig.BLOCKED_EXTENSIONS) > 0
        assert len(FileSecurityConfig.COMPOUND_BLOCKED_EXTENSIONS) > 0

    def test_reserved_names_lowercase(self):
        """Test that Windows reserved names are lowercase."""
        reserved = FileSecurityConfig.WINDOWS_RESERVED_NAMES

        for name in reserved:
            assert name == name.lower(), f"Reserved name {name} should be lowercase"

    def test_extensions_include_dot(self):
        """Test that extensions include leading dot."""
        for ext in FileSecurityConfig.ALLOWED_IMAGE_EXTENSIONS:
            assert ext.startswith("."), f"Extension {ext} should start with dot"

        for ext in FileSecurityConfig.BLOCKED_EXTENSIONS:
            assert ext.startswith("."), f"Extension {ext} should start with dot"
