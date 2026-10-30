"""Tests for FileSecurityConfig and SecurityLimits."""

from typing import Any

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
            assert name == name.lower(), (
                f"Reserved name {name} should be lowercase"
            )

    def test_extensions_include_dot(self):
        """Test that extensions include leading dot."""
        for ext in FileSecurityConfig.ALLOWED_IMAGE_EXTENSIONS:
            assert ext.startswith("."), (
                f"Extension {ext} should start with dot"
            )

        for ext in FileSecurityConfig.BLOCKED_EXTENSIONS:
            assert ext.startswith("."), (
                f"Extension {ext} should start with dot"
            )


class TestConfigInstanceIsolation:
    """Regression tests for shared mutable config state."""

    def test_limits_are_not_shared_between_instances(self):
        """Each instance must own a distinct limits object."""
        a = FileSecurityConfig()
        b = FileSecurityConfig()

        assert a.limits is not b.limits

    def test_limit_mutation_does_not_leak_across_instances(self):
        """Mutating one instance's limits must not affect another."""
        a = FileSecurityConfig()
        b = FileSecurityConfig()

        a.limits.max_image_size = 12345

        assert b.limits.max_image_size == 20 * 1024 * 1024

    def test_limit_mutation_does_not_leak_to_class_default(self):
        """Instance limit mutation must not touch the class default."""
        original = SecurityLimits().max_image_size
        a = FileSecurityConfig()

        a.limits.max_image_size = 999

        assert FileSecurityConfig.limits.max_image_size == original

    def test_allowed_mime_sets_are_immutable(self):
        """Allow-list MIME sets must be immutable frozensets."""
        config = FileSecurityConfig()

        assert isinstance(config.ALLOWED_IMAGE_MIMES, frozenset)
        with pytest.raises(AttributeError):
            config.ALLOWED_IMAGE_MIMES.add("image/evil")

    def test_allowed_extension_sets_are_immutable(self):
        """Allow-list extension sets must be immutable frozensets."""
        config = FileSecurityConfig()

        assert isinstance(config.ALLOWED_ACTIVITY_EXTENSIONS, frozenset)
        with pytest.raises(AttributeError):
            config.ALLOWED_ACTIVITY_EXTENSIONS.add(".evil")


def _errors_for(**overrides: Any) -> list[ConfigValidationError]:
    """
    Validate an instance whose limits carry the given overrides.

    Args:
        **overrides: SecurityLimits field values to override.

    Returns:
        Error-severity issues reported for the instance.
    """
    config = FileSecurityConfig()
    config.limits = SecurityLimits(**overrides)
    return [e for e in config.validate_instance() if e.severity == "error"]


_LIMIT_CASES = [
    # (field, smallest valid value, first invalid value, error_type)
    ("max_activity_file_size", 1, 0, "invalid_size_limit"),
    ("max_gzip_size", 1, 0, "invalid_size_limit"),
    ("max_memory_buffer_size", 1, 0, "invalid_streaming_limit"),
    ("chunk_size", 1, 0, "invalid_streaming_limit"),
    ("max_validation_memory_mb", 1, 0, "invalid_streaming_limit"),
    ("max_validation_time_seconds", 0.001, 0, "invalid_timeout"),
    ("content_scan_max_size", 1, 0, "invalid_streaming_limit"),
    ("max_zip_depth", 0, -1, "invalid_zip_depth"),
    ("max_filename_length", 1, 0, "invalid_name_length"),
    ("max_path_length", 1, 0, "invalid_path_length"),
    ("max_number_files_same_type", 1, 0, "invalid_zip_entries"),
    ("max_total_entries_recursive", 1, 0, "invalid_zip_entries"),
]


class TestLimitRangeValidation:
    """Every numeric limit is range-checked at the boundary."""

    @pytest.mark.parametrize(
        ("field", "valid", "invalid", "kind"), _LIMIT_CASES
    )
    def test_smallest_valid_value_is_accepted(
        self, field, valid, invalid, kind
    ):
        """The smallest valid value raises no error-severity issue."""
        assert _errors_for(**{field: valid}) == []

    @pytest.mark.parametrize(
        ("field", "valid", "invalid", "kind"), _LIMIT_CASES
    )
    def test_first_invalid_value_is_rejected(
        self, field, valid, invalid, kind
    ):
        """The first invalid value is reported with its error_type."""
        errors = _errors_for(**{field: invalid})

        assert [e.error_type for e in errors] == [kind]
        assert field in errors[0].message

    @pytest.mark.parametrize("value", [float("nan"), float("inf")])
    @pytest.mark.parametrize(
        "field", ["max_validation_time_seconds", "zip_analysis_timeout"]
    )
    def test_non_finite_timeout_is_rejected(self, field, value):
        """NaN and infinity never count as a usable timeout."""
        errors = _errors_for(**{field: value})

        assert [e.error_type for e in errors] == ["invalid_timeout"]


class TestLimitTypeValidation:
    """Wrongly typed limits are reported without raising."""

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("chunk_size", "64"),
            ("chunk_size", True),
            ("chunk_size", 64.0),
            ("max_image_size", None),
            ("max_validation_time_seconds", "30"),
            ("max_validation_time_seconds", True),
            ("zip_analysis_timeout", False),
            ("allow_symlinks", 1),
            ("enable_audit_logging", "yes"),
        ],
    )
    def test_wrong_type_is_reported(self, field, value):
        """A wrong-typed field yields an invalid_limit_type error."""
        errors = _errors_for(**{field: value})

        assert [e.error_type for e in errors] == ["invalid_limit_type"]
        assert field in errors[0].message

    def test_int_accepted_for_float_field(self):
        """Integer seconds are valid for timeout fields."""
        assert _errors_for(max_validation_time_seconds=30) == []

    def test_several_wrong_types_all_reported(self):
        """Each wrong-typed field produces its own error."""
        errors = _errors_for(chunk_size="64", max_zip_size=True)

        assert len(errors) == 2
        assert {e.error_type for e in errors} == {"invalid_limit_type"}

    def test_default_config_reports_no_issues(self):
        """The default configuration reports nothing at all."""
        assert FileSecurityConfig().validate_instance() == []


_EXTENSION_SETS = [
    "ALLOWED_IMAGE_EXTENSIONS",
    "ALLOWED_ZIP_EXTENSIONS",
    "ALLOWED_ACTIVITY_EXTENSIONS",
    "ALLOWED_GZIP_EXTENSIONS",
    "BLOCKED_EXTENSIONS",
    "COMPOUND_BLOCKED_EXTENSIONS",
]


def _issue_types(**overrides: Any) -> list[str]:
    """
    Validate a FileSecurityConfig subclass with class overrides.

    Args:
        **overrides: Class attributes to override.

    Returns:
        error_type of every issue reported.
    """
    config_cls = type("Cfg", (FileSecurityConfig,), overrides)
    return [e.error_type for e in config_cls().validate_instance()]


class TestAllowListValidation:
    """Activity and gzip allow-lists get the image/ZIP checks."""

    @pytest.mark.parametrize(
        "name", ["ALLOWED_ACTIVITY_EXTENSIONS", "ALLOWED_GZIP_EXTENSIONS"]
    )
    def test_empty_extension_set_rejected(self, name):
        """An empty extension allow-list is an error."""
        assert _issue_types(**{name: frozenset()}) == ["empty_extension_set"]

    @pytest.mark.parametrize(
        "name", ["ALLOWED_ACTIVITY_EXTENSIONS", "ALLOWED_GZIP_EXTENSIONS"]
    )
    def test_extension_without_dot_rejected(self, name):
        """An extension without a leading dot is an error."""
        assert _issue_types(**{name: frozenset({"gpx"})}) == [
            "invalid_extension_format"
        ]

    @pytest.mark.parametrize(
        "name", ["ALLOWED_ACTIVITY_EXTENSIONS", "ALLOWED_GZIP_EXTENSIONS"]
    )
    def test_blocked_extension_conflict_rejected(self, name):
        """An allowed extension that is also blocked is an error."""
        assert _issue_types(**{name: frozenset({".exe"})}) == [
            "extension_conflict"
        ]

    @pytest.mark.parametrize(
        "name", ["ALLOWED_ACTIVITY_MIMES", "ALLOWED_GZIP_MIMES"]
    )
    def test_empty_mime_set_rejected(self, name):
        """An empty MIME allow-list is an error."""
        assert _issue_types(**{name: frozenset()}) == ["empty_mime_set"]

    @pytest.mark.parametrize("name", _EXTENSION_SETS)
    def test_uppercase_extension_rejected(self, name):
        """Filenames are lowercased, so an uppercase entry is dead."""
        value = frozenset(getattr(FileSecurityConfig, name) | {".ABC"})

        assert _issue_types(**{name: value}) == ["uppercase_extension"]

    @pytest.mark.parametrize("name", _EXTENSION_SETS)
    def test_default_extension_sets_are_lowercase(self, name):
        """No built-in extension entry contains uppercase."""
        for ext in getattr(FileSecurityConfig, name):
            assert ext == ext.lower()
