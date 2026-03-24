"""
Tests for FileSecurityConfig validation branches.

Covers: _validate_file_size_limits, _validate_mime_configurations,
_validate_extension_configurations, _validate_compression_settings,
validate_and_report, and class utility methods.
"""

import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.enums import (
    CompoundExtensionCategory,
    DangerousExtensionCategory,
    UnicodeAttackCategory,
)
from safeuploads.exceptions import (
    FileSecurityConfigurationError,
)


class TestFileSizeLimitValidation:
    """Tests for _validate_file_size_limits validation branches."""

    def test_negative_image_size_generates_error(
        self, monkeypatch
    ):
        """
        Test that a non-positive image size limit generates an error.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig,
            "limits",
            SecurityLimits(max_image_size=-1),
        )
        errors = FileSecurityConfig.validate_configuration()
        error_types = [
            e.error_type for e in errors if e.severity == "error"
        ]
        assert "invalid_size_limit" in error_types

    def test_excessive_image_size_generates_warning(
        self, monkeypatch
    ):
        """
        Test that an oversized image limit generates a warning.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig,
            "limits",
            SecurityLimits(
                max_image_size=200 * 1024 * 1024
            ),  # 200 MB
        )
        errors = FileSecurityConfig.validate_configuration()
        warnings = [
            e
            for e in errors
            if e.error_type == "excessive_size_limit"
            and e.severity == "warning"
        ]
        assert len(warnings) >= 1

    def test_negative_zip_size_generates_error(
        self, monkeypatch
    ):
        """
        Test that a non-positive ZIP size limit generates an error.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig,
            "limits",
            SecurityLimits(max_zip_size=-1),
        )
        errors = FileSecurityConfig.validate_configuration()
        error_types = [
            e.error_type for e in errors if e.severity == "error"
        ]
        assert "invalid_size_limit" in error_types

    def test_excessive_zip_size_generates_warning(
        self, monkeypatch
    ):
        """
        Test that an oversized ZIP limit generates a warning.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig,
            "limits",
            SecurityLimits(
                max_zip_size=3 * 1024 * 1024 * 1024
            ),  # 3 GB
        )
        errors = FileSecurityConfig.validate_configuration()
        warnings = [
            e
            for e in errors
            if e.error_type == "excessive_size_limit"
            and e.severity == "warning"
        ]
        assert len(warnings) >= 1

    def test_zip_smaller_than_image_generates_warning(
        self, monkeypatch
    ):
        """
        Test warning when ZIP size limit is smaller than image limit.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig,
            "limits",
            SecurityLimits(
                max_image_size=100 * 1024 * 1024,  # 100 MB
                max_zip_size=50 * 1024 * 1024,      # 50 MB
            ),
        )
        errors = FileSecurityConfig.validate_configuration()
        warnings = [
            e
            for e in errors
            if e.error_type == "inconsistent_size_limits"
        ]
        assert len(warnings) >= 1


class TestMimeConfigurationValidation:
    """Tests for _validate_mime_configurations validation branches."""

    def test_empty_allowed_image_mimes_generates_error(
        self, monkeypatch
    ):
        """
        Test that empty ALLOWED_IMAGE_MIMES generates an error.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig, "ALLOWED_IMAGE_MIMES", set()
        )
        errors = FileSecurityConfig.validate_configuration()
        error_types = [
            e.error_type for e in errors if e.severity == "error"
        ]
        assert "empty_mime_set" in error_types

    def test_non_image_mime_generates_warning(self, monkeypatch):
        """
        Test that a non-image MIME type in image set generates warning.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig,
            "ALLOWED_IMAGE_MIMES",
            {"application/pdf"},
        )
        errors = FileSecurityConfig.validate_configuration()
        warnings = [
            e
            for e in errors
            if e.error_type == "invalid_image_mime"
        ]
        assert len(warnings) >= 1

    def test_empty_allowed_zip_mimes_generates_error(
        self, monkeypatch
    ):
        """
        Test that empty ALLOWED_ZIP_MIMES generates an error.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig, "ALLOWED_ZIP_MIMES", set()
        )
        errors = FileSecurityConfig.validate_configuration()
        error_types = [
            e.error_type for e in errors if e.severity == "error"
        ]
        assert "empty_mime_set" in error_types

    def test_duplicate_mime_across_sets_generates_warning(
        self, monkeypatch
    ):
        """
        Test warning when a MIME type appears in both allowed sets.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        shared = "application/zip"
        monkeypatch.setattr(
            FileSecurityConfig,
            "ALLOWED_IMAGE_MIMES",
            {"image/jpeg", shared},
        )
        monkeypatch.setattr(
            FileSecurityConfig,
            "ALLOWED_ZIP_MIMES",
            {shared},
        )
        errors = FileSecurityConfig.validate_configuration()
        warnings = [
            e
            for e in errors
            if e.error_type == "duplicate_mime_types"
        ]
        assert len(warnings) >= 1


class TestExtensionConfigurationValidation:
    """Tests for _validate_extension_configurations branches."""

    def test_empty_image_extensions_generates_error(
        self, monkeypatch
    ):
        """
        Test that empty ALLOWED_IMAGE_EXTENSIONS generates an error.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig, "ALLOWED_IMAGE_EXTENSIONS", set()
        )
        errors = FileSecurityConfig.validate_configuration()
        error_types = [
            e.error_type for e in errors if e.severity == "error"
        ]
        assert "empty_extension_set" in error_types

    def test_extension_without_dot_generates_error(
        self, monkeypatch
    ):
        """
        Test that an extension without a leading dot generates an error.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig,
            "ALLOWED_IMAGE_EXTENSIONS",
            {"jpg"},  # Missing leading dot
        )
        errors = FileSecurityConfig.validate_configuration()
        error_types = [
            e.error_type for e in errors if e.severity == "error"
        ]
        assert "invalid_extension_format" in error_types

    def test_empty_blocked_extensions_generates_error(
        self, monkeypatch
    ):
        """
        Test that empty BLOCKED_EXTENSIONS generates an error.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig, "BLOCKED_EXTENSIONS", set()
        )
        errors = FileSecurityConfig.validate_configuration()
        error_types = [
            e.error_type for e in errors if e.severity == "error"
        ]
        assert "empty_blocked_extensions" in error_types

    def test_allowed_extension_in_blocked_generates_error(
        self, monkeypatch
    ):
        """
        Test error when an allowed image extension is also blocked.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        original_blocked = FileSecurityConfig.BLOCKED_EXTENSIONS.copy()
        monkeypatch.setattr(
            FileSecurityConfig,
            "BLOCKED_EXTENSIONS",
            original_blocked | {".jpg"},
        )
        errors = FileSecurityConfig.validate_configuration()
        error_types = [
            e.error_type for e in errors if e.severity == "error"
        ]
        assert "extension_conflict" in error_types

    def test_compound_extension_in_blocked_generates_warning(
        self, monkeypatch
    ):
        """
        Test warning when a blocked extension also appears as compound.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        original_blocked = FileSecurityConfig.BLOCKED_EXTENSIONS.copy()
        monkeypatch.setattr(
            FileSecurityConfig,
            "BLOCKED_EXTENSIONS",
            original_blocked | {".tar.gz"},
        )
        errors = FileSecurityConfig.validate_configuration()
        warnings = [
            e
            for e in errors
            if e.error_type == "compound_extension_overlap"
        ]
        assert len(warnings) >= 1


class TestCompressionSettingsValidation:
    """Tests for _validate_compression_settings branches."""

    def test_zero_compression_ratio_generates_error(
        self, monkeypatch
    ):
        """
        Test that a zero compression ratio limit generates an error.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig,
            "limits",
            SecurityLimits(max_compression_ratio=0),
        )
        errors = FileSecurityConfig.validate_configuration()
        error_types = [
            e.error_type for e in errors if e.severity == "error"
        ]
        assert "invalid_compression_ratio" in error_types

    def test_very_strict_compression_ratio_generates_warning(
        self, monkeypatch
    ):
        """
        Test that a very strict compression ratio generates a warning.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig,
            "limits",
            SecurityLimits(max_compression_ratio=5),
        )
        errors = FileSecurityConfig.validate_configuration()
        warnings = [
            e
            for e in errors
            if e.error_type == "too_strict_compression"
        ]
        assert len(warnings) >= 1

    def test_very_permissive_compression_ratio_generates_warning(
        self, monkeypatch
    ):
        """
        Test warning when compression ratio limit is very permissive.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig,
            "limits",
            SecurityLimits(max_compression_ratio=2000),
        )
        errors = FileSecurityConfig.validate_configuration()
        warnings = [
            e
            for e in errors
            if e.error_type == "too_permissive_compression"
        ]
        assert len(warnings) >= 1

    def test_zero_uncompressed_size_generates_error(
        self, monkeypatch
    ):
        """
        Test that a zero uncompressed size limit generates an error.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig,
            "limits",
            SecurityLimits(max_uncompressed_size=0),
        )
        errors = FileSecurityConfig.validate_configuration()
        error_types = [
            e.error_type for e in errors if e.severity == "error"
        ]
        assert "invalid_uncompressed_size" in error_types

    def test_zero_individual_file_size_generates_error(
        self, monkeypatch
    ):
        """
        Test that a zero individual file size limit generates an error.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig,
            "limits",
            SecurityLimits(max_individual_file_size=0),
        )
        errors = FileSecurityConfig.validate_configuration()
        error_types = [
            e.error_type for e in errors if e.severity == "error"
        ]
        assert "invalid_individual_file_size" in error_types

    def test_individual_file_exceeds_total_generates_warning(
        self, monkeypatch
    ):
        """
        Test warning when individual file limit exceeds total limit.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig,
            "limits",
            SecurityLimits(
                max_uncompressed_size=100 * 1024 * 1024,     # 100 MB
                max_individual_file_size=200 * 1024 * 1024,  # 200 MB
            ),
        )
        errors = FileSecurityConfig.validate_configuration()
        warnings = [
            e
            for e in errors
            if e.error_type == "inconsistent_size_limits"
            and e.component == "compression"
        ]
        assert len(warnings) >= 1

    def test_zero_zip_entries_generates_error(self, monkeypatch):
        """
        Test that a zero zip entries limit generates an error.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig,
            "limits",
            SecurityLimits(max_zip_entries=0),
        )
        errors = FileSecurityConfig.validate_configuration()
        error_types = [
            e.error_type for e in errors if e.severity == "error"
        ]
        assert "invalid_zip_entries" in error_types

    def test_excessive_zip_entries_generates_warning(
        self, monkeypatch
    ):
        """
        Test that an excessive zip entries limit generates a warning.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig,
            "limits",
            SecurityLimits(max_zip_entries=200_000),
        )
        errors = FileSecurityConfig.validate_configuration()
        warnings = [
            e
            for e in errors
            if e.error_type == "excessive_zip_entries"
        ]
        assert len(warnings) >= 1

    def test_zero_timeout_generates_error(self, monkeypatch):
        """
        Test that a zero analysis timeout generates an error.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig,
            "limits",
            SecurityLimits(zip_analysis_timeout=0),
        )
        errors = FileSecurityConfig.validate_configuration()
        error_types = [
            e.error_type for e in errors if e.severity == "error"
        ]
        assert "invalid_timeout" in error_types

    def test_excessive_timeout_generates_warning(self, monkeypatch):
        """
        Test that an excessive analysis timeout generates a warning.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig,
            "limits",
            SecurityLimits(zip_analysis_timeout=60.0),
        )
        errors = FileSecurityConfig.validate_configuration()
        warnings = [
            e for e in errors if e.error_type == "excessive_timeout"
        ]
        assert len(warnings) >= 1


class TestValidateAndReport:
    """Tests for validate_and_report method branches."""

    def test_strict_raises_on_configuration_errors(
        self, monkeypatch
    ):
        """
        Test strict mode raises FileSecurityConfigurationError on errors.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig, "ALLOWED_IMAGE_MIMES", set()
        )
        with pytest.raises(FileSecurityConfigurationError) as exc_info:
            FileSecurityConfig.validate_and_report(strict=True)
        assert len(exc_info.value.errors) >= 1
        assert all(
            e.severity == "error" for e in exc_info.value.errors
        )

    def test_strict_raises_on_warnings_only(self, monkeypatch):
        """
        Test strict mode raises when only warnings are present.

        max_compression_ratio=5 generates exactly one warning
        and no errors with default limits otherwise.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig,
            "limits",
            SecurityLimits(max_compression_ratio=5),
        )
        with pytest.raises(FileSecurityConfigurationError):
            FileSecurityConfig.validate_and_report(strict=True)

    def test_non_strict_does_not_raise_on_errors(self, monkeypatch):
        """
        Test that non-strict mode never raises, even on errors.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig, "ALLOWED_IMAGE_MIMES", set()
        )
        try:
            FileSecurityConfig.validate_and_report(strict=False)
        except FileSecurityConfigurationError:
            pytest.fail(
                "validate_and_report(strict=False) must not raise"
            )

    def test_valid_default_config_passes_strict_validation(self):
        """
        Test that the default configuration passes strict mode.

        Returns:
            None
        """
        try:
            FileSecurityConfig.validate_and_report(strict=True)
        except FileSecurityConfigurationError:
            pytest.fail(
                "Default config must pass strict validation"
            )


class TestConfigClassMethods:
    """Tests for class utility methods on FileSecurityConfig."""

    def test_get_extensions_by_category_returns_set(self):
        """
        Test that known dangerous extensions are returned for a category.

        Returns:
            None
        """
        exts = FileSecurityConfig.get_extensions_by_category(
            DangerousExtensionCategory.WINDOWS_EXECUTABLES
        )
        assert ".exe" in exts
        assert ".bat" in exts
        assert ".dll" in exts

    def test_get_extensions_by_category_returns_copy(self):
        """
        Test that the returned set is a copy, not the original.

        Returns:
            None
        """
        exts = FileSecurityConfig.get_extensions_by_category(
            DangerousExtensionCategory.WINDOWS_EXECUTABLES
        )
        exts.discard(".exe")
        assert ".exe" in DangerousExtensionCategory.WINDOWS_EXECUTABLES.value

    def test_get_compound_extensions_by_category(self):
        """
        Test correct compound extensions are returned for a category.

        Returns:
            None
        """
        exts = FileSecurityConfig.get_compound_extensions_by_category(
            CompoundExtensionCategory.COMPRESSED_ARCHIVES
        )
        assert ".tar.gz" in exts
        assert ".tar.bz2" in exts

    def test_get_compound_extensions_returns_copy(self):
        """
        Test that the returned compound extension set is a copy.

        Returns:
            None
        """
        exts = FileSecurityConfig.get_compound_extensions_by_category(
            CompoundExtensionCategory.JAVASCRIPT_VARIANTS
        )
        exts.discard(".user.js")
        assert ".user.js" in CompoundExtensionCategory.JAVASCRIPT_VARIANTS.value

    def test_get_unicode_chars_by_category(self):
        """
        Test that known dangerous code points are returned for a category.

        Returns:
            None
        """
        chars = FileSecurityConfig.get_unicode_chars_by_category(
            UnicodeAttackCategory.DIRECTIONAL_OVERRIDES
        )
        assert 0x202E in chars  # RIGHT-TO-LEFT OVERRIDE
        assert 0x202D in chars  # LEFT-TO-RIGHT OVERRIDE

    def test_get_unicode_chars_returns_copy(self):
        """
        Test that the returned Unicode chars set is a copy.

        Returns:
            None
        """
        chars = FileSecurityConfig.get_unicode_chars_by_category(
            UnicodeAttackCategory.ZERO_WIDTH_CHARACTERS
        )
        chars.discard(0x200B)
        assert 0x200B in UnicodeAttackCategory.ZERO_WIDTH_CHARACTERS.value

    def test_is_extension_in_category_true(self):
        """
        Test that a known dangerous extension is found in its category.

        Returns:
            None
        """
        result = FileSecurityConfig.is_extension_in_category(
            ".exe", DangerousExtensionCategory.WINDOWS_EXECUTABLES
        )
        assert result is True

    def test_is_extension_in_category_false(self):
        """
        Test that a safe extension is not found in a dangerous category.

        Returns:
            None
        """
        result = FileSecurityConfig.is_extension_in_category(
            ".jpg", DangerousExtensionCategory.WINDOWS_EXECUTABLES
        )
        assert result is False

    def test_is_extension_in_category_case_insensitive(self):
        """
        Test that extension category check is case-insensitive.

        Returns:
            None
        """
        result = FileSecurityConfig.is_extension_in_category(
            ".EXE", DangerousExtensionCategory.WINDOWS_EXECUTABLES
        )
        assert result is True

    def test_get_extension_category_found(self):
        """
        Test that a dangerous extension returns its category.

        Returns:
            None
        """
        category = FileSecurityConfig.get_extension_category(".exe")
        assert category == DangerousExtensionCategory.WINDOWS_EXECUTABLES

    def test_get_extension_category_not_found_returns_none(self):
        """
        Test that a safe extension returns None for category lookup.

        Returns:
            None
        """
        category = FileSecurityConfig.get_extension_category(".jpg")
        assert category is None

    def test_get_extension_category_case_insensitive(self):
        """
        Test that category lookup is case-insensitive.

        Returns:
            None
        """
        category = FileSecurityConfig.get_extension_category(".EXE")
        assert category == DangerousExtensionCategory.WINDOWS_EXECUTABLES


class TestCrossDependencyValidation:
    """Tests for _validate_cross_dependencies branches."""

    def test_non_lowercase_reserved_name_generates_warning(
        self, monkeypatch
    ):
        """
        Test that an uppercase reserved name generates a warning.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig,
            "WINDOWS_RESERVED_NAMES",
            {"con", "PRN"},
        )
        errors = FileSecurityConfig.validate_configuration()
        warnings = [
            e
            for e in errors
            if e.error_type == "case_sensitive_reserved_name"
        ]
        assert len(warnings) >= 1

    def test_non_integer_unicode_char_generates_error(
        self, monkeypatch
    ):
        """
        Test error when DANGEROUS_UNICODE_CHARS has non-int.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig,
            "DANGEROUS_UNICODE_CHARS",
            {0x202E, "not_an_int"},
        )
        errors = FileSecurityConfig.validate_configuration()
        error_types = [
            e.error_type
            for e in errors
            if e.severity == "error"
        ]
        assert "invalid_unicode_char" in error_types

    def test_out_of_range_unicode_char_generates_error(
        self, monkeypatch
    ):
        """
        Test error when DANGEROUS_UNICODE_CHARS has out of range.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            FileSecurityConfig,
            "DANGEROUS_UNICODE_CHARS",
            {0x202E, 0x110000},
        )
        errors = FileSecurityConfig.validate_configuration()
        error_types = [
            e.error_type
            for e in errors
            if e.severity == "error"
        ]
        assert "invalid_unicode_range" in error_types


class TestValidateAndReportLogging:
    """Tests for validate_and_report logging paths."""

    def test_valid_config_logs_success(self, caplog):
        """
        Test that valid config logs success message.

        Args:
            caplog: pytest log capture fixture.
        """
        import logging

        with caplog.at_level(logging.INFO, logger="safeuploads.config"):
            FileSecurityConfig.validate_and_report(
                strict=False,
            )
        assert "validation passed" in caplog.text.lower()

    def test_errors_are_logged(
        self, monkeypatch, caplog
    ):
        """
        Test that config errors are logged at ERROR level.

        Args:
            monkeypatch: pytest monkeypatch fixture.
            caplog: pytest log capture fixture.
        """
        import logging

        monkeypatch.setattr(
            FileSecurityConfig,
            "ALLOWED_IMAGE_MIMES",
            set(),
        )
        with caplog.at_level(
            logging.ERROR, logger="safeuploads.config"
        ):
            FileSecurityConfig.validate_and_report(
                strict=False,
            )
        assert "configuration error" in caplog.text.lower()

    def test_warnings_are_logged(
        self, monkeypatch, caplog
    ):
        """
        Test that config warnings are logged at WARNING level.

        Args:
            monkeypatch: pytest monkeypatch fixture.
            caplog: pytest log capture fixture.
        """
        import logging

        monkeypatch.setattr(
            FileSecurityConfig,
            "limits",
            SecurityLimits(max_compression_ratio=5),
        )
        with caplog.at_level(
            logging.WARNING,
            logger="safeuploads.config",
        ):
            FileSecurityConfig.validate_and_report(
                strict=False,
            )
        assert "configuration warning" in caplog.text.lower()

    def test_info_items_are_logged(
        self, monkeypatch, caplog
    ):
        """
        Test that info-level items are logged.

        Args:
            monkeypatch: pytest monkeypatch fixture.
            caplog: pytest log capture fixture.
        """
        import logging

        from safeuploads.exceptions import ConfigValidationError

        original = (
            FileSecurityConfig._validate_enum_consistency
        )

        @classmethod
        def _force_info(cls):
            results = original.__func__(cls)
            results.append(
                ConfigValidationError(
                    error_type="test_info",
                    message="Test info message",
                    severity="info",
                    component="test",
                )
            )
            return results

        monkeypatch.setattr(
            FileSecurityConfig,
            "_validate_enum_consistency",
            _force_info,
        )
        with caplog.at_level(
            logging.INFO, logger="safeuploads.config"
        ):
            FileSecurityConfig.validate_and_report(
                strict=False,
            )
        assert "test info message" in caplog.text.lower()


class TestInitSubclassValidation:
    """Tests for __init_subclass__ validation hook."""

    def test_subclass_triggers_validation(self, caplog):
        """
        Test that creating a subclass triggers validation.

        Args:
            caplog: pytest log capture fixture.
        """
        import logging

        # Creating a subclass should call validate_and_report
        with caplog.at_level(
            logging.DEBUG, logger="safeuploads.config"
        ):

            class _SubConfig(FileSecurityConfig):
                pass

        # Validation ran without raising (non-strict)
        assert _SubConfig is not None
