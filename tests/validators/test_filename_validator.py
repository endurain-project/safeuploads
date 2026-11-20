"""Tests for filename security validator."""

import io

import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.exceptions import (
    ErrorCode,
    ExtensionSecurityError,
    WindowsReservedNameError,
)
from safeuploads.file_validator import FileValidator
from safeuploads.validators.filename_validator import (
    FilenameSecurityValidator,
)
from tests.images import png


def _validator_with_limit(limit: int) -> FilenameSecurityValidator:
    """Return a validator whose base name limit is ``limit`` bytes."""
    config = FileSecurityConfig()
    config.limits = SecurityLimits(max_sanitized_name_length=limit)
    return FilenameSecurityValidator(config)


@pytest.fixture
def validator(default_config) -> FilenameSecurityValidator:
    """Return a validator with the default configuration."""
    return FilenameSecurityValidator(default_config)


class TestReplaceDangerousCharacters:
    """Test basename extraction and character replacement."""

    def test_safe_name_unchanged(self, validator):
        """A safe filename is returned as is."""
        assert validator.replace_dangerous_characters("a-b_1.jpg") == (
            "a-b_1.jpg"
        )

    @pytest.mark.parametrize(
        ("filename", "expected"),
        [
            ("../../etc/passwd.txt", "passwd.txt"),
            ("dir/photo.jpg", "photo.jpg"),
            ("a<b>c.txt", "a_b_c.txt"),
            ('a:b"c|d?e*f.txt', "a_b_c_d_e_f.txt"),
            ("back\\slash.txt", "back_slash.txt"),
        ],
    )
    def test_paths_and_dangerous_characters(
        self, validator, filename, expected
    ):
        """Path components are dropped and unsafe characters replaced."""
        assert validator.replace_dangerous_characters(filename) == expected

    def test_validate_delegates(self, validator):
        """validate applies the character replacement."""
        assert validator.validate("x/y?.txt") == "y_.txt"


class TestLimitLength:
    """Test truncation and empty-name substitution."""

    def test_short_name_unchanged(self, validator):
        """A name within the limit is returned as is."""
        assert validator.limit_length("photo.jpg") == "photo.jpg"

    def test_truncates_base_name_keeps_extension(self):
        """Only the base name is truncated."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(max_sanitized_name_length=10)
        validator = FilenameSecurityValidator(config)
        assert validator.limit_length("a" * 50 + ".jpg") == "a" * 10 + ".jpg"

    def test_name_at_limit_unchanged(self):
        """A base name exactly at the limit is kept."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(max_sanitized_name_length=10)
        validator = FilenameSecurityValidator(config)
        assert validator.limit_length("a" * 10 + ".jpg") == "a" * 10 + ".jpg"

    def test_blank_name_gets_random_name(self, validator):
        """A blank base name is replaced and the extension kept."""
        result = validator.limit_length("   .jpg")
        assert result.startswith("file_")
        assert result.endswith(".jpg")
        assert len(result) == len("file_") + 16 + len(".jpg")


class TestLimitLengthBytes:
    """The base name limit counts UTF-8 bytes, not characters."""

    def test_two_byte_characters_truncated_by_bytes(self):
        """Ten bytes hold five two-byte characters."""
        validator = _validator_with_limit(10)

        assert validator.limit_length("\u00e9" * 20 + ".jpg") == (
            "\u00e9" * 5 + ".jpg"
        )

    def test_name_at_byte_limit_unchanged(self):
        """A base name of exactly the limit in bytes is kept."""
        validator = _validator_with_limit(10)

        assert validator.limit_length("\u00e9" * 5 + ".jpg") == (
            "\u00e9" * 5 + ".jpg"
        )

    @pytest.mark.parametrize("limit", [9, 10, 11, 12])
    def test_never_cuts_a_multibyte_character(self, limit):
        """A character crossing the limit is dropped whole."""
        validator = _validator_with_limit(limit)

        result = validator.limit_length("a" + "\U0001f600" * 5 + ".jpg")

        name = result.removesuffix(".jpg")
        assert name == "a" + "\U0001f600" * ((limit - 1) // 4)
        assert len(name.encode("utf-8")) <= limit

    def test_default_limit_keeps_emoji_name_storable(self, validator):
        """150 emoji plus .png fit a 255-byte filesystem name."""
        result = validator.limit_length("\U0001f600" * 150 + ".png")

        assert result == "\U0001f600" * 25 + ".png"
        assert len(result.encode("utf-8")) <= 255


class TestSanitizedNameBytesPipeline:
    """Byte truncation is rechecked by the full filename pipeline."""

    @staticmethod
    def _file_validator(limit: int) -> FileValidator:
        config = FileSecurityConfig()
        config.limits = SecurityLimits(max_sanitized_name_length=limit)
        return FileValidator(config)

    def test_emoji_name_accepted_within_bytes(self):
        """A long emoji name is truncated to the default byte limit."""
        result = FileValidator().validate_image_file_sync(
            io.BytesIO(png()), "\U0001f600" * 150 + ".png"
        )

        assert result.filename == "\U0001f600" * 25 + ".png"
        assert len(result.filename.encode("utf-8")) <= 255

    def test_truncation_exposing_blocked_extension_rejected(self):
        """Dropping trailing emoji cannot expose a blocked extension."""
        with pytest.raises(ExtensionSecurityError) as exc_info:
            self._file_validator(7).validate_image_file_sync(
                io.BytesIO(png()), "x.php\U0001f600\U0001f600.png"
            )

        assert exc_info.value.error_code == ErrorCode.EXTENSION_BLOCKED

    def test_truncation_exposing_reserved_name_rejected(self):
        """Dropping trailing emoji cannot expose a reserved name."""
        with pytest.raises(WindowsReservedNameError) as exc_info:
            self._file_validator(4).validate_image_file_sync(
                io.BytesIO(png()), "con\U0001f600.png"
            )

        assert exc_info.value.error_code == ErrorCode.WINDOWS_RESERVED_NAME
