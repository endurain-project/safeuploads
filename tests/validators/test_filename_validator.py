"""Tests for filename security validator."""

import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.validators.filename_validator import (
    FilenameSecurityValidator,
)


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
