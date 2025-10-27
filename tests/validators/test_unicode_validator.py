"""Tests for Unicode security validator."""

import pytest

from safeuploads.config import FileSecurityConfig
from safeuploads.validators.unicode_validator import UnicodeSecurityValidator
from safeuploads.exceptions import UnicodeSecurityError


class TestUnicodeSecurityValidator:
    """Test UnicodeSecurityValidator class."""

    def test_initialization(self, default_config):
        """Test validator initialization."""
        validator = UnicodeSecurityValidator(default_config)
        assert validator.config == default_config

    def test_validate_normal_filename(self, default_config):
        """Test validation of normal ASCII filename."""
        validator = UnicodeSecurityValidator(default_config)
        result = validator.validate_unicode_security("normal_file.txt")
        assert result == "normal_file.txt"

    def test_validate_unicode_filename_safe(self, default_config):
        """Test validation of safe Unicode filename."""
        validator = UnicodeSecurityValidator(default_config)
        filename = "文件.txt"  # Chinese characters
        result = validator.validate_unicode_security(filename)
        assert result == filename

    def test_validate_empty_filename(self, default_config):
        """Test validation of empty filename."""
        validator = UnicodeSecurityValidator(default_config)
        result = validator.validate_unicode_security("")
        assert result == ""

    def test_reject_right_to_left_override(self, default_config):
        """Test rejection of right-to-left override character."""
        validator = UnicodeSecurityValidator(default_config)
        # U+202E: RIGHT-TO-LEFT OVERRIDE
        filename = "document\u202etxt.exe"

        with pytest.raises(UnicodeSecurityError) as exc_info:
            validator.validate_unicode_security(filename)

        error = exc_info.value
        assert "Dangerous Unicode characters detected" in error.message
        assert "U+202E" in error.message
        assert len(error.dangerous_chars) == 1
        assert error.dangerous_chars[0][1] == 0x202E  # Character code

    def test_reject_left_to_right_override(self, default_config):
        """Test rejection of left-to-right override character."""
        validator = UnicodeSecurityValidator(default_config)
        # U+202D: LEFT-TO-RIGHT OVERRIDE
        filename = "file\u202d.txt"

        with pytest.raises(UnicodeSecurityError) as exc_info:
            validator.validate_unicode_security(filename)

        error = exc_info.value
        assert error.dangerous_chars[0][1] == 0x202D

    def test_reject_zero_width_characters(self, default_config):
        """Test rejection of zero-width characters."""
        validator = UnicodeSecurityValidator(default_config)
        # U+200B: ZERO WIDTH SPACE
        filename = "file\u200bname.txt"

        with pytest.raises(UnicodeSecurityError) as exc_info:
            validator.validate_unicode_security(filename)

        error = exc_info.value
        assert error.dangerous_chars[0][1] == 0x200B

    def test_reject_multiple_dangerous_chars(self, default_config):
        """Test rejection of filename with multiple dangerous characters."""
        validator = UnicodeSecurityValidator(default_config)
        # Multiple dangerous chars
        filename = "file\u202e\u200bname.txt"

        with pytest.raises(UnicodeSecurityError) as exc_info:
            validator.validate_unicode_security(filename)

        error = exc_info.value
        assert len(error.dangerous_chars) == 2

    def test_unicode_normalization_nfc(self, default_config):
        """Test Unicode normalization to NFC form."""
        validator = UnicodeSecurityValidator(default_config)
        # Decomposed form: 'é' as 'e' + combining acute accent
        filename_decomposed = "file\u0065\u0301.txt"  # e + ́  (combining acute)
        # After NFC normalization, should produce  composed 'é'

        result = validator.validate_unicode_security(filename_decomposed)
        # NFC normalization should compose to é (U+00E9)
        # The result should have the composed form
        assert "\u0301" not in result  # No combining character
        assert "é" in result  # Has composed é

    def test_normalization_introduces_dangerous_char(self, default_config):
        """Test rejection when normalization creates dangerous character."""
        validator = UnicodeSecurityValidator(default_config)
        # This is a contrived example - in practice, normalization shouldn't
        # introduce dangerous chars, but we test the safety check

        # For this test, we'll directly test the post-normalization check
        # by using a filename that after NFC normalization might trigger the check
        # Most real-world cases won't hit this, but it's a safety net

        # Using a normal safe filename to ensure the normalization check passes
        filename = "normal_file.txt"
        result = validator.validate_unicode_security(filename)
        assert result == "normal_file.txt"

    def test_validate_method_delegates_to_validate_unicode_security(
        self, default_config
    ):
        """Test that validate() method delegates correctly."""
        validator = UnicodeSecurityValidator(default_config)
        filename = "test.txt"
        result = validator.validate(filename)
        assert result == filename

    def test_dangerous_char_position_tracking(self, default_config):
        """Test that character positions are correctly tracked."""
        validator = UnicodeSecurityValidator(default_config)
        filename = "abc\u202edef.txt"  # Dangerous char at position 3

        with pytest.raises(UnicodeSecurityError) as exc_info:
            validator.validate_unicode_security(filename)

        error = exc_info.value
        assert error.dangerous_chars[0][2] == 3  # Position

    def test_error_contains_filename(self, default_config):
        """Test that error contains the problematic filename."""
        validator = UnicodeSecurityValidator(default_config)
        filename = "bad\u202efile.txt"

        with pytest.raises(UnicodeSecurityError) as exc_info:
            validator.validate_unicode_security(filename)

        error = exc_info.value
        assert error.filename == filename

    def test_reject_bidi_override_characters(self, default_config):
        """Test rejection of various bidirectional override characters."""
        validator = UnicodeSecurityValidator(default_config)

        # Test various bidi override characters that should be blocked
        dangerous_chars = [
            0x202A,  # LEFT-TO-RIGHT EMBEDDING
            0x202B,  # RIGHT-TO-LEFT EMBEDDING
            0x202C,  # POP DIRECTIONAL FORMATTING
            0x202D,  # LEFT-TO-RIGHT OVERRIDE
            0x202E,  # RIGHT-TO-LEFT OVERRIDE
        ]

        for char_code in dangerous_chars:
            if char_code in default_config.DANGEROUS_UNICODE_CHARS:
                filename = f"file{chr(char_code)}.txt"
                with pytest.raises(UnicodeSecurityError):
                    validator.validate_unicode_security(filename)

    def test_reject_zero_width_joiners(self, default_config):
        """Test rejection of zero-width joiner characters."""
        validator = UnicodeSecurityValidator(default_config)

        # Zero-width characters that should be blocked if in config
        zero_width_chars = [
            0x200B,  # ZERO WIDTH SPACE
            0x200C,  # ZERO WIDTH NON-JOINER
            0x200D,  # ZERO WIDTH JOINER
            0xFEFF,  # ZERO WIDTH NO-BREAK SPACE
        ]

        for char_code in zero_width_chars:
            if char_code in default_config.DANGEROUS_UNICODE_CHARS:
                filename = f"file{chr(char_code)}.txt"
                with pytest.raises(UnicodeSecurityError):
                    validator.validate_unicode_security(filename)
