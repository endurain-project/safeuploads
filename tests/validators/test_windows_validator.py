"""Tests for Windows security validator."""

import pytest

from safeuploads.config import FileSecurityConfig
from safeuploads.validators.windows_validator import WindowsSecurityValidator
from safeuploads.exceptions import WindowsReservedNameError


class TestWindowsSecurityValidator:
    """Test WindowsSecurityValidator class."""

    def test_initialization(self, default_config):
        """Test validator initialization."""
        validator = WindowsSecurityValidator(default_config)
        assert validator.config == default_config

    def test_validate_normal_filename(self, default_config):
        """Test validation of normal filename."""
        validator = WindowsSecurityValidator(default_config)
        validator.validate_windows_reserved_names("document.txt")
        validator.validate_windows_reserved_names("photo.jpg")
        # No exceptions means success

    def test_reject_con_device_name(self, default_config):
        """Test rejection of CON reserved device name."""
        validator = WindowsSecurityValidator(default_config)

        with pytest.raises(WindowsReservedNameError) as exc_info:
            validator.validate_windows_reserved_names("CON.txt")

        error = exc_info.value
        assert "CON" in error.message
        assert error.reserved_name == "CON"

    def test_reject_prn_device_name(self, default_config):
        """Test rejection of PRN reserved device name."""
        validator = WindowsSecurityValidator(default_config)

        with pytest.raises(WindowsReservedNameError) as exc_info:
            validator.validate_windows_reserved_names("PRN.doc")

        error = exc_info.value
        assert error.reserved_name == "PRN"

    def test_reject_aux_device_name(self, default_config):
        """Test rejection of AUX reserved device name."""
        validator = WindowsSecurityValidator(default_config)

        with pytest.raises(WindowsReservedNameError):
            validator.validate_windows_reserved_names("AUX.log")

    def test_reject_nul_device_name(self, default_config):
        """Test rejection of NUL reserved device name."""
        validator = WindowsSecurityValidator(default_config)

        with pytest.raises(WindowsReservedNameError):
            validator.validate_windows_reserved_names("NUL.dat")

    def test_reject_com_ports(self, default_config):
        """Test rejection of COM port device names."""
        validator = WindowsSecurityValidator(default_config)

        for i in range(1, 10):
            with pytest.raises(WindowsReservedNameError) as exc_info:
                validator.validate_windows_reserved_names(f"COM{i}.txt")
            assert exc_info.value.reserved_name == f"COM{i}"

    def test_reject_lpt_ports(self, default_config):
        """Test rejection of LPT port device names."""
        validator = WindowsSecurityValidator(default_config)

        for i in range(1, 10):
            with pytest.raises(WindowsReservedNameError) as exc_info:
                validator.validate_windows_reserved_names(f"LPT{i}.doc")
            assert exc_info.value.reserved_name == f"LPT{i}"

    def test_case_insensitive_reserved_names(self, default_config):
        """Test that reserved name checking is case-insensitive."""
        validator = WindowsSecurityValidator(default_config)

        # Should reject all case variations
        with pytest.raises(WindowsReservedNameError):
            validator.validate_windows_reserved_names("con.txt")

        with pytest.raises(WindowsReservedNameError):
            validator.validate_windows_reserved_names("Con.txt")

        with pytest.raises(WindowsReservedNameError):
            validator.validate_windows_reserved_names("CON.txt")

    def test_reserved_name_without_extension(self, default_config):
        """Test rejection of reserved names without extensions."""
        validator = WindowsSecurityValidator(default_config)

        with pytest.raises(WindowsReservedNameError):
            validator.validate_windows_reserved_names("CON")

        with pytest.raises(WindowsReservedNameError):
            validator.validate_windows_reserved_names("PRN")

    def test_reserved_name_with_leading_dot(self, default_config):
        """Test rejection of hidden reserved names."""
        validator = WindowsSecurityValidator(default_config)

        # .CON.txt should still be rejected
        with pytest.raises(WindowsReservedNameError):
            validator.validate_windows_reserved_names(".CON.txt")

    def test_reserved_name_with_trailing_dots(self, default_config):
        """Test rejection of reserved names with trailing dots."""
        validator = WindowsSecurityValidator(default_config)

        # CON. and CON.. should be rejected
        with pytest.raises(WindowsReservedNameError):
            validator.validate_windows_reserved_names("CON.")

        with pytest.raises(WindowsReservedNameError):
            validator.validate_windows_reserved_names("CON..")

    def test_reserved_name_with_spaces(self, default_config):
        """Test rejection of reserved names with spaces."""
        validator = WindowsSecurityValidator(default_config)

        # " CON " with spaces should be rejected after stripping
        with pytest.raises(WindowsReservedNameError):
            validator.validate_windows_reserved_names(" CON .txt")

    def test_filename_containing_but_not_matching_reserved(self, default_config):
        """Test that filenames containing reserved words are allowed."""
        validator = WindowsSecurityValidator(default_config)

        # These should be allowed - they contain but don't match reserved names
        validator.validate_windows_reserved_names("console.txt")
        validator.validate_windows_reserved_names("printer.doc")
        validator.validate_windows_reserved_names("context.log")
        validator.validate_windows_reserved_names("acon.txt")

    def test_validate_method_delegates_correctly(self, default_config):
        """Test that validate() method delegates correctly."""
        validator = WindowsSecurityValidator(default_config)

        # Should not raise for safe filename
        validator.validate("normal.txt")

        # Should raise for reserved name
        with pytest.raises(WindowsReservedNameError):
            validator.validate("CON.txt")

    def test_error_includes_filename(self, default_config):
        """Test that error includes the problematic filename."""
        validator = WindowsSecurityValidator(default_config)
        filename = "CON.txt"

        with pytest.raises(WindowsReservedNameError) as exc_info:
            validator.validate_windows_reserved_names(filename)

        error = exc_info.value
        assert error.filename == filename

    def test_all_reserved_names_covered(self, default_config):
        """Test all Windows reserved device names are rejected."""
        validator = WindowsSecurityValidator(default_config)

        reserved_names = [
            "CON",
            "PRN",
            "AUX",
            "NUL",
            "COM1",
            "COM2",
            "COM3",
            "COM4",
            "COM5",
            "COM6",
            "COM7",
            "COM8",
            "COM9",
            "LPT1",
            "LPT2",
            "LPT3",
            "LPT4",
            "LPT5",
            "LPT6",
            "LPT7",
            "LPT8",
            "LPT9",
        ]

        for reserved in reserved_names:
            with pytest.raises(WindowsReservedNameError):
                validator.validate_windows_reserved_names(f"{reserved}.txt")

    def test_reserved_name_various_extensions(self, default_config):
        """Test reserved names with various file extensions."""
        validator = WindowsSecurityValidator(default_config)

        extensions = [".txt", ".doc", ".jpg", ".exe", ".zip", ""]

        for ext in extensions:
            with pytest.raises(WindowsReservedNameError):
                validator.validate_windows_reserved_names(f"CON{ext}")

    def test_compound_extension_with_reserved_name(self, default_config):
        """Test reserved names with compound extensions.

        The validator now checks all intermediate basenames when removing
        extensions iteratively, so 'CON.tar.gz' is properly detected.
        """
        validator = WindowsSecurityValidator(default_config)

        # These ARE caught - compound extensions with reserved names
        with pytest.raises(WindowsReservedNameError):
            validator.validate_windows_reserved_names("CON.tar.gz")

        with pytest.raises(WindowsReservedNameError):
            validator.validate_windows_reserved_names("PRN.backup.zip")

        with pytest.raises(WindowsReservedNameError):
            validator.validate_windows_reserved_names("AUX.tar.bz2")

        # These should be allowed - not reserved names
        validator.validate_windows_reserved_names("console.tar.gz")
        validator.validate_windows_reserved_names("content.backup.zip")
