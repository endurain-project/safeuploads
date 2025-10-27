"""Tests for extension security validator."""

import pytest

from safeuploads.config import FileSecurityConfig
from safeuploads.validators.extension_validator import ExtensionSecurityValidator
from safeuploads.exceptions import ExtensionSecurityError, ErrorCode


class TestExtensionSecurityValidator:
    """Test ExtensionSecurityValidator class."""

    def test_initialization(self, default_config):
        """Test validator initialization."""
        validator = ExtensionSecurityValidator(default_config)
        assert validator.config == default_config

    def test_validate_safe_extension(self, default_config):
        """Test validation of safe file extension."""
        validator = ExtensionSecurityValidator(default_config)
        # .txt is not in blocked extensions
        validator.validate_extensions("document.txt")
        # No exception raised means success

    def test_validate_image_extension(self, default_config):
        """Test validation of image file extension."""
        validator = ExtensionSecurityValidator(default_config)
        validator.validate_extensions("photo.jpg")
        validator.validate_extensions("image.png")
        # No exceptions raised

    def test_reject_executable_extension(self, default_config):
        """Test rejection of executable file extension."""
        validator = ExtensionSecurityValidator(default_config)

        with pytest.raises(ExtensionSecurityError) as exc_info:
            validator.validate_extensions("malware.exe")

        error = exc_info.value
        assert ".exe" in error.message
        assert error.extension == ".exe"
        assert error.error_code == ErrorCode.EXTENSION_BLOCKED

    def test_reject_script_extensions(self, default_config):
        """Test rejection of various script file extensions."""
        validator = ExtensionSecurityValidator(default_config)

        dangerous_scripts = [
            "script.bat",
            "command.cmd",
            "shell.sh",
            "code.js",
            "script.vbs",
            "program.ps1",
        ]

        for filename in dangerous_scripts:
            with pytest.raises(ExtensionSecurityError):
                validator.validate_extensions(filename)

    def test_reject_compound_extension_tar_gz(self, default_config):
        """Test rejection of .tar.gz compound extension."""
        validator = ExtensionSecurityValidator(default_config)

        with pytest.raises(ExtensionSecurityError) as exc_info:
            validator.validate_extensions("archive.tar.gz")

        error = exc_info.value
        assert ".tar.gz" in error.message
        assert error.error_code == ErrorCode.COMPOUND_EXTENSION_BLOCKED

    def test_reject_compound_extension_user_js(self, default_config):
        """Test rejection of .user.js compound extension."""
        validator = ExtensionSecurityValidator(default_config)

        with pytest.raises(ExtensionSecurityError) as exc_info:
            validator.validate_extensions("greasemonkey.user.js")

        error = exc_info.value
        assert ".user.js" in error.message
        assert error.error_code == ErrorCode.COMPOUND_EXTENSION_BLOCKED

    def test_compound_extension_checked_before_single(self, default_config):
        """Test that compound extensions are checked before single extensions."""
        validator = ExtensionSecurityValidator(default_config)

        # .tar.gz should be caught as compound extension first
        with pytest.raises(ExtensionSecurityError) as exc_info:
            validator.validate_extensions("file.tar.gz")

        error = exc_info.value
        assert error.error_code == ErrorCode.COMPOUND_EXTENSION_BLOCKED

    def test_reject_multiple_extensions_with_dangerous_one(self, default_config):
        """Test rejection when multiple extensions include dangerous one."""
        validator = ExtensionSecurityValidator(default_config)

        # file.txt.exe should be rejected because of .exe
        with pytest.raises(ExtensionSecurityError):
            validator.validate_extensions("document.txt.exe")

    def test_case_insensitive_extension_check(self, default_config):
        """Test that extension checking is case-insensitive."""
        validator = ExtensionSecurityValidator(default_config)

        # Should reject .EXE, .Exe, .exe, etc.
        with pytest.raises(ExtensionSecurityError):
            validator.validate_extensions("malware.EXE")

        with pytest.raises(ExtensionSecurityError):
            validator.validate_extensions("malware.Exe")

    def test_case_insensitive_compound_extension(self, default_config):
        """Test case-insensitive compound extension checking."""
        validator = ExtensionSecurityValidator(default_config)

        with pytest.raises(ExtensionSecurityError):
            validator.validate_extensions("archive.TAR.GZ")

        with pytest.raises(ExtensionSecurityError):
            validator.validate_extensions("archive.Tar.Gz")

    def test_validate_method_delegates_correctly(self, default_config):
        """Test that validate() method delegates to validate_extensions()."""
        validator = ExtensionSecurityValidator(default_config)

        # Should not raise for safe extension
        validator.validate("safe.txt")

        # Should raise for dangerous extension
        with pytest.raises(ExtensionSecurityError):
            validator.validate("dangerous.exe")

    def test_all_parts_checked_for_dangerous_extensions(self, default_config):
        """Test that all extension parts are checked."""
        validator = ExtensionSecurityValidator(default_config)

        # file.doc.exe - should catch .exe even though .doc is first
        with pytest.raises(ExtensionSecurityError) as exc_info:
            validator.validate_extensions("report.doc.exe")

        error = exc_info.value
        assert ".exe" in error.message or "exe" in error.message.lower()

    def test_error_includes_filename(self, default_config):
        """Test that error includes the problematic filename."""
        validator = ExtensionSecurityValidator(default_config)
        filename = "malware.exe"

        with pytest.raises(ExtensionSecurityError) as exc_info:
            validator.validate_extensions(filename)

        error = exc_info.value
        assert error.filename == filename

    def test_reject_dll_extension(self, default_config):
        """Test rejection of DLL files."""
        validator = ExtensionSecurityValidator(default_config)

        with pytest.raises(ExtensionSecurityError):
            validator.validate_extensions("library.dll")

    def test_reject_msi_extension(self, default_config):
        """Test rejection of MSI installer files."""
        validator = ExtensionSecurityValidator(default_config)

        with pytest.raises(ExtensionSecurityError):
            validator.validate_extensions("installer.msi")

    def test_reject_scr_extension(self, default_config):
        """Test rejection of screensaver executable files."""
        validator = ExtensionSecurityValidator(default_config)

        with pytest.raises(ExtensionSecurityError):
            validator.validate_extensions("screensaver.scr")

    def test_no_extension_file_allowed(self, default_config):
        """Test that files without extensions are allowed."""
        validator = ExtensionSecurityValidator(default_config)
        # Files without extensions should not trigger blocked extension check
        validator.validate_extensions("README")
        validator.validate_extensions("Makefile")

    def test_hidden_file_allowed_if_extension_safe(self, default_config):
        """Test that hidden files with safe extensions are allowed."""
        validator = ExtensionSecurityValidator(default_config)
        validator.validate_extensions(".hidden.txt")

    def test_reject_hidden_file_with_dangerous_extension(self, default_config):
        """Test rejection of hidden files with dangerous extensions."""
        validator = ExtensionSecurityValidator(default_config)

        with pytest.raises(ExtensionSecurityError):
            validator.validate_extensions(".hidden.exe")

    def test_multiple_dots_with_safe_extensions(self, default_config):
        """Test files with multiple dots but safe extensions."""
        validator = ExtensionSecurityValidator(default_config)
        # Should be allowed - no dangerous extensions
        validator.validate_extensions("my.document.v2.txt")
        validator.validate_extensions("file.2024.10.27.log")
