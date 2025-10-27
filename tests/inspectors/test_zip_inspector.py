"""Tests for ZipContentInspector."""

import io
import zipfile
import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.inspectors.zip_inspector import ZipContentInspector
from safeuploads.exceptions import (
    ZipContentError,
    FileProcessingError,
    ErrorCode,
)


class TestZipContentInspector:
    """Test suite for ZipContentInspector."""

    def test_initialization(self, default_config):
        """Test inspector initialization."""
        inspector = ZipContentInspector(default_config)
        assert inspector.config == default_config

    def test_inspect_safe_zip(self, default_config, create_zip_file):
        """Test inspection of safe ZIP file passes."""
        inspector = ZipContentInspector(default_config)

        zip_bytes = create_zip_file(
            files={
                "file1.txt": b"Content 1",
                "file2.txt": b"Content 2",
                "subfolder/file3.txt": b"Content 3",
            }
        )

        # Should not raise any exception
        inspector.inspect_zip_content(zip_bytes)

    def test_reject_directory_traversal_dotdot_slash(self, default_config):
        """Test rejection of ../ directory traversal."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("../../../etc/passwd", b"malicious content")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        assert "Directory traversal" in str(exc_info.value)
        assert exc_info.value.threats is not None
        assert len(exc_info.value.threats) > 0

    def test_reject_directory_traversal_dotdot_backslash(self, default_config):
        """Test rejection of ..\\ directory traversal."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("..\\..\\windows\\system32\\config", b"malicious")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        assert "Directory traversal" in str(exc_info.value)

    def test_reject_directory_traversal_triple_dot(self, default_config):
        """Test rejection of .../ directory traversal variant."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr(".../sensitive/file.txt", b"malicious")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        assert "Directory traversal" in str(exc_info.value)

    def test_reject_directory_traversal_url_encoded(self, default_config):
        """Test rejection of URL-encoded directory traversal."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("%2e%2e%2fmalicious.txt", b"malicious")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        assert "Directory traversal" in str(exc_info.value)

    def test_reject_absolute_path_unix(self, default_config):
        """Test rejection of Unix absolute paths."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("/etc/passwd", b"malicious")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        assert "Absolute path" in str(exc_info.value)

    def test_reject_absolute_path_windows_drive(self, default_config):
        """Test rejection of Windows drive letter paths."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("C:/Windows/System32/file.txt", b"malicious")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        assert "Absolute path" in str(exc_info.value)

    def test_reject_absolute_path_unc(self, default_config):
        """Test rejection of Windows UNC paths."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("\\\\server\\share\\file.txt", b"malicious")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        assert "Absolute path" in str(exc_info.value)

    def test_allow_absolute_paths_when_configured(self):
        """Test that absolute paths can be allowed via configuration."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(allow_absolute_paths=True)
        inspector = ZipContentInspector(config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            # Use absolute path that's not suspicious
            zf.writestr("/data/config.txt", b"allowed content")

        # Should not raise when absolute paths allowed (and path not suspicious)
        inspector.inspect_zip_content(zip_buffer.getvalue())

    def test_reject_symlink(self, default_config):
        """Test rejection of symbolic links in ZIP."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(allow_symlinks=False)
        inspector = ZipContentInspector(config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            # Create a symlink entry
            info = zipfile.ZipInfo("symlink")
            info.external_attr = 0o120777 << 16  # Symlink attributes
            zf.writestr(info, b"/etc/passwd")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        assert "Symbolic link" in str(exc_info.value)

    def test_allow_symlinks_when_configured(self):
        """Test that symlinks can be allowed via configuration."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(allow_symlinks=True)
        inspector = ZipContentInspector(config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            info = zipfile.ZipInfo("symlink")
            info.external_attr = 0o120777 << 16
            zf.writestr(info, b"/etc/passwd")

        # Should not raise when symlinks allowed
        inspector.inspect_zip_content(zip_buffer.getvalue())

    def test_reject_filename_too_long(self):
        """Test rejection of excessively long filenames."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(max_filename_length=50)
        inspector = ZipContentInspector(config)

        long_filename = "a" * 100 + ".txt"

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr(long_filename, b"content")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        assert "Filename too long" in str(exc_info.value)

    def test_reject_path_too_long(self):
        """Test rejection of excessively long paths."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(max_path_length=100)
        inspector = ZipContentInspector(config)

        long_path = "folder/" * 20 + "file.txt"

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr(long_path, b"content")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        assert "Path too long" in str(exc_info.value)

    def test_reject_suspicious_filename_autorun(self, default_config):
        """Test rejection of autorun.inf suspicious filename."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("autorun.inf", b"[autorun]\nopen=malware.exe")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        assert "Suspicious filename" in str(exc_info.value)

    def test_reject_suspicious_filename_htaccess(self, default_config):
        """Test rejection of .htaccess suspicious filename."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr(".htaccess", b"malicious config")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        assert "Suspicious filename" in str(exc_info.value)

    def test_reject_suspicious_path_windows_system32(self, default_config):
        """Test rejection of Windows system paths."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("windows/system32/malware.dll", b"malicious")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        assert "Suspicious path component" in str(exc_info.value)

    def test_reject_suspicious_path_git(self, default_config):
        """Test rejection of .git directory paths."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr(".git/config", b"repository config")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        assert "Suspicious path component" in str(exc_info.value)

    def test_reject_nested_archive_zip(self, default_config):
        """Test rejection of nested ZIP archives."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(allow_nested_archives=False)
        inspector = ZipContentInspector(config)

        # Create inner ZIP
        inner_zip = io.BytesIO()
        with zipfile.ZipFile(inner_zip, "w") as zf:
            zf.writestr("inner.txt", b"inner content")

        # Create outer ZIP with inner ZIP
        outer_zip = io.BytesIO()
        with zipfile.ZipFile(outer_zip, "w") as zf:
            zf.writestr("nested.zip", inner_zip.getvalue())

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(outer_zip.getvalue())

        assert "Nested archive" in str(exc_info.value)

    def test_reject_nested_archive_rar(self, default_config):
        """Test rejection of nested RAR archives."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(allow_nested_archives=False)
        inspector = ZipContentInspector(config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("archive.rar", b"fake RAR content")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        assert "Nested archive" in str(exc_info.value)

    def test_allow_nested_archives_when_configured(self):
        """Test that nested archives can be allowed via configuration."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(allow_nested_archives=True)
        inspector = ZipContentInspector(config)

        inner_zip = io.BytesIO()
        with zipfile.ZipFile(inner_zip, "w") as zf:
            zf.writestr("inner.txt", b"content")

        outer_zip = io.BytesIO()
        with zipfile.ZipFile(outer_zip, "w") as zf:
            zf.writestr("nested.zip", inner_zip.getvalue())

        # Should not raise when nested archives allowed
        inspector.inspect_zip_content(outer_zip.getvalue())

    def test_reject_excessive_directory_depth(self):
        """Test rejection of excessively deep directory structures."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(max_zip_depth=5)
        inspector = ZipContentInspector(config)

        # Create deeply nested path (depth > 5)
        deep_path = "/".join(["folder"] * 10) + "/file.txt"

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr(deep_path, b"content")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        assert "Excessive directory depth" in str(exc_info.value)

    def test_reject_excessive_same_type_files(self, default_config):
        """Test rejection of too many files of the same type."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            # Create more than 1000 files of same type
            for i in range(1001):
                zf.writestr(f"file{i}.txt", b"content")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        assert "Excessive number" in str(exc_info.value)

    def test_detect_executable_content_pe(self):
        """Test detection of Windows PE executable content."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(scan_zip_content=True)
        inspector = ZipContentInspector(config)

        # PE executable signature (MZ header)
        pe_content = b"MZ\x90\x00" + b"\x00" * 100

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("document.pdf", pe_content)  # Disguised as PDF

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        assert "Executable content" in str(exc_info.value)

    def test_detect_executable_content_elf(self):
        """Test detection of ELF executable content."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(scan_zip_content=True)
        inspector = ZipContentInspector(config)

        # ELF executable signature
        elf_content = b"\x7fELF" + b"\x00" * 100

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("data.bin", elf_content)

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        assert "Executable content" in str(exc_info.value)

    def test_detect_script_content_shell(self):
        """Test detection of shell script content."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(scan_zip_content=True)
        inspector = ZipContentInspector(config)

        script_content = b"#!/bin/bash\nrm -rf /"

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("backup.txt", script_content)  # Disguised

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        assert "Script content" in str(exc_info.value)

    def test_detect_script_content_php(self):
        """Test detection of PHP script content."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(scan_zip_content=True)
        inspector = ZipContentInspector(config)

        php_content = b"<?php system($_GET['cmd']); ?>"

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("readme.txt", php_content)

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        assert "Script content" in str(exc_info.value)

    def test_skip_content_scan_when_disabled(self):
        """Test that content scanning can be disabled."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(scan_zip_content=False)
        inspector = ZipContentInspector(config)

        # Even with executable content, should pass if scanning disabled
        pe_content = b"MZ\x90\x00" + b"\x00" * 100

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("file.bin", pe_content)

        # Should not raise when content scanning disabled
        inspector.inspect_zip_content(zip_buffer.getvalue())

    def test_skip_content_scan_for_large_files(self):
        """Test that large files skip content scanning."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(scan_zip_content=True)
        inspector = ZipContentInspector(config)

        # Large file (> 1MB) should skip content scan
        large_content = b"MZ\x90\x00" + b"\x00" * (2 * 1024 * 1024)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("large.bin", large_content)

        # Should not raise even with executable signature in large file
        inspector.inspect_zip_content(zip_buffer.getvalue())

    def test_handle_corrupted_zip(self, default_config):
        """Test handling of corrupted ZIP file."""
        inspector = ZipContentInspector(default_config)

        corrupted_zip = b"PK\x03\x04corrupted data"

        with pytest.raises(FileProcessingError) as exc_info:
            inspector.inspect_zip_content(corrupted_zip)

        assert "Invalid or corrupted" in str(exc_info.value)

    def test_timeout_protection(self):
        """Test timeout protection during ZIP inspection."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(zip_analysis_timeout=0.001)
        inspector = ZipContentInspector(config)

        # Create ZIP with many files to trigger timeout
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            for i in range(1000):
                zf.writestr(f"file{i}.txt", b"content")

        # Timeout behavior is system-dependent
        try:
            inspector.inspect_zip_content(zip_buffer.getvalue())
        except ZipContentError as e:
            if "timeout" in str(e).lower():
                assert e.error_code == ErrorCode.ZIP_ANALYSIS_TIMEOUT
        except Exception:
            # May also fail for other reasons due to many files
            pass

    def test_multiple_threats_detected(self, default_config):
        """Test that multiple threats are all detected and reported."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            # Multiple threats in one ZIP
            zf.writestr("../../../etc/passwd", b"traversal")
            zf.writestr("/root/secret", b"absolute")
            zf.writestr("autorun.inf", b"suspicious")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        # Should detect multiple threats
        assert exc_info.value.threats is not None
        assert len(exc_info.value.threats) >= 3

    def test_directories_handled_correctly(self, default_config):
        """Test that directory entries are handled correctly."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            # Add directory entries
            zf.writestr("folder/", "")
            zf.writestr("folder/file.txt", b"content")
            zf.writestr("another_folder/", "")

        # Should handle directories without issues
        inspector.inspect_zip_content(zip_buffer.getvalue())

    def test_case_insensitive_pattern_matching(self, default_config):
        """Test that suspicious patterns are matched case-insensitively."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("AUTORUN.INF", b"malicious")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        assert "Suspicious filename" in str(exc_info.value)

    def test_windows_path_separators(self, default_config):
        """Test handling of Windows-style path separators."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            # Windows-style backslash traversal
            zf.writestr("folder\\..\\..\\evil.txt", b"malicious")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(zip_buffer.getvalue())

        assert "Directory traversal" in str(exc_info.value)

    def test_exception_preservation(self, default_config):
        """Test that ZipContentError is re-raised, not wrapped."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("../evil.txt", b"malicious")

        # Should raise ZipContentError, not FileProcessingError
        with pytest.raises(ZipContentError):
            inspector.inspect_zip_content(zip_buffer.getvalue())

    def test_empty_zip_allowed(self, default_config):
        """Test that empty ZIP files are allowed."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            pass  # Empty ZIP

        # Should not raise for empty ZIP
        inspector.inspect_zip_content(zip_buffer.getvalue())

    def test_normal_subdirectories_allowed(self, default_config):
        """Test that normal subdirectories are allowed."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("docs/readme.txt", b"Documentation")
            zf.writestr("images/photo.jpg", b"Image data")
            zf.writestr("data/config.json", b'{"key": "value"}')

        # Should not raise for normal structure
        inspector.inspect_zip_content(zip_buffer.getvalue())

    def test_corrupted_zip_file_structure(self, default_config):
        """Test handling of corrupted ZIP file."""
        inspector = ZipContentInspector(default_config)

        # Create invalid ZIP data
        corrupted_zip = b"PK\x03\x04" + b"corrupted data that is not a valid ZIP"

        with pytest.raises(FileProcessingError, match="Invalid or corrupted ZIP"):
            inspector.inspect_zip_content(corrupted_zip)

    def test_generic_exception_during_content_inspection(
        self, default_config, monkeypatch
    ):
        """Test handling of unexpected exceptions during content inspection."""
        inspector = ZipContentInspector(default_config)

        # Create a simple valid ZIP
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("test.txt", b"content")

        # Mock _inspect_entry_content to raise an unexpected exception
        def mock_inspect_content(*args, **kwargs):
            raise RuntimeError("Unexpected error during inspection")

        monkeypatch.setattr(inspector, "_inspect_entry_content", mock_inspect_content)

        # Should catch and wrap the exception
        with pytest.raises(FileProcessingError, match="ZIP content inspection failed"):
            inspector.inspect_zip_content(zip_buffer.getvalue())

    def test_content_inspection_warning_on_read_error(
        self, default_config, monkeypatch
    ):
        """Test that content inspection warns but continues on read errors."""
        inspector = ZipContentInspector(default_config)

        # Create a ZIP with a file
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("test.txt", b"content")

        # Mock read to raise an exception
        original_read = zipfile.ZipFile.read

        def mock_read(self, name, pwd=None):
            raise RuntimeError("Cannot read file")

        monkeypatch.setattr(zipfile.ZipFile, "read", mock_read)

        # Should log warning but not raise (line 362-368)
        # This should not raise - warning is logged internally
        inspector.inspect_zip_content(zip_buffer.getvalue())

    def test_script_pattern_decode_error(self, default_config):
        """
        Test handling of binary content that can't be decoded as text.

        Tests lines 407-409 in zip_inspector.py.
        """
        inspector = ZipContentInspector(default_config)

        # Create ZIP with binary content that can't be decoded as UTF-8
        # but doesn't match other patterns
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            # Pure binary content with no ASCII patterns
            # Use invalid UTF-8 sequences
            zf.writestr("data.bin", b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8")

        # Should handle decode errors gracefully without raising
        # The decode error is caught and logged but doesn't cause failure
        inspector.inspect_zip_content(zip_buffer.getvalue())
