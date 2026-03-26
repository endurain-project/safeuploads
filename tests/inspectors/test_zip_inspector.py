"""Tests for ZipContentInspector."""

import io
import zipfile

import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.exceptions import (
    ErrorCode,
    FileProcessingError,
    ZipContentError,
)
from safeuploads.inspectors.zip_inspector import ZipContentInspector


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
        inspector.inspect_zip_content(io.BytesIO(zip_bytes))

    def test_reject_directory_traversal_dotdot_slash(self, default_config):
        """Test rejection of ../ directory traversal."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("../../../etc/passwd", b"malicious content")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

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
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

        assert "Directory traversal" in str(exc_info.value)

    def test_reject_directory_traversal_triple_dot(self, default_config):
        """Test rejection of .../ directory traversal variant."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr(".../sensitive/file.txt", b"malicious")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

        assert "Directory traversal" in str(exc_info.value)

    def test_reject_directory_traversal_url_encoded(self, default_config):
        """Test rejection of URL-encoded directory traversal."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("%2e%2e%2fmalicious.txt", b"malicious")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

        assert "Directory traversal" in str(exc_info.value)

    def test_reject_absolute_path_unix(self, default_config):
        """Test rejection of Unix absolute paths."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("/etc/passwd", b"malicious")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

        assert "Absolute path" in str(exc_info.value)

    def test_reject_absolute_path_windows_drive(self, default_config):
        """Test rejection of Windows drive letter paths."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("C:/Windows/System32/file.txt", b"malicious")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

        assert "Absolute path" in str(exc_info.value)

    def test_reject_absolute_path_unc(self, default_config):
        """Test rejection of Windows UNC paths."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("\\\\server\\share\\file.txt", b"malicious")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

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

        # Should not raise when absolute paths allowed
        # (and path not suspicious)
        inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

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
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

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
        inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

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
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

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
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

        assert "Path too long" in str(exc_info.value)

    def test_reject_suspicious_filename_autorun(self, default_config):
        """Test rejection of autorun.inf suspicious filename."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("autorun.inf", b"[autorun]\nopen=malware.exe")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

        assert "Suspicious filename" in str(exc_info.value)

    def test_reject_suspicious_filename_htaccess(self, default_config):
        """Test rejection of .htaccess suspicious filename."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr(".htaccess", b"malicious config")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

        assert "Suspicious filename" in str(exc_info.value)

    def test_reject_suspicious_path_windows_system32(self, default_config):
        """Test rejection of Windows system paths."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("windows/system32/malware.dll", b"malicious")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

        assert "Suspicious path component" in str(exc_info.value)

    def test_reject_suspicious_path_git(self, default_config):
        """Test rejection of .git directory paths."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr(".git/config", b"repository config")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

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
            inspector.inspect_zip_content(io.BytesIO(outer_zip.getvalue()))

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
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

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
        inspector.inspect_zip_content(io.BytesIO(outer_zip.getvalue()))

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
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

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
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

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
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

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
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

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
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

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
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

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
        inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

    def test_scan_content_for_large_files(self):
        """Test that large files are also content-scanned."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(scan_zip_content=True)
        inspector = ZipContentInspector(config)

        # Large file (> 1MB) with executable signature
        large_content = b"MZ\x90\x00" + b"\x00" * (2 * 1024 * 1024)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(
            zip_buffer, "w", compression=zipfile.ZIP_STORED
        ) as zf:
            zf.writestr("large.bin", large_content)

        # Should detect executable signature regardless of size
        with pytest.raises(ZipContentError):
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

    def test_handle_corrupted_zip(self, default_config):
        """Test handling of corrupted ZIP file."""
        inspector = ZipContentInspector(default_config)

        corrupted_zip = b"PK\x03\x04corrupted data"

        with pytest.raises(FileProcessingError) as exc_info:
            inspector.inspect_zip_content(io.BytesIO(corrupted_zip))

        assert "Invalid or corrupted" in str(exc_info.value)

    def test_timeout_protection(self):
        """
        Test timeout protection during ZIP inspection.

        Uses deterministic mocking of time.monotonic to
        guarantee the timeout path triggers regardless of
        host speed.

        Returns:
            None
        """
        from unittest.mock import patch

        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            zip_analysis_timeout=5.0,
        )
        inspector = ZipContentInspector(config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            for i in range(5):
                zf.writestr(f"file{i}.txt", b"content")

        _start = 1_000_000.0
        _calls = {"n": 0}

        def _mock_monotonic() -> float:
            _calls["n"] += 1
            if _calls["n"] == 1:
                return _start
            return _start + config.limits.zip_analysis_timeout + 1.0

        target = "safeuploads.inspectors.zip_inspector.time.monotonic"
        with (
            patch(target, side_effect=_mock_monotonic),
            pytest.raises(ZipContentError) as exc_info,
        ):
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

        assert "timeout" in str(exc_info.value).lower()
        assert exc_info.value.error_code == ErrorCode.ZIP_ANALYSIS_TIMEOUT

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
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

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
        inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

    def test_case_insensitive_pattern_matching(self, default_config):
        """Test that suspicious patterns are matched case-insensitively."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("AUTORUN.INF", b"malicious")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

        assert "Suspicious filename" in str(exc_info.value)

    def test_windows_path_separators(self, default_config):
        """Test handling of Windows-style path separators."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            # Windows-style backslash traversal
            zf.writestr("folder\\..\\..\\evil.txt", b"malicious")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

        assert "Directory traversal" in str(exc_info.value)

    def test_exception_preservation(self, default_config):
        """Test that ZipContentError is re-raised, not wrapped."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("../evil.txt", b"malicious")

        # Should raise ZipContentError, not FileProcessingError
        with pytest.raises(ZipContentError):
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

    def test_empty_zip_allowed(self, default_config):
        """Test that empty ZIP files are allowed."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as _zf:
            pass  # Empty ZIP

        # Should not raise for empty ZIP
        inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

    def test_normal_subdirectories_allowed(self, default_config):
        """Test that normal subdirectories are allowed."""
        inspector = ZipContentInspector(default_config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("docs/readme.txt", b"Documentation")
            zf.writestr("images/photo.jpg", b"Image data")
            zf.writestr("data/config.json", b'{"key": "value"}')

        # Should not raise for normal structure
        inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

    def test_corrupted_zip_file_structure(self, default_config):
        """Test handling of corrupted ZIP file."""
        inspector = ZipContentInspector(default_config)

        # Create invalid ZIP data
        corrupted_zip = (
            b"PK\x03\x04" + b"corrupted data that is not a valid ZIP"
        )

        with pytest.raises(
            FileProcessingError, match="Invalid or corrupted ZIP"
        ):
            inspector.inspect_zip_content(io.BytesIO(corrupted_zip))

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

        monkeypatch.setattr(
            inspector, "_inspect_entry_content", mock_inspect_content
        )

        # Should catch and wrap the exception
        with pytest.raises(
            FileProcessingError, match="ZIP content inspection failed"
        ):
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

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
        def mock_read(self, name, pwd=None):
            raise RuntimeError("Cannot read file")

        monkeypatch.setattr(zipfile.ZipFile, "read", mock_read)

        # Should log warning but not raise (line 362-368)
        # This should not raise - warning is logged internally
        inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))

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
        inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))


class TestRecursiveZipDetection:
    """Tests for recursive/quine/complexity ZIP detection."""

    def test_detect_deeply_nested_zip(self):
        """Test detection of excessive nesting depth."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            allow_nested_archives=True,
            max_zip_depth=1,
        )
        inspector = ZipContentInspector(config)

        # Create a 3-level nested ZIP (exceeds depth 1)
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as zf:
            zf.writestr("deep.txt", b"deep content")
        inner_bytes = inner.getvalue()

        mid = io.BytesIO()
        with zipfile.ZipFile(mid, "w") as zf:
            zf.writestr("inner.zip", inner_bytes)
        mid_bytes = mid.getvalue()

        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as zf:
            zf.writestr("mid.zip", mid_bytes)

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_nested_archives(io.BytesIO(outer.getvalue()))
        assert exc_info.value.error_code == ErrorCode.ZIP_RECURSIVE_STRUCTURE

    def test_detect_quine_zip(self):
        """Test detection of quine ZIP via seen hashes."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            allow_nested_archives=True,
            max_zip_depth=5,
        )
        inspector = ZipContentInspector(config)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("data.txt", b"content")
        zip_bytes = buf.getvalue()

        import hashlib

        h = hashlib.sha256(zip_bytes).hexdigest()

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_nested_archives(
                io.BytesIO(zip_bytes),
                seen_hashes={h},
            )
        assert exc_info.value.error_code == ErrorCode.ZIP_QUINE_DETECTED

    def test_detect_complexity_attack(self):
        """Test detection of excessive total entries."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            allow_nested_archives=True,
            max_zip_depth=10,
            max_total_entries_recursive=5,
        )
        inspector = ZipContentInspector(config)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for i in range(10):
                zf.writestr(f"file{i}.txt", b"x")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_nested_archives(io.BytesIO(buf.getvalue()))
        assert exc_info.value.error_code == ErrorCode.ZIP_COMPLEXITY_ATTACK

    def test_nested_inspection_passes_safe_archive(self):
        """Test that safe nested archive passes."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            allow_nested_archives=True,
            max_zip_depth=5,
            max_total_entries_recursive=50000,
        )
        inspector = ZipContentInspector(config)

        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as zf:
            zf.writestr("inner.txt", b"safe content")

        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as zf:
            zf.writestr("safe.zip", inner.getvalue())
            zf.writestr("readme.txt", b"hello")

        inspector.inspect_nested_archives(io.BytesIO(outer.getvalue()))

    def test_inspect_zip_content_triggers_recursive(self):
        """Test inspect_zip_content calls recursive check."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            allow_nested_archives=True,
            max_zip_depth=5,
            max_total_entries_recursive=50000,
        )
        inspector = ZipContentInspector(config)

        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as zf:
            zf.writestr("inner.txt", b"content")

        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as zf:
            zf.writestr("nested.zip", inner.getvalue())

        inspector.inspect_zip_content(io.BytesIO(outer.getvalue()))

    def test_timeout_during_recursive_inspection(self):
        """Test timeout enforcement during recursion."""
        import time

        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            allow_nested_archives=True,
            max_zip_depth=10,
            zip_analysis_timeout=0.001,
            max_total_entries_recursive=50000,
        )
        inspector = ZipContentInspector(config)

        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as zf:
            for i in range(100):
                zf.writestr(f"f{i}.txt", b"x")

        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as zf:
            zf.writestr("big.zip", inner.getvalue())

        with pytest.raises(
            ZipContentError,
            match="timeout",
        ):
            inspector.inspect_nested_archives(
                io.BytesIO(outer.getvalue()),
                start_time=time.monotonic() - 1.0,
            )

    def test_non_zip_nested_archive_ignored(self):
        """Test that invalid nested archives are skipped."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            allow_nested_archives=True,
            max_zip_depth=5,
        )
        inspector = ZipContentInspector(config)

        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as zf:
            zf.writestr("fake.zip", b"not a zip")
            zf.writestr("data.txt", b"hello")

        inspector.inspect_nested_archives(io.BytesIO(outer.getvalue()))

    def test_compute_archive_hash(self):
        """Test archive hash computation."""
        config = FileSecurityConfig()
        inspector = ZipContentInspector(config)

        buf = io.BytesIO(b"test data")
        h1 = inspector._compute_archive_hash(buf)
        h2 = inspector._compute_archive_hash(buf)

        assert h1 == h2
        assert len(h1) == 64
        assert buf.tell() == 0


class TestZipInspectorStructureGaps:
    def test_max_files_same_type_exceeded_raises(self):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            max_number_files_same_type=3,
            scan_zip_content=False,
            max_zip_entries=100,
        )
        inspector = ZipContentInspector(config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            for i in range(5):
                zf.writestr(f"file{i}.txt", b"x")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))
        assert "Excessive number" in str(exc_info.value)

    def test_script_in_txt_entry_detected(self):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            scan_zip_content=True,
        )
        inspector = ZipContentInspector(config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr(
                "notes.txt",
                b"#!/bin/bash\necho hello",
            )

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_zip_content(io.BytesIO(zip_buffer.getvalue()))
        assert "Script content" in str(exc_info.value)

    def test_entry_content_read_exception_ignored(self, monkeypatch):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            scan_zip_content=True,
        )
        inspector = ZipContentInspector(config)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("safe.txt", b"plain text")
        zip_data = zip_buffer.getvalue()

        def _mock_open(self, name, mode="r", pwd=None, **kw):
            raise RuntimeError("Cannot open entry")

        monkeypatch.setattr(zipfile.ZipFile, "open", _mock_open)
        # Exception caught internally — should not raise
        inspector.inspect_zip_content(io.BytesIO(zip_data))

    def test_null_byte_in_entry_filename_detected(
        self,
    ):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            scan_zip_content=False,
        )
        inspector = ZipContentInspector(config)

        # ZipInfo truncates at null on construction, so
        # set filename directly after creating the object.
        # scan_zip_content=False means zip_file=None is safe.
        bad_info = zipfile.ZipInfo("safe.txt")
        bad_info.filename = "test\x00evil.txt"
        threats = inspector._inspect_zip_entry(bad_info, None)
        assert any("Null byte" in t for t in threats)

    def test_script_pattern_decode_exception_silenced(
        self,
    ):
        config = FileSecurityConfig()
        inspector = ZipContentInspector(config)

        class _BadBytes:
            def decode(self, *args, **kwargs):
                raise RuntimeError("decode failed")

        # Passes a non-bytes object whose .decode() raises;
        # covers the except Exception branch (lines 488-490)
        result = inspector._contains_script_patterns(_BadBytes(), "file.txt")
        assert result is False


class TestZipInspectorNestedArchives:
    def test_valid_nested_archive_passes(self):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            allow_nested_archives=True,
            max_zip_depth=5,
            max_total_entries_recursive=50000,
            zip_analysis_timeout=30.0,
        )
        inspector = ZipContentInspector(config)

        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as zf:
            zf.writestr("data.txt", b"safe")

        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as zf:
            zf.writestr("inner.zip", inner.getvalue())

        # Should not raise for a safe nested archive
        inspector.inspect_nested_archives(io.BytesIO(outer.getvalue()))

    def test_excessive_depth_raises_recursive_structure(
        self,
    ):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            allow_nested_archives=True,
            max_zip_depth=2,
            max_total_entries_recursive=50000,
        )
        inspector = ZipContentInspector(config)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("file.txt", b"x")

        # depth=3 immediately exceeds max_zip_depth=2
        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_nested_archives(
                io.BytesIO(buf.getvalue()), depth=3
            )
        assert exc_info.value.error_code == ErrorCode.ZIP_RECURSIVE_STRUCTURE

    def test_quine_detection_raises_zip_quine_detected(
        self,
    ):
        import hashlib as _hashlib

        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            allow_nested_archives=True,
            max_zip_depth=5,
        )
        inspector = ZipContentInspector(config)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("f.txt", b"content")
        zip_bytes = buf.getvalue()

        existing_hash = _hashlib.sha256(zip_bytes).hexdigest()

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_nested_archives(
                io.BytesIO(zip_bytes),
                seen_hashes={existing_hash},
            )
        assert exc_info.value.error_code == ErrorCode.ZIP_QUINE_DETECTED

    def test_max_total_entries_exceeded_raises_complexity(
        self,
    ):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            allow_nested_archives=True,
            max_zip_depth=10,
            max_total_entries_recursive=2,
        )
        inspector = ZipContentInspector(config)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for i in range(5):
                zf.writestr(f"file{i}.txt", b"x")

        with pytest.raises(ZipContentError) as exc_info:
            inspector.inspect_nested_archives(io.BytesIO(buf.getvalue()))
        assert exc_info.value.error_code == ErrorCode.ZIP_COMPLEXITY_ATTACK

    def test_timeout_during_recursion_raises_timeout(
        self,
    ):
        from unittest.mock import patch

        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            allow_nested_archives=True,
            max_zip_depth=10,
            zip_analysis_timeout=5.0,
            max_total_entries_recursive=50000,
        )
        inspector = ZipContentInspector(config)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for i in range(3):
                zf.writestr(f"file{i}.txt", b"x")

        _start = 1_000_000.0
        _calls = {"n": 0}

        def _mock_monotonic() -> float:
            _calls["n"] += 1
            if _calls["n"] == 1:
                return _start
            return _start + config.limits.zip_analysis_timeout + 1.0

        target = "safeuploads.inspectors.zip_inspector.time.monotonic"
        with (
            patch(target, side_effect=_mock_monotonic),
            pytest.raises(ZipContentError) as exc_info,
        ):
            inspector.inspect_nested_archives(io.BytesIO(buf.getvalue()))
        assert exc_info.value.error_code == ErrorCode.ZIP_ANALYSIS_TIMEOUT

    def test_directory_entries_skipped_in_nested_loop(
        self,
    ):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            allow_nested_archives=True,
            max_zip_depth=5,
            max_total_entries_recursive=50000,
        )
        inspector = ZipContentInspector(config)

        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as zf:
            zf.writestr("data.txt", b"safe")

        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as zf:
            # Directory entry triggers `continue` at line 643
            zf.writestr(zipfile.ZipInfo("subdir/"), b"")
            zf.writestr("inner.zip", inner.getvalue())

        # Should complete without raising
        inspector.inspect_nested_archives(io.BytesIO(outer.getvalue()))

    def test_oversized_archive_entry_skipped(
        self,
    ):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            allow_nested_archives=True,
            max_zip_depth=5,
            max_total_entries_recursive=50000,
            max_individual_file_size=1,  # 1-byte limit
        )
        inspector = ZipContentInspector(config)

        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as zf:
            zf.writestr("data.txt", b"safe content")
        # inner.zip is larger than 1 byte

        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as zf:
            zf.writestr("inner.zip", inner.getvalue())

        # inner.zip is skipped (too large) — covers line 666
        inspector.inspect_nested_archives(io.BytesIO(outer.getvalue()))

    def test_read_failure_skips_archive_entry(self, monkeypatch):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            allow_nested_archives=True,
            max_zip_depth=5,
            max_total_entries_recursive=50000,
        )
        inspector = ZipContentInspector(config)

        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as zf:
            zf.writestr("data.txt", b"x")

        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as zf:
            zf.writestr("inner.zip", inner.getvalue())
        outer_bytes = outer.getvalue()

        original_read = zipfile.ZipFile.read

        def _fail_read(self, name, pwd=None):
            if name == "inner.zip":
                raise RuntimeError("Corrupt entry")
            return original_read(self, name, pwd)

        monkeypatch.setattr(zipfile.ZipFile, "read", _fail_read)
        # Read failure is caught (lines 670-676) and skipped
        inspector.inspect_nested_archives(io.BytesIO(outer_bytes))

    def test_bad_zip_file_silenced_in_nested_inspection(
        self,
    ):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            allow_nested_archives=True,
            max_zip_depth=5,
        )
        inspector = ZipContentInspector(config)

        # A non-ZIP buffer triggers BadZipFile inside
        # inspect_nested_archives — silenced by lines 693-694
        inspector.inspect_nested_archives(
            io.BytesIO(b"definitely not a zip file")
        )

    def test_unexpected_exception_silenced_in_nested(self, monkeypatch):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            allow_nested_archives=True,
            max_zip_depth=5,
        )
        inspector = ZipContentInspector(config)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("file.txt", b"x")
        zip_bytes = buf.getvalue()

        def _failing_init(self, *args, **kwargs):
            raise RuntimeError("Unexpected IO error")

        monkeypatch.setattr(zipfile.ZipFile, "__init__", _failing_init)
        # RuntimeError is caught (lines 695-696) and logged
        inspector.inspect_nested_archives(io.BytesIO(zip_bytes))
