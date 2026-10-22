"""Tests for ContentSecurityInspector."""

import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.exceptions import FileProcessingError
from safeuploads.inspectors.content_inspector import (
    ContentSecurityInspector,
)
from tests.conftest import (
    ELF_EXECUTABLE,
    JAVA_CLASS,
    JPEG_SOF0,
    MACHO_EXECUTABLE,
    PE_EXECUTABLE,
    WINDOWS_SHORTCUT,
    ZIP_LOCAL_HEADER,
    entropy_bytes,
)


class TestContentSecurityInspector:
    """Test suite for ContentSecurityInspector."""

    def test_initialization(self, default_config):
        """Test inspector initialization."""
        inspector = ContentSecurityInspector(default_config)
        assert inspector.config == default_config

    def test_clean_content_returns_empty(self, default_config):
        """Test clean content produces no threats."""
        inspector = ContentSecurityInspector(default_config)
        content = b"\x00" * 200
        threats = inspector.scan_content(content, "clean.dat", "")
        assert threats == []

    def test_detect_pe_signature(self, default_config):
        """Test detection of PE executable header."""
        inspector = ContentSecurityInspector(default_config)
        content = b"\x00" * 50 + PE_EXECUTABLE + b"\x00" * 50
        threats = inspector.scan_content(content, "f.dat", "")
        assert any("Executable signature" in t for t in threats)

    def test_detect_elf_signature(self, default_config):
        """Test detection of ELF executable header."""
        inspector = ContentSecurityInspector(default_config)
        content = ELF_EXECUTABLE + b"\x00" * 100
        threats = inspector.scan_content(content, "f.dat", "")
        assert any("Executable signature" in t for t in threats)

    def test_detect_macho_signature(self, default_config):
        """Test detection of Mach-O executable header."""
        inspector = ContentSecurityInspector(default_config)
        content = MACHO_EXECUTABLE + b"\x00" * 100
        threats = inspector.scan_content(content, "f.dat", "")
        assert any("Executable signature" in t for t in threats)

    def test_detect_java_class_signature(self, default_config):
        """Test detection of Java class file header."""
        inspector = ContentSecurityInspector(default_config)
        content = JAVA_CLASS + b"\x00" * 100
        threats = inspector.scan_content(content, "f.dat", "")
        assert any("Executable signature" in t for t in threats)

    def test_detect_windows_shortcut_signature(self, default_config):
        """Test detection of a .lnk ShellLinkHeader."""
        inspector = ContentSecurityInspector(default_config)
        content = b"\x00" * 32 + WINDOWS_SHORTCUT
        threats = inspector.scan_content(content, "f.dat", "")
        assert any("Executable signature" in t for t in threats)

    def test_detect_webshell_signature(self, default_config):
        """Test detection of web shell byte marker."""
        inspector = ContentSecurityInspector(default_config)
        content = b"padding" + b"<?php system($_GET[0]); ?>"
        threats = inspector.scan_content(content, "f.dat", "")
        assert any("Web shell" in t or "Script" in t for t in threats)

    def test_detect_script_eval_pattern(self, default_config):
        """Test detection of eval() text pattern."""
        inspector = ContentSecurityInspector(default_config)
        content = b"x = eval(input)"
        threats = inspector.scan_content(content, "f.txt", "")
        assert any("Script pattern" in t for t in threats)

    def test_detect_polyglot_in_image(self, default_config):
        """Test polyglot detection for image type."""
        inspector = ContentSecurityInspector(default_config)
        # Header padding + polyglot sig after 20 bytes
        content = b"\x00" * 20 + ZIP_LOCAL_HEADER + b"\x00" * 50
        threats = inspector.scan_content(content, "f.jpg", "image")
        assert any("Polyglot" in t for t in threats)

    def test_polyglot_skipped_for_zip(self, default_config):
        """Test polyglot check skipped for zip type."""
        inspector = ContentSecurityInspector(default_config)
        content = ZIP_LOCAL_HEADER + b"\x00" * 100
        threats = inspector.scan_content(content, "f.zip", "zip")
        polyglot = [t for t in threats if "Polyglot" in t]
        assert len(polyglot) == 0

    def test_binary_no_script_false_positive(self, default_config):
        """Test pure binary produces no script threats."""
        inspector = ContentSecurityInspector(default_config)
        content = bytes(range(128, 256)) * 10
        threats = inspector.scan_content(content, "data.bin", "")
        script = [t for t in threats if "Script" in t]
        assert len(script) == 0

    def test_empty_content(self, default_config):
        """Test empty content produces no threats."""
        inspector = ContentSecurityInspector(default_config)
        threats = inspector.scan_content(b"", "e.dat", "")
        assert threats == []


class TestShortSignatureFalsePositives:
    """Short magics must not fire on incidental byte pairs."""

    @pytest.mark.parametrize("size", [64 * 1024, 1024 * 1024])
    def test_high_entropy_content_is_clean(self, default_config, size):
        """Entropy-coded data contains every 2-byte pair by chance."""
        inspector = ContentSecurityInspector(default_config)
        content = entropy_bytes(size, seed=size)

        threats = inspector.scan_content(content, "photo.jpg", "image")

        assert threats == []

    def test_entropy_content_really_contains_the_magics(self):
        """Guard the premise: the bytes are present, just meaningless."""
        content = entropy_bytes(1024 * 1024, seed=1024 * 1024)
        assert b"MZ" in content
        assert b"<%" in content

    def test_bare_mz_without_pe_header_is_ignored(self, default_config):
        """An `MZ` with no PE header behind it is not an executable."""
        inspector = ContentSecurityInspector(default_config)
        content = b"\x00" * 64 + b"MZ\x90\x00" + b"\x00" * 64
        threats = inspector.scan_content(content, "f.jpg", "image")
        assert threats == []

    def test_asp_tag_in_binary_is_ignored(self, default_config):
        """`<%` surrounded by binary carries no signal."""
        inspector = ContentSecurityInspector(default_config)
        content = b"\xff\xd8" + b"\x81\x9f" * 40 + b"<%" + b"\x81\x9f" * 40
        threats = inspector.scan_content(content, "f.jpg", "image")
        assert threats == []

    def test_asp_tag_in_text_is_detected(self, default_config):
        """`<%` inside real markup is still reported."""
        inspector = ContentSecurityInspector(default_config)
        content = b"<html><body>" + b"padding text " * 4 + b"<%= Request(1) %>"
        threats = inspector.scan_content(content, "f.jpg", "image")
        assert any("<%" in t for t in threats)

    def test_truncated_pe_header_is_ignored(self, default_config):
        """An `MZ` whose e_lfanew runs off the buffer is ignored."""
        inspector = ContentSecurityInspector(default_config)
        threats = inspector.scan_content(b"MZ", "f.dat", "")
        assert threats == []

    def test_zip_header_with_unknown_method_is_ignored(self, default_config):
        """A `PK\\x03\\x04` with a bogus method is not a ZIP."""
        inspector = ContentSecurityInspector(default_config)
        bogus = (
            b"PK\x03\x04"
            + (20).to_bytes(2, "little")
            + b"\x00\x00"
            + (777).to_bytes(2, "little")
            + b"\x00" * 16
        )
        content = b"\x00" * 20 + bogus
        threats = inspector.scan_content(content, "f.jpg", "image")
        assert threats == []


class TestContentAnalysisIntegration:
    """Test content analysis in FileValidator."""

    @pytest.mark.asyncio
    async def test_clean_image_passes(
        self, mock_upload_file, valid_jpeg_bytes
    ):
        """Test clean image passes with analysis on."""
        from safeuploads.file_validator import FileValidator

        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            enable_content_analysis=True,
        )
        validator = FileValidator(config=config)
        file = mock_upload_file(
            filename="photo.jpg",
            content=valid_jpeg_bytes,
        )
        await validator.validate_image_file(file)

    @pytest.mark.asyncio
    async def test_image_with_embedded_sig_rejected(self, mock_upload_file):
        """Test image with embedded exec sig rejected."""
        from safeuploads.file_validator import FileValidator

        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            enable_content_analysis=True,
        )
        validator = FileValidator(config=config)

        content = (
            b"\xff\xd8\xff\xe0"
            b"\x00\x10"
            b"JFIF\x00"
            b"\x01\x01\x00"
            b"\x00\x01\x00\x01"
            b"\x00\x00"
            + JPEG_SOF0
            + b"\x00" * 50
            + PE_EXECUTABLE
            + b"\x00" * 50
            + b"\xff\xd9"
        )
        file = mock_upload_file(filename="bad.jpg", content=content)
        with pytest.raises(FileProcessingError) as exc:
            await validator.validate_image_file(file)
        assert "Content analysis" in str(exc.value)

    @pytest.mark.asyncio
    async def test_clean_zip_passes(self, mock_upload_file, create_zip_file):
        """Test clean ZIP passes with analysis on."""
        from safeuploads.file_validator import FileValidator

        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            enable_content_analysis=True,
        )
        validator = FileValidator(config=config)
        zip_bytes = create_zip_file(files={"readme.txt": b"Hello"})
        file = mock_upload_file(filename="safe.zip", content=zip_bytes)
        await validator.validate_zip_file(file)

    @pytest.mark.asyncio
    async def test_disabled_skips_scan(self, mock_upload_file):
        """Test disabled analysis allows threats."""
        from safeuploads.file_validator import FileValidator

        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            enable_content_analysis=False,
        )
        validator = FileValidator(config=config)

        content = (
            b"\xff\xd8\xff\xe0"
            b"\x00\x10"
            b"JFIF\x00"
            b"\x01\x01\x00"
            b"\x00\x01\x00\x01"
            b"\x00\x00"
            + JPEG_SOF0
            + b"\x00" * 50
            + PE_EXECUTABLE
            + b"\x00" * 50
            + b"\xff\xd9"
        )
        file = mock_upload_file(filename="img.jpg", content=content)
        # Should pass — analysis disabled
        await validator.validate_image_file(file)


class TestContentInspectorActivityPolyglot:
    def test_polyglot_in_activity_file_is_detected(self, default_config):
        inspector = ContentSecurityInspector(default_config)
        content = b"\x00" * 20 + ZIP_LOCAL_HEADER + b"\x00" * 50
        threats = inspector.scan_content(content, "run.gpx", "activity")
        assert any("Polyglot" in t for t in threats)
