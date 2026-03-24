"""Tests for ContentSecurityInspector."""

import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.enums import MalwareSignatureCategory
from safeuploads.exceptions import FileProcessingError
from safeuploads.inspectors.content_inspector import (
    ContentSecurityInspector,
)


def _sig(category: MalwareSignatureCategory) -> bytes:
    """Get first signature from a category."""
    return next(iter(category.value))


class TestContentSecurityInspector:
    """Test suite for ContentSecurityInspector."""

    def test_initialization(self, default_config):
        """Test inspector initialization."""
        inspector = ContentSecurityInspector(default_config)
        assert inspector.config == default_config

    def test_clean_content_returns_empty(
        self, default_config
    ):
        """Test clean content produces no threats."""
        inspector = ContentSecurityInspector(default_config)
        content = b"\x00" * 200
        threats = inspector.scan_content(
            content, "clean.dat", ""
        )
        assert threats == []

    def test_detect_pe_signature(self, default_config):
        """Test detection of PE executable header."""
        inspector = ContentSecurityInspector(default_config)
        sig = _sig(MalwareSignatureCategory.PE_EXECUTABLE)
        content = b"\x00" * 50 + sig + b"\x00" * 50
        threats = inspector.scan_content(
            content, "f.dat", ""
        )
        assert any(
            "Executable signature" in t for t in threats
        )

    def test_detect_elf_signature(self, default_config):
        """Test detection of ELF executable header."""
        inspector = ContentSecurityInspector(default_config)
        sig = _sig(MalwareSignatureCategory.ELF_EXECUTABLE)
        content = sig + b"\x00" * 100
        threats = inspector.scan_content(
            content, "f.dat", ""
        )
        assert any(
            "Executable signature" in t for t in threats
        )

    def test_detect_macho_signature(self, default_config):
        """Test detection of Mach-O executable header."""
        inspector = ContentSecurityInspector(default_config)
        sig = _sig(MalwareSignatureCategory.MACHO_EXECUTABLE)
        content = sig + b"\x00" * 100
        threats = inspector.scan_content(
            content, "f.dat", ""
        )
        assert any(
            "Executable signature" in t for t in threats
        )

    def test_detect_java_class_signature(
        self, default_config
    ):
        """Test detection of Java class file header."""
        inspector = ContentSecurityInspector(default_config)
        sig = _sig(MalwareSignatureCategory.JAVA_CLASS)
        content = sig + b"\x00" * 100
        threats = inspector.scan_content(
            content, "f.dat", ""
        )
        assert any(
            "Executable signature" in t for t in threats
        )

    def test_detect_webshell_signature(
        self, default_config
    ):
        """Test detection of web shell byte marker."""
        inspector = ContentSecurityInspector(default_config)
        sig = _sig(
            MalwareSignatureCategory.WEBSHELL_PATTERNS
        )
        content = b"padding" + sig + b"extra"
        threats = inspector.scan_content(
            content, "f.dat", ""
        )
        assert any(
            "Web shell" in t or "Script" in t
            for t in threats
        )

    def test_detect_script_eval_pattern(
        self, default_config
    ):
        """Test detection of eval() text pattern."""
        inspector = ContentSecurityInspector(default_config)
        content = b"x = eval(input)"
        threats = inspector.scan_content(
            content, "f.txt", ""
        )
        assert any("Script pattern" in t for t in threats)

    def test_detect_polyglot_in_image(
        self, default_config
    ):
        """Test polyglot detection for image type."""
        inspector = ContentSecurityInspector(default_config)
        sig = _sig(
            MalwareSignatureCategory.POLYGLOT_SIGNATURES
        )
        # Header padding + polyglot sig after 16 bytes
        content = b"\x00" * 20 + sig + b"\x00" * 50
        threats = inspector.scan_content(
            content, "f.jpg", "image"
        )
        assert any("Polyglot" in t for t in threats)

    def test_polyglot_skipped_for_zip(
        self, default_config
    ):
        """Test polyglot check skipped for zip type."""
        inspector = ContentSecurityInspector(default_config)
        sig = _sig(
            MalwareSignatureCategory.POLYGLOT_SIGNATURES
        )
        content = sig + b"\x00" * 100
        threats = inspector.scan_content(
            content, "f.zip", "zip"
        )
        polyglot = [t for t in threats if "Polyglot" in t]
        assert len(polyglot) == 0

    def test_binary_no_script_false_positive(
        self, default_config
    ):
        """Test pure binary produces no script threats."""
        inspector = ContentSecurityInspector(default_config)
        content = bytes(range(128, 256)) * 10
        threats = inspector.scan_content(
            content, "data.bin", ""
        )
        script = [t for t in threats if "Script" in t]
        assert len(script) == 0

    def test_empty_content(self, default_config):
        """Test empty content produces no threats."""
        inspector = ContentSecurityInspector(default_config)
        threats = inspector.scan_content(b"", "e.dat", "")
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
    async def test_image_with_embedded_sig_rejected(
        self, mock_upload_file
    ):
        """Test image with embedded exec sig rejected."""
        from safeuploads.file_validator import FileValidator

        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            enable_content_analysis=True,
        )
        validator = FileValidator(config=config)

        sig = _sig(MalwareSignatureCategory.PE_EXECUTABLE)
        content = (
            b"\xff\xd8\xff\xe0"
            b"\x00\x10"
            b"JFIF\x00"
            b"\x01\x01\x00"
            b"\x00\x01\x00\x01"
            b"\x00\x00"
            + b"\x00" * 50
            + sig
            + b"\x00" * 50
            + b"\xff\xd9"
        )
        file = mock_upload_file(
            filename="bad.jpg", content=content
        )
        with pytest.raises(FileProcessingError) as exc:
            await validator.validate_image_file(file)
        assert "Content analysis" in str(exc.value)

    @pytest.mark.asyncio
    async def test_clean_zip_passes(
        self, mock_upload_file, create_zip_file
    ):
        """Test clean ZIP passes with analysis on."""
        from safeuploads.file_validator import FileValidator

        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            enable_content_analysis=True,
        )
        validator = FileValidator(config=config)
        zip_bytes = create_zip_file(
            files={"readme.txt": b"Hello"}
        )
        file = mock_upload_file(
            filename="safe.zip", content=zip_bytes
        )
        await validator.validate_zip_file(file)

    @pytest.mark.asyncio
    async def test_disabled_skips_scan(
        self, mock_upload_file
    ):
        """Test disabled analysis allows threats."""
        from safeuploads.file_validator import FileValidator

        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            enable_content_analysis=False,
        )
        validator = FileValidator(config=config)

        sig = _sig(MalwareSignatureCategory.PE_EXECUTABLE)
        content = (
            b"\xff\xd8\xff\xe0"
            b"\x00\x10"
            b"JFIF\x00"
            b"\x01\x01\x00"
            b"\x00\x01\x00\x01"
            b"\x00\x00"
            + b"\x00" * 50
            + sig
            + b"\x00" * 50
            + b"\xff\xd9"
        )
        file = mock_upload_file(
            filename="img.jpg", content=content
        )
        # Should pass — analysis disabled
        await validator.validate_image_file(file)
