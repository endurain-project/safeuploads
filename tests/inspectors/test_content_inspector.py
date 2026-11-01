"""Tests for ContentSecurityInspector."""

import hashlib
import io
import struct
import zlib

import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.enums import MalwareSignatureCategory
from safeuploads.exceptions import ContentThreatError, ErrorCode
from safeuploads.inspectors.content_inspector import (
    ContentSecurityInspector,
)


def _sig(category: MalwareSignatureCategory) -> bytes:
    """Get first signature from a category."""
    return next(iter(category.value))


_JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
_PAD = b"\x00" * 64
_LNK_CLSID = (
    b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
)

# Minimal in-memory headers; each is the smallest structure the
# inspector accepts for its format.
_HOSTILE_PAYLOADS = {
    "pe": b"MZ" + b"\x00" * 58 + struct.pack("<L", 64) + b"PE\x00\x00" + _PAD,
    "elf": b"\x7fELF\x02\x01\x01" + _PAD,
    "macho_le64": b"\xcf\xfa\xed\xfe"
    + struct.pack("<LLL", 0x0100000C, 0, 2)
    + _PAD,
    "macho_be32": b"\xfe\xed\xfa\xce" + struct.pack(">LLL", 7, 3, 2) + _PAD,
    "macho_fat": b"\xca\xfe\xba\xbe"
    + struct.pack(">LL", 2, 0x01000007)
    + _PAD,
    "java": b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + _PAD,
    "lnk": b"L\x00\x00\x00" + _LNK_CLSID + _PAD,
    "php": b"<?php system($_GET[1]); ?>",
    "script": b"<script>alert(1)</script>",
    "script_mixed_case": b"<ScRiPt src=x>",
    "jsp": b'<%@ page import="java.io.*" %>',
    "asp": b'<%@ Language="VBScript" %>',
}


def _random_bytes(seed: int, size: int) -> bytes:
    """Return deterministic, seeded pseudo-random bytes."""
    return hashlib.shake_256(seed.to_bytes(4, "big")).digest(size)


def _random_png(seed: int, size: int = 256) -> bytes:
    """Build a valid random-pixel RGB PNG in memory."""
    raw = b"".join(
        b"\x00" + _random_bytes(seed * 1000 + row, size * 3)
        for row in range(size)
    )

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return (
            struct.pack(">I", len(data))
            + body
            + struct.pack(">I", zlib.crc32(body))
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def _zip_bytes() -> bytes:
    """Build a tiny ZIP archive in memory."""
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("a.txt", b"hello")
    return buf.getvalue()


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
        """Test detection of a structurally valid PE header."""
        inspector = ContentSecurityInspector(default_config)
        content = b"\x00" * 50 + _HOSTILE_PAYLOADS["pe"]
        threats = inspector.scan_content(content, "f.dat", "")
        assert any("Executable signature" in t for t in threats)

    def test_bare_pe_magics_not_detected(self, default_config):
        """Test MZ without a valid PE signature is accepted."""
        inspector = ContentSecurityInspector(default_config)
        dos_only = b"MZ" + b"\x00" * 58 + struct.pack("<L", 64) + _PAD
        wrong_offset = (
            b"MZ" + b"\x00" * 58 + struct.pack("<L", 200) + b"PE\x00\x00"
        )
        short = b"MZ" + b"\x00" * 20
        for content in (dos_only, wrong_offset, short, b"PE\x00\x00"):
            assert inspector.scan_content(content, "f.dat", "") == []

    @pytest.mark.parametrize("e_lfanew", [0x10000, 0x123456])
    def test_detect_pe_with_large_e_lfanew(self, default_config, e_lfanew):
        inspector = ContentSecurityInspector(default_config)
        content = (
            b"MZ"
            + b"\x00" * 58
            + struct.pack("<L", e_lfanew)
            + b"\x00" * (e_lfanew - 64)
            + b"PE\x00\x00"
        )
        threats = inspector.scan_content(content, "f.dat", "")
        assert any("PE executable" in t for t in threats)

    def test_pe_magic_ending_at_end_of_content_is_detected(
        self, default_config
    ):
        inspector = ContentSecurityInspector(default_config)
        e_lfanew = 0x10000
        content = (
            b"MZ"
            + b"\x00" * 58
            + struct.pack("<L", e_lfanew)
            + b"\x00" * (e_lfanew - 64)
            + b"PE\x00\x00"
        )
        assert len(content) == e_lfanew + 4
        threats = inspector.scan_content(content, "f.dat", "")
        assert any("PE executable" in t for t in threats)
        assert inspector.scan_content(content[:-1], "f.dat", "") == []

    def test_large_e_lfanew_without_pe_magic_not_detected(
        self, default_config
    ):
        inspector = ContentSecurityInspector(default_config)
        header = b"MZ" + b"\x00" * 58 + struct.pack("<L", 0x10000)
        no_magic = header + b"\x00" * (0x10000 - 64) + b"PX\x00\x00"
        past_end = header + _PAD
        for content in (no_magic, past_end):
            assert inspector.scan_content(content, "f.dat", "") == []

    def test_detect_elf_signature(self, default_config):
        """Test detection of ELF executable header."""
        inspector = ContentSecurityInspector(default_config)
        threats = inspector.scan_content(_HOSTILE_PAYLOADS["elf"], "f.dat", "")
        assert any("Executable signature" in t for t in threats)

    def test_bare_elf_magic_not_detected(self, default_config):
        """Test ELF magic with invalid class/data/version is accepted."""
        inspector = ContentSecurityInspector(default_config)
        content = b"\x7fELF\x09\x09\x09" + _PAD
        assert inspector.scan_content(content, "f.dat", "") == []

    def test_detect_macho_signature(self, default_config):
        """Test detection of thin and universal Mach-O headers."""
        inspector = ContentSecurityInspector(default_config)
        for key in ("macho_le64", "macho_be32", "macho_fat"):
            threats = inspector.scan_content(
                _HOSTILE_PAYLOADS[key], "f.dat", ""
            )
            assert any("Executable signature" in t for t in threats), key

    def test_bare_macho_magic_not_detected(self, default_config):
        """Test Mach-O magic with an unknown CPU type is accepted."""
        inspector = ContentSecurityInspector(default_config)
        for magic in MalwareSignatureCategory.MACHO_EXECUTABLE.value:
            assert inspector.scan_content(magic + _PAD, "f.dat", "") == []

    def test_detect_java_class_signature(self, default_config):
        """Test detection of Java class file header."""
        inspector = ContentSecurityInspector(default_config)
        threats = inspector.scan_content(
            _HOSTILE_PAYLOADS["java"], "f.dat", ""
        )
        assert any("Executable signature" in t for t in threats)

    def test_bare_java_magic_not_detected(self, default_config):
        """Test CAFEBABE with an invalid version is accepted."""
        inspector = ContentSecurityInspector(default_config)
        magic = _sig(MalwareSignatureCategory.JAVA_CLASS)
        assert inspector.scan_content(magic + _PAD, "f.dat", "") == []

    def test_detect_lnk_signature(self, default_config):
        """Test LNK needs the Shell Link CLSID after the header size."""
        inspector = ContentSecurityInspector(default_config)
        threats = inspector.scan_content(_HOSTILE_PAYLOADS["lnk"], "f.dat", "")
        assert any("Executable signature" in t for t in threats)
        bare = _sig(MalwareSignatureCategory.WINDOWS_SHORTCUT) + _PAD
        assert inspector.scan_content(bare, "f.dat", "") == []

    def test_detect_webshell_signature(self, default_config):
        """Test detection of web shell byte markers."""
        inspector = ContentSecurityInspector(default_config)
        for sig in MalwareSignatureCategory.WEBSHELL_PATTERNS.value:
            content = b"padding" + sig + b"extra"
            threats = inspector.scan_content(content, "f.dat", "")
            assert any("Web shell" in t or "Script" in t for t in threats)

    def test_bare_asp_delimiter_not_detected(self, default_config):
        """Test the bare ASP delimiter is not a threat on its own."""
        inspector = ContentSecurityInspector(default_config)
        content = b"width: 50<%; " + b"<%=" + b"x"
        assert inspector.scan_content(content, "f.txt", "") == []

    @pytest.mark.parametrize(
        "key", ["php", "script", "script_mixed_case", "jsp", "asp"]
    )
    def test_script_markers_detected_case_insensitively(
        self, default_config, key
    ):
        """Test script markers are found, whatever their case."""
        inspector = ContentSecurityInspector(default_config)
        threats = inspector.scan_content(
            b"data" + _HOSTILE_PAYLOADS[key], "f.dat", ""
        )
        assert threats

    def test_invalid_bytes_do_not_join_script_marker(self, default_config):
        """Test bytes between marker characters break the match."""
        inspector = ContentSecurityInspector(default_config)
        content = b"<\xff?php \xff<scr\xffipt"
        assert inspector.scan_content(content, "f.bin", "") == []

    def test_detect_script_eval_pattern(self, default_config):
        """Test detection of eval() text pattern."""
        inspector = ContentSecurityInspector(default_config)
        content = b"x = eval(input)"
        threats = inspector.scan_content(content, "f.txt", "")
        assert any("Script pattern" in t for t in threats)

    def test_detect_polyglot_in_image(self, default_config):
        """Test polyglot detection for image type."""
        inspector = ContentSecurityInspector(default_config)
        sig = b"PK\x03\x04"
        # Header padding + polyglot sig after 16 bytes
        content = b"\x00" * 20 + sig + b"\x00" * 50
        threats = inspector.scan_content(content, "f.jpg", "image")
        assert any("Polyglot" in t for t in threats)

    def test_polyglot_skipped_for_zip(self, default_config):
        """Test polyglot check skipped for zip type."""
        inspector = ContentSecurityInspector(default_config)
        sig = b"PK\x03\x04"
        content = sig + b"\x00" * 100
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

        sig = _HOSTILE_PAYLOADS["pe"]
        content = (
            b"\xff\xd8\xff\xe0"
            b"\x00\x10"
            b"JFIF\x00"
            b"\x01\x01\x00"
            b"\x00\x01\x00\x01"
            b"\x00\x00" + b"\x00" * 50 + sig + b"\x00" * 50 + b"\xff\xd9"
        )
        file = mock_upload_file(filename="bad.jpg", content=content)
        with pytest.raises(ContentThreatError) as exc:
            await validator.validate_image_file(file)
        assert "Content analysis" in str(exc.value)
        assert exc.value.error_code == ErrorCode.CONTENT_THREAT_DETECTED
        assert exc.value.filename == "bad.jpg"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("key", sorted(_HOSTILE_PAYLOADS))
    async def test_hostile_image_rejected(self, mock_upload_file, key):
        """Test each hostile structure in an image is rejected."""
        from safeuploads.file_validator import FileValidator

        config = FileSecurityConfig()
        config.limits = SecurityLimits(enable_content_analysis=True)
        validator = FileValidator(config=config)
        content = _JPEG + _random_bytes(5, 2000) + _HOSTILE_PAYLOADS[key]
        file = mock_upload_file(filename="bad.jpg", content=content)
        with pytest.raises(ContentThreatError) as exc:
            await validator.validate_image_file(file)
        assert exc.value.error_code == ErrorCode.CONTENT_THREAT_DETECTED

    @pytest.mark.asyncio
    async def test_png_with_appended_zip_rejected(self, mock_upload_file):
        """Test a PNG + ZIP polyglot is rejected."""
        from safeuploads.file_validator import FileValidator

        config = FileSecurityConfig()
        config.limits = SecurityLimits(enable_content_analysis=True)
        validator = FileValidator(config=config)
        file = mock_upload_file(
            filename="p.png", content=_random_png(2, 8) + _zip_bytes()
        )
        with pytest.raises(ContentThreatError) as exc:
            await validator.validate_image_file(file)
        assert exc.value.error_code == ErrorCode.CONTENT_THREAT_DETECTED

    @pytest.mark.asyncio
    async def test_random_images_accepted(self, mock_upload_file):
        """Test random JPEG bodies and random-pixel PNGs are accepted."""
        from safeuploads.file_validator import FileValidator

        config = FileSecurityConfig()
        config.limits = SecurityLimits(enable_content_analysis=True)
        validator = FileValidator(config=config)
        for seed in range(5):
            jpeg = _JPEG + _random_bytes(seed, 300_000) + b"\xff\xd9"
            await validator.validate_image_file(
                mock_upload_file(filename="a.jpg", content=jpeg)
            )
            await validator.validate_image_file(
                mock_upload_file(filename="a.png", content=_random_png(seed))
            )

    @pytest.mark.asyncio
    async def test_zip_with_random_entry_accepted(
        self, mock_upload_file, create_zip_file
    ):
        """Test a ZIP with a random-data entry is not byte-scanned."""
        from safeuploads.file_validator import FileValidator

        config = FileSecurityConfig()
        config.limits = SecurityLimits(enable_content_analysis=True)
        validator = FileValidator(config=config)
        for seed in range(5):
            zip_bytes = create_zip_file(
                files={"a.dat": _random_bytes(seed, 300_000)}
            )
            await validator.validate_zip_file(
                mock_upload_file(filename="r.zip", content=zip_bytes)
            )

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

        sig = _HOSTILE_PAYLOADS["pe"]
        content = (
            b"\xff\xd8\xff\xe0"
            b"\x00\x10"
            b"JFIF\x00"
            b"\x01\x01\x00"
            b"\x00\x01\x00\x01"
            b"\x00\x00" + b"\x00" * 50 + sig + b"\x00" * 50 + b"\xff\xd9"
        )
        file = mock_upload_file(filename="img.jpg", content=content)
        # Should pass — analysis disabled
        await validator.validate_image_file(file)


class TestContentInspectorActivityPolyglot:
    def test_polyglot_in_activity_file_is_detected(self, default_config):
        inspector = ContentSecurityInspector(default_config)
        sig = b"PK\x03\x04"
        content = b"\x00" * 20 + sig + b"\x00" * 50
        threats = inspector.scan_content(content, "run.gpx", "activity")
        assert any("Polyglot" in t for t in threats)

    def test_png_with_appended_zip_is_polyglot(self, default_config):
        inspector = ContentSecurityInspector(default_config)
        content = _random_png(1, 8) + _zip_bytes()
        threats = inspector.scan_content(content, "a.png", "image")
        assert any("Polyglot" in t for t in threats)

    @pytest.mark.parametrize("expected_type", ["image", "activity"])
    @pytest.mark.parametrize(
        "secondary",
        [
            pytest.param(b"PK\x03\x04" + _PAD, id="zip"),
            pytest.param(b"Rar!\x1a\x07" + _PAD, id="rar"),
            pytest.param(_HOSTILE_PAYLOADS["java"], id="java"),
        ],
    )
    def test_polyglot_right_after_short_header_is_detected(
        self, default_config, expected_type, secondary
    ):
        inspector = ContentSecurityInspector(default_config)
        content = b"\xff\xd8\xff" + secondary
        threats = inspector.scan_content(content, "a.bin", expected_type)
        assert any("Polyglot" in t for t in threats)

    def test_jpeg_without_secondary_signature_is_clean(self, default_config):
        inspector = ContentSecurityInspector(default_config)
        content = _JPEG + _random_bytes(7, 2000) + b"\xff\xd9"
        assert inspector.scan_content(content, "a.jpg", "image") == []

    def test_java_class_in_image_needs_valid_version(self, default_config):
        inspector = ContentSecurityInspector(default_config)
        magic = _sig(MalwareSignatureCategory.JAVA_CLASS)
        valid = _JPEG + _HOSTILE_PAYLOADS["java"]
        invalid = _JPEG + magic + _PAD
        assert any(
            "Polyglot" in t
            for t in inspector.scan_content(valid, "a.jpg", "image")
        )
        assert inspector.scan_content(invalid, "a.jpg", "image") == []


class TestContentFalsePositives:
    """Random image data is accepted; hostile structures are not."""

    def test_random_jpeg_bodies_are_clean(self, default_config):
        inspector = ContentSecurityInspector(default_config)
        for seed in range(25):
            content = _JPEG + _random_bytes(seed, 300_000) + b"\xff\xd9"
            assert inspector.scan_content(content, "a.jpg", "image") == []

    def test_random_pixel_pngs_are_clean(self, default_config):
        inspector = ContentSecurityInspector(default_config)
        for seed in range(5):
            content = _random_png(seed)
            assert inspector.scan_content(content, "a.png", "image") == []

    @pytest.mark.parametrize("key", sorted(_HOSTILE_PAYLOADS))
    def test_hostile_appended_to_jpeg_is_detected(self, default_config, key):
        inspector = ContentSecurityInspector(default_config)
        content = _JPEG + _random_bytes(3, 2000) + _HOSTILE_PAYLOADS[key]
        assert inspector.scan_content(content, "a.jpg", "image")

    def test_pe_candidates_scan_is_linear(self, default_config):
        inspector = ContentSecurityInspector(default_config)
        content = (b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00") * 20_000
        assert inspector.scan_content(content, "a.dat", "") == []
