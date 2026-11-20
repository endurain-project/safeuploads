"""Tests for file signature validator."""

import pytest

from safeuploads.config import FileSecurityConfig
from safeuploads.exceptions import ErrorCode, FileSignatureError
from safeuploads.validators.signature_validator import (
    FileSignatureValidator,
)
from tests.images import heic, heif_ftyp


class TestSignature:
    """Test file signature validation."""

    def test_validate_jpeg_signature(self, valid_jpeg_bytes):
        """Test JPEG signature validation."""
        validator = FileSignatureValidator(FileSecurityConfig())

        # Should not raise
        validator.validate(valid_jpeg_bytes, expected_type="image")

    def test_validate_png_signature(self, valid_png_bytes):
        """Test PNG signature validation."""
        validator = FileSignatureValidator(FileSecurityConfig())

        # Should not raise
        validator.validate(valid_png_bytes, expected_type="image")

    def test_validate_webp_signature(self, valid_webp_bytes):
        """A RIFF container with the WEBP form type passes."""
        validator = FileSignatureValidator(FileSecurityConfig())

        # Should not raise
        validator.validate(valid_webp_bytes, expected_type="image")

    @pytest.mark.parametrize(
        "content",
        [
            b"RIFF\x24\x00\x00\x00WAVEfmt " + b"\x00" * 28,
            b"RIFF\x24\x00\x00\x00AVI LIST" + b"\x00" * 28,
            b"RIFF\x1a\x00\x00\x00",
            b"RIFF\x1a\x00\x00\x00WEB",
            b"\x00\x00\x00\x00RIFFWEBP" + b"\x00" * 8,
        ],
        ids=["wav", "avi", "riff-header-only", "truncated-form", "offset"],
    )
    def test_riff_that_is_not_webp_rejected(self, content):
        """RIFF content without WEBP at bytes 8-11 is not an image."""
        validator = FileSignatureValidator(FileSecurityConfig())

        with pytest.raises(FileSignatureError) as exc_info:
            validator.validate(content, expected_type="image")
        assert exc_info.value.error_code == ErrorCode.FILE_SIGNATURE_MISMATCH

    @pytest.mark.parametrize(
        "content",
        [
            heif_ftyp(b"heic", (b"mif1", b"heic")),
            heif_ftyp(b"heix", (b"mif1", b"heix")),
            heif_ftyp(b"mif1", (b"mif1", b"heic")),
            heif_ftyp(b"mif1", (b"miaf", b"heix")),
        ],
        ids=["heic", "heix", "mif1-heic", "mif1-heix"],
    )
    def test_heic_signature_accepted(self, content):
        """An ftyp box with an HEVC still-image brand passes."""
        validator = FileSignatureValidator(FileSecurityConfig())

        # Should not raise
        validator.validate(content + b"\x00" * 16, expected_type="image")

    @pytest.mark.parametrize(
        "content",
        [
            heif_ftyp(b"avif", (b"mif1", b"avif")),
            heif_ftyp(b"msf1", (b"msf1", b"hevc")),
            heif_ftyp(b"mif1", (b"mif1",)),
            heif_ftyp(b"isom", (b"isom", b"mp41")),
            # heic beyond the declared ftyp size
            b"\x00\x00\x00\x10ftypmif1\x00\x00\x00\x00heic" + b"\x00" * 8,
            # ftyp size past the bytes read
            b"\x00\x00\x01\x00ftypmif1\x00\x00\x00\x00heic",
            b"\x00\x00\x00\x0cftypheic",
            b"\x00\x00\x00\x18ftop" + b"heic" * 4,
        ],
        ids=[
            "avif",
            "sequence",
            "mif1-only",
            "mp4",
            "brand-outside-box",
            "box-past-content",
            "box-below-minimum",
            "not-ftyp",
        ],
    )
    def test_non_heic_iso_media_rejected(self, content):
        """ISO media without an HEVC still-image brand is rejected."""
        validator = FileSignatureValidator(FileSecurityConfig())

        with pytest.raises(FileSignatureError) as exc_info:
            validator.validate(content + b"\x00" * 16, expected_type="image")
        assert exc_info.value.error_code == ErrorCode.FILE_SIGNATURE_MISMATCH

    def test_heic_signature_not_accepted_for_other_types(self):
        """The HEIC signature counts only for the image type."""
        validator = FileSignatureValidator(FileSecurityConfig())

        with pytest.raises(FileSignatureError):
            validator.validate(heic(), expected_type="zip")

    def test_webp_signature_not_accepted_for_other_types(
        self, valid_webp_bytes
    ):
        """The WebP signature counts only for the image type."""
        validator = FileSignatureValidator(FileSecurityConfig())

        with pytest.raises(FileSignatureError) as exc_info:
            validator.validate(valid_webp_bytes, expected_type="zip")
        assert exc_info.value.error_code == ErrorCode.FILE_SIGNATURE_MISMATCH

    def test_validate_gif_signature(self):
        """Test GIF signature validation - GIF not in allowed signatures."""
        validator = FileSignatureValidator(FileSecurityConfig())
        gif_bytes = b"GIF89a" + b"\x00" * 100

        # GIF is not an allowed image signature (JPEG, PNG, WebP)
        with pytest.raises(FileSignatureError) as exc_info:
            validator.validate(gif_bytes, expected_type="image")
        assert exc_info.value.error_code == ErrorCode.FILE_SIGNATURE_MISMATCH

    def test_validate_zip_signature(self, create_zip_file):
        """Test ZIP signature validation."""
        validator = FileSignatureValidator(FileSecurityConfig())
        zip_bytes = create_zip_file(files={"test.txt": b"content"})

        # Should not raise
        validator.validate(zip_bytes, expected_type="zip")

    def test_validate_invalid_image_signature(self):
        """Test that invalid image signature is rejected."""
        validator = FileSignatureValidator(FileSecurityConfig())
        invalid_bytes = b"This is not an image"

        with pytest.raises(
            FileSignatureError,
            match="File content does not match expected image",
        ):
            validator.validate(invalid_bytes, expected_type="image")

    def test_validate_invalid_zip_signature(self):
        """Test that invalid ZIP signature is rejected."""
        validator = FileSignatureValidator(FileSecurityConfig())
        invalid_bytes = b"This is not a ZIP"

        with pytest.raises(
            FileSignatureError,
            match="File content does not match expected zip",
        ):
            validator.validate(invalid_bytes, expected_type="zip")

    def test_validate_activity_signature_leading_whitespace(self):
        """Leading whitespace before <?xml is tolerated."""
        validator = FileSignatureValidator(FileSecurityConfig())
        content = b"\n  <?xml version='1.0'?><gpx></gpx>"

        # Should not raise
        validator.validate(content, "activity")

    def test_validate_activity_signature_bom_then_whitespace(self):
        """A UTF-8 BOM followed by whitespace before <?xml passes."""
        validator = FileSignatureValidator(FileSecurityConfig())
        content = b"\xef\xbb\xbf\n<?xml version='1.0'?><gpx></gpx>"

        # Should not raise
        validator.validate(content, "activity")

    def test_validate_pdf_signature(self):
        """A PDF header at offset 0 passes."""
        validator = FileSignatureValidator(FileSecurityConfig())

        # Should not raise
        validator.validate(b"%PDF-1.7\n", "pdf")

    @pytest.mark.parametrize(
        "content",
        [b" %PDF-1.7\n", b"\xef\xbb\xbf%PDF-1.7", b"<html>%PDF-1.7"],
    )
    def test_pdf_header_not_at_start_rejected(self, content):
        """Readers accept a late header; the signature check does not."""
        validator = FileSignatureValidator(FileSecurityConfig())

        with pytest.raises(FileSignatureError) as exc_info:
            validator.validate(content, "pdf")
        assert exc_info.value.error_code == ErrorCode.FILE_SIGNATURE_MISMATCH


class TestSignatureEdgeCases:
    """Tests for signature edge cases."""

    def test_signature_too_small_file(self):
        """
        Test that files smaller than 4 bytes are rejected.

        Returns:
            None
        """
        validator = FileSignatureValidator(FileSecurityConfig())

        with pytest.raises(FileSignatureError, match="too small"):
            validator.validate(b"\xff\xd8", "image")

    def test_signature_one_byte_file(self):
        """
        Test that single byte files are rejected.

        Returns:
            None
        """
        validator = FileSignatureValidator(FileSecurityConfig())

        with pytest.raises(FileSignatureError) as exc_info:
            validator.validate(b"X", "zip")
        assert exc_info.value.error_code == ErrorCode.FILE_SIGNATURE_MISSING

    def test_signature_empty_content(self):
        """
        Test that empty content is rejected.

        Returns:
            None
        """
        validator = FileSignatureValidator(FileSecurityConfig())

        with pytest.raises(FileSignatureError) as exc_info:
            validator.validate(b"", "image")
        assert exc_info.value.error_code == ErrorCode.FILE_SIGNATURE_MISSING

    def test_signature_too_small_reports_missing_code(self):
        """A too-small header reports FILE_SIGNATURE_MISSING."""
        validator = FileSignatureValidator(FileSecurityConfig())
        with pytest.raises(FileSignatureError) as exc_info:
            validator.validate(b"\xff\xd8", "image")
        assert exc_info.value.error_code == ErrorCode.FILE_SIGNATURE_MISSING
