"""Integration tests for FileValidator.validate_activity_file."""

import logging

import pytest

from safeuploads.audit import get_correlation_id
from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.exceptions import (
    ExtensionSecurityError,
    FilenameSecurityError,
    FileProcessingError,
    FileSignatureError,
    FileSizeError,
    MimeTypeError,
    ResourceLimitError,
    UnicodeSecurityError,
)
from safeuploads.file_validator import FileValidator

# ---------------------------------------------------------------------------
# Minimal valid activity file payloads
# ---------------------------------------------------------------------------

_GPX_CONTENT = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b"<gpx>"
    b"<trk><trkseg>"
    b'<trkpt lat="0" lon="0"/>'
    b"</trkseg></trk>"
    b"</gpx>"
)

_TCX_CONTENT = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b"<TrainingCenterDatabase>"
    b"<Activities>"
    b'<Activity Sport="Running"></Activity>'
    b"</Activities>"
    b"</TrainingCenterDatabase>"
)

# 14-byte FIT header: bytes 8-11 must be b".FIT"
_FIT_CONTENT = (
    b"\x0e\x10\x00\x00"  # header_size, protocol, profile
    b"\x00\x00\x00\x00"  # data_size
    b".FIT"  # signature at bytes 8-11
    b"\x00\x00"  # crc
)

_XXE_XML = (
    b'<?xml version="1.0"?>'
    b'<!DOCTYPE foo ['
    b'<!ENTITY xxe SYSTEM "file:///etc/passwd">'
    b"]>"
    b"<gpx>&xxe;</gpx>"
)

_MALFORMED_XML = b'<?xml version="1.0"?><gpx><unclosed>'


class TestValidateActivityFileHappyPath:
    """Tests for valid activity files that should pass validation."""

    async def test_validate_activity_file_valid_gpx_passes(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("track.gpx", _GPX_CONTENT)
        await validator.validate_activity_file(f)

    async def test_validate_activity_file_valid_tcx_passes(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("workout.tcx", _TCX_CONTENT)
        await validator.validate_activity_file(f)

    async def test_validate_activity_file_valid_fit_passes(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("activity.fit", _FIT_CONTENT)
        await validator.validate_activity_file(f)


class TestValidateActivityFileFilenameErrors:
    """Tests for filename validation failures."""

    async def test_validate_activity_file_none_filename_raises(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file(None, _GPX_CONTENT)
        with pytest.raises(FilenameSecurityError):
            await validator.validate_activity_file(f)

    async def test_validate_activity_file_empty_filename_raises(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("", _GPX_CONTENT)
        with pytest.raises(FilenameSecurityError):
            await validator.validate_activity_file(f)

    async def test_validate_activity_file_unicode_filename_raises(
        self, mock_upload_file, dangerous_unicode_filename
    ):
        validator = FileValidator()
        f = mock_upload_file(
            dangerous_unicode_filename, _GPX_CONTENT
        )
        with pytest.raises(UnicodeSecurityError):
            await validator.validate_activity_file(f)


class TestValidateActivityFileExtensionErrors:
    """Tests for disallowed and blocked file extensions."""

    async def test_validate_activity_file_pdf_extension_raises(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("document.pdf", _GPX_CONTENT)
        with pytest.raises(ExtensionSecurityError):
            await validator.validate_activity_file(f)

    async def test_validate_activity_file_exe_extension_raises(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("malware.exe", b"data")
        with pytest.raises(ExtensionSecurityError):
            await validator.validate_activity_file(f)


class TestValidateActivityFileSizeErrors:
    """Tests for file size validation failures."""

    async def test_validate_activity_file_empty_file_raises(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("track.gpx", b"", size=0)
        with pytest.raises(FileSizeError):
            await validator.validate_activity_file(f)

    async def test_validate_activity_file_exceeds_max_size_raises(
        self, mock_upload_file
    ):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(max_activity_file_size=1024)
        validator = FileValidator(config=config)
        oversized = b"X" * 2048
        f = mock_upload_file("track.gpx", oversized)
        with pytest.raises(FileSizeError):
            await validator.validate_activity_file(f)


class TestValidateActivityFileMimeErrors:
    """Tests for MIME type validation failures."""

    async def test_validate_activity_file_wrong_mime_raises(
        self, mock_upload_file, monkeypatch
    ):
        validator = FileValidator()
        monkeypatch.setattr(
            validator,
            "_detect_mime_type",
            lambda content, filename: "application/pdf",
        )
        f = mock_upload_file("track.gpx", _GPX_CONTENT)
        with pytest.raises(MimeTypeError):
            await validator.validate_activity_file(f)


class TestValidateActivityFileSignatureErrors:
    """Tests for file signature validation failures."""

    async def test_validate_activity_file_non_xml_gpx_raises(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("track.gpx", b"This is not XML")
        with pytest.raises(FileSignatureError):
            await validator.validate_activity_file(f)

    async def test_validate_activity_file_invalid_fit_signature(
        self, mock_upload_file
    ):
        validator = FileValidator()
        bad_fit = b"\x0e\x10\x00\x00\x00\x00\x00\x00XXXX\x00\x00"
        f = mock_upload_file("activity.fit", bad_fit)
        with pytest.raises(FileSignatureError):
            await validator.validate_activity_file(f)


class TestValidateActivityFileXmlSecurity:
    """Tests for XML security checks (XXE, malformed XML)."""

    async def test_validate_activity_file_xxe_attack_raises(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("track.gpx", _XXE_XML)
        with pytest.raises(FileProcessingError):
            await validator.validate_activity_file(f)

    async def test_validate_activity_file_malformed_xml_raises(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("track.gpx", _MALFORMED_XML)
        with pytest.raises(FileProcessingError):
            await validator.validate_activity_file(f)


class TestValidateActivityFileExceptionWrapping:
    """Tests that unexpected errors are wrapped in FileProcessingError."""

    async def test_validate_activity_file_runtime_error_wrapped(
        self, mock_upload_file, monkeypatch
    ):
        validator = FileValidator()

        async def _raise_runtime(*_args, **_kwargs):
            raise RuntimeError("unexpected failure")

        monkeypatch.setattr(
            validator, "_stream_to_temp_file", _raise_runtime
        )
        f = mock_upload_file("track.gpx", _GPX_CONTENT)
        with pytest.raises(FileProcessingError):
            await validator.validate_activity_file(f)


class TestValidateActivityFileAuditEvents:
    """Tests for audit event emission and correlation ID handling."""

    async def test_validate_activity_file_success_emits_audit_events(
        self, mock_upload_file, caplog
    ):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(enable_audit_logging=True)
        validator = FileValidator(config=config)
        f = mock_upload_file("track.gpx", _GPX_CONTENT)
        with caplog.at_level(
            logging.INFO, logger="safeuploads.audit"
        ):
            await validator.validate_activity_file(f)

        audit_msgs = [
            r.getMessage()
            for r in caplog.records
            if r.name == "safeuploads.audit"
        ]
        assert any("validation_start" in m for m in audit_msgs)
        assert any("validation_success" in m for m in audit_msgs)

    async def test_validate_activity_file_failure_emits_audit_events(
        self, mock_upload_file, caplog
    ):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(enable_audit_logging=True)
        validator = FileValidator(config=config)
        f = mock_upload_file("", _GPX_CONTENT)
        with caplog.at_level(
            logging.WARNING, logger="safeuploads.audit"
        ):
            with pytest.raises(FilenameSecurityError):
                await validator.validate_activity_file(f)

        audit_msgs = [
            r.getMessage()
            for r in caplog.records
            if r.name == "safeuploads.audit"
        ]
        assert any("validation_failure" in m for m in audit_msgs)

    async def test_validate_activity_file_correlation_id_reset_success(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("track.gpx", _GPX_CONTENT)
        await validator.validate_activity_file(f)
        assert get_correlation_id() is None

    async def test_validate_activity_file_correlation_id_reset_failure(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("", _GPX_CONTENT)
        with pytest.raises(FilenameSecurityError):
            await validator.validate_activity_file(f)
        assert get_correlation_id() is None


class TestValidateActivityFileResourceLimit:
    """Tests for resource monitor enforcement."""

    async def test_validate_activity_file_resource_limit_raises(
        self, mock_upload_file
    ):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            max_validation_time_seconds=-1.0
        )
        validator = FileValidator(config=config)
        f = mock_upload_file("track.gpx", _GPX_CONTENT)
        with pytest.raises(ResourceLimitError):
            await validator.validate_activity_file(f)
