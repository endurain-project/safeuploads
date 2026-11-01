"""Integration tests for FileValidator.validate_activity_file."""

import logging

import pytest

from safeuploads.audit import get_correlation_id
from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.exceptions import (
    ContentThreatError,
    ErrorCode,
    ExtensionSecurityError,
    FilenameSecurityError,
    FileProcessingError,
    FileSignatureError,
    FileSizeError,
    FileValidationError,
    MimeTypeError,
    ResourceLimitError,
    UnicodeSecurityError,
    XmlSecurityError,
)
from safeuploads.file_validator import FileValidator
from tests.validators.test_fit_validator import build_fit

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

# libmagic reports text/plain for this header (namespaced extension
# element), although it is a valid GPX file.
_OSMAND_GPX_CONTENT = (
    b"<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n"
    b'<gpx version="1.1" creator="OsmAnd~ 5.4.10"'
    b' xmlns="http://www.topografix.com/GPX/1/1"'
    b' xmlns:osmand="https://osmand.net/docs/technical/'
    b'osmand-file-formats/osmand-gpx"'
    b' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
    b' xsi:schemaLocation="http://www.topografix.com/GPX/1/1'
    b' http://www.topografix.com/GPX/1/1/gpx.xsd">\n'
    b"  <metadata>\n"
    b"    <name>ride</name>\n"
    b"    <extensions>\n"
    b"      <osmand:activity>road_cycling</osmand:activity>\n"
    b"    </extensions>\n"
    b"  </metadata>\n"
    b'  <trk><trkseg><trkpt lat="0" lon="0"/></trkseg></trk>\n'
    b"</gpx>\n"
)

_FIT_CONTENT = build_fit(header_size=14)

_XXE_XML = (
    b'<?xml version="1.0"?>'
    b"<!DOCTYPE foo ["
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

    async def test_validate_activity_file_osmand_gpx_passes(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("track.gpx", _OSMAND_GPX_CONTENT)
        await validator.validate_activity_file(f)


class TestValidateActivityFileFilenameErrors:
    """Tests for filename validation failures."""

    async def test_validate_activity_file_none_filename_raises(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file(None, _GPX_CONTENT)
        with pytest.raises(FilenameSecurityError) as exc_info:
            await validator.validate_activity_file(f)
        assert exc_info.value.error_code == ErrorCode.FILENAME_EMPTY

    async def test_validate_activity_file_empty_filename_raises(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("", _GPX_CONTENT)
        with pytest.raises(FilenameSecurityError) as exc_info:
            await validator.validate_activity_file(f)
        assert exc_info.value.error_code == ErrorCode.FILENAME_EMPTY

    async def test_validate_activity_file_unicode_filename_raises(
        self, mock_upload_file, dangerous_unicode_filename
    ):
        validator = FileValidator()
        f = mock_upload_file(dangerous_unicode_filename, _GPX_CONTENT)
        with pytest.raises(UnicodeSecurityError) as exc_info:
            await validator.validate_activity_file(f)
        assert exc_info.value.error_code == ErrorCode.UNICODE_DANGEROUS_CHARS


class TestValidateActivityFileExtensionErrors:
    """Tests for disallowed and blocked file extensions."""

    async def test_validate_activity_file_pdf_extension_raises(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("document.pdf", _GPX_CONTENT)
        with pytest.raises(ExtensionSecurityError) as exc_info:
            await validator.validate_activity_file(f)
        assert exc_info.value.error_code == ErrorCode.EXTENSION_NOT_ALLOWED

    async def test_validate_activity_file_exe_extension_raises(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("malware.exe", b"data")
        with pytest.raises(ExtensionSecurityError) as exc_info:
            await validator.validate_activity_file(f)
        assert exc_info.value.error_code == ErrorCode.EXTENSION_BLOCKED


class TestValidateActivityFileSizeErrors:
    """Tests for file size validation failures."""

    async def test_validate_activity_file_empty_file_raises(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("track.gpx", b"", size=0)
        with pytest.raises(FileSizeError) as exc_info:
            await validator.validate_activity_file(f)
        assert exc_info.value.error_code == ErrorCode.FILE_EMPTY

    async def test_validate_activity_file_exceeds_max_size_raises(
        self, mock_upload_file
    ):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(max_activity_file_size=1024)
        validator = FileValidator(config=config)
        oversized = b"X" * 2048
        f = mock_upload_file("track.gpx", oversized)
        with pytest.raises(FileSizeError) as exc_info:
            await validator.validate_activity_file(f)
        assert exc_info.value.error_code == ErrorCode.FILE_TOO_LARGE


class TestValidateActivityFileMimeErrors:
    """Tests for MIME type validation failures."""

    async def test_validate_activity_file_wrong_mime_raises(
        self, mock_upload_file, monkeypatch
    ):
        validator = FileValidator()
        monkeypatch.setattr(
            validator.mime_validator,
            "detect",
            lambda content, filename: "application/pdf",
        )
        f = mock_upload_file("track.gpx", _GPX_CONTENT)
        with pytest.raises(MimeTypeError) as exc_info:
            await validator.validate_activity_file(f)
        assert exc_info.value.error_code == ErrorCode.MIME_TYPE_MISMATCH


class TestValidateActivityFileTextPlain:
    """libmagic reports text/plain for some valid XML."""

    @staticmethod
    def _as_text_plain(validator, monkeypatch):
        monkeypatch.setattr(
            validator.mime_validator,
            "detect",
            lambda content, filename: "text/plain",
        )

    async def test_non_xml_gpx_still_rejected(
        self, mock_upload_file, monkeypatch
    ):
        validator = FileValidator()
        self._as_text_plain(validator, monkeypatch)
        f = mock_upload_file("track.gpx", b"This is not XML")
        with pytest.raises(FileSignatureError) as exc_info:
            await validator.validate_activity_file(f)
        assert exc_info.value.error_code == ErrorCode.FILE_SIGNATURE_MISMATCH

    async def test_xxe_gpx_still_rejected(self, mock_upload_file, monkeypatch):
        validator = FileValidator()
        self._as_text_plain(validator, monkeypatch)
        f = mock_upload_file("track.gpx", _XXE_XML)
        with pytest.raises(XmlSecurityError) as exc_info:
            await validator.validate_activity_file(f)
        assert exc_info.value.error_code == ErrorCode.XML_DTD_FORBIDDEN

    async def test_fake_fit_still_rejected(
        self, mock_upload_file, monkeypatch
    ):
        validator = FileValidator()
        self._as_text_plain(validator, monkeypatch)
        fake = b"\x0e\x10" + b"\0" * 6 + b".FIT" + b"<?php evil ?>" * 10
        f = mock_upload_file("a.fit", fake)
        with pytest.raises(FileSignatureError) as exc_info:
            await validator.validate_activity_file(f)
        assert exc_info.value.error_code == ErrorCode.FIT_INVALID_STRUCTURE

    async def test_image_renamed_gpx_still_rejected(
        self, mock_upload_file, monkeypatch
    ):
        validator = FileValidator()
        self._as_text_plain(validator, monkeypatch)
        png = b"\x89PNG\r\n\x1a\n" + b"\0" * 64
        f = mock_upload_file("track.gpx", png)
        with pytest.raises(FileSignatureError) as exc_info:
            await validator.validate_activity_file(f)
        assert exc_info.value.error_code == ErrorCode.FILE_SIGNATURE_MISMATCH


class TestValidateActivityFileSignatureErrors:
    """Tests for file signature validation failures."""

    async def test_validate_activity_file_non_xml_gpx_raises(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("track.gpx", b"This is not XML")
        with pytest.raises(FileSignatureError) as exc_info:
            await validator.validate_activity_file(f)
        assert exc_info.value.error_code == ErrorCode.FILE_SIGNATURE_MISMATCH

    async def test_validate_activity_file_invalid_fit_signature(
        self, mock_upload_file
    ):
        validator = FileValidator()
        bad_fit = b"\x0e\x10\x00\x00\x00\x00\x00\x00XXXX\x00\x00"
        f = mock_upload_file("activity.fit", bad_fit)
        with pytest.raises(FileSignatureError) as exc_info:
            await validator.validate_activity_file(f)
        assert exc_info.value.error_code == ErrorCode.FILE_SIGNATURE_MISMATCH

    async def test_validate_activity_file_fake_fit_rejected(
        self, mock_upload_file
    ):
        validator = FileValidator()
        fake = b"\x0e\x10" + b"\0" * 6 + b".FIT" + b"<?php evil ?>" * 10
        f = mock_upload_file("a.fit", fake)
        with pytest.raises(FileSignatureError) as exc_info:
            await validator.validate_activity_file(f)
        assert exc_info.value.error_code == ErrorCode.FIT_INVALID_STRUCTURE

    async def test_validate_activity_file_fit_trailing_data_rejected(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("a.fit", _FIT_CONTENT + b"<?php evil ?>")
        with pytest.raises(FileSignatureError) as exc_info:
            await validator.validate_activity_file(f)
        assert exc_info.value.error_code == ErrorCode.FIT_INVALID_STRUCTURE


def _analysis_validator(enabled: bool) -> FileValidator:
    config = FileSecurityConfig()
    config.limits = SecurityLimits(enable_content_analysis=enabled)
    return FileValidator(config)


_GPX_SCRIPT = b'<?xml version="1.0"?><gpx><script>x</script></gpx>'
_FIT_PHP = build_fit(b"<?php evil ?>" * 4)
_TCX_SCRIPT = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b"<TrainingCenterDatabase>"
    b"<Activities>"
    b'<Activity Sport="Running"><script>x</script></Activity>'
    b"</Activities>"
    b"</TrainingCenterDatabase>"
)


class TestValidateActivityFileContentAnalysis:
    """Optional content analysis covers activity files."""

    @pytest.mark.parametrize(
        ("name", "content"),
        [
            ("a.gpx", _GPX_SCRIPT),
            ("a.tcx", _TCX_SCRIPT),
            ("a.fit", _FIT_PHP),
        ],
    )
    async def test_threat_rejected_when_enabled(
        self, mock_upload_file, name, content
    ):
        validator = _analysis_validator(True)
        with pytest.raises(ContentThreatError) as exc_info:
            await validator.validate_activity_file(
                mock_upload_file(name, content)
            )
        assert exc_info.value.error_code == ErrorCode.CONTENT_THREAT_DETECTED

    @pytest.mark.parametrize(
        ("name", "content"),
        [
            ("a.gpx", _GPX_SCRIPT),
            ("a.tcx", _TCX_SCRIPT),
            ("a.fit", _FIT_PHP),
        ],
    )
    async def test_threat_accepted_when_disabled(
        self, mock_upload_file, name, content
    ):
        validator = _analysis_validator(False)
        await validator.validate_activity_file(mock_upload_file(name, content))

    @pytest.mark.parametrize(
        ("name", "content"),
        [
            ("a.gpx", _GPX_CONTENT),
            ("a.tcx", _TCX_CONTENT),
            ("a.fit", _FIT_CONTENT),
        ],
    )
    async def test_clean_file_accepted_when_enabled(
        self, mock_upload_file, name, content
    ):
        validator = _analysis_validator(True)
        await validator.validate_activity_file(mock_upload_file(name, content))


class TestValidateActivityFileXmlSecurity:
    """Tests for XML security checks (XXE, malformed XML)."""

    async def test_validate_activity_file_xxe_attack_raises(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("track.gpx", _XXE_XML)
        with pytest.raises(XmlSecurityError) as exc_info:
            await validator.validate_activity_file(f)
        assert exc_info.value.error_code == ErrorCode.XML_DTD_FORBIDDEN
        assert isinstance(exc_info.value, FileValidationError)

    async def test_validate_activity_file_malformed_xml_raises(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("track.gpx", _MALFORMED_XML)
        with pytest.raises(XmlSecurityError) as exc_info:
            await validator.validate_activity_file(f)
        assert exc_info.value.error_code == ErrorCode.XML_MALFORMED


class TestValidateActivityFileExceptionWrapping:
    """Tests that unexpected errors are wrapped in FileProcessingError."""

    async def test_validate_activity_file_runtime_error_wrapped(
        self, mock_upload_file, monkeypatch
    ):
        validator = FileValidator()

        async def _raise_runtime(*_args, **_kwargs):
            raise RuntimeError("unexpected failure")

        monkeypatch.setattr(validator, "_stream_to_temp_file", _raise_runtime)
        f = mock_upload_file("track.gpx", _GPX_CONTENT)
        with pytest.raises(FileProcessingError) as exc_info:
            await validator.validate_activity_file(f)
        assert exc_info.value.error_code == ErrorCode.PROCESSING_ERROR


class TestValidateActivityFileAuditEvents:
    """Tests for audit event emission and correlation ID handling."""

    async def test_validate_activity_file_success_emits_audit_events(
        self, mock_upload_file, caplog
    ):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(enable_audit_logging=True)
        validator = FileValidator(config=config)
        f = mock_upload_file("track.gpx", _GPX_CONTENT)
        with caplog.at_level(logging.INFO, logger="safeuploads.audit"):
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
        with (
            caplog.at_level(logging.WARNING, logger="safeuploads.audit"),
            pytest.raises(FilenameSecurityError),
        ):
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
        with pytest.raises(FilenameSecurityError) as exc_info:
            await validator.validate_activity_file(f)
        assert exc_info.value.error_code == ErrorCode.FILENAME_EMPTY
        assert get_correlation_id() is None


class TestValidateActivityFileResourceLimit:
    """Tests for resource monitor enforcement."""

    async def test_validate_activity_file_resource_limit_raises(
        self, mock_upload_file
    ):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(max_validation_time_seconds=1e-9)
        validator = FileValidator(config=config)
        f = mock_upload_file("track.gpx", _GPX_CONTENT)
        with pytest.raises(ResourceLimitError) as exc_info:
            await validator.validate_activity_file(f)
        assert exc_info.value.error_code == ErrorCode.RESOURCE_TIME_EXCEEDED
