"""Tests for audit logging module."""

import asyncio
import logging

import pytest

from safeuploads.audit import (
    AuditEvent,
    AuditEventType,
    SecurityAuditLogger,
    get_correlation_id,
    reset_correlation_id,
    set_correlation_id,
)
from safeuploads.config import FileSecurityConfig
from safeuploads.exceptions import (
    CompressionSecurityError,
    ErrorCode,
    FileSizeError,
    UnicodeSecurityError,
    ZipBombError,
    ZipContentError,
)
from safeuploads.file_validator import FileValidator


class TestCorrelationId:
    """Test correlation ID context variable."""

    def test_default_is_none(self):
        """Test correlation ID defaults to None."""
        reset_correlation_id()
        assert get_correlation_id() is None

    def test_set_generates_uuid(self):
        """Test set generates a UUID hex string."""
        cid = set_correlation_id()
        assert cid is not None
        assert len(cid) == 32  # UUID4 hex
        assert get_correlation_id() == cid
        reset_correlation_id()

    def test_set_explicit_value(self):
        """Test set accepts explicit value."""
        cid = set_correlation_id("my-custom-id")
        assert cid == "my-custom-id"
        assert get_correlation_id() == "my-custom-id"
        reset_correlation_id()

    def test_reset_clears_value(self):
        """Test reset clears correlation ID."""
        set_correlation_id()
        reset_correlation_id()
        assert get_correlation_id() is None


class TestAuditEvent:
    """Test AuditEvent dataclass."""

    def test_create_event(self):
        """Test creating an audit event."""
        event = AuditEvent(
            event_type=AuditEventType.VALIDATION_START,
            correlation_id="abc123",
            filename="test.jpg",
            result="started",
        )
        assert event.event_type == AuditEventType.VALIDATION_START
        assert event.correlation_id == "abc123"
        assert event.filename == "test.jpg"
        assert event.result == "started"
        assert event.duration_ms == 0.0
        assert event.source_ip is None

    def test_event_with_all_fields(self):
        """Test event with all fields populated."""
        event = AuditEvent(
            event_type=AuditEventType.VALIDATION_FAILURE,
            correlation_id="def456",
            filename="bad.zip",
            result="failed",
            details="zip bomb detected",
            duration_ms=150.5,
            source_ip="192.168.1.1",
        )
        assert event.details == "zip bomb detected"
        assert event.duration_ms == 150.5
        assert event.source_ip == "192.168.1.1"


class TestAuditEventType:
    """Test AuditEventType enum."""

    def test_all_types_exist(self):
        """Test all expected event types exist."""
        assert AuditEventType.VALIDATION_START.value == "validation_start"
        assert AuditEventType.VALIDATION_SUCCESS.value == "validation_success"
        assert AuditEventType.VALIDATION_FAILURE.value == "validation_failure"
        assert AuditEventType.THREAT_DETECTED.value == "threat_detected"
        assert AuditEventType.RESOURCE_LIMIT.value == "resource_limit"


class TestSecurityAuditLogger:
    """Test SecurityAuditLogger."""

    def test_disabled_does_not_log(self, caplog):
        """Test disabled logger produces no output."""
        audit = SecurityAuditLogger(enabled=False)
        with caplog.at_level(logging.DEBUG, logger="safeuploads.audit"):
            audit.start("test.jpg", "cid123")
        assert len(caplog.records) == 0

    def test_enabled_logs_start(self, caplog):
        """Test enabled logger logs start event."""
        audit = SecurityAuditLogger(enabled=True)
        with caplog.at_level(logging.DEBUG, logger="safeuploads.audit"):
            audit.start("photo.jpg", "cid-abc")
        assert len(caplog.records) == 1
        record = caplog.records[0]
        assert "validation_start" in record.message
        assert "photo.jpg" in record.message
        assert record.audit_correlation_id == "cid-abc"

    def test_enabled_logs_success(self, caplog):
        """Test enabled logger logs success event."""
        audit = SecurityAuditLogger(enabled=True)
        with caplog.at_level(logging.DEBUG, logger="safeuploads.audit"):
            audit.success("photo.jpg", "cid-abc", 42.5)
        assert len(caplog.records) == 1
        record = caplog.records[0]
        assert "validation_success" in record.message
        assert record.audit_duration_ms == 42.5
        assert record.levelno == logging.INFO

    def test_enabled_logs_failure(self, caplog):
        """Test enabled logger logs failure event."""
        audit = SecurityAuditLogger(enabled=True)
        with caplog.at_level(logging.DEBUG, logger="safeuploads.audit"):
            audit.failure(
                "bad.zip",
                "cid-def",
                100.0,
                "ZipBombError",
                "ratio exceeded",
            )
        assert len(caplog.records) == 1
        record = caplog.records[0]
        assert "validation_failure" in record.message
        assert record.levelno == logging.WARNING
        assert record.audit_details == "ratio exceeded"

    def test_enabled_logs_threat(self, caplog):
        """Test enabled logger logs threat event."""
        audit = SecurityAuditLogger(enabled=True)
        with caplog.at_level(logging.DEBUG, logger="safeuploads.audit"):
            audit.threat(
                "evil.zip",
                "cid-ghi",
                "directory traversal detected",
            )
        assert len(caplog.records) == 1
        record = caplog.records[0]
        assert "threat_detected" in record.message
        assert record.levelno == logging.WARNING

    def test_enabled_logs_resource_limit(self, caplog):
        """Test enabled logger logs resource limit event."""
        audit = SecurityAuditLogger(enabled=True)
        with caplog.at_level(logging.DEBUG, logger="safeuploads.audit"):
            audit.resource_limit("big.zip", "cid-rl", 12.5, "time limit")
        assert len(caplog.records) == 1
        record = caplog.records[0]
        assert record.audit_event_type == "resource_limit"
        assert record.audit_filename == "big.zip"
        assert record.audit_result == "time limit"
        assert record.audit_duration_ms == 12.5
        assert record.levelno == logging.WARNING

    def test_log_event_with_full_audit_event(self, caplog):
        """Test log_event with direct AuditEvent."""
        audit = SecurityAuditLogger(enabled=True)
        event = AuditEvent(
            event_type=AuditEventType.RESOURCE_LIMIT,
            correlation_id="cid-rl",
            filename="huge.zip",
            result="resource_exceeded",
            details="time limit",
            duration_ms=30000.0,
        )
        with caplog.at_level(logging.DEBUG, logger="safeuploads.audit"):
            audit.log_event(event)
        assert len(caplog.records) == 1
        assert caplog.records[0].levelno == logging.WARNING

    def test_extra_fields_on_log_record(self, caplog):
        """Test that extra fields are attached to log record."""
        audit = SecurityAuditLogger(enabled=True)
        with caplog.at_level(logging.DEBUG, logger="safeuploads.audit"):
            audit.start("test.png", "cid-extra")
        record = caplog.records[0]
        assert record.audit_event_type == "validation_start"
        assert record.audit_correlation_id == "cid-extra"
        assert record.audit_filename == "test.png"
        assert record.audit_result == "started"
        assert record.audit_source_ip == ""


class TestAuditIntegration:
    """Test audit logging integration with FileValidator."""

    @pytest.mark.asyncio
    async def test_image_validation_produces_audit_events(
        self, mock_upload_file, valid_jpeg_bytes, caplog
    ):
        """Test image validation emits start+success events."""
        from safeuploads.config import FileSecurityConfig, SecurityLimits
        from safeuploads.file_validator import FileValidator

        config = FileSecurityConfig()
        config.limits = SecurityLimits(enable_audit_logging=True)
        validator = FileValidator(config=config)
        file = mock_upload_file(filename="photo.jpg", content=valid_jpeg_bytes)

        with caplog.at_level(logging.DEBUG, logger="safeuploads.audit"):
            await validator.validate_image_file(file)

        # Should have start + success
        audit_records = [
            r for r in caplog.records if r.name == "safeuploads.audit"
        ]
        assert len(audit_records) == 2
        assert "validation_start" in audit_records[0].message
        assert "validation_success" in audit_records[1].message
        # Same correlation ID
        assert (
            audit_records[0].audit_correlation_id
            == audit_records[1].audit_correlation_id
        )

    @pytest.mark.asyncio
    async def test_image_validation_failure_produces_audit(
        self, mock_upload_file, caplog
    ):
        """Test failed validation emits start+failure events."""
        from safeuploads.config import FileSecurityConfig, SecurityLimits
        from safeuploads.file_validator import FileValidator

        config = FileSecurityConfig()
        config.limits = SecurityLimits(enable_audit_logging=True)
        validator = FileValidator(config=config)
        file = mock_upload_file(filename="photo.jpg", content=b"")

        with (
            caplog.at_level(logging.DEBUG, logger="safeuploads.audit"),
            pytest.raises(FileSizeError),
        ):
            await validator.validate_image_file(file)

        audit_records = [
            r for r in caplog.records if r.name == "safeuploads.audit"
        ]
        assert len(audit_records) == 2
        assert "validation_start" in audit_records[0].message
        assert "validation_failure" in audit_records[1].message

    @pytest.mark.asyncio
    async def test_resource_limit_emits_single_resource_limit_event(
        self, mock_upload_file, valid_jpeg_bytes, fake_clock, caplog
    ):
        """Test a time limit emits start+resource_limit, no failure."""
        from safeuploads.config import FileSecurityConfig, SecurityLimits
        from safeuploads.exceptions import ResourceLimitError
        from safeuploads.file_validator import FileValidator

        config = FileSecurityConfig()
        config.limits = SecurityLimits(enable_audit_logging=True)
        validator = FileValidator(config=config)
        file = mock_upload_file(filename="photo.jpg", content=valid_jpeg_bytes)
        fake_clock.step = 1000.0
        fake_clock.advancing = True

        with (
            caplog.at_level(logging.DEBUG, logger="safeuploads.audit"),
            pytest.raises(ResourceLimitError) as exc_info,
        ):
            await validator.validate_image_file(file)

        assert exc_info.value.error_code == ErrorCode.RESOURCE_TIME_EXCEEDED
        audit_records = [
            r for r in caplog.records if r.name == "safeuploads.audit"
        ]
        assert [r.audit_event_type for r in audit_records] == [
            "validation_start",
            "resource_limit",
        ]
        limit_record = audit_records[1]
        assert limit_record.audit_filename == "photo.jpg"
        assert limit_record.audit_result == str(exc_info.value)
        assert limit_record.levelno == logging.WARNING
        assert (
            limit_record.audit_correlation_id
            == audit_records[0].audit_correlation_id
        )

    @pytest.mark.asyncio
    async def test_zip_validation_produces_audit_events(
        self, mock_upload_file, create_zip_file, caplog
    ):
        """Test ZIP validation emits start+success events."""
        from safeuploads.config import FileSecurityConfig, SecurityLimits
        from safeuploads.file_validator import FileValidator

        config = FileSecurityConfig()
        config.limits = SecurityLimits(enable_audit_logging=True)
        validator = FileValidator(config=config)
        zip_bytes = create_zip_file(files={"test.txt": b"content"})
        file = mock_upload_file(filename="archive.zip", content=zip_bytes)

        with caplog.at_level(logging.DEBUG, logger="safeuploads.audit"):
            await validator.validate_zip_file(file)

        audit_records = [
            r for r in caplog.records if r.name == "safeuploads.audit"
        ]
        assert len(audit_records) == 2
        assert "validation_start" in audit_records[0].message
        assert "validation_success" in audit_records[1].message

    @pytest.mark.asyncio
    async def test_audit_disabled_produces_no_events(
        self, mock_upload_file, valid_jpeg_bytes, caplog
    ):
        """Test disabled audit produces no events."""
        from safeuploads.config import FileSecurityConfig, SecurityLimits
        from safeuploads.file_validator import FileValidator

        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            enable_audit_logging=False,
        )
        validator = FileValidator(config=config)
        file = mock_upload_file(filename="photo.jpg", content=valid_jpeg_bytes)

        with caplog.at_level(logging.DEBUG, logger="safeuploads.audit"):
            await validator.validate_image_file(file)

        audit_records = [
            r for r in caplog.records if r.name == "safeuploads.audit"
        ]
        assert len(audit_records) == 0

    @pytest.mark.asyncio
    async def test_correlation_id_reset_after_validation(
        self, mock_upload_file, valid_jpeg_bytes
    ):
        """Test correlation ID is reset after validation."""
        from safeuploads.config import FileSecurityConfig, SecurityLimits
        from safeuploads.file_validator import FileValidator

        config = FileSecurityConfig()
        config.limits = SecurityLimits(enable_audit_logging=True)
        validator = FileValidator(config=config)
        file = mock_upload_file(filename="photo.jpg", content=valid_jpeg_bytes)

        await validator.validate_image_file(file)
        assert get_correlation_id() is None


class TestThreatAuditEvents:
    """Test threat audit events from inspectors/validators."""

    @pytest.mark.asyncio
    async def test_zip_threats_emit_audit_event(
        self, mock_upload_file, caplog
    ):
        """Test ZIP content threats emit THREAT_DETECTED."""
        import io
        import zipfile

        from safeuploads.config import (
            FileSecurityConfig,
            SecurityLimits,
        )
        from safeuploads.file_validator import FileValidator

        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            enable_audit_logging=True,
        )
        validator = FileValidator(config=config)

        # ZIP with directory traversal
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../../../etc/passwd", b"evil")
        zip_bytes = buf.getvalue()

        file = mock_upload_file(filename="evil.zip", content=zip_bytes)

        with (
            caplog.at_level(logging.DEBUG, logger="safeuploads.audit"),
            pytest.raises(ZipContentError),
        ):
            await validator.validate_zip_file(file)

        threat_records = [
            r
            for r in caplog.records
            if r.name == "safeuploads.audit" and "threat_detected" in r.message
        ]
        assert len(threat_records) >= 1

    @pytest.mark.asyncio
    async def test_zip_bomb_emits_audit_threat(self, mock_upload_file, caplog):
        """Test zip bomb detection emits THREAT_DETECTED."""
        import io
        import zipfile

        from safeuploads.config import (
            FileSecurityConfig,
            SecurityLimits,
        )
        from safeuploads.file_validator import FileValidator

        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            enable_audit_logging=True,
            max_compression_ratio=5,
            max_uncompressed_size=100 * 1024 * 1024,
        )
        validator = FileValidator(config=config)

        # Highly compressible content
        data = b"\x00" * (1024 * 1024)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("zeros.bin", data)
        zip_bytes = buf.getvalue()

        file = mock_upload_file(filename="bomb.zip", content=zip_bytes)

        with (
            caplog.at_level(logging.DEBUG, logger="safeuploads.audit"),
            pytest.raises((ZipBombError, CompressionSecurityError)),
        ):
            await validator.validate_zip_file(file)

        threat_records = [
            r
            for r in caplog.records
            if r.name == "safeuploads.audit" and "threat_detected" in r.message
        ]
        assert len(threat_records) >= 1

    @pytest.mark.asyncio
    async def test_gzip_bomb_emits_audit_threat(
        self, mock_upload_file, caplog
    ):
        """Test gzip bomb detection emits THREAT_DETECTED."""
        import gzip
        import io

        from safeuploads.config import (
            FileSecurityConfig,
            SecurityLimits,
        )
        from safeuploads.file_validator import FileValidator

        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            enable_audit_logging=True,
            max_compression_ratio=5,
            max_uncompressed_size=100 * 1024 * 1024,
        )
        validator = FileValidator(config=config)

        content = b"\x00" * (1024 * 1024)
        buf = io.BytesIO()
        with gzip.open(buf, "wb") as gz:
            gz.write(content)
        gz_bytes = buf.getvalue()

        file = mock_upload_file(filename="bomb.gz", content=gz_bytes)

        with (
            caplog.at_level(logging.DEBUG, logger="safeuploads.audit"),
            pytest.raises(ZipBombError),
        ):
            await validator.validate_gzip_file(file)

        threat_records = [
            r
            for r in caplog.records
            if r.name == "safeuploads.audit" and "threat_detected" in r.message
        ]
        assert len(threat_records) >= 1


class TestLogExtraCorrelationId:
    """Test correlation_id propagation in log extras."""

    def test_log_extra_adds_correlation_id(self):
        """Test log_extra adds correlation_id to dict."""
        from safeuploads.audit import log_extra

        set_correlation_id("test-cid-123")
        extra = log_extra({"key": "value"})
        assert extra["correlation_id"] == "test-cid-123"
        assert extra["key"] == "value"
        reset_correlation_id()

    def test_log_extra_without_correlation_id(self):
        """Test log_extra works when correlation ID not set."""
        from safeuploads.audit import log_extra

        reset_correlation_id()
        extra = log_extra({"key": "value"})
        assert "correlation_id" not in extra
        assert extra["key"] == "value"

    def test_log_extra_with_no_base_dict(self):
        """Test log_extra with no base dict."""
        from safeuploads.audit import log_extra

        set_correlation_id("cid-abc")
        extra = log_extra()
        assert extra["correlation_id"] == "cid-abc"
        reset_correlation_id()


_FORGED = (
    "a.jpg\nsafeuploads.audit: [forged] validation_success"
    " file=evil.exe result=passed"
)


def _log_one(caplog, **fields) -> logging.LogRecord:
    """
    Emit one audit event and return the single captured record.

    Args:
        caplog: pytest log capture fixture.
        **fields: ``AuditEvent`` fields to override.

    Returns:
        The only record captured on ``safeuploads.audit``.
    """
    audit = SecurityAuditLogger(enabled=True)
    event = AuditEvent(
        event_type=AuditEventType.VALIDATION_FAILURE,
        correlation_id="cid-1234567890abcdef",
        **fields,
    )
    with caplog.at_level(logging.DEBUG, logger="safeuploads.audit"):
        audit.log_event(event)
    assert len(caplog.records) == 1
    return caplog.records[0]


class TestAuditLogInjection:
    """Attacker-controlled audit fields cannot forge or flood records."""

    @pytest.mark.parametrize("field", ["filename", "result", "details"])
    def test_newline_does_not_forge_record(self, caplog, field):
        """A newline in any field stays one escaped log record."""
        record = _log_one(caplog, **{field: _FORGED})
        assert "\n" not in record.getMessage()
        value = getattr(record, f"audit_{field}")
        assert "\n" not in value
        assert value.startswith("a.jpg\\nsafeuploads.audit: [forged]")

    def test_legitimate_filename_unchanged(self, caplog):
        """Ordinary non-ASCII letters are kept as-is."""
        record = _log_one(caplog, filename="résumé_日本.jpg")
        assert "file=résumé_日本.jpg" in record.getMessage()
        assert record.audit_filename == "résumé_日本.jpg"

    def test_control_and_format_chars_escaped(self, caplog):
        """Tabs, ESC, bidi overrides and tag chars are escaped."""
        name = "a\t\r\x1b\u202e\U000e0041\u2028.jpg"
        record = _log_one(caplog, filename=name)
        assert record.audit_filename == (
            "a\\t\\r\\x1b\\u202e\\U000e0041\\u2028.jpg"
        )
        assert "\u202e" not in record.getMessage()

    def test_length_boundary(self, caplog):
        """1,024 characters pass; 1,025 are truncated and marked."""
        exact = "a" * 1024
        record = _log_one(caplog, filename=exact)
        assert record.audit_filename == exact

        caplog.clear()
        record = _log_one(caplog, filename="a" * 1025)
        assert len(record.audit_filename) == 1024
        assert record.audit_filename.endswith("...[truncated]")

    def test_details_are_bounded(self, caplog):
        """Oversized threat details cannot flood the record."""
        record = _log_one(caplog, details="x" * 1_000_000)
        assert len(record.audit_details) == 1024


class TestAuditLogInjectionEndToEnd:
    """A hostile upload filename cannot forge an audit line."""

    async def test_forged_filename_cannot_forge_audit_line(
        self, caplog, mock_upload_file, valid_jpeg_bytes
    ):
        """Every audit record is one line; no forged line appears."""
        cfg = FileSecurityConfig()
        cfg.limits.enable_audit_logging = True
        validator = FileValidator(cfg)
        file = mock_upload_file(_FORGED + ".jpg", valid_jpeg_bytes)

        with (
            caplog.at_level(logging.DEBUG, logger="safeuploads.audit"),
            pytest.raises(UnicodeSecurityError),
        ):
            await validator.validate_image_file(file)

        records = [r for r in caplog.records if r.name == "safeuploads.audit"]
        assert len(records) == 2  # start + failure
        for record in records:
            assert "\n" not in record.getMessage()
        assert "\nsafeuploads.audit: [forged]" not in caplog.text


class TestCorrelationIdPreservedByValidation:
    """Validation keeps a host-set correlation ID."""

    @staticmethod
    def _validator():
        from safeuploads.config import FileSecurityConfig, SecurityLimits
        from safeuploads.file_validator import FileValidator

        config = FileSecurityConfig()
        config.limits = SecurityLimits(enable_audit_logging=True)
        return FileValidator(config=config)

    @pytest.mark.asyncio
    async def test_host_id_is_used_and_restored(
        self, mock_upload_file, valid_jpeg_bytes, caplog
    ):
        """Audit records carry the host ID and it survives."""
        set_correlation_id("host-123")
        try:
            file = mock_upload_file(
                filename="photo.jpg", content=valid_jpeg_bytes
            )
            with caplog.at_level(logging.DEBUG, logger="safeuploads.audit"):
                await self._validator().validate_image_file(file)
            records = [
                r for r in caplog.records if r.name == "safeuploads.audit"
            ]
            assert len(records) == 2
            assert {r.audit_correlation_id for r in records} == {"host-123"}
            assert get_correlation_id() == "host-123"
        finally:
            reset_correlation_id()

    @pytest.mark.asyncio
    async def test_fresh_id_during_and_none_after(
        self, mock_upload_file, valid_jpeg_bytes, caplog
    ):
        """Without a host ID a fresh one is used, then cleared."""
        reset_correlation_id()
        file = mock_upload_file(filename="photo.jpg", content=valid_jpeg_bytes)
        with caplog.at_level(logging.DEBUG, logger="safeuploads.audit"):
            await self._validator().validate_image_file(file)
        records = [r for r in caplog.records if r.name == "safeuploads.audit"]
        assert len({r.audit_correlation_id for r in records}) == 1
        assert records[0].audit_correlation_id
        assert get_correlation_id() is None

    @pytest.mark.asyncio
    async def test_id_restored_after_failed_validation(self, mock_upload_file):
        """A rejected upload still restores the host ID."""
        from safeuploads.exceptions import FileValidationError

        set_correlation_id("host-err")
        try:
            file = mock_upload_file(filename="photo.jpg", content=b"")
            with pytest.raises(FileValidationError) as exc_info:
                await self._validator().validate_image_file(file)
            assert exc_info.value.error_code == ErrorCode.FILE_EMPTY
            assert get_correlation_id() == "host-err"
        finally:
            reset_correlation_id()

    @pytest.mark.asyncio
    async def test_concurrent_validations_restore_their_own_ids(
        self, mock_upload_file, valid_jpeg_bytes
    ):
        """Gathered tasks each keep and restore their own ID."""
        validator = self._validator()

        async def _run(cid: str | None) -> str | None:
            if cid is not None:
                set_correlation_id(cid)
            file = mock_upload_file(
                filename="photo.jpg", content=valid_jpeg_bytes
            )
            await validator.validate_image_file(file)
            return get_correlation_id()

        results = await asyncio.gather(_run("a"), _run("b"), _run(None))
        assert results == ["a", "b", None]
        assert get_correlation_id() is None
