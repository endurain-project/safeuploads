"""Tests for audit logging module."""

import logging

import pytest

from safeuploads.audit import (
    AuditEvent,
    AuditEventType,
    SecurityAuditLogger,
    correlation_id_var,
    get_correlation_id,
    reset_correlation_id,
    set_correlation_id,
)


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
                "bad.zip", "cid-def", 100.0,
                "ZipBombError", "ratio exceeded",
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
                "evil.zip", "cid-ghi",
                "directory traversal detected",
            )
        assert len(caplog.records) == 1
        record = caplog.records[0]
        assert "threat_detected" in record.message
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
        file = mock_upload_file(
            filename="photo.jpg", content=valid_jpeg_bytes
        )

        with caplog.at_level(logging.DEBUG, logger="safeuploads.audit"):
            await validator.validate_image_file(file)

        # Should have start + success
        audit_records = [
            r for r in caplog.records
            if r.name == "safeuploads.audit"
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
        from safeuploads.exceptions import FileSizeError
        from safeuploads.file_validator import FileValidator

        config = FileSecurityConfig()
        config.limits = SecurityLimits(enable_audit_logging=True)
        validator = FileValidator(config=config)
        file = mock_upload_file(
            filename="photo.jpg", content=b""
        )

        with caplog.at_level(logging.DEBUG, logger="safeuploads.audit"):
            with pytest.raises(FileSizeError):
                await validator.validate_image_file(file)

        audit_records = [
            r for r in caplog.records
            if r.name == "safeuploads.audit"
        ]
        assert len(audit_records) == 2
        assert "validation_start" in audit_records[0].message
        assert "validation_failure" in audit_records[1].message

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
        zip_bytes = create_zip_file(
            files={"test.txt": b"content"}
        )
        file = mock_upload_file(
            filename="archive.zip", content=zip_bytes
        )

        with caplog.at_level(logging.DEBUG, logger="safeuploads.audit"):
            await validator.validate_zip_file(file)

        audit_records = [
            r for r in caplog.records
            if r.name == "safeuploads.audit"
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
        file = mock_upload_file(
            filename="photo.jpg", content=valid_jpeg_bytes
        )

        with caplog.at_level(logging.DEBUG, logger="safeuploads.audit"):
            await validator.validate_image_file(file)

        audit_records = [
            r for r in caplog.records
            if r.name == "safeuploads.audit"
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
        file = mock_upload_file(
            filename="photo.jpg", content=valid_jpeg_bytes
        )

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

        file = mock_upload_file(
            filename="evil.zip", content=zip_bytes
        )

        with caplog.at_level(
            logging.DEBUG, logger="safeuploads.audit"
        ):
            with pytest.raises(Exception):
                await validator.validate_zip_file(file)

        threat_records = [
            r
            for r in caplog.records
            if r.name == "safeuploads.audit"
            and "threat_detected" in r.message
        ]
        assert len(threat_records) >= 1

    @pytest.mark.asyncio
    async def test_zip_bomb_emits_audit_threat(
        self, mock_upload_file, caplog
    ):
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
        with zipfile.ZipFile(
            buf, "w", zipfile.ZIP_DEFLATED
        ) as zf:
            zf.writestr("zeros.bin", data)
        zip_bytes = buf.getvalue()

        file = mock_upload_file(
            filename="bomb.zip", content=zip_bytes
        )

        with caplog.at_level(
            logging.DEBUG, logger="safeuploads.audit"
        ):
            with pytest.raises(Exception):
                await validator.validate_zip_file(file)

        threat_records = [
            r
            for r in caplog.records
            if r.name == "safeuploads.audit"
            and "threat_detected" in r.message
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

        file = mock_upload_file(
            filename="bomb.gz", content=gz_bytes
        )

        with caplog.at_level(
            logging.DEBUG, logger="safeuploads.audit"
        ):
            with pytest.raises(Exception):
                await validator.validate_gzip_file(file)

        threat_records = [
            r
            for r in caplog.records
            if r.name == "safeuploads.audit"
            and "threat_detected" in r.message
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
