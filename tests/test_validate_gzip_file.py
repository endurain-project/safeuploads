"""Integration tests for FileValidator.validate_gzip_file."""

import gzip
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
    ZipBombError,
)
from safeuploads.file_validator import FileValidator

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_GZIP = gzip.compress(b"Hello World")


class TestValidateGzipFileHappyPath:
    """Tests for valid gzip files that should pass validation."""

    async def test_validate_gzip_file_valid_gzip_passes(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("archive.gz", _VALID_GZIP)
        await validator.validate_gzip_file(f)


class TestValidateGzipFileFilenameErrors:
    """Tests for filename validation failures."""

    async def test_validate_gzip_file_none_filename_raises(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file(None, _VALID_GZIP)
        with pytest.raises(FilenameSecurityError):
            await validator.validate_gzip_file(f)


class TestValidateGzipFileExtensionErrors:
    """Tests for disallowed file extensions."""

    async def test_validate_gzip_file_zip_extension_raises(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("archive.zip", _VALID_GZIP)
        with pytest.raises(ExtensionSecurityError):
            await validator.validate_gzip_file(f)


class TestValidateGzipFileSizeErrors:
    """Tests for file size validation failures."""

    async def test_validate_gzip_file_empty_file_raises(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("archive.gz", b"", size=0)
        with pytest.raises(FileSizeError):
            await validator.validate_gzip_file(f)

    async def test_validate_gzip_file_exceeds_max_size_raises(
        self, mock_upload_file
    ):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(max_gzip_size=1024)
        validator = FileValidator(config=config)
        # Use compresslevel=0 (store) so compressed size ≈ raw size
        # 2048 bytes raw → ~2080 bytes stored gzip > 1024 byte limit
        raw = bytes(range(256)) * 8  # 2048 bytes
        oversized = gzip.compress(raw, compresslevel=0)
        f = mock_upload_file("archive.gz", oversized)
        with pytest.raises(FileSizeError):
            await validator.validate_gzip_file(f)


class TestValidateGzipFileMimeErrors:
    """Tests for MIME type validation failures."""

    async def test_validate_gzip_file_wrong_mime_raises(
        self, mock_upload_file, monkeypatch
    ):
        validator = FileValidator()
        monkeypatch.setattr(
            validator,
            "_detect_mime_type",
            lambda content, filename: "text/plain",
        )
        f = mock_upload_file("archive.gz", _VALID_GZIP)
        with pytest.raises(MimeTypeError):
            await validator.validate_gzip_file(f)


class TestValidateGzipFileSignatureErrors:
    """Tests for gzip signature validation failures."""

    async def test_validate_gzip_file_non_gzip_content_raises(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("archive.gz", b"Hello World")
        with pytest.raises(FileSignatureError):
            await validator.validate_gzip_file(f)


class TestValidateGzipFileDecompressionBomb:
    """Tests for decompression bomb detection."""

    async def test_validate_gzip_file_bomb_raises_zip_bomb_error(
        self, mock_upload_file
    ):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(max_compression_ratio=5)
        validator = FileValidator(config=config)
        # 1MB of zeros compresses to ~1KB — ratio far exceeds 5
        bomb = gzip.compress(b"\x00" * 1024 * 1024)
        f = mock_upload_file("archive.gz", bomb)
        with pytest.raises(ZipBombError):
            await validator.validate_gzip_file(f)


class TestValidateGzipFileExceptionWrapping:
    """Tests that unexpected errors are wrapped in FileProcessingError."""

    async def test_validate_gzip_file_runtime_error_wrapped(
        self, mock_upload_file, monkeypatch
    ):
        validator = FileValidator()

        async def _raise_runtime(*_args, **_kwargs):
            raise RuntimeError("unexpected failure")

        monkeypatch.setattr(
            validator, "_stream_to_temp_file", _raise_runtime
        )
        f = mock_upload_file("archive.gz", _VALID_GZIP)
        with pytest.raises(FileProcessingError):
            await validator.validate_gzip_file(f)


class TestValidateGzipFileAuditEvents:
    """Tests for audit event emission and correlation ID handling."""

    async def test_validate_gzip_file_success_emits_audit_events(
        self, mock_upload_file, caplog
    ):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(enable_audit_logging=True)
        validator = FileValidator(config=config)
        f = mock_upload_file("archive.gz", _VALID_GZIP)
        with caplog.at_level(
            logging.INFO, logger="safeuploads.audit"
        ):
            await validator.validate_gzip_file(f)

        audit_msgs = [
            r.getMessage()
            for r in caplog.records
            if r.name == "safeuploads.audit"
        ]
        assert any("validation_start" in m for m in audit_msgs)
        assert any("validation_success" in m for m in audit_msgs)

    async def test_validate_gzip_file_failure_emits_audit_events(
        self, mock_upload_file, caplog
    ):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(enable_audit_logging=True)
        validator = FileValidator(config=config)
        f = mock_upload_file(None, _VALID_GZIP)
        with caplog.at_level(
            logging.WARNING, logger="safeuploads.audit"
        ):
            with pytest.raises(FilenameSecurityError):
                await validator.validate_gzip_file(f)

        audit_msgs = [
            r.getMessage()
            for r in caplog.records
            if r.name == "safeuploads.audit"
        ]
        assert any("validation_failure" in m for m in audit_msgs)

    async def test_validate_gzip_file_correlation_id_reset_success(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file("archive.gz", _VALID_GZIP)
        await validator.validate_gzip_file(f)
        assert get_correlation_id() is None

    async def test_validate_gzip_file_correlation_id_reset_failure(
        self, mock_upload_file
    ):
        validator = FileValidator()
        f = mock_upload_file(None, _VALID_GZIP)
        with pytest.raises(FilenameSecurityError):
            await validator.validate_gzip_file(f)
        assert get_correlation_id() is None


class TestValidateGzipFileOctetStream:
    """Tests for application/octet-stream MIME handling."""

    async def test_validate_gzip_file_octet_stream_mime_passes(
        self, mock_upload_file, monkeypatch
    ):
        validator = FileValidator()
        monkeypatch.setattr(
            validator,
            "_detect_mime_type",
            lambda content, filename: "application/octet-stream",
        )
        f = mock_upload_file("archive.gz", _VALID_GZIP)
        await validator.validate_gzip_file(f)


class TestValidateGzipFileResourceLimit:
    """Tests for resource monitor enforcement."""

    async def test_validate_gzip_file_resource_limit_raises(
        self, mock_upload_file
    ):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            max_validation_time_seconds=-1.0
        )
        validator = FileValidator(config=config)
        f = mock_upload_file("archive.gz", _VALID_GZIP)
        with pytest.raises(ResourceLimitError):
            await validator.validate_gzip_file(f)
