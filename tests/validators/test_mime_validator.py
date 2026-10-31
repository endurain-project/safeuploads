"""Tests for MIME type validator."""

import pytest

import safeuploads.validators.mime_validator as _mv
from safeuploads.config import FileSecurityConfig
from safeuploads.exceptions import ErrorCode, MimeTypeError
from safeuploads.validators.mime_validator import MimeTypeValidator


def _break_magic_init(monkeypatch) -> None:
    """
    Make ``magic.Magic`` fail so libmagic cannot initialise.

    Args:
        monkeypatch: pytest monkeypatch fixture.
    """

    def _fail(**_):
        raise Exception("python-magic unavailable")

    monkeypatch.setattr(_mv.magic, "Magic", _fail)


class TestDetect:
    """Test MIME type detection."""

    def test_detect_mime_with_magic_available(self, valid_jpeg_bytes):
        """Test MIME detection when python-magic is available."""
        validator = MimeTypeValidator(FileSecurityConfig())

        mime_type = validator.detect(valid_jpeg_bytes, "photo.jpg")

        assert mime_type == "image/jpeg"

    def test_detect_mime_magic_unavailable_rejects(self):
        """Test detection fails closed when libmagic is unavailable."""
        validator = MimeTypeValidator(FileSecurityConfig())
        validator.magic_available = False

        with pytest.raises(MimeTypeError) as exc_info:
            validator.detect(b"fake content", "document.pdf")

        assert exc_info.value.error_code == ErrorCode.MIME_DETECTION_FAILED
        assert exc_info.value.filename == "document.pdf"

    def test_detect_mime_empty_result_rejects(self, monkeypatch):
        """Test an empty magic result is rejected, not guessed."""
        validator = MimeTypeValidator(FileSecurityConfig())
        monkeypatch.setattr(
            validator.magic_mime, "from_buffer", lambda _content: ""
        )

        with pytest.raises(MimeTypeError) as exc_info:
            validator.detect(b"fake", "photo.jpg")

        assert exc_info.value.error_code == ErrorCode.MIME_DETECTION_FAILED

    def test_init_failure_detect_rejects(self, monkeypatch, valid_jpeg_bytes):
        """
        Test detection rejects instead of guessing from the filename.

        Args:
            monkeypatch: pytest monkeypatch fixture.
            valid_jpeg_bytes: Valid JPEG bytes fixture.
        """
        _break_magic_init(monkeypatch)
        validator = MimeTypeValidator(FileSecurityConfig())
        assert validator.magic_available is False
        with pytest.raises(MimeTypeError) as exc_info:
            validator.detect(valid_jpeg_bytes, "photo.jpg")
        assert exc_info.value.error_code == ErrorCode.MIME_DETECTION_FAILED


class TestDetectMagicException:
    """Tests for detect when magic raises."""

    def test_magic_from_buffer_exception_rejects(
        self, monkeypatch, valid_jpeg_bytes
    ):
        """
        Test detection rejects when magic.from_buffer raises.

        Args:
            monkeypatch: pytest monkeypatch fixture.
            valid_jpeg_bytes: Valid JPEG bytes fixture.
        """
        validator = MimeTypeValidator(FileSecurityConfig())
        assert validator.magic_available is True

        def _explode(_content):
            raise RuntimeError("secret internal detail")

        monkeypatch.setattr(validator.magic_mime, "from_buffer", _explode)

        with pytest.raises(MimeTypeError) as exc_info:
            validator.detect(valid_jpeg_bytes, "photo.jpg")

        assert exc_info.value.error_code == ErrorCode.MIME_DETECTION_FAILED
        assert "secret internal detail" not in str(exc_info.value)
        assert isinstance(exc_info.value.__cause__, RuntimeError)


class TestEnforce:
    """Tests for the allowed-MIME check."""

    def test_enforce_mime_allows_permitted_type(self):
        """Permitted MIME types pass without raising."""
        validator = MimeTypeValidator(FileSecurityConfig())
        validator.enforce(
            "application/zip",
            validator.config.ALLOWED_ZIP_MIMES,
            "a.zip",
        )

    def test_enforce_mime_allows_octet_stream_when_enabled(self):
        """octet-stream is accepted only when explicitly allowed."""
        validator = MimeTypeValidator(FileSecurityConfig())
        validator.enforce(
            "application/octet-stream",
            validator.config.ALLOWED_ZIP_MIMES,
            "a.zip",
            allow_octet_stream=True,
        )

    def test_enforce_mime_rejects_octet_stream_by_default(self):
        """octet-stream is rejected when not explicitly allowed."""
        validator = MimeTypeValidator(FileSecurityConfig())
        with pytest.raises(MimeTypeError) as exc_info:
            validator.enforce(
                "application/octet-stream",
                validator.config.ALLOWED_ZIP_MIMES,
                "a.zip",
            )
        assert exc_info.value.error_code == ErrorCode.MIME_TYPE_INVALID

    def test_enforce_mime_wires_mismatch_error_code(self):
        """A disallowed MIME type raises with the supplied code."""
        validator = MimeTypeValidator(FileSecurityConfig())
        with pytest.raises(MimeTypeError) as exc_info:
            validator.enforce(
                "text/plain",
                validator.config.ALLOWED_ZIP_MIMES,
                "a.zip",
                error_code=ErrorCode.MIME_TYPE_MISMATCH,
            )
        assert exc_info.value.error_code == ErrorCode.MIME_TYPE_MISMATCH
