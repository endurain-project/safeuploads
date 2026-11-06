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
    """Tests for the allowed-MIME and extension-match check."""

    def test_enforce_mime_allows_permitted_pair(self):
        """A permitted MIME type with one of its extensions passes."""
        validator = MimeTypeValidator(FileSecurityConfig())
        validator.enforce(
            "application/zip",
            validator.config.ALLOWED_ZIP_TYPES,
            "a.zip",
        )

    @pytest.mark.parametrize("name", ["a.jpg", "a.jpeg", "A.JPG"])
    def test_enforce_accepts_every_listed_extension(self, name):
        """Each extension listed for the MIME type passes, any case."""
        validator = MimeTypeValidator(FileSecurityConfig())
        validator.enforce(
            "image/jpeg", validator.config.ALLOWED_IMAGE_TYPES, name
        )

    def test_enforce_mime_allows_octet_stream_when_enabled(self):
        """octet-stream is accepted only when explicitly allowed."""
        validator = MimeTypeValidator(FileSecurityConfig())
        validator.enforce(
            "application/octet-stream",
            validator.config.ALLOWED_ZIP_TYPES,
            "a.zip",
            allow_octet_stream=True,
        )

    def test_enforce_mime_rejects_octet_stream_by_default(self):
        """octet-stream is rejected when not explicitly allowed."""
        validator = MimeTypeValidator(FileSecurityConfig())
        with pytest.raises(MimeTypeError) as exc_info:
            validator.enforce(
                "application/octet-stream",
                validator.config.ALLOWED_ZIP_TYPES,
                "a.zip",
            )
        assert exc_info.value.error_code == ErrorCode.MIME_TYPE_INVALID

    def test_enforce_mime_wires_mismatch_error_code(self):
        """A disallowed MIME type raises with the supplied code."""
        validator = MimeTypeValidator(FileSecurityConfig())
        with pytest.raises(MimeTypeError) as exc_info:
            validator.enforce(
                "text/plain",
                validator.config.ALLOWED_ZIP_TYPES,
                "a.zip",
                error_code=ErrorCode.MIME_TYPE_MISMATCH,
            )
        assert exc_info.value.error_code == ErrorCode.MIME_TYPE_MISMATCH
        assert exc_info.value.detected_mime == "text/plain"
        assert sorted(exc_info.value.allowed_mimes) == sorted(
            validator.config.ALLOWED_ZIP_TYPES
        )

    @pytest.mark.parametrize(
        ("detected", "name", "allowed"),
        [
            ("image/webp", "a.jpg", ["image/jpeg"]),
            ("image/png", "a.jpeg", ["image/jpeg"]),
            ("image/jpeg", "a.png", ["image/png"]),
            ("image/png", "a.webp", ["image/webp"]),
        ],
    )
    def test_enforce_rejects_extension_of_another_type(
        self, detected, name, allowed
    ):
        """Content of one allowed type under another's extension fails."""
        validator = MimeTypeValidator(FileSecurityConfig())
        with pytest.raises(MimeTypeError) as exc_info:
            validator.enforce(
                detected,
                validator.config.ALLOWED_IMAGE_TYPES,
                name,
                error_code=ErrorCode.MIME_TYPE_MISMATCH,
            )
        assert exc_info.value.error_code == ErrorCode.EXTENSION_MIME_MISMATCH
        assert exc_info.value.detected_mime == detected
        assert exc_info.value.allowed_mimes == allowed
        assert exc_info.value.filename == name

    @pytest.mark.parametrize(
        ("detected", "name"),
        [
            ("text/xml", "ride.fit"),
            ("application/octet-stream", "track.gpx"),
            ("application/octet-stream", "workout.tcx"),
        ],
    )
    def test_enforce_rejects_activity_mismatch(self, detected, name):
        """XML under .fit, or binary under .gpx/.tcx, fails."""
        validator = MimeTypeValidator(FileSecurityConfig())
        with pytest.raises(MimeTypeError) as exc_info:
            validator.enforce(
                detected, validator.config.ALLOWED_ACTIVITY_TYPES, name
            )
        assert exc_info.value.error_code == ErrorCode.EXTENSION_MIME_MISMATCH

    def test_enforce_octet_stream_allowance_still_checks_extension(self):
        """Allowed octet-stream still needs an allowed extension."""
        validator = MimeTypeValidator(FileSecurityConfig())
        with pytest.raises(MimeTypeError) as exc_info:
            validator.enforce(
                "application/octet-stream",
                validator.config.ALLOWED_ZIP_TYPES,
                "a.gz",
                allow_octet_stream=True,
            )
        assert exc_info.value.error_code == ErrorCode.EXTENSION_MIME_MISMATCH
        assert exc_info.value.allowed_mimes == []
