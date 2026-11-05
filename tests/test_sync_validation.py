"""Tests for the synchronous FileValidator.validate_*_file_sync API."""

import asyncio
import gzip
import io
import logging
import tempfile
import zipfile
from pathlib import Path

import pytest

from safeuploads.audit import correlation_id_var
from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.exceptions import (
    CompressionSecurityError,
    ContentThreatError,
    ErrorCode,
    ExtensionSecurityError,
    FilenameSecurityError,
    FileProcessingError,
    FileSecurityError,
    FileSignatureError,
    FileSizeError,
    FileValidationError,
    MimeTypeError,
    ResourceLimitError,
    UnicodeSecurityError,
    WindowsReservedNameError,
    XmlSecurityError,
    ZipBombError,
    ZipContentError,
)
from safeuploads.file_validator import FileValidator
from tests.validators.test_fit_validator import build_fit

# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------

_JPEG = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    b"\xff\xd9"
)
_POLYGLOT_JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 9000 + b"PK\x03\x04\xff\xd9"
_GPX = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b"<gpx><trk><trkseg>"
    b'<trkpt lat="0" lon="0"/>'
    b"</trkseg></trk></gpx>"
)
_TCX = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b"<TrainingCenterDatabase><Activities>"
    b'<Activity Sport="Running"></Activity>'
    b"</Activities></TrainingCenterDatabase>"
)
_FIT = build_fit(header_size=14)
_XXE_GPX = (
    b'<?xml version="1.0"?>'
    b"<!DOCTYPE foo ["
    b'<!ENTITY xxe SYSTEM "file:///etc/passwd">'
    b"]>"
    b"<gpx>&xxe;</gpx>"
)
_MALFORMED_GPX = b'<?xml version="1.0"?><gpx><unclosed>'
_GZIP = gzip.compress(b"Hello World")


def _zip_of(files: dict[str, bytes], method: int = zipfile.ZIP_STORED):
    """Build a ZIP archive in memory from a name-to-content map."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=method) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


_ZIP = _zip_of({"a.txt": b"Hello, World!"})
_ZIP_TRAVERSAL = _zip_of({"../../../etc/passwd": b"x"})
_ZIP_BOMB = _zip_of(
    {"zeros.bin": b"\x00" * (1024 * 1024)}, zipfile.ZIP_DEFLATED
)
_GZIP_BOMB = gzip.compress(b"\x00" * (1024 * 1024))

_BOMB_LIMITS = {
    "max_compression_ratio": 5,
    "max_uncompressed_size": 100 * 1024 * 1024,
}

# (method stem, valid filename, valid payload)
_VALID = [
    ("image", "photo.jpg", _JPEG),
    ("zip", "archive.zip", _ZIP),
    ("activity", "track.gpx", _GPX),
    ("activity", "workout.tcx", _TCX),
    ("activity", "ride.fit", _FIT),
    ("gzip", "archive.gz", _GZIP),
]
_VALID_IDS = [f"{stem}-{name}" for stem, name, _ in _VALID]

_STEMS = ["image", "zip", "activity", "gzip"]
_STEM_FILES = {
    "image": ("photo.jpg", _JPEG),
    "zip": ("archive.zip", _ZIP),
    "activity": ("track.gpx", _GPX),
    "gzip": ("archive.gz", _GZIP),
}


def _make_validator(**limits) -> FileValidator:
    """Build a validator whose SecurityLimits use the given overrides."""
    config = FileSecurityConfig()
    config.limits = SecurityLimits(**limits)
    return FileValidator(config=config)


def _run_sync(validator, stem, name, payload) -> str:
    """Call ``validate_<stem>_file_sync`` on an in-memory file."""
    method = getattr(validator, f"validate_{stem}_file_sync")
    return method(io.BytesIO(payload), name)


async def _run_async(validator, mock_upload_file, stem, name, payload):
    """Call ``validate_<stem>_file`` and return the sanitized name."""
    upload = mock_upload_file(name, payload)
    await getattr(validator, f"validate_{stem}_file")(upload)
    return upload.filename


class _SpyFile(io.BytesIO):
    """BytesIO recording whether it was read, seeked or closed."""

    def __init__(self, data: bytes):
        super().__init__(data)
        self.touched = False

    def read(self, size: int = -1, /) -> bytes:
        self.touched = True
        return super().read(size)

    def seek(self, offset: int, whence: int = 0, /) -> int:
        self.touched = True
        return super().seek(offset, whence)


# ---------------------------------------------------------------------------
# Accepted payloads
# ---------------------------------------------------------------------------


class TestSyncAccepts:
    """Valid payloads are accepted and the sanitized name is returned."""

    @pytest.mark.parametrize(
        ("stem", "name", "payload"), _VALID, ids=_VALID_IDS
    )
    def test_valid_payload_returns_filename(self, stem, name, payload):
        """A valid payload returns its (unchanged) filename."""
        assert _run_sync(FileValidator(), stem, name, payload) == name

    def test_returns_sanitized_filename(self):
        """Path components are stripped from the returned name."""
        result = _run_sync(FileValidator(), "image", "../a/photo.jpg", _JPEG)
        assert result == "photo.jpg"

    @pytest.mark.parametrize(
        ("stem", "name", "payload"), _VALID, ids=_VALID_IDS
    )
    def test_position_is_zero_and_file_open_after_success(
        self, stem, name, payload
    ):
        """The caller's file is rewound to 0 and left open."""
        f = io.BytesIO(payload)
        getattr(FileValidator(), f"validate_{stem}_file_sync")(f, name)
        assert f.tell() == 0
        assert not f.closed

    @pytest.mark.parametrize("stem", ["image", "zip"])
    def test_midstream_position_is_validated_from_start(self, stem):
        """A file left at offset 5 is still validated from byte 0."""
        name, payload = _STEM_FILES[stem]
        f = io.BytesIO(payload)
        f.seek(5)
        result = getattr(FileValidator(), f"validate_{stem}_file_sync")(
            f, name
        )
        assert result == name
        assert f.tell() == 0


# ---------------------------------------------------------------------------
# Rejected payloads
# ---------------------------------------------------------------------------


class TestSyncImageRejects:
    """Hostile or invalid images are rejected like the async method."""

    def test_wrong_signature_raises(self):
        """Non-image bytes under a .jpg name fail the MIME check."""
        with pytest.raises(MimeTypeError) as exc_info:
            _run_sync(FileValidator(), "image", "a.jpg", b"not an image!!")
        assert exc_info.value.error_code == ErrorCode.MIME_TYPE_MISMATCH

    def test_polyglot_content_threat_raises(self):
        """A ZIP signature past the header is a content threat."""
        validator = _make_validator(enable_content_analysis=True)
        with pytest.raises(ContentThreatError) as exc_info:
            _run_sync(validator, "image", "poly.jpg", _POLYGLOT_JPEG)
        assert exc_info.value.error_code == ErrorCode.CONTENT_THREAT_DETECTED

    def test_oversize_raises(self):
        """A file over max_image_size raises FILE_TOO_LARGE."""
        validator = _make_validator(max_image_size=1024)
        with pytest.raises(FileSizeError) as exc_info:
            _run_sync(validator, "image", "a.jpg", _JPEG + b"\x00" * 2048)
        assert exc_info.value.error_code == ErrorCode.FILE_TOO_LARGE

    def test_extension_not_allowed_raises(self):
        """A .txt name is not in the allowed image extensions."""
        with pytest.raises(ExtensionSecurityError) as exc_info:
            _run_sync(FileValidator(), "image", "a.txt", _JPEG)
        assert exc_info.value.error_code == ErrorCode.EXTENSION_NOT_ALLOWED


class TestSyncZipRejects:
    """Hostile or invalid archives are rejected."""

    def test_traversal_entry_raises(self):
        """A ../ entry raises ZIP_DIRECTORY_TRAVERSAL."""
        with pytest.raises(ZipContentError) as exc_info:
            _run_sync(FileValidator(), "zip", "a.zip", _ZIP_TRAVERSAL)
        assert exc_info.value.error_code == ErrorCode.ZIP_DIRECTORY_TRAVERSAL

    def test_zip_bomb_raises(self):
        """A highly compressible entry raises ZipBombError."""
        validator = _make_validator(**_BOMB_LIMITS)
        with pytest.raises(ZipBombError) as exc_info:
            _run_sync(validator, "zip", "bomb.zip", _ZIP_BOMB)
        assert (
            exc_info.value.error_code == ErrorCode.COMPRESSION_RATIO_EXCEEDED
        )

    def test_oversize_raises(self):
        """A file over max_zip_size raises FILE_TOO_LARGE."""
        validator = _make_validator(max_zip_size=64)
        with pytest.raises(FileSizeError) as exc_info:
            _run_sync(validator, "zip", "a.zip", _ZIP)
        assert exc_info.value.error_code == ErrorCode.FILE_TOO_LARGE

    def test_non_zip_content_raises(self):
        """Plain text under a .zip name fails the signature check."""
        with pytest.raises(FileSignatureError):
            _run_sync(FileValidator(), "zip", "a.zip", b"Hello World")


class TestSyncActivityRejects:
    """Hostile or invalid activity files are rejected."""

    def test_doctype_gpx_raises(self):
        """A DOCTYPE/XXE GPX raises XML_DTD_FORBIDDEN."""
        with pytest.raises(XmlSecurityError) as exc_info:
            _run_sync(FileValidator(), "activity", "t.gpx", _XXE_GPX)
        assert exc_info.value.error_code == ErrorCode.XML_DTD_FORBIDDEN

    def test_doctype_tcx_raises(self):
        """A DOCTYPE/XXE TCX raises XML_DTD_FORBIDDEN."""
        with pytest.raises(XmlSecurityError) as exc_info:
            _run_sync(FileValidator(), "activity", "t.tcx", _XXE_GPX)
        assert exc_info.value.error_code == ErrorCode.XML_DTD_FORBIDDEN

    def test_malformed_gpx_raises(self):
        """Malformed XML raises XML_MALFORMED."""
        with pytest.raises(XmlSecurityError) as exc_info:
            _run_sync(FileValidator(), "activity", "t.gpx", _MALFORMED_GPX)
        assert exc_info.value.error_code == ErrorCode.XML_MALFORMED

    def test_fit_with_bad_signature_raises(self):
        """Non-FIT bytes under a .fit name fail the signature check."""
        with pytest.raises(FileSignatureError):
            _run_sync(FileValidator(), "activity", "r.fit", b"\x00" * 64)

    def test_oversize_raises(self):
        """A file over max_activity_file_size raises FILE_TOO_LARGE."""
        validator = _make_validator(max_activity_file_size=64)
        with pytest.raises(FileSizeError) as exc_info:
            _run_sync(validator, "activity", "t.gpx", _GPX)
        assert exc_info.value.error_code == ErrorCode.FILE_TOO_LARGE


class TestSyncGzipRejects:
    """Hostile or invalid gzip files are rejected."""

    def test_decompression_bomb_raises(self):
        """A highly compressible stream raises ZipBombError."""
        validator = _make_validator(**_BOMB_LIMITS)
        with pytest.raises(ZipBombError) as exc_info:
            _run_sync(validator, "gzip", "bomb.gz", _GZIP_BOMB)
        assert (
            exc_info.value.error_code == ErrorCode.COMPRESSION_RATIO_EXCEEDED
        )

    def test_oversize_raises(self):
        """A file over max_gzip_size raises FILE_TOO_LARGE."""
        validator = _make_validator(max_gzip_size=1024)
        raw = bytes(range(256)) * 8
        stored = gzip.compress(raw, compresslevel=0)
        with pytest.raises(FileSizeError) as exc_info:
            _run_sync(validator, "gzip", "a.gz", stored)
        assert exc_info.value.error_code == ErrorCode.FILE_TOO_LARGE

    def test_non_gzip_content_raises(self):
        """Plain text under a .gz name fails the signature check."""
        with pytest.raises(FileSignatureError):
            _run_sync(FileValidator(), "gzip", "a.gz", b"Hello World")

    def test_invalid_gzip_structure_is_compression_error(self):
        """A gzip header with a corrupt body is a compression error."""
        corrupt = _GZIP[:10] + b"\xff" * 8
        with pytest.raises(CompressionSecurityError):
            _run_sync(FileValidator(), "gzip", "a.gz", corrupt)


class TestSyncCommonRejects:
    """Rejections shared by all four methods."""

    @pytest.mark.parametrize("stem", _STEMS)
    def test_empty_file_raises(self, stem):
        """An empty file raises FILE_EMPTY."""
        name, _ = _STEM_FILES[stem]
        with pytest.raises(FileSizeError) as exc_info:
            _run_sync(FileValidator(), stem, name, b"")
        assert exc_info.value.error_code == ErrorCode.FILE_EMPTY

    @pytest.mark.parametrize("stem", _STEMS)
    def test_empty_filename_raises(self, stem):
        """An empty filename raises FILENAME_EMPTY."""
        _, payload = _STEM_FILES[stem]
        with pytest.raises(FilenameSecurityError) as exc_info:
            _run_sync(FileValidator(), stem, "", payload)
        assert exc_info.value.error_code == ErrorCode.FILENAME_EMPTY

    @pytest.mark.parametrize("stem", _STEMS)
    def test_windows_reserved_name_raises(self, stem):
        """A reserved device name raises WINDOWS_RESERVED_NAME."""
        name, payload = _STEM_FILES[stem]
        with pytest.raises(WindowsReservedNameError) as exc_info:
            _run_sync(
                FileValidator(), stem, f"CON{Path(name).suffix}", payload
            )
        assert exc_info.value.error_code == ErrorCode.WINDOWS_RESERVED_NAME

    @pytest.mark.parametrize("stem", _STEMS)
    def test_rtl_override_raises(self, stem):
        """A right-to-left override raises UNICODE_DANGEROUS_CHARS."""
        name, payload = _STEM_FILES[stem]
        suffix = Path(name).suffix
        with pytest.raises(UnicodeSecurityError) as exc_info:
            _run_sync(FileValidator(), stem, f"doc‮txt{suffix}", payload)
        assert exc_info.value.error_code == ErrorCode.UNICODE_DANGEROUS_CHARS

    @pytest.mark.parametrize(
        ("stem", "name"),
        [
            ("image", "x.php.jpg"),
            ("zip", "x.php.zip"),
            ("activity", "x.php.gpx"),
            ("gzip", "x.php.gz"),
        ],
    )
    def test_blocked_extension_raises(self, stem, name):
        """A blocked inner extension raises EXTENSION_BLOCKED."""
        _, payload = _STEM_FILES[stem]
        with pytest.raises(ExtensionSecurityError) as exc_info:
            _run_sync(FileValidator(), stem, name, payload)
        assert exc_info.value.error_code == ErrorCode.EXTENSION_BLOCKED


# ---------------------------------------------------------------------------
# Parity with the async API
# ---------------------------------------------------------------------------

_PARITY = [
    *[(stem, name, payload) for stem, name, payload in _VALID],
    ("image", "../a/photo.jpg", _JPEG),
    ("image", "my photo.jpg", _JPEG),
    ("image", "photo.jpg", b"not an image!!"),
    ("image", "photo.jpg", b""),
    ("image", "CON.jpg", _JPEG),
    ("image", "doc‮txt.jpg", _JPEG),
    ("image", "x.php.jpg", _JPEG),
    ("image", "photo.txt", _JPEG),
    ("zip", "t.zip", _ZIP_TRAVERSAL),
    ("zip", "a.zip", b"Hello World"),
    ("zip", "a.zip", b""),
    ("zip", "CON.zip", _ZIP),
    ("activity", "t.gpx", _XXE_GPX),
    ("activity", "t.tcx", _XXE_GPX),
    ("activity", "t.gpx", _MALFORMED_GPX),
    ("activity", "r.fit", b"\x00" * 64),
    ("activity", "t.gpx", b""),
    ("activity", "t.exe", _GPX),
    ("gzip", "a.gz", b"Hello World"),
    ("gzip", "a.gz", b""),
    ("gzip", "a.zip", _GZIP),
    ("gzip", "x.php.gz", _GZIP),
    ("image", "", _JPEG),
    ("zip", "", _ZIP),
    ("activity", "", _GPX),
    ("gzip", "", _GZIP),
]


class TestSyncAsyncParity:
    """Sync and async methods agree on every outcome."""

    @staticmethod
    async def _outcome_async(validator, mock_upload_file, case):
        stem, name, payload = case
        try:
            return (
                "ok",
                await _run_async(
                    validator, mock_upload_file, stem, name, payload
                ),
            )
        except FileSecurityError as exc:
            return (type(exc), getattr(exc, "error_code", None))

    @staticmethod
    def _outcome_sync(validator, case):
        stem, name, payload = case
        try:
            return ("ok", _run_sync(validator, stem, name, payload))
        except FileSecurityError as exc:
            return (type(exc), getattr(exc, "error_code", None))

    @pytest.mark.parametrize("case", _PARITY, ids=lambda c: f"{c[0]}-{c[1]!r}")
    async def test_outcome_matches_async(self, mock_upload_file, case):
        """Same success name or same exception type and error code."""
        validator = FileValidator()
        expected = await self._outcome_async(validator, mock_upload_file, case)
        actual = await asyncio.to_thread(self._outcome_sync, validator, case)
        assert actual == expected

    @pytest.mark.parametrize(
        ("stem", "name", "payload", "limits"),
        [
            (
                "image",
                "poly.jpg",
                _POLYGLOT_JPEG,
                {"enable_content_analysis": True},
            ),
            ("zip", "bomb.zip", _ZIP_BOMB, _BOMB_LIMITS),
            ("gzip", "bomb.gz", _GZIP_BOMB, _BOMB_LIMITS),
            ("zip", "a.zip", _ZIP, {"max_zip_size": 64}),
            ("gzip", "a.gz", _GZIP, {"max_gzip_size": 8}),
        ],
        ids=["polyglot", "zip-bomb", "gzip-bomb", "zip-size", "gzip-size"],
    )
    async def test_limit_outcome_matches_async(
        self, mock_upload_file, stem, name, payload, limits
    ):
        """Custom limits give the same outcome in both APIs."""
        validator = _make_validator(**limits)
        case = (stem, name, payload)
        expected = await self._outcome_async(validator, mock_upload_file, case)
        actual = await asyncio.to_thread(self._outcome_sync, validator, case)
        assert expected[0] != "ok"
        assert actual == expected


# ---------------------------------------------------------------------------
# File objects
# ---------------------------------------------------------------------------


class _ShortReadRaw(io.RawIOBase):
    """Seekable raw stream returning at most 4096 bytes per read."""

    def __init__(self, data: bytes):
        self._buffer = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, offset: int, whence: int = 0, /) -> int:
        return self._buffer.seek(offset, whence)

    def tell(self) -> int:
        return self._buffer.tell()

    def readinto(self, buffer) -> int:
        data = self._buffer.read(min(len(buffer), 4096))
        buffer[: len(data)] = data
        return len(data)


class TestSyncShortReads:
    """Streams that return fewer bytes than asked are read fully."""

    def test_valid_image_accepted(self):
        """A valid image larger than one short read is accepted."""
        validator = _make_validator(enable_content_analysis=True)
        payload = _JPEG[:-2] + b"\x00" * 9000 + b"\xff\xd9"
        f = _ShortReadRaw(payload)
        assert validator.validate_image_file_sync(f, "a.jpg") == "a.jpg"
        assert f.tell() == 0

    def test_polyglot_past_first_read_rejected(self):
        """A ZIP signature past the first short read is still found."""
        validator = _make_validator(enable_content_analysis=True)
        with pytest.raises(ContentThreatError) as exc_info:
            validator.validate_image_file_sync(
                _ShortReadRaw(_POLYGLOT_JPEG), "poly.jpg"
            )
        assert exc_info.value.error_code == ErrorCode.CONTENT_THREAT_DETECTED


class TestSyncFileObjects:
    """Any seekable binary file object works and stays open."""

    @pytest.mark.parametrize("stem", _STEMS)
    def test_open_file_on_disk(self, tmp_path, stem):
        """An open(path, 'rb') file validates and stays open."""
        name, payload = _STEM_FILES[stem]
        path = tmp_path / "upload.bin"
        path.write_bytes(payload)
        with open(path, "rb") as f:
            result = getattr(FileValidator(), f"validate_{stem}_file_sync")(
                f, name
            )
            assert result == name
            assert not f.closed
            assert f.tell() == 0

    @pytest.mark.parametrize("stem", _STEMS)
    def test_spooled_temporary_file(self, stem):
        """A SpooledTemporaryFile validates and stays open."""
        name, payload = _STEM_FILES[stem]
        with tempfile.SpooledTemporaryFile() as f:
            f.write(payload)
            f.seek(0)
            result = getattr(FileValidator(), f"validate_{stem}_file_sync")(
                f, name
            )
            assert result == name
            assert not f.closed
            assert f.tell() == 0

    def test_spooled_file_rolled_to_disk(self):
        """A SpooledTemporaryFile already spilled to disk validates."""
        with tempfile.SpooledTemporaryFile(max_size=4) as f:
            f.write(_ZIP)
            f.seek(0)
            result = FileValidator().validate_zip_file_sync(f, "a.zip")
            assert result == "a.zip"
            assert not f.closed

    @pytest.mark.parametrize("stem", _STEMS)
    def test_file_not_closed_after_failure(self, stem):
        """The caller's file stays open when validation fails."""
        name, _ = _STEM_FILES[stem]
        f = io.BytesIO(b"garbage that is not valid")
        with pytest.raises(FileValidationError):
            getattr(FileValidator(), f"validate_{stem}_file_sync")(f, name)
        assert not f.closed


# ---------------------------------------------------------------------------
# Threading and event loop behavior
# ---------------------------------------------------------------------------


class TestSyncNoOffload:
    """Sync validation runs in the calling thread."""

    @pytest.mark.parametrize(
        ("stem", "name", "payload"), _VALID, ids=_VALID_IDS
    )
    def test_submit_is_never_called(self, monkeypatch, stem, name, payload):
        """_submit is not used; the call still succeeds."""
        validator = FileValidator()

        def _boom(*args, **kwargs):
            raise AssertionError("worker-thread offload used")

        monkeypatch.setattr(validator, "_submit", _boom)
        assert _run_sync(validator, stem, name, payload) == name


class TestSyncRunningLoopGuard:
    """Calling directly on an event loop thread is refused."""

    @pytest.mark.parametrize("stem", _STEMS)
    async def test_raises_runtime_error_inside_coroutine(self, stem):
        """RuntimeError names the async counterpart; file untouched."""
        name, payload = _STEM_FILES[stem]
        f = _SpyFile(payload)
        f.seek(3)
        f.touched = False
        validator = FileValidator()
        with pytest.raises(RuntimeError, match=f"validate_{stem}_file"):
            getattr(validator, f"validate_{stem}_file_sync")(f, name)
        assert not f.touched
        assert f.tell() == 3

    @pytest.mark.parametrize("stem", _STEMS)
    async def test_to_thread_works_inside_coroutine(self, stem):
        """asyncio.to_thread runs the sync call without a loop."""
        name, payload = _STEM_FILES[stem]
        validator = FileValidator()
        method = getattr(validator, f"validate_{stem}_file_sync")
        result = await asyncio.to_thread(method, io.BytesIO(payload), name)
        assert result == name


# ---------------------------------------------------------------------------
# Audit, correlation id, resource limits, internal errors
# ---------------------------------------------------------------------------


def _audit_types(caplog) -> list[str]:
    """Return the audit event types logged, in order."""
    return [
        r.audit_event_type
        for r in caplog.records
        if r.name == "safeuploads.audit"
    ]


class TestSyncAudit:
    """Sync validation emits the same audit events as async."""

    @pytest.mark.parametrize(
        ("stem", "name", "payload"), _VALID, ids=_VALID_IDS
    )
    def test_success_emits_start_then_success(
        self, caplog, stem, name, payload
    ):
        """A valid file logs validation_start, validation_success."""
        validator = _make_validator(enable_audit_logging=True)
        with caplog.at_level(logging.DEBUG, logger="safeuploads.audit"):
            _run_sync(validator, stem, name, payload)
        assert _audit_types(caplog) == [
            "validation_start",
            "validation_success",
        ]
        records = [r for r in caplog.records if r.name == "safeuploads.audit"]
        assert (
            records[0].audit_correlation_id == records[1].audit_correlation_id
        )

    @pytest.mark.parametrize("stem", _STEMS)
    def test_failure_emits_start_then_failure(self, caplog, stem):
        """A rejected file logs validation_start, validation_failure."""
        name, _ = _STEM_FILES[stem]
        validator = _make_validator(enable_audit_logging=True)
        with (
            caplog.at_level(logging.DEBUG, logger="safeuploads.audit"),
            pytest.raises(FileSizeError),
        ):
            _run_sync(validator, stem, name, b"")
        assert _audit_types(caplog) == [
            "validation_start",
            "validation_failure",
        ]

    def test_empty_filename_emits_start_then_failure(self, caplog):
        """An empty filename still yields exactly one terminal event."""
        validator = _make_validator(enable_audit_logging=True)
        with (
            caplog.at_level(logging.DEBUG, logger="safeuploads.audit"),
            pytest.raises(FilenameSecurityError),
        ):
            validator.validate_image_file_sync(io.BytesIO(_JPEG), "")
        assert _audit_types(caplog) == [
            "validation_start",
            "validation_failure",
        ]

    def test_disabled_audit_emits_nothing(self, caplog):
        """No audit records are logged when auditing is off."""
        with caplog.at_level(logging.DEBUG, logger="safeuploads.audit"):
            _run_sync(FileValidator(), "image", "photo.jpg", _JPEG)
        assert _audit_types(caplog) == []

    def test_events_match_async(self, caplog, mock_upload_file):
        """Sync and async log the same event sequence on success."""
        validator = _make_validator(enable_audit_logging=True)
        with caplog.at_level(logging.DEBUG, logger="safeuploads.audit"):
            asyncio.run(
                _run_async(validator, mock_upload_file, "zip", "t.zip", _ZIP)
            )
            _run_sync(validator, "zip", "t.zip", _ZIP)
        types = _audit_types(caplog)
        assert types == ["validation_start", "validation_success"] * 2


class TestSyncCorrelationId:
    """The correlation id is restored after every call."""

    @pytest.mark.parametrize("previous", [None, "outer-id"])
    def test_restored_after_success(self, previous):
        """The previous id is back after a successful call."""
        token = correlation_id_var.set(previous)
        try:
            _run_sync(FileValidator(), "image", "photo.jpg", _JPEG)
            assert correlation_id_var.get() == previous
        finally:
            correlation_id_var.reset(token)

    @pytest.mark.parametrize("previous", [None, "outer-id"])
    def test_restored_after_failure(self, previous):
        """The previous id is back after a rejected call."""
        token = correlation_id_var.set(previous)
        try:
            with pytest.raises(FileSizeError):
                _run_sync(FileValidator(), "image", "photo.jpg", b"")
            assert correlation_id_var.get() == previous
        finally:
            correlation_id_var.reset(token)

    def test_caller_id_is_used_in_audit(self, caplog):
        """A caller-bound id appears on the audit records."""
        validator = _make_validator(enable_audit_logging=True)
        token = correlation_id_var.set("outer-id")
        try:
            with caplog.at_level(logging.DEBUG, logger="safeuploads.audit"):
                _run_sync(validator, "image", "photo.jpg", _JPEG)
        finally:
            correlation_id_var.reset(token)
        ids = {
            r.audit_correlation_id
            for r in caplog.records
            if r.name == "safeuploads.audit"
        }
        assert ids == {"outer-id"}


class TestSyncResourceLimits:
    """ResourceMonitor limits apply to the sync path."""

    _HOSTILE_STEP = 5.0
    _BENIGN_STEP = 0.01

    def _many_entries_zip(self) -> bytes:
        return _zip_of({f"f{i}.txt": b"data" for i in range(50)})

    def test_zip_over_time_budget_raises(self, fake_clock, caplog):
        """A slow inspection raises RESOURCE_TIME_EXCEEDED."""
        validator = _make_validator(enable_audit_logging=True)
        fake_clock.step = self._HOSTILE_STEP
        fake_clock.advancing = True
        with (
            caplog.at_level(logging.INFO, logger="safeuploads.audit"),
            pytest.raises(ResourceLimitError) as exc_info,
        ):
            _run_sync(validator, "zip", "a.zip", self._many_entries_zip())
        assert type(exc_info.value) is ResourceLimitError
        assert exc_info.value.error_code == ErrorCode.RESOURCE_TIME_EXCEEDED
        assert _audit_types(caplog) == ["validation_start", "resource_limit"]

    def test_zip_within_budget_passes(self, fake_clock):
        """A fast inspection stays inside the budget."""
        fake_clock.step = self._BENIGN_STEP
        fake_clock.advancing = True
        result = _run_sync(
            FileValidator(), "zip", "a.zip", self._many_entries_zip()
        )
        assert result == "a.zip"


class TestSyncInternalErrors:
    """Unexpected exceptions are wrapped like in the async API."""

    @pytest.mark.parametrize("stem", _STEMS)
    def test_unexpected_error_wrapped(self, monkeypatch, caplog, stem):
        """A KeyError from an inner validator becomes FileProcessingError."""
        name, payload = _STEM_FILES[stem]
        validator = _make_validator(enable_audit_logging=True)

        def _explode(*args, **kwargs):
            raise KeyError("boom")

        monkeypatch.setattr(
            validator.signature_validator, "validate", _explode
        )
        with (
            caplog.at_level(logging.DEBUG, logger="safeuploads.audit"),
            pytest.raises(FileProcessingError) as exc_info,
        ):
            _run_sync(validator, stem, name, payload)
        assert type(exc_info.value) is FileProcessingError
        assert isinstance(exc_info.value.__cause__, KeyError)
        assert _audit_types(caplog) == [
            "validation_start",
            "validation_failure",
        ]

    def test_filename_internal_error_wrapped(self, monkeypatch):
        """An unexpected error while sanitizing is wrapped too."""
        validator = FileValidator()

        def _explode(*args, **kwargs):
            raise KeyError("boom")

        monkeypatch.setattr(
            validator.unicode_validator, "validate_unicode_security", _explode
        )
        with pytest.raises(FileProcessingError):
            _run_sync(validator, "image", "photo.jpg", _JPEG)
