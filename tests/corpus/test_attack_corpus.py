"""
Traceability corpus: every attack the threat model claims to stop.

Each sample is a named, deterministically constructed file rather
than a checked-in binary, so the repository carries no payload that
an antivirus scanner would quarantine. Samples are structural — a
traversal entry name, a compression ratio, an XML entity — not
functional malware.

Adding a threat to ``docs/security/threat-model.md`` without adding
it here should be treated as an incomplete change.
"""

import gzip
import io
import os
import zipfile
from dataclasses import dataclass

import pytest

from safeuploads import (
    CompressionSecurityError,
    ErrorCode,
    ExtensionSecurityError,
    FileProcessingError,
    FileSecurityConfig,
    FileSizeError,
    FileValidator,
    ImageSecurityError,
    MimeTypeError,
    SecurityLimits,
    UnicodeSecurityError,
    WindowsReservedNameError,
    ZipBombError,
    ZipContentError,
)
from tests.conftest import (
    JPEG_SOF0,
    PE_EXECUTABLE,
    ZIP_LOCAL_HEADER,
    entropy_bytes,
)

# ----------------------------------------------------------------
# Builders
# ----------------------------------------------------------------


def _png(width: int, height: int) -> bytes:
    """Build a PNG header declaring the given dimensions."""
    return (
        b"\x89PNG\r\n\x1a\n"
        + b"\x00\x00\x00\x0d"
        + b"IHDR"
        + width.to_bytes(4, "big")
        + height.to_bytes(4, "big")
        + b"\x08\x02\x00\x00\x00"
        + b"\x00\x00\x00\x00"
    )


def _jpeg(extra: bytes = b"") -> bytes:
    """Build a structurally valid JPEG with optional trailing bytes."""
    return b"\xff\xd8" + JPEG_SOF0 + extra + b"\xff\xd9"


def _zip(
    files: dict[str, bytes],
    compression: int = zipfile.ZIP_STORED,
) -> bytes:
    """Build a ZIP archive from a name-to-content mapping."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buffer.getvalue()


def _zip_with_symlink() -> bytes:
    """Build a ZIP whose single entry is a symbolic link."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.external_attr = 0o120777 << 16
        zf.writestr(info, "/etc/passwd")
    return buffer.getvalue()


def _gpx(body: bytes = b"<trk/>") -> bytes:
    """Build a minimal GPX document."""
    return b'<?xml version="1.0"?><gpx>' + body + b"</gpx>"


def _assert_cannot_escape(name: str) -> None:
    """Assert a sanitized name stays inside its upload directory."""
    assert "/" not in name
    assert "\\" not in name
    assert os.path.basename(name) == name

    resolved = os.path.normpath(os.path.join("/srv/uploads", name))
    assert resolved.startswith("/srv/uploads/")


# ----------------------------------------------------------------
# Corpus
# ----------------------------------------------------------------


@dataclass(frozen=True)
class AttackSample:
    """
    A single attack and the rejection it must produce.

    Attributes:
        name: Threat name, matching the threat model.
        filename: Name the file is uploaded under.
        content: Raw bytes of the upload.
        method: ``FileValidator`` method under test.
        expected: Exception type the upload must raise.
        error_code: Machine-readable code the error must carry.
        limits: Optional limits needed to exercise the attack.
    """

    name: str
    filename: str
    content: bytes
    method: str
    expected: type[Exception]
    error_code: str | None = None
    limits: SecurityLimits | None = None


_CONTENT_ANALYSIS = SecurityLimits(enable_content_analysis=True)

# Nesting is off by default, so an archive-in-archive is rejected
# outright; these limits reach the recursive path instead.
_NESTED_ALLOWED = SecurityLimits(allow_nested_archives=True)

REJECTED: tuple[AttackSample, ...] = (
    # --- Filename attacks ---
    AttackSample(
        name="rtl-override-extension-spoof",
        filename="photo\u202egpj.exe",
        content=_jpeg(),
        method="validate_image_file",
        expected=UnicodeSecurityError,
        error_code=ErrorCode.UNICODE_DANGEROUS_CHARS,
    ),
    AttackSample(
        name="zero-width-joiner-filename",
        filename="photo\u200d.jpg",
        content=_jpeg(),
        method="validate_image_file",
        expected=UnicodeSecurityError,
        error_code=ErrorCode.UNICODE_DANGEROUS_CHARS,
    ),
    AttackSample(
        name="windows-reserved-device-name",
        filename="CON.jpg",
        content=_jpeg(),
        method="validate_image_file",
        expected=WindowsReservedNameError,
        error_code=ErrorCode.WINDOWS_RESERVED_NAME,
    ),
    AttackSample(
        name="double-extension-php",
        filename="photo.php.jpg",
        content=_jpeg(),
        method="validate_image_file",
        expected=ExtensionSecurityError,
        error_code=ErrorCode.EXTENSION_BLOCKED,
    ),
    AttackSample(
        name="disallowed-extension",
        filename="photo.txt",
        content=_jpeg(),
        method="validate_image_file",
        expected=ExtensionSecurityError,
        error_code=ErrorCode.EXTENSION_NOT_ALLOWED,
    ),
    # --- Content / type confusion ---
    AttackSample(
        name="gif-masquerading-as-jpeg",
        filename="photo.jpg",
        content=b"GIF89a" + b"\x00" * 64,
        method="validate_image_file",
        expected=MimeTypeError,
    ),
    AttackSample(
        name="empty-upload",
        filename="photo.jpg",
        content=b"",
        method="validate_image_file",
        expected=FileSizeError,
        error_code=ErrorCode.FILE_EMPTY,
    ),
    AttackSample(
        name="oversized-upload",
        filename="photo.jpg",
        content=_jpeg(b"\x00" * 4096),
        method="validate_image_file",
        expected=FileSizeError,
        error_code=ErrorCode.FILE_TOO_LARGE,
        limits=SecurityLimits(max_image_size=1024),
    ),
    # --- Image decompression bombs ---
    AttackSample(
        name="png-pixel-bomb",
        filename="bomb.png",
        content=_png(30000, 30000),
        method="validate_image_file",
        expected=ImageSecurityError,
        error_code=ErrorCode.IMAGE_DIMENSIONS_EXCEEDED,
    ),
    AttackSample(
        name="jpeg-without-frame-header",
        filename="headerless.jpg",
        content=b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00"
        b"\x00\x01\x00\x01\x00\x00\xff\xd9",
        method="validate_image_file",
        expected=ImageSecurityError,
        error_code=ErrorCode.IMAGE_DIMENSIONS_UNREADABLE,
    ),
    # --- Polyglot and embedded executables ---
    AttackSample(
        name="gifar-polyglot",
        filename="poly.jpg",
        content=_jpeg(b"\x00" * 64 + ZIP_LOCAL_HEADER),
        method="validate_image_file",
        expected=FileProcessingError,
        limits=_CONTENT_ANALYSIS,
    ),
    AttackSample(
        name="pe-header-embedded-in-image",
        filename="dropper.jpg",
        content=_jpeg(b"\x00" * 64 + PE_EXECUTABLE),
        method="validate_image_file",
        expected=FileProcessingError,
        limits=_CONTENT_ANALYSIS,
    ),
    # --- Compression attacks ---
    AttackSample(
        name="zip-bomb-compression-ratio",
        filename="bomb.zip",
        content=_zip({"big.txt": b"\x00" * 2_000_000}, zipfile.ZIP_DEFLATED),
        method="validate_zip_file",
        expected=ZipBombError,
        error_code=ErrorCode.COMPRESSION_RATIO_EXCEEDED,
    ),
    AttackSample(
        name="zip-slip-traversal-entry",
        filename="slip.zip",
        content=_zip({"../../etc/passwd": b"root:x:0:0"}),
        method="validate_zip_file",
        expected=ZipContentError,
        error_code=ErrorCode.ZIP_CONTENT_THREAT,
    ),
    AttackSample(
        name="zip-absolute-path-entry",
        filename="abs.zip",
        content=_zip({"/etc/shadow": b"secret"}),
        method="validate_zip_file",
        expected=ZipContentError,
        error_code=ErrorCode.ZIP_CONTENT_THREAT,
    ),
    AttackSample(
        name="zip-symlink-entry",
        filename="link.zip",
        content=_zip_with_symlink(),
        method="validate_zip_file",
        expected=ZipContentError,
        error_code=ErrorCode.ZIP_CONTENT_THREAT,
    ),
    AttackSample(
        name="zip-webshell-entry-extension",
        filename="shell.zip",
        content=_zip({"invoice.php.txt": b"harmless looking text"}),
        method="validate_zip_file",
        expected=ZipContentError,
        error_code=ErrorCode.ZIP_CONTENT_THREAT,
    ),
    AttackSample(
        name="zip-nested-archive",
        filename="nested.zip",
        content=_zip({"inner.zip": _zip({"a.txt": b"a"})}),
        method="validate_zip_file",
        expected=CompressionSecurityError,
        error_code=ErrorCode.ZIP_NESTED_ARCHIVE,
    ),
    # Nesting must not be a way to smuggle an entry past the
    # checks the outermost archive is subjected to.
    AttackSample(
        name="zip-slip-smuggled-in-nested-archive",
        filename="nested-slip.zip",
        content=_zip({"inner.zip": _zip({"../../etc/passwd": b"root:x:0:0"})}),
        method="validate_zip_file",
        expected=ZipContentError,
        error_code=ErrorCode.ZIP_CONTENT_THREAT,
        limits=_NESTED_ALLOWED,
    ),
    AttackSample(
        name="webshell-smuggled-in-nested-archive",
        filename="nested-shell.zip",
        content=_zip({"inner.zip": _zip({"invoice.php.txt": b"text"})}),
        method="validate_zip_file",
        expected=ZipContentError,
        error_code=ErrorCode.ZIP_CONTENT_THREAT,
        limits=_NESTED_ALLOWED,
    ),
    AttackSample(
        name="symlink-smuggled-in-nested-archive",
        filename="nested-link.zip",
        content=_zip({"inner.zip": _zip_with_symlink()}),
        method="validate_zip_file",
        expected=ZipContentError,
        error_code=ErrorCode.ZIP_CONTENT_THREAT,
        limits=_NESTED_ALLOWED,
    ),
    AttackSample(
        name="gzip-decompression-bomb",
        filename="bomb.gz",
        content=gzip.compress(b"\x00" * 2_000_000),
        method="validate_gzip_file",
        expected=ZipBombError,
        error_code=ErrorCode.COMPRESSION_RATIO_EXCEEDED,
    ),
    # --- XML attacks ---
    AttackSample(
        name="xxe-external-entity",
        filename="track.gpx",
        content=b'<?xml version="1.0"?>'
        b'<!DOCTYPE gpx [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        b"<gpx>&xxe;</gpx>",
        method="validate_activity_file",
        expected=FileProcessingError,
        error_code=ErrorCode.XML_FORBIDDEN_CONSTRUCT,
    ),
    AttackSample(
        name="billion-laughs",
        filename="track.gpx",
        content=b'<?xml version="1.0"?>'
        b"<!DOCTYPE gpx ["
        b'<!ENTITY lol "lol">'
        b'<!ENTITY lol2 "&lol;&lol;&lol;">'
        b"]>"
        b"<gpx>&lol2;</gpx>",
        method="validate_activity_file",
        expected=FileProcessingError,
        error_code=ErrorCode.XML_FORBIDDEN_CONSTRUCT,
    ),
    AttackSample(
        name="html-payload-behind-gpx-extension",
        filename="track.gpx",
        content=b'<?xml version="1.0"?>'
        b"<html><body><script>alert(1)</script></body></html>",
        method="validate_activity_file",
        expected=FileProcessingError,
        error_code=ErrorCode.XML_INVALID_ROOT,
    ),
    AttackSample(
        name="xml-element-flood",
        filename="track.gpx",
        content=_gpx(b"<trkpt/>" * 200),
        method="validate_activity_file",
        expected=FileProcessingError,
        error_code=ErrorCode.XML_TOO_MANY_ELEMENTS,
        limits=SecurityLimits(max_xml_elements=10),
    ),
)


@dataclass(frozen=True)
class BenignSample:
    """
    A legitimate upload that must survive validation.

    Attributes:
        name: Sample name.
        filename: Name the file is uploaded under.
        content: Raw bytes of the upload.
        method: ``FileValidator`` method under test.
    """

    name: str
    filename: str
    content: bytes
    method: str


# Realistically sized files. A detection tuned only against
# hand-written 40-byte fixtures will pass its own tests while
# rejecting every real upload: a megabyte of entropy-coded image
# data contains every two-byte sequence many times over, so any
# short signature matched without corroboration fires on all of
# them.
ACCEPTED: tuple[BenignSample, ...] = (
    BenignSample(
        name="photographic-jpeg-512kb",
        filename="photo.jpg",
        content=_jpeg(entropy_bytes(512 * 1024, seed=1)),
        method="validate_image_file",
    ),
    BenignSample(
        name="photographic-png-512kb",
        filename="photo.png",
        content=_png(1024, 768) + entropy_bytes(512 * 1024, seed=2),
        method="validate_image_file",
    ),
    BenignSample(
        name="gpx-with-many-trackpoints",
        filename="track.gpx",
        content=_gpx(
            b"<trk><trkseg>"
            + b'<trkpt lat="48.1" lon="11.5"><ele>520</ele></trkpt>' * 5000
            + b"</trkseg></trk>"
        ),
        method="validate_activity_file",
    ),
    BenignSample(
        name="tcx-activity",
        filename="ride.tcx",
        content=(
            b'<?xml version="1.0"?>'
            b'<TrainingCenterDatabase xmlns="http://www.garmin.com/'
            b'xmlschemas/TrainingCenterDatabase/v2">'
            b'<Activities><Activity Sport="Biking">'
            + b"<Lap><Track><Trackpoint><DistanceMeters>1"
            b"</DistanceMeters></Trackpoint></Track></Lap>"
            * 500
            + b"</Activity></Activities></TrainingCenterDatabase>"
        ),
        method="validate_activity_file",
    ),
    BenignSample(
        name="zip-of-documents",
        filename="export.zip",
        content=_zip(
            {
                "readme.txt": b"Export of your activity data.\n",
                "data/track-1.gpx": _gpx(),
                "data/track-2.gpx": _gpx(),
                "data/photo.jpg": _jpeg(entropy_bytes(64 * 1024, seed=3)),
            },
            zipfile.ZIP_DEFLATED,
        ),
        method="validate_zip_file",
    ),
    BenignSample(
        name="gzipped-activity-export",
        filename="track.gpx.gz",
        content=gzip.compress(
            _gpx(b'<trk><trkseg><trkpt lat="1" lon="2"/></trkseg></trk>')
            + entropy_bytes(32 * 1024, seed=4)
        ),
        method="validate_gzip_file",
    ),
)


@pytest.mark.corpus
class TestAttackCorpus:
    """Every catalogued attack must be rejected."""

    @pytest.mark.parametrize(
        "sample", REJECTED, ids=[s.name for s in REJECTED]
    )
    @pytest.mark.asyncio
    async def test_attack_is_rejected(self, sample, mock_upload_file):
        config = (
            FileSecurityConfig(sample.limits)
            if sample.limits is not None
            else FileSecurityConfig()
        )
        validator = FileValidator(config=config)
        file = mock_upload_file(
            filename=sample.filename, content=sample.content
        )

        with pytest.raises(sample.expected) as exc_info:
            await getattr(validator, sample.method)(file)

        if sample.error_code is not None:
            assert exc_info.value.error_code == sample.error_code

    def test_every_sample_is_uniquely_named(self):
        names = [s.name for s in REJECTED]
        assert len(names) == len(set(names))


@pytest.mark.corpus
class TestBenignCorpus:
    """Realistic uploads must survive, with and without deep scanning."""

    @pytest.mark.parametrize(
        "analysis", [False, True], ids=["analysis-off", "analysis-on"]
    )
    @pytest.mark.parametrize(
        "sample", ACCEPTED, ids=[s.name for s in ACCEPTED]
    )
    @pytest.mark.asyncio
    async def test_benign_upload_is_accepted(
        self, sample, analysis, mock_upload_file
    ):
        config = FileSecurityConfig(
            SecurityLimits(enable_content_analysis=analysis)
        )
        validator = FileValidator(config=config)
        file = mock_upload_file(
            filename=sample.filename, content=sample.content
        )

        await getattr(validator, sample.method)(file)

    def test_every_benign_sample_is_uniquely_named(self):
        names = [s.name for s in ACCEPTED]
        assert len(names) == len(set(names))


@pytest.mark.corpus
class TestNeutralisedAttacks:
    """Attacks defused by sanitization rather than rejection."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "filename",
        [
            "../../../etc/passwd.jpg",
            "..\\..\\windows\\system32\\evil.jpg",
            "/absolute/path/photo.jpg",
            "....//....//photo.jpg",
        ],
    )
    async def test_sanitized_name_cannot_escape_a_directory(
        self, filename, mock_upload_file
    ):
        validator = FileValidator()
        file = mock_upload_file(filename=filename, content=_jpeg())

        await validator.validate_image_file(file)

        # Leading dots may survive as literal characters; with no
        # separator left they cannot traverse.
        _assert_cannot_escape(file.filename)

    @pytest.mark.asyncio
    async def test_control_characters_are_stripped(self, mock_upload_file):
        validator = FileValidator()
        file = mock_upload_file(
            filename="photo\x00\x07\x1b.jpg", content=_jpeg()
        )

        await validator.validate_image_file(file)

        assert all(ord(c) >= 32 for c in file.filename)
