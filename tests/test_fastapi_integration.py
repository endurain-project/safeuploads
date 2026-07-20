"""Integration tests against a real Starlette ``UploadFile``.

The rest of the suite validates against an in-memory mock that
implements the upload protocol. These tests exercise the actual
``starlette.datastructures.UploadFile`` object FastAPI hands to a
route, so protocol drift (async ``read``/``seek`` via a threadpool,
the ``size`` attribute, and in-place ``filename`` mutation) is caught
against the real dependency rather than a stand-in.
"""

import io

import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.exceptions import (
    ExtensionSecurityError,
    FileSizeError,
    UnicodeSecurityError,
)
from safeuploads.file_validator import FileValidator

# Skip the whole module if Starlette (a FastAPI dependency) is absent.
datastructures = pytest.importorskip("starlette.datastructures")
UploadFile = datastructures.UploadFile
Headers = datastructures.Headers


def _make_upload(
    filename: str,
    content: bytes,
    content_type: str = "application/octet-stream",
) -> "datastructures.UploadFile":
    """
    Build a real Starlette UploadFile backed by an in-memory buffer.

    Args:
        filename: Client-supplied filename.
        content: Raw file bytes.
        content_type: MIME type advertised in the part headers.

    Returns:
        A ``starlette.datastructures.UploadFile`` instance.
    """
    headers = Headers({"content-type": content_type})
    return UploadFile(
        io.BytesIO(content),
        size=len(content),
        filename=filename,
        headers=headers,
    )


@pytest.mark.integration
class TestRealUploadFile:
    """Validate real Starlette UploadFile objects end to end."""

    async def test_valid_jpeg_passes(self, valid_jpeg_bytes):
        """A valid JPEG in a real UploadFile validates cleanly."""
        validator = FileValidator()
        upload = _make_upload("photo.jpg", valid_jpeg_bytes, "image/jpeg")

        await validator.validate_image_file(upload)

        assert upload.filename == "photo.jpg"

    async def test_valid_png_passes(self, valid_png_bytes):
        """A valid PNG in a real UploadFile validates cleanly."""
        validator = FileValidator()
        upload = _make_upload("image.png", valid_png_bytes, "image/png")

        await validator.validate_image_file(upload)

    async def test_valid_zip_passes(self, create_zip_file):
        """A valid ZIP in a real UploadFile validates cleanly."""
        validator = FileValidator()
        zip_bytes = create_zip_file(files={"a.txt": b"hello"})
        upload = _make_upload("archive.zip", zip_bytes, "application/zip")

        await validator.validate_zip_file(upload)

    async def test_unicode_filename_rejected(self, valid_jpeg_bytes):
        """A right-to-left override in the filename is rejected."""
        validator = FileValidator()
        upload = _make_upload("photo\u202e.jpg", valid_jpeg_bytes)

        with pytest.raises(UnicodeSecurityError):
            await validator.validate_image_file(upload)

    async def test_wrong_extension_rejected(self, valid_jpeg_bytes):
        """A non-image extension is rejected for image validation."""
        validator = FileValidator()
        upload = _make_upload("photo.txt", valid_jpeg_bytes)

        with pytest.raises(ExtensionSecurityError):
            await validator.validate_image_file(upload)

    async def test_filename_sanitized_in_place(self, valid_jpeg_bytes):
        """Dangerous filename characters are sanitized on the object."""
        validator = FileValidator()
        upload = _make_upload("pho<>to.jpg", valid_jpeg_bytes, "image/jpeg")

        await validator.validate_image_file(upload)

        assert "<" not in (upload.filename or "")
        assert ">" not in (upload.filename or "")

    async def test_declared_size_triggers_fast_reject(self):
        """The real ``size`` attribute drives the fast size reject."""
        limits = SecurityLimits(max_image_size=1024)  # 1 KB cap
        config = FileSecurityConfig()
        config.limits = limits
        validator = FileValidator(config=config)

        content = b"\xff\xd8\xff\xe0" + b"\x00" * 4096  # ~4 KB > cap
        upload = _make_upload("big.jpg", content, "image/jpeg")

        with pytest.raises(FileSizeError):
            await validator.validate_image_file(upload)


@pytest.mark.integration
def test_multipart_round_trip(valid_jpeg_bytes):
    """
    Drive validation through a real FastAPI multipart request.

    Skips when the HTTP test stack (``httpx`` and
    ``python-multipart``) is unavailable, so it runs in fuller CI
    environments while staying optional locally.
    """
    pytest.importorskip("httpx")
    pytest.importorskip("multipart")

    from fastapi import FastAPI, HTTPException
    from fastapi import UploadFile as FastAPIUploadFile
    from fastapi.testclient import TestClient

    from safeuploads.exceptions import FileValidationError

    app = FastAPI()
    validator = FileValidator()

    @app.post("/upload")
    async def upload(file: FastAPIUploadFile) -> dict[str, str]:
        try:
            await validator.validate_image_file(file)
        except FileValidationError as err:
            raise HTTPException(status_code=400, detail=str(err)) from err
        return {"filename": file.filename or ""}

    client = TestClient(app)

    ok = client.post(
        "/upload",
        files={"file": ("photo.jpg", valid_jpeg_bytes, "image/jpeg")},
    )
    assert ok.status_code == 200
    assert ok.json()["filename"] == "photo.jpg"

    blocked = client.post(
        "/upload",
        files={"file": ("malware.exe", valid_jpeg_bytes, "image/jpeg")},
    )
    assert blocked.status_code == 400
