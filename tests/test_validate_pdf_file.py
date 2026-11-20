"""Integration tests for FileValidator.validate_pdf_file."""

import io

import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.exceptions import (
    ContentThreatError,
    ErrorCode,
    ExtensionSecurityError,
    FileSignatureError,
    FileSizeError,
    MimeTypeError,
    PdfSecurityError,
)
from safeuploads.file_validator import FileValidator, ValidationResult
from tests import images, pdfs

_VALID_PDF = pdfs.document()
_JS_PDF = pdfs.document(
    catalog=b" /OpenAction << /S /JavaScript /JS (app.alert(1)) >>"
)


class TestValidatePdfFile:
    """Async PDF validation."""

    async def test_valid_pdf(self, mock_upload_file):
        result = await FileValidator().validate_pdf_file(
            mock_upload_file("report.pdf", _VALID_PDF)
        )
        assert result == ValidationResult("report.pdf", "application/pdf")

    async def test_javascript_rejected(self, mock_upload_file):
        with pytest.raises(PdfSecurityError) as exc_info:
            await FileValidator().validate_pdf_file(
                mock_upload_file("report.pdf", _JS_PDF)
            )
        assert exc_info.value.error_code == ErrorCode.PDF_ACTIVE_CONTENT
        assert exc_info.value.filename == "report.pdf"

    async def test_extension_not_allowed(self, mock_upload_file):
        with pytest.raises(ExtensionSecurityError) as exc_info:
            await FileValidator().validate_pdf_file(
                mock_upload_file("report.txt", _VALID_PDF)
            )
        assert exc_info.value.error_code == ErrorCode.EXTENSION_NOT_ALLOWED

    async def test_png_named_pdf(self, mock_upload_file):
        with pytest.raises((FileSignatureError, MimeTypeError)):
            await FileValidator().validate_pdf_file(
                mock_upload_file("report.pdf", images.png(1, 1))
            )

    async def test_prefix_before_header(self, mock_upload_file):
        with pytest.raises((FileSignatureError, MimeTypeError)):
            await FileValidator().validate_pdf_file(
                mock_upload_file("report.pdf", b"\n" + _VALID_PDF)
            )

    async def test_size_limit(self, mock_upload_file):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(max_pdf_size=len(_VALID_PDF) - 1)
        with pytest.raises(FileSizeError) as exc_info:
            await FileValidator(config).validate_pdf_file(
                mock_upload_file("report.pdf", _VALID_PDF)
            )
        assert exc_info.value.error_code == ErrorCode.FILE_TOO_LARGE

    async def test_size_limit_boundary(self, mock_upload_file):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(max_pdf_size=len(_VALID_PDF))
        await FileValidator(config).validate_pdf_file(
            mock_upload_file("report.pdf", _VALID_PDF)
        )

    async def test_content_analysis(self, mock_upload_file):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(enable_content_analysis=True)
        payload = pdfs.document(extra=[pdfs.stream(b"", b"<?php system(1);")])
        with pytest.raises(ContentThreatError) as exc_info:
            await FileValidator(config).validate_pdf_file(
                mock_upload_file("report.pdf", payload)
            )
        assert exc_info.value.error_code == ErrorCode.CONTENT_THREAT_DETECTED

    async def test_content_analysis_clean(self, mock_upload_file):
        config = FileSecurityConfig()
        config.limits = SecurityLimits(enable_content_analysis=True)
        await FileValidator(config).validate_pdf_file(
            mock_upload_file("report.pdf", _VALID_PDF)
        )


class TestValidatePdfFileSync:
    """Synchronous PDF validation."""

    def test_valid_pdf(self):
        file = io.BytesIO(_VALID_PDF)
        result = FileValidator().validate_pdf_file_sync(file, "report.pdf")
        assert result == ValidationResult("report.pdf", "application/pdf")
        assert file.tell() == 0

    def test_javascript_rejected(self):
        with pytest.raises(PdfSecurityError) as exc_info:
            FileValidator().validate_pdf_file_sync(
                io.BytesIO(_JS_PDF), "report.pdf"
            )
        assert exc_info.value.error_code == ErrorCode.PDF_ACTIVE_CONTENT

    async def test_refuses_event_loop(self):
        with pytest.raises(RuntimeError, match="validate_pdf_file"):
            FileValidator().validate_pdf_file_sync(
                io.BytesIO(_VALID_PDF), "report.pdf"
            )
