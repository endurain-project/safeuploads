"""Fuzz tests for PDF validation."""

import io

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from safeuploads.config import FileSecurityConfig
from safeuploads.exceptions import ErrorCode, PdfSecurityError
from safeuploads.file_validator import FileValidator
from safeuploads.inspectors.pdf_inspector import PdfContentInspector
from tests import pdfs
from tests.fuzz.helpers import MockFile, accepted, accepted_async

_VALID = pdfs.document(xref_stream=True, compressed=[b"<< /Count 0 >>"])


def _inspect(data: bytes) -> None:
    """Run the PDF inspector on ``data``."""
    PdfContentInspector(FileSecurityConfig()).inspect_pdf_content(
        io.BytesIO(data)
    )


def _escaped(name: bytes, mask: list[bool]) -> bytes:
    """Hex-escape the characters of ``name`` selected by ``mask``."""
    return b"".join(
        b"#%02X" % byte if escape else bytes([byte])
        for byte, escape in zip(name, mask, strict=True)
    )


@pytest.mark.fuzz
class TestFuzzPdfValidation:
    """Property tests for PDF validation."""

    @given(body=st.binary(min_size=0, max_size=2000))
    @settings(max_examples=200, deadline=3000)
    def test_random_body_never_crashes(self, body):
        """Arbitrary bytes after a PDF header never crash."""
        accepted(_inspect, b"%PDF-1.7\n" + body)

    @given(
        position=st.integers(min_value=0, max_value=len(_VALID) - 1),
        value=st.integers(min_value=0, max_value=255),
    )
    @settings(max_examples=300, deadline=3000)
    def test_mutated_document_never_crashes(self, position, value):
        """A single changed byte is accepted or cleanly rejected."""
        data = bytearray(_VALID)
        data[position] = value
        accepted(_inspect, bytes(data))

    @given(
        cut=st.integers(min_value=0, max_value=len(_VALID) - 1),
        insert=st.binary(min_size=1, max_size=64),
    )
    @settings(max_examples=200, deadline=3000)
    def test_spliced_document_never_crashes(self, cut, insert):
        """Bytes spliced into a document never crash."""
        accepted(_inspect, _VALID[:cut] + insert + _VALID[cut:])

    @given(
        name=st.sampled_from(sorted(FileSecurityConfig.BLOCKED_PDF_NAMES)),
        data=st.data(),
        compressed=st.booleans(),
    )
    @settings(max_examples=200, deadline=3000)
    def test_escaped_blocked_name_always_rejected(
        self, name, data, compressed
    ):
        """A blocked name is rejected however it is hex-escaped."""
        raw = name.encode("ascii")
        mask = data.draw(
            st.lists(st.booleans(), min_size=len(raw), max_size=len(raw))
        )
        action = b"<< /X /" + _escaped(raw, mask) + b" >>"
        if compressed:
            pdf = pdfs.document(
                catalog=b" /A 5 0 R", compressed=[action], xref_stream=True
            )
        else:
            pdf = pdfs.document(catalog=b" /A 5 0 R", extra=[action])
        with pytest.raises(PdfSecurityError) as exc_info:
            _inspect(pdf)
        assert exc_info.value.error_code == ErrorCode.PDF_ACTIVE_CONTENT

    @given(data=st.binary(min_size=1, max_size=500))
    @settings(max_examples=100, deadline=3000)
    @pytest.mark.asyncio
    async def test_random_bytes_as_pdf(self, data):
        """Arbitrary bytes named .pdf never crash the validator."""
        file = MockFile("random.pdf", data)
        if await accepted_async(FileValidator().validate_pdf_file(file)):
            assert data.startswith(b"%PDF-")
