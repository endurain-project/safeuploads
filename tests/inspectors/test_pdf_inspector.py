"""Tests for the PDF content inspector."""

import base64
import io
import zlib

import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.exceptions import ErrorCode, PdfSecurityError
from safeuploads.inspectors import pdf_inspector
from safeuploads.inspectors.pdf_inspector import PdfContentInspector
from tests import pdfs

JS_ACTION = b"<< /S /JavaScript /JS (app.alert(1)) >>"


def _inspect(data: bytes, config: FileSecurityConfig | None = None) -> None:
    """Run the inspector on ``data``."""
    inspector = PdfContentInspector(config or FileSecurityConfig())
    inspector.inspect_pdf_content(io.BytesIO(data), filename="doc.pdf")


def _rejected(
    data: bytes, config: FileSecurityConfig | None = None
) -> PdfSecurityError:
    """Run the inspector and return the error it raised."""
    with pytest.raises(PdfSecurityError) as exc_info:
        _inspect(data, config)
    assert exc_info.value.filename == "doc.pdf"
    return exc_info.value


def _xref_offset(pdf: bytes, num: int) -> int:
    """Return the offset of object ``num`` in an xref table."""
    marker = b"%d 0 obj" % num
    return pdf.index(marker)


def _set_xref_offset(pdf: bytes, num: int, offset: int) -> bytes:
    """Point the xref table entry of object ``num`` at ``offset``."""
    old = b"%010d 00000 n " % _xref_offset(pdf, num)
    return pdf.replace(old, b"%010d 00000 n " % offset)


class TestAcceptedDocuments:
    """Documents without blocked features pass."""

    def test_minimal_document(self):
        _inspect(pdfs.document())

    def test_xref_stream_with_png_predictor(self):
        _inspect(pdfs.document(xref_stream=True))

    def test_object_stream(self):
        _inspect(
            pdfs.document(
                catalog=b" /Metadata 5 0 R /Outlines 6 0 R",
                extra=[pdfs.stream(b"/Type /Metadata", b"<x/>")],
                compressed=[b"<< /Type /Outlines /Count 0 >>"],
                xref_stream=True,
            )
        )

    def test_incremental_update(self):
        base = pdfs.document()
        updated = pdfs.append_update(base, {5: b"<< /Producer (editor) >>"})
        _inspect(updated)

    def test_open_action_to_a_page(self):
        _inspect(pdfs.document(catalog=b" /OpenAction [3 0 R /Fit]"))

    def test_uri_link(self):
        link = (
            b" /Annots [<< /Type /Annot /Subtype /Link /Rect [0 0 1 1]"
            b" /A << /S /URI /URI (https://example.com) >> >>]"
        )
        _inspect(pdfs.document(page=link))

    def test_acroform_without_xfa(self):
        _inspect(pdfs.document(catalog=b" /AcroForm << /Fields [] >>"))

    def test_indirect_length(self):
        body = b"<< /Length 6 0 R >>\nstream\n" + pdfs.CONTENT + b"\nendstream"
        length = str(len(pdfs.CONTENT)).encode()
        _inspect(pdfs.document(extra=[body, length]))

    def test_indirect_length_in_object_stream(self):
        body = b"<< /Length 6 0 R >>\nstream\n" + pdfs.CONTENT + b"\nendstream"
        length = str(len(pdfs.CONTENT)).encode()
        _inspect(
            pdfs.document(extra=[body], compressed=[length], xref_stream=True)
        )

    def test_length_counting_the_end_of_line(self):
        data = pdfs.CONTENT + b"\n"
        body = pdfs.stream(b"", pdfs.CONTENT, length=b"%d" % len(data))
        _inspect(pdfs.document(extra=[body]))

    def test_image_filter_is_not_decoded(self):
        image = pdfs.stream(
            b"/Type /XObject /Subtype /Image /Width 1 /Height 1"
            b" /BitsPerComponent 1 /Filter /JBIG2Decode",
            b"\x97JB2\r\n\x1a\n",
        )
        _inspect(pdfs.document(extra=[image]))

    def test_ascii85_then_flate_chain(self):
        data = base64.a85encode(zlib.compress(pdfs.CONTENT)) + b"~>"
        body = pdfs.stream(b"/Filter [/ASCII85Decode /FlateDecode]", data)
        _inspect(pdfs.document(extra=[body]))

    def test_ascii_hex_stream(self):
        body = pdfs.stream(b"/Filter /AHx", pdfs.CONTENT.hex().encode() + b">")
        _inspect(pdfs.document(extra=[body]))

    def test_value_types(self):
        _inspect(
            pdfs.document(
                extra=[
                    b"<< /A true /B false /C null /D 1.5 /E -.5"
                    b" /F <48656C6C6F> /G (a(b)c\\)) /H [1 0 R] >>"
                ]
            )
        )

    def test_many_tokens(self):
        _inspect(pdfs.document(extra=[b"[" + b"1 " * 5000 + b"]"]))

    def test_crlf_after_stream_keyword(self):
        body = b"<< /Length 3 >>\r\nstream\r\nabc\r\nendstream"
        _inspect(pdfs.document(extra=[body]))

    def test_decode_parms_array(self):
        body = pdfs.stream(
            b"/Filter [/FlateDecode] /DecodeParms [null]",
            zlib.compress(pdfs.CONTENT),
        )
        _inspect(pdfs.document(extra=[body]))

    @pytest.mark.parametrize(
        ("entries", "target"),
        [
            (b"/Filter 6 0 R", b"/FlateDecode"),
            (b"/Filter [6 0 R]", b"/FlateDecode"),
            (
                b"/Filter /FlateDecode /DecodeParms 6 0 R",
                b"<< /Predictor 1 >>",
            ),
            (
                b"/Filter /FlateDecode /DecodeParms [6 0 R]",
                b"<< /Predictor 1 >>",
            ),
        ],
        ids=["filter", "filter-item", "parms", "parms-item"],
    )
    def test_indirect_filter_and_parms(self, entries, target):
        body = pdfs.stream(entries, zlib.compress(pdfs.CONTENT))
        _inspect(pdfs.document(extra=[body, target]))

    def test_duplicate_key_with_equal_value(self):
        _inspect(pdfs.document(catalog=b" /PageMode /UseOutlines" * 2))

    def test_conflicting_duplicate_outside_stream_and_trailer(self):
        _inspect(
            pdfs.document(
                catalog=b" /PageMode /UseNone /PageMode /UseOutlines"
            )
        )

    def test_ascii_hex_odd_digit_count(self):
        body = pdfs.stream(b"/Filter /ASCIIHexDecode", b"414>")
        _inspect(pdfs.document(extra=[body]))

    @pytest.mark.parametrize("kind", ["array", "dict"])
    def test_deep_nesting_without_duplicate_key(self, kind):
        value = _nested(kind, b"1")
        _inspect(pdfs.document(extra=[pdfs.stream(b"/X " + value, b"abc")]))

    @pytest.mark.parametrize("kind", ["array", "dict"])
    def test_deeply_nested_duplicate_key_with_equal_value(self, kind):
        value = _nested(kind, b"1")
        body = pdfs.stream(b"/X " + value + b" /X " + value, b"abc")
        _inspect(pdfs.document(extra=[body]))

    def test_catalog_and_page_tree_in_object_stream(self):
        page = b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>"
        _inspect(
            pdfs.build(
                [],
                compressed=[pdfs.CATALOG, pdfs.PAGES, page],
                xref_stream=True,
            )
        )

    def test_trailing_whitespace_after_eof(self):
        _inspect(pdfs.document(tail=b"\r\n \n"))

    def test_names_inside_strings_and_comments(self):
        _inspect(
            pdfs.document(
                extra=[b"<< /Title (see /JavaScript) >> % /JS comment"]
            )
        )

    def test_unblocked_name_is_accepted_when_configured(self):
        config = FileSecurityConfig()
        config.BLOCKED_PDF_NAMES = FileSecurityConfig.BLOCKED_PDF_NAMES - {
            "JavaScript",
            "JS",
        }
        _inspect(pdfs.document(catalog=b" /OpenAction " + JS_ACTION), config)

    def test_file_rewound(self):
        data = pdfs.document()
        file_obj = io.BytesIO(data)
        PdfContentInspector(FileSecurityConfig()).inspect_pdf_content(file_obj)
        assert file_obj.tell() == 0


class TestActiveContent:
    """Blocked names are rejected wherever readers would see them."""

    def test_javascript_open_action(self):
        err = _rejected(pdfs.document(catalog=b" /OpenAction " + JS_ACTION))
        assert err.error_code == ErrorCode.PDF_ACTIVE_CONTENT

    @pytest.mark.parametrize(
        "name",
        [
            b"JavaScript",
            b"JS",
            b"Launch",
            b"EmbeddedFile",
            b"EmbeddedFiles",
            b"EF",
            b"FileAttachment",
            b"RichMedia",
            b"XFA",
            b"SubmitForm",
            b"ImportData",
            b"GoToR",
            b"GoToE",
        ],
    )
    def test_default_blocked_names(self, name):
        err = _rejected(pdfs.document(catalog=b" /X /" + name))
        assert err.error_code == ErrorCode.PDF_ACTIVE_CONTENT

    @pytest.mark.parametrize("name", [b"J#61vaScript", b"#4A#53", b"Launc#68"])
    def test_hex_escaped_names(self, name):
        err = _rejected(pdfs.document(catalog=b" /A << /S /" + name + b" >>"))
        assert err.error_code == ErrorCode.PDF_ACTIVE_CONTENT

    def test_javascript_in_object_stream(self):
        err = _rejected(
            pdfs.document(
                catalog=b" /OpenAction 5 0 R",
                compressed=[JS_ACTION],
                xref_stream=True,
            )
        )
        assert err.error_code == ErrorCode.PDF_ACTIVE_CONTENT

    def test_javascript_in_incremental_update(self):
        updated = pdfs.append_update(
            pdfs.document(),
            {1: pdfs.CATALOG[:-2] + b" /OpenAction " + JS_ACTION + b" >>"},
        )
        err = _rejected(updated)
        assert err.error_code == ErrorCode.PDF_ACTIVE_CONTENT

    def test_configured_name_is_blocked(self):
        config = FileSecurityConfig()
        config.BLOCKED_PDF_NAMES = frozenset({"URI"})
        err = _rejected(
            pdfs.document(catalog=b" /A << /S /URI /URI (x) >>"), config
        )
        assert err.error_code == ErrorCode.PDF_ACTIVE_CONTENT

    @pytest.mark.parametrize("key", [b"F", b"FFilter", b"FDecodeParms"])
    def test_external_stream_data(self, key):
        body = pdfs.stream(b"/" + key + b" (data.bin)", b"")
        err = _rejected(pdfs.document(extra=[body]))
        assert err.error_code == ErrorCode.PDF_ACTIVE_CONTENT


class TestEncryption:
    """Encrypted documents cannot be inspected."""

    def test_encrypt_in_trailer(self):
        err = _rejected(
            pdfs.document(
                extra=[b"<< /Filter /Standard /V 1 /R 2 >>"],
                trailer=b"/Encrypt 5 0 R",
            )
        )
        assert err.error_code == ErrorCode.PDF_ENCRYPTED

    def test_encrypt_in_xref_stream(self):
        err = _rejected(
            pdfs.document(
                extra=[b"<< /Filter /Standard /V 1 /R 2 >>"],
                trailer=b"/Encrypt 5 0 R",
                xref_stream=True,
            )
        )
        assert err.error_code == ErrorCode.PDF_ENCRYPTED


class TestFileLayout:
    """Header and trailer framing."""

    @pytest.mark.parametrize("header", [b"%PDF-x.y", b"%PDF-3.0", b"%PDF-17 "])
    def test_invalid_version(self, header):
        data = header + pdfs.document()[8:]
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_file_ends_inside_object(self):
        err = _rejected(b"%PDF-1.7\n1 0 obj\n1")
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_header_only(self):
        err = _rejected(b"%PDF-1.7")
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    @pytest.mark.parametrize(
        "tail",
        [
            pytest.param(b"PK\x03\x04" + bytes(26), id="zip"),
            pytest.param(b"<html><script>x</script></html>", id="html"),
            pytest.param(b"% trailing comment\n", id="comment"),
        ],
    )
    def test_data_after_eof(self, tail):
        err = _rejected(pdfs.document(tail=tail))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_missing_eof_marker(self):
        data = pdfs.document().replace(b"%%EOF", b"")
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_missing_startxref(self):
        data = pdfs.document()
        data = data[: data.rindex(b"startxref")] + b"%%EOF\n"
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_startxref_without_offset(self):
        data = pdfs.document()
        index = data.rindex(b"startxref")
        data = data[:index] + b"startxref\n/A\n%%EOF\n"
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_object_after_startxref(self):
        data = pdfs.document()
        index = data.rindex(b"%%EOF")
        data = data[:index] + b"9 0 obj\n1\nendobj\n" + data[index:]
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE


class TestSyntax:
    """Malformed syntax is rejected instead of being repaired."""

    @pytest.mark.parametrize(
        "body",
        [
            pytest.param(b"<< /A >>", id="odd-dict"),
            pytest.param(b"<< 1 2 >>", id="non-name-key"),
            pytest.param(b"<< /A 1", id="unterminated-dict"),
            pytest.param(b"[1 2", id="unterminated-array"),
            pytest.param(b"(abc", id="unterminated-string"),
            pytest.param(b"<< /A 1 ]", id="mismatched-close"),
            pytest.param(b"<0G>", id="bad-hex-string"),
            pytest.param(b"/J#6", id="bad-name-escape"),
            pytest.param(b"/J#zz", id="bad-name-escape-digits"),
            pytest.param(b"{ 1 }", id="brace"),
            pytest.param(b"1 2 3", id="three-values"),
            pytest.param(b"bogus", id="unknown-keyword"),
            pytest.param(b"1.2.3", id="bad-number"),
            pytest.param(b"9" * 5000, id="huge-integer"),
            pytest.param(b"[R]", id="dangling-reference"),
            pytest.param(b"[/A 0 R]", id="name-reference"),
            pytest.param(b"<< /A endobj >>", id="keyword-in-dict"),
        ],
    )
    def test_malformed_object(self, body):
        err = _rejected(pdfs.document(extra=[body]))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_object_without_endobj(self):
        data = pdfs.document(extra=[b"1"])
        data = data.replace(b"1\nendobj\nxref", b"1\nxref")
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    @pytest.mark.parametrize("header", [b"0 0 obj", b"5 70000 obj"])
    def test_invalid_object_number(self, header):
        data = pdfs.document(extra=[b"1"]).replace(b"5 0 obj", header)
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_stray_token_between_objects(self):
        data = pdfs.document().replace(
            b"endobj\n2 0 obj", b"endobj\n7\n2 0 obj"
        )
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_stray_trailer(self):
        data = pdfs.document().replace(
            b"endobj\n2 0 obj", b"endobj\ntrailer\n2 0 obj"
        )
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE


class TestStreams:
    """Stream extents must agree for every reader."""

    def test_length_shorter_than_data_hides_object(self):
        hidden = b"\nendobj\n9 0 obj\n" + JS_ACTION + b"\n"
        data = pdfs.CONTENT + hidden
        body = pdfs.stream(b"", data, length=b"%d" % len(pdfs.CONTENT))
        err = _rejected(pdfs.document(extra=[body]))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_length_shorter_than_data(self):
        body = pdfs.stream(b"", pdfs.CONTENT, length=b"3")
        err = _rejected(pdfs.document(extra=[body]))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_length_longer_than_data(self):
        body = pdfs.stream(b"", pdfs.CONTENT, length=b"9999")
        err = _rejected(pdfs.document(extra=[body]))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    @pytest.mark.parametrize(
        "length",
        [b"-1", b"(5)", b"7 0 R", b"6 0 R", b"6 1 R"],
        ids=[
            "negative",
            "string",
            "missing-ref",
            "non-integer-ref",
            "wrong-generation",
        ],
    )
    def test_invalid_length(self, length):
        body = pdfs.stream(b"", pdfs.CONTENT, length=length)
        err = _rejected(pdfs.document(extra=[body, b"/Name"]))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    @pytest.mark.parametrize(
        "entries",
        [b"/Length 3 /Length 4", b"/Type /ObjStm /Type /XObject"],
        ids=["length", "type"],
    )
    def test_conflicting_duplicate_in_stream_dictionary(self, entries):
        body = b"<< " + entries + b" >>\nstream\nabc\nendstream"
        err = _rejected(pdfs.document(extra=[body]))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_missing_length(self):
        body = b"<< >>\nstream\n" + pdfs.CONTENT + b"\nendstream"
        err = _rejected(pdfs.document(extra=[body]))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_missing_endstream(self):
        data = pdfs.document(extra=[pdfs.stream(b"", b"abc")])
        data = data.replace(b"abc\nendstream", b"abc\n")
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    @pytest.mark.parametrize("kind", ["array", "dict"])
    def test_deeply_nested_conflicting_duplicate(self, kind):
        first, second = _nested(kind, b"1"), _nested(kind, b"2")
        body = pdfs.stream(b"/X " + first + b" /X " + second, b"abc")
        err = _rejected(pdfs.document(extra=[body]))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_endstream_glued_to_keyword(self):
        data = pdfs.document(extra=[pdfs.stream(b"", b"abc")])
        data = data.replace(b"endstream\nendobj", b"endstreamendobj")
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_stream_keyword_without_end_of_line(self):
        data = pdfs.document(extra=[pdfs.stream(b"", b"abc")])
        data = data.replace(b"stream\nabc", b"stream abc")
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_stream_without_dictionary(self):
        data = pdfs.document(extra=[b"[1]\nstream\nabc\nendstream"])
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    @pytest.mark.parametrize(
        "filters",
        [
            b"/LZWDecode",
            b"/RunLengthDecode",
            b"/Crypt",
            b"/Unknown",
            b"[/DCTDecode /FlateDecode]",
            b"(FlateDecode)",
            b"[/FlateDecode (x)]",
        ],
    )
    def test_unsupported_filters(self, filters):
        body = pdfs.stream(b"/Filter " + filters, b"abc")
        err = _rejected(pdfs.document(extra=[body]))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    @pytest.mark.parametrize(
        "entries",
        [b"/Filter 6 0 R", b"/Filter [6 0 R]", b"/Filter 9 0 R"],
        ids=["unsupported", "unsupported-item", "missing"],
    )
    def test_indirect_filter_is_resolved(self, entries):
        body = pdfs.stream(entries, b"abc")
        err = _rejected(pdfs.document(extra=[body, b"/LZWDecode"]))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    @pytest.mark.parametrize(
        "parms",
        [b"[<< >> << >>]", b"(x)", b"[(x)]"],
        ids=["count-mismatch", "string", "string-in-array"],
    )
    def test_invalid_decode_parms(self, parms):
        body = pdfs.stream(b"/DecodeParms " + parms, pdfs.CONTENT, flate=True)
        err = _rejected(pdfs.document(extra=[body]))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    @pytest.mark.parametrize(
        "data",
        [b"not zlib data", b"zz>", b"vvvv~>"],
        ids=["flate", "hex", "ascii85"],
    )
    def test_undecodable_stream(self, data):
        filters = {
            b"not zlib data": b"/FlateDecode",
            b"zz>": b"/ASCIIHexDecode",
            b"vvvv~>": b"[/ASCII85Decode /FlateDecode]",
        }[data]
        body = pdfs.stream(b"/Filter " + filters, data)
        err = _rejected(pdfs.document(extra=[body]))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_truncated_flate_stream_is_accepted(self):
        data = zlib.compress(pdfs.CONTENT)[:-4]
        body = pdfs.stream(b"/Filter /FlateDecode", data)
        _inspect(pdfs.document(extra=[body]))


class TestStreamBombs:
    """Decompressed stream output is bounded."""

    def _bomb(self, size: int) -> bytes:
        body = pdfs.stream(b"", bytes(size), flate=True)
        return pdfs.document(extra=[body])

    def test_uncompressed_size_limit_boundary(self):
        data = self._bomb(100_000)
        content = len(pdfs.CONTENT)
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            max_pdf_uncompressed_size=100_000 + content,
            max_compression_ratio=1000,
        )
        _inspect(data, config)

        config.limits = SecurityLimits(
            max_pdf_uncompressed_size=100_000 + content - 1,
            max_compression_ratio=1000,
        )
        err = _rejected(data, config)
        assert err.error_code == ErrorCode.PDF_STREAM_BOMB

    def test_compression_ratio(self):
        data = self._bomb(1_000_000)
        assert 1_000_000 / len(data) > 100
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_STREAM_BOMB

    def test_ratio_below_limit(self):
        data = self._bomb(50_000)
        assert 50_000 / len(data) < 100
        _inspect(data)

    def test_nested_flate_bomb(self):
        inner = zlib.compress(bytes(2_000_000))
        body = pdfs.stream(
            b"/Filter [/FlateDecode /FlateDecode]", zlib.compress(inner)
        )
        err = _rejected(pdfs.document(extra=[body]))
        assert err.error_code == ErrorCode.PDF_STREAM_BOMB

    def test_object_stream_bomb(self):
        padding = b" " * 5_000_000
        err = _rejected(
            pdfs.document(compressed=[b"1" + padding], xref_stream=True)
        )
        assert err.error_code == ErrorCode.PDF_STREAM_BOMB


class TestCrossReference:
    """Every xref entry must point at an object the scan parsed."""

    def test_offset_into_string_hides_object(self):
        hidden = b"5 0 obj " + JS_ACTION + b" endobj"
        carrier = b"(" + hidden.replace(b"(", b"[").replace(b")", b"]") + b")"
        data = pdfs.document(extra=[carrier])
        target = data.index(b"5 0 obj <<")
        data = _set_xref_offset(data, 5, target)
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_offset_into_stream_data(self):
        hidden = b"5 0 obj\n<< /A 1 >>\nendobj\n"
        data = pdfs.document(extra=[pdfs.stream(b"", hidden)])
        target = data.index(b"5 0 obj\n<< /A")
        data = _set_xref_offset(data, 5, target)
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_offset_before_whitespace_is_accepted(self):
        data = pdfs.document()
        data = _set_xref_offset(data, 2, _xref_offset(data, 2) - 1)
        _inspect(data)

    def test_wrong_object_number(self):
        data = pdfs.document()
        data = _set_xref_offset(data, 2, _xref_offset(data, 3))
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_wrong_generation(self):
        data = pdfs.document()
        old = b"%010d 00000 n " % _xref_offset(data, 2)
        data = data.replace(old, b"%010d 00001 n " % _xref_offset(data, 2))
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_offset_past_end(self):
        data = _set_xref_offset(pdfs.document(), 2, 10**9)
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_startxref_not_at_xref(self):
        data = pdfs.document()
        start = int(data.split(b"startxref\n")[1].split(b"\n")[0])
        data = data.replace(
            b"startxref\n%d" % start, b"startxref\n%d" % (start - 9)
        )
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_circular_prev(self):
        data = pdfs.document()
        start = int(data.split(b"startxref\n")[1].split(b"\n")[0])
        data = data.replace(b"/Size 5", b"/Size 5 /Prev %d" % start)
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_conflicting_duplicate_in_trailer(self):
        err = _rejected(pdfs.document(trailer=b"/Root 2 0 R"))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    @pytest.mark.parametrize(
        "entry",
        [b"/Prev (x)", b"/XRefStm (x)", b"/Prev 0"],
        ids=["string-prev", "string-xrefstm", "prev-to-header"],
    )
    def test_invalid_trailer_links(self, entry):
        data = pdfs.document(trailer=entry)
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    @pytest.mark.parametrize(
        "section",
        [
            b"xref\n0 1 2\ntrailer",
            b"xref\n0 1\n0000000000 65535 x \ntrailer",
            b"xref\n0 1\n0000000000 65535 f \ntrailer\n[1]",
            b"xref\n0 1\n0000000000 65535 f \ntrailer\n5",
            b"xref\n/A",
            b"xref\n-1 1\n0000000000 65535 f \ntrailer",
        ],
        ids=[
            "short-entry",
            "bad-flag",
            "array-trailer",
            "int-trailer",
            "name-in-xref",
            "negative-start",
        ],
    )
    def test_malformed_xref_table(self, section):
        data = pdfs.document()
        xref = data.index(b"xref\n")
        trailer_end = data.index(b">>\n", xref) + 2
        data = data[:xref] + section + data[trailer_end:]
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    @pytest.mark.parametrize(
        ("offset_valid", "entries"),
        [(True, b""), (False, b""), (True, b" /Prev 0")],
        ids=["valid", "wrong-offset", "prev-in-stream"],
    )
    def test_hybrid_xref_stream(self, offset_valid, entries):
        base = pdfs.document()
        xref = base.index(b"xref\n")
        offset = xref if offset_valid else 17
        rows = b"\x01" + offset.to_bytes(4, "big") + b"\x00"
        body = pdfs.stream(
            b"/Type /XRef /W [1 4 1] /Size 6 /Index [5 1]" + entries, rows
        )
        data = base[:xref] + b"5 0 obj\n" + body + b"\nendobj\n" + base[xref:]
        start = data.index(b"xref\n", xref)
        data = data.replace(b"/Size 5", b"/Size 6 /XRefStm %d" % xref)
        data = data[: data.rindex(b"startxref")] + (
            b"startxref\n%d\n%%%%EOF\n" % start
        )
        if offset_valid and not entries:
            _inspect(data)
        else:
            err = _rejected(data)
            assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE


class TestCatalog:
    """The newest trailer must lead to a catalog with a page tree."""

    @pytest.mark.parametrize(
        "data",
        [
            pytest.param(
                pdfs.document().replace(b"/Root 1 0 R ", b""),
                id="root-missing",
            ),
            pytest.param(
                pdfs.document().replace(b"/Root 1 0 R", b"/Root 9 0 R"),
                id="root-object-missing",
            ),
            pytest.param(
                pdfs.document().replace(b"/Root 1 0 R", b"/Root (1 0)"),
                id="root-string",
            ),
            pytest.param(
                pdfs.build([b"[2 0 R]", pdfs.PAGES]), id="root-array"
            ),
            pytest.param(
                pdfs.build([pdfs.stream(pdfs.CATALOG[3:-3], b""), pdfs.PAGES]),
                id="root-stream",
            ),
            pytest.param(
                pdfs.build([b"<< /Type /Catalog >>"]), id="pages-missing"
            ),
            pytest.param(
                pdfs.build([pdfs.CATALOG]), id="pages-object-missing"
            ),
            pytest.param(
                pdfs.build([pdfs.CATALOG, b"[3 0 R]"]), id="pages-array"
            ),
            pytest.param(
                pdfs.build([pdfs.CATALOG, pdfs.stream(pdfs.PAGES[3:-3], b"")]),
                id="pages-stream",
            ),
            pytest.param(
                pdfs.build([], compressed=[b"5"], xref_stream=True),
                id="compressed-root-integer",
            ),
            pytest.param(
                pdfs.build(
                    [], compressed=[pdfs.CATALOG, b"null"], xref_stream=True
                ),
                id="compressed-pages-null",
            ),
        ],
    )
    def test_invalid_catalog(self, data):
        err = _rejected(data)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_newest_catalog_without_page_tree(self):
        updated = pdfs.append_update(
            pdfs.document(), {1: b"<< /Type /Catalog >>"}
        )
        err = _rejected(updated)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE


class TestXrefStreams:
    """Cross-reference streams are decoded and verified."""

    def _xref_stream_pdf(
        self, entries: bytes, rows: bytes, *, flate: bool = False
    ) -> bytes:
        base = pdfs.build([pdfs.CATALOG, pdfs.PAGES])
        head = base[: base.index(b"xref\n")]
        body = pdfs.stream(
            b"/Type /XRef /Root 1 0 R " + entries, rows, flate=flate
        )
        return (
            head
            + b"3 0 obj\n"
            + body
            + b"\nendobj\nstartxref\n%d\n%%%%EOF\n" % len(head)
        )

    def _rows(self, pdf: bytes) -> bytes:
        rows = b"\x00\x00\x00\x00\x00\xff\xff"
        for num in (1, 2):
            rows += b"\x01" + pdf.index(b"%d 0 obj" % num).to_bytes(4, "big")
            rows += b"\x00\x00"
        return rows

    def _valid(self, entries: bytes) -> bytes:
        probe = self._xref_stream_pdf(entries, b"")
        return self._xref_stream_pdf(entries, self._rows(probe))

    def test_uncompressed_xref_stream(self):
        _inspect(self._valid(b"/W [1 4 2] /Size 3"))

    def test_xref_stream_with_index(self):
        _inspect(self._valid(b"/W [1 4 2] /Size 3 /Index [0 3]"))

    @pytest.mark.parametrize(
        "entries",
        [
            b"/W [1 4] /Size 3",
            b"/W [1 4 9] /Size 3",
            b"/W [0 0 0] /Size 3",
            b"/W [1 4 2] /Size (3)",
            b"/W [1 4 2] /Size 3 /Index [0]",
            b"/W [1 4 2] /Size 3 /Index [0 4]",
            b"/W (x) /Size 3",
            b"/W [1 4 (x)] /Size 3",
        ],
        ids=[
            "short-w",
            "wide-field",
            "zero-width",
            "string-size",
            "odd-index",
            "index-mismatch",
            "string-w",
            "string-in-w",
        ],
    )
    def test_invalid_xref_stream_dictionary(self, entries):
        err = _rejected(self._valid(entries))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_unknown_entry_type(self):
        probe = self._xref_stream_pdf(b"/W [1 4 2] /Size 3", b"")
        rows = self._rows(probe)[:-7] + b"\x07\x00\x00\x00\x00\x00\x00"
        err = _rejected(self._xref_stream_pdf(b"/W [1 4 2] /Size 3", rows))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_xref_stream_with_image_filter(self):
        err = _rejected(self._valid(b"/W [1 4 2] /Size 3 /Filter /DCTDecode"))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    @pytest.mark.parametrize(
        "parms",
        [
            b"<< /Predictor 2 /Columns 7 >>",
            b"<< /Predictor 12 /Columns 0 >>",
            b"<< /Predictor 12 /Colors 99 /Columns 7 >>",
            b"<< /Predictor 12 /BitsPerComponent 3 /Columns 7 >>",
            b"<< /Predictor (12) >>",
            b"<< /Predictor 12 /Columns 6 >>",
            b"<< /Predictor 12 /Columns 7 /Predictor 1 >>",
        ],
        ids=[
            "tiff",
            "zero-columns",
            "colors",
            "bits",
            "string-predictor",
            "row-mismatch",
            "conflicting-key",
        ],
    )
    def test_invalid_predictor(self, parms):
        pdf = pdfs.document(xref_stream=True)
        pdf = pdf.replace(
            b"/DecodeParms << /Predictor 12 /Columns 7 >>",
            b"/DecodeParms " + parms,
        )
        err = _rejected(pdf)
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    @pytest.mark.parametrize("filter_type", [0, 1, 2, 3, 4])
    def test_png_filter_types(self, filter_type):
        probe = self._xref_stream_pdf(b"", b"")
        rows = self._rows(probe)
        encoded = bytearray()
        previous = bytes(7)
        for start in range(0, len(rows), 7):
            row = rows[start : start + 7]
            encoded.append(filter_type)
            encoded += _png_encode(filter_type, row, previous)
            previous = row
        entries = (
            b"/W [1 4 2] /Size 3 /DecodeParms << /Predictor 12 /Columns 7 >>"
        )
        _inspect(self._xref_stream_pdf(entries, bytes(encoded), flate=True))

    def test_invalid_png_filter_type(self):
        rows = b"\x05" + bytes(7)
        entries = (
            b"/W [1 4 2] /Size 1 /DecodeParms << /Predictor 12 /Columns 7 >>"
        )
        err = _rejected(self._xref_stream_pdf(entries, rows, flate=True))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE


class TestObjectStreams:
    """Object streams are decoded, parsed and verified."""

    def _object_stream_pdf(
        self, header: bytes, payload: bytes, *, n: int, entries: bytes = b""
    ) -> bytes:
        body = pdfs.stream(
            b"/Type /ObjStm /N %d /First %d " % (n, len(header)) + entries,
            header + payload,
            flate=True,
        )
        return pdfs.document(extra=[body])

    def test_object_stream_outside_xref_is_scanned(self):
        err = _rejected(self._object_stream_pdf(b"9 0 ", JS_ACTION, n=1))
        assert err.error_code == ErrorCode.PDF_ACTIVE_CONTENT

    def test_offset_into_string(self):
        payload = b"(abc /JavaScript) "
        header = b"9 0 10 5 "
        err = _rejected(self._object_stream_pdf(header, payload, n=2))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    @pytest.mark.parametrize(
        ("header", "payload", "n"),
        [
            (b"9 4 10 0 ", b"1 2 ", 2),
            (b"9 0 ", b"1 2", 1),
            (b"9 0 ", b"", 1),
            (b"9 ", b"1", 1),
            (b"9 0 /A ", b"1", 1),
            (b"9 0 ", b"1", 2),
            (b"0 0 ", b"1", 1),
            (b"9 99 ", b"1", 1),
            (b"9 0 ", b"1 endobj", 1),
            (b"9 0 ", b"<< /A 1", 1),
        ],
        ids=[
            "decreasing-offsets",
            "two-values",
            "empty-object",
            "short-header",
            "extra-header-token",
            "n-too-large",
            "object-zero",
            "offset-past-end",
            "keyword",
            "unterminated-dictionary",
        ],
    )
    def test_malformed_object_stream(self, header, payload, n):
        err = _rejected(self._object_stream_pdf(header, payload, n=n))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_paeth_predictor(self):
        text = b"9 0 << /A 1 /B [2 3] >>"
        text += b" " * (-len(text) % 2)
        encoded = bytearray()
        previous = bytes(2)
        for start in range(0, len(text), 2):
            row = text[start : start + 2]
            encoded += b"\x04" + _png_encode(4, row, previous)
            previous = row
        body = pdfs.stream(
            b"/Type /ObjStm /N 1 /First 4"
            b" /DecodeParms << /Predictor 12 /Columns 2 >>",
            bytes(encoded),
            flate=True,
        )
        _inspect(pdfs.document(extra=[body]))

    @pytest.mark.parametrize("filter_type", [0, 1, 2, 3, 4])
    @pytest.mark.parametrize(
        ("value", "code"),
        [
            (b"<< /A [1 2 3] /B /UseNone >>", None),
            (b"<< /S /JavaScript >>", ErrorCode.PDF_ACTIVE_CONTENT),
        ],
        ids=["valid", "javascript"],
    )
    def test_predictor_rows_wider_than_a_chunk(self, filter_type, value, code):
        # Three-byte pixels over five-byte chunks, two rows deep, so
        # pixels and filter references straddle every chunk boundary
        text = b"9 0 " + value
        text += b" " * (-len(text) % 6)
        row = len(text) // 2
        encoded = bytearray()
        previous = bytes(row)
        for start in (0, row):
            current = text[start : start + row]
            encoded.append(filter_type)
            encoded += _png_encode(filter_type, current, previous, pixel=3)
            previous = current
        body = pdfs.stream(
            b"/Type /ObjStm /N 1 /First 4 /DecodeParms"
            b" << /Predictor 12 /Colors 3 /Columns %d >>" % (row // 3),
            bytes(encoded),
            flate=True,
        )
        config = FileSecurityConfig()
        config.limits = SecurityLimits(chunk_size=5)
        data = pdfs.document(extra=[body])
        if code is None:
            _inspect(data, config)
        else:
            assert _rejected(data, config).error_code == code

    def test_resource_limits_are_checked_inside_a_predictor_row(
        self, monkeypatch
    ):
        chunk_size = 64
        width = 50 * chunk_size + 10
        text = b"9 0 << /A 1 >>".ljust(width)
        predicted = pdfs.stream(
            b"/Type /ObjStm /N 1 /First 4"
            b" /DecodeParms << /Predictor 12 /Columns %d >>" % width,
            b"\x04" + _png_encode(4, text, bytes(width)),
            flate=True,
        )
        plain = pdfs.stream(b"/Type /ObjStm /N 1 /First 4", text, flate=True)
        config = FileSecurityConfig()
        config.limits = SecurityLimits(chunk_size=chunk_size)
        calls = []
        monkeypatch.setattr(
            pdf_inspector, "check_resource_limits", lambda: calls.append(1)
        )
        _inspect(pdfs.document(extra=[plain]), config)
        without_predictor = len(calls)
        calls.clear()
        _inspect(pdfs.document(extra=[predicted]), config)
        # One check per chunk of the row, not one for the whole row
        assert len(calls) - without_predictor >= width // chunk_size

    def test_gap_before_first_object(self):
        _inspect(self._object_stream_pdf(b"9 2 ", b"  1", n=1))

    def test_value_in_gap_before_first_object(self):
        err = _rejected(self._object_stream_pdf(b"9 2 ", b"/A1", n=1))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    @pytest.mark.parametrize(
        "entries",
        [b"/N (1) /First 4", b"/N 1 /First 99", b"/N -1 /First 4"],
        ids=["string-n", "first-past-end", "negative-n"],
    )
    def test_invalid_object_stream_dictionary(self, entries):
        body = pdfs.stream(b"/Type /ObjStm " + entries, b"9 0 1", flate=True)
        err = _rejected(pdfs.document(extra=[body]))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_object_stream_with_image_filter(self):
        body = pdfs.stream(
            b"/Type /ObjStm /N 1 /First 4 /Filter /DCTDecode", b"9 0 1"
        )
        err = _rejected(pdfs.document(extra=[body]))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_compressed_entry_with_wrong_index(self):
        data = pdfs.document(
            catalog=b" /Outlines 5 0 R",
            compressed=[b"<< /Count 0 >>", b"<< /Count 1 >>"],
            xref_stream=True,
        )
        err = _rejected(_swap_compressed_index(data, 5))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_container_is_not_an_object_stream(self):
        data = pdfs.document(
            catalog=b" /Outlines 5 0 R",
            compressed=[b"<< /Count 0 >>"],
            xref_stream=True,
        )
        err = _rejected(_point_compressed_at(data, 5, container=4))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_container_missing_from_xref(self):
        data = pdfs.document(
            catalog=b" /Outlines 5 0 R",
            compressed=[b"<< /Count 0 >>"],
            xref_stream=True,
        )
        err = _rejected(_point_compressed_at(data, 5, container=40))
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE

    def test_compressed_length_reference_must_have_generation_zero(self):
        body = b"<< /Length 6 1 R >>\nstream\n" + pdfs.CONTENT + b"\nendstream"
        length = str(len(pdfs.CONTENT)).encode()
        err = _rejected(
            pdfs.document(extra=[body], compressed=[length], xref_stream=True)
        )
        assert err.error_code == ErrorCode.PDF_INVALID_STRUCTURE


def _nested(kind: str, inner: bytes, depth: int = 50_000) -> bytes:
    """Wrap ``inner`` in ``depth`` arrays or single-key dictionaries."""
    if kind == "array":
        return b"[" * depth + inner + b"]" * depth
    return b"<</B " * depth + inner + b">>" * depth


def _png_encode(
    filter_type: int, row: bytes, previous: bytes, pixel: int = 1
) -> bytes:
    """Encode one row with a PNG filter type."""
    out = bytearray()
    for i, value in enumerate(row):
        left = row[i - pixel] if i >= pixel else 0
        up = previous[i]
        upper_left = previous[i - pixel] if i >= pixel else 0
        if filter_type == 0:
            predicted = 0
        elif filter_type == 1:
            predicted = left
        elif filter_type == 2:
            predicted = up
        elif filter_type == 3:
            predicted = (left + up) // 2
        else:
            estimate = left + up - upper_left
            pa, pb, pc = (
                abs(estimate - left),
                abs(estimate - up),
                abs(estimate - upper_left),
            )
            if pa <= pb and pa <= pc:
                predicted = left
            elif pb <= pc:
                predicted = up
            else:
                predicted = upper_left
        out.append((value - predicted) & 0xFF)
    return bytes(out)


def _xref_rows(data: bytes) -> tuple[int, int, bytes]:
    """Return the xref stream's data span and decoded rows."""
    start = data.rindex(b"/Type /XRef")
    begin = data.index(b"stream\n", start) + len(b"stream\n")
    end = data.index(b"\nendstream", begin)
    raw = zlib.decompress(data[begin:end])
    rows = bytearray()
    previous = bytes(7)
    for pos in range(0, len(raw), 8):
        row = bytes(
            (a + b) & 0xFF
            for a, b in zip(raw[pos + 1 : pos + 8], previous, strict=True)
        )
        rows += row
        previous = row
    return begin, end, bytes(rows)


def _replace_xref_rows(data: bytes, rows: bytes) -> bytes:
    """Re-encode the xref stream rows and fix its /Length."""
    begin, end, _ = _xref_rows(data)
    encoded = bytearray()
    previous = bytes(7)
    for pos in range(0, len(rows), 7):
        row = rows[pos : pos + 7]
        encoded.append(2)
        encoded += bytes(
            (a - b) & 0xFF for a, b in zip(row, previous, strict=True)
        )
        previous = row
    new = zlib.compress(bytes(encoded))
    head = data[:begin]
    pos = head.rindex(b"/Length ")
    length_end = head.index(b" ", pos + len(b"/Length "))
    head = head[:pos] + b"/Length %d" % len(new) + head[length_end:]
    return head + new + data[end:]


def _swap_compressed_index(data: bytes, num: int) -> bytes:
    """Point compressed object ``num`` at the next index."""
    _, _, rows = _xref_rows(data)
    row = bytearray(rows[num * 7 : num * 7 + 7])
    row[6] += 1
    rows = rows[: num * 7] + bytes(row) + rows[num * 7 + 7 :]
    return _replace_xref_rows(data, rows)


def _point_compressed_at(data: bytes, num: int, *, container: int) -> bytes:
    """Point compressed object ``num`` at another container."""
    _, _, rows = _xref_rows(data)
    row = bytearray(rows[num * 7 : num * 7 + 7])
    row[1:5] = container.to_bytes(4, "big")
    rows = rows[: num * 7] + bytes(row) + rows[num * 7 + 7 :]
    return _replace_xref_rows(data, rows)
