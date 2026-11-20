"""Tests for XmlSecurityValidator."""

import io
import tracemalloc

import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.exceptions import (
    ErrorCode,
    FileProcessingError,
    FileValidationError,
    ResourceLimitError,
    XmlSecurityError,
)
from safeuploads.validators.xml_validator import XmlSecurityValidator


class TestXmlSecurityValidator:
    """Test suite for XmlSecurityValidator."""

    def test_initialization(self, default_config):
        """Test validator initialization."""
        validator = XmlSecurityValidator(default_config)
        assert validator.config == default_config

    def test_valid_gpx_xml(self, default_config):
        """Test validation of valid GPX XML passes."""
        validator = XmlSecurityValidator(default_config)
        gpx_xml = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b"<gpx><trk><trkseg>"
            b'<trkpt lat="0" lon="0"/>'
            b"</trkseg></trk></gpx>"
        )
        file_obj = io.BytesIO(gpx_xml)
        validator.validate_xml_safety(file_obj, extension=".gpx")

    def test_valid_tcx_xml(self, default_config):
        """Test validation of valid TCX XML passes."""
        validator = XmlSecurityValidator(default_config)
        tcx_xml = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b"<TrainingCenterDatabase>"
            b'<Activities><Activity Sport="Running">'
            b"</Activity></Activities>"
            b"</TrainingCenterDatabase>"
        )
        file_obj = io.BytesIO(tcx_xml)
        validator.validate_xml_safety(file_obj, extension=".tcx")

    def test_reject_xxe_external_entity(self, default_config):
        """Test rejection of XXE external entity attack."""
        validator = XmlSecurityValidator(default_config)
        xxe_xml = (
            b'<?xml version="1.0"?>'
            b"<!DOCTYPE foo ["
            b'  <!ENTITY xxe SYSTEM "file:///etc/passwd">'
            b"]>"
            b"<gpx>&xxe;</gpx>"
        )
        file_obj = io.BytesIO(xxe_xml)
        with pytest.raises(
            XmlSecurityError, match="forbidden DTD declaration"
        ) as exc_info:
            validator.validate_xml_safety(file_obj, extension=".gpx")
        assert exc_info.value.error_code == ErrorCode.XML_DTD_FORBIDDEN

    def test_reject_dtd_declaration(self, default_config):
        """Test rejection of DTD declarations."""
        validator = XmlSecurityValidator(default_config)
        dtd_xml = (
            b'<?xml version="1.0"?>'
            b"<!DOCTYPE gpx ["
            b"  <!ELEMENT gpx (#PCDATA)>"
            b"]>"
            b"<gpx>test</gpx>"
        )
        file_obj = io.BytesIO(dtd_xml)
        with pytest.raises(
            XmlSecurityError, match="forbidden DTD declaration"
        ) as exc_info:
            validator.validate_xml_safety(file_obj, extension=".gpx")
        assert exc_info.value.error_code == ErrorCode.XML_DTD_FORBIDDEN

    def test_reject_billion_laughs(self, default_config):
        """Test rejection of billion laughs attack."""
        validator = XmlSecurityValidator(default_config)
        billion_laughs = (
            b'<?xml version="1.0"?>'
            b"<!DOCTYPE lolz ["
            b'  <!ENTITY lol "lol">'
            b'  <!ENTITY lol2 "&lol;&lol;&lol;">'
            b'  <!ENTITY lol3 "&lol2;&lol2;&lol2;">'
            b"]>"
            b"<root>&lol3;</root>"
        )
        file_obj = io.BytesIO(billion_laughs)
        with pytest.raises(
            XmlSecurityError, match="forbidden DTD declaration"
        ) as exc_info:
            validator.validate_xml_safety(file_obj, extension=".gpx")
        assert exc_info.value.error_code == ErrorCode.XML_DTD_FORBIDDEN

    def test_reject_malformed_xml(self, default_config):
        """Test rejection of malformed XML."""
        validator = XmlSecurityValidator(default_config)
        bad_xml = b"<gpx><unclosed>"
        file_obj = io.BytesIO(bad_xml)
        with pytest.raises(XmlSecurityError, match="Malformed") as exc_info:
            validator.validate_xml_safety(
                file_obj, extension=".gpx", filename="bad.gpx"
            )
        assert exc_info.value.error_code == ErrorCode.XML_MALFORMED
        assert exc_info.value.filename == "bad.gpx"
        assert isinstance(exc_info.value, FileValidationError)

    def test_reject_non_xml_content(self, default_config):
        """Test rejection of non-XML content."""
        validator = XmlSecurityValidator(default_config)
        file_obj = io.BytesIO(b"This is not XML at all.")
        with pytest.raises(XmlSecurityError) as exc_info:
            validator.validate_xml_safety(file_obj, extension=".gpx")
        assert exc_info.value.error_code == ErrorCode.XML_MALFORMED

    def test_validate_delegates_to_validate_xml_safety(self, default_config):
        """Test validate() delegates correctly."""
        validator = XmlSecurityValidator(default_config)
        valid_xml = b"<gpx/>"
        file_obj = io.BytesIO(valid_xml)
        validator.validate(file_obj, extension=".gpx")

    def test_file_position_reset_after_validation(self, default_config):
        """Test file position is reset after validation."""
        validator = XmlSecurityValidator(default_config)
        valid_xml = b"<gpx><trk/></gpx>"
        file_obj = io.BytesIO(valid_xml)
        file_obj.seek(5)
        validator.validate_xml_safety(file_obj, extension=".gpx")
        assert file_obj.tell() == 0

    def test_xml_with_bom(self, default_config):
        """Test XML with byte order mark passes."""
        validator = XmlSecurityValidator(default_config)
        bom_xml = b'\xef\xbb\xbf<?xml version="1.0" encoding="UTF-8"?><gpx/>'
        file_obj = io.BytesIO(bom_xml)
        validator.validate_xml_safety(file_obj, extension=".gpx")

    def test_empty_xml_document_rejected(self, default_config):
        """Test empty content is rejected."""
        validator = XmlSecurityValidator(default_config)
        file_obj = io.BytesIO(b"")
        with pytest.raises(XmlSecurityError) as exc_info:
            validator.validate_xml_safety(file_obj, extension=".gpx")
        assert exc_info.value.error_code == ErrorCode.XML_MALFORMED


def _parser_failing_with(error: Exception) -> type:
    """Return a stand-in parser class whose ``feed`` raises ``error``."""

    class _FailingParser:
        def __init__(self, *args, **kwargs):
            pass

        def feed(self, data):
            raise error

        def close(self):
            return None

    return _FailingParser


class TestXmlValidatorDefusedxmlBranches:
    def test_unexpected_exception_raises(self, default_config, monkeypatch):
        import safeuploads.validators.xml_validator as _mod

        validator = XmlSecurityValidator(default_config)
        monkeypatch.setattr(
            _mod.DefusedET,
            "DefusedXMLParser",
            _parser_failing_with(OSError("disk failure")),
        )
        with pytest.raises(FileProcessingError, match="failed") as exc_info:
            validator.validate_xml_safety(
                io.BytesIO(b"<gpx/>"), extension=".gpx"
            )
        assert not isinstance(exc_info.value, FileValidationError)
        assert exc_info.value.error_code == ErrorCode.PROCESSING_ERROR

    @pytest.mark.parametrize(
        "payload",
        [
            b'<?xml version="1.0" encoding="bogus"?><a/>',
            b'<?xml version="1.0" encoding="rot13"?><a/>',
            b'<?xml version="1.0" encoding="utf-7"?><a/>',
        ],
        ids=["unknown", "not-text", "multi-byte"],
    )
    def test_bad_encoding_declaration_is_malformed(
        self, default_config, payload
    ):
        """An unusable encoding declaration is attacker input."""
        validator = XmlSecurityValidator(default_config)
        with pytest.raises(XmlSecurityError) as exc_info:
            validator.validate_xml_safety(
                io.BytesIO(payload), extension=".gpx"
            )
        assert exc_info.value.error_code == ErrorCode.XML_MALFORMED

    def test_dtd_error_carries_filename(self, default_config):
        """The optional filename is attached to the error."""
        validator = XmlSecurityValidator(default_config)
        data = b'<?xml version="1.0"?><!DOCTYPE g [<!ENTITY a "b">]><g/>'
        with pytest.raises(XmlSecurityError) as exc_info:
            validator.validate(
                io.BytesIO(data), extension=".gpx", filename="x.gpx"
            )
        assert exc_info.value.error_code == ErrorCode.XML_DTD_FORBIDDEN
        assert exc_info.value.filename == "x.gpx"


def _gpx_of_size(size: int) -> bytes:
    """Build a valid GPX document of roughly ``size`` bytes."""
    head = b'<?xml version="1.0" encoding="UTF-8"?><gpx><trk><trkseg>'
    point = b'<trkpt lat="45.1" lon="7.1"><ele>100.0</ele></trkpt>'
    return head + point * (size // len(point)) + b"</trkseg></trk></gpx>"


class TestXmlStreamingParse:
    """Tests for the chunked, tree-free XML parse."""

    def test_large_gpx_parses_in_small_memory(self, default_config):
        """Peak allocation stays far below the document size."""
        validator = XmlSecurityValidator(default_config)
        data = _gpx_of_size(10 * 1024 * 1024)
        file_obj = io.BytesIO(data)

        tracemalloc.start()
        try:
            validator.validate_xml_safety(file_obj, extension=".gpx")
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        assert peak < len(data) // 20

    def test_tiny_chunks_split_multibyte_text(self):
        """Chunk boundaries inside UTF-8 characters still parse."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(chunk_size=3)
        validator = XmlSecurityValidator(config)
        data = (
            "\ufeff<?xml version='1.0' encoding='UTF-8'?>"
            "<gpx><name>Läufer 🏃 über Brücke</name></gpx>"
        ).encode()
        validator.validate_xml_safety(io.BytesIO(data), extension=".gpx")

    def test_tiny_chunks_still_reject_dtd(self):
        """A DOCTYPE split across chunks is still forbidden."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(chunk_size=3)
        validator = XmlSecurityValidator(config)
        data = b'<?xml version="1.0"?><!DOCTYPE g [<!ENTITY a "b">]><g/>'
        with pytest.raises(XmlSecurityError, match="DTD") as exc_info:
            validator.validate_xml_safety(io.BytesIO(data), extension=".gpx")
        assert exc_info.value.error_code == ErrorCode.XML_DTD_FORBIDDEN

    def test_parse_within_budget_passes(self, default_config, fake_clock):
        """A parse that stays in budget is accepted."""
        validator = XmlSecurityValidator(default_config)
        data = _gpx_of_size(1536 * 1024)
        fake_clock.step = 0.01

        fake_clock.run_monitored(
            lambda: validator.validate_xml_safety(
                io.BytesIO(data), extension=".gpx"
            )
        )

    def test_parse_over_budget_raises_unchanged(
        self, default_config, fake_clock
    ):
        """A slow parse raises ResourceLimitError, not a parse error."""
        validator = XmlSecurityValidator(default_config)
        data = _gpx_of_size(1536 * 1024)

        with pytest.raises(ResourceLimitError) as exc_info:
            fake_clock.run_monitored(
                lambda: validator.validate_xml_safety(
                    io.BytesIO(data), extension=".gpx"
                )
            )

        assert type(exc_info.value) is ResourceLimitError
        assert exc_info.value.error_code == ErrorCode.RESOURCE_TIME_EXCEEDED


_XSLT_AS_GPX = (
    b'<?xml version="1.0"?>'
    b'<xsl:stylesheet version="1.0"'
    b' xmlns:xsl="http://www.w3.org/1999/XSL/Transform">'
    b'<xsl:template match="/">'
    b"<html><script>alert(1)</script></html>"
    b"</xsl:template>"
    b"</xsl:stylesheet>"
)


class TestXmlRootElement:
    """The root element must be the one the extension names."""

    @pytest.mark.parametrize(
        ("extension", "data"),
        [
            (".gpx", b"<gpx/>"),
            (
                ".gpx",
                b'<gpx xmlns="http://www.topografix.com/GPX/1/0"'
                b' version="1.0"/>',
            ),
            (
                ".gpx",
                b'<gpx xmlns="http://www.topografix.com/GPX/1/1"'
                b' version="1.1"><trk/></gpx>',
            ),
            (
                ".gpx",
                b'<g:gpx xmlns:g="http://www.topografix.com/GPX/1/1"/>',
            ),
            (".tcx", b"<TrainingCenterDatabase/>"),
            (
                ".tcx",
                b"<TrainingCenterDatabase xmlns="
                b'"http://www.garmin.com/xmlschemas/'
                b'TrainingCenterDatabase/v2"><Activities/>'
                b"</TrainingCenterDatabase>",
            ),
            (".GPX", b"<gpx/>"),
        ],
        ids=[
            "gpx-bare",
            "gpx-1.0",
            "gpx-1.1",
            "gpx-prefixed",
            "tcx-bare",
            "tcx-v2",
            "uppercase-extension",
        ],
    )
    def test_expected_root_accepted(self, default_config, extension, data):
        """The local name matches whatever namespace it is in."""
        validator = XmlSecurityValidator(default_config)
        document = b'<?xml version="1.0" encoding="UTF-8"?>' + data

        validator.validate_xml_safety(
            io.BytesIO(document), extension=extension
        )

    @pytest.mark.parametrize(
        ("extension", "data"),
        [
            (".gpx", _XSLT_AS_GPX),
            (".gpx", b'<?xml version="1.0"?><html><script/></html>'),
            (".gpx", b'<?xml version="1.0"?><GPX/>'),
            (".gpx", b'<?xml version="1.0"?><gpxx/>'),
            (".gpx", b'<?xml version="1.0"?><TrainingCenterDatabase/>'),
            (".tcx", b'<?xml version="1.0"?><gpx/>'),
            (".tcx", _XSLT_AS_GPX),
        ],
        ids=[
            "xslt-as-gpx",
            "html-as-gpx",
            "uppercase-root",
            "longer-root",
            "tcx-as-gpx",
            "gpx-as-tcx",
            "xslt-as-tcx",
        ],
    )
    def test_other_root_rejected(self, default_config, extension, data):
        """A well-formed document with another root is rejected."""
        validator = XmlSecurityValidator(default_config)

        with pytest.raises(XmlSecurityError) as exc_info:
            validator.validate_xml_safety(
                io.BytesIO(data), extension=extension, filename="a.gpx"
            )

        assert exc_info.value.error_code == ErrorCode.XML_ROOT_MISMATCH
        assert exc_info.value.filename == "a.gpx"

    def test_nested_expected_element_does_not_count(self, default_config):
        """Only the root element is compared, not a nested one."""
        validator = XmlSecurityValidator(default_config)
        data = b'<?xml version="1.0"?><html><gpx/></html>'

        with pytest.raises(XmlSecurityError) as exc_info:
            validator.validate_xml_safety(io.BytesIO(data), extension=".gpx")

        assert exc_info.value.error_code == ErrorCode.XML_ROOT_MISMATCH

    def test_root_split_across_chunks(self):
        """A root start tag split across chunks is still recognized."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(chunk_size=3)
        validator = XmlSecurityValidator(config)
        data = b'<?xml version="1.0"?><TrainingCenterDatabase/>'

        validator.validate_xml_safety(io.BytesIO(data), extension=".tcx")

    @pytest.mark.parametrize("extension", [".xml", ".fit", ""])
    def test_extension_without_known_root_rejected(
        self, default_config, extension
    ):
        """An extension with no expected root fails closed."""
        validator = XmlSecurityValidator(default_config)

        with pytest.raises(XmlSecurityError) as exc_info:
            validator.validate_xml_safety(
                io.BytesIO(b'<?xml version="1.0"?><gpx/>'),
                extension=extension,
            )

        assert exc_info.value.error_code == ErrorCode.XML_ROOT_MISMATCH
