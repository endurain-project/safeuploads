"""Tests for XmlSecurityValidator."""

import io
import tracemalloc

import pytest

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.exceptions import (
    ErrorCode,
    FileProcessingError,
    ResourceLimitError,
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
        validator.validate_xml_safety(file_obj)

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
        validator.validate_xml_safety(file_obj)

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
            FileProcessingError, match="forbidden DTD declaration"
        ):
            validator.validate_xml_safety(file_obj)

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
            FileProcessingError, match="forbidden DTD declaration"
        ):
            validator.validate_xml_safety(file_obj)

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
            FileProcessingError, match="forbidden DTD declaration"
        ):
            validator.validate_xml_safety(file_obj)

    def test_reject_malformed_xml(self, default_config):
        """Test rejection of malformed XML."""
        validator = XmlSecurityValidator(default_config)
        bad_xml = b"<gpx><unclosed>"
        file_obj = io.BytesIO(bad_xml)
        with pytest.raises(FileProcessingError, match="Malformed"):
            validator.validate_xml_safety(file_obj)

    def test_reject_non_xml_content(self, default_config):
        """Test rejection of non-XML content."""
        validator = XmlSecurityValidator(default_config)
        file_obj = io.BytesIO(b"This is not XML at all.")
        with pytest.raises(FileProcessingError):
            validator.validate_xml_safety(file_obj)

    def test_validate_delegates_to_validate_xml_safety(self, default_config):
        """Test validate() delegates correctly."""
        validator = XmlSecurityValidator(default_config)
        valid_xml = b"<root/>"
        file_obj = io.BytesIO(valid_xml)
        validator.validate(file_obj)

    def test_file_position_reset_after_validation(self, default_config):
        """Test file position is reset after validation."""
        validator = XmlSecurityValidator(default_config)
        valid_xml = b"<root><child/></root>"
        file_obj = io.BytesIO(valid_xml)
        file_obj.seek(5)
        validator.validate_xml_safety(file_obj)
        assert file_obj.tell() == 0

    def test_xml_with_bom(self, default_config):
        """Test XML with byte order mark passes."""
        validator = XmlSecurityValidator(default_config)
        bom_xml = b'\xef\xbb\xbf<?xml version="1.0" encoding="UTF-8"?><root/>'
        file_obj = io.BytesIO(bom_xml)
        validator.validate_xml_safety(file_obj)

    def test_empty_xml_document_rejected(self, default_config):
        """Test empty content is rejected."""
        validator = XmlSecurityValidator(default_config)
        file_obj = io.BytesIO(b"")
        with pytest.raises(FileProcessingError):
            validator.validate_xml_safety(file_obj)


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
    def test_entities_forbidden_raises(self, default_config, monkeypatch):
        from defusedxml import ElementTree as DefusedET

        import safeuploads.validators.xml_validator as _mod

        validator = XmlSecurityValidator(default_config)
        error = DefusedET.EntitiesForbidden(
            "entity", None, None, None, None, None
        )
        monkeypatch.setattr(
            _mod.DefusedET, "DefusedXMLParser", _parser_failing_with(error)
        )
        with pytest.raises(FileProcessingError, match="entity"):
            validator.validate_xml_safety(io.BytesIO(b"<root/>"))

    def test_external_ref_forbidden_raises(self, default_config, monkeypatch):
        from defusedxml import ElementTree as DefusedET

        import safeuploads.validators.xml_validator as _mod

        validator = XmlSecurityValidator(default_config)
        error = DefusedET.ExternalReferenceForbidden("ref", None, None, None)
        monkeypatch.setattr(
            _mod.DefusedET, "DefusedXMLParser", _parser_failing_with(error)
        )
        with pytest.raises(FileProcessingError, match="external"):
            validator.validate_xml_safety(io.BytesIO(b"<root/>"))

    def test_unexpected_exception_raises(self, default_config, monkeypatch):
        import safeuploads.validators.xml_validator as _mod

        validator = XmlSecurityValidator(default_config)
        monkeypatch.setattr(
            _mod.DefusedET,
            "DefusedXMLParser",
            _parser_failing_with(OSError("disk failure")),
        )
        with pytest.raises(FileProcessingError, match="failed"):
            validator.validate_xml_safety(io.BytesIO(b"<root/>"))


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
            validator.validate_xml_safety(file_obj)
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
        validator.validate_xml_safety(io.BytesIO(data))

    def test_tiny_chunks_still_reject_dtd(self):
        """A DOCTYPE split across chunks is still forbidden."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(chunk_size=3)
        validator = XmlSecurityValidator(config)
        data = b'<?xml version="1.0"?><!DOCTYPE g [<!ENTITY a "b">]><g/>'
        with pytest.raises(FileProcessingError, match="DTD"):
            validator.validate_xml_safety(io.BytesIO(data))

    def test_parse_within_budget_passes(self, default_config, fake_clock):
        """A parse that stays in budget is accepted."""
        validator = XmlSecurityValidator(default_config)
        data = _gpx_of_size(1536 * 1024)
        fake_clock.step = 0.01

        fake_clock.run_monitored(
            lambda: validator.validate_xml_safety(io.BytesIO(data))
        )

    def test_parse_over_budget_raises_unchanged(
        self, default_config, fake_clock
    ):
        """A slow parse raises ResourceLimitError, not a parse error."""
        validator = XmlSecurityValidator(default_config)
        data = _gpx_of_size(1536 * 1024)

        with pytest.raises(ResourceLimitError) as exc_info:
            fake_clock.run_monitored(
                lambda: validator.validate_xml_safety(io.BytesIO(data))
            )

        assert type(exc_info.value) is ResourceLimitError
        assert exc_info.value.error_code == ErrorCode.RESOURCE_TIME_EXCEEDED
