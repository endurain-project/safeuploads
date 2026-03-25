"""Tests for XmlSecurityValidator."""

import io

import pytest

from safeuploads.config import FileSecurityConfig
from safeuploads.exceptions import FileProcessingError
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
            b"<trkpt lat=\"0\" lon=\"0\"/>"
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
            b"<Activities><Activity Sport=\"Running\">"
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
        with pytest.raises(FileProcessingError):
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
        with pytest.raises(FileProcessingError):
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
        with pytest.raises(FileProcessingError):
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

    def test_validate_delegates_to_validate_xml_safety(
        self, default_config
    ):
        """Test validate() delegates correctly."""
        validator = XmlSecurityValidator(default_config)
        valid_xml = b"<root/>"
        file_obj = io.BytesIO(valid_xml)
        validator.validate(file_obj)

    def test_file_position_reset_after_validation(
        self, default_config
    ):
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
        bom_xml = (
            b"\xef\xbb\xbf"
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b"<root/>"
        )
        file_obj = io.BytesIO(bom_xml)
        validator.validate_xml_safety(file_obj)

    def test_empty_xml_document_rejected(self, default_config):
        """Test empty content is rejected."""
        validator = XmlSecurityValidator(default_config)
        file_obj = io.BytesIO(b"")
        with pytest.raises(FileProcessingError):
            validator.validate_xml_safety(file_obj)


class TestXmlValidatorDefusedxmlBranches:
    def test_entities_forbidden_raises(
        self, default_config, monkeypatch
    ):
        import safeuploads.validators.xml_validator as _mod
        from defusedxml import ElementTree as DefusedET

        validator = XmlSecurityValidator(default_config)

        def _raise_entities(*a, **kw):
            raise DefusedET.EntitiesForbidden(
                "entity", None, None, None, None, None
            )

        monkeypatch.setattr(_mod.DefusedET, "parse", _raise_entities)
        with pytest.raises(
            FileProcessingError, match="entity"
        ):
            validator.validate_xml_safety(io.BytesIO(b"<root/>"))

    def test_external_ref_forbidden_raises(
        self, default_config, monkeypatch
    ):
        import safeuploads.validators.xml_validator as _mod
        from defusedxml import ElementTree as DefusedET

        validator = XmlSecurityValidator(default_config)

        def _raise_ext(*a, **kw):
            raise DefusedET.ExternalReferenceForbidden(
                "ref", None, None, None
            )

        monkeypatch.setattr(_mod.DefusedET, "parse", _raise_ext)
        with pytest.raises(
            FileProcessingError, match="external"
        ):
            validator.validate_xml_safety(io.BytesIO(b"<root/>"))

    def test_unexpected_exception_raises(
        self, default_config, monkeypatch
    ):
        import safeuploads.validators.xml_validator as _mod

        validator = XmlSecurityValidator(default_config)

        def _raise_generic(*a, **kw):
            raise OSError("disk failure")

        monkeypatch.setattr(_mod.DefusedET, "parse", _raise_generic)
        with pytest.raises(
            FileProcessingError, match="failed"
        ):
            validator.validate_xml_safety(io.BytesIO(b"<root/>"))
