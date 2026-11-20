"""XXE-safe XML validator for GPX/TCX activity files."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from xml.etree.ElementTree import ParseError

from defusedxml import ElementTree as DefusedET
from defusedxml.common import DTDForbidden

from ..exceptions import (
    ErrorCode,
    FileProcessingError,
    ResourceLimitError,
    XmlSecurityError,
)
from ..utils import check_resource_limits
from .base import BaseValidator

if TYPE_CHECKING:
    from ..config import FileSecurityConfig
    from ..protocols import SeekableFile


logger = logging.getLogger(__name__)


# Local name of the root element each activity XML format requires.
# GPX and TCX files in use carry different namespace versions, so
# the namespace is not compared.
_ROOT_ELEMENTS: dict[str, str] = {
    ".gpx": "gpx",
    ".tcx": "TrainingCenterDatabase",
}


class _RootTarget:
    """
    Parser target that keeps only the root element's local name.

    ``XMLParser`` installs element, text, comment and PI handlers
    only for the callbacks its target defines; this target defines
    ``start`` alone and keeps nothing after the first element, so
    the document is checked without building a tree.

    Attributes:
        root: Local name of the root element, or None before the
            first start tag.
    """

    def __init__(self) -> None:
        """Initialize with no root element seen."""
        self.root: str | None = None

    def start(self, tag: str, attrib: dict[str, str]) -> None:
        """
        Record the local name of the first element.

        Args:
            tag: Element name, as ``{namespace}local`` when
                namespaced.
            attrib: Element attributes (unused).
        """
        if self.root is None:
            self.root = tag.rpartition("}")[2]


class XmlSecurityValidator(BaseValidator):
    """
    Validates XML-based activity files for XXE and entity attacks.

    Uses ``defusedxml`` to parse XML safely. Rejects files
    containing DTD declarations, external entities, or
    excessive entity expansion, and files whose root element is
    not the one their GPX or TCX extension requires.

    Attributes:
        config: Security configuration for validation limits.
    """

    def __init__(self, config: FileSecurityConfig):
        """
        Initialize the XML security validator.

        Args:
            config: Security configuration with file limits.
        """
        super().__init__(config)

    def validate_xml_safety(
        self,
        file_obj: SeekableFile,
        *,
        extension: str,
        filename: str | None = None,
    ) -> None:
        """
        Parse XML with XXE protections and validate structure.

        The document is fed to ``defusedxml``'s parser in chunks of
        ``limits.chunk_size`` with a target that builds no element
        tree, so memory does not grow with the number of elements
        (expat buffers only the token it is parsing); resource
        limits are checked after every chunk. The root element's
        local name must be ``gpx`` for ``.gpx`` and
        ``TrainingCenterDatabase`` for ``.tcx``, whatever its
        namespace, so other XML documents (an XSLT stylesheet, XHTML)
        are not accepted under an activity extension.

        Args:
            file_obj: Seekable file containing XML data.
            extension: The file's extension (``.gpx`` or ``.tcx``),
                which selects the required root element.
            filename: Optional sanitized filename for error context.

        Raises:
            XmlSecurityError: If the XML contains a DTD, which is
                the only place entities and external references can
                be declared (XML_DTD_FORBIDDEN), is malformed
                (XML_MALFORMED), or its root element is not the one
                ``extension`` requires (XML_ROOT_MISMATCH).
            FileProcessingError: If reading the file fails
                unexpectedly.
            ResourceLimitError: If the active resource monitor's
                time or memory limit is exceeded.
        """
        expected_root = _ROOT_ELEMENTS.get(extension.lower())
        if expected_root is None:
            raise XmlSecurityError(
                "No XML root element is defined for this file type",
                filename=filename,
                error_code=ErrorCode.XML_ROOT_MISMATCH,
            )

        file_obj.seek(0)
        chunk_size = self.config.limits.chunk_size
        target = _RootTarget()

        logger.debug("Parsing activity XML with XXE protections")
        try:
            # defusedxml blocks external entities and
            # entity expansion by default.
            # forbid_dtd=True rejects ALL DTD declarations.
            parser = DefusedET.DefusedXMLParser(target=target, forbid_dtd=True)
            while chunk := file_obj.read(chunk_size):
                parser.feed(chunk)
                check_resource_limits()
            parser.close()
        except ResourceLimitError:
            raise
        except DTDForbidden as err:
            logger.warning("XML contains forbidden DTD declaration")
            raise XmlSecurityError(
                "XML contains forbidden DTD declaration",
                filename=filename,
                error_code=ErrorCode.XML_DTD_FORBIDDEN,
            ) from err
        except (ParseError, LookupError, ValueError) as err:
            # expat raises ParseError for malformed input; an
            # unknown or unsupported encoding declaration surfaces
            # as LookupError or ValueError.
            logger.warning("Malformed XML: %s", err)
            raise XmlSecurityError(
                "Malformed XML content",
                filename=filename,
                error_code=ErrorCode.XML_MALFORMED,
            ) from err
        except Exception as err:
            logger.warning("XML validation failed: %s", err)
            raise FileProcessingError("XML validation failed") from err

        # A well-formed document always has a root element.
        if target.root != expected_root:
            logger.warning("XML root element is not %s", expected_root)
            raise XmlSecurityError(
                f"XML root element must be <{expected_root}>",
                filename=filename,
                error_code=ErrorCode.XML_ROOT_MISMATCH,
            )

        logger.debug("XML safety validation passed")
        file_obj.seek(0)

    def validate(
        self,
        file_obj: SeekableFile,
        *,
        extension: str,
        filename: str | None = None,
    ) -> None:
        """
        Validate XML file for security threats.

        Args:
            file_obj: Seekable file containing XML data.
            extension: The file's extension (``.gpx`` or ``.tcx``),
                which selects the required root element.
            filename: Optional sanitized filename for error context.

        Raises:
            XmlSecurityError: If the XML fails safety checks.
            FileProcessingError: If reading the file fails
                unexpectedly.
            ResourceLimitError: If a resource limit is exceeded.
        """
        return self.validate_xml_safety(
            file_obj, extension=extension, filename=filename
        )
