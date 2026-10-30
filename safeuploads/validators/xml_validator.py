"""XXE-safe XML validator for GPX/TCX activity files."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from xml.etree.ElementTree import ParseError

from defusedxml import ElementTree as DefusedET
from defusedxml.common import (
    DTDForbidden,
    EntitiesForbidden,
    ExternalReferenceForbidden,
)

from ..exceptions import FileProcessingError, ResourceLimitError
from ..utils import check_resource_limits
from .base import BaseValidator

if TYPE_CHECKING:
    from ..config import FileSecurityConfig
    from ..protocols import SeekableFile


logger = logging.getLogger(__name__)


class _DiscardTarget:
    """
    Parser target with no callbacks, so parsing builds nothing.

    ``XMLParser`` installs element, text, comment and PI handlers
    only for the callbacks its target defines; this target defines
    none, so the document is checked without keeping any of it.
    """


class XmlSecurityValidator(BaseValidator):
    """
    Validates XML-based activity files for XXE and entity attacks.

    Uses ``defusedxml`` to parse XML safely. Rejects files
    containing DTD declarations, external entities, or
    excessive entity expansion.

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

    def validate_xml_safety(self, file_obj: SeekableFile) -> None:
        """
        Parse XML with XXE protections and validate structure.

        The document is fed to ``defusedxml``'s parser in chunks of
        ``limits.chunk_size`` with a target that builds no element
        tree, so memory does not grow with the number of elements
        (expat buffers only the token it is parsing); resource
        limits are checked after every chunk.

        Args:
            file_obj: Seekable file containing XML data.

        Raises:
            FileProcessingError: If the XML is malformed, contains
                XXE attacks, or fails safety checks.
            ResourceLimitError: If the active resource monitor's
                time or memory limit is exceeded.
        """
        file_obj.seek(0)
        chunk_size = self.config.limits.chunk_size

        logger.debug("Parsing activity XML with XXE protections")
        try:
            # defusedxml blocks external entities and
            # entity expansion by default.
            # forbid_dtd=True rejects ALL DTD declarations.
            parser = DefusedET.DefusedXMLParser(
                target=_DiscardTarget(), forbid_dtd=True
            )
            while chunk := file_obj.read(chunk_size):
                parser.feed(chunk)
                check_resource_limits()
            parser.close()
        except ResourceLimitError:
            raise
        except DTDForbidden as err:
            logger.warning("XML contains forbidden DTD declaration")
            raise FileProcessingError(
                "XML contains forbidden DTD declaration"
            ) from err
        except EntitiesForbidden as err:
            logger.warning("XML contains forbidden entity reference")
            raise FileProcessingError(
                "XML contains forbidden external entity"
            ) from err
        except ExternalReferenceForbidden as err:
            logger.warning("XML contains forbidden external reference")
            raise FileProcessingError(
                "XML contains forbidden external reference"
            ) from err
        except ParseError as err:
            logger.warning("Malformed XML: %s", err)
            raise FileProcessingError("Malformed XML content") from err
        except Exception as err:
            logger.warning("XML validation failed: %s", err)
            raise FileProcessingError("XML validation failed") from err

        logger.debug("XML safety validation passed")
        file_obj.seek(0)

    def validate(self, file_obj: SeekableFile) -> None:
        """
        Validate XML file for security threats.

        Args:
            file_obj: Seekable file containing XML data.

        Raises:
            FileProcessingError: If the XML fails safety checks.
        """
        return self.validate_xml_safety(file_obj)
