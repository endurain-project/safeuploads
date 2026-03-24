"""
XXE-safe XML validator for GPX/TCX activity files.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from xml.etree.ElementTree import ParseError

from defusedxml import ElementTree as DefusedET

from .base import BaseValidator
from ..exceptions import FileProcessingError

if TYPE_CHECKING:
    from ..protocols import SeekableFile
    from ..config import FileSecurityConfig


logger = logging.getLogger(__name__)


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

    def validate_xml_safety(
        self, file_obj: SeekableFile
    ) -> None:
        """
        Parse XML with XXE protections and validate structure.

        Args:
            file_obj: Seekable file containing XML data.

        Raises:
            FileProcessingError: If the XML is malformed, contains
                XXE attacks, or fails safety checks.
        """
        file_obj.seek(0)

        try:
            # defusedxml blocks external entities and
            # entity expansion by default.
            # forbid_dtd=True rejects ALL DTD declarations.
            DefusedET.parse(file_obj, forbid_dtd=True)
        except DefusedET.DTDForbidden:
            logger.warning("XML contains forbidden DTD declaration")
            raise FileProcessingError(
                "XML contains forbidden DTD declaration"
            )
        except DefusedET.EntitiesForbidden:
            logger.warning("XML contains forbidden entity reference")
            raise FileProcessingError(
                "XML contains forbidden external entity"
            )
        except DefusedET.ExternalReferenceForbidden:
            logger.warning("XML contains forbidden external reference")
            raise FileProcessingError(
                "XML contains forbidden external reference"
            )
        except ParseError as err:
            logger.warning("Malformed XML: %s", err)
            raise FileProcessingError(
                "Malformed XML content"
            ) from err
        except Exception as err:
            logger.warning("XML validation failed: %s", err)
            raise FileProcessingError(
                "XML validation failed"
            ) from err

        file_obj.seek(0)

    def validate(
        self, file_obj: SeekableFile
    ) -> None:
        """
        Validate XML file for security threats.

        Args:
            file_obj: Seekable file containing XML data.

        Raises:
            FileProcessingError: If the XML fails safety checks.
        """
        return self.validate_xml_safety(file_obj)
