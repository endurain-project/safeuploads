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

from ..exceptions import ErrorCode, FileProcessingError
from ..utils import safe_label
from .base import BaseValidator

if TYPE_CHECKING:
    from ..protocols import SeekableFile


logger = logging.getLogger(__name__)


class XmlSecurityValidator(BaseValidator):
    """
    Validates XML-based activity files for XXE and entity attacks.

    Uses ``defusedxml`` to parse XML safely. Rejects files
    containing DTD declarations, external entities, or
    excessive entity expansion. Parsing is incremental and the
    element count is capped, so a flat document with millions of
    elements cannot amplify a bounded upload into an unbounded
    object graph.

    Attributes:
        config: Security configuration for validation limits.
    """

    def validate_xml_safety(
        self,
        file_obj: SeekableFile,
        expected_root: str | None = None,
    ) -> None:
        """
        Parse XML with XXE protections and validate structure.

        Args:
            file_obj: Seekable file containing XML data.
            expected_root: Required root element name, lower-cased
                and namespace-free. Any root configured in
                ``ACTIVITY_XML_ROOTS`` is accepted when omitted.

        Raises:
            FileProcessingError: If the XML is malformed, contains
                XXE attacks, declares an unexpected root element,
                or exceeds the element cap.
        """
        file_obj.seek(0)

        logger.debug("Parsing activity XML with XXE protections")
        try:
            root_tag = self._parse_bounded(file_obj)
        except FileProcessingError:
            raise
        except DTDForbidden as err:
            logger.warning("XML contains forbidden DTD declaration")
            raise FileProcessingError(
                "XML contains forbidden DTD declaration",
                error_code=ErrorCode.XML_FORBIDDEN_CONSTRUCT,
            ) from err
        except EntitiesForbidden as err:
            logger.warning("XML contains forbidden entity reference")
            raise FileProcessingError(
                "XML contains forbidden external entity",
                error_code=ErrorCode.XML_FORBIDDEN_CONSTRUCT,
            ) from err
        except ExternalReferenceForbidden as err:
            logger.warning("XML contains forbidden external reference")
            raise FileProcessingError(
                "XML contains forbidden external reference",
                error_code=ErrorCode.XML_FORBIDDEN_CONSTRUCT,
            ) from err
        except ParseError as err:
            logger.warning("Malformed XML: %s", err)
            raise FileProcessingError(
                "Malformed XML content",
                error_code=ErrorCode.XML_MALFORMED,
            ) from err
        except Exception as err:
            logger.warning("XML validation failed: %s", err)
            raise FileProcessingError("XML validation failed") from err

        self._enforce_root(root_tag, expected_root)

        logger.debug("XML safety validation passed")
        file_obj.seek(0)

    def _parse_bounded(self, file_obj: SeekableFile) -> str | None:
        """
        Parse incrementally, capping the element count.

        Completed elements are discarded as they close so peak
        memory stays flat regardless of document length.

        Args:
            file_obj: Seekable file containing XML data.

        Returns:
            The root element tag, or None for an empty document.

        Raises:
            FileProcessingError: If the element cap is exceeded.
        """
        max_elements = self.config.limits.max_xml_elements
        root = None
        count = 0

        # forbid_dtd=True rejects ALL DTD declarations; external
        # entities and entity expansion are blocked by default.
        events = DefusedET.iterparse(
            file_obj, events=("start", "end"), forbid_dtd=True
        )
        for event, element in events:
            if event == "start":
                count += 1
                if root is None:
                    root = element
                if count > max_elements:
                    logger.warning(
                        "XML element count exceeded: %d > %d",
                        count,
                        max_elements,
                    )
                    raise FileProcessingError(
                        (
                            "XML contains too many elements."
                            f" Maximum allowed: {max_elements}"
                        ),
                        error_code=ErrorCode.XML_TOO_MANY_ELEMENTS,
                    )
            elif element is not root and root is not None:
                element.clear()
                root.clear()

        return None if root is None else str(root.tag)

    def _enforce_root(
        self, root_tag: str | None, expected_root: str | None
    ) -> None:
        """
        Check the document root against the allowed names.

        Args:
            root_tag: Root element tag, possibly namespace-qualified.
            expected_root: Required root name, or None to accept any
                root configured in ``ACTIVITY_XML_ROOTS``.

        Raises:
            FileProcessingError: If the root element is missing or
                not permitted.
        """
        allowed = (
            {expected_root}
            if expected_root is not None
            else set(self.config.ACTIVITY_XML_ROOTS.values())
        )

        if root_tag is None:
            raise FileProcessingError(
                "XML document has no root element",
                error_code=ErrorCode.XML_INVALID_ROOT,
            )

        # ElementTree reports namespaced tags as ``{uri}local``.
        local_name = root_tag.rpartition("}")[2].lower()
        if local_name not in allowed:
            logger.warning(
                "Unexpected XML root element: %s",
                safe_label(local_name, max_length=64),
            )
            raise FileProcessingError(
                (
                    "Unexpected XML root element."
                    f" Expected: {', '.join(sorted(allowed))}"
                ),
                error_code=ErrorCode.XML_INVALID_ROOT,
            )

    def validate(
        self,
        file_obj: SeekableFile,
        expected_root: str | None = None,
    ) -> None:
        """
        Validate XML file for security threats.

        Args:
            file_obj: Seekable file containing XML data.
            expected_root: Required root element name, lower-cased
                and namespace-free.

        Raises:
            FileProcessingError: If the XML fails safety checks.
        """
        return self.validate_xml_safety(file_obj, expected_root)
