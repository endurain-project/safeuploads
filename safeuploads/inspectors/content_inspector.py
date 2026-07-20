"""Content security inspector for malware and polyglots.

Scans raw file bytes for embedded malware signatures,
script injection, and polyglot file threats that pass
MIME/signature/extension checks.  Gated behind
``enable_content_analysis`` in ``SecurityLimits``.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ..audit import get_correlation_id, log_extra
from ..enums import MalwareSignatureCategory, SuspiciousFilePattern
from ..utils import find_embedded_signature, find_text_pattern
from .base import BaseInspector

if TYPE_CHECKING:
    from ..config import FileSecurityConfig


logger = logging.getLogger(__name__)

# Script patterns checked against decoded text content,
# sourced from the shared SuspiciousFilePattern enum.
_SCRIPT_PATTERNS: tuple[str, ...] = tuple(
    SuspiciousFilePattern.SCRIPT_PATTERNS.value
)


class ContentSecurityInspector(BaseInspector):
    """
    Scans file content for embedded malware and scripts.

    Three detection layers:
    1. **Executable signatures** — PE, ELF, Mach-O, Java
       class headers in files that should not be executables.
    2. **Script injection** — Common web shell and script
       markers in non-script files.
    3. **Polyglot detection** — Secondary format signatures
       (ZIP/JAR, RAR, Java class) embedded after a valid
       image or document header.

    Attributes:
        config: File security configuration.
    """

    def __init__(self, config: FileSecurityConfig):
        """
        Initialize the content inspector.

        Args:
            config: File security configuration.
        """
        super().__init__(config)

        # Pre-compile signature sets
        self._executable_sigs: tuple[bytes, ...] = tuple(
            sig
            for cat in (
                MalwareSignatureCategory.PE_EXECUTABLE,
                MalwareSignatureCategory.ELF_EXECUTABLE,
                MalwareSignatureCategory.MACHO_EXECUTABLE,
                MalwareSignatureCategory.JAVA_CLASS,
                MalwareSignatureCategory.WINDOWS_SHORTCUT,
            )
            for sig in cat.value
        )
        self._webshell_sigs: tuple[bytes, ...] = tuple(
            MalwareSignatureCategory.WEBSHELL_PATTERNS.value
        )
        self._polyglot_sigs: tuple[bytes, ...] = tuple(
            MalwareSignatureCategory.POLYGLOT_SIGNATURES.value
        )

    def scan_content(
        self,
        content: bytes,
        filename: str = "",
        expected_type: str = "",
    ) -> list[str]:
        """
        Scan file content for embedded threats.

        Args:
            content: Raw bytes to inspect (typically the
                first ``content_scan_max_size`` bytes).
            filename: Original filename for context.
            expected_type: Logical file type the content
                should represent (e.g. "image", "zip").

        Returns:
            List of threat descriptions found. Empty list
            means content is clean.
        """
        threats: list[str] = []

        logger.debug("Scanning content of '%s' for embedded threats", filename)

        # 1. Executable signature scan
        threats.extend(self._check_executable_signatures(content, filename))

        # 2. Script injection scan
        threats.extend(self._check_script_patterns(content, filename))

        # 3. Polyglot detection
        threats.extend(self._check_polyglot(content, filename, expected_type))

        if threats:
            logger.warning(
                "Content analysis threats detected in '%s': %s",
                filename,
                "; ".join(threats),
                extra=log_extra(),
            )
            cid = get_correlation_id()
            if cid:
                self._audit.threat(
                    filename,
                    cid,
                    "; ".join(threats),
                )
        else:
            logger.debug("Content scan clean for '%s'", filename)

        return threats

    def _check_executable_signatures(
        self, content: bytes, filename: str
    ) -> list[str]:
        """
        Check for embedded executable headers in content.

        Args:
            content: Raw bytes to inspect.
            filename: Filename for context.

        Returns:
            List of threat descriptions.
        """
        sig = find_embedded_signature(content, self._executable_sigs)
        if sig is not None:
            return [f"Executable signature detected in '{filename}': {sig!r}"]
        return []

    def _check_script_patterns(
        self, content: bytes, filename: str
    ) -> list[str]:
        """
        Check for script injection markers.

        Args:
            content: Raw bytes to inspect.
            filename: Filename for context.

        Returns:
            List of threat descriptions.
        """
        threats: list[str] = []

        # Binary-level web shell signatures
        sig = find_embedded_signature(content, self._webshell_sigs)
        if sig is not None:
            threats.append(
                f"Web shell signature detected in '{filename}': {sig!r}"
            )

        # Text-level script pattern scan
        pattern = find_text_pattern(content, _SCRIPT_PATTERNS)
        if pattern is not None:
            threats.append(
                f"Script pattern detected in '{filename}': '{pattern}'"
            )

        return threats

    def _check_polyglot(
        self,
        content: bytes,
        filename: str,
        expected_type: str,
    ) -> list[str]:
        """
        Check for polyglot files (valid in multiple formats).

        Looks for secondary format signatures embedded after
        the expected header. Only runs for image and activity
        file types where polyglot attacks are most dangerous.

        Args:
            content: Raw bytes to inspect.
            filename: Filename for context.
            expected_type: Expected file type ("image", etc.)

        Returns:
            List of threat descriptions.
        """
        if expected_type not in ("image", "activity"):
            return []

        # Skip first 8 bytes (longest common header is
        # PNG at 8 bytes) and search rest for secondary
        # signatures to detect polyglot files
        tail = content[8:]
        sig = find_embedded_signature(tail, self._polyglot_sigs)
        if sig is not None:
            return [
                f"Polyglot file detected"
                f" in '{filename}':"
                f" secondary signature {sig!r}"
                f" found after header"
            ]
        return []
