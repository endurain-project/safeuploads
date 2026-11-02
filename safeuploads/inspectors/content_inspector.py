"""Content security inspector for malware and polyglots.

Scans raw file bytes for embedded malware signatures,
script injection, and polyglot file threats that pass
MIME/signature/extension checks.  Gated behind
``enable_content_analysis`` in ``SecurityLimits``.
"""

from __future__ import annotations

import functools
import logging
import re
from typing import TYPE_CHECKING

from ..audit import get_correlation_id, log_extra
from ..enums import MalwareSignatureCategory, SuspiciousFilePattern
from ..utils import find_embedded_signature, find_text_pattern
from .base import BaseInspector

if TYPE_CHECKING:
    from ..config import FileSecurityConfig


logger = logging.getLogger(__name__)

# Script patterns checked against the lower-cased content,
# sourced from the shared SuspiciousFilePattern enum. The bare
# "<%" is left out: this scan covers whole binary samples, where
# a 2-byte marker occurs by chance. ASP/JSP is detected by the
# distinctive WEBSHELL_PATTERNS markers instead, added here so
# they also match in any letter case.
_SCRIPT_PATTERNS: tuple[str, ...] = tuple(
    pattern
    for pattern in SuspiciousFilePattern.SCRIPT_PATTERNS.value
    if pattern != "<%"
) + tuple(
    sig.decode("ascii").lower()
    for sig in MalwareSignatureCategory.WEBSHELL_PATTERNS.value
)

# Header structure that must follow an executable magic before it
# is reported. A bare 2-4 byte magic occurs by chance in random
# data (images, compressed streams), so each format is verified.
# Mach-O CPU types (x86, x86-64, ARM, ARM64, ARM64_32, PPC, PPC64)
# as 4 bytes, and file types 1-12 (MH_OBJECT to MH_FILESET).
_CPU_BE = rb"[\x00-\x02]\x00\x00[\x07\x0c\x12]"
_CPU_LE = rb"[\x07\x0c\x12]\x00\x00[\x00-\x02]"
_FILETYPE_BE = rb"\x00\x00\x00[\x01-\x0c]"
_FILETYPE_LE = rb"[\x01-\x0c]\x00\x00\x00"
# Shell Link CLSID {00021401-0000-0000-C000-000000000046} in its
# on-disk (little-endian fields) byte order.
_LNK_CLSID = (
    b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
)
# Java class files carry minor then major version (45 = Java 1.1);
# universal Mach-O binaries carry a big-endian architecture count
# below 45 followed by the first architecture's CPU type. The
# ranges do not overlap.
_JAVA_VERSION = rb"..\x00[\x2d-\x7f]"
_FAT_HEADER = rb"\x00\x00\x00[\x01-\x2c]" + _CPU_BE
# PE: the DOS header is 64 bytes and ends with the little-endian
# u32 ``e_lfanew``. Every ``MZ`` followed by a full DOS header is
# a candidate, except those whose ``e_lfanew`` points past the
# content: the most significant byte of ``e_lfanew`` (the last
# header byte) can be at most ``(len(content) - 1) >> 24``. The
# lookahead keeps scanning in C and leaves overlapping candidates
# to be found.
_PE_MAGIC_BYTES = next(iter(MalwareSignatureCategory.PE_EXECUTABLE.value))
_PE_MAGIC = b"PE\x00\x00"
_PE_MIN_OFFSET = 4


@functools.lru_cache(maxsize=256)
def _pe_candidate(max_high_byte: int) -> re.Pattern[bytes]:
    """
    Compile the PE candidate pattern for a content-length bound.

    Args:
        max_high_byte: Largest value (0-255) the most significant
            byte of ``e_lfanew`` may take.

    Returns:
        A pattern matching ``MZ`` followed by a full DOS header
        whose last byte is at most ``max_high_byte``.
    """
    return re.compile(
        re.escape(_PE_MAGIC_BYTES)
        + rb"(?=.{61}[\x00-"
        + b"\\x%02x" % max_high_byte
        + rb"])",
        re.DOTALL,
    )


def _build_executable_patterns() -> tuple[tuple[str, re.Pattern[bytes]], ...]:
    """
    Build the structural pattern for each executable format.

    Returns:
        ``(label, compiled pattern)`` pairs, one per format. A
        pattern matches only a magic followed by a plausible
        header.
    """
    escape = re.escape
    patterns: list[tuple[str, re.Pattern[bytes]]] = []
    for magic in MalwareSignatureCategory.ELF_EXECUTABLE.value:
        patterns.append(
            (
                "ELF executable",
                re.compile(
                    escape(magic) + rb"[\x01\x02][\x01\x02]\x01", re.DOTALL
                ),
            )
        )
    for magic in MalwareSignatureCategory.MACHO_EXECUTABLE.value:
        # Big-endian magics start with 0xfe, little-endian with 0xce
        # or 0xcf.
        if magic[0] == 0xFE:
            tail = _CPU_BE + rb".{4}" + _FILETYPE_BE
        else:
            tail = _CPU_LE + rb".{4}" + _FILETYPE_LE
        patterns.append(
            ("Mach-O executable", re.compile(escape(magic) + tail, re.DOTALL))
        )
    for magic in MalwareSignatureCategory.JAVA_CLASS.value:
        patterns.append(
            (
                "Java class file",
                re.compile(escape(magic) + _JAVA_VERSION, re.DOTALL),
            )
        )
        patterns.append(
            (
                "universal Mach-O executable",
                re.compile(escape(magic) + _FAT_HEADER, re.DOTALL),
            )
        )
    for magic in MalwareSignatureCategory.WINDOWS_SHORTCUT.value:
        patterns.append(
            (
                "Windows shortcut",
                re.compile(escape(magic + _LNK_CLSID), re.DOTALL),
            )
        )
    return tuple(patterns)


_EXECUTABLE_PATTERNS = _build_executable_patterns()
_JAVA_CLASS_PATTERNS = tuple(
    pattern
    for label, pattern in _EXECUTABLE_PATTERNS
    if label == "Java class file"
)


def _find_pe(content: bytes) -> bool:
    """
    Return whether a structurally valid PE header is present.

    A PE header is an ``MZ`` DOS header whose 32-bit ``e_lfanew``
    field points at the PE signature inside the content. The
    candidate pattern only drops headers whose ``e_lfanew`` points
    past the content.

    Args:
        content: Raw bytes to inspect.

    Returns:
        True if a structurally valid PE header is found.
    """
    pattern = _pe_candidate(min(0xFF, max(0, len(content) - 1) >> 24))
    for match in pattern.finditer(content):
        offset = match.start()
        e_lfanew = int.from_bytes(
            content[offset + 0x3C : offset + 0x40], "little"
        )
        if e_lfanew >= _PE_MIN_OFFSET and content.startswith(
            _PE_MAGIC, offset + e_lfanew
        ):
            return True
    return False


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

        self._webshell_sigs: tuple[bytes, ...] = tuple(
            MalwareSignatureCategory.WEBSHELL_PATTERNS.value
        )
        # The Java class magic is verified structurally instead.
        self._polyglot_sigs: tuple[bytes, ...] = tuple(
            sig
            for sig in MalwareSignatureCategory.POLYGLOT_SIGNATURES.value
            if sig not in MalwareSignatureCategory.JAVA_CLASS.value
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

        logger.debug("Scanning content of %r for embedded threats", filename)

        # 1. Executable signature scan
        threats.extend(self._check_executable_signatures(content, filename))

        # 2. Script injection scan
        threats.extend(self._check_script_patterns(content, filename))

        # 3. Polyglot detection
        threats.extend(self._check_polyglot(content, filename, expected_type))

        if threats:
            logger.warning(
                "Content analysis threats detected in %r: %r",
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
            logger.debug("Content scan clean for %r", filename)

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
        label = self._find_executable(content)
        if label is not None:
            return [f"Executable signature detected in '{filename}': {label}"]
        return []

    @staticmethod
    def _find_executable(content: bytes) -> str | None:
        """
        Find an executable header whose structure verifies.

        Args:
            content: Raw bytes to inspect.

        Returns:
            Label of the first executable format found, or None.
        """
        if _find_pe(content):
            return "PE executable"
        for label, pattern in _EXECUTABLE_PATTERNS:
            if pattern.search(content):
                return label
        return None

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

        Looks for secondary format signatures anywhere in the
        content. Only runs for image and activity
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

        # Search the whole content: no signed image or activity
        # file starts with a polyglot signature, so a match at any
        # offset, including right after a 3-byte JPEG header, is a
        # secondary format. A Java class magic counts only with a
        # valid class-file version.
        sig = find_embedded_signature(content, self._polyglot_sigs, 0)
        if sig is None and any(
            pattern.search(content) for pattern in _JAVA_CLASS_PATTERNS
        ):
            sig = next(iter(MalwareSignatureCategory.JAVA_CLASS.value))
        if sig is not None:
            return [
                f"Polyglot file detected"
                f" in '{filename}':"
                f" secondary signature {sig!r}"
                f" found in content"
            ]
        return []
