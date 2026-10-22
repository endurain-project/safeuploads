"""Content security inspector for malware and polyglots.

Scans raw file bytes for embedded malware signatures,
script injection, and polyglot file threats that pass
MIME/signature/extension checks.  Gated behind
``enable_content_analysis`` in ``SecurityLimits``.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Literal

from ..audit import get_correlation_id, log_extra
from ..enums import MalwareSignatureCategory, SuspiciousFilePattern
from ..utils import (
    find_embedded_signature,
    find_text_pattern,
    in_text_run,
    safe_label,
)
from .base import BaseInspector

if TYPE_CHECKING:
    from ..config import FileSecurityConfig


logger = logging.getLogger(__name__)

# Script patterns checked against decoded text content,
# sourced from the shared SuspiciousFilePattern enum.
_SCRIPT_PATTERNS: tuple[str, ...] = tuple(
    SuspiciousFilePattern.SCRIPT_PATTERNS.value
)

# ----------------------------------------------------------------
# Structural corroboration
#
# Several of these signatures are two to four bytes long and are
# searched for anywhere in a window of up to
# ``content_scan_max_size``. At that length a match is
# overwhelmingly likely to be coincidence: the entropy-coded body
# of any ordinary JPEG contains ``MZ`` roughly once per 64 KB.
# Each short signature is therefore only reported when the bytes
# around it form the header the format actually requires, which a
# real embedded payload carries and random data does not.
# ----------------------------------------------------------------

# Machine values a real PE COFF header declares.
_PE_MACHINES: frozenset[int] = frozenset(
    {
        0x014C,  # i386
        0x0166,  # MIPS little-endian
        0x01A2,  # SH3
        0x01C0,  # ARM
        0x01C2,  # ARM Thumb
        0x01C4,  # ARM Thumb-2
        0x01F0,  # PowerPC
        0x0200,  # Itanium
        0x0EBC,  # EFI byte code
        0x5064,  # RISC-V 64
        0x8664,  # x86-64
        0xAA64,  # ARM64
    }
)

# Compression methods defined by the ZIP specification.
_ZIP_METHODS: frozenset[int] = frozenset(
    {0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 14, 18, 19, 93, 95, 96, 97, 98}
)

# ShellLinkHeader CLSID, fixed for every .lnk file.
_LNK_CLSID = (
    b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
)

# Class file major versions, Java 1.1 through a generous ceiling.
_JAVA_MAJOR_RANGE = range(45, 100)

_MACHO_MAGICS = (
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
)


def _verify_pe_dos_header(content: bytes, offset: int) -> bool:
    """
    Check that an ``MZ`` marker heads a real PE image.

    Args:
        content: Raw bytes being scanned.
        offset: Offset of the ``MZ`` marker.

    Returns:
        True if ``e_lfanew`` points at a PE signature.
    """
    lfanew_at = offset + 0x3C
    if lfanew_at + 4 > len(content):
        return False
    pe_at = offset + int.from_bytes(
        content[lfanew_at : lfanew_at + 4], "little"
    )
    return _verify_pe_signature(content, pe_at)


def _verify_pe_signature(content: bytes, offset: int) -> bool:
    r"""
    Check that a ``PE\0\0`` marker heads a real COFF header.

    Args:
        content: Raw bytes being scanned.
        offset: Offset of the ``PE\0\0`` marker.

    Returns:
        True if the COFF machine field is a known architecture.
    """
    if offset < 0 or content[offset : offset + 4] != b"PE\x00\x00":
        return False
    machine = content[offset + 4 : offset + 6]
    if len(machine) < 2:
        return False
    return int.from_bytes(machine, "little") in _PE_MACHINES


def _verify_elf(content: bytes, offset: int) -> bool:
    r"""
    Check that an ELF magic is followed by a valid identifier.

    Args:
        content: Raw bytes being scanned.
        offset: Offset of the ``\x7fELF`` magic.

    Returns:
        True if class, data encoding and version are valid.
    """
    ident = content[offset + 4 : offset + 7]
    if len(ident) < 3:
        return False
    return ident[0] in (1, 2) and ident[1] in (1, 2) and ident[2] == 1


def _verify_macho(content: bytes, signature: bytes, offset: int) -> bool:
    """
    Check that a Mach-O magic is followed by a valid file type.

    Args:
        content: Raw bytes being scanned.
        signature: The matched Mach-O magic, which selects the
            byte order of the fields that follow it.
        offset: Offset of the magic.

    Returns:
        True if the header declares a defined Mach-O file type.
    """
    order: Literal["big", "little"] = (
        "big" if signature.startswith(b"\xfe") else "little"
    )
    filetype = content[offset + 12 : offset + 16]
    if len(filetype) < 4:
        return False
    return 1 <= int.from_bytes(filetype, order) <= 12


def _verify_java_class(content: bytes, offset: int) -> bool:
    r"""
    Check that a class magic is followed by a real version.

    Args:
        content: Raw bytes being scanned.
        offset: Offset of the ``\xca\xfe\xba\xbe`` magic.

    Returns:
        True if the major version is a released class format.
    """
    major = content[offset + 6 : offset + 8]
    if len(major) < 2:
        return False
    return int.from_bytes(major, "big") in _JAVA_MAJOR_RANGE


def _verify_lnk(content: bytes, offset: int) -> bool:
    r"""
    Check that a shortcut header carries the ShellLink CLSID.

    Args:
        content: Raw bytes being scanned.
        offset: Offset of the ``L\0\0\0`` header size field.

    Returns:
        True if the fixed CLSID follows the header size.
    """
    return content[offset + 4 : offset + 20] == _LNK_CLSID


def _verify_zip_local_header(content: bytes, offset: int) -> bool:
    r"""
    Check that a ZIP local file header is well formed.

    Args:
        content: Raw bytes being scanned.
        offset: Offset of the ``PK\x03\x04`` signature.

    Returns:
        True if the version and compression method are valid.
    """
    header = content[offset + 4 : offset + 10]
    if len(header) < 6:
        return False
    version = int.from_bytes(header[0:2], "little")
    method = int.from_bytes(header[4:6], "little")
    return version <= 63 and method in _ZIP_METHODS


def _corroborates(content: bytes, signature: bytes, offset: int) -> bool:
    """
    Report whether a signature match is structurally sound.

    Args:
        content: Raw bytes being scanned.
        signature: The matched signature.
        offset: Offset at which it matched.

    Returns:
        True if the match should be reported as a threat.
    """
    if signature == b"MZ":
        return _verify_pe_dos_header(content, offset)
    if signature == b"PE\x00\x00":
        return _verify_pe_signature(content, offset)
    if signature == b"\x7fELF":
        return _verify_elf(content, offset)
    if signature in _MACHO_MAGICS:
        return _verify_macho(content, signature, offset)
    if signature == b"\xca\xfe\xba\xbe":
        return _verify_java_class(content, offset)
    if signature == b"L\x00\x00\x00":
        return _verify_lnk(content, offset)
    if signature == b"PK\x03\x04":
        return _verify_zip_local_header(content, offset)
    if signature == b"<%":
        return in_text_run(content, offset)
    # Everything else is long enough to stand on its own.
    return True


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
        label = safe_label(filename)

        logger.debug("Scanning content of '%s' for embedded threats", label)

        # 1. Executable signature scan
        threats.extend(self._check_executable_signatures(content, label))

        # 2. Script injection scan
        threats.extend(self._check_script_patterns(content, label))

        # 3. Polyglot detection
        threats.extend(self._check_polyglot(content, label, expected_type))

        if threats:
            logger.warning(
                "Content analysis threats detected in '%s': %s",
                label,
                "; ".join(threats),
                extra=log_extra(),
            )
            cid = get_correlation_id()
            if cid:
                # Raw name: the audit logger escapes on emission,
                # and escaping twice can truncate mid-sequence.
                self._audit.threat(
                    filename,
                    cid,
                    "; ".join(threats),
                )
        else:
            logger.debug("Content scan clean for '%s'", label)

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
        sig = find_embedded_signature(
            content, self._executable_sigs, verify=_corroborates
        )
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
        sig = find_embedded_signature(
            content, self._webshell_sigs, verify=_corroborates
        )
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
        sig = find_embedded_signature(
            content, self._polyglot_sigs, 8, verify=_corroborates
        )
        if sig is not None:
            return [
                f"Polyglot file detected"
                f" in '{filename}':"
                f" secondary signature {sig!r}"
                f" found after header"
            ]
        return []
