"""
Security validation modules for uploaded files.

This package provides validators that check filenames and file
properties for potential security threats including Unicode attacks,
invalid extensions, Windows-specific vulnerabilities, and compression
bombs.
"""

from .base import BaseValidator
from .compression_validator import CompressionSecurityValidator
from .extension_validator import ExtensionSecurityValidator
from .filename_validator import FilenameSecurityValidator
from .fit_validator import FitSecurityValidator
from .mime_validator import MimeTypeValidator
from .signature_validator import FileSignatureValidator
from .unicode_validator import UnicodeSecurityValidator
from .windows_validator import WindowsSecurityValidator
from .xml_validator import XmlSecurityValidator

__all__ = [
    "BaseValidator",
    "CompressionSecurityValidator",
    "ExtensionSecurityValidator",
    "FileSignatureValidator",
    "FilenameSecurityValidator",
    "FitSecurityValidator",
    "MimeTypeValidator",
    "UnicodeSecurityValidator",
    "WindowsSecurityValidator",
    "XmlSecurityValidator",
]
