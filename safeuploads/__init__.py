"""
File Security Module.

A comprehensive file security system for
validating uploads and preventing attacks.
"""

from importlib.metadata import PackageNotFoundError, version
from typing import TYPE_CHECKING

from .audit import (
    AuditEvent,
    AuditEventType,
    SecurityAuditLogger,
    get_correlation_id,
    set_correlation_id,
)

# Core classes and configurations
from .config import FileSecurityConfig, SecurityLimits
from .enums import (
    BinaryFileCategory,
    CompoundExtensionCategory,
    DangerousExtensionCategory,
    MalwareSignatureCategory,
    SuspiciousFilePattern,
    UnicodeAttackCategory,
    ZipThreatCategory,
)
from .exceptions import (
    CompressionSecurityError,
    ConfigValidationIssue,
    ContentThreatError,
    ErrorCode,
    ExtensionSecurityError,
    FilenameSecurityError,
    FileProcessingError,
    FileSecurityConfigurationError,
    FileSecurityError,
    FileSignatureError,
    FileSizeError,
    FileValidationError,
    MimeTypeError,
    ResourceLimitError,
    UnicodeSecurityError,
    WindowsReservedNameError,
    XmlSecurityError,
    ZipBombError,
    ZipContentError,
)

# Main validator
from .file_validator import FileValidator

# Inspectors
from .inspectors import (
    BaseInspector,
    ContentSecurityInspector,
    GzipContentInspector,
    ZipContentInspector,
)
from .protocols import SeekableFile, UploadFileProtocol
from .utils import ResourceMonitor

# Specialized validators
from .validators import (
    BaseValidator,
    CompressionSecurityValidator,
    ExtensionSecurityValidator,
    FilenameSecurityValidator,
    FileSignatureValidator,
    FitSecurityValidator,
    MimeTypeValidator,
    UnicodeSecurityValidator,
    WindowsSecurityValidator,
    XmlSecurityValidator,
)

if TYPE_CHECKING:
    # Deprecated alias, resolved by ``__getattr__`` at runtime
    from .exceptions import ConfigValidationError as ConfigValidationError
else:
    from .exceptions import _resolve_deprecated

    def __getattr__(name: str) -> object:
        """Resolve deprecated package attributes (PEP 562)."""
        return _resolve_deprecated(__name__, name)

# Configuration is validated explicitly rather than at import
# time: FileValidator validates its config on construction, and
# callers can invoke FileSecurityConfig.validate_and_report() or
# config.validate_instance() for an early check.

try:
    __version__ = version("safeuploads")
except PackageNotFoundError:  # uninstalled source tree or vendored copy
    __version__ = "0+unknown"

# Export all public APIs
__all__ = [
    "__version__",
    # Core configuration
    "SecurityLimits",
    "FileSecurityConfig",
    # Protocols
    "SeekableFile",
    "UploadFileProtocol",
    # Exceptions
    "ConfigValidationIssue",
    "FileSecurityConfigurationError",
    "ErrorCode",
    "FileSecurityError",
    "FileValidationError",
    "FilenameSecurityError",
    "UnicodeSecurityError",
    "ExtensionSecurityError",
    "WindowsReservedNameError",
    "FileSizeError",
    "MimeTypeError",
    "FileSignatureError",
    "CompressionSecurityError",
    "ZipBombError",
    "ZipContentError",
    "XmlSecurityError",
    "ContentThreatError",
    "FileProcessingError",
    "ResourceLimitError",
    # Enums
    "BinaryFileCategory",
    "DangerousExtensionCategory",
    "CompoundExtensionCategory",
    "UnicodeAttackCategory",
    "SuspiciousFilePattern",
    "ZipThreatCategory",
    "MalwareSignatureCategory",
    # Main validator
    "FileValidator",
    # Specialized validators
    "BaseValidator",
    "UnicodeSecurityValidator",
    "ExtensionSecurityValidator",
    "WindowsSecurityValidator",
    "CompressionSecurityValidator",
    "FitSecurityValidator",
    "FilenameSecurityValidator",
    "FileSignatureValidator",
    "MimeTypeValidator",
    "XmlSecurityValidator",
    # Inspectors
    "BaseInspector",
    "ZipContentInspector",
    "GzipContentInspector",
    "ContentSecurityInspector",
    # Utilities
    "ResourceMonitor",
    # Audit logging
    "SecurityAuditLogger",
    "AuditEvent",
    "AuditEventType",
    "get_correlation_id",
    "set_correlation_id",
]
