"""
File Security Module.

A comprehensive file security system for
validating uploads and preventing attacks.
"""

from importlib.metadata import PackageNotFoundError, version

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
    ImageDimensionError,
    MimeTypeError,
    ResourceLimitError,
    UnicodeSecurityError,
    WindowsReservedNameError,
    XmlSecurityError,
    ZipBombError,
    ZipContentError,
)

# Main validator
from .file_validator import FileValidator, ValidationResult

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
    ImageDimensionValidator,
    MimeTypeValidator,
    UnicodeSecurityValidator,
    WindowsSecurityValidator,
    XmlSecurityValidator,
)

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
    "ImageDimensionError",
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
    "ValidationResult",
    # Specialized validators
    "BaseValidator",
    "UnicodeSecurityValidator",
    "ExtensionSecurityValidator",
    "WindowsSecurityValidator",
    "CompressionSecurityValidator",
    "FitSecurityValidator",
    "ImageDimensionValidator",
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
