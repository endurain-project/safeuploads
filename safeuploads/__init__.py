"""
File Security Module.

A comprehensive file security system for
validating uploads and preventing attacks.
"""

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
    ConfigValidationError,
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
    ZipBombError,
    ZipContentError,
)

# Main validator
from .file_validator import FileValidator

# Inspectors
from .inspectors import (
    ContentSecurityInspector,
    GzipContentInspector,
    ZipContentInspector,
)
from .protocols import SeekableFile
from .utils import ResourceMonitor

# Specialized validators
from .validators import (
    BaseValidator,
    CompressionSecurityValidator,
    ExtensionSecurityValidator,
    UnicodeSecurityValidator,
    WindowsSecurityValidator,
    XmlSecurityValidator,
)

# Perform configuration validation when module is imported
# This ensures configuration issues are caught early during application startup
FileSecurityConfig.validate_and_report(strict=False)

# Export all public APIs
__all__ = [
    # Core configuration
    "SecurityLimits",
    "FileSecurityConfig",
    # Protocols
    "SeekableFile",
    # Exceptions
    "ConfigValidationError",
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
    "XmlSecurityValidator",
    # Inspectors
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
