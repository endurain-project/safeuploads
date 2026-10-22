"""Base validator providing shared configuration and audit state."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..audit import SecurityAuditLogger

if TYPE_CHECKING:
    from ..config import FileSecurityConfig


class BaseValidator:
    """
    Base class for file security validators.

    Centralizes storage of the security configuration and the
    shared audit logger. Concrete validators expose a
    purpose-named entry point rather than a common ``validate``
    method, because their inputs are not interchangeable.

    Attributes:
        config: File security configuration parameters.
    """

    def __init__(self, config: FileSecurityConfig):
        """
        Initialize validator with configuration.

        Args:
            config: File security settings to apply.
        """
        self.config = config
        self._audit = SecurityAuditLogger(
            enabled=config.limits.enable_audit_logging
        )
