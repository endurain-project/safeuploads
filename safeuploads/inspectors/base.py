"""Base inspector providing shared configuration and audit state."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..audit import SecurityAuditLogger

if TYPE_CHECKING:
    from ..config import FileSecurityConfig


class BaseInspector:
    """
    Base class for file content inspectors.

    Centralizes storage of the security configuration and the
    shared audit logger used by all inspectors.

    Attributes:
        config: File security configuration.
    """

    def __init__(self, config: FileSecurityConfig) -> None:
        """
        Initialize the inspector with configuration.

        Args:
            config: File security configuration.
        """
        self.config = config
        self._audit = SecurityAuditLogger(
            enabled=config.limits.enable_audit_logging
        )
