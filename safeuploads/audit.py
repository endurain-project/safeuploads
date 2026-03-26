"""
Structured audit logging for security validation events.

Provides a ``SecurityAuditLogger`` that emits structured log
records under the ``safeuploads.audit`` logger hierarchy.
Applications attach their own handlers to this logger (or
the parent ``safeuploads`` logger) to capture events.

Correlation IDs are propagated via ``contextvars`` so every
log message emitted during a single validation call carries
the same identifier without requiring explicit parameter
passing.
"""

from __future__ import annotations

import contextvars
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum

# ----------------------------------------------------------------
# Context variable for correlation ID
# ----------------------------------------------------------------

correlation_id_var: contextvars.ContextVar[str | None] = (
    contextvars.ContextVar("safeuploads_correlation_id", default=None)
)


def get_correlation_id() -> str | None:
    """
    Return the current correlation ID.

    Returns:
        Correlation ID string or None if not set.
    """
    return correlation_id_var.get()


def set_correlation_id(cid: str | None = None) -> str:
    """
    Set a new correlation ID for the current context.

    Args:
        cid: Explicit ID to use. Generates a UUID4 if None.

    Returns:
        The correlation ID that was set.
    """
    if cid is None:
        cid = uuid.uuid4().hex
    correlation_id_var.set(cid)
    return cid


def reset_correlation_id() -> None:
    """Clear the current correlation ID."""
    correlation_id_var.set(None)


def log_extra(
    extra: dict | None = None,
) -> dict:
    """
    Build a log ``extra`` dict enriched with the correlation ID.

    Args:
        extra: Optional existing extra dict to merge into.

    Returns:
        Dict with ``correlation_id`` key added.
    """
    merged = dict(extra) if extra else {}
    cid = correlation_id_var.get()
    if cid is not None:
        merged["correlation_id"] = cid
    return merged


# ----------------------------------------------------------------
# Audit event types and dataclass
# ----------------------------------------------------------------


class AuditEventType(Enum):
    """
    Types of security audit events.

    Attributes:
        VALIDATION_START: Validation process started.
        VALIDATION_SUCCESS: Validation completed successfully.
        VALIDATION_FAILURE: Validation failed with error.
        THREAT_DETECTED: Security threat detected.
        RESOURCE_LIMIT: Resource limit exceeded.
    """

    VALIDATION_START = "validation_start"
    VALIDATION_SUCCESS = "validation_success"
    VALIDATION_FAILURE = "validation_failure"
    THREAT_DETECTED = "threat_detected"
    RESOURCE_LIMIT = "resource_limit"


@dataclass
class AuditEvent:
    """
    A structured security audit event.

    Attributes:
        event_type: Category of the audit event.
        correlation_id: Unique ID linking related events.
        filename: Name of the file being validated.
        result: Outcome description.
        details: Additional context information.
        duration_ms: Elapsed time in milliseconds.
        source_ip: Optional client IP address.
        timestamp: Monotonic time when event was created.
    """

    event_type: AuditEventType
    correlation_id: str
    filename: str = ""
    result: str = ""
    details: str = ""
    duration_ms: float = 0.0
    source_ip: str | None = None
    timestamp: float = field(default_factory=time.monotonic)


# ----------------------------------------------------------------
# Audit logger
# ----------------------------------------------------------------

_audit_logger = logging.getLogger("safeuploads.audit")


class SecurityAuditLogger:
    """
    Emits structured audit log records.

    All records are emitted under the ``safeuploads.audit``
    logger with ``extra`` fields containing the structured
    ``AuditEvent`` data. The application configures handlers
    on this logger (or a parent) to capture events.

    Attributes:
        enabled: Whether audit logging is active.
    """

    def __init__(self, enabled: bool = False):
        """
        Initialize the audit logger.

        Args:
            enabled: Whether to emit audit events.
        """
        self.enabled = enabled

    def log_event(self, event: AuditEvent) -> None:
        """
        Emit an audit event as a structured log record.

        Args:
            event: The audit event to record.
        """
        if not self.enabled:
            return

        extra = {
            "audit_event_type": event.event_type.value,
            "audit_correlation_id": event.correlation_id,
            "audit_filename": event.filename,
            "audit_result": event.result,
            "audit_details": event.details,
            "audit_duration_ms": event.duration_ms,
            "audit_source_ip": event.source_ip or "",
        }

        level = logging.INFO
        if event.event_type in (
            AuditEventType.THREAT_DETECTED,
            AuditEventType.VALIDATION_FAILURE,
            AuditEventType.RESOURCE_LIMIT,
        ):
            level = logging.WARNING

        _audit_logger.log(
            level,
            "[%s] %s file=%s result=%s",
            event.correlation_id[:12],
            event.event_type.value,
            event.filename,
            event.result,
            extra=extra,
        )

    def start(
        self,
        filename: str,
        correlation_id: str,
    ) -> None:
        """
        Log a validation start event.

        Args:
            filename: Name of the file being validated.
            correlation_id: Unique operation identifier.
        """
        self.log_event(
            AuditEvent(
                event_type=AuditEventType.VALIDATION_START,
                correlation_id=correlation_id,
                filename=filename,
                result="started",
            )
        )

    def success(
        self,
        filename: str,
        correlation_id: str,
        duration_ms: float,
    ) -> None:
        """
        Log a validation success event.

        Args:
            filename: Name of the validated file.
            correlation_id: Unique operation identifier.
            duration_ms: Validation duration in milliseconds.
        """
        self.log_event(
            AuditEvent(
                event_type=(AuditEventType.VALIDATION_SUCCESS),
                correlation_id=correlation_id,
                filename=filename,
                result="passed",
                duration_ms=duration_ms,
            )
        )

    def failure(
        self,
        filename: str,
        correlation_id: str,
        duration_ms: float,
        error: str,
        details: str = "",
    ) -> None:
        """
        Log a validation failure event.

        Args:
            filename: Name of the failed file.
            correlation_id: Unique operation identifier.
            duration_ms: Validation duration in milliseconds.
            error: Short error description.
            details: Additional failure context.
        """
        self.log_event(
            AuditEvent(
                event_type=(AuditEventType.VALIDATION_FAILURE),
                correlation_id=correlation_id,
                filename=filename,
                result=error,
                details=details,
                duration_ms=duration_ms,
            )
        )

    def threat(
        self,
        filename: str,
        correlation_id: str,
        threat_description: str,
    ) -> None:
        """
        Log a threat detection event.

        Args:
            filename: Name of the threatening file.
            correlation_id: Unique operation identifier.
            threat_description: Description of the threat.
        """
        self.log_event(
            AuditEvent(
                event_type=AuditEventType.THREAT_DETECTED,
                correlation_id=correlation_id,
                filename=filename,
                result="threat_detected",
                details=threat_description,
            )
        )
