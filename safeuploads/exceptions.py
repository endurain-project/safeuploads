"""
File Security Exceptions Module

Contains all exception classes used by the file security system.
"""

from typing import List
from dataclasses import dataclass


@dataclass
class ConfigValidationError:
    """
    Represents a configuration validation issue, including details about its
    type, severity, component, and an optional recommendation.
    """

    error_type: str
    message: str
    severity: str  # 'error', 'warning', 'info'
    component: str
    recommendation: str = ""


class FileSecurityConfigurationError(Exception):
    """
    Exception raised when file security configuration validation fails, aggregating all collected errors.

    Args:
        errors (List[ConfigValidationError]): Sequence of configuration validation errors that caused the failure.
    """

    def __init__(self, errors: List[ConfigValidationError]):
        """
        Initialize the exception with validation errors.

        Args:
            errors (List[ConfigValidationError]): Collected configuration validation errors whose messages will be aggregated.

        """
        self.errors = errors
        error_messages = [
            f"{error.severity.upper()}: {error.message}" for error in errors
        ]
        super().__init__(
            f"Configuration validation failed: {'; '.join(error_messages)}"
        )
