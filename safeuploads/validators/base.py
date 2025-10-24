"""
Base Validator Module

Contains base classes and interfaces for file security validators.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..config import FileSecurityConfig


class BaseValidator(ABC):
    """
    Abstract base class for file security validators.
    This class defines the interface that concrete validators must implement.
    It stores the shared file security configuration and enforces implementation
    of the `validate` method in subclasses.
    Attributes:
        config (FileSecurityConfig): Shared configuration parameters for the validator.
    """

    def __init__(self, config: "FileSecurityConfig"):
        """
        Initialize the validator with the provided configuration.

        Args:
            config (FileSecurityConfig): The file security settings to apply during validation.
        """
        self.config = config

    @abstractmethod
    def validate(self, *args, **kwargs) -> Any:
        """
        Validate provided data using subclass-specific logic.

        Args:
            *args: Positional arguments required by the concrete validator.
            **kwargs: Keyword arguments required by the concrete validator.

        Returns:
            Any: The validated result or outcome defined by subclasses.
        """
        pass
