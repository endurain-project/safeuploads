"""
Utility classes for resource monitoring during validation.
"""

import logging
import resource
import time

from .exceptions import ErrorCode, ResourceLimitError

logger = logging.getLogger(__name__)


class ResourceMonitor:
    """
    Context manager that enforces wall-clock and memory limits.

    Tracks elapsed time continuously and samples memory usage
    via ``resource.getrusage`` on entry and exit. Raises
    ``ResourceLimitError`` when either limit is exceeded.

    Attributes:
        max_time_seconds: Maximum allowed wall-clock seconds.
        max_memory_bytes: Maximum allowed memory delta in bytes.
        start_time: Timestamp when the context was entered.
        start_memory: RSS memory in bytes at context entry.
    """

    def __init__(
        self,
        max_time_seconds: float = 30.0,
        max_memory_mb: int = 512,
    ):
        """
        Initialize the resource monitor.

        Args:
            max_time_seconds: Wall-clock timeout in seconds.
            max_memory_mb: Maximum memory delta in megabytes.
        """
        self.max_time_seconds = max_time_seconds
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.start_time: float = 0.0
        self.start_memory: int = 0
        self._elapsed: float = 0.0
        self._memory_delta: int = 0

    def __enter__(self) -> "ResourceMonitor":
        """
        Record baseline time and memory on context entry.

        Returns:
            Self for use in ``with`` statements.
        """
        self.start_time = time.monotonic()
        self.start_memory = self._get_rss_bytes()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """
        Check resource usage on context exit.

        Args:
            exc_type: Exception type if raised inside block.
            exc_val: Exception value if raised inside block.
            exc_tb: Exception traceback if raised inside block.

        Raises:
            ResourceLimitError: If time or memory limits were
                exceeded during the monitored block.
        """
        if exc_type is not None:
            return

        self._elapsed = time.monotonic() - self.start_time
        current_memory = self._get_rss_bytes()
        self._memory_delta = current_memory - self.start_memory

        if self._elapsed > self.max_time_seconds:
            logger.error(
                "Validation time limit exceeded: "
                "%.2fs > %.2fs",
                self._elapsed,
                self.max_time_seconds,
            )
            raise ResourceLimitError(
                message=(
                    f"Validation time limit exceeded: "
                    f"{self._elapsed:.1f}s "
                    f"(max {self.max_time_seconds:.1f}s)"
                ),
                error_code=ErrorCode.RESOURCE_TIME_EXCEEDED,
                elapsed_seconds=self._elapsed,
            )

        if (
            self._memory_delta > 0
            and self._memory_delta > self.max_memory_bytes
        ):
            delta_mb = self._memory_delta // (1024 * 1024)
            max_mb = self.max_memory_bytes // (1024 * 1024)
            logger.error(
                "Validation memory limit exceeded: "
                "%dMB > %dMB",
                delta_mb,
                max_mb,
            )
            raise ResourceLimitError(
                message=(
                    f"Validation memory limit exceeded: "
                    f"{delta_mb}MB (max {max_mb}MB)"
                ),
                error_code=(
                    ErrorCode.RESOURCE_MEMORY_EXCEEDED
                ),
                memory_bytes=self._memory_delta,
            )

    def check_time(self) -> None:
        """
        Check elapsed time mid-operation.

        Raises:
            ResourceLimitError: If the wall-clock time limit has
                been exceeded since context entry.
        """
        elapsed = time.monotonic() - self.start_time
        if elapsed > self.max_time_seconds:
            logger.error(
                "Validation time limit exceeded: "
                "%.2fs > %.2fs",
                elapsed,
                self.max_time_seconds,
            )
            raise ResourceLimitError(
                message=(
                    f"Validation time limit exceeded: "
                    f"{elapsed:.1f}s "
                    f"(max {self.max_time_seconds:.1f}s)"
                ),
                error_code=ErrorCode.RESOURCE_TIME_EXCEEDED,
                elapsed_seconds=elapsed,
            )

    @property
    def elapsed(self) -> float:
        """
        Return elapsed seconds since context entry.

        Returns:
            Elapsed wall-clock seconds.
        """
        if self.start_time == 0.0:
            return 0.0
        return time.monotonic() - self.start_time

    @property
    def memory_delta(self) -> int:
        """
        Return memory delta since context entry.

        Returns:
            Memory delta in bytes (may be negative).
        """
        if self.start_memory == 0:
            return 0
        return self._get_rss_bytes() - self.start_memory

    @staticmethod
    def _get_rss_bytes() -> int:
        """
        Return current process RSS in bytes.

        Returns:
            Resident set size in bytes.
        """
        usage = resource.getrusage(resource.RUSAGE_SELF)
        # macOS reports in bytes, Linux in kilobytes
        import sys

        if sys.platform == "darwin":
            return usage.ru_maxrss
        return usage.ru_maxrss * 1024
