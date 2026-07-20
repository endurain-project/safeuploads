"""Utility classes for resource monitoring during validation."""

import logging
import resource
import sys
import time
from types import TracebackType

from .exceptions import ErrorCode, ResourceLimitError

logger = logging.getLogger(__name__)

# ``resource.getrusage`` reports peak RSS (``ru_maxrss``) in bytes on
# macOS but in kilobytes on Linux/BSD. Normalize to bytes with a
# platform-specific multiplier resolved once at import time.
_RSS_UNIT_BYTES: int = 1 if sys.platform == "darwin" else 1024


def bytes_to_mb(num_bytes: int) -> int:
    """
    Convert a byte count to whole megabytes.

    Args:
        num_bytes: Size in bytes.

    Returns:
        Size in whole megabytes using floor division.
    """
    return num_bytes // (1024 * 1024)


class ResourceMonitor:
    """
    Context manager that enforces wall-clock and memory limits.

    Tracks elapsed time continuously and samples memory usage
    via ``resource.getrusage``. Memory accounting uses the
    process peak RSS (``ru_maxrss``), a monotonic high-water
    mark for the whole process, so the reported delta is a
    coarse, best-effort upper bound rather than the exact
    memory used by this validation. Call ``check_time`` and
    ``check_memory`` inside long loops for early enforcement;
    otherwise limits are checked on context exit.

    Attributes:
        max_time_seconds: Maximum allowed wall-clock seconds.
        max_memory_bytes: Maximum allowed peak-RSS growth in bytes.
        start_time: Timestamp when the context was entered.
        start_memory: Peak process RSS in bytes at context entry.
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
        self.start_memory = self._get_peak_rss_bytes()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
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
        current_memory = self._get_peak_rss_bytes()
        # Peak RSS only grows, so the delta is non-negative;
        # clamp defensively in case the platform reports noise.
        self._memory_delta = max(0, current_memory - self.start_memory)

        if self._elapsed > self.max_time_seconds:
            logger.error(
                "Validation time limit exceeded: %.2fs > %.2fs",
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

        if self._memory_delta > self.max_memory_bytes:
            delta_mb = bytes_to_mb(self._memory_delta)
            max_mb = bytes_to_mb(self.max_memory_bytes)
            logger.error(
                "Validation memory limit exceeded: %dMB > %dMB",
                delta_mb,
                max_mb,
            )
            raise ResourceLimitError(
                message=(
                    f"Validation memory limit exceeded: "
                    f"{delta_mb}MB (max {max_mb}MB)"
                ),
                error_code=(ErrorCode.RESOURCE_MEMORY_EXCEEDED),
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
                "Validation time limit exceeded: %.2fs > %.2fs",
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

    def check_memory(self) -> None:
        """
        Check peak memory growth mid-operation.

        Enables early enforcement inside long-running loops
        instead of waiting for context exit. Uses the process
        peak RSS high-water mark, so it is a coarse upper bound.

        Raises:
            ResourceLimitError: If peak-RSS growth since context
                entry exceeds the configured memory limit.
        """
        delta = max(0, self._get_peak_rss_bytes() - self.start_memory)
        if delta > self.max_memory_bytes:
            delta_mb = bytes_to_mb(delta)
            max_mb = bytes_to_mb(self.max_memory_bytes)
            logger.error(
                "Validation memory limit exceeded: %dMB > %dMB",
                delta_mb,
                max_mb,
            )
            raise ResourceLimitError(
                message=(
                    f"Validation memory limit exceeded: "
                    f"{delta_mb}MB (max {max_mb}MB)"
                ),
                error_code=ErrorCode.RESOURCE_MEMORY_EXCEEDED,
                memory_bytes=delta,
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
        Return peak-RSS growth since context entry.

        Returns:
            Non-negative peak-RSS growth in bytes. Because the
            underlying metric is a process-wide high-water mark,
            this never decreases and may include memory used by
            concurrent work outside this monitor.
        """
        if self.start_memory == 0:
            return 0
        return max(0, self._get_peak_rss_bytes() - self.start_memory)

    @staticmethod
    def _get_peak_rss_bytes() -> int:
        """
        Return the process peak RSS in bytes.

        Returns:
            Peak resident set size (high-water mark) in bytes
            since the process started, normalized across
            platforms.
        """
        usage = resource.getrusage(resource.RUSAGE_SELF)
        return usage.ru_maxrss * _RSS_UNIT_BYTES
