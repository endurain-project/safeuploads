"""Utility helpers for resource monitoring and content scanning."""

import logging
import sys
import time
from collections.abc import Iterable
from types import TracebackType

from .exceptions import ErrorCode, ResourceLimitError

try:
    # ``resource`` is a Unix-only stdlib module and is absent on
    # Windows; memory accounting degrades to a no-op there while
    # the wall-clock timeout keeps working.
    import resource
except ImportError:  # pragma: no cover - platform-specific (Windows)
    resource = None  # type: ignore[assignment]

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


def matches_signature_prefix(
    content: bytes, signatures: Iterable[bytes]
) -> bytes | None:
    """
    Return the first signature the content begins with.

    Anchored match via ``bytes.startswith``; use when deciding
    whether content *is* a given format from its header.

    Args:
        content: Raw bytes to test.
        signatures: Candidate byte signatures.

    Returns:
        The first matching signature, or None if none match.
    """
    for sig in signatures:
        if content.startswith(sig):
            return sig
    return None


def find_embedded_signature(
    content: bytes, signatures: Iterable[bytes]
) -> bytes | None:
    """
    Return the first signature found anywhere in the content.

    Substring match; use when detecting a format embedded inside
    otherwise-valid content (polyglots, appended payloads).

    Args:
        content: Raw bytes to scan.
        signatures: Candidate byte signatures.

    Returns:
        The first matching signature, or None if none present.
    """
    for sig in signatures:
        if sig in content:
            return sig
    return None


def find_text_pattern(content: bytes, patterns: Iterable[str]) -> str | None:
    """
    Return the first text pattern present in decoded content.

    Content is decoded as UTF-8 with errors ignored and lower-
    cased so binary data degrades gracefully. Any decoding
    failure is treated as "no match".

    Args:
        content: Raw bytes to scan.
        patterns: Lower-case substrings to search for.

    Returns:
        The first matching pattern, or None if none present.
    """
    try:
        text = content.decode("utf-8", errors="ignore").lower()
    except Exception:
        return None
    for pattern in patterns:
        if pattern in text:
            return pattern
    return None


_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

# Start-of-frame markers that carry the frame dimensions. 0xC4
# (DHT), 0xC8 (JPG) and 0xCC (DAC) share the range but are not
# start-of-frame markers, so they are excluded.
_JPEG_SOF_MARKERS: frozenset[int] = frozenset(
    {
        0xC0,
        0xC1,
        0xC2,
        0xC3,
        0xC5,
        0xC6,
        0xC7,
        0xC9,
        0xCA,
        0xCB,
        0xCD,
        0xCE,
        0xCF,
    }
)


def _parse_png_dimensions(content: bytes) -> tuple[int, int] | None:
    """
    Read width and height from a PNG IHDR chunk.

    Args:
        content: Raw bytes starting at the PNG signature.

    Returns:
        ``(width, height)`` tuple, or None if the IHDR chunk is
        missing or truncated.
    """
    # IHDR is required to be the first chunk: 8-byte signature,
    # 4-byte length, 4-byte type, then two big-endian uint32.
    if len(content) < 24 or content[12:16] != b"IHDR":
        return None
    width = int.from_bytes(content[16:20], "big")
    height = int.from_bytes(content[20:24], "big")
    return width, height


def _parse_jpeg_dimensions(content: bytes) -> tuple[int, int] | None:
    """
    Walk JPEG segments to the first start-of-frame marker.

    Args:
        content: Raw bytes starting at the SOI marker.

    Returns:
        ``(width, height)`` tuple, or None if no start-of-frame
        segment is present before the entropy-coded data.
    """
    pos = 2  # Skip the SOI marker.
    total = len(content)

    while pos + 3 < total:
        # Segments are contiguous; anything else is malformed.
        if content[pos] != 0xFF:
            return None

        marker = content[pos + 1]

        # 0xFF fill bytes may pad the gap before a marker.
        if marker == 0xFF:
            pos += 1
            continue

        # Standalone markers carry no length field.
        if marker == 0x01 or 0xD0 <= marker <= 0xD8:
            pos += 2
            continue

        # EOI or the start of scan data: no frame header found.
        if marker in (0xD9, 0xDA):
            return None

        segment_len = int.from_bytes(content[pos + 2 : pos + 4], "big")
        if segment_len < 2:
            return None

        if marker in _JPEG_SOF_MARKERS:
            # SOF payload: precision, height, width.
            sof = content[pos + 4 : pos + 9]
            if len(sof) < 5:
                return None
            height = int.from_bytes(sof[1:3], "big")
            width = int.from_bytes(sof[3:5], "big")
            return width, height

        pos += 2 + segment_len

    return None


def parse_image_dimensions(content: bytes) -> tuple[int, int] | None:
    """
    Extract pixel dimensions from a PNG or JPEG header.

    Args:
        content: Leading bytes of the image file.

    Returns:
        ``(width, height)`` tuple, or None if the format is
        unsupported or the header is malformed or truncated.
    """
    if content.startswith(_PNG_SIGNATURE):
        return _parse_png_dimensions(content)
    if content.startswith(b"\xff\xd8"):
        return _parse_jpeg_dimensions(content)
    return None


class ResourceMonitor:
    """
    Context manager that enforces wall-clock and memory limits.

    Tracks elapsed time continuously and samples memory usage
    via ``resource.getrusage``. Memory accounting uses the
    process peak RSS (``ru_maxrss``), a monotonic high-water
    mark for the whole process, so the reported delta is a
    coarse, best-effort upper bound rather than the exact
    memory used by this validation. Call ``check`` (or the
    individual ``check_time`` / ``check_memory``) inside long
    loops so a runaway operation is aborted while it runs;
    otherwise limits are only checked on context exit.

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

        self._raise_if_time_exceeded(self._elapsed)
        self._raise_if_memory_exceeded(self._memory_delta)

    def check_time(self) -> None:
        """
        Check elapsed time mid-operation.

        Raises:
            ResourceLimitError: If the wall-clock time limit has
                been exceeded since context entry.
        """
        self._raise_if_time_exceeded(time.monotonic() - self.start_time)

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
        self._raise_if_memory_exceeded(delta)

    def check(self) -> None:
        """
        Check both time and memory limits mid-operation.

        Raises:
            ResourceLimitError: If the wall-clock or memory limit
                has been exceeded since context entry.
        """
        self.check_time()
        self.check_memory()

    def _raise_if_time_exceeded(self, elapsed: float) -> None:
        """
        Raise if elapsed wall-clock time exceeds the limit.

        Args:
            elapsed: Seconds elapsed since context entry.

        Raises:
            ResourceLimitError: If the time limit is exceeded.
        """
        if elapsed <= self.max_time_seconds:
            return
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

    def _raise_if_memory_exceeded(self, delta: int) -> None:
        """
        Raise if peak-RSS growth exceeds the limit.

        Args:
            delta: Peak-RSS growth in bytes since context entry.

        Raises:
            ResourceLimitError: If the memory limit is exceeded.
        """
        if delta <= self.max_memory_bytes:
            return
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
            platforms, or 0 on platforms without the ``resource``
            module (e.g. Windows), which disables memory-limit
            enforcement while leaving the timeout active.
        """
        if resource is None:  # pragma: no cover - platform-specific
            return 0
        usage = resource.getrusage(resource.RUSAGE_SELF)
        return usage.ru_maxrss * _RSS_UNIT_BYTES
