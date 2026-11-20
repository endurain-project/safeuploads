"""Utility helpers for allow-lists, resource monitoring and scanning."""

import contextvars
import logging
import mmap
import sys
import time
import zlib
from collections.abc import Iterable, Iterator, Mapping
from types import TracebackType

from .exceptions import ErrorCode, ResourceLimitError
from .protocols import SeekableFile

logger = logging.getLogger(__name__)


def _read_statm_rss_bytes() -> int:
    """
    Return the current RSS in bytes from ``/proc/self/statm`` (Linux).

    The second field of the file is the resident page count.
    """
    with open("/proc/self/statm", "rb") as statm:
        resident_pages = int(statm.read().split()[1])
    return resident_pages * mmap.PAGESIZE


# ``_read_rss_bytes`` is chosen once for the platform: the current
# RSS on Linux and macOS, the peak RSS elsewhere on Unix and 0 where
# ``resource`` is missing (Windows), which disables the memory limit.
if sys.platform == "darwin":  # pragma: no cover - platform-specific
    import ctypes

    class _MachTaskBasicInfo(ctypes.Structure):
        """``struct mach_task_basic_info`` from ``<mach/task_info.h>``."""

        _pack_ = 4
        _fields_ = [
            ("virtual_size", ctypes.c_uint64),
            ("resident_size", ctypes.c_uint64),
            ("resident_size_max", ctypes.c_uint64),
            ("user_time", ctypes.c_int32 * 2),
            ("system_time", ctypes.c_int32 * 2),
            ("policy", ctypes.c_int),
            ("suspend_count", ctypes.c_int),
        ]

    _MACH_TASK_BASIC_INFO = 20
    _libsystem = ctypes.CDLL(None)
    _mach_task_self = _libsystem.mach_task_self
    _mach_task_self.argtypes = []
    _mach_task_self.restype = ctypes.c_uint
    _task_info = _libsystem.task_info
    _task_info.argtypes = [
        ctypes.c_uint,
        ctypes.c_int,
        ctypes.POINTER(_MachTaskBasicInfo),
        ctypes.POINTER(ctypes.c_uint),
    ]
    _task_info.restype = ctypes.c_int

    def _read_mach_rss_bytes() -> int:
        """
        Return the current RSS in bytes from mach ``task_info`` (macOS).

        Raises:
            OSError: If ``task_info`` returns an error.
        """
        info = _MachTaskBasicInfo()
        # The count is in ``natural_t`` (unsigned int) units
        count = ctypes.c_uint(
            ctypes.sizeof(info) // ctypes.sizeof(ctypes.c_uint)
        )
        status = _task_info(
            _mach_task_self(),
            _MACH_TASK_BASIC_INFO,
            ctypes.byref(info),
            ctypes.byref(count),
        )
        if status != 0:
            raise OSError(f"task_info failed with kern_return_t {status}")
        return int(info.resident_size)

    _read_rss_bytes = _read_mach_rss_bytes
elif sys.platform == "linux":
    _read_rss_bytes = _read_statm_rss_bytes
else:  # pragma: no cover - platform-specific
    try:
        import resource
    except ImportError:

        def _read_rss_bytes() -> int:
            """Return 0: this platform has no ``resource`` module."""
            return 0

    else:

        def _read_rss_bytes() -> int:
            """Return the process peak RSS in bytes from ``getrusage``."""
            # ``ru_maxrss`` is in kilobytes on the BSDs
            usage = resource.getrusage(resource.RUSAGE_SELF)
            return usage.ru_maxrss * 1024


def bytes_to_mb(num_bytes: int) -> int:
    """
    Convert a byte count to whole megabytes.

    Args:
        num_bytes: Size in bytes.

    Returns:
        Size in whole megabytes using floor division.
    """
    return num_bytes // (1024 * 1024)


def allowed_extensions(
    allowed_types: Mapping[str, frozenset[str]],
) -> frozenset[str]:
    """
    Collect every extension an allowed-types mapping permits.

    Args:
        allowed_types: Allowed MIME types mapped to the extensions
            each one permits.

    Returns:
        Union of the mapping's extension sets.
    """
    return frozenset().union(*allowed_types.values())


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
    content: bytes, signatures: Iterable[bytes], start: int = 0
) -> bytes | None:
    """
    Return the first signature found anywhere in the content.

    Substring match; use when detecting a format embedded inside
    otherwise-valid content (polyglots, appended payloads).

    Args:
        content: Raw bytes to scan.
        signatures: Candidate byte signatures.
        start: Offset at which the search begins; bytes before it
            are skipped without copying the content.

    Returns:
        The first matching signature, or None if none present.
    """
    for sig in signatures:
        if content.find(sig, start) != -1:
            return sig
    return None


def find_text_pattern(content: bytes, patterns: Iterable[str]) -> str | None:
    """
    Return the first text pattern present in the content.

    The content is matched as bytes, lower-cased in ASCII, with
    no decoding: invalid bytes never join the text around them,
    and the only copy made is the lower-cased one.

    Args:
        content: Raw bytes to scan.
        patterns: Lower-case ASCII substrings to search for.

    Returns:
        The first matching pattern, or None if none present.
    """
    lowered = content.lower()
    for pattern in patterns:
        if pattern.encode("ascii") in lowered:
            return pattern
    return None


class ResourceMonitor:
    """
    Context manager that enforces wall-clock and memory limits.

    While the block runs the monitor is the active one for the
    current context (and worker threads that copy it), so
    ``check_resource_limits`` enforces both limits at the loop
    boundaries of long-running work; they are checked again on
    exit. A single blocking call, such as one ``zipfile`` parse,
    is not interrupted mid-call.

    Memory growth is the current resident set size (RSS) minus the
    RSS at entry, read from ``/proc/self/statm`` on Linux and mach
    ``task_info`` on macOS. RSS is process-wide, so concurrent
    validations and other work in the process add to each other's
    growth; memory the allocator keeps after a free stays resident,
    so reusing it is not growth. Other Unix platforms use the peak
    RSS (``ru_maxrss``), where an earlier, higher peak hides later
    growth, and platforms without the ``resource`` module (Windows)
    do not enforce the memory limit. A failing memory reading
    raises ``OSError``.

    Attributes:
        max_time_seconds: Maximum allowed wall-clock seconds.
        max_memory_bytes: Maximum allowed RSS growth in bytes.
        start_time: Timestamp when the context was entered.
        start_memory: Process RSS in bytes at context entry.
    """

    # Restores the previously active monitor on exit
    _token: contextvars.Token["ResourceMonitor | None"]

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
        Record baseline time and memory and become the active monitor.

        Returns:
            Self for use in ``with`` statements.

        Raises:
            OSError: If the platform's memory reading fails.
        """
        self.start_time = time.monotonic()
        self.start_memory = self._get_rss_bytes()
        self._token = _active_monitor.set(self)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """
        Restore the previous active monitor and check usage.

        The previous monitor is restored even when the block
        raised; the limits are checked only on a clean exit so
        an exception from the block is not masked.

        Args:
            exc_type: Exception type if raised inside block.
            exc_val: Exception value if raised inside block.
            exc_tb: Exception traceback if raised inside block.

        Raises:
            ResourceLimitError: If time or memory limits were
                exceeded during the monitored block.
            OSError: If the platform's memory reading fails.
        """
        _active_monitor.reset(self._token)
        if exc_type is not None:
            return

        self._elapsed = time.monotonic() - self.start_time
        # RSS below the entry baseline (memory freed) is no growth
        self._memory_delta = max(0, self._get_rss_bytes() - self.start_memory)

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
        Check RSS growth since context entry mid-operation.

        Raises:
            ResourceLimitError: If RSS growth since context entry
                exceeds the configured memory limit.
            OSError: If the platform's memory reading fails.
        """
        delta = max(0, self._get_rss_bytes() - self.start_memory)
        self._raise_if_memory_exceeded(delta)

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
        Raise if RSS growth exceeds the limit.

        Args:
            delta: RSS growth in bytes since context entry.

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
        Return RSS growth since context entry.

        Returns:
            RSS growth in bytes, 0 when RSS is at or below the
            entry baseline. RSS is process-wide, so this includes
            memory used by concurrent work outside this monitor.

        Raises:
            OSError: If the platform's memory reading fails.
        """
        if self.start_memory == 0:
            return 0
        return max(0, self._get_rss_bytes() - self.start_memory)

    @staticmethod
    def _get_rss_bytes() -> int:
        """
        Return the process RSS in bytes.

        Returns:
            Current resident set size on Linux and macOS, peak
            RSS on other Unix platforms, or 0 on platforms without
            the ``resource`` module (e.g. Windows), which disables
            memory-limit enforcement while leaving the timeout
            active.

        Raises:
            OSError: If the platform's memory reading fails.
        """
        return _read_rss_bytes()


_active_monitor: contextvars.ContextVar[ResourceMonitor | None] = (
    contextvars.ContextVar("safeuploads_resource_monitor", default=None)
)


def check_resource_limits() -> None:
    """
    Enforce the active ``ResourceMonitor`` limits, if any.

    Called at the loop boundaries of long-running work; returns
    at once when no monitor is active. The active monitor is held
    in a context variable, so a worker thread started with a copy
    of the caller's context sees the caller's monitor.

    Raises:
        ResourceLimitError: If the active monitor's time or
            memory limit has been exceeded.
    """
    monitor = _active_monitor.get()
    if monitor is None:
        return
    monitor.check_time()
    monitor.check_memory()


def iter_gzip_chunks(stream: SeekableFile, chunk_size: int) -> Iterator[bytes]:
    """
    Decompress gzip data in bounded steps, yielding each output chunk.

    The data is inflated with ``zlib`` instead of the ``gzip`` module,
    whose reader loops inside a single ``read`` call over members
    that produce no output (and over long header fields), so limits
    cannot be enforced between steps. Here every step reads at most
    ``chunk_size`` input bytes, produces at most ``chunk_size``
    output bytes and calls ``check_resource_limits``. Members may be
    concatenated and zero padded; data that does not start a gzip
    member is an error.

    Args:
        stream: Binary file positioned at the start of the gzip data.
        chunk_size: Bytes read, and at most inflated, per step.

    Yields:
        Non-empty chunks of decompressed data.

    Raises:
        ResourceLimitError: If the active resource monitor's time or
            memory limit is exceeded.
        zlib.error: If a header, deflate stream or trailer is invalid.
        EOFError: If the input ends inside a gzip member.
    """
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    # True while the current decompressor has been given no input,
    # where the stream may end
    fresh = True
    # True once a member has ended: zero padding may follow it
    after_member = False
    while True:
        check_resource_limits()
        if decompressor.eof:
            data = decompressor.unused_data
            decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
            fresh = after_member = True
        else:
            data = decompressor.unconsumed_tail
        from_stream = not data
        if from_stream:
            data = stream.read(chunk_size)
        if fresh:
            if from_stream and not data:
                return
            if after_member:
                data = data.lstrip(b"\x00")
                if not data:
                    continue
            fresh = False
        output = decompressor.decompress(data, chunk_size)
        if output:
            yield output
        elif from_stream and not data and not decompressor.eof:
            # All input is consumed and nothing was pending
            raise EOFError("Compressed gzip data ended before the end")
