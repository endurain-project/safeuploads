"""Tests for ResourceMonitor utility."""

import gzip
import io
import time
import zlib

import pytest

from safeuploads.exceptions import (
    ErrorCode,
    ResourceLimitError,
)
from safeuploads.utils import (
    ResourceMonitor,
    check_resource_limits,
    iter_gzip_chunks,
)


class TestResourceMonitorInit:
    """Test ResourceMonitor initialization."""

    def test_default_values(self):
        """Test default initialization values."""
        monitor = ResourceMonitor()
        assert monitor.max_time_seconds == 30.0
        assert monitor.max_memory_bytes == 512 * 1024 * 1024

    def test_custom_values(self):
        """Test custom initialization values."""
        monitor = ResourceMonitor(max_time_seconds=5.0, max_memory_mb=128)
        assert monitor.max_time_seconds == 5.0
        assert monitor.max_memory_bytes == 128 * 1024 * 1024


class TestResourceMonitorTime:
    """Test wall-clock time monitoring."""

    def test_passes_within_time_limit(self):
        """Test that fast operations pass without error."""
        with ResourceMonitor(max_time_seconds=5.0, max_memory_mb=512):
            pass  # Immediate exit

    def test_raises_on_time_exceeded_at_exit(self):
        """Test that exceeding time limit raises at exit."""
        with (
            pytest.raises(ResourceLimitError) as exc_info,
            ResourceMonitor(
                max_time_seconds=0.05,
                max_memory_mb=512,
            ),
        ):
            time.sleep(0.1)

        assert exc_info.value.error_code == ErrorCode.RESOURCE_TIME_EXCEEDED
        assert exc_info.value.elapsed_seconds is not None
        assert exc_info.value.elapsed_seconds >= 0.05
        assert "time limit" in str(exc_info.value).lower()

    def test_check_time_raises_mid_operation(self):
        """Test mid-operation time check raises."""
        with (  # noqa: PT012
            pytest.raises(ResourceLimitError) as exc_info,
            ResourceMonitor(
                max_time_seconds=0.05,
                max_memory_mb=512,
            ) as monitor,
        ):
            time.sleep(0.1)
            monitor.check_time()

        assert exc_info.value.error_code == ErrorCode.RESOURCE_TIME_EXCEEDED

    def test_check_time_passes_within_limit(self):
        """Test mid-operation check passes within limit."""
        with ResourceMonitor(
            max_time_seconds=5.0, max_memory_mb=512
        ) as monitor:
            monitor.check_time()  # Should not raise

    def test_does_not_raise_when_exception_already_active(
        self,
    ):
        """Test monitor does not mask existing exceptions."""
        with (  # noqa: PT012
            pytest.raises(ValueError, match="test error"),
            ResourceMonitor(
                max_time_seconds=0.01,
                max_memory_mb=512,
            ),
        ):
            time.sleep(0.05)
            raise ValueError("test error")


class TestResourceMonitorMemory:
    """Test memory monitoring."""

    def test_passes_within_memory_limit(self):
        """Test that small operations pass without error."""
        with ResourceMonitor(max_time_seconds=30.0, max_memory_mb=512):
            _ = b"x" * 1024  # Tiny allocation

    def test_get_peak_rss_bytes_returns_positive(self):
        """Test that peak RSS measurement returns positive value."""
        rss = ResourceMonitor._get_peak_rss_bytes()
        assert rss > 0


class TestResourceMonitorProperties:
    """Test ResourceMonitor property accessors."""

    def test_elapsed_before_enter(self):
        """Test elapsed returns 0 before entering context."""
        monitor = ResourceMonitor()
        assert monitor.elapsed == 0.0

    def test_elapsed_during_context(self):
        """Test elapsed returns positive value during context."""
        with ResourceMonitor(
            max_time_seconds=30.0, max_memory_mb=512
        ) as monitor:
            time.sleep(0.01)
            assert monitor.elapsed > 0.0

    def test_memory_delta_before_enter(self):
        """Test memory_delta returns 0 before entering context."""
        monitor = ResourceMonitor()
        assert monitor.memory_delta == 0

    def test_memory_delta_during_context(self):
        """Test memory_delta returns a value during context."""
        with ResourceMonitor(
            max_time_seconds=30.0, max_memory_mb=512
        ) as monitor:
            # Just verify it's an integer
            assert isinstance(monitor.memory_delta, int)


class TestResourceLimitErrorAttributes:
    """Test ResourceLimitError exception attributes."""

    def test_time_exceeded_error_attributes(self):
        """Test error attributes for time exceeded."""
        err = ResourceLimitError(
            message="Time exceeded",
            error_code=ErrorCode.RESOURCE_TIME_EXCEEDED,
            elapsed_seconds=5.5,
        )
        assert err.elapsed_seconds == 5.5
        assert err.memory_bytes is None
        assert err.error_code == ErrorCode.RESOURCE_TIME_EXCEEDED

    def test_memory_exceeded_error_attributes(self):
        """Test error attributes for memory exceeded."""
        err = ResourceLimitError(
            message="Memory exceeded",
            error_code=ErrorCode.RESOURCE_MEMORY_EXCEEDED,
            memory_bytes=1024 * 1024 * 600,
        )
        assert err.memory_bytes == 1024 * 1024 * 600
        assert err.elapsed_seconds is None
        assert err.error_code == ErrorCode.RESOURCE_MEMORY_EXCEEDED

    def test_generic_resource_limit_error(self):
        """Test generic resource limit error."""
        err = ResourceLimitError(
            message="Resource limit",
            error_code=ErrorCode.RESOURCE_LIMIT_EXCEEDED,
        )
        assert err.error_code == ErrorCode.RESOURCE_LIMIT_EXCEEDED
        assert err.elapsed_seconds is None
        assert err.memory_bytes is None

    def test_inherits_from_file_processing_error(self):
        """Test that ResourceLimitError is a FileProcessingError."""
        from safeuploads.exceptions import FileProcessingError

        err = ResourceLimitError(message="test")
        assert isinstance(err, FileProcessingError)


class TestResourceMonitorMemoryExceeded:
    """Test memory limit enforcement via mocked RSS."""

    def test_memory_exceeded_raises_at_exit(self, monkeypatch):
        """
        Test that exceeding memory limit raises at exit.

        Uses monkeypatch to fake RSS growth, making the
        memory check deterministic.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        _calls = {"n": 0}

        def _fake_rss() -> int:
            _calls["n"] += 1
            if _calls["n"] == 1:
                return 100 * 1024 * 1024  # 100 MB at entry
            # 700 MB at exit → delta = 600 MB
            return 700 * 1024 * 1024

        monkeypatch.setattr(
            ResourceMonitor, "_get_peak_rss_bytes", staticmethod(_fake_rss)
        )

        with (
            pytest.raises(ResourceLimitError) as exc_info,
            ResourceMonitor(
                max_time_seconds=30.0,
                max_memory_mb=512,
            ),
        ):
            pass  # Immediate exit

        assert exc_info.value.error_code == ErrorCode.RESOURCE_MEMORY_EXCEEDED
        assert exc_info.value.memory_bytes is not None
        assert "memory limit" in str(exc_info.value).lower()

    def test_check_memory_passes_within_limit(self):
        """Test that check_memory does not raise within the limit."""
        with ResourceMonitor(
            max_time_seconds=30.0, max_memory_mb=512
        ) as monitor:
            monitor.check_memory()  # Should not raise

    def test_check_memory_raises_when_exceeded(self, monkeypatch):
        """
        Test that check_memory raises mid-operation on growth.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        rss_mb = {"value": 100}  # 100 MB at entry
        monkeypatch.setattr(
            ResourceMonitor,
            "_get_peak_rss_bytes",
            staticmethod(lambda: rss_mb["value"] * 1024 * 1024),
        )

        # Exit the block so the monitor stops being the active one
        with ResourceMonitor(
            max_time_seconds=30.0, max_memory_mb=512
        ) as monitor:
            rss_mb["value"] = 700  # 700 MB later → delta 600 MB
            with pytest.raises(ResourceLimitError) as exc_info:
                monitor.check_memory()
            rss_mb["value"] = 100

        assert exc_info.value.error_code == ErrorCode.RESOURCE_MEMORY_EXCEEDED


def _check_repeatedly(limit: float, clock, progress: list[int]) -> None:
    """Run up to 100 checks in a monitor while the clock advances."""
    with ResourceMonitor(max_time_seconds=limit):
        clock.advancing = True
        for _ in range(100):
            check_resource_limits()
            progress.append(1)


def _nested_then_outer_check(clock, progress: list[int]) -> None:
    """Spend outer budget in a nested monitor, then check the outer."""
    with ResourceMonitor(max_time_seconds=10.0):
        with ResourceMonitor(max_time_seconds=1000.0):
            clock.advancing = True
            clock.step = 50.0
            check_resource_limits()
        clock.step = 0.0
        check_resource_limits()
        progress.append(1)


class TestCheckResourceLimits:
    """Test enforcement of the active monitor during the work."""

    def test_no_active_monitor_is_a_no_op(self, fake_clock):
        """Test the check does nothing outside a monitor."""
        fake_clock.advancing = True
        fake_clock.step = 1000.0
        check_resource_limits()

    def test_within_limits_passes(self, fake_clock):
        """Test the check passes while the work stays in budget."""
        progress: list[int] = []
        fake_clock.step = 0.05
        _check_repeatedly(10.0, fake_clock, progress)
        assert len(progress) == 100

    def test_time_exceeded_raises_mid_operation(self, fake_clock):
        """Test the check raises as soon as the time limit is spent."""
        progress: list[int] = []
        with pytest.raises(ResourceLimitError) as exc_info:
            _check_repeatedly(10.0, fake_clock, progress)

        assert exc_info.value.error_code == ErrorCode.RESOURCE_TIME_EXCEEDED
        assert len(progress) == 10

    def test_memory_exceeded_raises_mid_operation(self, monkeypatch):
        """
        Test the check raises when peak RSS grows past the limit.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        rss_mb = {"value": 100}
        monkeypatch.setattr(
            ResourceMonitor,
            "_get_peak_rss_bytes",
            staticmethod(lambda: rss_mb["value"] * 1024 * 1024),
        )
        with ResourceMonitor(max_memory_mb=512):
            check_resource_limits()
            rss_mb["value"] = 700
            with pytest.raises(ResourceLimitError) as exc_info:
                check_resource_limits()
            rss_mb["value"] = 100

        assert exc_info.value.error_code == ErrorCode.RESOURCE_MEMORY_EXCEEDED

    def test_monitor_inactive_after_exit(self, fake_clock):
        """Test leaving the block deactivates the monitor."""
        with ResourceMonitor(max_time_seconds=10.0):
            pass
        fake_clock.advancing = True
        fake_clock.step = 1000.0
        check_resource_limits()

    def test_monitor_inactive_after_exception(self, fake_clock):
        """Test an exception leaving the block deactivates it."""

        def _fail_inside_monitor() -> None:
            with ResourceMonitor(max_time_seconds=10.0):
                raise ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            _fail_inside_monitor()
        fake_clock.advancing = True
        fake_clock.step = 1000.0
        check_resource_limits()

    def test_nested_monitor_restores_outer(self, fake_clock):
        """Test the outer monitor is enforced again after a nested one."""
        progress: list[int] = []
        with pytest.raises(ResourceLimitError) as exc_info:
            _nested_then_outer_check(fake_clock, progress)

        assert exc_info.value.error_code == ErrorCode.RESOURCE_TIME_EXCEEDED
        # Raised by the check after the nested block, not at exit
        assert progress == []


class TestResourceMonitorLimitBoundaries:
    """Tests that a limit accepts its value and rejects the next."""

    def test_time_at_limit_accepted(self):
        """Elapsed time equal to the limit passes."""
        monitor = ResourceMonitor(max_time_seconds=5.0, max_memory_mb=1)

        monitor._raise_if_time_exceeded(5.0)

    def test_time_over_limit_rejected(self):
        """Elapsed time just above the limit raises."""
        monitor = ResourceMonitor(max_time_seconds=5.0, max_memory_mb=1)

        with pytest.raises(ResourceLimitError) as exc_info:
            monitor._raise_if_time_exceeded(5.01)

        assert exc_info.value.error_code == ErrorCode.RESOURCE_TIME_EXCEEDED

    def test_memory_at_limit_accepted(self):
        """Growth equal to the limit passes."""
        monitor = ResourceMonitor(max_time_seconds=5.0, max_memory_mb=1)

        monitor._raise_if_memory_exceeded(1024 * 1024)

    def test_memory_over_limit_rejected(self):
        """Growth one byte over the limit raises."""
        monitor = ResourceMonitor(max_time_seconds=5.0, max_memory_mb=1)

        with pytest.raises(ResourceLimitError) as exc_info:
            monitor._raise_if_memory_exceeded(1024 * 1024 + 1)

        assert exc_info.value.error_code == ErrorCode.RESOURCE_MEMORY_EXCEEDED
        assert exc_info.value.memory_bytes == 1024 * 1024 + 1


def _decompress(data: bytes, chunk_size: int = 64) -> list[bytes]:
    """Return the chunks ``iter_gzip_chunks`` yields for ``data``."""
    return list(iter_gzip_chunks(io.BytesIO(data), chunk_size))


class TestIterGzipChunks:
    """``iter_gzip_chunks`` decompresses gzip data in bounded steps."""

    def test_single_member(self):
        """A single member round-trips."""
        payload = b"hello gzip " * 50
        chunks = _decompress(gzip.compress(payload))
        assert b"".join(chunks) == payload

    def test_chunks_never_exceed_chunk_size(self):
        """Every yielded chunk is non-empty and at most chunk_size."""
        payload = bytes(range(256)) * 40
        chunks = _decompress(gzip.compress(payload), chunk_size=100)
        assert len(chunks) > 1
        assert all(0 < len(chunk) <= 100 for chunk in chunks)
        assert b"".join(chunks) == payload

    def test_multi_member(self):
        """Concatenated members decompress to the joined payloads."""
        data = gzip.compress(b"first ") + gzip.compress(b"second")
        assert b"".join(_decompress(data)) == b"first second"

    def test_zero_padding_between_and_after_members(self):
        """Zero padding is skipped, as the gzip module does."""
        data = (
            gzip.compress(b"a")
            + b"\x00" * 300
            + gzip.compress(b"b")
            + b"\x00" * 300
        )
        assert b"".join(_decompress(data)) == b"ab"
        assert gzip.decompress(data) == b"ab"

    def test_trailing_garbage_raises(self):
        """Non-zero data after the last member is a zlib error."""
        with pytest.raises(zlib.error):
            _decompress(gzip.compress(b"a") + b"garbage")

    def test_truncated_member_raises_eof(self):
        """Input ending inside a member raises EOFError."""
        data = gzip.compress(bytes(range(256)) * 100)
        with pytest.raises(EOFError):
            _decompress(data[: len(data) // 2])

    def test_truncated_trailer_raises_eof(self):
        """A member missing its trailer raises EOFError."""
        with pytest.raises(EOFError):
            _decompress(gzip.compress(b"abc" * 100)[:-4])

    def test_corrupted_crc_raises(self):
        """A wrong CRC is a zlib error."""
        data = bytearray(gzip.compress(b"abc" * 100))
        data[-8] ^= 0xFF
        with pytest.raises(zlib.error):
            _decompress(bytes(data))

    def test_not_gzip_raises(self):
        """Data without a gzip header is a zlib error."""
        with pytest.raises(zlib.error):
            _decompress(b"plain text, not gzip")

    def test_empty_input_yields_nothing(self):
        """An empty stream yields no chunks."""
        assert _decompress(b"") == []

    def test_leading_zeros_raise(self):
        """Zero bytes before the first member are a zlib error."""
        data = b"\x00" * 200 + gzip.compress(b"a")
        with pytest.raises(zlib.error):
            _decompress(data)
        with pytest.raises(gzip.BadGzipFile):
            gzip.decompress(data)

    def test_many_empty_members_exceed_time_limit(self, fake_clock):
        """Empty members cannot run past the monitor's time limit."""
        data = gzip.compress(b"", 0) * 5000

        with pytest.raises(ResourceLimitError) as exc_info:
            fake_clock.run_monitored(lambda: _decompress(data, chunk_size=64))

        assert exc_info.value.error_code == ErrorCode.RESOURCE_TIME_EXCEEDED

    def test_many_empty_members_within_budget(self, fake_clock):
        """The same stream completes when time stays in budget."""
        data = gzip.compress(b"", 0) * 50
        fake_clock.step = 0.001

        fake_clock.run_monitored(lambda: _decompress(data, chunk_size=64))
