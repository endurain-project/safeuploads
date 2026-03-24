"""Tests for ResourceMonitor utility."""

import time

import pytest

from safeuploads.exceptions import (
    ErrorCode,
    ResourceLimitError,
)
from safeuploads.utils import ResourceMonitor


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

    def test_get_rss_bytes_returns_positive(self):
        """Test that RSS measurement returns positive value."""
        rss = ResourceMonitor._get_rss_bytes()
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
            ResourceMonitor, "_get_rss_bytes", staticmethod(_fake_rss)
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
