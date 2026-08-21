"""Tests for ResourceMonitor utility."""

import time

import pytest

from safeuploads.exceptions import (
    ErrorCode,
    ResourceLimitError,
)
from safeuploads.utils import (
    ResourceMonitor,
    find_text_pattern,
    parse_image_dimensions,
    safe_label,
    strip_unsafe_chars,
)
from tests.conftest import JPEG_SOF0


class TestSafeLabel:
    """Untrusted text is escaped before it reaches a log."""

    def test_plain_text_unchanged(self):
        """Test ordinary filenames pass through untouched."""
        assert safe_label("holiday-photo.jpg") == "holiday-photo.jpg"

    def test_non_ascii_preserved(self):
        """Test legitimate non-ASCII names stay readable."""
        assert safe_label("caf\u00e9.jpg") == "caf\u00e9.jpg"

    def test_empty_value(self):
        """Test empty input yields empty output."""
        assert safe_label("") == ""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("a\nb", "a\\u000ab"),
            ("a\rb", "a\\u000db"),
            ("a\u202eb", "a\\u202eb"),
            ("a\u2028b", "a\\u2028b"),
            ("a\x00b", "a\\u0000b"),
        ],
    )
    def test_control_characters_escaped(self, raw, expected):
        """Test newline and format characters cannot break a line."""
        assert safe_label(raw) == expected

    def test_forged_log_line_neutralised(self):
        """Test a crafted filename cannot inject a log record."""
        result = safe_label("ok.jpg\nWARNING forged entry")
        assert "\n" not in result

    def test_truncates_long_values(self):
        """Test oversized input is bounded and marked."""
        result = safe_label("a" * 400, max_length=16)
        assert result == "a" * 16 + "..."

    def test_exact_length_is_not_marked_truncated(self):
        """Test the boundary case keeps the value intact."""
        assert safe_label("a" * 16, max_length=16) == "a" * 16

    def test_default_length_bound(self):
        """Test the documented default bound is applied."""
        assert safe_label("a" * 300) == "a" * 256 + "..."
        assert safe_label("a" * 256) == "a" * 256


class TestStripUnsafeChars:
    """Log-breaking code points are removed, not escaped."""

    def test_plain_text_unchanged(self):
        """Test ordinary filenames pass through untouched."""
        assert strip_unsafe_chars("holiday-photo.jpg") == "holiday-photo.jpg"

    def test_non_ascii_preserved(self):
        """Test legitimate non-ASCII names stay readable."""
        assert strip_unsafe_chars("caf\u00e9.jpg") == "caf\u00e9.jpg"

    def test_empty_value(self):
        """Test empty input yields empty output."""
        assert strip_unsafe_chars("") == ""

    @pytest.mark.parametrize(
        "raw",
        [
            "a\x00b.jpg",  # C0 null
            "a\nb.jpg",  # C0 newline
            "a\x7fb.jpg",  # Delete
            "a\x85b.jpg",  # C1 next-line
            "a\x9bb.jpg",  # C1 control sequence introducer
            "a\u2028b.jpg",  # Line separator
            "a\u2029b.jpg",  # Paragraph separator
            "a\u200bb.jpg",  # Zero-width space (format)
        ],
    )
    def test_unsafe_code_points_removed(self, raw):
        """Test every log-breaking category is stripped."""
        assert strip_unsafe_chars(raw) == "ab.jpg"


class TestFindTextPattern:
    """Pattern scanning runs over raw bytes."""

    def test_match_is_case_insensitive(self):
        """Test uppercase content matches a lower-case pattern."""
        assert find_text_pattern(b"XX<?PHP", ("<?php",)) == "<?php"

    def test_no_match_returns_none(self):
        """Test absent patterns yield None."""
        assert find_text_pattern(b"clean content", ("<?php",)) is None

    def test_empty_pattern_set_returns_none(self):
        """Test an empty pattern set never matches."""
        assert find_text_pattern(b"anything", ()) is None

    def test_undecodable_bytes_do_not_raise(self):
        """Test invalid UTF-8 is scanned without decoding."""
        assert find_text_pattern(b"\xff\xfe\xfd", ("<?php",)) is None


def _png(width: int, height: int) -> bytes:
    """Build a PNG header declaring the given dimensions."""
    return (
        b"\x89PNG\r\n\x1a\n"
        + b"\x00\x00\x00\x0d"
        + b"IHDR"
        + width.to_bytes(4, "big")
        + height.to_bytes(4, "big")
    )


class TestParseImageDimensions:
    """Tests for PNG/JPEG dimension extraction."""

    def test_png_dimensions(self):
        """Test PNG IHDR dimensions are read."""
        assert parse_image_dimensions(_png(1920, 1080)) == (1920, 1080)

    def test_png_truncated_returns_none(self):
        """Test truncated PNG header yields no dimensions."""
        assert parse_image_dimensions(_png(10, 10)[:20]) is None

    def test_png_without_ihdr_returns_none(self):
        """Test PNG whose first chunk is not IHDR is rejected."""
        content = (
            b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x0d" + b"IDAT" + b"\x00" * 8
        )
        assert parse_image_dimensions(content) is None

    def test_jpeg_dimensions(self):
        """Test JPEG SOF0 dimensions are read."""
        assert parse_image_dimensions(b"\xff\xd8" + JPEG_SOF0) == (16, 16)

    def test_jpeg_skips_app_segment(self):
        """Test segments before the frame header are skipped."""
        app0 = b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        content = b"\xff\xd8" + app0 + JPEG_SOF0
        assert parse_image_dimensions(content) == (16, 16)

    def test_jpeg_tolerates_fill_bytes(self):
        """Test 0xFF padding before a marker is skipped."""
        content = b"\xff\xd8" + b"\xff" * 4 + JPEG_SOF0
        assert parse_image_dimensions(content) == (16, 16)

    def test_jpeg_skips_standalone_marker(self):
        """Test standalone markers carry no length field."""
        content = b"\xff\xd8" + b"\xff\xd0" + JPEG_SOF0
        assert parse_image_dimensions(content) == (16, 16)

    def test_jpeg_desynchronised_returns_none(self):
        """Test a non-marker byte where a segment must start."""
        content = b"\xff\xd8" + b"\x00\x11\x22\x33" + JPEG_SOF0
        assert parse_image_dimensions(content) is None

    @pytest.mark.parametrize("marker", [b"\xff\xd9", b"\xff\xda"])
    def test_jpeg_scan_end_before_frame(self, marker):
        """Test EOI or SOS before any frame header."""
        content = b"\xff\xd8" + marker + JPEG_SOF0
        assert parse_image_dimensions(content) is None

    def test_jpeg_invalid_segment_length(self):
        """Test a segment length below the minimum is rejected."""
        content = b"\xff\xd8" + b"\xff\xe0\x00\x01" + JPEG_SOF0
        assert parse_image_dimensions(content) is None

    def test_jpeg_truncated_frame_header(self):
        """Test a frame header cut short yields no dimensions."""
        content = b"\xff\xd8" + JPEG_SOF0[:6] + b"\x00\x00"
        assert parse_image_dimensions(content) is None

    def test_unsupported_format_returns_none(self):
        """Test a non-PNG, non-JPEG payload yields no dimensions."""
        assert parse_image_dimensions(b"GIF89a" + b"\x00" * 32) is None


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

    def test_check_enforces_time_budget(self):
        """Test check() raises once the time budget is spent."""
        with (
            pytest.raises(ResourceLimitError) as exc_info,
            ResourceMonitor(max_time_seconds=0.0) as monitor,
        ):
            monitor.check()
        assert exc_info.value.error_code == ErrorCode.RESOURCE_TIME_EXCEEDED

    def test_check_passes_within_budget(self):
        """Test check() is a no-op while within limits."""
        with ResourceMonitor(max_time_seconds=30.0) as monitor:
            monitor.check()


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
                enforce_memory=True,
            ),
        ):
            pass  # Immediate exit

        assert exc_info.value.error_code == ErrorCode.RESOURCE_MEMORY_EXCEEDED
        assert exc_info.value.memory_bytes is not None
        assert "memory limit" in str(exc_info.value).lower()

    def test_memory_overrun_warns_when_not_enforced(self, monkeypatch, caplog):
        """
        Test the default posture reports but does not fail.

        Args:
            monkeypatch: pytest monkeypatch fixture.
            caplog: pytest log capture fixture.
        """
        _calls = {"n": 0}

        def _fake_rss() -> int:
            _calls["n"] += 1
            if _calls["n"] == 1:
                return 100 * 1024 * 1024
            return 700 * 1024 * 1024

        monkeypatch.setattr(
            ResourceMonitor, "_get_peak_rss_bytes", staticmethod(_fake_rss)
        )

        with (
            caplog.at_level("WARNING", logger="safeuploads.utils"),
            ResourceMonitor(max_time_seconds=30.0, max_memory_mb=512),
        ):
            pass

        assert "not enforced" in caplog.text

    def test_check_skips_memory_when_not_enforced(self, monkeypatch):
        """
        Test check() does not sample memory unless enforcing.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        _calls = {"n": 0}

        def _fake_rss() -> int:
            _calls["n"] += 1
            return 100 * 1024 * 1024

        monkeypatch.setattr(
            ResourceMonitor, "_get_peak_rss_bytes", staticmethod(_fake_rss)
        )

        with ResourceMonitor(max_time_seconds=30.0) as monitor:
            baseline = _calls["n"]
            monitor.check()
            assert _calls["n"] == baseline

    def test_check_samples_memory_when_enforced(self, monkeypatch):
        """
        Test check() enforces the memory budget when enabled.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        _calls = {"n": 0}

        def _fake_rss() -> int:
            _calls["n"] += 1
            if _calls["n"] == 1:
                return 100 * 1024 * 1024
            return 700 * 1024 * 1024

        monkeypatch.setattr(
            ResourceMonitor, "_get_peak_rss_bytes", staticmethod(_fake_rss)
        )

        with (
            pytest.raises(ResourceLimitError) as exc_info,
            ResourceMonitor(
                max_time_seconds=30.0,
                max_memory_mb=512,
                enforce_memory=True,
            ) as monitor,
        ):
            monitor.check()

        assert exc_info.value.error_code == ErrorCode.RESOURCE_MEMORY_EXCEEDED

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
        _calls = {"n": 0}

        def _fake_rss() -> int:
            _calls["n"] += 1
            if _calls["n"] == 1:
                return 100 * 1024 * 1024  # 100 MB at entry
            return 700 * 1024 * 1024  # 700 MB later → delta 600 MB

        monkeypatch.setattr(
            ResourceMonitor, "_get_peak_rss_bytes", staticmethod(_fake_rss)
        )

        monitor = ResourceMonitor(
            max_time_seconds=30.0, max_memory_mb=512, enforce_memory=True
        )
        monitor.__enter__()
        with pytest.raises(ResourceLimitError) as exc_info:
            monitor.check_memory()

        assert exc_info.value.error_code == ErrorCode.RESOURCE_MEMORY_EXCEEDED
