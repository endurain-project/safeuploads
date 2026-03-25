"""Fuzz tests for filename sanitization."""

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from safeuploads.exceptions import (
    ExtensionSecurityError,
    FileValidationError,
    UnicodeSecurityError,
    WindowsReservedNameError,
)
from safeuploads.file_validator import FileValidator


# Strategy: arbitrary Unicode text including control chars
_unicode_text = st.text(
    alphabet=st.characters(), min_size=1, max_size=300
)

# Strategy: printable filenames with random extensions
_printable_filename = st.from_regex(
    r"[a-zA-Z0-9_\- ]{1,100}\.[a-z]{1,5}", fullmatch=True
)


@pytest.mark.fuzz
class TestFuzzFilenameSanitization:
    """Property tests for _sanitize_filename."""

    @given(filename=_unicode_text)
    @settings(max_examples=500, deadline=2000)
    def test_sanitize_never_crashes(self, filename):
        """Sanitization must not raise unhandled exceptions."""
        validator = FileValidator()
        try:
            validator._sanitize_filename(filename)
        except (
            ValueError,
            FileValidationError,
        ):
            pass  # Expected rejections

    @given(filename=_unicode_text)
    @settings(max_examples=500, deadline=2000)
    def test_sanitize_no_path_traversal(self, filename):
        """Sanitized name must not contain traversal sequences."""
        validator = FileValidator()
        try:
            result = validator._sanitize_filename(filename)
        except (ValueError, FileValidationError):
            return
        assert "/" not in result
        assert "\\" not in result
        assert "../" not in result
        assert "..\\" not in result

    @given(filename=_unicode_text)
    @settings(max_examples=500, deadline=2000)
    def test_sanitize_no_null_bytes(self, filename):
        """Sanitized name must not contain null bytes."""
        validator = FileValidator()
        try:
            result = validator._sanitize_filename(filename)
        except (ValueError, FileValidationError):
            return
        assert "\x00" not in result

    @given(filename=_unicode_text)
    @settings(max_examples=500, deadline=2000)
    def test_sanitize_no_control_chars(self, filename):
        """Sanitized name must not contain control chars."""
        validator = FileValidator()
        try:
            result = validator._sanitize_filename(filename)
        except (ValueError, FileValidationError):
            return
        for ch in result:
            assert ord(ch) >= 32
            assert ch != "\x7f"

    @given(
        name=st.text(
            alphabet=st.characters(
                whitelist_categories=("L", "N"),
            ),
            min_size=1,
            max_size=50,
        ),
        ext=st.sampled_from(
            [".jpg", ".png", ".txt", ".pdf", ".gpx"]
        ),
    )
    @settings(max_examples=200, deadline=2000)
    def test_sanitize_preserves_safe_extension(
        self, name, ext
    ):
        """Safe filenames keep their extension."""
        validator = FileValidator()
        filename = name + ext
        try:
            result = validator._sanitize_filename(filename)
        except (ValueError, FileValidationError):
            return
        assert result.endswith(ext)

    @given(length=st.integers(min_value=200, max_value=1000))
    @settings(max_examples=50, deadline=2000)
    def test_sanitize_limits_length(self, length):
        """Extremely long names are truncated."""
        validator = FileValidator()
        filename = "a" * length + ".txt"
        try:
            result = validator._sanitize_filename(filename)
        except (ValueError, FileValidationError):
            return
        # Name part capped at 100 + extension
        assert len(result) <= 104
