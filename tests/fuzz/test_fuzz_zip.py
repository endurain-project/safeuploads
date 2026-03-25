"""Fuzz tests for ZIP validation."""

import io
import struct
import zipfile

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.exceptions import (
    CompressionSecurityError,
    FileProcessingError,
    FileValidationError,
    ZipBombError,
    ZipContentError,
)
from safeuploads.inspectors.zip_inspector import ZipContentInspector
from safeuploads.validators.compression_validator import (
    CompressionSecurityValidator,
)


# Strategy: random filenames for ZIP entries
_entry_name = st.text(
    alphabet=st.characters(
        whitelist_categories=("L", "N", "P"),
        blacklist_characters="\x00",
    ),
    min_size=1,
    max_size=50,
).map(lambda s: s + ".txt")

# Strategy: random binary content
_content = st.binary(min_size=0, max_size=1024)


@pytest.mark.fuzz
class TestFuzzZipInspector:
    """Property tests for ZIP content inspection."""

    @given(
        entries=st.dictionaries(
            keys=_entry_name,
            values=_content,
            min_size=1,
            max_size=20,
        )
    )
    @settings(max_examples=200, deadline=5000)
    def test_inspect_never_crashes(self, entries):
        """Inspection must not raise unhandled exceptions."""
        config = FileSecurityConfig()
        inspector = ZipContentInspector(config)

        buf = io.BytesIO()
        try:
            with zipfile.ZipFile(buf, "w") as zf:
                for name, data in entries.items():
                    zf.writestr(name, data)
        except Exception:
            return  # Invalid ZIP construction

        try:
            inspector.inspect_zip_content(
                io.BytesIO(buf.getvalue())
            )
        except (
            ZipContentError,
            FileProcessingError,
        ):
            pass  # Expected rejections

    @given(data=st.binary(min_size=4, max_size=200))
    @settings(max_examples=200, deadline=3000)
    def test_inspect_random_bytes_never_crashes(self, data):
        """Random bytes must not cause unhandled crashes."""
        config = FileSecurityConfig()
        inspector = ZipContentInspector(config)

        try:
            inspector.inspect_zip_content(io.BytesIO(data))
        except (
            ZipContentError,
            FileProcessingError,
        ):
            pass


@pytest.mark.fuzz
class TestFuzzCompressionValidator:
    """Property tests for compression validation."""

    @given(
        num_files=st.integers(min_value=1, max_value=50),
        content_size=st.integers(
            min_value=1, max_value=5000
        ),
        content_byte=st.integers(
            min_value=0, max_value=255
        ),
    )
    @settings(max_examples=100, deadline=5000)
    def test_validate_never_crashes(
        self, num_files, content_size, content_byte
    ):
        """Compression check must not crash."""
        config = FileSecurityConfig()
        validator = CompressionSecurityValidator(config)

        buf = io.BytesIO()
        with zipfile.ZipFile(
            buf, "w", zipfile.ZIP_DEFLATED
        ) as zf:
            for i in range(num_files):
                zf.writestr(
                    f"file_{i}.txt",
                    bytes([content_byte]) * content_size,
                )

        zip_bytes = buf.getvalue()
        try:
            validator.validate_zip_compression_ratio(
                io.BytesIO(zip_bytes), len(zip_bytes)
            )
        except (
            ZipBombError,
            CompressionSecurityError,
            FileProcessingError,
        ):
            pass
