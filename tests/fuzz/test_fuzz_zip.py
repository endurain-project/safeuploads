"""Fuzz tests for ZIP validation."""

import io
import zipfile

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from safeuploads.config import FileSecurityConfig
from safeuploads.exceptions import CompressionSecurityError, ErrorCode
from safeuploads.file_validator import FileValidator
from safeuploads.inspectors.zip_inspector import ZipContentInspector
from safeuploads.validators.compression_validator import (
    CompressionSecurityValidator,
)
from tests.fuzz.helpers import MockFile, accepted, accepted_async

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


def _assert_entries_safe(config, data):
    """Check an accepted archive opens and its names obey the limits."""
    limits = config.limits
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = zf.infolist()
    for info in infos:
        name = info.filename
        assert "\x00" not in info.orig_filename
        assert ".." not in name.replace("\\", "/").split("/")
        assert not name.startswith(("/", "\\"))
        assert len(name) <= limits.max_path_length
        assert len(name.rsplit("/", 1)[-1]) <= limits.max_filename_length


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

        data = buf.getvalue()
        if accepted(inspector.inspect_zip_content, io.BytesIO(data)):
            _assert_entries_safe(config, data)

    @given(data=st.binary(min_size=4, max_size=200))
    @settings(max_examples=200, deadline=3000)
    def test_inspect_random_bytes_never_crashes(self, data):
        """Random bytes must not cause unhandled crashes."""
        config = FileSecurityConfig()
        inspector = ZipContentInspector(config)

        if accepted(inspector.inspect_zip_content, io.BytesIO(data)):
            _assert_entries_safe(config, data)


@pytest.mark.fuzz
class TestFuzzZipPipeline:
    """Property tests for the full ZIP validation pipeline."""

    @given(tail=st.binary(min_size=0, max_size=300))
    @settings(max_examples=200, deadline=5000)
    @pytest.mark.asyncio
    async def test_zip_signature_with_random_tail(self, tail):
        """Corrupt data behind a ZIP signature is rejected cleanly."""
        data = b"PK\x03\x04" + tail
        validator = FileValidator()
        file = MockFile("fuzz.zip", data)
        if await accepted_async(validator.validate_zip_file(file)):
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                assert len(zf.infolist()) <= (
                    validator.config.limits.max_zip_entries
                )


@pytest.mark.fuzz
class TestFuzzCompressionValidator:
    """Property tests for compression validation."""

    @given(
        num_files=st.integers(min_value=1, max_value=50),
        content_size=st.integers(min_value=1, max_value=5000),
        content_byte=st.integers(min_value=0, max_value=255),
    )
    @settings(max_examples=100, deadline=5000)
    def test_validate_never_crashes(
        self, num_files, content_size, content_byte
    ):
        """Compression check must not crash."""
        config = FileSecurityConfig()
        validator = CompressionSecurityValidator(config)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for i in range(num_files):
                zf.writestr(
                    f"file_{i}.txt",
                    bytes([content_byte]) * content_size,
                )

        zip_bytes = buf.getvalue()
        if accepted(
            validator.validate_zip_compression_ratio,
            io.BytesIO(zip_bytes),
            len(zip_bytes),
        ):
            limits = config.limits
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                infos = zf.infolist()
            assert len(infos) <= limits.max_zip_entries
            assert (
                sum(i.file_size for i in infos) <= limits.max_uncompressed_size
            )
            for info in infos:
                assert info.file_size <= limits.max_individual_file_size
                if info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    assert ratio <= limits.max_compression_ratio


@pytest.mark.fuzz
class TestKnownBugs:
    """Regression tests pinning bugs found by fuzzing."""

    def test_inspector_maps_non_zip_to_validation_error(self):
        """Corrupt ZIP data is rejected with ZIP_CORRUPT."""
        inspector = ZipContentInspector(FileSecurityConfig())
        with pytest.raises(CompressionSecurityError) as exc_info:
            inspector.inspect_zip_content(io.BytesIO(b"\x00\x00\x00\x00"))
        assert exc_info.value.error_code == ErrorCode.ZIP_CORRUPT
