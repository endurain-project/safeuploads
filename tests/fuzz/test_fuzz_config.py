"""Fuzz tests for SecurityLimits configuration."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.file_validator import FileValidator


@pytest.mark.fuzz
class TestFuzzConfig:
    """Property tests for configuration edge cases."""

    @given(
        max_image=st.integers(min_value=1, max_value=2**30),
        max_zip=st.integers(min_value=1, max_value=2**30),
        ratio=st.integers(min_value=1, max_value=10000),
        entries=st.integers(min_value=1, max_value=100000),
        timeout=st.floats(
            min_value=0.01,
            max_value=60.0,
            allow_nan=False,
            allow_infinity=False,
        ),
    )
    @settings(max_examples=200, deadline=3000)
    def test_security_limits_accepts_valid_values(
        self, max_image, max_zip, ratio, entries, timeout
    ):
        """SecurityLimits must accept valid int/float combos."""
        limits = SecurityLimits(
            max_image_size=max_image,
            max_zip_size=max_zip,
            max_compression_ratio=ratio,
            max_zip_entries=entries,
            zip_analysis_timeout=timeout,
        )
        assert limits.max_image_size == max_image
        assert limits.max_zip_size == max_zip

    @given(
        max_image=st.integers(min_value=1, max_value=2**20),
        chunk=st.integers(min_value=512, max_value=2**18),
    )
    @settings(max_examples=100, deadline=3000)
    def test_validator_init_with_random_config(self, max_image, chunk):
        """FileValidator must init with any valid config."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            max_image_size=max_image,
            chunk_size=chunk,
        )
        validator = FileValidator(config=config)
        assert validator.config.limits.max_image_size == max_image

    @given(
        depth=st.integers(min_value=1, max_value=100),
        fname_len=st.integers(min_value=1, max_value=1024),
        path_len=st.integers(min_value=1, max_value=4096),
    )
    @settings(max_examples=100, deadline=2000)
    def test_zip_limits_accept_valid_ranges(self, depth, fname_len, path_len):
        """ZIP inspection limits accept valid ranges."""
        limits = SecurityLimits(
            max_zip_depth=depth,
            max_filename_length=fname_len,
            max_path_length=path_len,
        )
        assert limits.max_zip_depth == depth
        assert limits.max_filename_length == fname_len

    @given(
        buffer_size=st.integers(min_value=1024, max_value=100 * 1024 * 1024),
        memory_mb=st.integers(min_value=1, max_value=4096),
        time_s=st.floats(
            min_value=0.1,
            max_value=300.0,
            allow_nan=False,
            allow_infinity=False,
        ),
    )
    @settings(max_examples=100, deadline=2000)
    def test_resource_limits_accept_valid_ranges(
        self, buffer_size, memory_mb, time_s
    ):
        """Resource monitoring limits accept valid ranges."""
        limits = SecurityLimits(
            max_memory_buffer_size=buffer_size,
            max_validation_memory_mb=memory_mb,
            max_validation_time_seconds=time_s,
        )
        assert limits.max_memory_buffer_size == buffer_size
        assert limits.max_validation_memory_mb == memory_mb
