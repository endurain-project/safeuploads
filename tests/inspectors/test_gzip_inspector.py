"""Tests for GzipContentInspector."""

import gzip
import hashlib
import io
import struct
import zipfile
import zlib

import pytest

import safeuploads.inspectors.gzip_inspector as gzip_inspector_module
from safeuploads.config import FileSecurityConfig, SecurityLimits
from safeuploads.exceptions import (
    CompressionSecurityError,
    ErrorCode,
    FileProcessingError,
    ResourceLimitError,
    ZipBombError,
    ZipContentError,
)
from safeuploads.inspectors.gzip_inspector import GzipContentInspector


class TestGzipContentInspector:
    """Test suite for GzipContentInspector."""

    def test_initialization(self, default_config):
        """Test inspector initialization."""
        inspector = GzipContentInspector(default_config)
        assert inspector.config == default_config

    def test_valid_gzip_passes(self, default_config):
        """Test inspection of safe gzip file passes."""
        inspector = GzipContentInspector(default_config)
        content = b"Hello, World! " * 100
        buf = io.BytesIO()
        with gzip.open(buf, "wb") as gz:
            gz.write(content)
        compressed = buf.getvalue()
        file_obj = io.BytesIO(compressed)
        inspector.inspect_gzip_content(file_obj, len(compressed))

    def test_reject_excessive_compression_ratio(self):
        """Test rejection of high compression ratio."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            max_compression_ratio=5,
            max_uncompressed_size=100 * 1024 * 1024,
        )
        inspector = GzipContentInspector(config)

        # Highly compressible data
        content = b"\x00" * (1024 * 1024)  # 1MB of zeros
        buf = io.BytesIO()
        with gzip.open(buf, "wb") as gz:
            gz.write(content)
        compressed = buf.getvalue()
        file_obj = io.BytesIO(compressed)

        with pytest.raises(ZipBombError) as exc_info:
            inspector.inspect_gzip_content(file_obj, len(compressed))
        assert (
            exc_info.value.error_code == ErrorCode.COMPRESSION_RATIO_EXCEEDED
        )
        assert "ratio" in str(exc_info.value).lower()

    def test_reject_excessive_uncompressed_size(self):
        """Test rejection of oversized uncompressed output."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            max_compression_ratio=10000,
            max_uncompressed_size=1024,  # 1KB limit
        )
        inspector = GzipContentInspector(config)

        content = b"A" * 2048  # 2KB
        buf = io.BytesIO()
        with gzip.open(buf, "wb") as gz:
            gz.write(content)
        compressed = buf.getvalue()
        file_obj = io.BytesIO(compressed)

        with pytest.raises(ZipBombError) as exc_info:
            inspector.inspect_gzip_content(file_obj, len(compressed))
        assert exc_info.value.error_code == ErrorCode.ZIP_BOMB_DETECTED
        assert "size" in str(exc_info.value).lower()

    def test_reject_corrupted_gzip(self, default_config):
        """Test rejection of corrupted gzip file."""
        inspector = GzipContentInspector(default_config)
        # Valid gzip header but corrupted body
        corrupted = b"\x1f\x8b\x08\x00" + b"corrupted"
        file_obj = io.BytesIO(corrupted)

        with pytest.raises(CompressionSecurityError) as exc_info:
            inspector.inspect_gzip_content(file_obj, len(corrupted))
        assert exc_info.value.error_code == ErrorCode.ZIP_CORRUPT

    def test_corrupt_deflate_data_rejected_as_corrupt(self, default_config):
        """Invalid deflate data (zlib.error) is a corrupt-archive error."""
        inspector = GzipContentInspector(default_config)
        good = gzip.compress(b"hello world" * 100)
        bad = good[:12] + b"\xff\xff\xff\xff" + good[16:]

        with pytest.raises(CompressionSecurityError) as exc_info:
            inspector.inspect_gzip_content(io.BytesIO(bad), len(bad))
        assert exc_info.value.error_code == ErrorCode.ZIP_CORRUPT
        assert isinstance(exc_info.value.__cause__, zlib.error)
        # The untouched stream is accepted
        inspector.inspect_gzip_content(io.BytesIO(good), len(good))

    @pytest.mark.parametrize("offset", [-8, -4], ids=["bad_crc", "bad_length"])
    def test_bad_trailer_rejected_as_corrupt(self, default_config, offset):
        """A wrong CRC or length trailer is a corrupt-archive error."""
        inspector = GzipContentInspector(default_config)
        good = gzip.compress(b"hello world" * 100)
        bad = good[:offset] + b"\x00\x00\x00\x01" + good[offset + 4 :]

        with pytest.raises(CompressionSecurityError) as exc_info:
            inspector.inspect_gzip_content(io.BytesIO(bad), len(bad))
        assert exc_info.value.error_code == ErrorCode.ZIP_CORRUPT

    def test_file_position_reset_after_inspection(self, default_config):
        """Test file position is reset after inspection."""
        inspector = GzipContentInspector(default_config)
        content = b"test data"
        buf = io.BytesIO()
        with gzip.open(buf, "wb") as gz:
            gz.write(content)
        compressed = buf.getvalue()
        file_obj = io.BytesIO(compressed)
        inspector.inspect_gzip_content(file_obj, len(compressed))
        assert file_obj.tell() == 0

    def test_small_gzip_within_limits(self, default_config):
        """Test small gzip file passes all checks."""
        inspector = GzipContentInspector(default_config)
        content = b"small content"
        buf = io.BytesIO()
        with gzip.open(buf, "wb") as gz:
            gz.write(content)
        compressed = buf.getvalue()
        file_obj = io.BytesIO(compressed)
        inspector.inspect_gzip_content(file_obj, len(compressed))

    def test_memory_error_handling(self, default_config, monkeypatch):
        """Test handling of MemoryError during decompression."""
        inspector = GzipContentInspector(default_config)

        def failing_chunks(*args, **kwargs):
            raise MemoryError("Simulated memory error")

        monkeypatch.setattr(
            gzip_inspector_module, "iter_gzip_chunks", failing_chunks
        )

        file_obj = io.BytesIO(b"\x1f\x8b")
        with pytest.raises(ZipBombError) as exc_info:
            inspector.inspect_gzip_content(file_obj, 100)
        assert exc_info.value.error_code == ErrorCode.ZIP_BOMB_DETECTED
        assert "memory" in str(exc_info.value).lower()


class TestGzipInspectorEdgeCases:
    def test_compressed_size_zero_skips_ratio_check(self, default_config):
        inspector = GzipContentInspector(default_config)
        content = b"Hello, World!"
        buf = io.BytesIO()
        with gzip.open(buf, "wb") as gz:
            gz.write(content)
        compressed = buf.getvalue()
        # compressed_size=0 bypasses the in-loop
        # ratio check (line 97) and final ratio
        # log (line 197) — both False branches.
        inspector.inspect_gzip_content(io.BytesIO(compressed), 0)

    def test_eof_error_raises_compression_security_error(self, default_config):
        inspector = GzipContentInspector(default_config)

        # Create valid gzip then truncate to trigger
        # EOFError during decompression
        content = b"A" * 10000
        buf = io.BytesIO()
        with gzip.open(buf, "wb") as gz:
            gz.write(content)
        full = buf.getvalue()
        truncated = full[:15]

        with pytest.raises(CompressionSecurityError) as exc:
            inspector.inspect_gzip_content(
                io.BytesIO(truncated), len(truncated)
            )
        assert exc.value.error_code == ErrorCode.ZIP_CORRUPT
        assert "Truncated" in str(exc.value)

    def test_generic_exception_raises_file_processing_error(
        self, default_config, monkeypatch
    ):
        inspector = GzipContentInspector(default_config)

        content = b"Hello"
        buf = io.BytesIO()
        with gzip.open(buf, "wb") as gz:
            gz.write(content)
        compressed = buf.getvalue()

        def _failing_chunks(*a, **kw):
            raise OSError("disk failure")

        monkeypatch.setattr(
            gzip_inspector_module, "iter_gzip_chunks", _failing_chunks
        )

        with pytest.raises(FileProcessingError) as exc_info:
            inspector.inspect_gzip_content(
                io.BytesIO(compressed), len(compressed)
            )
        assert exc_info.value.error_code == ErrorCode.PROCESSING_ERROR

    def test_size_exceeded_with_correlation_id(self):
        from safeuploads.audit import (
            reset_correlation_id,
            set_correlation_id,
        )

        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            max_compression_ratio=10000,
            max_uncompressed_size=1024,
            enable_audit_logging=True,
        )
        inspector = GzipContentInspector(config)

        content = b"A" * 2048
        buf = io.BytesIO()
        with gzip.open(buf, "wb") as gz:
            gz.write(content)
        compressed = buf.getvalue()

        set_correlation_id("test-cid")
        try:
            with pytest.raises(ZipBombError) as exc_info:
                inspector.inspect_gzip_content(
                    io.BytesIO(compressed),
                    len(compressed),
                )
            assert exc_info.value.error_code == ErrorCode.ZIP_BOMB_DETECTED
        finally:
            reset_correlation_id()

    def test_ratio_exceeded_with_correlation_id(self):
        """Trigger ratio-exceeded with CID (line 134)."""
        from safeuploads.audit import (
            reset_correlation_id,
            set_correlation_id,
        )

        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            max_compression_ratio=2,
            max_uncompressed_size=100 * 1024 * 1024,
            enable_audit_logging=True,
        )
        inspector = GzipContentInspector(config)

        content = b"\x00" * (1024 * 1024)
        buf = io.BytesIO()
        with gzip.open(buf, "wb") as gz:
            gz.write(content)
        compressed = buf.getvalue()

        set_correlation_id("ratio-cid")
        try:
            with pytest.raises(ZipBombError) as exc:
                inspector.inspect_gzip_content(
                    io.BytesIO(compressed),
                    len(compressed),
                )
            assert exc.value.error_code == ErrorCode.COMPRESSION_RATIO_EXCEEDED
            assert "ratio" in str(exc.value).lower()
        finally:
            reset_correlation_id()

    def test_bad_gzip_file_raises_compression_error(self, default_config):
        """Trigger gzip.BadGzipFile (lines 156-160)."""
        inspector = GzipContentInspector(default_config)
        # Invalid magic byte (\x8a instead of \x8b)
        bad_magic = b"\x1f\x8a\x08\x00" + b"\x00" * 6
        with pytest.raises(CompressionSecurityError) as exc:
            inspector.inspect_gzip_content(
                io.BytesIO(bad_magic), len(bad_magic)
            )
        assert exc.value.error_code == ErrorCode.ZIP_CORRUPT
        assert "corrupted" in str(exc.value).lower()


class TestGzipResourceLimits:
    """Tests that the active resource monitor stops decompression."""

    @staticmethod
    def _gzip_of_chunks(chunks: int) -> bytes:
        """Build a gzip that decompresses to ``chunks`` 64 KB chunks."""
        block = hashlib.shake_256(b"gzip").digest(16 * 1024)
        return gzip.compress(block * (4 * chunks), mtime=0)

    def test_within_budget_passes(self, default_config, fake_clock):
        """Decompression that stays in budget is accepted."""
        inspector = GzipContentInspector(default_config)
        data = self._gzip_of_chunks(20)
        fake_clock.step = 0.01

        fake_clock.run_monitored(
            lambda: inspector.inspect_gzip_content(io.BytesIO(data), len(data))
        )

    def test_over_budget_raises_inside_read_loop(
        self, default_config, fake_clock
    ):
        """Slow decompression raises ResourceLimitError unchanged."""
        inspector = GzipContentInspector(default_config)
        data = self._gzip_of_chunks(20)

        with pytest.raises(ResourceLimitError) as exc_info:
            fake_clock.run_monitored(
                lambda: inspector.inspect_gzip_content(
                    io.BytesIO(data), len(data)
                )
            )

        assert type(exc_info.value) is ResourceLimitError
        assert exc_info.value.error_code == ErrorCode.RESOURCE_TIME_EXCEEDED
        assert "inspect_gzip_content" in {
            entry.name for entry in exc_info.traceback
        }


class TestGzipLimitBoundaries:
    """Tests that each limit accepts its value and rejects the next."""

    @staticmethod
    def _inspector(**limits) -> GzipContentInspector:
        config = FileSecurityConfig()
        config.limits = SecurityLimits(**limits)
        return GzipContentInspector(config)

    def test_uncompressed_size_at_limit_accepted(self):
        """Output of exactly the size limit passes."""
        data = gzip.compress(b"A" * 1024)
        inspector = self._inspector(
            max_uncompressed_size=1024, max_compression_ratio=1000
        )

        inspector.inspect_gzip_content(io.BytesIO(data), len(data))

    def test_uncompressed_size_over_limit_rejected(self):
        """Output one byte over the size limit is rejected."""
        data = gzip.compress(b"A" * 1025)
        inspector = self._inspector(
            max_uncompressed_size=1024, max_compression_ratio=1000
        )

        with pytest.raises(ZipBombError) as exc_info:
            inspector.inspect_gzip_content(io.BytesIO(data), len(data))

        assert exc_info.value.error_code == ErrorCode.ZIP_BOMB_DETECTED
        assert exc_info.value.uncompressed_size == 1025

    def test_ratio_at_limit_accepted(self):
        """1000 bytes from 100 compressed bytes is exactly 10:1."""
        data = gzip.compress(b"A" * 1000)
        inspector = self._inspector(max_compression_ratio=10)

        inspector.inspect_gzip_content(io.BytesIO(data), 100)

    def test_ratio_over_limit_rejected(self):
        """1000 bytes from 99 compressed bytes is above 10:1."""
        data = gzip.compress(b"A" * 1000)
        inspector = self._inspector(max_compression_ratio=10)

        with pytest.raises(ZipBombError) as exc_info:
            inspector.inspect_gzip_content(io.BytesIO(data), 99)

        assert (
            exc_info.value.error_code == ErrorCode.COMPRESSION_RATIO_EXCEEDED
        )


class TestGzipMemberHandling:
    """Members are inspected and bounded one chunk at a time."""

    def test_many_empty_members_exceed_time_limit(
        self, default_config, fake_clock
    ):
        """Output-free members still hit the time limit."""
        inspector = GzipContentInspector(default_config)
        data = gzip.compress(b"", 0) * 5000

        with pytest.raises(ResourceLimitError) as exc_info:
            fake_clock.run_monitored(
                lambda: inspector.inspect_gzip_content(
                    io.BytesIO(data), len(data)
                )
            )

        assert exc_info.value.error_code == ErrorCode.RESOURCE_TIME_EXCEEDED

    def test_valid_multi_member_passes(self, default_config):
        """A multi-member file with padding is accepted."""
        data = (
            gzip.compress(b"first " * 100)
            + b"\x00" * 16
            + gzip.compress(b"second " * 100)
        )
        GzipContentInspector(default_config).inspect_gzip_content(
            io.BytesIO(data), len(data)
        )

    def test_size_limit_counts_all_members(self):
        """The uncompressed size is summed across members."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            max_uncompressed_size=1024 * 1024,
            max_compression_ratio=100000,
        )
        member = gzip.compress(bytes(400 * 1024))
        data = member * 4
        with pytest.raises(ZipBombError) as exc_info:
            GzipContentInspector(config).inspect_gzip_content(
                io.BytesIO(data), len(data)
            )
        assert exc_info.value.error_code == ErrorCode.ZIP_BOMB_DETECTED

    def test_ratio_limit_counts_all_members(self):
        """The ratio is checked on the output summed across members."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(max_compression_ratio=50)
        data = gzip.compress(bytes(100 * 1024)) * 3
        with pytest.raises(ZipBombError) as exc_info:
            GzipContentInspector(config).inspect_gzip_content(
                io.BytesIO(data), len(data)
            )
        assert (
            exc_info.value.error_code == ErrorCode.COMPRESSION_RATIO_EXCEEDED
        )

    def test_trailing_garbage_rejected(self, default_config):
        """Non-gzip data after a member is reported as corrupted."""
        data = gzip.compress(b"abc") + b"garbage"
        with pytest.raises(CompressionSecurityError) as exc_info:
            GzipContentInspector(default_config).inspect_gzip_content(
                io.BytesIO(data), len(data)
            )
        assert exc_info.value.error_code == ErrorCode.ZIP_CORRUPT


def _incompressible(size: int) -> bytes:
    """Return ``size`` deterministic bytes deflate cannot shrink."""
    blocks = (
        hashlib.sha256(i.to_bytes(4, "little")).digest()
        for i in range(size // 32 + 1)
    )
    return b"".join(blocks)[:size]


class TestIterDecompressedChunks:
    """iter_decompressed_chunks yields the output under the limits."""

    def test_yields_decompressed_content(self, default_config):
        """The chunks join to the decompressed content of all members."""
        content = _incompressible(256_000)
        data = gzip.compress(content[:1000]) + gzip.compress(content[1000:])
        inspector = GzipContentInspector(default_config)

        chunks = list(
            inspector.iter_decompressed_chunks(io.BytesIO(data), len(data))
        )

        assert b"".join(chunks) == content
        assert max(map(len, chunks)) <= default_config.limits.chunk_size

    def test_stops_before_chunk_over_size_limit(self):
        """No chunk past max_uncompressed_size is yielded."""
        config = FileSecurityConfig()
        config.limits = SecurityLimits(
            max_uncompressed_size=100_000, chunk_size=10_000
        )
        data = gzip.compress(_incompressible(256_000))
        received: list[bytes] = []
        chunks = GzipContentInspector(config).iter_decompressed_chunks(
            io.BytesIO(data), len(data)
        )

        with pytest.raises(ZipBombError) as exc_info:
            received.extend(chunks)

        assert exc_info.value.error_code == ErrorCode.ZIP_BOMB_DETECTED
        assert sum(map(len, received)) <= 100_000


_FHCRC = 0x02
_FEXTRA = 0x04
_FNAME = 0x08
_FCOMMENT = 0x10


def build_gzip_member(
    payload: bytes,
    *,
    name: bytes | None = None,
    comment: bytes | None = None,
    extra: bytes | None = None,
    header_crc: bool = False,
    level: int = 6,
) -> bytes:
    """
    Build one gzip member with the given optional header fields.

    Args:
        payload: Data to compress.
        name: FNAME bytes, written NUL-terminated, or None.
        comment: FCOMMENT bytes, written NUL-terminated, or None.
        extra: FEXTRA data, written after its length, or None.
        header_crc: Whether to add an FHCRC field.
        level: Deflate level; 0 writes stored blocks.

    Returns:
        Raw gzip member bytes.
    """
    flags = 0
    fields = b""
    if extra is not None:
        flags |= _FEXTRA
        fields += struct.pack("<H", len(extra)) + extra
    if name is not None:
        flags |= _FNAME
        fields += name + b"\x00"
    if comment is not None:
        flags |= _FCOMMENT
        fields += comment + b"\x00"
    if header_crc:
        flags |= _FHCRC
    header = b"\x1f\x8b\x08" + bytes([flags]) + b"\x00" * 5 + b"\xff"
    header += fields
    if header_crc:
        header += struct.pack("<H", zlib.crc32(header) & 0xFFFF)
    deflate = zlib.compressobj(level, zlib.DEFLATED, -zlib.MAX_WBITS)
    body = deflate.compress(payload) + deflate.flush()
    trailer = struct.pack("<2L", zlib.crc32(payload), len(payload))
    return header + body + trailer


def _zip_with_executable() -> bytes:
    """Return a ZIP archive holding one ``evil.exe`` entry."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("evil.exe", b"harmless")
    return buf.getvalue()


def build_fextra_polyglot() -> bytes:
    """
    Build a gzip file whose FEXTRA field holds a whole ZIP archive.

    The ZIP's end record declares a comment covering the deflate data
    and trailer that follow it, so ``zipfile`` opens the file as an
    archive holding ``evil.exe`` while gzip readers see ``benign``.

    Returns:
        Raw gzip/ZIP polyglot bytes.
    """
    payload = b"benign\n"
    tail = len(build_gzip_member(payload)) - 10
    archive = _zip_with_executable()[:-2] + struct.pack("<H", tail)
    data = build_gzip_member(payload, extra=archive)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        assert zf.namelist() == ["evil.exe"]
    assert gzip.decompress(data) == payload
    return data


def build_stored_polyglot() -> bytes:
    """
    Build a gzip file whose stored deflate block is a ZIP archive.

    Level 0 copies the ZIP bytes verbatim into the gzip data, where
    ``zipfile`` finds its end record behind the gzip header.

    Returns:
        Raw gzip/ZIP polyglot bytes.
    """
    data = build_gzip_member(_zip_with_executable(), level=0)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        assert zf.namelist() == ["evil.exe"]
    return data


def _inspect(data: bytes, config=None) -> None:
    """Run inspect_gzip_content on ``data``."""
    inspector = GzipContentInspector(config or FileSecurityConfig())
    inspector.inspect_gzip_content(io.BytesIO(data), len(data))


def _rejected(data: bytes, config=None) -> CompressionSecurityError:
    """Return the CompressionSecurityError inspecting ``data`` raises."""
    with pytest.raises(CompressionSecurityError) as exc_info:
        _inspect(data, config)
    return exc_info.value


class TestGzipZipPolyglot:
    """A gzip file zipfile also opens as a ZIP archive is rejected."""

    def test_plain_gzip_accepted(self):
        """Gzip data without a ZIP end record passes."""
        _inspect(build_gzip_member(b"benign\n" * 100, level=0))

    def test_fextra_polyglot_rejected(self):
        """A ZIP hidden in the FEXTRA field is rejected."""
        err = _rejected(build_fextra_polyglot())
        assert err.error_code == ErrorCode.GZIP_ZIP_POLYGLOT

    def test_stored_block_polyglot_rejected(self):
        """A ZIP stored verbatim in a deflate block is rejected."""
        err = _rejected(build_stored_polyglot())
        assert err.error_code == ErrorCode.GZIP_ZIP_POLYGLOT

    def test_polyglot_rejected_before_inflating(self):
        """iter_decompressed_chunks yields nothing for a polyglot."""
        data = build_stored_polyglot()
        chunks = GzipContentInspector(
            FileSecurityConfig()
        ).iter_decompressed_chunks(io.BytesIO(data), len(data))
        with pytest.raises(CompressionSecurityError) as exc_info:
            next(chunks)
        assert exc_info.value.error_code == ErrorCode.GZIP_ZIP_POLYGLOT


class TestGzipMemberNames:
    """Every member's FNAME gets the archive entry-name checks."""

    @pytest.mark.parametrize(
        "name", [b"activity.fit", b"notes.txt", b"caf\xe9.csv", b""]
    )
    def test_safe_name_accepted(self, name):
        """Ordinary stored names pass."""
        _inspect(build_gzip_member(b"hello\n", name=name))

    @pytest.mark.parametrize(
        ("name", "code", "text"),
        [
            (
                b"../../evil.txt",
                ErrorCode.ZIP_DIRECTORY_TRAVERSAL,
                "Directory traversal",
            ),
            (b"evil.exe", ErrorCode.ZIP_CONTENT_THREAT, "Dangerous file"),
            (b"evil.exe/.", ErrorCode.ZIP_CONTENT_THREAT, "Dangerous file"),
            (b"shell.php", ErrorCode.ZIP_CONTENT_THREAT, "Dangerous file"),
            (b"CON.txt", ErrorCode.ZIP_CONTENT_THREAT, "reserved"),
            (b"/etc/passwd", ErrorCode.ZIP_ABSOLUTE_PATH, "Absolute path"),
        ],
    )
    def test_unsafe_name_rejected(self, name, code, text):
        """A traversal, executable or reserved FNAME is rejected."""
        err = _rejected(build_gzip_member(b"hello\n", name=name))
        assert type(err) is ZipContentError
        assert err.error_code == code
        assert text in str(err)

    def test_unicode_name_rejected(self):
        """An ISO-8859-1 control character in FNAME is rejected."""
        err = _rejected(build_gzip_member(b"hello\n", name=b"a\x85b.txt"))
        assert err.error_code == ErrorCode.ZIP_CONTENT_THREAT
        assert "Unicode" in str(err)

    def test_later_member_name_checked(self):
        """The FNAME of every member is checked, not only the first."""
        data = build_gzip_member(b"a", name=b"a.txt") + build_gzip_member(
            b"b", name=b"evil.bat"
        )
        err = _rejected(data)
        assert err.error_code == ErrorCode.ZIP_CONTENT_THREAT
        assert "evil.bat" in str(err)

    def test_all_header_fields_parsed(self):
        """FEXTRA, FCOMMENT and a valid FHCRC around FNAME are read."""
        data = build_gzip_member(
            b"hello\n",
            name=b"evil.exe",
            comment=b"c" * 100_000,
            extra=b"x" * 1000,
            header_crc=True,
        )
        assert gzip.decompress(data) == b"hello\n"
        err = _rejected(data, _small_chunks())
        assert err.error_code == ErrorCode.ZIP_CONTENT_THREAT

    def test_header_fields_accepted_with_safe_name(self):
        """A member with every optional header field passes."""
        data = build_gzip_member(
            b"hello\n",
            name=b"notes.txt",
            comment=b"exported",
            extra=b"x" * 1000,
            header_crc=True,
        )
        _inspect(data, _small_chunks())

    def test_name_too_long_rejected(self):
        """An FNAME longer than 65,535 bytes is a corrupt header."""
        data = build_gzip_member(b"hello\n", name=b"a" * 70_000)
        assert _rejected(data).error_code == ErrorCode.ZIP_CORRUPT

    def test_wrong_header_crc_rejected(self):
        """A header CRC that does not match is a corrupt header."""
        data = bytearray(
            build_gzip_member(b"hello\n", name=b"a.txt", header_crc=True)
        )
        data[16] ^= 0xFF
        assert _rejected(bytes(data)).error_code == ErrorCode.ZIP_CORRUPT

    @pytest.mark.parametrize("cut", [5, 11, 14, 17])
    def test_truncated_header_rejected(self, cut):
        """A header cut inside a field is a corrupt header."""
        data = build_gzip_member(
            b"hello\n", name=b"a.txt", extra=b"xy", header_crc=True
        )
        assert _rejected(data[:cut]).error_code == ErrorCode.ZIP_CORRUPT

    def test_reserved_flag_rejected(self):
        """A header with a reserved flag bit set is corrupt."""
        data = bytearray(build_gzip_member(b"hello\n"))
        data[3] |= 0x20
        assert _rejected(bytes(data)).error_code == ErrorCode.ZIP_CORRUPT


def _small_chunks() -> FileSecurityConfig:
    """Return a configuration reading 64 bytes per step."""
    config = FileSecurityConfig()
    config.limits = SecurityLimits(chunk_size=64)
    return config
