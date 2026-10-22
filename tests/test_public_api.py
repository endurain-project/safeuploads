"""Contract tests for the package's public API surface."""

import safeuploads


class TestPublicExports:
    """Every advertised name must be importable and unique."""

    def test_all_names_are_resolvable(self):
        missing = [
            name
            for name in safeuploads.__all__
            if not hasattr(safeuploads, name)
        ]
        assert missing == []

    def test_all_has_no_duplicates(self):
        assert len(safeuploads.__all__) == len(set(safeuploads.__all__))

    def test_framework_agnostic_protocols_exported(self):
        # A caller integrating a non-FastAPI framework needs both
        # protocols from the top-level package.
        assert "SeekableFile" in safeuploads.__all__
        assert "UploadFileProtocol" in safeuploads.__all__

    def test_correlation_id_helpers_exported(self):
        for name in (
            "get_correlation_id",
            "set_correlation_id",
            "reset_correlation_id",
        ):
            assert name in safeuploads.__all__

    def test_upload_file_protocol_is_runtime_checkable(self):
        class _Upload:
            filename = "a.jpg"
            size = 3

            async def read(self, size: int = -1) -> bytes:
                return b""

            async def seek(self, offset: int) -> int:
                return offset

        assert isinstance(_Upload(), safeuploads.UploadFileProtocol)
