"""Shared helpers for the fuzz tests."""

from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from safeuploads.exceptions import (
    FileProcessingError,
    FileValidationError,
    ResourceLimitError,
)


class MockFile:
    """Minimal mock upload file for fuzz tests."""

    def __init__(self, filename, content):
        self.filename = filename
        self.content = content
        self.size = len(content)
        self._pos = 0

    async def read(self, size=-1):
        if size == -1:
            data = self.content[self._pos :]
            self._pos = len(self.content)
        else:
            data = self.content[self._pos : self._pos + size]
            self._pos += len(data)
        return data

    async def seek(self, offset):
        self._pos = offset
        return self._pos


def _fail_on_internal_error(err: FileProcessingError) -> None:
    """Fail the test for a plain FileProcessingError."""
    pytest.fail(
        "internal error escaped validation: "
        f"error_code={err.error_code!r} message={err.message!r} "
        f"original_error={err.original_error!r}",
        pytrace=False,
    )


def accepted(
    call: Callable[..., Any],
    *args: Any,
    known_causes: tuple[type[Exception], ...] = (),
) -> bool:
    """
    Run ``call`` and classify its outcome.

    Returns:
        True when validation passed, False when it was rejected with a
        FileValidationError or ResourceLimitError. Any other outcome,
        including a plain FileProcessingError, fails the test.
        A plain FileProcessingError wrapping one of ``known_causes``
        counts as a rejection; use it only for a bug that a strict
        xfail regression test pins.
    """
    try:
        call(*args)
    except (FileValidationError, ResourceLimitError):
        return False
    except FileProcessingError as err:
        if isinstance(err.original_error, known_causes):
            return False
        _fail_on_internal_error(err)
    return True


async def accepted_async(awaitable: Awaitable[Any]) -> bool:
    """Async counterpart of :func:`accepted`."""
    try:
        await awaitable
    except (FileValidationError, ResourceLimitError):
        return False
    except FileProcessingError as err:
        _fail_on_internal_error(err)
    return True
