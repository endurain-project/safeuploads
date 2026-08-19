#!/usr/bin/env python3
"""Smoke-test that the built safeuploads wheel is self-contained.

Imports the installed package (not the source tree) and constructs
a FileValidator to prove the distribution's declared dependencies
are sufficient to actually use the library.
"""

from __future__ import annotations

import sys
from importlib.metadata import version

from safeuploads import FileSecurityConfig, FileValidator


def main() -> int:
    """Exercise the installed package and return a process exit code.

    Returns:
        0 on success, 1 if a check fails.
    """
    print(f"safeuploads version: {version('safeuploads')}")

    validator = FileValidator(config=FileSecurityConfig())
    if not isinstance(validator, FileValidator):
        print("FileValidator construction failed.", file=sys.stderr)
        return 1

    print("Smoke test passed: package imported and validator built.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
