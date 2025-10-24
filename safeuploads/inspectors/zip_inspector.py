"""
ZIP Content Inspector Module

Handles deep inspection of ZIP file contents for security threats.
"""

import io
import os
import time
import zipfile
from typing import List, Tuple, TYPE_CHECKING

import logging
from ..enums import SuspiciousFilePattern, ZipThreatCategory

if TYPE_CHECKING:
    from ..config import FileSecurityConfig


logger = logging.getLogger(__name__)


class ZipContentInspector:

    def __init__(self, config: "FileSecurityConfig"):
        """
        Initialize the zip inspector with the provided file security configuration.

        Args:
            config (FileSecurityConfig): The configuration settings used to validate ZIP archives.
        """
        self.config = config

    def inspect_zip_content(self, file_content: bytes) -> Tuple[bool, str]:
        """
        Inspect the contents and structure of a ZIP archive for potential threats.

        Args:
            file_content (bytes): Raw bytes of the ZIP archive to be inspected.

        Returns:
            Tuple[bool, str]: A tuple where the boolean indicates whether the inspection
            passed, and the string provides a detailed status or error message.
        """
        try:
            zip_bytes = io.BytesIO(file_content)
            threats_found = []

            # Start analysis timer
            start_time = time.time()

            with zipfile.ZipFile(zip_bytes, "r") as zip_file:
                zip_entries = zip_file.infolist()

                # Analyze each entry in the ZIP
                for entry in zip_entries:
                    # Check for timeout
                    if (
                        time.time() - start_time
                        > self.config.limits.zip_analysis_timeout
                    ):
                        return (
                            False,
                            f"ZIP content inspection timeout after {self.config.limits.zip_analysis_timeout}s",
                        )

                    # Inspect individual entry
                    entry_threats = self._inspect_zip_entry(entry, zip_file)
                    threats_found.extend(entry_threats)

                # Check for ZIP structure threats
                structure_threats = self._inspect_zip_structure(zip_entries)
                threats_found.extend(structure_threats)

                # Return results
                if threats_found:
                    return (
                        False,
                        f"ZIP content threats detected: {'; '.join(threats_found)}",
                    )

                logger.debug(
                    "ZIP content inspection passed: %s entries analyzed",
                    len(zip_entries),
                )
                return True, "ZIP content inspection passed"

        except zipfile.BadZipFile:
            return False, "Invalid or corrupted ZIP file structure"
        except Exception as err:
            logger.warning(
                "Error during ZIP content inspection: %s",
                err,
                exc_info=err,
            )
            return False, f"ZIP content inspection failed: {str(err)}"

    def _inspect_zip_entry(
        self, entry: zipfile.ZipInfo, zip_file: zipfile.ZipFile
    ) -> List[str]:
        """
        Inspect a ZIP archive entry for security threats such as traversal attempts, disallowed paths, symlinks, excessive name lengths, suspicious patterns, nested archives, and optionally hostile content.

        Args:
            entry (zipfile.ZipInfo): The ZIP entry metadata to analyze.
            zip_file (zipfile.ZipFile): The parent archive, used for reading entry content when needed.

        Returns:
            list[str]: A collection of human-readable threat descriptions detected for the entry.
        """
        threats = []
        filename = entry.filename

        # 1. Check for directory traversal attacks
        if self._has_directory_traversal(filename):
            threats.append(f"Directory traversal attack in '{filename}'")

        # 2. Check for absolute paths
        if not self.config.limits.allow_absolute_paths and self._has_absolute_path(
            filename
        ):
            threats.append(f"Absolute path detected in '{filename}'")

        # 3. Check for symbolic links
        if not self.config.limits.allow_symlinks and self._is_symlink(entry):
            threats.append(f"Symbolic link detected: '{filename}'")

        # 4. Check filename length limits
        if len(os.path.basename(filename)) > self.config.limits.max_filename_length:
            threats.append(
                f"Filename too long: '{filename}' ({len(os.path.basename(filename))} chars)"
            )

        # 5. Check path length limits
        if len(filename) > self.config.limits.max_path_length:
            threats.append(f"Path too long: '{filename}' ({len(filename)} chars)")

        # 6. Check for suspicious filename patterns
        suspicious_patterns = self._check_suspicious_patterns(filename)
        threats.extend(suspicious_patterns)

        # 7. Check for nested archives
        if not self.config.limits.allow_nested_archives and self._is_nested_archive(
            filename
        ):
            threats.append(f"Nested archive detected: '{filename}'")

        # 8. Check file content if enabled and entry is small enough
        if (
            self.config.limits.scan_zip_content
            and not entry.is_dir()
            and entry.file_size < 1024 * 1024
        ):  # 1MB limit for content scan
            content_threats = self._inspect_entry_content(entry, zip_file)
            threats.extend(content_threats)

        return threats

    def _inspect_zip_structure(self, entries: List[zipfile.ZipInfo]) -> List[str]:
        """
        Inspect ZIP archive entries for structural anomalies and return descriptive threat messages.

        Args:
            entries (List[zipfile.ZipInfo]): ZIP entries to analyze, including files and directories.

        Returns:
            List[str]: A list of human-readable threat descriptions, such as excessive
            directory depth relative to the configured maximum or an unusually large number
            of files sharing the same extension.
        """
        threats = []

        # Check directory depth
        max_depth = 0
        for entry in entries:
            depth = entry.filename.count("/") + entry.filename.count("\\")
            max_depth = max(max_depth, depth)

        if max_depth > self.config.limits.max_zip_depth:
            threats.append(
                f"Excessive directory depth: {max_depth} (max: {self.config.limits.max_zip_depth})"
            )

        # Check for suspicious file distribution
        file_types = {}
        for entry in entries:
            if not entry.is_dir():
                ext = os.path.splitext(entry.filename)[1].lower()
                file_types[ext] = file_types.get(ext, 0) + 1

        # Check for excessive number of same-type files (potential spam/bomb)
        for ext, count in file_types.items():
            if count > 1000:  # More than 1000 files of same type
                threats.append(f"Excessive number of {ext} files: {count}")

        return threats

    def _has_directory_traversal(self, filename: str) -> bool:
        """
        Identify if the provided filename matches directory traversal indicators
        by checking against suspicious patterns and normalized path segments.

        Args:
            filename (str): Name of the file within the archive to examine.

        Returns:
            bool: True if directory traversal is detected; otherwise, False.
        """
        filename_lower = filename.lower()

        for category in SuspiciousFilePattern:
            if category == SuspiciousFilePattern.DIRECTORY_TRAVERSAL:
                for pattern in category.value:
                    if pattern.lower() in filename_lower:
                        return True

        # Additional checks for normalized paths
        normalized = os.path.normpath(filename)
        if normalized.startswith("..") or "/.." in normalized or "\\.." in normalized:
            return True

        return False

    def _has_absolute_path(self, filename: str) -> bool:
        """
        Determine whether the provided filename represents an absolute path on Unix or Windows systems.

        Args:
            filename: The path string to examine.

        Returns:
            True if the filename is an absolute path (Unix-style, UNC, or Windows drive letter); otherwise, False.
        """
        return (
            filename.startswith("/")  # Unix absolute path
            or filename.startswith("\\")  # Windows UNC path
            or (len(filename) > 1 and filename[1] == ":")  # Windows drive path
        )

    def _is_symlink(self, entry: zipfile.ZipInfo) -> bool:
        """
        Determine whether a ZIP archive entry represents a symbolic link.

        Args:
            entry (zipfile.ZipInfo): Metadata for a member of the ZIP archive.

        Returns:
            bool: True if the entry is identified as a symbolic link, otherwise False.
        """
        # Check if entry has symlink attributes
        return (entry.external_attr >> 16) & 0o120000 == 0o120000

    def _check_suspicious_patterns(self, filename: str) -> List[str]:
        """
        Identify suspicious filename patterns within an archive entry.

        Args:
            filename (str): The path of a file inside the archive to evaluate.

        Returns:
            List[str]: A list of human-readable warnings describing any detected
                suspicious patterns. The list is empty when no issues are found.
        """
        threats = []
        filename_lower = filename.lower()
        basename = os.path.basename(filename_lower)

        # Check suspicious names
        for pattern in SuspiciousFilePattern.SUSPICIOUS_NAMES.value:
            if basename == pattern.lower():
                threats.append(f"Suspicious filename pattern: '{filename}'")
                break

        # Check suspicious path components
        for pattern in SuspiciousFilePattern.SUSPICIOUS_PATHS.value:
            if pattern.lower() in filename_lower:
                threats.append(
                    f"Suspicious path component: '{filename}' contains '{pattern}'"
                )
                break

        return threats

    def _is_nested_archive(self, filename: str) -> bool:
        """
        Determine if the provided filename represents a nested archive based on its file extension.

        Args:
            filename (str): The name of the file to evaluate.

        Returns:
            bool: True if the filename indicates a nested archive; otherwise, False.
        """
        ext = os.path.splitext(filename)[1].lower()

        for category in ZipThreatCategory:
            if category == ZipThreatCategory.NESTED_ARCHIVES:
                return ext in category.value

        return False

    def _inspect_entry_content(
        self, entry: zipfile.ZipInfo, zip_file: zipfile.ZipFile
    ) -> List[str]:
        """
        Inspect a ZIP entry for potentially malicious content signatures.

        Args:
            entry (zipfile.ZipInfo): Metadata describing the ZIP archive entry to inspect.
            zip_file (zipfile.ZipFile): Open ZIP archive providing access to entry contents.

        Returns:
            List[str]: Descriptions of any detected threats, including executable or script content indicators.
        """
        threats = []

        try:
            # Read first few bytes to check for executable signatures
            with zip_file.open(entry, "r") as file:
                content_sample = file.read(512)  # Read first 512 bytes

                # Check for executable signatures
                for signature in SuspiciousFilePattern.EXECUTABLE_SIGNATURES.value:
                    if content_sample.startswith(signature):
                        threats.append(
                            f"Executable content detected in '{entry.filename}'"
                        )
                        break

                # Check for script content patterns
                if self._contains_script_patterns(content_sample, entry.filename):
                    threats.append(f"Script content detected in '{entry.filename}'")

        except Exception as err:
            logger.warning(
                "Could not inspect content of '%s': %s",
                entry.filename,
                err,
            )

        return threats

    def _contains_script_patterns(self, content: bytes, filename: str) -> bool:
        """
        Checks if the content contains common script patterns that could indicate malicious code.

        This method attempts to decode the content as UTF-8 text and searches for common
        patterns found in executable scripts, shell commands, and code injection attempts.

        Args:
            content (bytes): The raw bytes content to inspect for script patterns.
            filename (str): The name of the file being inspected (currently unused but
                           provided for potential future use).

        Returns:
            bool: True if any script pattern is found in the content, False otherwise.
                  Also returns False if the content cannot be decoded as text (likely binary).
        """
        try:
            # Try to decode as text
            text_content = content.decode("utf-8", errors="ignore").lower()

            # Check for common script patterns
            script_patterns = [
                "#!/bin/",
                "#!/usr/bin/",
                "powershell",
                "cmd.exe",
                "eval(",
                "exec(",
                "system(",
                "shell_exec(",
                "<script",
                "<?php",
                "<%",
                "import os",
                "import subprocess",
            ]

            for pattern in script_patterns:
                if pattern in text_content:
                    return True

        except Exception:
            # If we can't decode as text, it's probably binary
            pass

        return False
