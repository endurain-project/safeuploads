"""File security configuration module."""

import itertools
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any, ClassVar

from .enums import (
    CompoundExtensionCategory,
    DangerousExtensionCategory,
    UnicodeAttackCategory,
    ZipThreatCategory,
)
from .exceptions import ConfigValidationError, FileSecurityConfigurationError
from .utils import bytes_to_mb

logger = logging.getLogger(__name__)

# Conservative floor for gzip inflation throughput, used only to
# size the analysis timeout against the uncompressed byte limit.
# Well below what a modern host sustains, so the derived timeout
# stays generous rather than borderline.
_MIN_INFLATE_THROUGHPUT_MB_S = 50


def _config_error(
    error_type: str,
    message: str,
    component: str,
    recommendation: str,
    severity: str = "error",
) -> ConfigValidationError:
    """
    Build a ConfigValidationError with a default severity.

    Centralizes construction so the many validation branches
    share one call shape instead of repeating every field.

    Args:
        error_type: Machine-readable error category.
        message: Human-readable description of the issue.
        component: Configuration component that failed.
        recommendation: Suggested remediation.
        severity: Severity level ('error', 'warning', 'info').

    Returns:
        Populated ConfigValidationError instance.
    """
    return ConfigValidationError(
        error_type=error_type,
        message=message,
        severity=severity,
        component=component,
        recommendation=recommendation,
    )


@dataclass
class SecurityLimits:
    """
    Security constraints for file submissions.

    Attributes:
        max_image_size: Maximum size in bytes for image files.
        max_image_pixels: Maximum width x height product allowed
            for an image, guarding against decompression bombs
            that are small on the wire but huge once decoded.
        max_zip_size: Maximum size in bytes for ZIP archives.
        max_activity_file_size: Maximum size in bytes for
            GPX/TCX/FIT activity files.
        max_gzip_size: Maximum size in bytes for gzip files.
        max_memory_buffer_size: Bytes kept in memory before a
            streamed upload spills to a temporary file on disk.
        temp_dir: Directory used for spilled uploads. Uses the
            system default temporary directory when unset.
        chunk_size: Chunk size in bytes for streaming reads.
        max_validation_memory_mb: Peak-RSS growth budget in MB
            for a single validation. Best-effort telemetry only
            unless ``enforce_memory_limit`` is set.
        enforce_memory_limit: Whether exceeding
            ``max_validation_memory_mb`` fails the validation
            instead of logging a warning. Off by default because
            peak RSS is process-wide and misattributes
            concurrent work.
        max_validation_time_seconds: Overall validation timeout
            in seconds.
        max_compression_ratio: Maximum expansion ratio for ZIP files.
        max_uncompressed_size: Maximum cumulative size of ZIP contents.
        max_individual_file_size: Maximum size of single file in ZIP.
        max_zip_entries: Maximum number of file entries in ZIP.
        zip_analysis_timeout: Maximum seconds for ZIP analysis.
        gzip_analysis_timeout: Maximum seconds spent inflating a
            gzip stream during inspection.
        max_xml_elements: Maximum number of elements parsed from
            an XML activity file before it is rejected.
        max_zip_depth: Maximum directory nesting depth in ZIP.
        max_filename_length: Maximum length for filenames in ZIP.
        max_path_length: Maximum length for full paths in ZIP.
        max_sanitized_name_length: Maximum length of the base
            name (extension excluded) kept when sanitizing an
            uploaded filename.
        max_number_files_same_type: Maximum number of files
            sharing the same extension inside a ZIP.
        allow_nested_archives: Whether nested archives are permitted.
        allow_symlinks: Whether symbolic links are permitted.
        allow_absolute_paths: Whether absolute paths are permitted.
        blocked_zip_entry_categories: ``ZipThreatCategory`` names
            whose extensions are rejected when they appear on a
            ZIP entry.
        scan_zip_content: Whether deep content inspection is enabled.
        verify_zip_decompression: Whether to decompress every ZIP
            entry to reject forged central-directory metadata.
        max_total_entries_recursive: Maximum cumulative entry
            count across all nesting levels of nested archives.
        enable_audit_logging: Whether structured security audit
            logging is emitted.
        enable_content_analysis: Whether optional deep content
            scanning (malware/script/polyglot) runs.
        content_scan_max_size: Maximum bytes scanned during
            optional content analysis.
    """

    # File size limits (in bytes)
    max_image_size: int = 20 * 1024 * 1024  # 20MB for images
    max_zip_size: int = 500 * 1024 * 1024  # 500MB for ZIP files
    max_activity_file_size: int = 50 * 1024 * 1024  # 50MB for GPX/TCX/FIT
    max_gzip_size: int = 500 * 1024 * 1024  # 500MB for gzip files

    # Decoded image size limit. Matches Pillow's default
    # MAX_IMAGE_PIXELS, the de facto decompression-bomb
    # threshold (~0.25GB uncompressed at 3 bytes per pixel).
    max_image_pixels: int = 89_478_485

    # Streaming validation settings
    max_memory_buffer_size: int = (
        10 * 1024 * 1024  # 10MB before spilling to disk
    )
    # Where spilled uploads land. Point this at a dedicated,
    # quota-enforced partition to keep large uploads off the
    # system temp directory.
    temp_dir: str | None = None
    chunk_size: int = 65536  # 64KB chunks for streaming reads

    # Resource monitoring limits
    max_validation_memory_mb: int = 512  # Peak-RSS growth budget
    # Peak RSS is a process-wide high-water mark, so it cannot be
    # attributed to one validation under concurrency. Enforcement
    # is opt-in and only sound when the process validates one
    # upload at a time.
    enforce_memory_limit: bool = False
    max_validation_time_seconds: float = (
        30.0  # Overall validation timeout in seconds
    )

    # ZIP compression security settings
    # Maximum allowed expansion ratio (e.g., 100:1)
    max_compression_ratio: int = 100
    # 1GB max uncompressed size
    max_uncompressed_size: int = 1024 * 1024 * 1024
    max_individual_file_size: int = (
        500 * 1024 * 1024
    )  # 500MB max per individual file in ZIP
    max_zip_entries: int = 10000  # Maximum number of files in ZIP archive
    zip_analysis_timeout: float = (
        5.0  # Maximum seconds to spend analyzing ZIP structure
    )
    gzip_analysis_timeout: float = (
        25.0  # Maximum seconds to spend inflating a gzip stream
    )

    # XML activity file limits. Entity expansion is blocked by
    # defusedxml, but a flat document with millions of elements
    # still costs CPU, so cap the element count.
    max_xml_elements: int = 1_000_000

    # ZIP content inspection settings
    max_zip_depth: int = 10  # Maximum nesting depth for directories in ZIP
    max_filename_length: int = 255  # Maximum length for individual file names
    max_path_length: int = 1024  # Maximum length for full file paths
    # Maximum length of the base name (extension excluded) kept when
    # sanitizing an uploaded filename; longer names are truncated.
    max_sanitized_name_length: int = 100
    # Maximum number of files of the same type
    max_number_files_same_type: int = 1000
    # Whether to allow nested archive files
    allow_nested_archives: bool = False
    # Whether to allow symbolic links in ZIP
    allow_symlinks: bool = False
    # Whether to allow absolute paths in ZIP
    allow_absolute_paths: bool = False
    # Entry extensions rejected inside an accepted archive.
    # EXECUTABLE_FILES and SCRIPT_FILES are code; SYSTEM_FILES is
    # mostly configuration and is a different threat class, so it
    # is available but not on by default.
    blocked_zip_entry_categories: frozenset[str] = frozenset(
        {"EXECUTABLE_FILES", "SCRIPT_FILES"}
    )
    scan_zip_content: bool = True  # Whether to perform deep content inspection
    # Decompress every ZIP entry to reject forged central-
    # directory metadata (extra CPU/IO; off by default)
    verify_zip_decompression: bool = False

    # Recursive ZIP inspection limits
    max_total_entries_recursive: int = (
        50000  # Max total entries across all nesting levels
    )

    # Audit logging
    enable_audit_logging: bool = False  # Structured security event logging

    # Content analysis (optional deep scan)
    enable_content_analysis: bool = False  # Malware/script/polyglot scan
    content_scan_max_size: int = (
        50 * 1024 * 1024  # Max bytes to scan (50MB)
    )


class FileSecurityConfig:
    """
    Centralizes file upload security settings and validation.

    The class-level ``limits`` is the template copied into each
    new instance, not the live configuration. Pass a
    ``SecurityLimits`` to the constructor to configure an
    instance; assigning to ``FileSecurityConfig.limits`` or
    mutating it in place changes the default for every config
    created afterwards.

    Attributes:
        limits: Security limits for this instance. At class
            level, the template new instances are built from.
        ALLOWED_IMAGE_MIMES: Permitted MIME types for images.
        ALLOWED_ZIP_MIMES: Permitted MIME types for ZIP files.
        ALLOWED_ACTIVITY_MIMES: Permitted MIME types for activity
            files (GPX/TCX/FIT).
        ALLOWED_GZIP_MIMES: Permitted MIME types for gzip files.
        ALLOWED_IMAGE_EXTENSIONS: Permitted image file extensions.
        ALLOWED_ZIP_EXTENSIONS: Permitted ZIP file extensions.
        ALLOWED_ACTIVITY_EXTENSIONS: Permitted activity file
            extensions.
        ALLOWED_GZIP_EXTENSIONS: Permitted gzip file extensions.
        ACTIVITY_XML_ROOTS: Required XML root element per
            activity extension.
        BLOCKED_EXTENSIONS: Dangerous file extensions to block.
        COMPOUND_BLOCKED_EXTENSIONS: Multi-part extensions to block.
        DANGEROUS_UNICODE_CHARS: Unicode characters for filename attacks.
        WINDOWS_RESERVED_NAMES: Platform-specific reserved filenames.
    """

    # Security limits configuration
    limits = SecurityLimits()

    # Allowed MIME types for images
    ALLOWED_IMAGE_MIMES: ClassVar[frozenset[str]] = frozenset(
        {
            "image/jpeg",
            "image/jpg",
            "image/png",
        }
    )

    # Allowed MIME types for ZIP files
    ALLOWED_ZIP_MIMES: ClassVar[frozenset[str]] = frozenset(
        {
            "application/zip",
            "application/x-zip-compressed",
            "multipart/x-zip",
        }
    )

    # Allowed MIME types for activity files (GPX/TCX/FIT)
    ALLOWED_ACTIVITY_MIMES: ClassVar[frozenset[str]] = frozenset(
        {
            "application/gpx+xml",
            "application/xml",
            "text/xml",
            "application/octet-stream",  # FIT files detected as binary
        }
    )

    # Allowed MIME types for gzip files
    ALLOWED_GZIP_MIMES: ClassVar[frozenset[str]] = frozenset(
        {
            "application/gzip",
            "application/x-gzip",
        }
    )

    # Allowed file extensions
    ALLOWED_IMAGE_EXTENSIONS: ClassVar[frozenset[str]] = frozenset(
        {
            ".jpg",
            ".jpeg",
            ".png",
        }
    )
    ALLOWED_ZIP_EXTENSIONS: ClassVar[frozenset[str]] = frozenset({".zip"})
    ALLOWED_ACTIVITY_EXTENSIONS: ClassVar[frozenset[str]] = frozenset(
        {
            ".gpx",
            ".tcx",
            ".fit",
        }
    )
    ALLOWED_GZIP_EXTENSIONS: ClassVar[frozenset[str]] = frozenset({".gz"})

    # Required root element per XML activity format, lower-cased
    # and namespace-stripped. Guards against an arbitrary XML
    # document (or an HTML/SVG payload) wearing a .gpx name.
    ACTIVITY_XML_ROOTS: ClassVar[Mapping[str, str]] = MappingProxyType(
        {
            ".gpx": "gpx",
            ".tcx": "trainingcenterdatabase",
        }
    )

    # Generate dangerous file extensions from categorized enums
    @staticmethod
    def _generate_blocked_extensions() -> frozenset[str]:
        """
        Aggregate all dangerous extension categories.

        Returns:
            Combined frozenset of blocked file extensions.
        """
        blocked_extensions: set[str] = set()

        # Combine all dangerous extension categories
        for category in DangerousExtensionCategory:
            blocked_extensions.update(category.value)

        return frozenset(blocked_extensions)

    # Generate compound dangerous file extensions
    @staticmethod
    def _generate_compound_blocked_extensions() -> frozenset[str]:
        """
        Aggregate all compound extension categories.

        Returns:
            Combined frozenset of blocked compound extensions.
        """
        compound_extensions: set[str] = set()

        # Combine all compound extension categories
        for category in CompoundExtensionCategory:
            compound_extensions.update(category.value)

        return frozenset(compound_extensions)

    # Generate dangerous Unicode characters from categorized enums
    @staticmethod
    def _generate_dangerous_unicode_chars() -> frozenset[int]:
        """
        Aggregate all dangerous Unicode code points.

        Returns:
            Combined frozenset of dangerous Unicode code points.
        """
        dangerous_chars: set[int] = set()

        # Combine all Unicode attack categories
        for category in UnicodeAttackCategory:
            dangerous_chars.update(category.value)

        return frozenset(dangerous_chars)

    # Dangerous file extensions (generated from enums)
    BLOCKED_EXTENSIONS: ClassVar[frozenset[str]] = (
        _generate_blocked_extensions()
    )

    # Compound dangerous extensions (multi-part)
    COMPOUND_BLOCKED_EXTENSIONS: ClassVar[frozenset[str]] = (
        _generate_compound_blocked_extensions()
    )

    # Dangerous Unicode characters for filename attacks
    DANGEROUS_UNICODE_CHARS: ClassVar[frozenset[int]] = (
        _generate_dangerous_unicode_chars()
    )

    # Windows reserved names
    WINDOWS_RESERVED_NAMES: ClassVar[frozenset[str]] = frozenset(
        {
            "con",
            "prn",
            "aux",
            "nul",
            "com1",
            "com2",
            "com3",
            "com4",
            "com5",
            "com6",
            "com7",
            "com8",
            "com9",
            "lpt1",
            "lpt2",
            "lpt3",
            "lpt4",
            "lpt5",
            "lpt6",
            "lpt7",
            "lpt8",
            "lpt9",
        }
    )

    def __init__(self, limits: SecurityLimits | None = None) -> None:
        """
        Create a config instance with isolated mutable state.

        The supplied or class-level ``limits`` is copied, so
        mutating one instance's limits never affects other
        instances, the caller's object, or the class default.

        Args:
            limits: Security limits to use. Falls back to the
                class-level default when omitted.
        """
        # Per-instance copy prevents cross-instance mutation
        self.limits = replace(type(self).limits if limits is None else limits)

    # Configuration validation trigger
    @classmethod
    def __init_subclass__(cls, **kwargs: Any) -> None:
        """
        Validate configuration on subclass creation.

        Args:
            **kwargs: Subclass initialization arguments.
        """
        super().__init_subclass__(**kwargs)
        # Perform validation with warnings allowed (non-strict mode)
        try:
            cls.validate_and_report(strict=False)
        except Exception as err:
            logger.warning("Configuration validation failed: %s", err)

    @classmethod
    def get_extensions_by_category(
        cls, category: DangerousExtensionCategory
    ) -> set[str]:
        """
        Return extensions for a dangerous extension category.

        Args:
            category: The dangerous extension category.

        Returns:
            Copy of extensions in the specified category.
        """
        return category.value.copy()

    @classmethod
    def get_compound_extensions_by_category(
        cls, category: CompoundExtensionCategory
    ) -> set[str]:
        """
        Return compound extensions for a category.

        Args:
            category: The compound extension category.

        Returns:
            Copy of compound extensions in the specified category.
        """
        return category.value.copy()

    @classmethod
    def get_unicode_chars_by_category(
        cls, category: UnicodeAttackCategory
    ) -> set[int]:
        """
        Return Unicode code points for an attack category.

        Args:
            category: The Unicode attack category.

        Returns:
            Copy of code points in the specified category.
        """
        return category.value.copy()

    @classmethod
    def is_extension_in_category(
        cls, extension: str, category: DangerousExtensionCategory
    ) -> bool:
        """
        Check if extension belongs to a dangerous category.

        Args:
            extension: File extension to evaluate.
            category: Category to check against.

        Returns:
            True if extension is in the category, False otherwise.
        """
        return extension.lower() in category.value

    @classmethod
    def get_extension_category(
        cls, extension: str
    ) -> DangerousExtensionCategory | None:
        """
        Return the dangerous extension category for an extension.

        Args:
            extension: The file extension to evaluate.

        Returns:
            Matching category if dangerous, None otherwise.
        """
        extension_lower = extension.lower()
        for category in DangerousExtensionCategory:
            if extension_lower in category.value:
                return category
        return None

    @classmethod
    def validate_configuration(
        cls, strict: bool = True
    ) -> list[ConfigValidationError]:
        """
        Validate the class-level default configuration.

        Args:
            strict: Reserved for future behavior adjustments.

        Returns:
            List of detected validation errors.
        """
        return cls._collect_errors(cls.limits)

    def validate_instance(
        self, strict: bool = True
    ) -> list[ConfigValidationError]:
        """
        Validate this instance's configuration.

        Validates the per-instance ``limits`` so a customized
        instance is checked instead of the class default.

        Args:
            strict: Reserved for future behavior adjustments.

        Returns:
            List of detected validation errors.
        """
        return type(self)._collect_errors(self.limits)

    @classmethod
    def _collect_errors(
        cls, limits: SecurityLimits
    ) -> list[ConfigValidationError]:
        """
        Run all validation routines for the given limits.

        Class-level MIME, extension, and enum checks are
        instance-independent and always validated as-is.

        Args:
            limits: Security limits to validate.

        Returns:
            List of detected validation errors.
        """
        errors: list[ConfigValidationError] = []

        # Validate file size limits
        errors.extend(cls._validate_file_size_limits(limits))

        # Validate MIME type configurations
        errors.extend(cls._validate_mime_configurations())

        # Validate file extension configurations
        errors.extend(cls._validate_extension_configurations())

        # Validate ZIP compression settings
        errors.extend(cls._validate_compression_settings(limits))

        # Validate enum consistency
        errors.extend(cls._validate_enum_consistency())

        # Validate cross-configuration dependencies
        errors.extend(cls._validate_cross_dependencies())

        return errors

    @staticmethod
    def _validate_file_size_limits(
        limits: SecurityLimits,
    ) -> list[ConfigValidationError]:
        """
        Validate the provided file size limits.

        Args:
            limits: Security limits to validate.

        Returns:
            List of detected configuration issues.
        """
        errors = []

        # Check image size limits
        if limits.max_image_size <= 0:
            errors.append(
                _config_error(
                    "invalid_size_limit",
                    "max_image_size must be greater than 0",
                    "file_sizes",
                    "Set max_image_size to a positive value (e.g., 20MB)",
                )
            )

        if limits.max_image_size > 100 * 1024 * 1024:  # 100MB
            errors.append(
                _config_error(
                    "excessive_size_limit",
                    (
                        "max_image_size"
                        f" ({bytes_to_mb(limits.max_image_size)}"
                        "MB) is very large"
                    ),
                    "file_sizes",
                    (
                        "Consider reducing image size"
                        " limit to prevent resource"
                        " exhaustion"
                    ),
                    severity="warning",
                )
            )

        # Check ZIP size limits
        if limits.max_zip_size <= 0:
            errors.append(
                _config_error(
                    "invalid_size_limit",
                    "max_zip_size must be greater than 0",
                    "file_sizes",
                    "Set max_zip_size to a positive value (e.g., 500MB)",
                )
            )

        if limits.max_zip_size > 2 * 1024 * 1024 * 1024:  # 2GB
            errors.append(
                _config_error(
                    "excessive_size_limit",
                    (
                        "max_zip_size"
                        f" ({bytes_to_mb(limits.max_zip_size)}"
                        "MB) is very large"
                    ),
                    "file_sizes",
                    (
                        "Consider reducing ZIP size"
                        " limit to prevent resource"
                        " exhaustion"
                    ),
                    severity="warning",
                )
            )

        # Validate size relationship
        if limits.max_zip_size <= limits.max_image_size:
            errors.append(
                _config_error(
                    "inconsistent_size_limits",
                    (
                        "max_zip_size should typically be"
                        " larger than max_image_size"
                    ),
                    "file_sizes",
                    (
                        "ZIP files usually contain"
                        " multiple files and should"
                        " have higher limits"
                    ),
                    severity="warning",
                )
            )

        # Validate sanitized filename length
        if limits.max_sanitized_name_length <= 0:
            errors.append(
                _config_error(
                    "invalid_name_length",
                    "max_sanitized_name_length must be greater than 0",
                    "file_sizes",
                    "Set max_sanitized_name_length to a positive value",
                )
            )

        # Validate decoded image size limit
        if limits.max_image_pixels <= 0:
            errors.append(
                _config_error(
                    "invalid_pixel_limit",
                    "max_image_pixels must be greater than 0",
                    "file_sizes",
                    (
                        "Set max_image_pixels to a positive"
                        " value (e.g., 89478485)"
                    ),
                )
            )

        # Validate XML element cap
        if limits.max_xml_elements <= 0:
            errors.append(
                _config_error(
                    "invalid_xml_element_limit",
                    "max_xml_elements must be greater than 0",
                    "file_sizes",
                    (
                        "Set max_xml_elements to a positive"
                        " value (e.g., 1000000)"
                    ),
                )
            )

        if limits.content_scan_max_size <= 0:
            errors.append(
                _config_error(
                    "invalid_content_scan_size",
                    "content_scan_max_size must be greater than 0",
                    "content_analysis",
                    (
                        "Set content_scan_max_size to a positive"
                        " byte limit (e.g., 50MB)"
                    ),
                )
            )

        # A missing temp directory only surfaces when an upload
        # spills to disk, so check it up front.
        if limits.temp_dir is not None and not os.path.isdir(limits.temp_dir):
            errors.append(
                _config_error(
                    "invalid_temp_dir",
                    f"temp_dir '{limits.temp_dir}' is not a directory",
                    "file_sizes",
                    (
                        "Create the directory or leave temp_dir"
                        " unset to use the system default"
                    ),
                )
            )

        # Someone who tuned the memory budget but left enforcement
        # off believes they have a control they do not have. Only
        # informational: leaving enforcement off is the correct
        # choice under concurrency, so this must not fail strict
        # validation for an otherwise sound configuration.
        if (
            not limits.enforce_memory_limit
            and limits.max_validation_memory_mb
            != SecurityLimits.max_validation_memory_mb
        ):
            errors.append(
                _config_error(
                    "memory_limit_not_enforced",
                    (
                        "max_validation_memory_mb is set to"
                        f" {limits.max_validation_memory_mb}MB but"
                        " enforce_memory_limit is False, so exceeding"
                        " it is only logged"
                    ),
                    "resource_limits",
                    (
                        "Set enforce_memory_limit=True if this must"
                        " fail the validation, and only in a process"
                        " that validates one upload at a time;"
                        " otherwise rely on the byte limits"
                    ),
                    severity="info",
                )
            )

        return errors

    @classmethod
    def _validate_mime_configurations(cls) -> list[ConfigValidationError]:
        """
        Validate MIME type configurations.

        Returns:
            List of detected configuration issues.
        """
        errors = []

        # Check image MIME types
        if not cls.ALLOWED_IMAGE_MIMES:
            errors.append(
                _config_error(
                    "empty_mime_set",
                    "ALLOWED_IMAGE_MIMES cannot be empty",
                    "mime_types",
                    "Add at least one allowed image MIME type",
                )
            )

        # Validate image MIME type format
        for mime_type in cls.ALLOWED_IMAGE_MIMES:
            if not mime_type.startswith("image/"):
                errors.append(
                    _config_error(
                        "invalid_image_mime",
                        (
                            "Image MIME type"
                            f" '{mime_type}' should"
                            " start with 'image/'"
                        ),
                        "mime_types",
                        (
                            "Use standard image MIME"
                            " types like 'image/jpeg',"
                            " 'image/png'"
                        ),
                        severity="warning",
                    )
                )

        # Check ZIP MIME types
        if not cls.ALLOWED_ZIP_MIMES:
            errors.append(
                _config_error(
                    "empty_mime_set",
                    "ALLOWED_ZIP_MIMES cannot be empty",
                    "mime_types",
                    "Add at least one allowed ZIP MIME type",
                )
            )

        # Check for duplicate MIME types
        all_mimes = list(cls.ALLOWED_IMAGE_MIMES) + list(cls.ALLOWED_ZIP_MIMES)
        duplicates = {mime for mime in all_mimes if all_mimes.count(mime) > 1}
        if duplicates:
            errors.append(
                _config_error(
                    "duplicate_mime_types",
                    f"Duplicate MIME types found: {duplicates}",
                    "mime_types",
                    "Remove duplicate MIME types to avoid confusion",
                    severity="warning",
                )
            )

        return errors

    @classmethod
    def _validate_extension_configurations(cls) -> list[ConfigValidationError]:
        """
        Validate file extension configurations.

        Returns:
            List of detected configuration issues.
        """
        errors = []

        # Check extension format
        for ext_set_name, ext_set in [
            ("ALLOWED_IMAGE_EXTENSIONS", cls.ALLOWED_IMAGE_EXTENSIONS),
            ("ALLOWED_ZIP_EXTENSIONS", cls.ALLOWED_ZIP_EXTENSIONS),
        ]:
            if not ext_set:
                errors.append(
                    _config_error(
                        "empty_extension_set",
                        f"{ext_set_name} cannot be empty",
                        "extensions",
                        f"Add at least one extension to {ext_set_name}",
                    )
                )

            for ext in ext_set:
                if not ext.startswith("."):
                    errors.append(
                        _config_error(
                            "invalid_extension_format",
                            (
                                f"Extension '{ext}'"
                                f" in {ext_set_name}"
                                " should start with '.'"
                            ),
                            "extensions",
                            "Use format '.ext' for file extensions",
                        )
                    )

        # Check blocked extensions
        if not cls.BLOCKED_EXTENSIONS:
            errors.append(
                _config_error(
                    "empty_blocked_extensions",
                    "BLOCKED_EXTENSIONS is empty - security risk",
                    "extensions",
                    "Ensure dangerous extensions are properly blocked",
                )
            )

        # Check for overlap between allowed and blocked extensions
        image_blocked = cls.ALLOWED_IMAGE_EXTENSIONS.intersection(
            cls.BLOCKED_EXTENSIONS
        )
        if image_blocked:
            errors.append(
                _config_error(
                    "extension_conflict",
                    (
                        f"Image extensions {image_blocked}"
                        " are both allowed and blocked"
                    ),
                    "extensions",
                    (
                        "Remove conflicts between"
                        " allowed and blocked"
                        " extensions"
                    ),
                )
            )

        zip_blocked = cls.ALLOWED_ZIP_EXTENSIONS.intersection(
            cls.BLOCKED_EXTENSIONS
        )
        if zip_blocked:
            errors.append(
                _config_error(
                    "extension_conflict",
                    (
                        f"ZIP extensions {zip_blocked}"
                        " are both allowed and blocked"
                    ),
                    "extensions",
                    (
                        "Remove conflicts between"
                        " allowed and blocked"
                        " extensions"
                    ),
                )
            )

        # Check compound extension consistency
        compound_overlap = cls.BLOCKED_EXTENSIONS.intersection(
            cls.COMPOUND_BLOCKED_EXTENSIONS
        )
        if compound_overlap:
            errors.append(
                _config_error(
                    "compound_extension_overlap",
                    (
                        f"Extensions {compound_overlap}"
                        " appear in both blocked and"
                        " compound blocked lists"
                    ),
                    "extensions",
                    (
                        "Compound extensions should"
                        " only be in"
                        " COMPOUND_BLOCKED_EXTENSIONS"
                    ),
                    severity="warning",
                )
            )

        return errors

    @staticmethod
    def _validate_compression_settings(
        limits: SecurityLimits,
    ) -> list[ConfigValidationError]:
        """
        Validate the provided compression-related limits.

        Args:
            limits: Security limits to validate.

        Returns:
            List of detected configuration issues.
        """
        errors = []

        # Validate compression ratio
        if limits.max_compression_ratio <= 0:
            errors.append(
                _config_error(
                    "invalid_compression_ratio",
                    "max_compression_ratio must be greater than 0",
                    "compression",
                    "Set a reasonable compression ratio limit (e.g., 100:1)",
                )
            )

        if limits.max_compression_ratio < 10:
            errors.append(
                _config_error(
                    "too_strict_compression",
                    (
                        "max_compression_ratio"
                        f" ({limits.max_compression_ratio})"
                        " is very strict"
                    ),
                    "compression",
                    (
                        "Consider allowing higher"
                        " compression ratios for"
                        " legitimate files"
                    ),
                    severity="warning",
                )
            )

        if limits.max_compression_ratio > 1000:
            errors.append(
                _config_error(
                    "too_permissive_compression",
                    (
                        "max_compression_ratio"
                        f" ({limits.max_compression_ratio})"
                        " may allow zip bombs"
                    ),
                    "compression",
                    (
                        "Reduce compression ratio"
                        " limit to prevent zip bomb"
                        " attacks"
                    ),
                    severity="warning",
                )
            )

        # Validate uncompressed size limit
        if limits.max_uncompressed_size <= 0:
            errors.append(
                _config_error(
                    "invalid_uncompressed_size",
                    "max_uncompressed_size must be greater than 0",
                    "compression",
                    "Set a reasonable uncompressed size limit",
                )
            )

        # Validate individual file size limit
        if limits.max_individual_file_size <= 0:
            errors.append(
                _config_error(
                    "invalid_individual_file_size",
                    "max_individual_file_size must be greater than 0",
                    "compression",
                    "Set a reasonable individual file size limit",
                )
            )

        # Check individual file size doesn't exceed total uncompressed size
        if limits.max_individual_file_size > (limits.max_uncompressed_size):
            ind_mb = bytes_to_mb(limits.max_individual_file_size)
            uncomp_mb = bytes_to_mb(limits.max_uncompressed_size)
            errors.append(
                _config_error(
                    "inconsistent_size_limits",
                    (
                        "max_individual_file_size"
                        f" ({ind_mb}MB) exceeds"
                        " max_uncompressed_size"
                        f" ({uncomp_mb}MB)"
                    ),
                    "compression",
                    (
                        "Individual file size limit"
                        " should not exceed total"
                        " uncompressed size limit"
                    ),
                    severity="warning",
                )
            )

        # Validate ZIP entry limits
        if limits.max_zip_entries <= 0:
            errors.append(
                _config_error(
                    "invalid_zip_entries",
                    "max_zip_entries must be greater than 0",
                    "compression",
                    "Set a reasonable limit for ZIP file entries",
                )
            )

        if limits.max_zip_entries > 100000:
            errors.append(
                _config_error(
                    "excessive_zip_entries",
                    (
                        "max_zip_entries"
                        f" ({limits.max_zip_entries})"
                        " is very high"
                    ),
                    "compression",
                    "High entry limits may impact performance",
                    severity="warning",
                )
            )

        # Validate timeout settings
        if limits.zip_analysis_timeout <= 0:
            errors.append(
                _config_error(
                    "invalid_timeout",
                    "zip_analysis_timeout must be greater than 0",
                    "compression",
                    "Set a reasonable timeout for ZIP analysis",
                )
            )

        if limits.zip_analysis_timeout > 30:
            errors.append(
                _config_error(
                    "excessive_timeout",
                    (
                        "zip_analysis_timeout"
                        f" ({limits.zip_analysis_timeout}s)"
                        " is very long"
                    ),
                    "compression",
                    "Long timeouts may impact user experience",
                    severity="warning",
                )
            )

        if limits.gzip_analysis_timeout <= 0:
            errors.append(
                _config_error(
                    "invalid_timeout",
                    "gzip_analysis_timeout must be greater than 0",
                    "compression",
                    "Set a reasonable timeout for gzip inflation",
                )
            )

        # A timeout too short to inflate a permitted stream turns
        # every slow-but-legitimate upload into a ZipBombError and
        # a THREAT_DETECTED audit event, so the two limits have to
        # be sized against each other.
        required = (
            bytes_to_mb(limits.max_uncompressed_size)
            / _MIN_INFLATE_THROUGHPUT_MB_S
        )
        if 0 < limits.gzip_analysis_timeout < required:
            errors.append(
                _config_error(
                    "gzip_timeout_below_size_limit",
                    (
                        "gzip_analysis_timeout"
                        f" ({limits.gzip_analysis_timeout}s) is too"
                        " short to inflate max_uncompressed_size"
                        f" ({bytes_to_mb(limits.max_uncompressed_size)}MB),"
                        f" which needs about {required:.0f}s at"
                        f" {_MIN_INFLATE_THROUGHPUT_MB_S}MB/s; legitimate"
                        " uploads will be rejected as decompression bombs"
                    ),
                    "compression",
                    (
                        f"Raise gzip_analysis_timeout to at least"
                        f" {required:.0f}s or lower"
                        " max_uncompressed_size"
                    ),
                    severity="warning",
                )
            )

        # A misspelled category would silently disable the check.
        known = {category.name for category in ZipThreatCategory}
        unknown = sorted(set(limits.blocked_zip_entry_categories) - known)
        if unknown:
            errors.append(
                _config_error(
                    "unknown_zip_entry_category",
                    (
                        "blocked_zip_entry_categories contains"
                        f" unknown names: {', '.join(unknown)}"
                    ),
                    "compression",
                    (
                        "Use ZipThreatCategory member names"
                        f" ({', '.join(sorted(known))})"
                    ),
                )
            )

        return errors

    @classmethod
    def _validate_enum_consistency(cls) -> list[ConfigValidationError]:
        """
        Validate enum categories for emptiness and overlaps.

        Returns:
            List of detected configuration issues.
        """
        errors = []

        # Check for empty enum categories
        for dangerous_category in DangerousExtensionCategory:
            if not dangerous_category.value:
                errors.append(
                    _config_error(
                        "empty_enum_category",
                        (
                            "Extension category"
                            f" {dangerous_category.name} is empty"
                        ),
                        "enums",
                        (
                            "Add extensions to"
                            f" {dangerous_category.name} or remove"
                            " unused category"
                        ),
                        severity="warning",
                    )
                )

        for compound_category in CompoundExtensionCategory:
            if not compound_category.value:
                errors.append(
                    _config_error(
                        "empty_enum_category",
                        (
                            "Compound extension"
                            " category"
                            f" {compound_category.name} is empty"
                        ),
                        "enums",
                        (
                            "Add extensions to"
                            f" {compound_category.name} or remove"
                            " unused category"
                        ),
                        severity="warning",
                    )
                )

        for unicode_category in UnicodeAttackCategory:
            if not unicode_category.value:
                errors.append(
                    _config_error(
                        "empty_enum_category",
                        (
                            "Unicode attack category"
                            f" {unicode_category.name} is empty"
                        ),
                        "enums",
                        (
                            "Add Unicode characters to"
                            f" {unicode_category.name} or remove"
                            " unused category"
                        ),
                        severity="warning",
                    )
                )

        # Check for overlapping extensions between categories.
        # Use combinations so each unordered pair is reported once.
        all_extensions_by_category = {
            category.name: category.value
            for category in DangerousExtensionCategory
        }

        for (cat1_name, cat1_exts), (
            cat2_name,
            cat2_exts,
        ) in itertools.combinations(all_extensions_by_category.items(), 2):
            overlap = cat1_exts.intersection(cat2_exts)
            if overlap:
                errors.append(
                    _config_error(
                        "category_overlap",
                        (
                            f"Categories {cat1_name}"
                            f" and {cat2_name}"
                            " share extensions:"
                            f" {overlap}"
                        ),
                        "enums",
                        (
                            "Consider if extensions"
                            " should belong to"
                            " multiple categories"
                        ),
                        severity="info",
                    )
                )

        return errors

    @classmethod
    def _validate_cross_dependencies(cls) -> list[ConfigValidationError]:
        """
        Validate cross-field configuration constraints.

        Returns:
            List of detected configuration issues.
        """
        errors = []

        # Check Windows reserved names format
        for name in cls.WINDOWS_RESERVED_NAMES:
            if not name.islower():
                errors.append(
                    _config_error(
                        "case_sensitive_reserved_name",
                        (
                            "Windows reserved name"
                            f" '{name}' should be"
                            " lowercase"
                        ),
                        "reserved_names",
                        (
                            "Use lowercase for"
                            " consistent"
                            " case-insensitive matching"
                        ),
                        severity="warning",
                    )
                )

        # Validate Unicode character ranges
        for char_code in cls.DANGEROUS_UNICODE_CHARS:
            if not isinstance(char_code, int):
                errors.append(
                    _config_error(
                        "invalid_unicode_char",
                        (
                            "Unicode character code"
                            f" {char_code} is not"
                            " an integer"
                        ),
                        "unicode",
                        "Use integer Unicode code points",
                    )
                )
            elif char_code < 0 or char_code > 0x10FFFF:
                errors.append(
                    _config_error(
                        "invalid_unicode_range",
                        (
                            "Unicode character code"
                            f" {char_code} is outside"
                            " valid range"
                        ),
                        "unicode",
                        "Use valid Unicode code points (0-0x10FFFF)",
                    )
                )

        return errors

    @classmethod
    def validate_and_report(cls, strict: bool = True) -> None:
        """
        Validate the class-level configuration and log outcomes.

        Args:
            strict: If True, raise on errors/warnings.

        Raises:
            FileSecurityConfigurationError: If strict and issues found.
        """
        cls._report_errors(cls.validate_configuration(strict=strict), strict)

    def validate_and_report_instance(self, strict: bool = True) -> None:
        """
        Validate this instance's configuration and log outcomes.

        Args:
            strict: If True, raise on errors/warnings.

        Raises:
            FileSecurityConfigurationError: If strict and issues found.
        """
        type(self)._report_errors(
            self.validate_instance(strict=strict), strict
        )

    @staticmethod
    def _report_errors(
        errors: list[ConfigValidationError], strict: bool
    ) -> None:
        """
        Log validation issues and optionally raise.

        Args:
            errors: Validation errors to report.
            strict: If True, raise when errors or warnings exist.

        Raises:
            FileSecurityConfigurationError: If strict and issues found.
        """
        if not errors:
            logger.info("File security configuration validation passed")
            return

        # Separate errors by severity
        error_list = [e for e in errors if e.severity == "error"]
        warning_list = [e for e in errors if e.severity == "warning"]
        info_list = [e for e in errors if e.severity == "info"]

        # Log validation results
        if error_list:
            for error in error_list:
                logger.error(
                    "Configuration error in %s: %s. %s",
                    error.component,
                    error.message,
                    error.recommendation,
                )

        if warning_list:
            for warning in warning_list:
                logger.warning(
                    "Configuration warning in %s: %s. %s",
                    warning.component,
                    warning.message,
                    warning.recommendation,
                )

        if info_list:
            for info in info_list:
                logger.info(
                    "Configuration info in %s: %s. %s",
                    info.component,
                    info.message,
                    info.recommendation,
                )

        # Raise exception if there are errors and strict mode is enabled
        if strict and error_list:
            raise FileSecurityConfigurationError(error_list)
        if strict and warning_list:
            raise FileSecurityConfigurationError(warning_list)
