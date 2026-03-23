"""
Tests for safeuploads enum definitions.

Verifies that every security-critical enum category contains the
expected extension, pattern, or code point values so that regressions
in the definitions are caught immediately.
"""


from safeuploads.enums import (
    BinaryFileCategory,
    CompoundExtensionCategory,
    DangerousExtensionCategory,
    SuspiciousFilePattern,
    UnicodeAttackCategory,
    ZipThreatCategory,
)


class TestBinaryFileCategory:
    """Tests for BinaryFileCategory enum."""

    def test_fitness_files_contains_fit_extension(self):
        """
        Test that fitness file category includes .fit extension.

        Returns:
            None
        """
        assert ".fit" in BinaryFileCategory.FITNESS_FILES.value

    def test_fitness_files_is_nonempty(self):
        """
        Test that the fitness file category is not empty.

        Returns:
            None
        """
        assert len(BinaryFileCategory.FITNESS_FILES.value) > 0


class TestDangerousExtensionCategory:
    """Tests for DangerousExtensionCategory enum members."""

    def test_windows_executables_contains_exe(self):
        """
        Test that Windows executables category contains .exe.

        Returns:
            None
        """
        assert ".exe" in DangerousExtensionCategory.WINDOWS_EXECUTABLES.value

    def test_windows_executables_contains_bat(self):
        """
        Test that Windows executables category contains .bat.

        Returns:
            None
        """
        assert ".bat" in DangerousExtensionCategory.WINDOWS_EXECUTABLES.value

    def test_windows_executables_contains_dll(self):
        """
        Test that Windows executables category contains .dll.

        Returns:
            None
        """
        assert ".dll" in DangerousExtensionCategory.WINDOWS_EXECUTABLES.value

    def test_script_files_contains_vbs(self):
        """
        Test that script files category contains .vbs.

        Returns:
            None
        """
        assert ".vbs" in DangerousExtensionCategory.SCRIPT_FILES.value

    def test_script_files_contains_ps1(self):
        """
        Test that script files category contains .ps1.

        Returns:
            None
        """
        assert ".ps1" in DangerousExtensionCategory.SCRIPT_FILES.value

    def test_web_scripts_contains_php(self):
        """
        Test that web scripts category contains .php.

        Returns:
            None
        """
        assert ".php" in DangerousExtensionCategory.WEB_SCRIPTS.value

    def test_web_scripts_contains_asp(self):
        """
        Test that web scripts category contains .asp.

        Returns:
            None
        """
        assert ".asp" in DangerousExtensionCategory.WEB_SCRIPTS.value

    def test_unix_executables_contains_sh(self):
        """
        Test that Unix executables category contains .sh.

        Returns:
            None
        """
        assert ".sh" in DangerousExtensionCategory.UNIX_EXECUTABLES.value

    def test_macos_executables_contains_app(self):
        """
        Test that macOS executables category contains .app.

        Returns:
            None
        """
        assert ".app" in DangerousExtensionCategory.MACOS_EXECUTABLES.value

    def test_java_executables_contains_jar(self):
        """
        Test that Java executables category contains .jar.

        Returns:
            None
        """
        assert ".jar" in DangerousExtensionCategory.JAVA_EXECUTABLES.value

    def test_mobile_apps_contains_apk(self):
        """
        Test that mobile apps category contains .apk.

        Returns:
            None
        """
        assert ".apk" in DangerousExtensionCategory.MOBILE_APPS.value

    def test_browser_extensions_contains_crx(self):
        """
        Test that browser extensions category contains .crx.

        Returns:
            None
        """
        assert ".crx" in DangerousExtensionCategory.BROWSER_EXTENSIONS.value

    def test_archive_formats_contains_rar(self):
        """
        Test that archive formats category contains .rar.

        Returns:
            None
        """
        assert ".rar" in DangerousExtensionCategory.ARCHIVE_FORMATS.value

    def test_archive_formats_contains_7z(self):
        """
        Test that archive formats category contains .7z.

        Returns:
            None
        """
        assert ".7z" in DangerousExtensionCategory.ARCHIVE_FORMATS.value

    def test_office_macros_contains_docm(self):
        """
        Test that office macros category contains .docm.

        Returns:
            None
        """
        assert ".docm" in DangerousExtensionCategory.OFFICE_MACROS.value

    def test_all_categories_are_nonempty(self):
        """
        Test that every dangerous extension category has at least one entry.

        Returns:
            None
        """
        for category in DangerousExtensionCategory:
            assert len(category.value) > 0, (
                f"Category {category.name} must not be empty"
            )

    def test_all_extensions_start_with_dot(self):
        """
        Test that every extension in every category starts with a dot.

        Returns:
            None
        """
        for category in DangerousExtensionCategory:
            for ext in category.value:
                assert ext.startswith("."), (
                    f"Extension '{ext}' in {category.name} "
                    f"must start with '.'"
                )


class TestCompoundExtensionCategory:
    """Tests for CompoundExtensionCategory enum members."""

    def test_compressed_archives_contains_tar_gz(self):
        """
        Test that compressed archives category contains .tar.gz.

        Returns:
            None
        """
        assert (
            ".tar.gz"
            in CompoundExtensionCategory.COMPRESSED_ARCHIVES.value
        )

    def test_compressed_archives_contains_tar_bz2(self):
        """
        Test that compressed archives category contains .tar.bz2.

        Returns:
            None
        """
        assert (
            ".tar.bz2"
            in CompoundExtensionCategory.COMPRESSED_ARCHIVES.value
        )

    def test_javascript_variants_contains_user_js(self):
        """
        Test that JavaScript variants category contains .user.js.

        Returns:
            None
        """
        assert (
            ".user.js"
            in CompoundExtensionCategory.JAVASCRIPT_VARIANTS.value
        )

    def test_web_content_contains_min_css(self):
        """
        Test that web content category contains .min.css.

        Returns:
            None
        """
        assert ".min.css" in CompoundExtensionCategory.WEB_CONTENT.value

    def test_all_categories_are_nonempty(self):
        """
        Test that every compound extension category has at least one entry.

        Returns:
            None
        """
        for category in CompoundExtensionCategory:
            assert len(category.value) > 0, (
                f"Category {category.name} must not be empty"
            )


class TestUnicodeAttackCategory:
    """Tests for UnicodeAttackCategory enum members."""

    def test_directional_overrides_contains_rlo(self):
        """
        Test that directional overrides contains RIGHT-TO-LEFT OVERRIDE.

        Returns:
            None
        """
        assert (
            0x202E
            in UnicodeAttackCategory.DIRECTIONAL_OVERRIDES.value
        )

    def test_directional_overrides_contains_lro(self):
        """
        Test that directional overrides contains LEFT-TO-RIGHT OVERRIDE.

        Returns:
            None
        """
        assert (
            0x202D
            in UnicodeAttackCategory.DIRECTIONAL_OVERRIDES.value
        )

    def test_zero_width_characters_contains_zwsp(self):
        """
        Test that zero-width characters category contains ZERO WIDTH SPACE.

        Returns:
            None
        """
        assert (
            0x200B
            in UnicodeAttackCategory.ZERO_WIDTH_CHARACTERS.value
        )

    def test_zero_width_characters_contains_bom(self):
        """
        Test that zero-width characters category contains BOM (FEFF).

        Returns:
            None
        """
        assert (
            0xFEFF
            in UnicodeAttackCategory.ZERO_WIDTH_CHARACTERS.value
        )

    def test_confusing_punctuation_contains_fullwidth_stop(self):
        """
        Test confusing punctuation contains fullwidth full stop.

        Returns:
            None
        """
        assert (
            0xFF0E
            in UnicodeAttackCategory.CONFUSING_PUNCTUATION.value
        )

    def test_all_code_points_are_valid_integers(self):
        """
        Test that all code points are valid Unicode integer values.

        Returns:
            None
        """
        for category in UnicodeAttackCategory:
            for code_point in category.value:
                assert isinstance(code_point, int), (
                    f"Code point {code_point!r} in {category.name} "
                    f"must be an integer"
                )
                assert 0 <= code_point <= 0x10FFFF, (
                    f"Code point {code_point:#x} in {category.name} "
                    f"is outside the Unicode range"
                )

    def test_all_categories_are_nonempty(self):
        """
        Test that every Unicode attack category has at least one entry.

        Returns:
            None
        """
        for category in UnicodeAttackCategory:
            assert len(category.value) > 0, (
                f"Category {category.name} must not be empty"
            )


class TestSuspiciousFilePattern:
    """Tests for SuspiciousFilePattern enum members."""

    def test_directory_traversal_contains_dotdot_slash(self):
        """
        Test that directory traversal patterns include ../ variant.

        Returns:
            None
        """
        assert "../" in SuspiciousFilePattern.DIRECTORY_TRAVERSAL.value

    def test_directory_traversal_contains_url_encoded(self):
        """
        Test that directory traversal patterns include URL-encoded variant.

        Returns:
            None
        """
        assert (
            "%2e%2e%2f"
            in SuspiciousFilePattern.DIRECTORY_TRAVERSAL.value
        )

    def test_suspicious_names_contains_autorun_inf(self):
        """
        Test that suspicious names include autorun.inf.

        Returns:
            None
        """
        assert (
            "autorun.inf" in SuspiciousFilePattern.SUSPICIOUS_NAMES.value
        )

    def test_suspicious_names_contains_htaccess(self):
        """
        Test that suspicious names include .htaccess.

        Returns:
            None
        """
        assert (
            ".htaccess" in SuspiciousFilePattern.SUSPICIOUS_NAMES.value
        )

    def test_executable_signatures_contains_mz_header(self):
        """
        Test that executable signatures include Windows MZ header.

        Returns:
            None
        """
        assert (
            b"MZ" in SuspiciousFilePattern.EXECUTABLE_SIGNATURES.value
        )

    def test_executable_signatures_contains_elf_header(self):
        """
        Test that executable signatures include ELF header.

        Returns:
            None
        """
        assert (
            b"\x7fELF"
            in SuspiciousFilePattern.EXECUTABLE_SIGNATURES.value
        )

    def test_suspicious_paths_contains_etc(self):
        """
        Test that suspicious paths include Unix /etc/ directory.

        Returns:
            None
        """
        assert "/etc/" in SuspiciousFilePattern.SUSPICIOUS_PATHS.value

    def test_suspicious_paths_contains_git(self):
        """
        Test that suspicious paths include .git/ directory.

        Returns:
            None
        """
        assert ".git/" in SuspiciousFilePattern.SUSPICIOUS_PATHS.value


class TestZipThreatCategory:
    """Tests for ZipThreatCategory enum members."""

    def test_nested_archives_contains_zip(self):
        """
        Test that nested archives threat category includes .zip.

        Returns:
            None
        """
        assert ".zip" in ZipThreatCategory.NESTED_ARCHIVES.value

    def test_nested_archives_contains_rar(self):
        """
        Test that nested archives threat category includes .rar.

        Returns:
            None
        """
        assert ".rar" in ZipThreatCategory.NESTED_ARCHIVES.value

    def test_executable_files_contains_exe(self):
        """
        Test that executable files threat category includes .exe.

        Returns:
            None
        """
        assert ".exe" in ZipThreatCategory.EXECUTABLE_FILES.value

    def test_script_files_contains_js(self):
        """
        Test that script files threat category includes .js.

        Returns:
            None
        """
        assert ".js" in ZipThreatCategory.SCRIPT_FILES.value

    def test_system_files_contains_dll(self):
        """
        Test that system files threat category includes .dll.

        Returns:
            None
        """
        assert ".dll" in ZipThreatCategory.SYSTEM_FILES.value

    def test_all_categories_are_nonempty(self):
        """
        Test that every ZIP threat category has at least one entry.

        Returns:
            None
        """
        for category in ZipThreatCategory:
            assert len(category.value) > 0, (
                f"ZIP threat category {category.name} must not be empty"
            )
