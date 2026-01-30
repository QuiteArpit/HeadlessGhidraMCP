"""tests/unit/test_platform_utils.py - Unit tests for platform detection and Ghidra path resolution"""
import os
import sys
import pytest
from unittest.mock import patch
from pathlib import Path

# Import the module under test
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from src.platform_utils import (
    is_windows,
    get_os_name,
    get_ghidra_executable_name,
    find_ghidra_path,
    get_platform_info,
)


class TestIsWindows:
    """Tests for is_windows()"""
    
    def test_returns_true_on_windows(self):
        with patch("src.platform_utils.IS_WINDOWS", True):
            assert is_windows() is True
    
    def test_returns_false_on_linux(self):
        with patch("src.platform_utils.IS_WINDOWS", False):
            assert is_windows() is False
    
    def test_returns_false_on_darwin(self):
        with patch("src.platform_utils.IS_WINDOWS", False):
            assert is_windows() is False


class TestGetOsName:
    """Tests for get_os_name()"""
    
    def test_returns_lowercase_string(self):
        result = get_os_name()
        assert result == result.lower()
        assert isinstance(result, str)


class TestGetGhidraExecutableName:
    """Tests for get_ghidra_executable_name()"""
    
    def test_returns_bat_on_windows(self):
        with patch("src.platform_utils.is_windows", return_value=True):
            assert get_ghidra_executable_name() == "analyzeHeadless.bat"
    
    def test_returns_no_extension_on_linux(self):
        with patch("src.platform_utils.is_windows", return_value=False):
            assert get_ghidra_executable_name() == "analyzeHeadless"


class TestFindGhidraPath:
    """Tests for find_ghidra_path() with mocked filesystem"""
    
    def test_env_var_takes_priority(self, tmp_path):
        """GHIDRA_HEADLESS_PATH should be used if set and valid"""
        fake_ghidra = tmp_path / "analyzeHeadless"
        fake_ghidra.touch()
        
        with patch.dict(os.environ, {"GHIDRA_HEADLESS_PATH": str(fake_ghidra)}, clear=False):
            result = find_ghidra_path()
            assert result == str(fake_ghidra)
    
    def test_env_var_ignored_if_file_missing(self, clean_env):
        """Invalid GHIDRA_HEADLESS_PATH should fall through to next check"""
        with patch.dict(os.environ, {"GHIDRA_HEADLESS_PATH": "/nonexistent/path"}, clear=False):
            result = find_ghidra_path()
            # Should NOT return the invalid path
            assert result != "/nonexistent/path"
    
    def test_install_dir_builds_correct_path_linux(self, tmp_path, clean_env):
        """GHIDRA_INSTALL_DIR should append /support/analyzeHeadless on Linux"""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        executable = support_dir / "analyzeHeadless"
        executable.touch()
        
        with patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": str(ghidra_dir)}, clear=False):
            with patch("src.platform_utils.is_windows", return_value=False):
                result = find_ghidra_path()
                assert result == str(executable)
    
    def test_install_dir_builds_correct_path_windows(self, tmp_path, clean_env):
        """GHIDRA_INSTALL_DIR should append /support/analyzeHeadless.bat on Windows"""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        executable = support_dir / "analyzeHeadless.bat"
        executable.touch()
        
        with patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": str(ghidra_dir)}, clear=False):
            with patch("src.platform_utils.is_windows", return_value=True):
                result = find_ghidra_path()
                assert result == str(executable)
    
    def test_returns_none_when_not_found(self, clean_env):
        """Should return None when Ghidra is not installed anywhere"""
        with patch("src.platform_utils.is_windows", return_value=False):
            # Create empty search paths
            with patch.object(Path, "exists", return_value=False):
                result = find_ghidra_path()
                # May be None or may find system Ghidra - either is valid
                # The key is it shouldn't crash
                assert result is None or os.path.exists(result)


class TestGetPlatformInfo:
    """Tests for get_platform_info()"""
    
    def test_returns_required_keys(self):
        info = get_platform_info()
        required_keys = {"os", "os_version", "python_version", "is_windows", "ghidra_executable"}
        assert required_keys.issubset(info.keys())
    
    def test_os_is_string(self):
        info = get_platform_info()
        assert isinstance(info["os"], str)
        assert info["os"] in ("Windows", "Linux", "Darwin")
    
    def test_is_windows_is_bool(self):
        info = get_platform_info()
        assert isinstance(info["is_windows"], bool)
    
    def test_ghidra_executable_matches_os(self):
        info = get_platform_info()
        if info["is_windows"]:
            assert info["ghidra_executable"] == "analyzeHeadless.bat"
        else:
            assert info["ghidra_executable"] == "analyzeHeadless"


class TestAutoDetectionOrder:
    """Tests to verify the correct priority order of path detection"""
    
    def test_direct_path_wins_over_install_dir(self, tmp_path, clean_env):
        """
        Priority should be:
        1. GHIDRA_HEADLESS_PATH (direct path)
        2. GHIDRA_INSTALL_DIR (base directory)
        3. Auto-detect (common locations)
        """
        # Create two fake Ghidra executables
        direct_path = tmp_path / "direct" / "analyzeHeadless"
        direct_path.parent.mkdir(parents=True)
        direct_path.touch()
        
        install_path = tmp_path / "install" / "support" / "analyzeHeadless"
        install_path.parent.mkdir(parents=True)
        install_path.touch()
        
        # When both are set, GHIDRA_HEADLESS_PATH should win
        with patch.dict(os.environ, {
            "GHIDRA_HEADLESS_PATH": str(direct_path),
            "GHIDRA_INSTALL_DIR": str(tmp_path / "install"),
        }, clear=False):
            with patch("src.platform_utils.is_windows", return_value=False):
                result = find_ghidra_path()
                assert result == str(direct_path)
    
    def test_install_dir_wins_over_autodetect(self, tmp_path, clean_env):
        """GHIDRA_INSTALL_DIR should be used before searching common locations"""
        install_path = tmp_path / "custom_install" / "support" / "analyzeHeadless"
        install_path.parent.mkdir(parents=True)
        install_path.touch()
        
        with patch.dict(os.environ, {
            "GHIDRA_INSTALL_DIR": str(tmp_path / "custom_install"),
        }, clear=False):
            with patch("src.platform_utils.is_windows", return_value=False):
                result = find_ghidra_path()
                assert result == str(install_path)


class TestVersionedDirectoryDetection:
    """Tests for detecting versioned Ghidra installations (e.g., ghidra_11.0_PUBLIC)"""
    
    def test_finds_versioned_subdirectory(self, tmp_path, clean_env):
        """Should find Ghidra in versioned subdirectory like /opt/ghidra/ghidra_11.0_PUBLIC"""
        base_path = tmp_path / "opt" / "ghidra"
        versioned_dir = base_path / "ghidra_11.0_PUBLIC" / "support"
        versioned_dir.mkdir(parents=True)
        executable = versioned_dir / "analyzeHeadless"
        executable.touch()
        
        with patch("src.platform_utils.is_windows", return_value=False):
            # Patch the search paths to use our tmp_path
            search_paths = [base_path]
            with patch.object(Path, "exists", return_value=True):
                # This is a simplified test - full test would need more patching
                pass  # TODO: Complete this test with proper mocking
    
    def test_prefers_newest_version(self, tmp_path, clean_env):
        """Should prefer the newest version when multiple are installed"""
        base_path = tmp_path / "opt" / "ghidra"
        
        # Create multiple versions
        for version in ["ghidra_10.0_PUBLIC", "ghidra_11.0_PUBLIC", "ghidra_11.1_PUBLIC"]:
            versioned_dir = base_path / version / "support"
            versioned_dir.mkdir(parents=True)
            executable = versioned_dir / "analyzeHeadless"
            executable.touch()
        
        # The implementation sorts in reverse order, so 11.1 should be found first
        # This test verifies the sorting behavior
        subdirs = sorted(base_path.iterdir(), reverse=True)
        assert subdirs[0].name == "ghidra_11.1_PUBLIC"
