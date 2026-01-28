"""tests/integration/test_ghidra_detection.py - Integration tests for Ghidra detection"""
import os
import pytest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from src.platform_utils import find_ghidra_path, get_platform_info


@pytest.mark.integration
class TestRealGhidraDetection:
    """Integration tests that check actual Ghidra installation on the system"""
    
    def test_detects_ghidra_if_installed(self):
        """Skip if Ghidra not installed, pass if it finds it"""
        path = find_ghidra_path()
        
        if path is None:
            pytest.skip("Ghidra not installed on this system")
        
        assert os.path.isfile(path)
        assert "analyzeHeadless" in path
    
    def test_ghidra_is_executable(self):
        """Verify detected Ghidra path is actually executable"""
        path = find_ghidra_path()
        
        if path is None:
            pytest.skip("Ghidra not installed on this system")
        
        info = get_platform_info()
        if not info["is_windows"]:
            # On Linux, check execute permission
            assert os.access(path, os.X_OK), f"{path} is not executable"
    
    def test_ghidra_path_contains_support_directory(self):
        """Verify the path structure is correct (should be in support/ directory)"""
        path = find_ghidra_path()
        
        if path is None:
            pytest.skip("Ghidra not installed on this system")
        
        # The executable should be in a 'support' directory
        parent = Path(path).parent
        assert parent.name == "support", f"Expected Ghidra to be in 'support' dir, got {parent}"


@pytest.mark.integration
class TestPlatformInfoIntegration:
    """Integration tests for platform info gathering"""
    
    def test_os_matches_actual_system(self):
        """Verify get_platform_info returns correct OS"""
        import platform
        info = get_platform_info()
        
        assert info["os"] == platform.system()
    
    def test_python_version_matches(self):
        """Verify Python version is correctly reported"""
        import platform
        info = get_platform_info()
        
        assert info["python_version"] == platform.python_version()
