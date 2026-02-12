"""tests/conftest.py - Pytest fixtures for HeadlessGhidraMCP tests"""
import pytest
import os
import sys


def pytest_configure(config):
    """Register custom markers"""
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "e2e: marks tests as end-to-end tests")


@pytest.fixture
def mock_ghidra_install(tmp_path):
    """Create a mock Ghidra installation structure (auto-detects OS)."""
    ghidra_dir = tmp_path / "ghidra_11.0_PUBLIC"
    support_dir = ghidra_dir / "support"
    support_dir.mkdir(parents=True)
    
    if sys.platform == "win32":
        executable = support_dir / "analyzeHeadless.bat"
        executable.write_text("@echo off\necho Mock Ghidra")
    else:
        executable = support_dir / "analyzeHeadless"
        executable.write_text("#!/bin/bash\necho 'Mock Ghidra'")
        executable.chmod(0o755)
    
    return ghidra_dir


@pytest.fixture
def mock_ghidra_install_windows(tmp_path):
    """Create a mock Ghidra installation structure for Windows."""
    ghidra_dir = tmp_path / "ghidra_11.0_PUBLIC"
    support_dir = ghidra_dir / "support"
    support_dir.mkdir(parents=True)
    
    executable = support_dir / "analyzeHeadless.bat"
    executable.write_text("@echo off\necho Mock Ghidra")
    
    return ghidra_dir


@pytest.fixture
def clean_env():
    """Remove Ghidra-related env vars for clean testing"""
    old_env = {}
    vars_to_clear = ["GHIDRA_HEADLESS_PATH", "GHIDRA_INSTALL_DIR"]
    
    for var in vars_to_clear:
        old_env[var] = os.environ.pop(var, None)
    
    yield
    
    # Restore
    for var, value in old_env.items():
        if value is not None:
            os.environ[var] = value
