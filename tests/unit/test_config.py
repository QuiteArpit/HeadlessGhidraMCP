import os
import pytest
from src import config

def test_base_dir_structure():
    """Verify that essential directories are defined relative to BASE_DIR"""
    assert os.path.isdir(config.BASE_DIR)
    assert config.SCRIPT_DIR.endswith("scripts/ghidra")
    assert config.LOGS_DIR.endswith("analysis_output")

def test_ghidra_path_detection():
    """Verify Ghidra path detection logic (it might return None in CI, but here it should be set)"""
    # In this environment, we expect it to be found
    if config.GHIDRA_HEADLESS_PATH:
        assert os.path.exists(config.GHIDRA_HEADLESS_PATH)
        assert "analyzeHeadless" in config.GHIDRA_HEADLESS_PATH
    else:
        pytest.skip("Ghidra not found in environment")
