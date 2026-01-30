import pytest
import json
import os
import tempfile
from src.tools import analysis
from src import config

@pytest.mark.integration
def test_missing_file_robustness():
    """Verify handling of missing files."""
    res_str = analysis.analyze_binary("/path/to/invalid/file.exe")
    res = json.loads(res_str)
    
    assert res["status"] == "error"
    assert res["error_code"] == "FILE_NOT_FOUND"

@pytest.mark.integration
def test_reanalysis_overwrite():
    """Verify that force=True correctly overwrites previous analysis."""
    binary_path = os.path.join(config.BASE_DIR, "samples", "program.exe")
    if not os.path.exists(binary_path):
        pytest.skip("Sample binary not found")
        
    # First Run
    res1_str = analysis.analyze_binary(binary_path, force=True)
    res1 = json.loads(res1_str)
    assert res1.get("status") != "error"
    t1 = res1.get("data", {}).get("analysis_time_ms", 0)
    
    # Second Run (Force)
    res2_str = analysis.analyze_binary(binary_path, force=True)
    res2 = json.loads(res2_str)
    assert res2.get("status") != "error"
    assert res2["data"]["status"] == "analyzed"
    
    # Verify it really ran again (not cached)
    # Status should be 'analyzed', if cached it says 'cached' (but we used force=True)
    # Analyzer returns 'cached' status only if force=False.
    
    # Also verify output files are valid
    assert os.path.exists(os.path.join(config.BASE_DIR, res2["data"]["output_path"]))

@pytest.mark.integration
def test_corrupted_file_handling():
    """Verify behavior with a non-binary text file (corrupted binary)."""
    # Create temp file in project directory to ensure it passes Safe Dir checks
    samples_dir = os.path.join(config.BASE_DIR, "samples")
    os.makedirs(samples_dir, exist_ok=True)
    
    bad_bin_path = os.path.join(samples_dir, "temp_corrupt.exe")
    with open(bad_bin_path, "wb") as f:
        f.write(b"Not a PE file")
        
    try:
        # Ghidra might fail to import or analyze
        res_str = analysis.analyze_binary(bad_bin_path, force=True)
        res = json.loads(res_str)
        
        # Use safe assertion: Ghidra might create a project but fail import, 
        # or import as Raw Binary. If it fails, we get error. If it succeeds as raw, we get 0 imports.
        if res.get("status") == "error":
            # On Windows, Ghidra might allow it but fail later. 
            # We accept ANALYSIS_FAILED, Import failed, or even SECURITY_VIOLATION if config is weird.
            valid_errors = ["ANALYSIS_FAILED", "SECURITY_VIOLATION"]
            error_msg = str(res)
            assert res.get("error_code") in valid_errors or "Import failed" in error_msg
        else:
            # If it succeeds (Raw Binary), imports should be 0
            assert res["data"]["imports_count"] == 0
    finally:
        if os.path.exists(bad_bin_path):
            os.unlink(bad_bin_path)
