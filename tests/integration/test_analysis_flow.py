import pytest
import json
import os
import shutil
from src.tools import analysis
from src import config

@pytest.mark.integration
def test_full_analysis_cycle():
    """
    Test the full analysis pipeline on a sample binary.
    This runs Ghidra Headless, so it is slow.
    """
    binary_path = os.path.join(config.BASE_DIR, "samples", "program.exe")
    if not os.path.exists(binary_path):
        pytest.skip("Sample binary not found")
        
    print(f"Analyzing {binary_path}...")
    
    # Force analysis to ensure we test the Ghidra execution
    res_str = analysis.analyze_binary(binary_path, force=True)
    res = json.loads(res_str)
    
    # Verify success
    assert res.get("status") != "error", f"Analysis failed: {res.get('error')}"
    assert res["data"]["status"] == "analyzed"
    assert res["data"]["imports_count"] == 55
    assert res["data"]["exports_count"] == 5
    
    # Verify file exists
    output_path = os.path.join(config.BASE_DIR, res["data"]["output_path"])
    assert os.path.exists(output_path)
    
    # Load JSON and verify deep structure
    with open(output_path, 'r') as f:
        data = json.load(f)
        
    assert len(data["functions"]) == 73
    
    # Check if 'callees' populated for main-ish function
    # heuristic search like in our detailed test
    found_callees = False
    for func in data["functions"]:
        if func.get("callees"):
            found_callees = True
            break
    assert found_callees, "No callees found in any function"
