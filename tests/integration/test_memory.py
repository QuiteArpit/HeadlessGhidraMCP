import os
import pytest
import json
from unittest.mock import patch, MagicMock
from src import session
from src.tools.graph import get_function_callers

@pytest.fixture
def mock_json_file(tmp_path):
    f = tmp_path / "test.json"
    data = {
        "functions": [
            {"name": "main", "callers": ["entry"], "callees": ["printf"]},
            {"name": "printf", "callers": ["main"], "callees": []}
        ],
        "strings": [],
        "imports": [],
        "exports": []
    }
    f.write_text(json.dumps(data))
    return str(f)

def test_lru_eviction():
    """Verify that session size limit causes eviction."""
    # Set limit to 2
    with patch("src.session.GHIDRA_SESSION_SIZE", 2):
        session.clear_session_data()
        
        # Add 3 items
        session.add_to_session("/bin/1", "h1", "/path/1.json", 10, 0)
        session.add_to_session("/bin/2", "h2", "/path/2.json", 10, 0)
        session.add_to_session("/bin/3", "h3", "/path/3.json", 10, 0)
        
        bins = session.get_all_session_binaries()
        assert len(bins) == 2
        assert "/bin/1" not in bins # Oldest
        assert "/bin/3" in bins # Newest

def test_hybrid_loading_switch(mock_json_file):
    """Verify switching between Dict and Streaming based on threshold."""
    
    # CASE 1: Small File (Dict Mode)
    # Threshold 100MB > File Size -> Dict
    with patch("src.session.GHIDRA_STREAMING_THRESHOLD_MB", 100):
        session.clear_session_data()
        session.add_to_session("/bin/small", "h", mock_json_file, 2, 0)
        
        # Spy on json.load
        with patch("json.load", wraps=json.load) as mock_json_load:
            acc = session.load_data_accessor("/bin/small")
            # Trigger load
            funcs = list(acc.get_functions())
            assert len(funcs) == 2
            mock_json_load.assert_called()

    # CASE 2: "Large" File (Streaming Mode)
    # Threshold 0MB < File Size -> Streaming
    with patch("src.session.GHIDRA_STREAMING_THRESHOLD_MB", 0):
        session.clear_session_data()
        session.add_to_session("/bin/large", "h", mock_json_file, 2, 0)
        
        # Spy on ijson.items
        with patch("ijson.items") as mock_ijson:
            # Mock return of ijson
            mock_ijson.return_value = iter([{"name": "main"}])
            
            acc = session.load_data_accessor("/bin/large")
            funcs = list(acc.get_functions())
            
            assert len(funcs) == 1
            mock_ijson.assert_called()

def test_tool_compatibility(mock_json_file):
    """Verify tool works with the new accessor."""
    session.clear_session_data()
    session.add_to_session("/bin/real", "h", mock_json_file, 2, 0)

    # Mock GHIDRA_STREAMING_THRESHOLD_MB to ensure we test specific mode if needed
    # But let's test default (small file -> dict)
    
    # We must patch load_data_accessor to return our session-backed accessor 
    # because tools import it from session
    # Actually, integration test usually just runs the tool
    
    # Just run the tool function
    result = get_function_callers("/bin/real", "main")
    # Result is a JSON string response (pretty printed)
    result_dict = json.loads(result)
    assert result_dict["status"] == "success"
    assert result_dict["data"]["callers"] == ["entry"]
