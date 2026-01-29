import pytest
import json
from unittest.mock import patch, MagicMock
from src.tools import graph

# Sample analysis data
SAMPLE_DATA = {
    "functions": [
        {
            "name": "main",
            "callers": ["entry"],
            "callees": ["printf", "puts"]
        },
        {
            "name": "printf",
            "callers": ["main"],
            "callees": []
        }
    ]
}

@patch('src.tools.graph.load_json_for_binary')
def test_get_function_callers(mock_load):
    mock_load.return_value = SAMPLE_DATA
    
    # Test valid function
    res_str = graph.get_function_callers("/tmp/bin", "main")
    res = json.loads(res_str)
    
    assert res["data"]["function"] == "main"
    assert res["data"]["callers"] == ["entry"]
    assert res["data"]["caller_count"] == 1

@patch('src.tools.graph.load_json_for_binary')
def test_get_function_callees(mock_load):
    mock_load.return_value = SAMPLE_DATA
    
    # Test valid function
    res_str = graph.get_function_callees("/tmp/bin", "main")
    res = json.loads(res_str)
    
    assert res["data"]["function"] == "main"
    assert sorted(res["data"]["callees"]) == ["printf", "puts"]
    assert res["data"]["callee_count"] == 2

@patch('src.tools.graph.load_json_for_binary')
def test_function_not_found(mock_load):
    mock_load.return_value = SAMPLE_DATA
    
    res_str = graph.get_function_callers("/tmp/bin", "missing_func")
    res = json.loads(res_str)
    
    assert res.get("status") == "error"
    assert res.get("error_code") == "FUNCTION_NOT_FOUND"

@patch('src.tools.graph.load_json_for_binary')
def test_no_analysis(mock_load):
    mock_load.return_value = None
    
    res_str = graph.get_function_callers("/tmp/bin", "main")
    res = json.loads(res_str)
    
    assert res.get("status") == "error"
    assert res.get("error_code") == "NO_ANALYSIS"
