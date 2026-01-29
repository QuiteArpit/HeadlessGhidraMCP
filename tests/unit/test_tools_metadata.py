import pytest
import json
from unittest.mock import patch
from src.tools import metadata

# Sample data
SAMPLE_DATA = {
    "imports": [
        {"library": "KERNEL32.DLL", "name": "CreateFileW"},
        {"library": "KERNEL32.DLL", "name": "CloseHandle"},
        {"library": "USER32.DLL", "name": "MessageBoxA"}
    ],
    "exports": [
        {"name": "start", "address": "0x140001"}
    ]
}

@patch('src.tools.metadata.load_json_for_binary')
def test_list_imports(mock_load):
    mock_load.return_value = SAMPLE_DATA
    
    res_str = metadata.list_imports("/tmp/bin")
    res = json.loads(res_str)
    
    assert res["data"]["total_imports"] == 3
    assert set(res["data"]["libraries"]) == {"KERNEL32.DLL", "USER32.DLL"}
    assert len(res["data"]["imports_by_library"]["KERNEL32.DLL"]) == 2

@patch('src.tools.metadata.load_json_for_binary')
def test_list_exports(mock_load):
    mock_load.return_value = SAMPLE_DATA
    
    res_str = metadata.list_exports("/tmp/bin")
    res = json.loads(res_str)
    
    assert res["data"]["total_exports"] == 1
    assert res["data"]["exports"][0]["name"] == "start"

@patch('src.tools.metadata.load_json_for_binary')
def test_no_analysis(mock_load):
    mock_load.return_value = None
    res_str = metadata.list_imports("/tmp/bin")
    assert json.loads(res_str).get("status") == "error"
