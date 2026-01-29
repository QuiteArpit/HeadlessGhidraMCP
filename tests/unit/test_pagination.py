import pytest
from unittest.mock import MagicMock, patch
from src.session import DataAccessor
from src.tools import query, graph, metadata
import json

# Setup Mock Session
MOCK_FUNCTIONS = [{"name": f"func_{i}", "entry": f"0x{i:04x}", "callers": ["main"], "callees": []} for i in range(1500)]
MOCK_IMPORTS = [{"library": "A.dll", "name": f"imp_{i}"} for i in range(2500)]

@pytest.fixture
def mock_accessor():
    acc = MagicMock()
    # Mock slice_items generically
    def slice_side_effect(key, offset, limit):
        if key == "functions": return MOCK_FUNCTIONS[offset : offset + limit]
        if key == "imports": return MOCK_IMPORTS[offset : offset + limit]
        return []
    
    acc.slice_items.side_effect = slice_side_effect
    
    # Mock counts
    def count_side_effect(key):
        if key == "functions": return len(MOCK_FUNCTIONS)
        if key == "imports": return len(MOCK_IMPORTS)
        return 0
    acc.get_count.side_effect = count_side_effect
    
    # Mock get_functions for tools that use iteration (graph search)
    acc.get_functions.return_value = iter(MOCK_FUNCTIONS)
    
    # Mock get_strings for read_strings
    acc.get_strings.return_value = iter([{"value": f"str_{i}", "address": "0x00"} for i in range(200)])
    
    return acc

@pytest.mark.parametrize("offset,limit,expected_count", [
    (0, 100, 100),
    (0, 1000, 1000),
    (1400, 200, 100), # Partial last page
    (2000, 100, 0)    # Empty page
])
@patch("src.tools.query.load_data_accessor")
def test_list_functions_pagination(mock_load, mock_accessor, offset, limit, expected_count):
    mock_load.return_value = mock_accessor
    
    res_str = query.list_functions("dummy", offset=offset, limit=limit)
    res = json.loads(res_str)
    
    assert res["data"]["returned_count"] == expected_count
    assert res["data"]["total_functions"] == 1500

@patch("src.tools.metadata.load_data_accessor")
def test_list_imports_pagination(mock_load, mock_accessor):
    mock_load.return_value = mock_accessor
    
    # Test Page 1
    res = json.loads(metadata.list_imports("dummy", offset=0, limit=100))
    assert res["data"]["returned_count"] == 100
    assert res["data"]["total_imports"] == 2500
    
    # Test Page 26
    res = json.loads(metadata.list_imports("dummy", offset=2400, limit=100))
    assert res["data"]["returned_count"] == 100
    assert res["data"]["imports"][0]["name"] == "imp_2400"

@patch("src.tools.graph.load_data_accessor")
def test_get_function_callers_pagination(mock_load, mock_accessor):
    mock_load.return_value = mock_accessor
    # Setup a function with many callers
    target = MOCK_FUNCTIONS[0].copy()
    target["callers"] = [f"parent_{i}" for i in range(150)]
    
    # Use side_effect to return FRESH iterator each call
    mock_accessor.get_functions.side_effect = lambda: iter([target])
    
    # Request first 100
    res = json.loads(graph.get_function_callers("dummy", "func_0", offset=0, limit=100))
    if "error" in res:
        pytest.fail(f"Tool failed: {res}")
        
    assert res["data"]["total_callers"] == 150
    assert res["data"]["returned_count"] == 100
    assert len(res["data"]["callers"]) == 100
    assert res["data"]["callers"][0] == "parent_0"
    
    # Request next 50
    # Update side effect again? No, lambda works.
    res = json.loads(graph.get_function_callers("dummy", "func_0", offset=100, limit=100))
    assert res["data"]["returned_count"] == 50
    assert len(res["data"]["callers"]) == 50
    assert res["data"]["callers"][0] == "parent_100"
