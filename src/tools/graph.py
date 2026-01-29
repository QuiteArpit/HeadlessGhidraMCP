"""
Graph/XRef tools for Ghidra MCP server.
Functions for querying function call graphs.
"""
from typing import List, Dict, Any
from ..server import mcp
from ..session import load_json_for_binary
from ..response_utils import make_response, make_error


@mcp.tool()
def get_function_callers(binary_path: str, function_name: str) -> str:
    """
    Get list of functions that call the specified function.
    Returns direct callers (parents).
    """
    data = load_json_for_binary(binary_path)
    if not data:
        return make_error(
            "No analysis found. Run 'analyze_binary' first.",
            code="NO_ANALYSIS"
        )

    target_func = None
    for f in data.get('functions', []):
        if f['name'] == function_name:
            target_func = f
            break
    
    if not target_func:
        return make_error(
            f"Function '{function_name}' not found.",
            code="FUNCTION_NOT_FOUND"
        )

    callers = target_func.get('callers', [])
    
    return make_response(data={
        "binary": binary_path,
        "function": function_name,
        "caller_count": len(callers),
        "callers": callers
    })


@mcp.tool()
def get_function_callees(binary_path: str, function_name: str) -> str:
    """
    Get list of functions called by the specified function.
    Returns direct callees (children).
    """
    data = load_json_for_binary(binary_path)
    if not data:
        return make_error(
            "No analysis found. Run 'analyze_binary' first.",
            code="NO_ANALYSIS"
        )

    target_func = None
    for f in data.get('functions', []):
        if f['name'] == function_name:
            target_func = f
            break
    
    if not target_func:
        return make_error(
            f"Function '{function_name}' not found.",
            code="FUNCTION_NOT_FOUND"
        )

    callees = target_func.get('callees', [])
    
    return make_response(data={
        "binary": binary_path,
        "function": function_name,
        "callee_count": len(callees),
        "callees": callees
    })
