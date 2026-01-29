"""
Graph/XRef tools for Ghidra MCP server.
Functions for querying function call graphs.
"""
from typing import List, Dict, Any
from mcp.types import ToolAnnotations
from ..server import mcp
from ..session import load_data_accessor
from ..response_utils import make_response, make_error


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_function_callers(binary_path: str, function_name: str, offset: int = 0, limit: int = 1000) -> str:
    """
    Get list of functions that call the specified function.
    Returns direct callers (parents).
    """
    acc = load_data_accessor(binary_path)
    if not acc:
        return make_error(
            "No analysis found. Run 'analyze_binary' first.",
            code="NO_ANALYSIS"
        )

    target_func = None
    # Support streaming iterator
    for f in acc.get_functions():
        if f['name'] == function_name:
            target_func = f
            break
    
    if not target_func:
        return make_error(
            f"Function '{function_name}' not found.",
            code="FUNCTION_NOT_FOUND"
        )

    callers = target_func.get('callers', [])
    total_count = len(callers)
    paginated_callers = callers[offset : offset + limit]
    
    return make_response(data={
        "binary": binary_path,
        "function": function_name,
        "total_callers": total_count,
        "returned_count": len(paginated_callers),
        "offset": offset,
        "limit": limit,
        "callers": paginated_callers
    })


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_function_callees(binary_path: str, function_name: str, offset: int = 0, limit: int = 1000) -> str:
    """
    Get list of functions called by the specified function.
    Returns direct callees (children).
    """
    acc = load_data_accessor(binary_path)
    if not acc:
        return make_error(
            "No analysis found. Run 'analyze_binary' first.",
            code="NO_ANALYSIS"
        )

    target_func = None
    for f in acc.get_functions():
        if f['name'] == function_name:
            target_func = f
            break
    
    if not target_func:
        return make_error(
            f"Function '{function_name}' not found.",
            code="FUNCTION_NOT_FOUND"
        )

    callees = target_func.get('callees', [])
    total_count = len(callees)
    paginated_callees = callees[offset : offset + limit]
    
    return make_response(data={
        "binary": binary_path,
        "function": function_name,
        "total_callees": total_count,
        "returned_count": len(paginated_callees),
        "offset": offset,
        "limit": limit,
        "callees": paginated_callees
    })
