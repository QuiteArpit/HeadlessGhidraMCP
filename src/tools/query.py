"""
Query tools for Ghidra MCP server.
Functions for querying analyzed binary data.
"""
from itertools import islice
from mcp.types import ToolAnnotations
from ..server import mcp
from ..session import load_data_accessor
from ..response_utils import make_response, make_error


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def list_functions(binary_path: str, offset: int = 0, limit: int = 1000) -> str:
    """List all functions found in the analyzed binary."""
    acc = load_data_accessor(binary_path)
    if not acc:
        return make_error(
            "No analysis found. Run 'analyze_binary' first.",
            code="NO_ANALYSIS"
        )

    # Use slice_items (paginated access)
    functions = acc.slice_items('functions', offset, limit)
    total_estimated = acc.get_count('functions')
    
    func_list = [
        {"name": f['name'], "address": f['entry']}
        for f in functions
    ]

    return make_response(data={
        "binary": binary_path,
        "total_functions": total_estimated,
        "returned_count": len(func_list),
        "offset": offset,
        "limit": limit,
        "functions": func_list
    })


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def read_function_code(binary_path: str, function_name: str) -> str:
    """Decompile and return the C code for a specific function."""
    acc = load_data_accessor(binary_path)
    if not acc:
        return make_error(
            "No analysis found. Run 'analyze_binary' first.",
            code="NO_ANALYSIS"
        )

    for f in acc.get_functions():
        if f['name'] == function_name:
            return make_response(data={
                "binary": binary_path,
                "function_name": function_name,
                "address": f.get('entry', 'unknown'),
                "decompiled_code": f['code']
            })

    return make_error(
        f"Function '{function_name}' not found.",
        code="FUNCTION_NOT_FOUND"
    )


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def read_strings(binary_path: str, min_length: int = 5, offset: int = 0, limit: int = 1000) -> str:
    """Extract strings from the analyzed binary."""
    acc = load_data_accessor(binary_path)
    if not acc:
        return make_error(
            "No analysis found. Run 'analyze_binary' first.",
            code="NO_ANALYSIS"
        )

    # Filter generator
    filtered_strings = (
        {
            "value": s['value'], 
            "address": s.get('address', 'unknown')
        }
        for s in acc.get_strings()
        if len(s.get('value', '')) > min_length
    )
    
    # Paginate filtered results
    page_items = list(islice(filtered_strings, offset, offset + limit))
                
    return make_response(data={
        "binary": binary_path,
        "returned_count": len(page_items),
        "min_length": min_length,
        "offset": offset,
        "limit": limit,
        "strings": page_items
    })
