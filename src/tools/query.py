"""
Query tools for Ghidra MCP server.
Functions for querying analyzed binary data.
"""
from ..server import mcp
from ..session import load_json_for_binary
from ..response_utils import make_response, make_error


@mcp.tool()
def list_functions(binary_path: str, limit: int = 300) -> str:
    """List all functions found in the analyzed binary."""
    data = load_json_for_binary(binary_path)
    if not data:
        return make_error(
            "No analysis found. Run 'analyze_binary' first.",
            code="NO_ANALYSIS"
        )

    functions = data.get('functions', [])
    func_list = [
        {"name": f['name'], "address": f['entry']}
        for f in functions[:limit]
    ]

    return make_response(data={
        "binary": binary_path,
        "total_count": len(functions),
        "returned_count": len(func_list),
        "limit": limit,
        "functions": func_list
    })


@mcp.tool()
def read_function_code(binary_path: str, function_name: str) -> str:
    """Decompile and return the C code for a specific function."""
    data = load_json_for_binary(binary_path)
    if not data:
        return make_error(
            "No analysis found. Run 'analyze_binary' first.",
            code="NO_ANALYSIS"
        )

    for f in data.get('functions', []):
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


@mcp.tool()
def read_strings(binary_path: str, min_length: int = 5, limit: int = 100) -> str:
    """Extract strings from the analyzed binary."""
    data = load_json_for_binary(binary_path)
    if not data:
        return make_error(
            "No analysis found. Run 'analyze_binary' first.",
            code="NO_ANALYSIS"
        )

    all_strings = data.get('strings', [])
    filtered = [s for s in all_strings if len(s.get('value', '')) > min_length]
    
    string_list = [
        {"value": s['value'], "address": s.get('address', 'unknown')}
        for s in filtered[:limit]
    ]

    return make_response(data={
        "binary": binary_path,
        "total_count": len(all_strings),
        "filtered_count": len(filtered),
        "returned_count": len(string_list),
        "min_length": min_length,
        "limit": limit,
        "strings": string_list
    })
