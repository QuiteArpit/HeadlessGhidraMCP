"""
Query tools for Ghidra MCP server.
Functions for querying analyzed binary data.
"""
from itertools import islice
from ..server import mcp
from ..session import load_data_accessor
from ..response_utils import make_response, make_error


@mcp.tool()
def list_functions(binary_path: str, limit: int = 300) -> str:
    """List all functions found in the analyzed binary."""
    acc = load_data_accessor(binary_path)
    if not acc:
        return make_error(
            "No analysis found. Run 'analyze_binary' first.",
            code="NO_ANALYSIS"
        )

    # Use islice for efficient streaming limit
    # Note: total_count might not be available accurately in streaming mode without full scan
    # But usually session metadata has 'functions' count!
    # acc._cached_data might be None. session info has the count.
    # We can get total count from session.get_from_session(binary_path) if needed, 
    # but let's just return what we have or accept that total_count is nice-to-have.
    # Actually, session metadata DOES store function count. Let's assume we can get it from there if we really want,
    # or just omit it / set to -1 if unknown in stream.
    # For now, let's just grab the items.
    
    func_iter = acc.get_functions()
    limited_funcs = list(islice(func_iter, limit))
    
    func_list = [
        {"name": f['name'], "address": f['entry']}
        for f in limited_funcs
    ]

    return make_response(data={
        "binary": binary_path,
        "returned_count": len(func_list),
        "limit": limit,
        "functions": func_list
    })


@mcp.tool()
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


@mcp.tool()
def read_strings(binary_path: str, min_length: int = 5, limit: int = 100) -> str:
    """Extract strings from the analyzed binary."""
    acc = load_data_accessor(binary_path)
    if not acc:
        return make_error(
            "No analysis found. Run 'analyze_binary' first.",
            code="NO_ANALYSIS"
        )

    # Streaming filter
    string_iter = acc.get_strings()
    
    # We need to filter by length AND limit count.
    # itertools.islice consumes, so we filter first.
    filtered_strings = []
    count = 0
    
    for s in string_iter:
        if len(s.get('value', '')) > min_length:
            filtered_strings.append({
                "value": s['value'], 
                "address": s.get('address', 'unknown')
            })
            count += 1
            if count >= limit:
                break
                
    return make_response(data={
        "binary": binary_path,
        "returned_count": len(filtered_strings),
        "min_length": min_length,
        "limit": limit,
        "strings": filtered_strings
    })
