"""
Metadata tools for Ghidra MCP server.
Functions for querying Imports and Exports.
"""
from ..server import mcp
from ..session import load_json_for_binary
from ..response_utils import make_response, make_error


@mcp.tool()
def list_imports(binary_path: str) -> str:
    """List imported libraries and functions."""
    data = load_json_for_binary(binary_path)
    if not data:
        return make_error(
            "No analysis found. Run 'analyze_binary' first.",
            code="NO_ANALYSIS"
        )

    imports = data.get('imports', [])
    
    # Group by library for cleaner output
    grouped = {}
    for imp in imports:
        lib = imp.get('library', 'Unknown')
        if lib not in grouped:
            grouped[lib] = []
        grouped[lib].append(imp['name'])

    return make_response(data={
        "binary": binary_path,
        "total_imports": len(imports),
        "libraries": list(grouped.keys()),
        "imports_by_library": grouped,
        "raw_imports": imports if len(imports) < 500 else "Too many to list raw, see grouped"
    })


@mcp.tool()
def list_exports(binary_path: str) -> str:
    """List exported functions (entry points)."""
    data = load_json_for_binary(binary_path)
    if not data:
        return make_error(
            "No analysis found. Run 'analyze_binary' first.",
            code="NO_ANALYSIS"
        )

    exports = data.get('exports', [])
    
    return make_response(data={
        "binary": binary_path,
        "total_exports": len(exports),
        "exports": exports
    })
