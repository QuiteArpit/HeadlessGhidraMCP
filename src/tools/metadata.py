"""
Metadata tools for Ghidra MCP server.
Functions for querying Imports and Exports.
"""
from ..server import mcp
from ..session import load_data_accessor
from ..response_utils import make_response, make_error


@mcp.tool()
def list_imports(binary_path: str) -> str:
    """List imported libraries and functions."""
    acc = load_data_accessor(binary_path)
    if not acc:
        return make_error(
            "No analysis found. Run 'analyze_binary' first.",
            code="NO_ANALYSIS"
        )

    imports = acc.get_imports()
    
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
    acc = load_data_accessor(binary_path)
    if not acc:
        return make_error(
            "No analysis found. Run 'analyze_binary' first.",
            code="NO_ANALYSIS"
        )

    exports = acc.get_exports()
    
    return make_response(data={
        "binary": binary_path,
        "total_exports": len(exports),
        "exports": exports
    })
