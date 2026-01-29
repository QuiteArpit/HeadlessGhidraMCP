"""
Metadata tools for Ghidra MCP server.
Functions for querying Imports and Exports.
"""
from mcp.types import ToolAnnotations
from ..server import mcp
from ..session import load_data_accessor
from ..response_utils import make_response, make_error


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def list_imports(binary_path: str, offset: int = 0, limit: int = 1000) -> str:
    """List imported libraries and functions."""
    acc = load_data_accessor(binary_path)
    if not acc:
        return make_error(
            "No analysis found. Run 'analyze_binary' first.",
            code="NO_ANALYSIS"
        )
    
    # Imports can be numerous, support pagination
    # Slice the raw list first
    imports_slice = acc.slice_items('imports', offset, limit)
    total_imports = acc.get_count('imports')
    
    # Group by library for cleaner output (of the current page)
    grouped = {}
    for imp in imports_slice:
        lib = imp.get('library', 'Unknown')
        if lib not in grouped:
            grouped[lib] = []
        grouped[lib].append(imp['name'])

    return make_response(data={
        "binary": binary_path,
        "total_imports": total_imports,
        "returned_count": len(imports_slice),
        "offset": offset,
        "limit": limit,
        "libraries": list(grouped.keys()),
        "imports_by_library": grouped,
        # "raw_imports" removed as it's redundant if we have grouped, or we can keep it for machine readability
        # Let's keep distinct list for machines
        "imports": imports_slice 
    })


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def list_exports(binary_path: str, offset: int = 0, limit: int = 1000) -> str:
    """List exported functions (entry points)."""
    acc = load_data_accessor(binary_path)
    if not acc:
        return make_error(
            "No analysis found. Run 'analyze_binary' first.",
            code="NO_ANALYSIS"
        )

    exports_slice = acc.slice_items('exports', offset, limit)
    total_exports = acc.get_count('exports')
    
    return make_response(data={
        "binary": binary_path,
        "total_exports": total_exports,
        "returned_count": len(exports_slice),
        "offset": offset,
        "limit": limit,
        "exports": exports_slice
    })
