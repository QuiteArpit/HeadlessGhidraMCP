"""
System tools for Ghidra MCP server.
Health checks, session management, diagnostics.
"""
import os

from ..server import mcp
from ..config import GHIDRA_HEADLESS_PATH, SCRIPT_DIR, LOGS_DIR
from ..cache import load_index
from ..session import get_all_session_binaries, clear_session_data
from ..platform_utils import get_platform_info
from ..response_utils import make_response, make_error


@mcp.tool()
def health_check() -> str:
    """
    Check MCP server status, Ghidra installation, and platform info.
    Use this to diagnose configuration issues.
    """
    ghidra_found = GHIDRA_HEADLESS_PATH is not None and os.path.exists(GHIDRA_HEADLESS_PATH)
    scripts_found = os.path.exists(SCRIPT_DIR)
    
    # Load index for cached count
    index = load_index()
    cached_count = len(index.get("binaries", {}))
    session_binaries = get_all_session_binaries()
    
    response_data = {
        "platform": get_platform_info(),
        "ghidra_path": GHIDRA_HEADLESS_PATH,
        "ghidra_found": ghidra_found,
        "scripts_dir": SCRIPT_DIR,
        "scripts_found": scripts_found,
        "output_dir": LOGS_DIR,
        "session_binaries": len(session_binaries),
        "cached_binaries": cached_count
    }
    
    if not ghidra_found:
        return make_error("Ghidra not found", code="GHIDRA_NOT_FOUND")
    
    return make_response(data=response_data)


@mcp.tool()
def list_session_binaries() -> str:
    """List all binaries currently loaded in the session."""
    session = get_all_session_binaries()
    binaries = []
    
    for path, info in session.items():
        binaries.append({
            "path": path,
            "name": os.path.basename(path),
            "hash": info["hash"],
            "functions": info["functions"],
            "strings": info["strings"]
        })

    return make_response(data={
        "count": len(binaries),
        "binaries": binaries
    })


@mcp.tool()
def clear_session() -> str:
    """Clear the current session (does not delete cached files)."""
    count = clear_session_data()
    return make_response(data={
        "cleared": count,
        "message": f"Cleared {count} binaries from session"
    })
