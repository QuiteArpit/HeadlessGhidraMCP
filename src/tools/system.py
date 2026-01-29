"""
System tools for Ghidra MCP server.
Health checks, session management, diagnostics.
"""
import os
from mcp.types import ToolAnnotations

from ..server import mcp
from ..config import GHIDRA_HEADLESS_PATH, SCRIPT_DIR, LOGS_DIR
from ..cache import load_index
from ..session import get_all_session_binaries, clear_session_data
from ..platform_utils import get_platform_info
from ..response_utils import make_response, make_error


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
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


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def list_session_binaries() -> str:
    """List all binaries currently loaded in the session."""
    session = get_all_session_binaries()
    binaries = []
    
    for path, info in session.items():
        # Helper to get counts safely (handle legacy structure if any)
        counts = info.get("counts", {})
        if not counts:
            # Fallback for old structure
            counts = {
                "functions": info.get("functions", 0),
                "strings": info.get("strings", 0)
            }
            
        binaries.append({
            "path": path,
            "name": os.path.basename(path),
            "hash": info["hash"],
            "functions": counts.get("functions", 0),
            "strings": counts.get("strings", 0)
        })

    return make_response(data={
        "count": len(binaries),
        "binaries": binaries
    })


@mcp.tool(annotations=ToolAnnotations(destructiveHint=True))
def clear_session() -> str:
    """Clear the current session (does not delete cached files)."""
    count = clear_session_data()
    return make_response(data={
        "cleared": count,
        "message": f"Cleared {count} binaries from session"
    })


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def scan_folder(folder_path: str) -> str:
    """
    List files in a directory with basic metadata (Size, Type).
    Useful for scouting before analyzing.
    """
    # 1. Security Check
    # We import here to avoid circular dependencies if any (though currently safe)
    from ..analyzer import validate_path
    
    # Check if folder itself is accessible
    # validate_path checks if path is within SAFE_DIR
    safety_check = validate_path(folder_path)
    if safety_check:
        return make_error(safety_check["error"], code=safety_check["code"])

    if not os.path.isdir(folder_path):
        return make_error(f"Not a directory: {folder_path}", code="NOT_DIRECTORY")

    files = []
    try:
        with os.scandir(folder_path) as it:
            for entry in it:
                if entry.name.startswith('.'): continue
                
                info = {
                    "name": entry.name,
                    "is_dir": entry.is_dir(),
                    "size_bytes": entry.stat().st_size if entry.is_file() else 0
                }
                
                # Basic Magic Byte Check for Files
                if entry.is_file():
                    try:
                        with open(entry.path, 'rb') as f:
                            header = f.read(4)
                            info['magic'] = header.hex()
                            if header.startswith(b'MZ'):
                                info['type'] = 'PE (Windows)'
                            elif header.startswith(b'\x7fELF'):
                                info['type'] = 'ELF (Linux)'
                            elif header.startswith(b'\xca\xfe\xba\xbe') or header.startswith(b'\xfe\xed\xfa\xce'):
                                info['type'] = 'Mach-O (Mac)'
                            else:
                                info['type'] = 'Unknown'
                    except Exception:
                        info['magic'] = 'error'
                        info['type'] = 'Unreadable'
                
                files.append(info)
                
    except PermissionError:
        return make_error("Permission denied scanning folder", code="PERMISSION_DENIED")
        
    # Sort: Directories first, then files
    files.sort(key=lambda x: (not x['is_dir'], x['name']))

    return make_response(data={
        "folder": folder_path,
        "count": len(files),
        "items": files
    })
