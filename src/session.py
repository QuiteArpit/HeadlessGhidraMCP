"""
Session management module for Ghidra MCP server.
Tracks currently loaded binaries in memory.
"""
import os
import json
from typing import Dict, Any, Optional


# Session Cache: {binary_path: {"hash": str, "json_path": str, "functions": int, "strings": int}}
_session_context: Dict[str, Dict[str, Any]] = {}


def add_to_session(binary_path: str, file_hash: str, json_path: str, 
                   functions: int, strings: int) -> None:
    """Add a binary to the current session."""
    _session_context[binary_path] = {
        "hash": file_hash,
        "json_path": json_path,
        "functions": functions,
        "strings": strings
    }


def get_from_session(binary_path: str) -> Optional[Dict[str, Any]]:
    """Get session info for a binary."""
    return _session_context.get(binary_path)


def get_all_session_binaries() -> Dict[str, Dict[str, Any]]:
    """Get all binaries in the session."""
    return _session_context.copy()


def clear_session_data() -> int:
    """Clear all binaries from session. Returns count cleared."""
    count = len(_session_context)
    _session_context.clear()
    return count


def load_json_for_binary(binary_path: str) -> Optional[Dict[str, Any]]:
    """Load cached analysis JSON for a binary in session."""
    info = _session_context.get(binary_path)
    if not info:
        return None
    
    json_path = info["json_path"]
    if not os.path.exists(json_path):
        return None
    
    with open(json_path, 'r', encoding='utf-8') as f:
        return json.load(f)
