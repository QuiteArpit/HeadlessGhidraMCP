"""
Cache management module for Ghidra MCP server.
Handles file hashing, index management, and cache lookups.
"""
import os
import json
import hashlib
from typing import Dict, Any, Optional

from .config import LOGS_DIR, CACHE_DIR, INDEX_FILE


def get_file_hash(filepath: str) -> str:
    """Calculate SHA256 hash of a file (first 16 chars)."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()[:16]
    except FileNotFoundError:
        return "file_not_found"


def load_index() -> Dict[str, Any]:
    """Load the analysis index from disk."""
    if os.path.exists(INDEX_FILE):
        try:
            with open(INDEX_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {"version": "1.0", "binaries": {}}
    return {"version": "1.0", "binaries": {}}


def save_index(index: Dict[str, Any]) -> None:
    """Save the analysis index to disk."""
    os.makedirs(LOGS_DIR, exist_ok=True)
    with open(INDEX_FILE, 'w', encoding='utf-8') as f:
        json.dump(index, f, indent=2)


def get_cached_analysis(file_hash: str) -> Optional[str]:
    """Check if analysis exists in cache. Returns JSON path if found."""
    cache_path = os.path.join(CACHE_DIR, f"{file_hash}.json")
    if os.path.exists(cache_path):
        return cache_path
    return None
