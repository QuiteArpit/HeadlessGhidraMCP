"""
Session management module for Ghidra MCP server.
Tracks currently loaded binaries in memory.
"""
import os
import json
import ijson # type: ignore
from typing import Dict, Any, Optional, Iterator, Union, List
from collections import OrderedDict
from itertools import islice

from .config import GHIDRA_SESSION_SIZE, GHIDRA_STREAMING_THRESHOLD_MB

# Session Cache: LRU via OrderedDict directly
_session_context: OrderedDict[str, Dict[str, Any]] = OrderedDict()


class DataAccessor:
    """
    Abstracts access to analysis data (JSON).
    Handles switching between In-Memory Dict (Fast) and Streaming (Low RAM).
    """
    def __init__(self, json_path: str):
        self.json_path = json_path
        self.file_size_mb = os.path.getsize(json_path) / (1024 * 1024)
        self.use_streaming = self.file_size_mb > GHIDRA_STREAMING_THRESHOLD_MB
        self._cached_data = None

    def _ensure_loaded(self):
        if not self.use_streaming and self._cached_data is None:
            with open(self.json_path, 'r', encoding='utf-8') as f:
                self._cached_data = json.load(f)

    def get_functions(self) -> Iterator[Dict[str, Any]]:
        if self.use_streaming:
            # Re-open file for streaming scan
            f = open(self.json_path, 'rb')
            return ijson.items(f, 'functions.item')
        else:
            self._ensure_loaded()
            return iter(self._cached_data.get('functions', []))

    def get_strings(self) -> Iterator[Dict[str, Any]]:
        if self.use_streaming:
            f = open(self.json_path, 'rb')
            return ijson.items(f, 'strings.item')
        else:
            self._ensure_loaded()
            return iter(self._cached_data.get('strings', []))
            
    def get_imports(self) -> List[Dict[str, Any]]:
        # Metadata usually small enough to load fully or stream quickly
        if self.use_streaming:
             with open(self.json_path, 'rb') as f:
                return list(ijson.items(f, 'imports.item'))
        else:
            self._ensure_loaded()
            return self._cached_data.get('imports', [])

    def get_exports(self) -> List[Dict[str, Any]]:
        self._ensure_loaded()
        if self._cached_data:
            return self._cached_data.get('exports', [])
        
        # Fallback for streaming (though exports usually small)
        with open(self.json_path, 'rb') as f:
            return list(ijson.items(f, 'exports.item'))

    def slice_items(self, key: str, offset: int, limit: int) -> List[Dict[str, Any]]:
        """
        Get a specific slice of a list (Pagination).
        """
        if self.use_streaming:
            with open(self.json_path, 'rb') as f:
                # ijson iterator
                iterator = ijson.items(f, f'{key}.item')
                # efficent slice without loading everything
                return list(islice(iterator, offset, offset + limit))
        else:
            self._ensure_loaded()
            data_list = self._cached_data.get(key, [])
            return data_list[offset : offset + limit]

    def get_count(self, key: str) -> int:
        """Get total count of items for a key."""
        if not self.use_streaming:
            self._ensure_loaded()
            return len(self._cached_data.get(key, []))
        
        # For streaming, we might have it cached in session context (functions/strings)
        # But DataAccessor doesn't know about session context directly.
        # We'll rely on the caller to provide totals if available, 
        # or fallback to counting (expensive) if needed.
        # However, for 'imports'/'exports' it's fast enough.
        # For 'functions', the caller usually has it from session info.
        # If we absolutely must count:
        with open(self.json_path, 'rb') as f:
            return sum(1 for _ in ijson.items(f, f'{key}.item'))


def add_to_session(binary_path: str, file_hash: str, json_path: str, 
                   functions: int, strings: int) -> None:
    """Add a binary to the current session (LRU)."""
    if binary_path in _session_context:
        _session_context.move_to_end(binary_path)
    
    _session_context[binary_path] = {
        "hash": file_hash,
        "json_path": json_path,
        "functions": functions,
        "strings": strings
    }
    
    # Enforce LRU Limit
    if len(_session_context) > GHIDRA_SESSION_SIZE:
        _session_context.popitem(last=False) # Remove oldest


def get_from_session(binary_path: str) -> Optional[Dict[str, Any]]:
    """Get session info for a binary."""
    if binary_path in _session_context:
        _session_context.move_to_end(binary_path) # Mark used
        return _session_context[binary_path]
    return None


def get_all_session_binaries() -> Dict[str, Dict[str, Any]]:
    """Get all binaries in the session."""
    return dict(_session_context)


def clear_session_data() -> int:
    """Clear all binaries from session. Returns count cleared."""
    count = len(_session_context)
    _session_context.clear()
    return count


def load_data_accessor(binary_path: str) -> Optional[DataAccessor]:
    """Get a DataAccessor for the binary."""
    info = get_from_session(binary_path)
    if not info:
        return None
    
    json_path = info["json_path"]
    if not os.path.exists(json_path):
        return None
        
    return DataAccessor(json_path)

# Legacy compatibility helper (Deprecated but keeps existing tests alive for now)
def load_json_for_binary(binary_path: str) -> Optional[Dict[str, Any]]:
    acc = load_data_accessor(binary_path)
    if not acc: return None
    # Force load for legacy calls
    acc._ensure_loaded()
    return acc._cached_data if acc._cached_data else None
