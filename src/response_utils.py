"""
Response utilities for standardized MCP responses.
All tools should return JSON in a consistent format.
"""
import json
import time
from typing import Any, Optional


def make_response(
    status: str = "success",
    data: Optional[dict] = None,
    error: Optional[str] = None
) -> str:
    """
    Create a standardized JSON response for MCP tools.
    
    Args:
        status: "success" or "error"
        data: Tool-specific payload (for success responses)
        error: Error message (for error responses)
    
    Returns:
        JSON string in standard format
    """
    response = {"status": status}
    
    if status == "error":
        response["error"] = error or "Unknown error"
    elif data is not None:
        response["data"] = data
    
    return json.dumps(response, indent=2)


def make_error(error: str, code: Optional[str] = None) -> str:
    """
    Create a standardized error response.
    
    Args:
        error: Human-readable error message
        code: Optional error code for programmatic handling
    """
    response = {
        "status": "error",
        "error": error
    }
    if code:
        response["error_code"] = code
    
    return json.dumps(response, indent=2)


class Timer:
    """Context manager for timing operations."""
    
    def __init__(self):
        self.start_time = None
        self.elapsed_ms = 0
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, *args):
        self.elapsed_ms = int((time.time() - self.start_time) * 1000)
