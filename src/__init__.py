"""
HeadlessGhidraMCP - MCP server for Ghidra-based binary analysis.
"""
from .server import mcp, main
from .platform_utils import find_ghidra_path, get_platform_info

__version__ = "1.1.0"
__all__ = ["mcp", "main", "find_ghidra_path", "get_platform_info"]
