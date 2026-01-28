"""
HeadlessGhidraMCP - MCP server for Ghidra-based binary analysis.
"""
from .ghidra_mcp import mcp
from .platform_utils import find_ghidra_path, get_platform_info

__version__ = "1.0.0"
__all__ = ["mcp", "find_ghidra_path", "get_platform_info"]
