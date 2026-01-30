"""
MCP Server module for Ghidra Analyst.
Creates the FastMCP instance and imports all tools.
"""
from mcp.server.fastmcp import FastMCP

# Create the MCP server instance - available for tools to import
mcp = FastMCP("Ghidra Analyst")


def _register_tools():
    """Import tools to register them with MCP. Deferred to avoid circular import."""
    from .tools import analysis, query, system, graph, metadata, inspection  # noqa: F401


def main():
    """Entry point for ghidra-mcp command."""
    _register_tools()
    mcp.run()


# Allow importing mcp from this module
__all__ = ["mcp", "main"]
