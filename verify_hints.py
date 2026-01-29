import sys
from src.server import mcp, _register_tools

# Force registration
_register_tools()

print("Verifying Tool Annotations...")
# Skip internal access, use async check below
# Tool has .name and .annotations
import asyncio
from mcp.types import Tool

async def check():
    tools = await mcp.list_tools()
    # FastMCP.list_tools() returns a list of Tool objects directly?
    # Or maybe it depends on the library version.
    # If it is a list, iterate it.
    iterable = tools.tools if hasattr(tools, 'tools') else tools
    
    for t in iterable:
        print(f"Tool: {t.name}")
        if t.annotations:
            print(f"  Annotations: {t.annotations}")
        else:
            print("  Annotations: None")

asyncio.run(check())
