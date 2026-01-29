"""
Analysis tools for Ghidra MCP server.
Binary analysis, folder scanning, batch processing.
"""
import os
import glob
from typing import List

from ..server import mcp
from ..analyzer import analyze_single_binary
from ..response_utils import make_response, make_error


@mcp.tool()
def analyze_binary(binary_path: str, force: bool = False) -> str:
    """
    Analyzes a binary using Ghidra and saves the results to a JSON file.
    Uses cache if available (set force=True to re-analyze).
    """
    result = analyze_single_binary(binary_path, force)
    
    if "error" in result:
        return make_error(result["error"], code=result.get("code"))
    
    return make_response(data=result)


@mcp.tool()
def analyze_folder(folder_path: str, extensions: List[str] = None) -> str:
    """
    Analyze all binaries in a folder.
    Default extensions: .exe, .dll, .so, .dylib, .bin, .elf
    """
    if not os.path.isdir(folder_path):
        return make_error(f"Not a directory: {folder_path}", code="NOT_DIRECTORY")

    if extensions is None:
        extensions = [".exe", ".dll", ".so", ".dylib", ".bin", ".elf"]

    results = {
        "folder": folder_path,
        "analyzed": 0,
        "cached": 0,
        "errors": 0,
        "binaries": []
    }

    for ext in extensions:
        pattern = os.path.join(folder_path, f"**/*{ext}")
        for file_path in glob.glob(pattern, recursive=True):
            result = analyze_single_binary(file_path)
            
            if "error" in result:
                results["errors"] += 1
                results["binaries"].append({
                    "name": os.path.basename(file_path),
                    "status": "error",
                    "error": result["error"]
                })
            elif result.get("status") == "cached":
                results["cached"] += 1
                results["binaries"].append({
                    "name": result["binary_name"],
                    "status": "cached",
                    "functions": result["functions_count"]
                })
            else:
                results["analyzed"] += 1
                results["binaries"].append({
                    "name": result["binary_name"],
                    "status": "analyzed",
                    "functions": result["functions_count"]
                })

    return make_response(data=results)


@mcp.tool()
def analyze_binaries(binary_paths: List[str]) -> str:
    """Analyze multiple binaries at once."""
    results = {
        "analyzed": 0,
        "cached": 0,
        "errors": 0,
        "binaries": []
    }

    for path in binary_paths:
        result = analyze_single_binary(path)
        
        if "error" in result:
            results["errors"] += 1
            results["binaries"].append({
                "path": path,
                "status": "error",
                "error": result["error"]
            })
        elif result.get("status") == "cached":
            results["cached"] += 1
            results["binaries"].append({
                "path": path,
                "name": result["binary_name"],
                "status": "cached",
                "functions": result["functions_count"]
            })
        else:
            results["analyzed"] += 1
            results["binaries"].append({
                "path": path,
                "name": result["binary_name"],
                "status": "analyzed",
                "functions": result["functions_count"]
            })

    return make_response(data=results)
