"""
Analysis tools for Ghidra MCP server.
Binary analysis, folder scanning, batch processing.
"""
import os
import glob
from typing import List
from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations

from ..server import mcp
from ..analyzer import analyze_single_binary
from ..response_utils import make_response, make_error


@mcp.tool(annotations=ToolAnnotations(idempotentHint=True))
def analyze_binary(binary_path: str, force: bool = False) -> str:
    """
    Analyzes a binary using Ghidra and saves the results to a JSON file.
    Uses cache if available (set force=True to re-analyze).
    """
    result = analyze_single_binary(binary_path, force)
    
    if "error" in result:
        return make_error(result["error"], code=result.get("code"))
    
    return make_response(data=result)


@mcp.tool(annotations=ToolAnnotations(idempotentHint=True))
def analyze_folder(folder_path: str, extensions: List[str] = None, ctx: Context = None) -> str:
    """
    Analyze all binaries in a folder.
    Default extensions: .exe, .dll, .so, .dylib, .bin, .elf
    """
    if not os.path.isdir(folder_path):
        return make_error(f"Not a directory: {folder_path}", code="NOT_DIRECTORY")

    if extensions is None:
        extensions = [".exe", ".dll", ".so", ".dylib", ".bin", ".elf"]

    # Gather all files first to count total
    all_files = []
    for ext in extensions:
        pattern = os.path.join(folder_path, f"**/*{ext}")
        all_files.extend(glob.glob(pattern, recursive=True))
    
    # Remove duplicates if any extension overlap
    all_files = sorted(list(set(all_files)))
    total_files = len(all_files)

    if ctx:
        ctx.info(f"Found {total_files} files in {folder_path}. Starting analysis...")

    results = {
        "folder": folder_path,
        "analyzed": 0,
        "cached": 0,
        "errors": 0,
        "binaries": []
    }

    for i, file_path in enumerate(all_files):
        if ctx:
            ctx.report_progress(i, total_files)
            ctx.info(f"[{i+1}/{total_files}] Analyzing: {os.path.basename(file_path)}")
            
        result = analyze_single_binary(file_path)
        
        if "error" in result:
            results["errors"] += 1
            results["binaries"].append({
                "name": os.path.basename(file_path),
                "status": "error",
                "error": result["error"]
            })
            if ctx: ctx.error(f"Error analyzing {os.path.basename(file_path)}: {result['error']}")
            
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
            if ctx: ctx.info(f"Finished {result['binary_name']}")

    if ctx:
        ctx.report_progress(total_files, total_files)
        ctx.info(f"Analysis complete. Processed {total_files} files.")

    return make_response(data=results)


@mcp.tool(annotations=ToolAnnotations(idempotentHint=True))
def analyze_binaries(binary_paths: List[str], ctx: Context = None) -> str:
    """Analyze multiple binaries at once."""
    total_files = len(binary_paths)
    if ctx:
        ctx.info(f"Starting batch analysis of {total_files} binaries...")
        
    results = {
        "analyzed": 0,
        "cached": 0,
        "errors": 0,
        "binaries": []
    }

    for i, path in enumerate(binary_paths):
        if ctx:
            ctx.report_progress(i, total_files)
            ctx.info(f"[{i+1}/{total_files}] Analyzing: {os.path.basename(path)}")
            
        result = analyze_single_binary(path)
        
        if "error" in result:
            results["errors"] += 1
            results["binaries"].append({
                "path": path,
                "status": "error",
                "error": result["error"]
            })
            if ctx: ctx.error(f"Error analyzing {os.path.basename(path)}: {result['error']}")
            
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
            if ctx: ctx.info(f"Finished {result['binary_name']}")
    
    if ctx:
        ctx.report_progress(total_files, total_files)
        ctx.info("Batch analysis complete.")

    return make_response(data=results)
