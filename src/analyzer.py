"""
Core analysis logic for Ghidra MCP server.
Handles the actual Ghidra invocation and data extraction.
"""
import os
import subprocess
import json
import shutil
from typing import Dict, Any

from .config import (
    BASE_DIR, SCRIPT_DIR, PROJECTS_DIR, CACHE_DIR,
    GHIDRA_HEADLESS_PATH, GHIDRA_SAFE_DIR
)
from .cache import get_file_hash, get_cached_analysis, load_index, save_index
from .session import add_to_session
from .platform_utils import get_platform_info
from .response_utils import Timer


def validate_path(binary_path: str) -> Dict[str, Any]:
    """
    Validate that the binary path is safe to access.
    Returns error dict if invalid, None if valid.
    """
    try:
        abs_path = os.path.abspath(binary_path)
        
        # 1. Existence check
        if not os.path.exists(abs_path):
            return {"error": f"File not found: {binary_path}", "code": "FILE_NOT_FOUND"}
            
        # 2. Security Check (if GHIDRA_SAFE_DIR is set)
        if GHIDRA_SAFE_DIR:
            safe_dir = os.path.abspath(GHIDRA_SAFE_DIR)
            # Resolve symlinks for strict security
            real_binary = os.path.realpath(abs_path)
            real_safe = os.path.realpath(safe_dir)
            
            # Use pathlib for clean 'is_relative_to' logic, or string startswith
            # String check is robust if we ensure trailing slash logic or strict dir containment
            if not real_binary.startswith(real_safe) or real_binary == real_safe:
                return {
                    "error": f"Security Violation: Access denied to {binary_path}. Must be within {GHIDRA_SAFE_DIR}",
                    "code": "SECURITY_VIOLATION"
                }
                
        return None
    except Exception as e:
        return {"error": f"Path validation error: {str(e)}", "code": "PATH_ERROR"}


def analyze_single_binary(binary_path: str, force: bool = False) -> Dict[str, Any]:
    """
    Internal function to analyze a single binary.
    Returns dict with status, data, or error.
    """
    # Security & Existence Check
    validation_error = validate_path(binary_path)
    if validation_error:
        return validation_error

    # Get file hash
    binary_path = os.path.abspath(binary_path) # Use abspath for consistency
    file_hash = get_file_hash(binary_path)
    binary_name = os.path.basename(binary_path)

    # Check cache first (unless force=True)
    if not force:
        cached_path = get_cached_analysis(file_hash)
        if cached_path:
            try:
                with open(cached_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Add to session
                add_to_session(
                    binary_path, file_hash, cached_path,
                    len(data.get('functions', [])),
                    len(data.get('strings', [])),
                    len(data.get('imports', [])),
                    len(data.get('exports', []))
                )
                
                return {
                    "status": "cached",
                    "binary": binary_path,
                    "binary_name": binary_name,
                    "binary_hash": file_hash,
                    "output_path": os.path.relpath(cached_path, BASE_DIR),
                    "functions_count": len(data.get('functions', [])),
                    "strings_count": len(data.get('strings', [])),
                    "analysis_time_ms": 0
                }
            except (json.JSONDecodeError, IOError):
                pass  # Cache corrupted, re-analyze

    # Check Ghidra path
    if not GHIDRA_HEADLESS_PATH or not os.path.exists(GHIDRA_HEADLESS_PATH):
        platform_info = get_platform_info()
        return {
            "error": f"Ghidra not found. Platform: {platform_info['os']}.",
            "code": "GHIDRA_NOT_FOUND"
        }

    # Ensure directories exist
    os.makedirs(PROJECTS_DIR, exist_ok=True)
    os.makedirs(CACHE_DIR, exist_ok=True)

    # Project directory for this binary
    proj_dir = os.path.join(PROJECTS_DIR, file_hash)
    proj_name = f"proj_{file_hash}"
    
    # Clean verification: If force=True, remove existing project to ensure fresh analysis
    if force and os.path.exists(proj_dir):
        shutil.rmtree(proj_dir, ignore_errors=True)
    
    os.makedirs(proj_dir, exist_ok=True)

    cmd = [
        GHIDRA_HEADLESS_PATH,
        proj_dir,
        proj_name,
        "-import", binary_path,
        "-scriptPath", SCRIPT_DIR,
        "-postScript", "GhidraDataDump.java",
        "-analysisTimeoutPerFile", "600"
    ]

    env = os.environ.copy()
    env["GHIDRA_ANALYSIS_OUTPUT"] = CACHE_DIR

    with Timer() as timer:
        try:
            result = subprocess.run(
                cmd,
                env=env,
                check=False,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace'
            )

            # Find generated JSON path
            generated_json_path = None
            for line in result.stdout.splitlines():
                if "GHIDRA_JSON_GENERATED:" in line:
                    raw_path = line.split("GHIDRA_JSON_GENERATED:")[1].strip()
                    # Remove potential Ghidra log suffixes like "(GhidraScript)"
                    if " (" in raw_path:
                        raw_path = raw_path.split(" (")[0]
                    generated_json_path = raw_path.strip('"').strip("'")
                    break

            # If analysis failed to generate output, return error with details
            if not generated_json_path:
                return {
                    "error": "Analysis failed. No JSON output.", 
                    "code": "ANALYSIS_FAILED",
                    "details": {
                        "stdout_tail": result.stdout[-1000:] if result.stdout else "",
                        "stderr_tail": result.stderr[-1000:] if result.stderr else ""
                    }
                }
            
            if not os.path.exists(generated_json_path):
                 return {
                    "error": f"JSON output missing at: {generated_json_path}",
                     "code": "FILE_MISSING"
                 }

            # Rename to hash-based name for caching
            cache_path = os.path.join(CACHE_DIR, f"{file_hash}.json")
            if generated_json_path != cache_path:
                shutil.move(generated_json_path, cache_path)
            
            # Load data
            with open(cache_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Update index
            index = load_index()
            index["binaries"][file_hash] = {
                "name": binary_name,
                "path": binary_path,
                "functions": len(data.get('functions', [])),
                "strings": len(data.get('strings', [])),
                "imports": len(data.get('imports', [])),
                "exports": len(data.get('exports', []))
            }
            save_index(index)

            # Add to session
            add_to_session(
                binary_path, file_hash, cache_path,
                len(data.get('functions', [])),
                len(data.get('strings', [])),
                len(data.get('imports', [])),
                len(data.get('exports', []))
            )

            return {
                "status": "analyzed",
                "binary": binary_path,
                "binary_name": binary_name,
                "binary_hash": file_hash,
                "output_path": os.path.relpath(cache_path, BASE_DIR),
                "functions_count": len(data.get('functions', [])),
                "strings_count": len(data.get('strings', [])),
                "imports_count": len(data.get('imports', [])),
                "exports_count": len(data.get('exports', [])),
                "analysis_time_ms": timer.elapsed_ms
            }

        except Exception as e:
            return {"error": str(e), "code": "SYSTEM_ERROR"}
