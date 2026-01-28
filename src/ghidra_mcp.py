import os
import subprocess
import json
import tempfile
import hashlib
import shutil
import sys
from typing import Dict, Any
from mcp.server.fastmcp import FastMCP
from .platform_utils import (
    find_ghidra_path,
    configure_console_encoding,
    get_platform_info,
)
from .response_utils import make_response, make_error, Timer

# --- PORTABLE CONFIGURATION ---

# 1. Base Directory: Project root (parent of src/)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 2. Scripts Directory: Ghidra Java scripts
SCRIPT_DIR = os.path.join(BASE_DIR, "scripts", "ghidra")

# 3. Output Directory: Relative to BASE_DIR
LOGS_DIR = os.path.join(BASE_DIR, "analysis_output")

# 4. Ghidra Headless Path (auto-detect)
GHIDRA_HEADLESS_PATH = find_ghidra_path()

# ------------------------------

# Configure console encoding for cross-platform UTF-8 support
configure_console_encoding()

mcp = FastMCP("Ghidra Analyst")

# Session Cache: {binary_path: json_path}
current_session_context: Dict[str, str] = {}


def get_file_hash(filepath: str) -> str:
    """Calculate SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        return "file_not_found"


@mcp.tool()
def analyze_binary(binary_path: str) -> str:
    """
    Analyzes a binary using Ghidra and saves the results to a JSON file
    in the 'analysis_output' folder.
    """
    # Validate file exists
    if not os.path.exists(binary_path):
        return make_error(
            f"File not found: {binary_path}",
            code="FILE_NOT_FOUND"
        )

    # Ensure output directory exists
    os.makedirs(LOGS_DIR, exist_ok=True)

    # Check Ghidra path
    if not GHIDRA_HEADLESS_PATH or not os.path.exists(GHIDRA_HEADLESS_PATH):
        platform_info = get_platform_info()
        return make_error(
            f"Ghidra not found. Platform: {platform_info['os']}. "
            f"Set GHIDRA_HEADLESS_PATH or install to standard location.",
            code="GHIDRA_NOT_FOUND"
        )

    # Get file hash for project naming
    file_hash = get_file_hash(binary_path)[:8]
    binary_name = os.path.basename(binary_path)

    # Create temp project folder
    temp_proj_dir = tempfile.mkdtemp()
    proj_name = f"ghidra_proj_{file_hash}"

    cmd = [
        GHIDRA_HEADLESS_PATH,
        temp_proj_dir,
        proj_name,
        "-import", binary_path,
        "-scriptPath", SCRIPT_DIR,
        "-postScript", "GhidraDataDump.java",
        "-deleteProject",
        "-analysisTimeoutPerFile", "600"
    ]

    env = os.environ.copy()
    env["GHIDRA_ANALYSIS_OUTPUT"] = LOGS_DIR

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
                    generated_json_path = raw_path.strip('"').strip("'")
                    break

            # Fallback: find newest JSON in output dir
            if not generated_json_path or not os.path.exists(generated_json_path):
                files = [os.path.join(LOGS_DIR, f) for f in os.listdir(LOGS_DIR) if f.endswith(".json")]
                if files:
                    generated_json_path = max(files, key=os.path.getctime)
                else:
                    return make_error(
                        f"Analysis failed. No JSON output found.",
                        code="ANALYSIS_FAILED"
                    )

            # Load and validate JSON
            with open(generated_json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Store in session
            current_session_context[binary_path] = generated_json_path

            # Cleanup temp project
            shutil.rmtree(temp_proj_dir, ignore_errors=True)

            return make_response(data={
                "binary": binary_path,
                "binary_name": binary_name,
                "binary_hash": file_hash,
                "output_path": os.path.relpath(generated_json_path, BASE_DIR),
                "functions_count": len(data.get('functions', [])),
                "strings_count": len(data.get('strings', [])),
                "analysis_time_ms": timer.elapsed_ms
            })

        except Exception as e:
            return make_error(str(e), code="SYSTEM_ERROR")


def load_latest_json(binary_path: str):
    """Load cached analysis JSON for a binary."""
    if binary_path not in current_session_context:
        return None
    json_path = current_session_context[binary_path]
    if not os.path.exists(json_path):
        return None
    with open(json_path, 'r', encoding='utf-8') as f:
        return json.load(f)


@mcp.tool()
def list_functions(binary_path: str, limit: int = 300) -> str:
    """List all functions found in the analyzed binary."""
    data = load_latest_json(binary_path)
    if not data:
        return make_error(
            "No analysis found. Run 'analyze_binary' first.",
            code="NO_ANALYSIS"
        )

    functions = data.get('functions', [])
    func_list = [
        {"name": f['name'], "address": f['entry']}
        for f in functions[:limit]
    ]

    return make_response(data={
        "binary": binary_path,
        "total_count": len(functions),
        "returned_count": len(func_list),
        "limit": limit,
        "functions": func_list
    })


@mcp.tool()
def read_function_code(binary_path: str, function_name: str) -> str:
    """Decompile and return the C code for a specific function."""
    data = load_latest_json(binary_path)
    if not data:
        return make_error(
            "No analysis found. Run 'analyze_binary' first.",
            code="NO_ANALYSIS"
        )

    for f in data.get('functions', []):
        if f['name'] == function_name:
            return make_response(data={
                "binary": binary_path,
                "function_name": function_name,
                "address": f.get('entry', 'unknown'),
                "decompiled_code": f['code']
            })

    return make_error(
        f"Function '{function_name}' not found.",
        code="FUNCTION_NOT_FOUND"
    )


@mcp.tool()
def read_strings(binary_path: str, min_length: int = 5, limit: int = 100) -> str:
    """Extract strings from the analyzed binary."""
    data = load_latest_json(binary_path)
    if not data:
        return make_error(
            "No analysis found. Run 'analyze_binary' first.",
            code="NO_ANALYSIS"
        )

    all_strings = data.get('strings', [])
    filtered = [s for s in all_strings if len(s.get('value', '')) > min_length]
    
    string_list = [
        {"value": s['value'], "address": s.get('address', 'unknown')}
        for s in filtered[:limit]
    ]

    return make_response(data={
        "binary": binary_path,
        "total_count": len(all_strings),
        "filtered_count": len(filtered),
        "returned_count": len(string_list),
        "min_length": min_length,
        "limit": limit,
        "strings": string_list
    })


@mcp.tool()
def health_check() -> str:
    """
    Check MCP server status, Ghidra installation, and platform info.
    Use this to diagnose configuration issues.
    """
    ghidra_found = GHIDRA_HEADLESS_PATH is not None and os.path.exists(GHIDRA_HEADLESS_PATH)
    scripts_found = os.path.exists(SCRIPT_DIR)
    
    status = "success" if ghidra_found else "error"
    
    response_data = {
        "platform": get_platform_info(),
        "ghidra_path": GHIDRA_HEADLESS_PATH,
        "ghidra_found": ghidra_found,
        "scripts_dir": SCRIPT_DIR,
        "scripts_found": scripts_found,
        "output_dir": LOGS_DIR,
        "session_binaries": len(current_session_context)
    }
    
    if not ghidra_found:
        return make_error("Ghidra not found", code="GHIDRA_NOT_FOUND")
    
    return make_response(data=response_data)


def main():
    """Entry point for ghidra-mcp command."""
    mcp.run()


if __name__ == "__main__":
    main()