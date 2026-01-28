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

# --- PORTABLE CONFIGURATION ---

# 1. Base Directory: Project root (parent of src/)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 2. Scripts Directory: Ghidra Java scripts
SCRIPT_DIR = os.path.join(BASE_DIR, "scripts", "ghidra")

# 3. Output Directory: Relative to BASE_DIR
# We will save JSON logs to: ./analysis_output/
LOGS_DIR = os.path.join(BASE_DIR, "analysis_output")

# 4. Ghidra Headless Path
# Auto-detect based on OS and common install locations
# Priority: GHIDRA_HEADLESS_PATH env var > GHIDRA_INSTALL_DIR env var > auto-detect
GHIDRA_HEADLESS_PATH = find_ghidra_path()

# ------------------------------

# Configure console encoding for cross-platform UTF-8 support
configure_console_encoding()

mcp = FastMCP("Ghidra Analyst")

# Session Cache
current_session_context: Dict[str, str] = {} 

def get_file_hash(filepath: str) -> str:
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
    if not os.path.exists(binary_path):
        return f"Error: File {binary_path} not found."

    # Ensure output directory exists
    if not os.path.exists(LOGS_DIR):
        os.makedirs(LOGS_DIR)

    # Check if Ghidra path is valid
    if not GHIDRA_HEADLESS_PATH or not os.path.exists(GHIDRA_HEADLESS_PATH):
        platform_info = get_platform_info()
        return (
            f"CONFIGURATION ERROR: Ghidra not found.\n"
            f"Platform: {platform_info['os']}\n"
            f"Expected executable: {platform_info['ghidra_executable']}\n\n"
            f"Please do ONE of the following:\n"
            f"1. Set GHIDRA_HEADLESS_PATH to the full path of your analyzeHeadless executable\n"
            f"2. Set GHIDRA_INSTALL_DIR to your Ghidra installation directory\n"
            f"3. Install Ghidra to a standard location:\n"
            f"   - Linux: /opt/ghidra/, ~/ghidra/\n"
            f"   - Windows: C:\\ghidra\\, C:\\Program Files\\ghidra\\\n"
        )

    # Create Temp Project Folder (deleted after analysis)
    temp_proj_dir = tempfile.mkdtemp()
    proj_name = f"ghidra_proj_{get_file_hash(binary_path)[:8]}"

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

    # Pass the SAFE relative output directory to Java
    env = os.environ.copy()
    env["GHIDRA_ANALYSIS_OUTPUT"] = LOGS_DIR

    try:
        print(f"[INFO] Starting Analysis on: {binary_path}")
        print(f"[INFO] Saving Output to: {LOGS_DIR}")
        
        result = subprocess.run(
            cmd, 
            env=env, 
            check=False, 
            capture_output=True, 
            text=True, 
            encoding='utf-8', 
            errors='replace'
        )
        
        # --- PARSING LOGIC ---
        generated_json_path = None
        
        # 1. Try to find the tag from Java stdout
        for line in result.stdout.splitlines():
            if "GHIDRA_JSON_GENERATED:" in line:
                raw_path = line.split("GHIDRA_JSON_GENERATED:")[1].strip()
                generated_json_path = raw_path.strip('"').strip("'")
                break
        
        # 2. Fallback: Find newest file in LOGS_DIR
        if not generated_json_path or not os.path.exists(generated_json_path):
            files = [os.path.join(LOGS_DIR, f) for f in os.listdir(LOGS_DIR) if f.endswith(".json")]
            if files:
                generated_json_path = max(files, key=os.path.getctime)
            else:
                return f"Analysis Failed. No JSON found in {LOGS_DIR}.\nDebug Stdout:\n{result.stdout}\n"

        current_session_context[binary_path] = generated_json_path
        
        with open(generated_json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        shutil.rmtree(temp_proj_dir, ignore_errors=True)
        
        rel_path = os.path.relpath(generated_json_path, BASE_DIR)
        return f"Success! Analysis saved to: {rel_path}\nFunctions found: {len(data['functions'])}\nStrings found: {len(data['strings'])}"

    except Exception as e:
        return f"System Error: {str(e)}"

def load_latest_json(binary_path: str):
    if binary_path not in current_session_context:
        return None
    json_path = current_session_context[binary_path]
    if not os.path.exists(json_path):
        return None
    with open(json_path, 'r', encoding='utf-8') as f:
        return json.load(f)

@mcp.tool()
def list_functions(binary_path: str) -> str:
    data = load_latest_json(binary_path)
    if not data:
        return "Error: No analysis found. Run 'analyze_binary' first."
    funcs = [f"{f['name']} (@ {f['entry']})" for f in data['functions']]
    return json.dumps(funcs[:300]) 

@mcp.tool()
def read_function_code(binary_path: str, function_name: str) -> str:
    data = load_latest_json(binary_path)
    if not data:
        return "Error: No analysis found. Run 'analyze_binary' first."
    for f in data['functions']:
        if f['name'] == function_name:
            return f['code']
    return f"Function '{function_name}' not found."

@mcp.tool()
def read_strings(binary_path: str) -> str:
    data = load_latest_json(binary_path)
    if not data:
        return "Error: No analysis found. Run 'analyze_binary' first."
    valid_strings = [s['value'] for s in data['strings'] if len(s['value']) > 5]
    return json.dumps(valid_strings[:100])

@mcp.tool()
def health_check() -> str:
    """
    Check MCP server status, Ghidra installation, and platform info.
    Use this to diagnose configuration issues.
    """
    result = {
        "status": "ok",
        "platform": get_platform_info(),
        "ghidra_path": GHIDRA_HEADLESS_PATH,
        "ghidra_found": GHIDRA_HEADLESS_PATH is not None and os.path.exists(GHIDRA_HEADLESS_PATH),
        "scripts_dir": SCRIPT_DIR,
        "scripts_found": os.path.exists(SCRIPT_DIR),
        "output_dir": LOGS_DIR,
    }
    
    if not result["ghidra_found"]:
        result["status"] = "error"
        result["error"] = "Ghidra not found"
    
    return json.dumps(result, indent=2)

def main():
    """Entry point for ghidra-mcp command."""
    mcp.run()

if __name__ == "__main__":
    main()