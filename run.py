#!/usr/bin/env python3
"""
Ghidra MCP Server - Cross-Platform Launcher
Auto-installs dependencies and runs the server.
Works on Windows, Linux (including Arch), and macOS.
"""
import subprocess
import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VENV_DIR = os.path.join(SCRIPT_DIR, ".venv")

def log(msg):
    """Print status message to stderr (visible to user, not MCP)."""
    print(msg, file=sys.stderr)

def get_venv_python():
    """Get path to venv Python executable."""
    if sys.platform == "win32":
        return os.path.join(VENV_DIR, "Scripts", "python.exe")
    return os.path.join(VENV_DIR, "bin", "python")

def in_venv():
    """Check if we're running inside the venv."""
    return sys.prefix == VENV_DIR or hasattr(sys, 'real_prefix')

def setup_venv():
    """Create venv and install dependencies if needed."""
    venv_python = get_venv_python()
    
    # Create venv if it doesn't exist
    if not os.path.exists(venv_python):
        log("[init] Creating venv...")
        subprocess.check_call([sys.executable, "-m", "venv", VENV_DIR])
    
    # Check if mcp is installed in venv
    try:
        result = subprocess.run(
            [venv_python, "-c", "import mcp"],
            capture_output=True
        )
        if result.returncode != 0:
            raise ImportError
    except (ImportError, subprocess.CalledProcessError):
        log("[init] Installing dependencies...")
        subprocess.check_call([venv_python, "-m", "pip", "install", "mcp", "-q"])
    
    return venv_python

def main():
    os.chdir(SCRIPT_DIR)
    
    # If not in venv, setup and re-run with venv Python
    if not in_venv():
        venv_python = setup_venv()
        log("[ready] Ghidra MCP server starting")
        os.execv(venv_python, [venv_python, __file__])
    
    # Now running inside venv - start the server
    sys.path.insert(0, SCRIPT_DIR)
    from src.server import main as run_server
    run_server()

if __name__ == "__main__":
    main()
