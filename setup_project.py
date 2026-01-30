#!/usr/bin/env python3
"""
Setup script for HeadlessGhidraMCP.
Automates virtual environment creation and dependency installation.
Handles Arch Linux 'externally-managed-environment' issues by using 'uv' if available.
"""
import subprocess
import sys
import os
import shutil

def run_command(cmd, shell=False):
    """Run a shell command and return True if successful."""
    print(f"Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    try:
        subprocess.check_call(cmd, shell=shell)
        return True
    except subprocess.CalledProcessError:
        print(f"Error executing command.")
        return False

def check_uv():
    """Check if 'uv' is installed."""
    return shutil.which("uv") is not None

def main():
    print("=== HeadlessGhidraMCP Project Setup ===\n")
    
    # 1. Check for Python 3.10+
    if sys.version_info < (3, 10):
        print("Error: Python 3.10 or higher is required.")
        sys.exit(1)
        
    # 2. Virtual Environment Creation
    venv_dir = ".venv"
    has_uv = check_uv()
    
    if os.path.exists(venv_dir):
        print(f"Virtual environment '{venv_dir}' already exists.")
    else:
        print(f"Creating virtual environment in '{venv_dir}'...")
        if has_uv:
            print("Using 'uv' for faster setup.")
            if not run_command(["uv", "venv", venv_dir]):
                sys.exit(1)
        else:
            print("Using standard 'venv' module.")
            if not run_command([sys.executable, "-m", "venv", venv_dir]):
                sys.exit(1)
    
    # 3. Install Dependencies
    print("\nInstalling dependencies...")

    # Determine executable paths inside venv for cross-platform support
    if os.name == "nt":
        pip_cmd = os.path.join(venv_dir, "Scripts", "pip.exe")
        python_cmd = os.path.join(venv_dir, "Scripts", "python.exe")
    else:
        pip_cmd = os.path.join(venv_dir, "bin", "pip")
        python_cmd = os.path.join(venv_dir, "bin", "python")

    if has_uv:
        print("Using 'uv' for dependency installation.")
        # Using the venv's python interpreter is a robust way to ensure installation
        # in the correct environment without activation scripts.
        install_cmd = ["uv", "pip", "install", "--python", python_cmd, "-e", ".[dev]"]
        if not run_command(install_cmd):
            print("'uv' installation failed. Please check your setup or report the issue.")
            sys.exit(1)
    else:
        print("Using 'pip' for dependency installation.")
        run_command([pip_cmd, "install", "--upgrade", "pip"])
        run_command([pip_cmd, "install", "-e", ".[dev]"])
        
    print("\n=== Setup Complete! ===")
    print("\nTo start using the project:")
    if os.name == 'nt':
        print(f"  .\\{venv_dir}\\Scripts\\activate")
    else:
        print(f"  source {venv_dir}/bin/activate")
    print("  ghidra-mcp")
    print("\nTo run tests:")
    print("  pytest")

if __name__ == "__main__":
    main()
