"""
platform_utils.py - Cross-platform utilities for HeadlessGhidraMCP

This module provides OS detection and Ghidra path resolution for Windows and Linux.
"""
import os
import sys
import platform
from pathlib import Path
from typing import Optional


def get_os_name() -> str:
    """Returns 'windows', 'linux', or 'darwin' (macOS)."""
    return platform.system().lower()


def is_windows() -> bool:
    """Check if running on Windows."""
    return sys.platform == "win32"


def get_ghidra_executable_name() -> str:
    """Returns the correct Ghidra headless executable name for the current OS."""
    if is_windows():
        return "analyzeHeadless.bat"
    return "analyzeHeadless"


def find_ghidra_path() -> Optional[str]:
    """
    Auto-detect Ghidra installation path.
    
    Search order (env vars always take priority):
    1. GHIDRA_HEADLESS_PATH environment variable (direct path to executable)
    2. GHIDRA_INSTALL_DIR environment variable + /support/analyzeHeadless
    3. Common installation locations for the current OS
    
    Returns:
        Full path to analyzeHeadless executable, or None if not found.
    """
    # 1. FIRST: Check GHIDRA_HEADLESS_PATH env var (highest priority)
    env_path = os.getenv("GHIDRA_HEADLESS_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path
    
    # 2. SECOND: Check GHIDRA_INSTALL_DIR env var
    install_dir = os.getenv("GHIDRA_INSTALL_DIR")
    if install_dir:
        candidate = os.path.join(install_dir, "support", get_ghidra_executable_name())
        if os.path.isfile(candidate):
            return candidate
    
    # 3. LAST: Search common locations (only if no env var is set)
    executable = get_ghidra_executable_name()
    
    if is_windows():
        search_paths = [
            Path("C:/ghidra"),
            Path("C:/Program Files/ghidra"),
            Path.home() / "ghidra",
        ]
    else:  # Linux/macOS
        search_paths = [
            Path("/opt/ghidra"),
            Path("/usr/local/ghidra"),
            Path.home() / "ghidra",
            Path.home() / ".local" / "share" / "ghidra",
        ]
    
    # Search for ghidra_* directories (versioned installs)
    for base_path in search_paths:
        if not base_path.exists():
            continue
        
        # Check if this is a direct Ghidra install (has support/ subfolder)
        candidate = base_path / "support" / executable
        if candidate.is_file():
            return str(candidate)
        
        # Check for versioned subdirectories (e.g., ghidra_11.0_PUBLIC)
        try:
            for subdir in sorted(base_path.iterdir(), reverse=True):  # Newest first
                if subdir.is_dir() and subdir.name.startswith("ghidra"):
                    candidate = subdir / "support" / executable
                    if candidate.is_file():
                        return str(candidate)
        except PermissionError:
            continue
    
    return None


def configure_console_encoding():
    """Configure console encoding for proper UTF-8 support on Windows."""
    if is_windows():
        # Windows console may not default to UTF-8
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        if hasattr(sys.stderr, 'reconfigure'):
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')


def get_platform_info() -> dict:
    """Return platform information for diagnostics."""
    return {
        "os": platform.system(),
        "os_version": platform.version(),
        "python_version": platform.python_version(),
        "is_windows": is_windows(),
        "ghidra_executable": get_ghidra_executable_name(),
    }
