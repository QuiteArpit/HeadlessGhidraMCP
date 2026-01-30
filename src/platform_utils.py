"""
platform_utils.py - Cross-platform utilities for HeadlessGhidraMCP

This module provides OS detection and Ghidra path resolution for Windows and Linux.
"""
import os
import sys
import platform
import shutil
import time
import stat
import logging
from pathlib import Path
from typing import Optional, Dict, Any, Union

logger = logging.getLogger(__name__)

# OS Checks
IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

def get_os_name() -> str:
    """Returns 'windows', 'linux', or 'darwin' (macOS)."""
    return platform.system().lower()


def is_windows() -> bool:
    """Check if running on Windows."""
    return IS_WINDOWS


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


# --- ROBUST FILE OPERATIONS & SECURITY ---

def validate_safe_path(binary_path: str, safe_dir: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Validate that the binary path is safe to access (prevents directory traversal).
    
    Args:
        binary_path: The file path to check.
        safe_dir: The directory restriction (optional). If None, checks file existence only.
        
    Returns:
        None if valid, or a dictionary {"error": "...", "code": "..."} if invalid.
    """
    try:
        abs_path = os.path.abspath(binary_path)
        
        # 1. Existence check
        if not os.path.exists(abs_path):
            return {"error": f"File not found: {binary_path}", "code": "FILE_NOT_FOUND"}
            
        # 2. Security Check
        if safe_dir:
            real_safe = os.path.realpath(os.path.abspath(safe_dir))
            real_binary = os.path.realpath(abs_path)
            
            # Normalize for Windows case-insensitivity
            if is_windows():
                real_safe = os.path.normcase(real_safe)
                real_binary = os.path.normcase(real_binary)
            
            # Use strict commonpath check
            try:
                common = os.path.commonpath([real_binary, real_safe])
            except ValueError:
                # Can happen on Windows if paths are on different drives
                return {
                    "error": f"Access denied: {binary_path} (Different drive than safe directory)",
                    "code": "SECURITY_VIOLATION"
                }

            if common != real_safe:
                return {
                    "error": f"Security Violation: Access denied to {binary_path}. Must be within {safe_dir}",
                    "code": "SECURITY_VIOLATION"
                }
                
        return None
    except Exception as e:
        return {"error": f"Path validation error: {str(e)}", "code": "PATH_ERROR"}


def _on_rm_error(func, path, exc_info):
    """
    Error handler for shutil.rmtree.
    If the error is due to an access error (read only file),
    it attempts to add write permission and then retries.
    If the error is because the file is in use, it waits a bit and retries.
    """
    # Check if access denied
    if not os.access(path, os.W_OK):
        # Is the error an access error?
        os.chmod(path, stat.S_IWUSR)
        try:
            func(path)
            return
        except Exception:
            pass
    
    # Simple retry for file locking issues
    time.sleep(0.1)
    try:
        func(path)
    except Exception as e:
        logger.warning(f"Failed to remove {path}: {e}")


def robust_rmtree(path: str) -> None:
    """
    Robustly remove a directory tree, handling Windows read-only files and locks.
    """
    if os.path.exists(path):
        shutil.rmtree(path, onerror=_on_rm_error)


def robust_move(src: str, dst: str, retries: int = 3) -> None:
    """
    Robustly move a file, handling potential temporary locks.
    """
    for i in range(retries):
        try:
            if os.path.exists(dst):
                os.remove(dst)
            shutil.move(src, dst)
            return
        except PermissionError:
            if i < retries - 1:
                time.sleep(0.2 * (i + 1))
            else:
                raise
        except Exception:
            raise
