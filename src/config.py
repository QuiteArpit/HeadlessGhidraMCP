"""
Configuration module for Ghidra MCP server.
All paths, constants, and global settings.
"""
import os
from .platform_utils import find_ghidra_path, configure_console_encoding

# --- PORTABLE CONFIGURATION ---

# 1. Base Directory: Project root (parent of src/)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 2. Scripts Directory: Ghidra Java scripts
SCRIPT_DIR = os.path.join(BASE_DIR, "scripts", "ghidra")

# 3. Output Directories
LOGS_DIR = os.path.join(BASE_DIR, "analysis_output")
PROJECTS_DIR = os.path.join(LOGS_DIR, "projects")
CACHE_DIR = os.path.join(LOGS_DIR, "cache")
INDEX_FILE = os.path.join(LOGS_DIR, "index.json")

# 4. Ghidra Headless Path (auto-detect)
GHIDRA_HEADLESS_PATH = find_ghidra_path()

# Configure console encoding for cross-platform UTF-8 support
configure_console_encoding()
