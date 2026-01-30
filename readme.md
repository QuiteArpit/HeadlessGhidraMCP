# HeadlessGhidraMCP 🕵️‍♂️

**AI-powered malware analysis using [MCP](https://modelcontextprotocol.io/) + Ghidra.**

Turn Claude into a master reverse engineer. Analyze binaries, extract call graphs, and audit imports/exports using natural language—no Ghidra GUI required!

---

## ⚡ Features

- **Deep Analysis**: Decompilation, Strings, Functions, Imports, Exports.
- **High-Performance Inspection**: Fast string search, hex dumping, and basic disassembly (without Ghidra).
- **Call Graph**: Inspect Function Callers (parents) and Callees (children).
- **Zero-Config**: Auto-detects Ghidra installation.
- **Robust**: Caching, persistence, and auto-cleanup of temporary projects.
- **Cross-Platform**: Works seamlessy on Linux, macOS, and Windows.

---

## 🚀 Quick Start

### Prerequisites
- **Python** 3.10+ ([download](https://www.python.org/downloads/))
- **Ghidra** 10.x+ ([download](https://ghidra-sre.org/))
- **Java** 17+ (Required by Ghidra)

### Install

**Linux / macOS / Windows:**
```bash
git clone https://github.com/QuiteArpit/HeadlessGhidraMCP.git
cd HeadlessGhidraMCP
python setup_project.py
```
*`setup_project.py` automatically handles environment creation, dependencies, and build logic.*

### 🔌 Connect to Claude Desktop

**Linux / macOS** (`~/.config/Claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "ghidra-analyst": {
      "command": "/absolute/path/to/HeadlessGhidraMCP/.venv/bin/ghidra-mcp",
      "args": []
    }
  }
}
```

**Windows** (`%APPDATA%\Claude\claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "ghidra-analyst": {
      "command": "C:\\Users\\YOU\\HeadlessGhidraMCP\\.venv\\Scripts\\ghidra-mcp.exe",
      "args": []
    }
  }
}
```
*Restart Claude Desktop to see the 🔌 icon.*

---

## 🎯 Usage Examples

**1. Rapid Recon (Fast)**
> "Search for 'password' strings in `/path/to/malware.exe`"
> "Show me the first 64 bytes of the binary"

**2. Deep Analysis (Ghidra)**
> "Analyze `/path/to/malware.exe`"
> "Decompile `main` function"
> "Who calls `main`? Use `get_function_callers`"

**3. Batch Processing**
> "Analyze all .exe files in `/malware_samples`"

---

## 🛠 Available Tools

| Tool | Description |
|------|-------------|
| **Inspection (Fast)** | *Native Python tools (No Ghidra overhead)* |
| `search_strings` | Find strings (regex supported) in binary |
| `read_bytes` | Read raw bytes (hexdump) from file |
| `disassemble_preview` | Quick disassembly of instructions at offset |
| `list_sections` | Show PE/ELF sections and entropy |
| **Analysis** | *Powered by Ghidra Headless* |
| `analyze_binary` | Analyze a single binary (Cached) |
| `analyze_binaries` | Batch analyze multiple binaries |
| `analyze_folder` | Recursively analyze a directory |
| **Query** | |
| `list_functions` | List functions (names, addresses) |
| `read_function_code` | Decompile C code for a function |
| `read_strings` | Extract analysis strings (from Ghidra) |
| **Graph & Metadata** | |
| `list_imports` | List imported libraries/functions |
| `list_exports` | List exported entry points |
| `get_function_callers` | List parents (functions calling target) |
| `get_function_callees` | List children (functions called by target) |
| **System** | |
| `scan_folder` | List files safely with type detection (PE/ELF/Mach-O) |
| `list_session_binaries` | Show currently loaded/cached binaries |
| `clear_session` | Clear in-memory session data |
| `health_check` | Verify Ghidra path and configuration |

---

## 🧪 Development & Testing

This project includes a comprehensive test suite.

```bash
# Activate environment
source .venv/bin/activate

# Run all tests
pytest

# Run fast unit tests only
pytest tests/unit

# Run full integration tests (requires Ghidra)
pytest tests/integration
```

---

## 🧹 Maintenance

The system caches analysis results and creates temporary Ghidra projects. To save disk space:

```bash
# Clean cache & output logs (Keeps virtual environment)
python clean.py

# Clean EVERYTHING (Including .venv)
python clean.py --all
```

---

## 📂 Project Structure

```text
HeadlessGhidraMCP/
├── setup_project.py       # One-click Setup Script
├── clean.py               # Cleanup Utility
├── pyproject.toml         # Dependencies & Build Config
├── pytest.ini             # Test Config
├── readme.md              # Documentation
├── analysis_output/       # (Created at runtime) Logs & Cache
├── src/                   # Python Source
│   ├── server.py          # MCP Server & Lifecycle
│   ├── analyzer.py        # Analysis Engine & Ghidra Wrapper
│   ├── session.py         # In-memory State Management
│   ├── cache.py           # Persistence & Hashing Logic
│   └── tools/             # MCP Tool Implementations
│       ├── analysis.py    # Core analysis (BatchProcessor)
│       ├── inspection.py  # Fast static analysis tools
│       ├── query.py       # Decompilation & string tools
│       ├── graph.py       # Call graph tools (XRefs)
│       └── ...
├── scripts/ghidra/        # Java Scripts (Run inside Ghidra)
│   └── GhidraDataDump.java # Main extraction logic
└── tests/                 # Comprehensive Test Suite
    ├── unit/              # Fast logic tests
    └── integration/       # End-to-end Ghidra tests
```