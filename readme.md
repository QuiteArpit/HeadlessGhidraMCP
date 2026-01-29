# HeadlessGhidraMCP 🕵️‍♂️

**AI-powered malware analysis using [MCP](https://modelcontextprotocol.io/) + Ghidra.**

Turn Claude into a master reverse engineer. Analyze binaries, extract call graphs, and audit imports/exports using natural language—no Ghidra GUI required!

---

## ⚡ Features

- **Deep Analysis**: Decompilation, Strings, Functions, Imports, Exports.
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
python run.py
```
*First run automatically creates a virtual environment and installs dependencies.*

### 🔌 Connect to Claude Desktop

**Linux / macOS** (`~/.config/Claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "ghidra-analyst": {
      "command": "python",
      "args": ["/absolute/path/to/HeadlessGhidraMCP/run.py"]
    }
  }
}
```

**Windows** (`%APPDATA%\Claude\claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "ghidra-analyst": {
      "command": "python",
      "args": ["C:\\Users\\YOU\\HeadlessGhidraMCP\\run.py"]
    }
  }
}
```
*Restart Claude Desktop to see the 🔌 icon.*

---

## 🎯 Usage Examples

**1. Basic Analysis**
> "Analyze `/path/to/malware.exe`"

**2. Explore Structure**
> "List imports using `list_imports`"
> "Show exported functions"

**3. Deep Dive**
> "Decompile `main` function"
> "Who calls `main`? Use `get_function_callers`"
> "What does `main` call? Use `get_function_callees`"

**4. Diagnostics**
> "Run `health_check`"

---

## 🛠 Available Tools

| Tool | Description |
|------|-------------|
| **Analysis** | |
| `analyze_binary` | Analyze a single binary (Cached) |
| `analyze_binaries` | Batch analyze multiple binaries |
| `analyze_folder` | Recursively analyze a directory |
| **Query** | |
| `list_functions` | List functions (names, addresses) |
| `read_function_code` | Decompile C code for a function |
| `read_strings` | Extract ASCII strings |
| **Graph & Metadata** | |
| `list_imports` | List imported libraries/functions |
| `list_exports` | List exported entry points |
| `get_function_callers` | List parents (functions calling target) |
| `get_function_callees` | List children (functions called by target) |
| **System** | |
| `list_session_binaries` | Show currently loaded/cached binaries |
| `clear_session` | Clear in-memory session data |
| `health_check` | Verify Ghidra path and configuration |

---

## ⚙️ Configuration

Ghidra path is **auto-detected**. To override:

**Linux/macOS:**
```bash
export GHIDRA_HEADLESS_PATH="/opt/ghidra/support/analyzeHeadless"
```

**Windows PowerShell:**
```powershell
$env:GHIDRA_HEADLESS_PATH = "C:\ghidra\support\analyzeHeadless.bat"
```

---

## 🧪 Development & Testing

This project includes a comprehensive test suite.

```bash
# specialized dev install
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run all tests
pytest -v tests/

# Run specific suite
pytest -v tests/integration/  # Requires Ghidra
```

---

## 🧹 Maintenance

The system caches analysis results and creates temporary Ghidra projects. To save disk space:

```bash
# Clean everything (cache + projs + pycache + venv)
python clean.py --all

# Clean only projects and cache
python clean.py --output

# Clean only cache
python clean.py --cache
```

---

## 📂 Project Structure

```text
HeadlessGhidraMCP/
├── run.py                 # Application entry point
├── clean.py               # Utility to clean cache/projects
├── pyproject.toml         # Dependencies & Build Config
├── pytest.ini             # Test Config
├── readme.md              # Documentation
├── analysis_output/       # (Created at runtime) Logs & Cache
├── src/                   # Python Source
│   ├── server.py          # MCP Server & Lifecycle
│   ├── analyzer.py        # Analysis Engine & Ghidra Wrapper
│   ├── session.py         # In-memory State Management
│   ├── cache.py           # Persistence & Hashing Logic
│   ├── config.py          # Paths & Constants
│   ├── platform_utils.py  # OS Detection utilities
│   └── tools/             # MCP Tool Implementations
│       ├── analysis.py    # Core analysis tools
│       ├── query.py       # Decompilation & string tools
│       ├── graph.py       # Call graph tools (XRefs)
│       ├── metadata.py    # Imports/Exports tools
│       └── system.py      # Health checks & session tools
├── scripts/ghidra/        # Java Scripts (Run inside Ghidra)
│   └── GhidraDataDump.java # Main extraction logic
└── tests/                 # Comprehensive Test Suite
    ├── unit/              # Fast logic tests
    └── integration/       # End-to-end Ghidra tests
```

---

## 🐛 Troubleshooting

**"Ghidra not found":**
Ensure `JAVA_HOME` is set and Ghidra is installed. Try setting `GHIDRA_HEADLESS_PATH` manually.

**"Analysis failed":**
Check `analysis_output/` logs. Ensure the binary is a valid executable (PE/ELF).

**"Server hangs":**
Analysis can take 30-60s for large files. This is normal.