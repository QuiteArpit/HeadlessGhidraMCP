# Ghidra MCP Analyst 🕵️‍♂️

AI-powered malware analysis using [MCP](https://modelcontextprotocol.io/) + Ghidra.

Analyze binaries with Claude using natural language - no Ghidra GUI required!

---

## ⚡ Quick Start

### Prerequisites
- **Python** 3.10+ ([download](https://www.python.org/downloads/))
- **Ghidra** 10.x+ ([download](https://ghidra-sre.org/))

### Install & Run

**Linux / macOS:**
```bash
git clone https://github.com/QuiteArpit/HeadlessGhidraMCP.git
cd HeadlessGhidraMCP
python run.py
```

**Windows (PowerShell):**
```powershell
git clone https://github.com/QuiteArpit/HeadlessGhidraMCP.git
cd HeadlessGhidraMCP
python run.py
```

First run auto-creates virtual environment and installs dependencies.

---

## 🔌 Claude Desktop Setup

### Linux / macOS
Edit `~/.config/Claude/claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "ghidra-analyst": {
      "command": "python",
      "args": ["/full/path/to/HeadlessGhidraMCP/run.py"]
    }
  }
}
```

### Windows
Edit `%APPDATA%\Claude\claude_desktop_config.json`:
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

Restart Claude Desktop → 🔌 icon appears → Ready!

---

## 🎯 Usage

Ask Claude:
> "Analyze `/path/to/malware.exe`"  
> "List functions"  
> "Decompile `main`"  
> "Show suspicious strings"  
> "Run health_check"

---

## ⚙️ Ghidra Path

Auto-detected in standard locations:
- **Linux:** `/opt/ghidra/`, `~/ghidra/`
- **Windows:** `C:\ghidra\`, `C:\Program Files\ghidra\`

**Manual override:**
```bash
# Linux/macOS
export GHIDRA_HEADLESS_PATH="/path/to/ghidra/support/analyzeHeadless"

# Windows PowerShell
$env:GHIDRA_HEADLESS_PATH = "C:\ghidra\support\analyzeHeadless.bat"
```

---

## 📂 Structure
```
HeadlessGhidraMCP/
├── run.py               # Entry point (cross-platform)
├── src/                 # Python source
├── scripts/ghidra/      # Ghidra Java scripts
└── tests/               # Test suite
```

---

## 🧪 Development
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest tests/ -v
```

---

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| Ghidra not found | Set `GHIDRA_HEADLESS_PATH` |
| JAVA_HOME error | Install JDK 17+ |
| Server "hangs" | Normal! It's waiting for Claude |

**Diagnostic:** Ask Claude → "Run health_check"