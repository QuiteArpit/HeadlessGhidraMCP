# Ghidra MCP Analyst 🕵️‍♂️

An autonomous **Malware Analysis Agent** powered by the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/).

This tool bridges the gap between **Claude (LLMs)** and **Ghidra's Headless Analyzer**. It allows you to drag-and-drop a binary into Claude Desktop and perform complex reverse engineering tasks—listing functions, decompiling code, and extracting strings—using natural language, all without opening the Ghidra GUI.

## 🚀 Features

* **Automated Decompilation:** Extracts C code from functions on demand.
* **Intelligent Caching:** Analyzes binaries once and caches the result for instant subsequent queries.
* **Portable Logging:** Automatically saves analysis artifacts (JSON) to an internal `analysis_output` folder.
* **No GUI Required:** Runs completely headless using Ghidra's automation scripts.

---

## 🛠️ Prerequisites

Before running this server, ensure you have the following installed:

1.  **Python 3.10+**
2.  **Ghidra** (Version 10.x or 11.x)
    * *Note: Ensure you can run Ghidra manually at least once to verify JDK setup.*
3.  **Claude Desktop App** (or any other MCP-compliant client)

---

## 📦 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/QuiteArpit/HeadlessGhidraMCP.git
cd HeadlessGhidraMCP
```

### 2. Install Dependencies
```Bash
pip install mcp
```

### 3. Configure the Ghidra Path (Critical Step!)
You need to tell the script where your Ghidra installation is located.

**Option A:** Using an Environment Variable (Recommended) Set the GHIDRA_HEADLESS_PATH variable to point to your analyzeHeadless executable.

* **Windows (PowerShell):**
```PowerShell
$env:GHIDRA_HEADLESS_PATH = "C:\Path\To\Ghidra\support\analyzeHeadless.bat"
```

* **Mac/Linux:**
```Bash
export GHIDRA_HEADLESS_PATH="/Path/To/Ghidra/support/analyzeHeadless"
```

**Option B:** Quick Edit Alternatively, you can open ghidra_mcp.py in a text editor and manually set the fallback path on line 28:

```Python
# ghidra_mcp.py
GHIDRA_HEADLESS_PATH = os.getenv("GHIDRA_HEADLESS_PATH", r"C:\Your\Actual\Path\support\analyzeHeadless.bat")
```

---

## 🔌 Connecting to Claude Desktop
To use this tool inside Claude, you must add it to your Claude Desktop configuration file.

### 1. Locate the Config File:

* Windows: ```%APPDATA%\Claude\claude_desktop_config.json```
* Mac: ```~/Library/Application Support/Claude/claude_desktop_config.json```

### 2. Add the Server Config:
Open the file and add the following JSON. **Make sure to update the absolute path to where you cloned this repo.**

```JSON
{
  "mcpServers": {
    "ghidra-analyst": {
      "command": "python",
      "args": [
        "C:\\Users\\YOUR_USER\\Documents\\GitHub\\ghidra-mcp-analyst\\ghidra_mcp.py"
      ]
    }
  }
}
```
*(Note: On Windows, remember to use double backslashes \\ in the path.)*

### 3. Restart Claude Desktop:
You should see a 🔌 plug icon or a active connector appear in the input bar indicating the tool is active.

---

## 🧪 How to Test
1. Locate the **Sample** folder in this repository (or use any binary you own).
2. We will use ```program.exe``` as a test subject.
3. Open Claude and type the following prompt:
```
I have a binary located at C:\Users\YOUR_USER\...\Sample\program.exe. Please analyze it. List the functions found, identify the main entry point, and then decompile the main function to explain what it does.
```
### What happens next:
1. Claude will ask for permission to run ```analyze_binary```. Click Allow.
2. Wait 10-20 seconds for Ghidra to run in the background.
3. Claude will receive the analysis data and answer your question.
4. A JSON log file will be generated in the ```analysis_output/``` folder of this project for your reference.

---

## 📂 Project Structure
* ```ghidra_mcp.py```: The main MCP server script.
* ```GhidraScripts/```: Contains the Java script (GhidraDataDump.java) that runs inside Ghidra.
* ```analysis_output/```: (Created at runtime) Stores the JSON analysis results.
* ```sample```: Contains dummy binaries for testing.

---

## ⚠️ Troubleshooting
- Error: ```The system cannot find the file specified```:
    - Your ```GHIDRA_HEADLESS_PATH``` is incorrect. Ensure it points to the ```.bat``` file on Windows.

- Error: ```JAVA_HOME not found```:
    - Ensure Ghidra is working properly. You may need to add your JDK installation to your system PATH.