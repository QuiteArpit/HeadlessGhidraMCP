// GhidraDataDump.java
// Place this inside the "GhidraScripts" folder in your project root.

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.File;
import java.io.FileWriter;
import java.text.SimpleDateFormat;
import java.util.*;

public class GhidraDataDump extends GhidraScript {
    
    // --- JSON Data Structures ---
    class AnalysisExport {
        String filename;
        String timestamp;
        List<FuncData> functions = new ArrayList<>();
        List<StringData> strings = new ArrayList<>();
    }

    class FuncData {
        String name;
        String entry;
        String code;
    }

    class StringData {
        String value;
        String address;
    }

    @Override
    public void run() throws Exception {
        // 1. GET OUTPUT DIRECTORY FROM ENV VAR
        // The Python script sets this to the "analysis_output" folder in the project root.
        String outputDirStr = System.getenv("GHIDRA_ANALYSIS_OUTPUT");
        
        // Safety Fallback: If ran manually without Python, save to user home so we don't crash
        if (outputDirStr == null || outputDirStr.trim().isEmpty()) {
            outputDirStr = System.getProperty("user.home") + File.separator + "ghidra_analysis_output";
            println("Warning: GHIDRA_ANALYSIS_OUTPUT env var not set. Defaulting to: " + outputDirStr);
        }

        File outputDir = new File(outputDirStr);
        if (!outputDir.exists()) {
            // Create the directory if it's missing
            outputDir.mkdirs(); 
        }

        // 2. GENERATE FILENAME
        String progName = currentProgram.getName();
        // Sanitize filename (remove spaces, slashes) to prevent filesystem errors
        String safeName = progName.replaceAll("[^a-zA-Z0-9.-]", "_");
        
        // Generate Timestamp: YYYY-MM-DD_HH-mm-ss
        String timeStamp = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss").format(new Date());
        
        String fileName = safeName + "_" + timeStamp + ".json";
        File outputFile = new File(outputDir, fileName);

        // 3. START EXTRACTION
        AnalysisExport export = new AnalysisExport();
        export.filename = progName;
        export.timestamp = timeStamp;

        // Setup Decompiler
        DecompInterface decompInterface = new DecompInterface();
        decompInterface.openProgram(currentProgram);

        // Extract Functions
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        monitor.initialize(currentProgram.getFunctionManager().getFunctionCount());
        monitor.setMessage("Extracting Functions...");

        while (functions.hasNext()) {
            if (monitor.isCancelled()) break;
            Function func = functions.next();
            monitor.incrementProgress(1);

            if (func.isThunk() || func.isExternal()) continue;

            FuncData fd = new FuncData();
            fd.name = func.getName();
            fd.entry = func.getEntryPoint().toString();

            // Decompile (timeout 30s per function)
            DecompileResults res = decompInterface.decompileFunction(func, 30, monitor);
            if (res.decompileCompleted()) {
                fd.code = res.getDecompiledFunction().getC();
            } else {
                fd.code = "// Decompilation failed";
            }
            export.functions.add(fd);
        }

        // Extract Strings
        DataIterator dataIt = currentProgram.getListing().getDefinedData(true);
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            if (data.hasStringValue()) {
                StringData sd = new StringData();
                sd.value = data.getDefaultValueRepresentation();
                sd.address = data.getAddress().toString();
                export.strings.add(sd);
            }
        }

        // 4. WRITE JSON FILE
        // Ghidra comes with Gson, so this dependency is safe.
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        FileWriter writer = new FileWriter(outputFile);
        gson.toJson(export, writer);
        writer.close();
        
        // 5. CRITICAL: COMMUNICATION TAG
        // This print statement is how the Python script knows the final file path.
        // Do not remove or change the "GHIDRA_JSON_GENERATED:" prefix.
        println("GHIDRA_JSON_GENERATED: " + outputFile.getAbsolutePath());
    }
}