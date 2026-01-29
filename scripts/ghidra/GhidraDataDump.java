// GhidraDataDump.java
// Place this inside the "GhidraScripts" folder in your project root.

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
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
        List<ImportData> imports = new ArrayList<>();
        List<ExportData> exports = new ArrayList<>();
        List<FuncData> functions = new ArrayList<>();
        List<StringData> strings = new ArrayList<>();
    }

    class ImportData {
        String library;
        String name;
        String address;
    }

    class ExportData {
        String name;
        String address;
    }

    class FuncData {
        String name;
        String entry;
        String code;
        List<String> callers = new ArrayList<>();
        List<String> callees = new ArrayList<>();
    }

    class StringData {
        String value;
        String address;
    }

    @Override
    public void run() throws Exception {
        // ... (Directory setup code omitted, keeping existing logic) ...
        // We will insert the logic after creating AnalysisExport and before writing JSON
        
        // 1. GET OUTPUT DIRECTORY FROM ENV VAR
        String outputDirStr = System.getenv("GHIDRA_ANALYSIS_OUTPUT");
        if (outputDirStr == null || outputDirStr.trim().isEmpty()) {
            outputDirStr = System.getProperty("user.home") + File.separator + "ghidra_analysis_output";
            println("Warning: GHIDRA_ANALYSIS_OUTPUT env var not set. Defaulting to: " + outputDirStr);
        }
        File outputDir = new File(outputDirStr);
        if (!outputDir.exists()) { outputDir.mkdirs(); }

        // 2. GENERATE FILENAME
        String progName = currentProgram.getName();
        String safeName = progName.replaceAll("[^a-zA-Z0-9.-]", "_");
        String timeStamp = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss").format(new Date());
        String fileName = safeName + "_" + timeStamp + ".json";
        File outputFile = new File(outputDir, fileName);

        // 3. START EXTRACTION
        AnalysisExport export = new AnalysisExport();
        export.filename = progName;
        export.timestamp = timeStamp;

        // --- EXTRACT IMPORTS ---
        monitor.setMessage("Extracting Imports...");
        ExternalManager extManager = currentProgram.getExternalManager();
        String[] extLibNames = extManager.getExternalLibraryNames();
        
        for (String libName : extLibNames) {
            Iterator<ExternalLocation> locs = extManager.getExternalLocations(libName);
            while (locs.hasNext()) {
                 ExternalLocation loc = locs.next();
                 if (loc.isFunction()) {
                    ImportData id = new ImportData();
                    id.library = libName;
                    String label = loc.getLabel();
                    id.name = (label != null) ? label : "Unlabeled";
                    if (loc.getAddress() != null) {
                         id.address = loc.getAddress().toString();
                    } else {
                         id.address = "External";
                    }
                    export.imports.add(id);
                 }
            }
        }

        // --- EXTRACT EXPORTS ---
        monitor.setMessage("Extracting Exports...");
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        AddressIterator entryPoints = symbolTable.getExternalEntryPointIterator();
        while (entryPoints.hasNext()) {
            Address addr = entryPoints.next();
            Symbol sym = symbolTable.getPrimarySymbol(addr);
            if (sym != null) {
                ExportData ed = new ExportData();
                ed.name = sym.getName();
                ed.address = addr.toString();
                export.exports.add(ed);
            }
        }

        // --- EXTRACT FUNCTIONS & XREFS ---
        DecompInterface decompInterface = new DecompInterface();
        decompInterface.openProgram(currentProgram);
        
        ReferenceManager refManager = currentProgram.getReferenceManager();
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        monitor.initialize(currentProgram.getFunctionManager().getFunctionCount());
        monitor.setMessage("Extracting Functions & XRefs...");

        while (functions.hasNext()) {
            if (monitor.isCancelled()) break;
            Function func = functions.next();
            monitor.incrementProgress(1);

            if (func.isThunk() || func.isExternal()) continue;

            FuncData fd = new FuncData();
            fd.name = func.getName();
            fd.entry = func.getEntryPoint().toString();

            // Decompile
            try {
                DecompileResults res = decompInterface.decompileFunction(func, 30, monitor);
                if (res != null && res.decompileCompleted()) {
                    fd.code = res.getDecompiledFunction().getC();
                } else {
                    fd.code = "// Decompilation failed";
                }
            } catch (Exception e) {
                fd.code = "// Decompilation exception: " + e.getMessage();
            }

            // XRefs: Callers (References TO the entry point of this function)
            Set<String> callerSet = new HashSet<>();
            ReferenceIterator refsTo = refManager.getReferencesTo(func.getEntryPoint());
            while (refsTo.hasNext()) {
                Reference ref = refsTo.next();
                if (ref.getReferenceType().isCall()) {
                    Address fromAddr = ref.getFromAddress();
                    Function caller = currentProgram.getFunctionManager().getFunctionContaining(fromAddr);
                    if (caller != null) {
                        callerSet.add(caller.getName());
                    } else {
                        callerSet.add("addr_" + fromAddr.toString());
                    }
                }
            }
            fd.callers = new ArrayList<>(callerSet);

            // XRefs: Callees (References FROM this function body TO other functions)
            Set<String> calleeSet = new HashSet<>();
            // Get all functions called by this function
            Set<Function> calledFuncs = func.getCalledFunctions(monitor);
            for (Function callee : calledFuncs) {
                 calleeSet.add(callee.getName());
            }
            fd.callees = new ArrayList<>(calleeSet);

            export.functions.add(fd);
        }

        // --- EXTRACT STRINGS ---
        monitor.setMessage("Extracting Strings...");
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