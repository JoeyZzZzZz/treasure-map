// ExportFunctions.java  -  Ghidra Headless Post-Script
//
// Exports from each analyzed binary:
//   1. All function pseudocode (skips thunks and externals)
//   2. Import symbols and their source libraries via ExternalManager
//   3. Export symbols (ELF external entry points)
//   4. Defined strings (length 5-300, filtered for noise)
//
// Environment variables:
//   OUTPUT_DIR  output directory (default /tmp/ghidra_output)
//   SHA8        first 8 chars of sha256, used to uniquify the output filename
//
// No external dependencies - JSON is built manually (no Gson).
// Tested on Ghidra 11.1.2

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class ExportFunctions extends GhidraScript {

    // Escape a string for JSON: handles control chars, quotes, backslashes
    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                case '\b': sb.append("\\b");  break;
                case '\f': sb.append("\\f");  break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    @Override
    public void run() throws Exception {

        // Read env vars
        String outputDir = System.getenv("OUTPUT_DIR");
        if (outputDir == null || outputDir.isEmpty()) {
            outputDir = "/tmp/ghidra_output";
        }
        String sha8 = System.getenv("SHA8");
        if (sha8 == null || sha8.isEmpty()) {
            // Batch mode: SHA8 env var is empty; compute from file content so the
            // output filename matches what the Python driver expects.
            try {
                java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
                String execPath = currentProgram.getExecutablePath();
                try (java.io.FileInputStream fis = new java.io.FileInputStream(execPath)) {
                    byte[] buf = new byte[65536];
                    int n;
                    while ((n = fis.read(buf)) != -1) md.update(buf, 0, n);
                }
                byte[] hashBytes = md.digest();
                StringBuilder hex = new StringBuilder(64);
                for (byte b : hashBytes) hex.append(String.format("%02x", b & 0xff));
                sha8 = hex.substring(0, 8);
            } catch (Exception ex) {
                sha8 = "00000000";
            }
        }

        String binaryName = currentProgram.getName();
        println("[ExportFunctions] start: binary=" + binaryName + " sha8=" + sha8);

        // Init decompiler
        DecompInterface decomp = new DecompInterface();
        DecompileOptions opts  = new DecompileOptions();
        opts.setMaxPayloadMBytes(64);   // prevent OOM on large files
        decomp.setOptions(opts);
        decomp.openProgram(currentProgram);

        FunctionManager  fm     = currentProgram.getFunctionManager();
        SymbolTable      st     = currentProgram.getSymbolTable();
        ExternalManager  extMgr = currentProgram.getExternalManager();

        // 1. Functions + pseudocode
        StringBuilder funcsJson = new StringBuilder("[");
        boolean firstFunc = true;
        int funcCount = 0;

        for (Function func : fm.getFunctions(true)) {
            if (monitor.isCancelled()) break;

            // Skip PLT thunks and external symbols (no real code body)
            if (func.isThunk() || func.isExternal()) continue;

            String funcName  = func.getName();
            String funcAddr  = func.getEntryPoint().toString();
            long   funcSize  = func.getBody().getNumAddresses();
            int    isExported = func.isGlobal() ? 1 : 0;

            // Skip micro-functions (< 10 bytes): trampolines, alignment stubs, etc.
            // Not worth decompiling; they carry no logic and slow down the batch.
            String pseudocode = "";
            if (funcSize < 10) {
                // Leave pseudocode empty — populate_db.py handles null pseudocode fine.
            } else try {
                DecompileResults dr = decomp.decompileFunction(func, 20, monitor);
                if (dr != null && dr.decompileCompleted()) {
                    DecompiledFunction df = dr.getDecompiledFunction();
                    if (df != null) {
                        pseudocode = df.getC();
                    }
                }
            } catch (Exception e) {
                pseudocode = "/* decompile_error: " + e.getMessage() + " */";
            }  // end if (funcSize >= 10)

            // Collect callee names (up to 200) via CALL-type references
            // Using ReferenceManager instead of getCalledFunctions() for OSGi compatibility
            StringBuilder calleesArr = new StringBuilder("[");
            boolean firstCallee = true;
            int calleeCount = 0;
            try {
                ReferenceManager refMgr = currentProgram.getReferenceManager();
                Set<String> seenCallees = new HashSet<>();
                InstructionIterator instrIter =
                    currentProgram.getListing().getInstructions(func.getBody(), true);
                while (instrIter.hasNext() && calleeCount < 200) {
                    Instruction instr = instrIter.next();
                    Reference[] refs = refMgr.getReferencesFrom(instr.getAddress());
                    for (Reference ref : refs) {
                        if (!ref.getReferenceType().isCall()) continue;
                        Function callee = fm.getFunctionAt(ref.getToAddress());
                        if (callee == null) continue;
                        String calleeName = callee.getName();
                        if (!seenCallees.add(calleeName)) continue;
                        if (!firstCallee) calleesArr.append(",");
                        firstCallee = false;
                        calleesArr.append("\"").append(esc(calleeName)).append("\"");
                        calleeCount++;
                    }
                }
            } catch (Exception ignored) {}
            calleesArr.append("]");

            if (!firstFunc) funcsJson.append(",");
            firstFunc = false;
            funcsJson.append("{")
                     .append("\"name\":")        .append("\"").append(esc(funcName))  .append("\",")
                     .append("\"address\":")     .append("\"").append(esc(funcAddr))  .append("\",")
                     .append("\"size\":")        .append(funcSize).append(",")
                     .append("\"is_exported\":") .append(isExported).append(",")
                     .append("\"callees\":")     .append(calleesArr).append(",")
                     .append("\"pseudocode\":")  .append("\"").append(esc(pseudocode)).append("\"")
                     .append("}");
            funcCount++;
        }
        funcsJson.append("]");
        println("[ExportFunctions] functions: " + funcCount);

        // 2. Import symbols (via ExternalManager, for accurate library names)
        StringBuilder importsJson = new StringBuilder("[");
        boolean firstImp = true;

        String[] libNames = extMgr.getExternalLibraryNames();
        for (String libName : libNames) {
            // Skip Ghidra internal placeholder library
            if (libName == null || "<EXTERNAL>".equals(libName)) continue;

            ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
            while (iter.hasNext()) {
                ExternalLocation loc   = iter.next();
                String           label = loc.getLabel();
                if (label == null || label.isEmpty()) continue;

                if (!firstImp) importsJson.append(",");
                firstImp = false;
                importsJson.append("{")
                           .append("\"func_name\":\"").append(esc(label))  .append("\",")
                           .append("\"lib_name\":\""  ).append(esc(libName)).append("\"")
                           .append("}");
            }
        }
        importsJson.append("]");

        // 3. Export symbols (ELF external entry points)
        StringBuilder exportsJson = new StringBuilder("[");
        boolean firstExp = true;

        AddressIterator entryPts = st.getExternalEntryPointIterator();
        while (entryPts.hasNext()) {
            Address addr = entryPts.next();
            Symbol  sym  = st.getPrimarySymbol(addr);
            if (sym == null) continue;

            if (!firstExp) exportsJson.append(",");
            firstExp = false;
            exportsJson.append("{")
                       .append("\"func_name\":\"").append(esc(sym.getName()))  .append("\",")
                       .append("\"address\":\""   ).append(esc(addr.toString())).append("\"")
                       .append("}");
        }
        exportsJson.append("]");

        // 4. Strings from Ghidra defined Data (up to 2000 entries)
        StringBuilder stringsJson = new StringBuilder("[");
        boolean firstStr = true;
        int     strCount = 0;
        final int STR_LIMIT = 2000;

        DataIterator dataIter = currentProgram.getListing().getDefinedData(true);
        while (dataIter.hasNext() && strCount < STR_LIMIT) {
            if (monitor.isCancelled()) break;

            Data   data   = dataIter.next();
            String dtName = data.getDataType().getName().toLowerCase();

            // Only process string types
            if (!dtName.contains("string") && !dtName.contains("unicode")) continue;

            // Prefer getValue() for the raw string
            String val = null;
            try {
                Object vObj = data.getValue();
                if (vObj instanceof String) {
                    val = (String) vObj;
                }
            } catch (Exception ignored) {}

            // Fall back to representation, stripping outer quotes
            if (val == null) {
                String repr = data.getDefaultValueRepresentation();
                if (repr == null) continue;
                if (repr.startsWith("\"") && repr.endsWith("\"") && repr.length() > 2) {
                    val = repr.substring(1, repr.length() - 1);
                } else {
                    val = repr;
                }
            }

            // Filter: length 5-300, must contain at least one letter/digit/path char
            if (val.length() < 5 || val.length() > 300) continue;
            if (!val.matches(".*[a-zA-Z0-9/._\\-].*")) continue;

            if (!firstStr) stringsJson.append(",");
            firstStr = false;
            stringsJson.append("{")
                       .append("\"value\":\""  ).append(esc(val))                       .append("\",")
                       .append("\"address\":\"").append(esc(data.getAddress().toString())).append("\"")
                       .append("}");
            strCount++;
        }
        stringsJson.append("]");
        println("[ExportFunctions] strings: " + strCount);

        // 5. Write JSON output file — atomically.
        // Write to a .tmp sibling first, then ATOMIC_MOVE into place so an
        // interrupted JVM (killpg on timeout / OOM) can never leave a partial
        // file that 05_populate_db.py would mistake for a complete export.
        new File(outputDir).mkdirs();
        String outFileName = binaryName + "_" + sha8 + "_ghidra.json";
        String outPath     = outputDir + "/" + outFileName;
        String tmpPath     = outPath + ".tmp";

        try (PrintWriter pw = new PrintWriter(
                new OutputStreamWriter(new FileOutputStream(tmpPath), "UTF-8"))) {
            pw.print("{");
            pw.print("\"binary\":\"" + esc(binaryName) + "\",");
            pw.print("\"functions\":"  + funcsJson   + ",");
            pw.print("\"imports\":"    + importsJson  + ",");
            pw.print("\"exports\":"    + exportsJson  + ",");
            pw.print("\"strings\":"    + stringsJson);
            pw.print("}");
        }
        try {
            Files.move(Paths.get(tmpPath), Paths.get(outPath),
                       StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            // Fall back to a plain replace if the filesystem can't do atomic rename.
            Files.move(Paths.get(tmpPath), Paths.get(outPath),
                       StandardCopyOption.REPLACE_EXISTING);
        }

        println("[ExportFunctions] done: " + outPath);
    }
}
