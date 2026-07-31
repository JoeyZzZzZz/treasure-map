// Copyright (C) 2025-2026 JoeyZzZzZz
// SPDX-License-Identifier: AGPL-3.0-only
//
// Headless BinExport: write the current program's BinExport2 protobuf to the path passed as the
// FIRST -postScript argument. Export half of the version-diff pipeline.
//
// ★ WHY THIS SCRIPT EXISTS (do not replace with the extension's own BinExport.java): that one is
// INTERACTIVE (askFile/askChoices), resolves answers from a sibling .properties the extension does
// not ship, and never calls getScriptArgs() -- so a path after -postScript is IGNORED. Under
// analyzeHeadless the askFile throws, the postScript aborts, yet analyzeHeadless STILL EXITS 0: a
// "successful" run that produced no file. This is the non-interactive equivalent -- the output path
// is an argument, and failure throws loudly.
//
// ★ NO IDA-compat options (no subtract-image-base / mnemonic remap / prepend-namespace). Addresses
// must stay Ghidra VIRTUAL addresses to align with the map's function addresses at layer-0 --
// verified against the reference fixture. Subtracting the image base would silently shift EVERY
// address and break alignment with no error.
//
// Requires the BinExport extension for its classes (Extensions/BinExport/lib/BinExport.jar).
//@category BinExport

import com.google.security.binexport.BinExport2Builder;
import com.google.security.zynamics.BinExport.BinExport2;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import java.io.File;
import java.io.FileOutputStream;

public class ExportBinExport extends GhidraScript {
  @Override
  protected void run() throws Exception {
    String[] args = getScriptArgs();
    if (args.length < 1 || args[0].isEmpty()) {
      printerr("ExportBinExport: missing output path (first -postScript argument)");
      throw new IllegalArgumentException("ExportBinExport: no output path argument");
    }
    Program program = currentProgram;
    if (program == null) {
      printerr("ExportBinExport: no current program (the -import step produced nothing)");
      throw new IllegalStateException("ExportBinExport: no current program");
    }
    File out = new File(args[0]);
    println("ExportBinExport: exporting " + program.getName() + " -> " + out.getAbsolutePath());
    BinExport2 proto = new BinExport2Builder(program, program.getMemory()).build();
    try (FileOutputStream os = new FileOutputStream(out)) {
      proto.writeTo(os);
    }
    if (!out.isFile() || out.length() == 0) {
      printerr("ExportBinExport: wrote no bytes to " + out.getAbsolutePath());
      throw new IllegalStateException("ExportBinExport: empty export");
    }
    println("ExportBinExport: wrote " + out.length() + " bytes");
  }
}
