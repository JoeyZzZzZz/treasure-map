// Copyright (C) 2026 JoeyZzZzZz
// SPDX-License-Identifier: Apache-2.0
//
// Creates a function for every basic block the analysis left outside any function, before the
// extraction runs — so the functions ExportFunctions writes and the functions the BinExport export
// later holds are one set, built once in this session.
//
// ★ A block already inside a function is skipped. Only the blocks no function contains are tried:
//   trying every block (as the BinExport builder's own promotion pass does) is far slower and can
//   carve a new function out of the middle of an existing one.
// ★ A created function takes Ghidra's default name (createFunction(entry, null) -> FUN_<addr>),
//   never a name derived from its address under another prefix: readers treat FUN_ names as
//   address-derived, any other name as a stable symbol.
// ★ The analysis is then re-run on what changed (analyzeChanges), so the new functions get their
//   references, signatures and the decompiler's view of the code that calls them.
//
// Prints one summary line: blocks tried, functions created, function counts.
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.UndefinedFunction;

public class PromoteUndefined extends GhidraScript {

  @Override
  protected void run() throws Exception {
    if (currentProgram == null) {
      printerr("[PromoteUndefined] no current program");
      return;
    }
    FunctionManager fm = currentProgram.getFunctionManager();
    int before = fm.getFunctionCount();
    int tried = 0;
    int created = 0;
    BasicBlockModel model = new BasicBlockModel(currentProgram, true);
    for (CodeBlockIterator it = model.getCodeBlocks(monitor); it.hasNext(); ) {
      if (monitor.isCancelled()) {
        break;
      }
      Address start = it.next().getFirstStartAddress();
      if (fm.getFunctionContaining(start) != null) {
        continue; // inside a function already (an external one included)
      }
      UndefinedFunction candidate = UndefinedFunction.findFunction(currentProgram, start, monitor);
      if (candidate == null) {
        continue;
      }
      tried++;
      if (createFunction(candidate.getEntryPoint(), null) != null) {
        created++;
      }
    }
    int afterCreate = fm.getFunctionCount();
    if (created > 0) {
      analyzeChanges(currentProgram);
    }
    println("[PromoteUndefined] tried=" + tried + " created=" + created + " functions_before="
        + before + " functions_after_create=" + afterCreate + " functions_after_analysis="
        + fm.getFunctionCount());
  }
}
