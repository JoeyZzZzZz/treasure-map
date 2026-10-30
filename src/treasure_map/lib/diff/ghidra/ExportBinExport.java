// Copyright (C) 2026 JoeyZzZzZz
// SPDX-License-Identifier: Apache-2.0
//
// Headless BinExport: write the current program's BinExport2 protobuf to the path passed as the
// FIRST -postScript argument, and a JSON report of what the export could not represent to the
// SECOND. Export half of the version-diff pipeline.
//
// ★ TWO MODES, by the optional THIRD argument:
//   - "scan": the export a scan writes in the same session as its extraction, after PromoteUndefined
//     and ExportFunctions. FallbackBinExport2Builder is the only builder, with its own promotion
//     pass OFF: the session has already created the functions, and the export must hold exactly the
//     functions the extraction wrote. builder = "fallback".
//   - anything else (absent): a standalone export of a freshly analysed program. The extension's
//     own builder first (it promotes undefined functions itself); FallbackBinExport2Builder, with
//     promotion on, only when that builder fails on a missing block index.
// Both files are written under a .tmp name and then moved into place, the report first: a run
// killed part way leaves no export file behind that reads as complete.
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
// ★ TWO REPAIRS, each limited to what BinDiff cannot load:
//   1. The extension's builder fails on a basic block that a function body yields but the
//      program-wide block iteration did not (it indexes blocks before it promotes undefined
//      functions, and looks the block up without a null check). FallbackBinExport2Builder (a
//      modified copy of the extension's builder) does not; the functions holding a degenerate block
//      are listed in the report, and so are the instructions whose operand markup it had to write
//      in its default form (operand_markup_degraded).
//   2. Every export is then checked for two kinds of flow graph BinDiff rejects, and repaired:
//      (a) a flow graph whose entry instruction carries no explicit address (BinDiff reads the
//          flow graph's address from that field, so it reads 0): the address the reader would
//          derive is written explicitly -- same address, so the program is unchanged;
//      (b) a flow graph with no entry basic block index (the function's entry is not the start of
//          any of its blocks): the flow graph is removed and its function listed in the report.
//      An export with neither is written exactly as the builder produced it.
//
// Requires the BinExport extension for its classes (Extensions/BinExport/lib/BinExport.jar).
//@category BinExport

import com.google.security.binexport.BinExport2Builder;
import com.google.security.zynamics.BinExport.BinExport2;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

public class ExportBinExport extends GhidraScript {

  /** What the flow-graph repair changed. */
  private static final class Repair {
    BinExport2 proto;
    int entryAddressesAdded = 0;
    final TreeSet<Long> droppedFunctions = new TreeSet<>();
  }

  /**
   * The extension builder's failure on a basic block missing from its index: a NullPointerException
   * raised in BinExport2Builder.buildFlowGraphs while unboxing the result of a map lookup. Any other
   * failure is something else and is left to propagate.
   */
  private static boolean isMissingBlockIndex(NullPointerException e) {
    StackTraceElement[] st = e.getStackTrace();
    if (st.length == 0) {
      return false;
    }
    String msg = String.valueOf(e.getMessage());
    return st[0].getClassName().equals(BinExport2Builder.class.getName())
        && st[0].getMethodName().equals("buildFlowGraphs")
        && msg.contains("Map.get(Object)");
  }

  /**
   * The entry point of the function each flow graph was built for, in flow-graph order. Mirrors the
   * builders' iteration: every function in address order, skipping one whose entry is not in loaded
   * memory or whose body yields no basic block.
   */
  private List<Address> flowGraphOwners(Program program) throws Exception {
    List<Address> owners = new ArrayList<>();
    BasicBlockModel model = new BasicBlockModel(program, true);
    for (Function func : program.getFunctionManager().getFunctions(true)) {
      if (func.getEntryPoint().isNonLoadedMemoryAddress()) {
        continue;
      }
      if (!model.getCodeBlocksContaining(func.getBody(), monitor).hasNext()) {
        continue;
      }
      owners.add(func.getEntryPoint());
    }
    return owners;
  }

  private Repair repairFlowGraphs(BinExport2 proto, Program program) throws Exception {
    Repair r = new Repair();
    r.proto = proto;
    int nInstr = proto.getInstructionCount();
    // The address a reader derives for each instruction: its own when present, else the previous
    // instruction's address plus that instruction's size.
    long[] addr = new long[nInstr];
    long prev = 0;
    int prevSize = 0;
    for (int i = 0; i < nInstr; i++) {
      BinExport2.Instruction ins = proto.getInstruction(i);
      addr[i] = ins.hasAddress() ? ins.getAddress() : prev + prevSize;
      prev = addr[i];
      prevSize = ins.getRawBytes().size();
    }
    Set<Integer> needAddress = new HashSet<>();
    List<Integer> noEntry = new ArrayList<>();
    for (int f = 0; f < proto.getFlowGraphCount(); f++) {
      BinExport2.FlowGraph fg = proto.getFlowGraph(f);
      if (!fg.hasEntryBasicBlockIndex()) {
        noEntry.add(f);
        continue;
      }
      int first = entryInstruction(proto, fg);
      if (!proto.getInstruction(first).hasAddress()) {
        needAddress.add(first);
        r.entryAddressesAdded++;
      }
    }
    if (needAddress.isEmpty() && noEntry.isEmpty()) {
      return r; // nothing BinDiff rejects: the builder's output, untouched
    }
    // Attribute every flow graph to its function, and check the attribution against each entry the
    // export does record: a flow graph is never charged to the wrong function.
    List<Address> owners = flowGraphOwners(program);
    if (owners.size() != proto.getFlowGraphCount()) {
      throw new IllegalStateException(
          "ExportBinExport: " + proto.getFlowGraphCount() + " flow graphs but " + owners.size()
              + " functions with a body; cannot attribute the flow graphs to functions");
    }
    for (int f = 0; f < proto.getFlowGraphCount(); f++) {
      BinExport2.FlowGraph fg = proto.getFlowGraph(f);
      if (fg.hasEntryBasicBlockIndex()
          && addr[entryInstruction(proto, fg)] != owners.get(f).getOffset()) {
        throw new IllegalStateException(
            "ExportBinExport: flow graph " + f + " starts at 0x"
                + Long.toHexString(addr[entryInstruction(proto, fg)]) + " but its function at "
                + owners.get(f) + "; cannot attribute the flow graphs to functions");
      }
    }
    BinExport2.Builder b = proto.toBuilder();
    for (int i : needAddress) {
      b.getInstructionBuilder(i).setAddress(addr[i]);
    }
    if (!noEntry.isEmpty()) {
      Set<Integer> drop = new HashSet<>(noEntry);
      List<BinExport2.FlowGraph> keep = new ArrayList<>();
      for (int f = 0; f < proto.getFlowGraphCount(); f++) {
        if (drop.contains(f)) {
          r.droppedFunctions.add(owners.get(f).getOffset());
        } else {
          keep.add(proto.getFlowGraph(f));
        }
      }
      b.clearFlowGraph().addAllFlowGraph(keep);
    }
    r.proto = b.build();
    return r;
  }

  private static int entryInstruction(BinExport2 proto, BinExport2.FlowGraph fg) {
    return proto.getBasicBlock(fg.getEntryBasicBlockIndex()).getInstructionIndex(0).getBeginIndex();
  }

  private static String jsonList(Collection<Long> values) {
    StringBuilder sb = new StringBuilder("[");
    for (long v : values) {
      if (sb.length() > 1) {
        sb.append(", ");
      }
      sb.append(Long.toUnsignedString(v));
    }
    return sb.append(']').toString();
  }

  /**
   * Moves {@code from} onto {@code to}: a rename within one directory, which replaces the target
   * in one step on POSIX. A failed rename throws (the export then reads as failed).
   */
  private static void moveIntoPlace(File from, File to) {
    if (!from.renameTo(to)) {
      throw new IllegalStateException("ExportBinExport: cannot move " + from + " to " + to);
    }
  }

  @Override
  protected void run() throws Exception {
    String[] args = getScriptArgs();
    if (args.length < 2 || args[0].isEmpty() || args[1].isEmpty()) {
      printerr("ExportBinExport: needs the output path and the report path (-postScript arguments)");
      throw new IllegalArgumentException("ExportBinExport: missing output or report path argument");
    }
    Program program = currentProgram;
    if (program == null) {
      printerr("ExportBinExport: no current program (the -import step produced nothing)");
      throw new IllegalStateException("ExportBinExport: no current program");
    }
    File out = new File(args[0]);
    File report = new File(args[1]);
    boolean scanMode = args.length > 2 && "scan".equals(args[2]);
    println("ExportBinExport: exporting " + program.getName() + " -> " + out.getAbsolutePath()
        + (scanMode ? " (scan mode)" : ""));
    int functionsBefore = program.getFunctionManager().getFunctionCount();
    BinExport2 proto = null;
    String builderUsed = "extension";
    Collection<Long> degenerate = new TreeSet<>();
    Collection<Long> degradedInstructions = new TreeSet<>();
    Collection<Long> degradedFunctions = new TreeSet<>();
    boolean useFallback = scanMode;
    if (!scanMode) {
      try {
        proto = new BinExport2Builder(program, program.getMemory()).build();
      } catch (NullPointerException e) {
        if (!isMissingBlockIndex(e)) {
          throw e;
        }
        println("ExportBinExport: the extension's builder missed a basic block in its index ("
            + e.getMessage() + "); rebuilding with FallbackBinExport2Builder");
        useFallback = true;
      }
    }
    if (useFallback) {
      FallbackBinExport2Builder fallback =
          new FallbackBinExport2Builder(program, program.getMemory())
              .setPromoteUndefined(!scanMode);
      proto = fallback.build();
      degenerate = fallback.getDegenerateFunctionEntries();
      degradedInstructions = fallback.getOperandMarkupDegradedInstructions();
      degradedFunctions = fallback.getOperandMarkupDegradedFunctions();
      builderUsed = "fallback";
    }
    int functionsAfter = program.getFunctionManager().getFunctionCount();
    Repair repair = repairFlowGraphs(proto, program);
    String json = "{\"builder\": \"" + builderUsed + "\""
        + ", \"mode\": \"" + (scanMode ? "scan" : "standalone") + "\""
        + ", \"functions_before_build\": " + functionsBefore
        + ", \"functions_after_build\": " + functionsAfter
        + ", \"entry_addresses_added\": " + repair.entryAddressesAdded
        + ", \"flow_graphs_dropped\": " + repair.droppedFunctions.size()
        + ", \"dropped_functions\": " + jsonList(repair.droppedFunctions)
        + ", \"degenerate_functions\": " + jsonList(degenerate)
        + ", \"operand_markup_degraded\": {\"instructions\": " + degradedInstructions.size()
        + ", \"instruction_addresses\": " + jsonList(degradedInstructions)
        + ", \"functions\": " + jsonList(degradedFunctions) + "}}\n";
    File reportTmp = new File(report.getPath() + ".tmp");
    File outTmp = new File(out.getPath() + ".tmp");
    try (FileOutputStream rs = new FileOutputStream(reportTmp)) {
      rs.write(json.getBytes("UTF-8"));
    }
    try (FileOutputStream os = new FileOutputStream(outTmp)) {
      repair.proto.writeTo(os);
    }
    if (!outTmp.isFile() || outTmp.length() == 0) {
      printerr("ExportBinExport: wrote no bytes to " + outTmp.getAbsolutePath());
      throw new IllegalStateException("ExportBinExport: empty export");
    }
    // The report first: an export file without its report is never left behind as complete.
    moveIntoPlace(reportTmp, report);
    moveIntoPlace(outTmp, out);
    println("ExportBinExport: wrote " + out.length() + " bytes; builder=" + builderUsed
        + " functions=" + functionsBefore + "->" + functionsAfter
        + " entry_addresses_added=" + repair.entryAddressesAdded
        + " flow_graphs_dropped=" + repair.droppedFunctions.size()
        + " degenerate_functions=" + degenerate.size()
        + " operand_markup_degraded=" + degradedInstructions.size() + "/"
        + degradedFunctions.size());
  }
}
