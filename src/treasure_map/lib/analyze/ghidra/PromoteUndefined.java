// Copyright (C) 2026 JoeyZzZzZz
// SPDX-License-Identifier: Apache-2.0
//
// Creates a function for every code block the analysis left outside any function, before the
// extraction runs — so the functions ExportFunctions writes and the functions the BinExport export
// later holds are one set, built once in this session.
//
// ★ The blocks are found by walking every INSTRUCTION, never with the program-wide block iterator
//   (BasicBlockModel.getCodeBlocks). That iterator gives up on a whole address range when it asks a
//   block start of an instruction the block model does not count as one (a labelled MIPS delay
//   slot makes the instruction after it a start of no block), so it can silently skip most of a
//   binary. getCodeBlocksContaining(set) rests on the same iterator and fails the same way. The
//   instructions are collected first and the listing changed only after.
// ★ A block already inside a function is skipped. Only the blocks no function contains are tried:
//   trying every block (as the BinExport builder's own promotion pass does) is far slower and can
//   carve a new function out of the middle of an existing one.
// ★ A created function takes Ghidra's default name (createFunction(entry, null) -> FUN_<addr>),
//   never a name derived from its address under another prefix: readers treat FUN_ names as
//   address-derived, any other name as a stable symbol.
// ★ The analysis is then re-run on what changed (analyzeChanges), so the new functions get their
//   references, signatures and the decompiler's view of the code that calls them.
// ★ Self-check, after that: every instruction still in no function is counted, by kind —
//     start     the start of a code block that findFunction did not turn into a function;
//     interior  inside such a block;
//     unowned   in no code block the block model gives for it (getCodeBlockAt null, and outside
//               the [min, max] of the block getFirstCodeBlockContaining returns) —
//   and merged into runs of contiguous addresses (at most RANGE_CAP, then truncated).
// ★ What it did stays in this session's program for ExportFunctions to write out: a bookmark
//   (BOOKMARK_CATEGORY) on each entry it created, and the counts and ranges as program options
//   (OPTIONS_CATEGORY). Written only when the pass ran to the end: a cancelled pass leaves no
//   options, which the export then reports as not recorded rather than as zero.
//
// Prints one summary line: tried, created, function counts, residual kinds and range count.
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.util.UndefinedFunction;

import java.util.ArrayList;
import java.util.List;

public class PromoteUndefined extends GhidraScript {

  // ExportFunctions reads these under the same spelling (its PROMOTE_* constants).
  static final String OPTIONS_CATEGORY = "TreasureMap PromoteUndefined";
  static final String BOOKMARK_CATEGORY = "TreasureMap promoted";
  static final int RANGE_CAP = 4096;

  @Override
  protected void run() throws Exception {
    if (currentProgram == null) {
      printerr("[PromoteUndefined] no current program");
      return;
    }
    FunctionManager fm = currentProgram.getFunctionManager();
    BookmarkManager bm = currentProgram.getBookmarkManager();
    int before = fm.getFunctionCount();
    BasicBlockModel model = new BasicBlockModel(currentProgram, true);

    // 1. Collect the block starts no function contains (no listing change while iterating).
    List<Address> starts = new ArrayList<>();
    InstructionIterator ii = currentProgram.getListing().getInstructions(true);
    while (ii.hasNext()) {
      if (monitor.isCancelled()) {
        return; // nothing recorded: the export reports the pass as not recorded
      }
      Address a = ii.next().getMinAddress();
      if (fm.getFunctionContaining(a) == null && model.getCodeBlockAt(a, monitor) != null) {
        starts.add(a);
      }
    }

    // 2. Promote them in address order.
    int tried = 0;
    int created = 0;
    for (Address a : starts) {
      if (monitor.isCancelled()) {
        return;
      }
      if (fm.getFunctionContaining(a) != null) {
        continue; // swallowed by a function created earlier in this loop
      }
      UndefinedFunction candidate = UndefinedFunction.findFunction(currentProgram, a, monitor);
      if (candidate == null) {
        continue;
      }
      tried++;
      Function fn = createFunction(candidate.getEntryPoint(), null);
      if (fn != null) {
        created++;
        bm.setBookmark(fn.getEntryPoint(), BookmarkType.INFO, BOOKMARK_CATEGORY, "created");
      }
    }
    int afterCreate = fm.getFunctionCount();
    if (created > 0) {
      analyzeChanges(currentProgram);
    }

    // 3. Self-check on the final state (what the export will see), with a fresh block model.
    BasicBlockModel check = new BasicBlockModel(currentProgram, true);
    long resStart = 0;
    long resInterior = 0;
    long resUnowned = 0;
    StringBuilder ranges = new StringBuilder("[");
    int rangeCount = 0;
    boolean truncated = false;
    Address runLo = null;
    Address runHi = null;
    ii = currentProgram.getListing().getInstructions(true);
    while (ii.hasNext()) {
      if (monitor.isCancelled()) {
        return;
      }
      Instruction insn = ii.next();
      Address a = insn.getMinAddress();
      if (fm.getFunctionContaining(a) != null) {
        continue;
      }
      if (check.getCodeBlockAt(a, monitor) != null) {
        resStart++;
      } else {
        CodeBlock owner = check.getFirstCodeBlockContaining(a, monitor);
        if (owner != null && owner.getMinAddress().compareTo(a) <= 0
            && owner.getMaxAddress().compareTo(a) >= 0) {
          resInterior++;
        } else {
          resUnowned++;
        }
      }
      Address hi = insn.getMaxAddress();
      if (runHi != null && isNext(runHi, a)) {
        runHi = hi;
        continue;
      }
      if (runLo != null) {
        if (rangeCount < RANGE_CAP) {
          appendRange(ranges, rangeCount, runLo, runHi);
          rangeCount++;
        } else {
          truncated = true;
        }
      }
      runLo = a;
      runHi = hi;
    }
    if (runLo != null) {
      if (rangeCount < RANGE_CAP) {
        appendRange(ranges, rangeCount, runLo, runHi);
        rangeCount++;
      } else {
        truncated = true;
      }
    }
    ranges.append("]");

    Options opts = currentProgram.getOptions(OPTIONS_CATEGORY);
    opts.setInt("tried", tried);
    opts.setInt("created", created);
    opts.setLong("residual_start", resStart);
    opts.setLong("residual_interior", resInterior);
    opts.setLong("residual_unowned", resUnowned);
    opts.setString("residual_ranges", ranges.toString());
    opts.setBoolean("residual_ranges_truncated", truncated);
    opts.setBoolean("recorded", true);

    println("[PromoteUndefined] tried=" + tried + " created=" + created + " functions_before="
        + before + " functions_after_create=" + afterCreate + " functions_after_analysis="
        + fm.getFunctionCount() + " residual_insns=" + (resStart + resInterior + resUnowned)
        + " residual_start=" + resStart + " residual_interior=" + resInterior
        + " residual_unowned=" + resUnowned + " residual_ranges=" + rangeCount
        + (truncated ? " residual_ranges_truncated" : ""));
  }

  /** True when {@code next} is the address right after {@code hi} in the same address space. */
  private static boolean isNext(Address hi, Address next) {
    if (!hi.getAddressSpace().equals(next.getAddressSpace())) {
      return false;
    }
    return next.getOffset() == hi.getOffset() + 1;
  }

  private static void appendRange(StringBuilder out, int index, Address lo, Address hi) {
    if (index > 0) {
      out.append(",");
    }
    out.append("[\"0x").append(Long.toHexString(lo.getOffset())).append("\",\"0x")
        .append(Long.toHexString(hi.getOffset())).append("\"]");
  }
}
