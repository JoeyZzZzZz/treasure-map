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
//
// Order in this one session, after Ghidra's own analysis (each step runs on what the one before it
// left — recording the counts at any earlier step would record a stale state):
//   1. Promote the leftover blocks (above), then analyzeChanges so the new functions get their
//      references, signatures and the decompiler's view of the code that calls them.
//   2. W14 — recover functions reached ONLY through pointers in the binary's own data (callback /
//      command / applet tables), which no code calls directly, so Ghidra never disassembled them.
//      Each pass seeds from every non-flow reference target and every aligned data word pointing
//      into executable memory where nothing sits yet, disassembles following flow, and makes a
//      function there unless the disassembly raised an error (then it is cleared again — rejected).
//      ★ Before any disassembly, a seed is refused when it lies above the top of the code Ghidra's
//      own analysis made into functions (taken before this script creates anything; with no such
//      function every seed is refused), or when its bytes read as a C string. Both are data the
//      analysis left in executable memory; disassembling them made functions out of strings.
//      ★ No-return discovery is FROZEN for the whole of W14 and the second promotion: without it,
//      re-analysis can newly, wrongly mark an existing command-wrapper non-returning and then
//      delete every instruction after each call to it. The original value is restored at the end.
//   3. A second block promotion (step 1's logic again, still frozen): W14's analysis can leave the
//      callees of a recovered function as bare blocks outside any function.
//   4. Self-check on the FINAL state (what the export will see):
//        - every instruction still in no function, by kind (start / interior / unowned), merged
//          into runs of contiguous addresses (at most RANGE_CAP, then truncated);
//        - W11 — the executable bytes Ghidra never disassembled at all: the undefined ranges of
//          executable memory >= UNDEFINED_MIN bytes (below that is inter-function alignment
//          padding). A function whose counterpart maps into one of these is code the other side's
//          analysis never built — a gap, not a determined "no such function";
//        - W14's guard counts: the existing code lost and the existing functions newly marked
//          non-returning. Both must be 0 by design; a positive count names the binary.
// ★ What it did stays in this session's program for ExportFunctions to write out: a bookmark on
//   each entry it created (BOOKMARK_CATEGORY for a promoted block, RECOVERED_BOOKMARK for a W14
//   recovery, so a reader can tell origin='promoted' from origin='recovered'), and the counts and
//   ranges as program options (OPTIONS_CATEGORY). Written only when the pass ran to the end: a
//   cancelled pass leaves no options, which the export then reports as not recorded rather than as
//   zero.
//
// Prints one summary line: tried, created (the genuinely-new functions — see promoteBlocks), the
// per-pass breakdown (pass1_created is the old raw count of every non-null createFunction return,
// kept only so A4 can compare it to the r6 single-pass log), function counts, residual kinds, range
// counts and the recovery counts.
//@category Analysis

import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.UndefinedFunction;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class PromoteUndefined extends GhidraScript {

  // ExportFunctions reads these under the same spelling (its PROMOTE_* constants).
  static final String OPTIONS_CATEGORY = "TreasureMap PromoteUndefined";
  static final String BOOKMARK_CATEGORY = "TreasureMap promoted";
  static final String RECOVERED_BOOKMARK = "TreasureMap recovered";
  static final int RANGE_CAP = 4096;
  // Shorter undefined runs are inter-function alignment padding, not missed code.
  static final int UNDEFINED_MIN = 16;
  static final int RECOVER_MAX_PASSES = 30;
  // A seed whose bytes read as a C string (this many printable bytes, then NUL, within the probe)
  // is data the analysis placed in executable memory, not an entry point.
  static final int STRING_PROBE_BYTES = 64;
  static final int STRING_MIN_PRINTABLE = 4;
  static final String NO_RETURN_OPTION = "Non-Returning Functions - Discovered";

  private FunctionManager fm;
  private BookmarkManager bm;

  @Override
  protected void run() throws Exception {
    if (currentProgram == null) {
      printerr("[PromoteUndefined] no current program");
      return;
    }
    fm = currentProgram.getFunctionManager();
    bm = currentProgram.getBookmarkManager();
    int before = fm.getFunctionCount();
    // The top of the code Ghidra's own analysis made into functions, taken HERE — before any
    // function this script creates — so nothing this script makes can raise it. W14 seeds nothing
    // above it; null (no function at all) makes W14 seed nothing.
    Address nativeCeiling = maxFunctionBodyEnd();

    // 1. Promote the code blocks no function contains, then re-analyse (nothing recorded on cancel).
    int[] p1 = promoteBlocks();
    if (p1 == null) {
      return;
    }
    if (p1[2] > 0) { // re-analyse whenever createFunction was applied (raw count), as before
      analyzeChanges(currentProgram);
    }

    // 2. W14 — recover functions reached only through pointers in the binary's data. The state the
    //    guard compares against is taken HERE (after step 1), before no-return discovery is frozen.
    AddressSet exec = executableSet();
    AddressSet data = dataSet();
    AddressSet insnBefore = instructionsIn(exec);
    Set<Address> funcsBefore = functionEntries();
    Set<Address> nrBefore = noReturnEntries();
    String nrWas = freezeNoReturn();
    // {recovered, rejected, seeds, above_native, rejected_string}
    long[] rec = {0, 0, 0, 0, 0};
    if (recoverFromPointers(exec, data, nativeCeiling, rec)) {
      restoreNoReturn(nrWas);
      return; // cancelled: nothing recorded
    }

    // 3. A second block promotion (still frozen): W14's analysis can leave recovered callees bare.
    int[] p2 = promoteBlocks();
    if (p2 == null) {
      restoreNoReturn(nrWas);
      return;
    }
    if (p2[2] > 0) { // raw count, as above
      analyzeChanges(currentProgram);
    }
    int tried = p1[0] + p2[0];
    int created = p1[1] + p2[1]; // genuinely-new functions across both passes (stored; MAJOR-2)
    int afterCreate = fm.getFunctionCount();

    // 4a. Residual self-check on the final state (what the export will see), with a fresh model.
    BasicBlockModel check = new BasicBlockModel(currentProgram, true);
    long resStart = 0;
    long resInterior = 0;
    long resUnowned = 0;
    StringBuilder ranges = new StringBuilder("[");
    int rangeCount = 0;
    boolean truncated = false;
    Address runLo = null;
    Address runHi = null;
    InstructionIterator ii = currentProgram.getListing().getInstructions(true);
    while (ii.hasNext()) {
      if (monitor.isCancelled()) {
        restoreNoReturn(nrWas);
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

    // 4b. W11 — the executable bytes Ghidra never disassembled (undefined ranges >= UNDEFINED_MIN).
    AddressSetView undef = currentProgram.getListing().getUndefinedRanges(exec, true, monitor);
    StringBuilder uRanges = new StringBuilder("[");
    int uCount = 0;
    boolean uTruncated = false;
    long uBytes = 0;
    for (AddressRange r : undef) {
      if (r.getLength() < UNDEFINED_MIN) {
        continue;
      }
      uBytes += r.getLength();
      if (uCount < RANGE_CAP) {
        appendRange(uRanges, uCount, r.getMinAddress(), r.getMaxAddress());
        uCount++;
      } else {
        uTruncated = true;
      }
    }
    uRanges.append("]");

    // 4c. W14 guard — existing code lost and existing functions newly non-returning (both 0 by
    //     design; a positive count means the freeze did not hold and names the binary in the log).
    AddressSet lost = insnBefore.subtract(instructionsIn(exec));
    long recoverLostBytes = lost.getNumAddresses();
    int recoverNoReturnFlips = 0;
    for (Function f : fm.getFunctions(true)) {
      Address e = f.getEntryPoint();
      if (f.hasNoReturn() && funcsBefore.contains(e) && !nrBefore.contains(e)) {
        recoverNoReturnFlips++;
      }
    }

    // 5. Record everything in one options write (only now, on the final state).
    Options opts = currentProgram.getOptions(OPTIONS_CATEGORY);
    opts.setInt("tried", tried);
    opts.setInt("created", created);
    opts.setLong("residual_start", resStart);
    opts.setLong("residual_interior", resInterior);
    opts.setLong("residual_unowned", resUnowned);
    opts.setString("residual_ranges", ranges.toString());
    opts.setBoolean("residual_ranges_truncated", truncated);
    opts.setString("undefined_ranges", uRanges.toString());
    opts.setBoolean("undefined_ranges_truncated", uTruncated);
    opts.setLong("undefined_bytes", uBytes);
    opts.setInt("recovered", (int) rec[0]);
    opts.setInt("recover_rejected", (int) rec[1]);
    opts.setInt("recover_seeds", (int) rec[2]);
    opts.setInt("recover_rejected_string", (int) rec[4]);
    opts.setLong("recover_lost_insn_bytes", recoverLostBytes);
    opts.setInt("recover_noreturn_flips", recoverNoReturnFlips);
    opts.setBoolean("recorded", true);

    // 6. Restore no-return discovery to what it was before W14.
    restoreNoReturn(nrWas);

    println("[PromoteUndefined] tried=" + tried + " created=" + created + " pass1_tried=" + p1[0]
        + " pass1_created=" + p1[2] + " pass2_created=" + p2[1] + " functions_before="
        + before + " functions_after_create=" + afterCreate + " functions_after_analysis="
        + fm.getFunctionCount() + " residual_insns=" + (resStart + resInterior + resUnowned)
        + " residual_start=" + resStart + " residual_interior=" + resInterior
        + " residual_unowned=" + resUnowned + " residual_ranges=" + rangeCount
        + (truncated ? " residual_ranges_truncated" : "") + " undefined_ranges=" + uCount
        + " undefined_bytes=" + uBytes + (uTruncated ? " undefined_ranges_truncated" : "")
        + " recovered=" + rec[0] + " recover_rejected=" + rec[1] + " recover_seeds=" + rec[2]
        + " recover_above_native=" + rec[3] + " recover_rejected_string=" + rec[4]
        + " native_ceiling=" + (nativeCeiling == null ? "none" : nativeCeiling.toString())
        + " recover_lost_insn_bytes=" + recoverLostBytes + " recover_noreturn_flips="
        + recoverNoReturnFlips);
  }

  /**
   * The highest address of any function body in executable memory, or null when there is none.
   * External functions do not count, and neither do the import thunks the ELF loader places in its
   * EXTERNAL block past the end of the image (they are not external functions themselves, and
   * counting them would put the ceiling above every byte of the binary).
   */
  private Address maxFunctionBodyEnd() {
    Memory mem = currentProgram.getMemory();
    Address max = null;
    for (Function f : fm.getFunctions(true)) {
      if (f.isExternal()) {
        continue;
      }
      Address hi = f.getBody().getMaxAddress();
      if (hi == null || !hi.isMemoryAddress()) {
        continue;
      }
      MemoryBlock block = mem.getBlock(hi);
      if (block == null || block.isExternalBlock() || !block.isExecute()) {
        continue;
      }
      if (max == null || hi.compareTo(max) > 0) {
        max = hi;
      }
    }
    return max;
  }

  /**
   * True when the bytes at {@code a} read as a C string: at least STRING_MIN_PRINTABLE printable
   * ASCII bytes followed by a NUL, within the first STRING_PROBE_BYTES bytes. Unreadable bytes are
   * not a string.
   */
  private static boolean looksLikeCString(Memory mem, Address a) {
    byte[] b = new byte[STRING_PROBE_BYTES];
    int n;
    try {
      n = mem.getBytes(a, b);
    } catch (Exception ex) {
      return false;
    }
    int run = 0;
    while (run < n && b[run] >= 32 && b[run] < 127) {
      run++;
    }
    return run >= STRING_MIN_PRINTABLE && run < n && b[run] == 0;
  }

  /**
   * W1 block promotion: make a function of every code block no function contains, in address order.
   * Returns {tried, createdReal, createdRaw}, or null when the pass was cancelled (so the caller
   * records nothing). createdReal counts only entries that had no function before the call and one
   * after — what the stored ``created`` and the origin='promoted' bookmark reflect; createdRaw is
   * the old count of every non-null createFunction return, kept only for the per-pass log line A4
   * compares against the r6 single-pass log.
   */
  private int[] promoteBlocks() throws Exception {
    BasicBlockModel model = new BasicBlockModel(currentProgram, true);
    List<Address> starts = new ArrayList<>();
    InstructionIterator ii = currentProgram.getListing().getInstructions(true);
    while (ii.hasNext()) {
      if (monitor.isCancelled()) {
        return null;
      }
      Address a = ii.next().getMinAddress();
      if (fm.getFunctionContaining(a) == null && model.getCodeBlockAt(a, monitor) != null) {
        starts.add(a);
      }
    }
    int tried = 0;
    int createdReal = 0;
    int createdRaw = 0;
    for (Address a : starts) {
      if (monitor.isCancelled()) {
        return null;
      }
      if (fm.getFunctionContaining(a) != null) {
        continue; // swallowed by a function created earlier in this loop
      }
      UndefinedFunction candidate = UndefinedFunction.findFunction(currentProgram, a, monitor);
      if (candidate == null) {
        continue;
      }
      tried++;
      // ★ createFunction returns the EXISTING function when one already sits at this entry (Ghidra's
      //   handleExistingFunction returns it for a body of more than one byte), so a non-null return
      //   is NOT proof a function was made here. Read whether one was there first: only an entry
      //   with none before and one after is a genuine creation to count and bookmark 'promoted'.
      //   Counting every non-null return over-counts `created` and stamps a Ghidra-analysed function
      //   origin='promoted' (both wrong). We still CALL createFunction either way — on a one-byte
      //   placeholder it makes Ghidra rebuild the real body, which we keep.
      Address entry = candidate.getEntryPoint();
      boolean existed = fm.getFunctionAt(entry) != null;
      Function fn = createFunction(entry, null);
      if (fn != null) {
        createdRaw++; // old method: every non-null return (for the r6-log A4 comparison only)
        if (!existed) {
          createdReal++;
          bm.setBookmark(fn.getEntryPoint(), BookmarkType.INFO, BOOKMARK_CATEGORY, "created");
        }
      }
    }
    return new int[] {tried, createdReal, createdRaw};
  }

  /**
   * W14: recover functions reached only through pointers in the binary's data. Returns true when
   * the pass was cancelled (caller records nothing); otherwise fills rec = {recovered, rejected,
   * seeds, above_native, rejected_string} and leaves no-return discovery frozen for the caller to
   * restore.
   *
   * Two seeds are refused before anything is disassembled, each counted once by address: one
   * above {@code nativeCeiling} (the top of the code the analysis itself made into functions —
   * what lies above it in executable memory is data there, and every seed is refused when there
   * is no such function), and one whose bytes read as a C string. A Thumb seed is judged at its
   * real address (the pointer value with the low bit cleared).
   */
  private boolean recoverFromPointers(
      AddressSet exec, AddressSet data, Address nativeCeiling, long[] rec) throws Exception {
    Listing listing = currentProgram.getListing();
    Memory mem = currentProgram.getMemory();
    boolean arm = currentProgram.getLanguage().getProcessor().toString().equalsIgnoreCase("ARM");
    int align = Math.max(1, currentProgram.getLanguage().getInstructionAlignment());
    int ptr = currentProgram.getDefaultPointerSize();
    Set<Address> tried = new HashSet<>();
    Set<Address> aboveNative = new HashSet<>();
    Set<Address> rejectedString = new HashSet<>();
    int recovered = 0;
    int rejected = 0;
    int seedsTotal = 0;
    for (int pass = 0; pass < RECOVER_MAX_PASSES; pass++) {
      if (monitor.isCancelled()) {
        return true;
      }
      // Collect this pass's seeds first (addr -> {mode, note}); the listing is changed only after.
      LinkedHashMap<Address, String[]> seeds = new LinkedHashMap<>();
      ReferenceManager rm = currentProgram.getReferenceManager();
      AddressSet all = new AddressSet(exec);
      all.add(data);
      AddressIterator src = rm.getReferenceSourceIterator(all, true);
      while (src.hasNext()) {
        if (monitor.isCancelled()) {
          return true;
        }
        Address from = src.next();
        for (Reference r : rm.getReferencesFrom(from)) {
          if (r.getReferenceType().isFlow()) {
            continue;
          }
          Address to = r.getToAddress();
          if (exec.contains(to) && to.getOffset() % align == 0) {
            seeds.putIfAbsent(to, new String[] {"arm", "ref@" + from});
          }
        }
      }
      for (AddressRange dr : data) {
        Address p = dr.getMinAddress();
        long mis = p.getOffset() % ptr;
        if (mis != 0) {
          p = p.add(ptr - mis);
        }
        while (p.add(ptr - 1).compareTo(dr.getMaxAddress()) <= 0) {
          if (monitor.isCancelled()) {
            return true;
          }
          long v;
          try {
            v = ptr == 8 ? mem.getLong(p) : (mem.getInt(p) & 0xffffffffL);
          } catch (Exception ex) {
            break;
          }
          boolean thumb = arm && (v & 1) == 1;
          long tv = thumb ? v & ~1L : v;
          if (thumb ? (tv % 2 == 0) : (tv % align == 0)) {
            Address to = null;
            try {
              to = toAddr(tv);
            } catch (Exception ex) {
              to = null;
            }
            if (to != null && exec.contains(to)) {
              seeds.putIfAbsent(to, new String[] {thumb ? "thumb" : "arm", "data@" + p});
            }
          }
          if (p.add(ptr).compareTo(dr.getMaxAddress()) > 0) {
            break;
          }
          p = p.add(ptr);
        }
      }
      int madeNow = 0;
      for (Map.Entry<Address, String[]> s : seeds.entrySet()) {
        if (monitor.isCancelled()) {
          return true;
        }
        Address a = s.getKey();
        if (tried.contains(a)) {
          continue;
        }
        if (listing.getInstructionContaining(a) != null
            || listing.getDefinedDataContaining(a) != null) {
          continue; // something already sits there
        }
        if (aboveNative.contains(a) || rejectedString.contains(a)) {
          continue; // refused in an earlier pass
        }
        if (nativeCeiling == null || a.compareTo(nativeCeiling) > 0) {
          aboveNative.add(a);
          continue;
        }
        if (looksLikeCString(mem, a)) {
          rejectedString.add(a);
          continue;
        }
        tried.add(a);
        seedsTotal++;
        int e0 = errorsIn(exec);
        boolean thumb = "thumb".equals(s.getValue()[0]);
        AddressSetView got;
        if (arm) {
          ArmDisassembleCommand cmd = new ArmDisassembleCommand(a, null, thumb);
          cmd.applyTo(currentProgram, monitor);
          got = cmd.getDisassembledAddressSet();
        } else {
          DisassembleCommand cmd = new DisassembleCommand(a, null, true);
          cmd.applyTo(currentProgram, monitor);
          got = cmd.getDisassembledAddressSet();
        }
        if (got == null || got.isEmpty() || errorsIn(exec) > e0) {
          if (got != null) {
            for (AddressRange g : got) {
              listing.clearCodeUnits(g.getMinAddress(), g.getMaxAddress(), false);
            }
          }
          rejected++;
          continue; // disassembly raised an error there: not code, undone
        }
        if (fm.getFunctionContaining(a) == null) {
          Function f = createFunction(a, null);
          if (f != null) {
            recovered++;
            bm.setBookmark(a, BookmarkType.INFO, RECOVERED_BOOKMARK, "recovered " + s.getValue()[1]);
            madeNow++;
          }
        }
      }
      if (madeNow > 0) {
        analyzeChanges(currentProgram);
      }
      if (madeNow == 0) {
        break; // fixpoint: a pass made nothing
      }
    }
    rec[0] = recovered;
    rec[1] = rejected;
    rec[2] = seedsTotal;
    rec[3] = aboveNative.size();
    rec[4] = rejectedString.size();
    return false;
  }

  /** How many ERROR bookmarks fall inside {@code set}. */
  private int errorsIn(AddressSetView set) {
    int n = 0;
    Iterator<Bookmark> it =
        currentProgram.getBookmarkManager().getBookmarksIterator(BookmarkType.ERROR);
    while (it.hasNext()) {
      if (set.contains(it.next().getAddress())) {
        n++;
      }
    }
    return n;
  }

  private AddressSet executableSet() {
    AddressSet s = new AddressSet();
    for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
      if (b.isExecute() && b.isInitialized()) {
        s.add(b.getStart(), b.getEnd());
      }
    }
    return s;
  }

  private AddressSet dataSet() {
    AddressSet s = new AddressSet();
    for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
      if (!b.isExecute() && b.isInitialized()) {
        s.add(b.getStart(), b.getEnd());
      }
    }
    return s;
  }

  private AddressSet instructionsIn(AddressSetView set) {
    AddressSet s = new AddressSet();
    InstructionIterator it = currentProgram.getListing().getInstructions(set, true);
    while (it.hasNext()) {
      Instruction x = it.next();
      s.add(x.getMinAddress(), x.getMaxAddress());
    }
    return s;
  }

  private Set<Address> functionEntries() {
    Set<Address> out = new HashSet<>();
    for (Function f : fm.getFunctions(true)) {
      out.add(f.getEntryPoint());
    }
    return out;
  }

  private Set<Address> noReturnEntries() {
    Set<Address> out = new HashSet<>();
    for (Function f : fm.getFunctions(true)) {
      if (f.hasNoReturn()) {
        out.add(f.getEntryPoint());
      }
    }
    return out;
  }

  /** Freeze "Non-Returning Functions - Discovered" for the recovery passes; returns its old value. */
  private String freezeNoReturn() {
    String was = "true";
    try {
      was = String.valueOf(currentProgram.getOptions("Analyzers").getBoolean(NO_RETURN_OPTION, true));
    } catch (Exception ex) {
      // keep the "true" default
    }
    setAnalysisOption(currentProgram, NO_RETURN_OPTION, "false");
    AutoAnalysisManager.getAnalysisManager(currentProgram).initializeOptions();
    return was;
  }

  private void restoreNoReturn(String was) {
    setAnalysisOption(currentProgram, NO_RETURN_OPTION, was);
    AutoAnalysisManager.getAnalysisManager(currentProgram).initializeOptions();
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
