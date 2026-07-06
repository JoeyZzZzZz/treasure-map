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
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.graph.*;
import ghidra.graph.algo.ChkDominanceAlgorithm;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

public class ExportFunctions extends GhidraScript {

    // Second callee data source (used in the callee block): recover `name(` call forms straight
    // from the decompiled text. PIC intra-.so calls via PLT/GOT frequently carry no call
    // reference, so the reference scan alone misses them. Intersecting the scanned identifiers
    // with the binary's known function + import names is the real filter — keywords, casts, pcode
    // helpers, and locals are simply absent from that set. The whitespace-free `name(` shape
    // matches call syntax while `if (` / `while (` (space before the paren) do not; C_KEYWORDS is
    // a cheap explicit belt-and-suspenders guard on top of the name intersection.
    private static final Pattern CALL_NAME = Pattern.compile("([A-Za-z_][A-Za-z0-9_]*)\\(");
    private static final Set<String> C_KEYWORDS = new HashSet<>(Arrays.asList(
        "if", "for", "while", "switch", "return", "sizeof", "do", "else", "goto",
        "case", "default", "break", "continue", "typedef", "struct", "union", "enum"));

    // ---- sink_arg_provenance sink lexicon (mirrors lib/pattern/classes.py CMD + FMT_STRING) ----
    // The "key argument" whose value origin we trace back: command sinks forward arg0 (the command
    // / path); format-string sinks carry the format string at a per-sink position (FMT_STRING_ARG).
    // Buffer formatters (snprintf/sprintf) are WRITERS, not provenance sinks. Value = 0-based key
    // arg index. Extra sinks (firmware-specific wrappers) can be appended via TMAP_EXTRA_SINKS.
    private static final Map<String, Integer> SINK_KEYARG = new HashMap<>();
    static {
        for (String s : new String[]{
                "system", "popen", "execl", "execlp", "execle", "execv", "execvp", "execve", "doSystem"})
            SINK_KEYARG.put(s, 0);
        SINK_KEYARG.put("printf", 0);  SINK_KEYARG.put("vprintf", 0);
        SINK_KEYARG.put("warn", 0);    SINK_KEYARG.put("warnx", 0);
        SINK_KEYARG.put("vwarn", 0);   SINK_KEYARG.put("vwarnx", 0);
        SINK_KEYARG.put("fprintf", 1); SINK_KEYARG.put("vfprintf", 1);
        SINK_KEYARG.put("dprintf", 1); SINK_KEYARG.put("vdprintf", 1);
        SINK_KEYARG.put("syslog", 1);  SINK_KEYARG.put("vsyslog", 1);
        SINK_KEYARG.put("err", 1);     SINK_KEYARG.put("errx", 1);
        SINK_KEYARG.put("verr", 1);    SINK_KEYARG.put("verrx", 1);
        SINK_KEYARG.put("asprintf", 1); SINK_KEYARG.put("vasprintf", 1);
    }
    // Functions that fill a destination buffer — candidate writers of a stack_buf sink argument.
    private static final Set<String> WRITERS = new HashSet<>(Arrays.asList(
        "snprintf", "sprintf", "vsnprintf", "vsprintf", "strcpy", "strncpy", "strcat", "strncat",
        "memcpy", "memmove", "stpcpy", "__sprintf_chk", "__snprintf_chk"));
    // Format-string argument index for the printf-family writers (0-based over the callee's args):
    // sprintf(dst, fmt, ...) → 1; snprintf(dst, n, fmt, ...) → 2; __sprintf_chk(dst, flag, n, fmt) → 3.
    private static final Map<String, Integer> WRITER_FMTARG = new HashMap<>();
    static {
        WRITER_FMTARG.put("sprintf", 1);   WRITER_FMTARG.put("vsprintf", 1);
        WRITER_FMTARG.put("snprintf", 2);  WRITER_FMTARG.put("vsnprintf", 2);
        WRITER_FMTARG.put("__sprintf_chk", 3); WRITER_FMTARG.put("__snprintf_chk", 4);
    }
    private static final Set<String> TOKENIZERS = new HashSet<>(Arrays.asList(
        "strtok", "strtok_r", "strsep", "sscanf"));
    private static final int PROV_MAX_DEPTH = 2;   // vararg / nested-source recursion cap (the provenance design)

    // ---- gap② nvram op lexicon (measured on real firmware: 6 APIs = 98% of calls, + pf family +
    // long tail; missing one = a missed key = a false negative, so the tail is included). Per API:
    //   op    read / write / commit / getall
    //   keyIdx  0-based arg holding the key (-1 = whole-store op, no key: commit/getall)
    //   nameIdx pf family only — the composite key is prefix(keyIdx)+name(nameIdx); -1 otherwise
    //   valIdx  write value arg (-1 = key-only write like unset, or a read)
    private static final class NvSpec {
        final String op; final int keyIdx, nameIdx, valIdx;
        NvSpec(String op, int keyIdx, int nameIdx, int valIdx) {
            this.op = op; this.keyIdx = keyIdx; this.nameIdx = nameIdx; this.valIdx = valIdx;
        }
    }
    private static final Map<String, NvSpec> NVRAM = new HashMap<>();
    static {
        for (String r : new String[]{"nvram_get", "nvram_get_int", "nvram_default_get",
                "nvram_contains_word", "nvram_get_hex", "nvram_get_r", "nvram_split_get",
                "wlcsm_nvram_get", "jffs_nvram_get", "nvram_is_empty", "nvram_valid_get_int",
                "nvram_get_bitflag", "nvram_get_double", "nvram_get_file", "internal_nvram_get_int"})
            NVRAM.put(r, new NvSpec("read", 0, -1, -1));
        for (String w : new String[]{"nvram_set", "nvram_set_int", "nvram_set_hex",
                "nvram_restore_var", "wlcsm_nvram_set", "jffs_nvram_set"})
            NVRAM.put(w, new NvSpec("write", 0, -1, 1));                 // key=arg0, value=arg1
        for (String w : new String[]{"nvram_unset", "jffs_nvram_unset"})
            NVRAM.put(w, new NvSpec("write", 0, -1, -1));                // key-only write (no value)
        for (String r : new String[]{"nvram_pf_get", "nvram_pf_get_int", "nvram_pf_match"})
            NVRAM.put(r, new NvSpec("read", 0, 1, -1));                  // composite key prefix+name
        for (String w : new String[]{"nvram_pf_set", "nvram_pf_set_int"})
            NVRAM.put(w, new NvSpec("write", 0, 1, 2));                  // prefix+name, value=arg2
        for (String c : new String[]{"nvram_commit", "nvram_commit_x", "wlcsm_nvram_commit"})
            NVRAM.put(c, new NvSpec("commit", -1, -1, -1));
        for (String g : new String[]{"nvram_getall", "jffs_nvram_getall"})
            NVRAM.put(g, new NvSpec("getall", -1, -1, -1));
    }

    // Per-run sink map = static lexicon + optional TMAP_EXTRA_SINKS (comma-separated, key arg 0).
    private Map<String, Integer> sinkKeyArg = SINK_KEYARG;

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

    // Resolve a call-target address to {calleeName, edgeKind}, following thunks and GOT pointers.
    // Returns null only when there is no statically recoverable target (register-indirect /
    // runtime-computed). This is what lets PIC intra-.so calls (PLT stub / GOT slot) resolve to the
    // real callee body instead of being dropped when getFunctionAt() returns null on the stub.
    private String[] resolveCallee(Address to, RefType rt, FunctionManager fm,
                                   SymbolTable symtab, Listing listing) {
        if (to == null) return null;
        // 1. A function is defined at the target.
        Function f = fm.getFunctionAt(to);
        if (f != null) {
            if (f.isThunk()) {                                   // PLT stub → follow to the real callee
                Function thunked = f.getThunkedFunction(true);
                if (thunked != null) return new String[]{ thunked.getName(), "thunk" };
                return new String[]{ f.getName(), "thunk" };     // thunk name if the target can't be followed
            }
            return new String[]{ f.getName(), rt.isComputed() ? "indirect" : "direct" };
        }
        // 2. A pointer (GOT slot) is defined at the target — follow it.
        Data d = listing.getDefinedDataAt(to);
        if (d != null && d.isPointer()) {
            Object val = null;
            try { val = d.getValue(); } catch (Exception ignore) {}
            if (val instanceof Address) {
                Address pa = (Address) val;
                Function pf = fm.getFunctionAt(pa);
                if (pf != null) return new String[]{ pf.getName(), "ptr" };
                Symbol ps = symtab.getPrimarySymbol(pa);
                if (ps != null) return new String[]{ ps.getName(), "ptr" };
            }
        }
        // 3. A symbol/label at the target (external stub without a Function object).
        Symbol s = symtab.getPrimarySymbol(to);
        if (s != null) return new String[]{ s.getName(), rt.isComputed() ? "indirect" : "direct" };
        return null;
    }

    // ============================ sink_arg_provenance (the provenance design) ============================
    // Backward def-use over the HighFunction Varnode graph + Ghidra CHK dominance over its block
    // graph. Pure fact extraction: where does each command/format sink's key argument come from.
    // Never a verdict; unresolved is reported honestly (a surfaced fact, never scored), never silently dropped.

    // Lazy CHK dominance over the decompiler block graph. Built once per function, only if a
    // stack_buf sink actually needs it. Ghidra owns the dominator algorithm; we only wrap the
    // pcode block CFG (getOut edges) into a GDirectedGraph — no alias analysis.
    private final class DomCtx {
        private final HighFunction hf;
        private ChkDominanceAlgorithm<PcodeBlockBasic, GEdge<PcodeBlockBasic>> algo;
        private final Map<Integer, Set<Integer>> cache = new HashMap<>();
        private boolean built = false, failed = false;

        DomCtx(HighFunction hf) { this.hf = hf; }

        private void build() {
            if (built || failed) return;
            try {
                GDirectedGraph<PcodeBlockBasic, GEdge<PcodeBlockBasic>> g =
                        GraphFactory.createDirectedGraph();
                ArrayList<PcodeBlockBasic> blocks = hf.getBasicBlocks();
                for (PcodeBlockBasic b : blocks) g.addVertex(b);
                for (PcodeBlockBasic b : blocks) {
                    for (int i = 0; i < b.getOutSize(); i++) {
                        PcodeBlock o = b.getOut(i);
                        if (o instanceof PcodeBlockBasic) {
                            g.addEdge(new DefaultGEdge<>(b, (PcodeBlockBasic) o));
                        }
                    }
                }
                algo = new ChkDominanceAlgorithm<>(g, monitor);
                built = true;
            } catch (Exception e) {
                failed = true;
            }
        }

        Set<Integer> dominatorsOf(PcodeBlockBasic sb) {
            build();
            if (!built) return Collections.emptySet();
            Integer idx = sb.getIndex();
            Set<Integer> c = cache.get(idx);
            if (c != null) return c;
            Set<Integer> res = new HashSet<>();
            try {
                for (PcodeBlockBasic b : algo.getDominators(sb)) res.add(b.getIndex());
            } catch (Exception e) { /* leave empty on failure */ }
            cache.put(idx, res);
            return res;
        }
    }

    // Build the per-function sink_provenance JSON array (one record per command/format sink call,
    // ordered by call-site address = sink_idx).
    private String buildSinkProvenance(HighFunction hf) {
        List<PcodeOpAST> ops = new ArrayList<>();
        Iterator<PcodeOpAST> it = hf.getPcodeOps();
        while (it.hasNext()) ops.add(it.next());

        List<PcodeOpAST> sinks = new ArrayList<>();
        for (PcodeOpAST op : ops) {
            int oc = op.getOpcode();
            if (oc != PcodeOp.CALL && oc != PcodeOp.CALLIND) continue;
            String cn = calleeNameOf(op);
            if (cn != null && sinkKeyArg.containsKey(cn)) sinks.add(op);
        }
        if (sinks.isEmpty()) return "[]";
        sinks.sort(new Comparator<PcodeOpAST>() {
            public int compare(PcodeOpAST a, PcodeOpAST b) {
                return Long.compare(a.getSeqnum().getTarget().getOffset(),
                                    b.getSeqnum().getTarget().getOffset());
            }
        });

        DomCtx dom = new DomCtx(hf);
        StringBuilder arr = new StringBuilder("[");
        int sinkIdx = 0;
        boolean first = true;
        for (PcodeOpAST sink : sinks) {
            String cn = calleeNameOf(sink);
            int keyArg = sinkKeyArg.get(cn);
            Varnode arg = (keyArg + 1 < sink.getNumInputs()) ? sink.getInput(keyArg + 1) : null;
            String prov = (arg == null)
                    ? "{\"kind\":\"unresolved\",\"note\":\"arg_absent\"}"
                    : classify(arg, sink, ops, dom, 0);
            if (!first) arr.append(",");
            first = false;
            arr.append("{\"sink_idx\":").append(sinkIdx)
               .append(",\"sink\":\"").append(esc(cn)).append("\"")
               .append(",\"sink_addr\":\"").append(esc(addr0x(sink))).append("\"")
               .append(",\"arg_idx\":").append(keyArg)
               .append(",\"provenance\":").append(prov)
               .append("}");
            sinkIdx++;
        }
        arr.append("]");
        return arr.toString();
    }

    // gap② phase 1: per-function nvram read/write ops. One record per nvram API call:
    //   {api, op, key + honest key three-state (constant / parametric-template / unresolved), and for
    //    writes value_source via the SAME classify as sink_provenance (a controllability signal;
    //    143/143 accurate on that axis in the probe)}. A surfaced def-use FACT — a key that cannot be
    //    read is marked parametric/unresolved, NEVER silently dropped. No cross-function key chasing
    //    (an unresolved key is flagged key_from_caller and left to the agent).
    private String buildNvramOps(HighFunction hf) {
        List<PcodeOpAST> ops = new ArrayList<>();
        Iterator<PcodeOpAST> it = hf.getPcodeOps();
        while (it.hasNext()) ops.add(it.next());
        DomCtx dom = new DomCtx(hf);
        StringBuilder arr = new StringBuilder("[");
        boolean first = true;
        for (PcodeOpAST op : ops) {
            int oc = op.getOpcode();
            if (oc != PcodeOp.CALL && oc != PcodeOp.CALLIND) continue;
            String cn = calleeNameOf(op);
            if (cn == null) continue;
            NvSpec spec = NVRAM.get(cn);
            if (spec == null) continue;
            if (!first) arr.append(",");
            first = false;
            arr.append("{\"api\":\"").append(esc(cn)).append("\",\"op\":\"").append(spec.op).append("\"");
            if (spec.keyIdx >= 0) arr.append(nvramKeyJson(op, spec, ops));
            if (spec.valIdx >= 0) {
                Varnode val = (spec.valIdx + 1 < op.getNumInputs()) ? op.getInput(spec.valIdx + 1) : null;
                String vs = (val == null) ? "{\"kind\":\"unresolved\",\"note\":\"arg_absent\"}"
                                          : classify(val, op, ops, dom, 0);
                arr.append(",\"value_source\":").append(vs);
            }
            arr.append("}");
        }
        arr.append("]");
        return arr.toString();
    }

    // Classify ONE key varnode into {"constant","<key>"} / {"parametric","<template>"} /
    // {"unresolved", null}. resolveConst reads a constant string key; a stack slot built by a string
    // writer is a parametric (built) key whose printf template is recovered when available.
    private String[] keyClass(Varnode kv, List<PcodeOpAST> ops) {
        if (kv == null) return new String[]{"unresolved", null};
        String k = resolveConst(kv, 0);
        if (k != null && !k.startsWith("0x")) return new String[]{"constant", k};
        String tmpl = nvramKeyTemplate(kv, ops);
        if (tmpl != null) return new String[]{"parametric", tmpl};
        return new String[]{"unresolved", null};
    }

    // Emit the key JSON fields for one nvram call (leading comma included). pf family emits a
    // composite key = prefix+name with per-part kinds; a single-key API emits one key.
    private String nvramKeyJson(PcodeOpAST op, NvSpec spec, List<PcodeOpAST> ops) {
        Varnode kv = (spec.keyIdx + 1 < op.getNumInputs()) ? op.getInput(spec.keyIdx + 1) : null;
        String[] kc = keyClass(kv, ops);
        if (spec.nameIdx < 0) return keyFields(kc, "key");
        // pf composite key: prefix + name. Composite kind is constant iff BOTH parts are constant;
        // unresolved iff both unresolved; parametric otherwise (a resolvable template with holes).
        Varnode nvn = (spec.nameIdx + 1 < op.getNumInputs()) ? op.getInput(spec.nameIdx + 1) : null;
        String[] nc = keyClass(nvn, ops);
        StringBuilder sb = new StringBuilder(",\"pf\":true");
        sb.append(",\"prefix\":\"").append(esc(kc[1] == null ? "?" : kc[1])).append("\"");
        sb.append(",\"name\":\"").append(esc(nc[1] == null ? "?" : nc[1])).append("\"");
        String composite = (kc[1] == null ? "?" : kc[1]) + (nc[1] == null ? "?" : nc[1]);
        if (kc[0].equals("constant") && nc[0].equals("constant"))
            sb.append(",\"key\":\"").append(esc(composite)).append("\",\"key_kind\":\"constant\"");
        else if (kc[0].equals("unresolved") && nc[0].equals("unresolved"))
            sb.append(",\"key_kind\":\"unresolved\",\"reason\":\"key_from_caller\"");
        else
            sb.append(",\"key\":\"").append(esc(composite))
              .append("\",\"key_kind\":\"parametric\",\"template\":\"").append(esc(composite)).append("\"");
        return sb.toString();
    }

    private String keyFields(String[] kc, String keyField) {
        if (kc[0].equals("constant"))
            return ",\"" + keyField + "\":\"" + esc(kc[1]) + "\",\"key_kind\":\"constant\"";
        if (kc[0].equals("parametric"))
            return ",\"" + keyField + "\":\"" + esc(kc[1]) + "\",\"key_kind\":\"parametric\",\"template\":\""
                 + esc(kc[1]) + "\"";
        return ",\"key_kind\":\"unresolved\",\"reason\":\"key_from_caller\"";
    }

    // A key arg is PARAMETRIC (built) when its stack slot is the destination of a string writer in
    // the same function; returns the printf template (e.g. "wl%d_ssid") when the writer is a
    // printf-family, else "<built:strcpy>" (built, no recoverable template). null if not built.
    private String nvramKeyTemplate(Varnode kv, List<PcodeOpAST> ops) {
        String key = stackKey(kv);
        if (key == null) return null;
        for (PcodeOpAST op : ops) {
            int oc = op.getOpcode();
            if (oc != PcodeOp.CALL && oc != PcodeOp.CALLIND) continue;
            String cn = calleeNameOf(op);
            if (cn == null || !WRITERS.contains(cn) || op.getNumInputs() < 2) continue;
            if (!key.equals(stackKey(op.getInput(1)))) continue;   // writes this slot (dst = arg0)
            Integer fi = WRITER_FMTARG.get(cn);
            if (fi != null && fi + 1 < op.getNumInputs()) {
                String fmt = constStrOf(op.getInput(fi + 1), 0);
                if (fmt != null) return fmt;
            }
            return "<built:" + cn + ">";
        }
        return null;
    }

    // Full backward classification of a value varnode → provenance kind object (the provenance design).
    private String classify(Varnode v, PcodeOpAST sink, List<PcodeOpAST> ops, DomCtx dom, int depth) {
        if (v == null) return "{\"kind\":\"unresolved\",\"note\":\"null_varnode\"}";
        if (depth > PROV_MAX_DEPTH) return "{\"kind\":\"unresolved\",\"truncated\":true}";
        if (v.isConstant()) return constNode(v);
        PcodeOp def = v.getDef();
        if (def == null) {
            HighVariable hv = v.getHigh();
            HighSymbol hs = hv != null ? hv.getSymbol() : null;
            if (hs != null && hs.isParameter())
                return "{\"kind\":\"param\",\"name\":\"" + esc(hs.getName()) + "\"}";
            String g = globalText(v);
            if (g != null) return g;
            return "{\"kind\":\"unresolved\",\"note\":\"input_no_def\"}";
        }
        switch (def.getOpcode()) {
            case PcodeOp.CAST:
            case PcodeOp.COPY:
                return classify(def.getInput(0), sink, ops, dom, depth);
            case PcodeOp.CALL:
            case PcodeOp.CALLIND: {
                String cn = calleeNameOf(def);
                if (cn != null && TOKENIZERS.contains(cn)) return tokenizerOut(def, cn, depth);
                return callReturn(def, cn);
            }
            case PcodeOp.MULTIEQUAL: {
                // A phi merge: classify each origin, but cap the fan-out at 6 to bound recursion.
                // Past the cap the remaining origins are NOT silently dropped — sources_truncated +
                // total_sources say the list is a prefix, so a controllable origin at input #7+ can
                // never hide behind a "sources" array read as complete (the silent-drop red line).
                StringBuilder sb = new StringBuilder("{\"kind\":\"multiple\",\"sources\":[");
                int total = def.getNumInputs();
                int n = 0;
                for (int i = 0; i < total && n < 6; i++) {
                    if (n > 0) sb.append(",");
                    sb.append(classify(def.getInput(i), sink, ops, dom, depth + 1));
                    n++;
                }
                sb.append("]");
                if (total > n) sb.append(",\"sources_truncated\":true,\"total_sources\":").append(total);
                sb.append("}");
                return sb.toString();
            }
            case PcodeOp.INDIRECT:
                return indirectUnresolved(v, ops);
            case PcodeOp.PTRSUB:
            case PcodeOp.PTRADD:
            case PcodeOp.INT_ADD: {
                String key = stackKey(v);
                if (key != null) return stackBuf(key, sink, ops, dom, depth);
                String g = globalText(v);
                if (g != null) return g;
                return classify(def.getInput(0), sink, ops, dom, depth);
            }
            case PcodeOp.LOAD: {
                String key = stackKey(def.getInput(1));
                if (key != null) return stackBuf(key, sink, ops, dom, depth);
                return "{\"kind\":\"unresolved\",\"note\":\"mem_load\"}";
            }
            default: {
                String key = stackKey(v);
                if (key != null) return stackBuf(key, sink, ops, dom, depth);
                return "{\"kind\":\"unresolved\",\"note\":\"" + esc(def.getMnemonic()) + "\"}";
            }
        }
    }

    // call_return with the callsite's constant arguments (the getter key — the provenance design, gap ③).
    private String callReturn(PcodeOp callDef, String cn) {
        StringBuilder sb = new StringBuilder("{\"kind\":\"call_return\",\"callee\":\"");
        sb.append(esc(cn == null ? "?" : cn)).append("\",\"const_args\":[");
        // input 0 is the call target; inputs 1.. are the callsite's actual arguments.
        int argCount = Math.max(0, callDef.getNumInputs() - 1);
        int n = 0;
        for (int i = 1; i < callDef.getNumInputs(); i++) {
            // A constant arg often reaches the callsite through a unique/COPY/CAST (Ghidra models
            // `getter("some_key")` as a unique that COPYs the string address), so resolve the chain.
            String val = resolveConst(callDef.getInput(i), 0);
            if (val == null) continue;   // non-constant arg — NOT dropped: flagged via has_unresolved_args
            if (n > 0) sb.append(",");
            sb.append("\"").append(esc(val)).append("\"");
            n++;
        }
        sb.append("],\"arg_count\":").append(argCount);
        // Honesty (never silently drop): const_args lists ONLY the args that resolved to a constant.
        // When some args were non-constant they are absent from const_args, so flag it here — a
        // consumer must never read const_args as the full argument list. e.g. getter(key, param_2)
        // with a caller-controlled param_2 would otherwise look like a lone constant key.
        if (n < argCount) sb.append(",\"has_unresolved_args\":true");
        sb.append("}");
        return sb.toString();
    }

    // Follow COPY/CAST/zext/sext back to a constant; return its string (if it addresses one) or hex.
    private String resolveConst(Varnode v, int depth) {
        if (v == null || depth > 6) return null;
        if (v.isConstant()) {
            String t = constText(v);
            return (t != null) ? t : ("0x" + Long.toHexString(v.getOffset()));
        }
        PcodeOp def = v.getDef();
        if (def == null) return null;
        switch (def.getOpcode()) {
            case PcodeOp.COPY:
            case PcodeOp.CAST:
            case PcodeOp.INT_ZEXT:
            case PcodeOp.INT_SEXT:
            case PcodeOp.SUBPIECE:
                return resolveConst(def.getInput(0), depth + 1);
            default:
                return null;
        }
    }

    // Honest constant record. A readable literal string is a CONFIRMED real constant
    // (value_kind:"literal_string"). A bare 0x that no string reads out of is value_kind:
    // "ambiguous_0x": Ghidra confirms this is a constant value 0x… but CANNOT tell an integer literal
    // from a pointer address — a two-firmware DataType probe found 0 pointers over 13162 such
    // constants (type unavailable here). Report what is certain (it IS a constant, value 0x…) and
    // flag what is NOT (integer vs pointer undecided). A consumer WITH spec/type context (%d=integer,
    // %s=pointer) must judge by it; a consumer WITHOUT such context must treat it as undetermined,
    // NEVER as a safe constant.
    private String constNode(Varnode v) {
        String t = constText(v);
        if (t != null) {
            String trunc = strAtTruncated ? ",\"text_truncated\":true" : "";
            return "{\"kind\":\"constant\",\"value\":\"" + esc(t)
                 + "\",\"value_kind\":\"literal_string\"" + trunc + "}";
        }
        return "{\"kind\":\"constant\",\"value\":\"0x" + Long.toHexString(v.getOffset())
             + "\",\"value_kind\":\"ambiguous_0x\"}";
    }

    // stack_buf: writer set (stackKey equal-match) + sound CHK-dominance ordering (the provenance design, gap ①).
    private String stackBuf(String key, PcodeOpAST sink, List<PcodeOpAST> ops, DomCtx dom, int depth) {
        List<PcodeOpAST> writers = new ArrayList<>();
        for (PcodeOpAST op : ops) {
            int oc = op.getOpcode();
            if (oc != PcodeOp.CALL && oc != PcodeOp.CALLIND) continue;
            String cn = calleeNameOf(op);
            if (cn == null || !WRITERS.contains(cn)) continue;
            for (int j = 1; j < op.getNumInputs(); j++) {
                if (key.equals(stackKey(op.getInput(j)))) { writers.add(op); break; }
            }
        }
        Set<Integer> domBlocks = dom.dominatorsOf(sink.getParent());
        int sinkBlk = sink.getParent().getIndex();
        long sinkAddr = sink.getSeqnum().getTarget().getOffset();

        PcodeOpAST nearest = null;
        long best = Long.MIN_VALUE;
        StringBuilder wsb = new StringBuilder("[");
        boolean firstW = true;
        for (PcodeOpAST w : writers) {
            int wblk = w.getParent().getIndex();
            long wa = w.getSeqnum().getTarget().getOffset();
            boolean dominates = domBlocks.contains(wblk);
            // Same block as the sink: a writer only precedes the sink if it is earlier by address.
            if (dominates && wblk == sinkBlk && wa >= sinkAddr) dominates = false;
            if (dominates && wa > best) { best = wa; nearest = w; }
            String cn = calleeNameOf(w);
            if (!firstW) wsb.append(",");
            firstW = false;
            wsb.append("{\"writer\":\"").append(esc(cn + "@" + addr0x(w))).append("\"")
               .append(",\"dominates_sink\":").append(dominates)
               .append(fmtAndVarargs(w, cn, depth))
               .append("}");
        }
        wsb.append("]");

        StringBuilder sb = new StringBuilder("{\"kind\":\"stack_buf\",\"stack_key\":\"");
        sb.append(esc(key)).append("\",\"writer_count\":").append(writers.size());
        if (nearest != null) {
            sb.append(",\"nearest_dominating_writer\":\"")
              .append(esc(calleeNameOf(nearest) + "@" + addr0x(nearest))).append("\"");
        } else {
            sb.append(",\"nearest_dominating_writer\":null");
        }
        sb.append(",\"writers\":").append(wsb).append(",\"attribution\":\"chk_dominance\"}");
        return sb.toString();
    }

    // A writer's format string + its varargs' shallow source classification. The fmt reaches the
    // callsite through a unique/COPY like any other constant, so resolve it (not raw constText); the
    // fmt is the agent's key signal ("read the dominating writer's fmt").
    private String fmtAndVarargs(PcodeOpAST writer, String cn, int depth) {
        StringBuilder sb = new StringBuilder();
        Integer fi = WRITER_FMTARG.get(cn);
        if (fi != null && fi + 1 < writer.getNumInputs()) {
            String fmt = constStrOf(writer.getInput(fi + 1), 0);
            List<String> specs = (fmt != null) ? formatSpecs(fmt) : Collections.<String>emptyList();
            if (fmt != null) sb.append(",\"fmt\":\"").append(esc(fmt)).append("\"");
            sb.append(",\"varargs\":[");
            boolean f = true;
            int vi = 0;
            for (int i = fi + 2; i < writer.getNumInputs(); i++) {
                if (!f) sb.append(",");
                f = false;
                sb.append("{\"pos\":").append(i - 1);
                if (vi < specs.size()) sb.append(",\"spec\":\"").append(esc(specs.get(vi))).append("\"");
                sb.append(",\"source\":").append(shallowSource(writer.getInput(i), depth + 1)).append("}");
                vi++;
            }
            sb.append("]");
        } else if (writer.getNumInputs() > 2) {
            // copy family (strcpy/memcpy/…): the "source" is the src argument (arg1).
            sb.append(",\"src_source\":").append(shallowSource(writer.getInput(2), depth + 1));
        }
        return sb.toString();
    }

    // Follow COPY/CAST/zext/sext back to a constant that addresses a string; return the string only.
    private String constStrOf(Varnode v, int depth) {
        if (v == null || depth > 6) return null;
        if (v.isConstant()) return constText(v);
        PcodeOp def = v.getDef();
        if (def == null) return null;
        switch (def.getOpcode()) {
            case PcodeOp.COPY:
            case PcodeOp.CAST:
            case PcodeOp.INT_ZEXT:
            case PcodeOp.INT_SEXT:
            case PcodeOp.SUBPIECE:
                return constStrOf(def.getInput(0), depth + 1);
            default:
                return null;
        }
    }

    // Ordered printf conversion specifiers in a format string (skips %%). Maps position -> vararg.
    private List<String> formatSpecs(String fmt) {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < fmt.length(); i++) {
            if (fmt.charAt(i) != '%') continue;
            int j = i + 1;
            if (j < fmt.length() && fmt.charAt(j) == '%') { i = j; continue; }   // literal %%
            while (j < fmt.length() && "-+ 0#".indexOf(fmt.charAt(j)) >= 0) j++;  // flags
            while (j < fmt.length() && (Character.isDigit(fmt.charAt(j)) || fmt.charAt(j) == '*')) j++;
            if (j < fmt.length() && fmt.charAt(j) == '.') {
                j++;
                while (j < fmt.length() && (Character.isDigit(fmt.charAt(j)) || fmt.charAt(j) == '*')) j++;
            }
            while (j < fmt.length() && "hljztL".indexOf(fmt.charAt(j)) >= 0) j++;  // length mods
            if (j < fmt.length()) {
                out.add("%" + fmt.charAt(j));
                i = j;
            }
        }
        return out;
    }

    // Shallow (non-recursive-into-writers) classification for a nested source — bounded output.
    private String shallowSource(Varnode v, int depth) {
        if (v == null) return "{\"kind\":\"unresolved\",\"note\":\"null\"}";
        if (depth > PROV_MAX_DEPTH) return "{\"kind\":\"unresolved\",\"truncated\":true}";
        if (v.isConstant()) return constNode(v);
        PcodeOp def = v.getDef();
        if (def == null) {
            HighVariable hv = v.getHigh();
            HighSymbol hs = hv != null ? hv.getSymbol() : null;
            if (hs != null && hs.isParameter())
                return "{\"kind\":\"param\",\"name\":\"" + esc(hs.getName()) + "\"}";
            String g = globalText(v);
            if (g != null) return g;
            return "{\"kind\":\"unresolved\",\"note\":\"input_no_def\"}";
        }
        switch (def.getOpcode()) {
            case PcodeOp.CAST:
            case PcodeOp.COPY:
            case PcodeOp.INT_ZEXT:
            case PcodeOp.INT_SEXT:
            case PcodeOp.SUBPIECE:
                return shallowSource(def.getInput(0), depth);
            case PcodeOp.CALL:
            case PcodeOp.CALLIND:
                return callReturn(def, calleeNameOf(def));
            case PcodeOp.INDIRECT:
                return "{\"kind\":\"indirect_unresolved\",\"reason\":\"call_clobbered_stack_slot\"}";
            case PcodeOp.PTRSUB:
            case PcodeOp.PTRADD:
            case PcodeOp.INT_ADD: {
                String key = stackKey(v);
                if (key != null) return "{\"kind\":\"stack_buf\",\"stack_key\":\"" + esc(key)
                        + "\",\"truncated_writers\":true}";
                String g = globalText(v);
                if (g != null) return g;
                return "{\"kind\":\"unresolved\",\"note\":\"ptr\"}";
            }
            default: {
                String g = globalText(v);
                if (g != null) return g;
                return "{\"kind\":\"unresolved\",\"note\":\"" + esc(def.getMnemonic()) + "\"}";
            }
        }
    }

    // tokenizer_output (the provenance design, gap ②): the value is a strtok/strsep/sscanf return used directly.
    private String tokenizerOut(PcodeOp def, String cn, int depth) {
        Varnode inp = def.getNumInputs() > 1 ? def.getInput(1) : null;
        String inSrc = (inp != null) ? shallowSource(inp, depth + 1) : "{\"kind\":\"unresolved\"}";
        return "{\"kind\":\"tokenizer_output\",\"tokenizer\":\"" + esc(cn + "@" + addr0x(def))
             + "\",\"input_source\":" + inSrc + ",\"sink_to_token\":\"resolved\"}";
    }

    // indirect_unresolved (the provenance design): a call clobbered the stack slot (array-element / cross-call
    // opaque). Best-effort last_writer as an honest handle; never claimed as the definition.
    private String indirectUnresolved(Varnode v, List<PcodeOpAST> ops) {
        String key = stackKey(v);
        String lastWriter = null;
        long bestAddr = Long.MIN_VALUE;
        if (key != null) {
            for (PcodeOpAST op : ops) {
                int oc = op.getOpcode();
                if (oc != PcodeOp.CALL && oc != PcodeOp.CALLIND) continue;
                String cn = calleeNameOf(op);
                if (cn == null) continue;
                // Only a call that WRITES or PRODUCES this slot is an honest last_writer. A pure
                // consumer that merely reads the slot as an argument (atoi/system/strlen on the same
                // token) is NOT a writer — including it points the agent the wrong way. Match only
                // buffer writers and tokenizers (whose token result lands in the slot).
                if (!WRITERS.contains(cn) && !TOKENIZERS.contains(cn)) continue;
                boolean hit = false;
                for (int j = 1; j < op.getNumInputs(); j++)
                    if (key.equals(stackKey(op.getInput(j)))) { hit = true; break; }
                if (hit) {
                    long a = op.getSeqnum().getTarget().getOffset();
                    if (a > bestAddr) { bestAddr = a; lastWriter = cn + "@" + addr0x(op); }
                }
            }
        }
        StringBuilder sb = new StringBuilder(
                "{\"kind\":\"indirect_unresolved\",\"reason\":\"call_clobbered_stack_slot\"");
        if (lastWriter != null) sb.append(",\"last_writer\":\"").append(esc(lastWriter)).append("\"");
        sb.append("}");
        return sb.toString();
    }

    // ---- provenance leaf helpers ----

    // Ghidra's canonical &stack_var idiom is PTRSUB(base_reg, const). Return a stable key
    // (base-reg offset + const) so a writer and a sink referencing the SAME slot match. Reading the
    // decompiler's already-resolved offsets — NOT alias analysis.
    private String stackKey(Varnode v) {
        return stackKey(v, 0);
    }

    private String stackKey(Varnode v, int depth) {
        if (v == null || depth > 20) return null;
        Address a = v.getAddress();
        if (a != null && a.isStackAddress()) return "stackvn:" + v.getOffset();
        PcodeOp def = v.getDef();
        if (def == null) return null;
        int oc = def.getOpcode();
        if (oc == PcodeOp.PTRSUB || oc == PcodeOp.PTRADD || oc == PcodeOp.INT_ADD) {
            Varnode base = def.getInput(0);
            Varnode off = def.getInput(1);
            if (base != null && off != null && off.isConstant() && base.isRegister()) {
                return "frame[" + base.getOffset() + "]+0x" + Long.toHexString(off.getOffset());
            }
        }
        // A reused stack buffer is often reached through an intermediate CAST/COPY (common when the
        // decompiler's type propagation does not settle) — follow it, as the def-use probe did.
        if (oc == PcodeOp.CAST || oc == PcodeOp.COPY) return stackKey(def.getInput(0), depth + 1);
        return null;
    }

    // A constant varnode that addresses a defined/readable string → the string; else null.
    private String constText(Varnode v) {
        if (v == null || !v.isConstant()) return null;
        long off = v.getOffset();
        if (off == 0) return null;
        try {
            return strAt(toAddr(off));
        } catch (Exception e) {
            return null;
        }
    }

    // A varnode addressing a global (.data/.rodata/.bss) → global_buf record; else null.
    private String globalText(Varnode v) {
        if (v == null) return null;
        Address a = null;
        if (v.isConstant() && v.getOffset() != 0) {
            try { a = toAddr(v.getOffset()); } catch (Exception e) { a = null; }
        } else if (v.isAddress()) {
            a = v.getAddress();
        }
        if (a == null) return null;
        MemoryBlock blk = currentProgram.getMemory().getBlock(a);
        if (blk == null || blk.isExecute()) return null;   // not a data reference
        Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(a);
        String ref = (s != null) ? s.getName() : ("DAT_" + a.toString());
        String txt = null;
        try { txt = strAt(a); } catch (Exception e) { txt = null; }
        StringBuilder sb = new StringBuilder("{\"kind\":\"global_buf\",\"data_ref\":\"").append(esc(ref)).append("\"");
        // problem②: report content honesty. A readable string is a known constant; no readable
        // string means the CONTENT is unknown (not "no value") — mark it so a consumer never reads a
        // global with unknown content as a fixed constant. A writable block is an extra caution flag.
        if (txt != null) {
            sb.append(",\"content\":\"known_string\",\"text\":\"").append(esc(txt)).append("\"");
            if (strAtTruncated) sb.append(",\"text_truncated\":true");
        } else {
            sb.append(",\"content\":\"unknown\"");
            if (blk.isWrite()) sb.append(",\"writable\":true");
        }
        sb.append("}");
        return sb.toString();
    }

    // Set by strAt when its raw-byte fallback hits the cap mid-string (no NUL / non-printable
    // terminator seen). Reset at the start of every strAt call; a caller reads it right after to
    // surface text_truncated, so a clipped constant/format string is never emitted as a full value.
    private boolean strAtTruncated = false;

    // Cap on the raw-byte fallback (defined Data returns the full value untruncated). Raised from
    // 200: real constant keys / format strings fit well under this, so truncation is now a rare
    // edge — and when it DOES bite, strAtTruncated flags it rather than silently clipping.
    private static final int STR_TEXT_LIMIT = 512;

    // Read a NUL-terminated printable string at an address: defined Data first, then raw bytes.
    private String strAt(Address a) {
        strAtTruncated = false;
        if (a == null) return null;
        Data d = currentProgram.getListing().getDefinedDataAt(a);
        if (d != null) {
            Object val = d.getValue();
            if (val instanceof String) return (String) val;   // defined Data: the full string
        }
        try {
            StringBuilder sb = new StringBuilder();
            boolean terminated = false;
            for (int i = 0; i < STR_TEXT_LIMIT; i++) {
                byte b = currentProgram.getMemory().getByte(a.add(i));
                if (b == 0) { terminated = true; break; }
                if (b < 0x20 || b > 0x7e) {
                    if (i == 0) return null;   // not a string at all
                    terminated = true;         // a printable run ended at a boundary — complete
                    break;
                }
                sb.append((char) b);
            }
            if (!terminated) strAtTruncated = true;   // ran to the cap with no terminator: clipped
            return sb.length() > 0 ? sb.toString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    // Resolve a CALL op's target to a callee name (follows thunks); null if not statically known.
    private String calleeNameOf(PcodeOp call) {
        Varnode t = call.getInput(0);
        if (t == null) return null;
        Address to = null;
        if (t.isConstant() && t.getOffset() != 0) {
            try { to = toAddr(t.getOffset()); } catch (Exception e) { to = null; }
        } else if (t.isAddress()) {
            to = t.getAddress();
        }
        if (to == null) return null;
        FunctionManager fm = currentProgram.getFunctionManager();
        Function f = fm.getFunctionAt(to);
        if (f != null) {
            if (f.isThunk()) {
                Function th = f.getThunkedFunction(true);
                if (th != null) return th.getName();
            }
            return f.getName();
        }
        Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(to);
        return s != null ? s.getName() : null;
    }

    private String addr0x(PcodeOp op) {
        return "0x" + Long.toHexString(op.getSeqnum().getTarget().getOffset());
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

        // Optional extra provenance sinks (firmware-specific command wrappers), comma-separated.
        // Key arg defaults to 0. Keeps the committed default lexicon vendor-neutral (CMD + FMT).
        String extraSinks = System.getenv("TMAP_EXTRA_SINKS");
        if (extraSinks != null && !extraSinks.trim().isEmpty()) {
            sinkKeyArg = new HashMap<>(SINK_KEYARG);
            for (String s : extraSinks.split(",")) {
                String n = s.trim();
                if (!n.isEmpty()) sinkKeyArg.put(n, 0);
            }
        }

        FunctionManager  fm     = currentProgram.getFunctionManager();
        SymbolTable      st     = currentProgram.getSymbolTable();
        ExternalManager  extMgr = currentProgram.getExternalManager();

        // 1. Functions + pseudocode
        StringBuilder funcsJson = new StringBuilder("[");
        boolean firstFunc = true;
        int funcCount = 0;

        // Name universe for the pseudocode-derived callee source: every defined function name in
        // THIS binary (thunks/externals included — a call to a thunked libc import is a real edge)
        // plus every imported symbol name. A scanned `name(` counts as a callee only if it lands
        // in here, so struct fields, locals, casts, and pcode helpers never leak in.
        Set<String> knownNames = new HashSet<>();
        for (Function fn : fm.getFunctions(true)) {
            String n = fn.getName();
            if (n != null && !n.isEmpty()) knownNames.add(n);
        }
        SymbolIterator knownExt = st.getExternalSymbols();
        while (knownExt.hasNext()) {
            Symbol esym = knownExt.next();
            if (esym == null) continue;
            String n = esym.getName();
            if (n != null && !n.isEmpty()) knownNames.add(n);
        }

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
            HighFunction hf = null;   // Varnode/def-use + block graph from the SAME decompile (design B)
            if (funcSize < 10) {
                // Leave pseudocode empty — populate_db.py handles null pseudocode fine.
            } else try {
                DecompileResults dr = decomp.decompileFunction(func, 20, monitor);
                if (dr != null && dr.decompileCompleted()) {
                    DecompiledFunction df = dr.getDecompiledFunction();
                    if (df != null) {
                        pseudocode = df.getC();
                    }
                    hf = dr.getHighFunction();   // reused, not a second decompile
                }
            } catch (Exception e) {
                pseudocode = "/* decompile_error: " + e.getMessage() + " */";
            }  // end if (funcSize >= 10)

            // Collect callee edges. Broaden beyond "CALL ref whose target is a Function AT that
            // address": PIC intra-.so calls go through PLT stubs / GOT slots, so the ref target is a
            // thunk/pointer/label, not the callee body → old getFunctionAt() returned null → the
            // edge was dropped (observed: an exported wrapper's callees came back empty while a
            // shared library showed a far higher empty-callees rate than its main daemon). Resolve
            // the target through: Function → thunked function → GOT pointer → symbol. Genuinely
            // register-indirect / runtime-computed targets stay omitted (honest: no static target).
            // ReferenceManager is used (not getCalledFunctions()) for OSGi compatibility.
            StringBuilder calleesArr = new StringBuilder("[");   // names only — existing consumer format, unchanged
            StringBuilder edgesArr   = new StringBuilder("[");   // {name,kind} — staged for optional call_edges, unemitted for now
            boolean firstCallee = true;
            int calleeCount = 0;
            // CALLEE_LIMIT caps the callee list (was 200 -> 300; dispatchers fan out wide). When it
            // IS hit the extra edges are NOT silently dropped: callees_truncated flags the record so
            // get_callees / get_xrefs never read a clipped callee (or synthesized-caller) set as the
            // complete call graph — the same silent-drop red line as strings/readers/data-gap.
            final int CALLEE_LIMIT = 300;
            boolean calleesTruncated = false;
            Set<String> seenCallees = new HashSet<>();   // shared across both callee data sources
            try {
                ReferenceManager refMgr = currentProgram.getReferenceManager();
                SymbolTable       symtab = currentProgram.getSymbolTable();
                Listing           listing = currentProgram.getListing();
                InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
                scanRefs:
                while (instrIter.hasNext()) {
                    Instruction instr = instrIter.next();
                    Reference[] refs = refMgr.getReferencesFrom(instr.getAddress());
                    for (Reference ref : refs) {
                        RefType rt = ref.getReferenceType();
                        if (!rt.isCall()) continue;                  // isCall() already includes COMPUTED_CALL
                        String[] nk = resolveCallee(ref.getToAddress(), rt, fm, symtab, listing);
                        if (nk == null) continue;                    // unresolved indirect — honest omission
                        String calleeName = nk[0];
                        if (calleeName == null || calleeName.isEmpty()) continue;
                        if (calleeName.equals(funcName)) continue;    // drop self-name (self-ref noise)
                        if (!seenCallees.add(calleeName)) continue;   // dedupe by name
                        if (calleeCount >= CALLEE_LIMIT) { calleesTruncated = true; break scanRefs; }
                        if (!firstCallee) { calleesArr.append(","); edgesArr.append(","); }
                        firstCallee = false;
                        calleesArr.append("\"").append(esc(calleeName)).append("\"");
                        edgesArr.append("{\"name\":\"").append(esc(calleeName))
                                .append("\",\"kind\":\"").append(esc(nk[1])).append("\"}");
                        calleeCount++;
                    }
                }
            } catch (Exception ignored) {}

            // Second data source: recover callee names from the decompiled text itself. PIC
            // intra-.so calls via PLT/GOT often carry NO call reference, so the reference scan
            // above misses them even though the pseudocode plainly shows name(...) calls. Scan for
            // `identifier(` and keep only tokens that are known function / import names (the
            // intersection is the filter). Merge-deduped into the shared seenCallees set, so a name
            // already found via reference is never repeated. Boundary: a failed decompile leaves no
            // usable text, and function-pointer calls `(*p)(...)` expose no name — both honestly
            // omitted here.
            try {
                if (pseudocode != null && !pseudocode.isEmpty()
                        && !pseudocode.startsWith("/* decompile_error")) {
                    Matcher m = CALL_NAME.matcher(pseudocode);
                    scanText:
                    while (m.find()) {
                        String cand = m.group(1);
                        if (cand == null || cand.isEmpty()) continue;
                        if (C_KEYWORDS.contains(cand)) continue;
                        if (!knownNames.contains(cand)) continue;   // the real filter
                        if (cand.equals(funcName)) continue;         // drop self-name (self-ref noise)
                        if (!seenCallees.add(cand)) continue;        // dedupe vs the reference source
                        if (calleeCount >= CALLEE_LIMIT) { calleesTruncated = true; break scanText; }
                        if (!firstCallee) { calleesArr.append(","); edgesArr.append(","); }
                        firstCallee = false;
                        calleesArr.append("\"").append(esc(cand)).append("\"");
                        edgesArr.append("{\"name\":\"").append(esc(cand))
                                .append("\",\"kind\":\"pcode\"}");
                        calleeCount++;
                    }
                }
            } catch (Exception ignored) {}
            calleesArr.append("]");
            edgesArr.append("]");

            // sink_arg_provenance: Ghidra def-use fact for each command/format sink's key argument.
            // Reuses the decompile above (hf); empty [] when unavailable or no sink present. Never
            // throws out of the loop — provenance is additive evidence, not a gate.
            String sinkProv = "[]";
            try {
                if (hf != null) sinkProv = buildSinkProvenance(hf);
            } catch (Throwable ignore) {
                sinkProv = "[]";
            }

            // gap② phase 1: per-function nvram read/write ops. Additive evidence, never a gate.
            String nvramOps = "[]";
            try {
                if (hf != null) nvramOps = buildNvramOps(hf);
            } catch (Throwable ignore) {
                nvramOps = "[]";
            }

            if (!firstFunc) funcsJson.append(",");
            firstFunc = false;
            funcsJson.append("{")
                     .append("\"name\":")        .append("\"").append(esc(funcName))  .append("\",")
                     .append("\"address\":")     .append("\"").append(esc(funcAddr))  .append("\",")
                     .append("\"size\":")        .append(funcSize).append(",")
                     .append("\"is_exported\":") .append(isExported).append(",")
                     .append("\"callees\":")     .append(calleesArr).append(",")
                     .append("\"callees_truncated\":").append(calleesTruncated).append(",")
                     .append("\"sink_provenance\":").append(sinkProv).append(",")
                     .append("\"nvram_ops\":")   .append(nvramOps).append(",")
                     .append("\"pseudocode\":")  .append("\"").append(esc(pseudocode)).append("\"")
                     .append("}");
            funcCount++;
        }
        funcsJson.append("]");
        println("[ExportFunctions] functions: " + funcCount);

        // 2. Import symbols. Enumerate ALL external symbols via the SymbolTable, not only the
        //    ones filed under a *named* library. On stripped IoT firmware — and on any headless
        //    single-binary run, where there is no sibling program to resolve against — the
        //    decompiler files PLT-resolved imports under the <EXTERNAL> placeholder rather than
        //    a named .so. Walking getExternalLibraryNames() and skipping <EXTERNAL> therefore
        //    dropped EVERY import (the imports=0 / L1-xref=0 symptom). getExternalSymbols()
        //    returns the imports regardless of which namespace they ended up in; the library
        //    name is recorded only when one was actually resolved (else "" — never "<EXTERNAL>").
        StringBuilder importsJson = new StringBuilder("[");
        boolean firstImp = true;

        SymbolIterator extSyms = st.getExternalSymbols();
        while (extSyms.hasNext()) {
            Symbol sym = extSyms.next();
            if (sym == null) continue;
            // Keep the callable externals (PLT-imported functions); skip external data symbols.
            SymbolType stype = sym.getSymbolType();
            if (stype != SymbolType.FUNCTION && stype != SymbolType.LABEL) continue;
            String label = sym.getName();
            if (label == null || label.isEmpty()) continue;

            String libName = "";
            try {
                ExternalLocation loc = extMgr.getExternalLocation(sym);
                if (loc != null) {
                    String ln = loc.getLibraryName();
                    if (ln != null && !"<EXTERNAL>".equals(ln)) libName = ln;
                }
            } catch (Exception ignored) {}

            if (!firstImp) importsJson.append(",");
            firstImp = false;
            importsJson.append("{")
                       .append("\"func_name\":\"").append(esc(label)) .append("\",")
                       .append("\"lib_name\":\"" ).append(esc(libName)).append("\"")
                       .append("}");
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

        // 4. Strings from Ghidra defined Data.
        // STR_LIMIT raised from 2000: real config binaries (rc / libshared) carry several thousand
        // defined strings and were silently HALVED at 2000, so get_strings read a capped binary's
        // dropped string as "absent" (a fake-empty — the same silent-drop red line as readers:[] and
        // data-gap). Iterating defined string Data is cheap (not the decompile cost), so the cap is a
        // large safety bound, not a tuning knob. When it IS still hit, truncation is SURFACED
        // (strings_truncated / strings_total below) so a consumer never mistakes a cap for absence.
        StringBuilder stringsJson = new StringBuilder("[");
        boolean firstStr = true;
        int     strCount = 0;   // strings actually stored (bounded by STR_LIMIT)
        int     strTotal = 0;   // total matching strings seen (uncapped) — drives honest truncation
        boolean strCancelled = false;
        final int STR_LIMIT = 20000;

        DataIterator dataIter = currentProgram.getListing().getDefinedData(true);
        while (dataIter.hasNext()) {
            if (monitor.isCancelled()) { strCancelled = true; break; }

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

            // A matching string: always count it toward the true total; store it only under the cap.
            // Past the cap we keep iterating (cheap) so strTotal is exact and truncation is honest.
            strTotal++;
            if (strCount >= STR_LIMIT) continue;

            if (!firstStr) stringsJson.append(",");
            firstStr = false;
            stringsJson.append("{")
                       .append("\"value\":\""  ).append(esc(val))                       .append("\",")
                       .append("\"address\":\"").append(esc(data.getAddress().toString())).append("\"")
                       .append("}");
            strCount++;
        }
        stringsJson.append("]");
        // Truncated if the cap dropped matches OR a cancel cut the count short (then strTotal is a
        // lower bound and completeness is unknown — flag it rather than imply a clean count).
        boolean strTruncated = strTotal > strCount || strCancelled;
        println("[ExportFunctions] strings: " + strCount + " stored / " + strTotal + " total"
                + (strTruncated ? " (TRUNCATED)" : ""));

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
            pw.print("\"strings\":"    + stringsJson + ",");
            // Honest truncation transport: strings_total is the true match count (>= stored), and
            // strings_truncated says the stored list is a prefix. get_strings surfaces both so a
            // capped/searched binary never reads its missing string as "absent".
            pw.print("\"strings_total\":"     + strTotal + ",");
            pw.print("\"strings_truncated\":" + strTruncated);
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
