# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Cross-binary reference builder (4-layer algorithm) + string classifier.

Layer 0: callees × exports  (primary, function-level, confidence=1.0)
Layer 1: imports × exports  (fallback, confidence=1.0)
Layer 2: dt_needed          (library-level, confidence=0.9)
Layer 3: string_ipc         (soft link, confidence=0.5)

Also classifies all strings via STRING_RULES.

Semantics: wipe-and-rebuild. xrefs is always derivable from current DB state.

NOTE on imports and Layer 1 on stripped MIPS/ARM firmware:
  Layer 0 (callees x exports) is the PRIMARY cross-binary call-graph source and does not
  depend on the ExternalManager, so the graph stands even when imports are sparse.
  Layer 1 (imports x exports) is a complementary, function-level signal and feeds component
  fidelity. imports=0 is NOT expected on a dynamically-linked binary: it indicates the
  extractor failed to enumerate external symbols (historically: the export script only
  walked NAMED external libraries and skipped the <EXTERNAL> placeholder, where PLT-resolved
  imports land on stripped firmware / headless single-binary runs). That has been fixed in
  the export script; a binary that still reports imports=0 should be treated as a
  data-quality gap to investigate, not as normal.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Type alias for the dedup-and-queue function passed to layer helpers.
# Signature: (caller_bid, caller_fid, callee_bid, callee_fid, xref_type, confidence) -> inserted
_AddFn = Callable[[int, "int | None", int, "int | None", str, float], bool]

# ★ Large-firmware scaling. Edges are flushed to the DB every XREF_FLUSH_BATCH rows so the in-memory
# ``pending`` list stays bounded regardless of total edge count (a 679-binary firmware produces
# tens of millions of L0 edges; accumulating them all is what OOMs). The dedup ``seen`` set is not
# bounded by this — it is bounded by FOLDING (below), which keeps the high-fan-out generic symbols
# out of ``seen`` entirely.
XREF_FLUSH_BATCH = 50_000

# ★ L0 fold criterion (data-driven, tunable). A generic export name (malloc/memcpy/…) is exported by
# MANY binaries and called by MANY functions -> caller_refs × exporters low-value edges. The primary
# criterion is that EDGE CONTRIBUTION (callers × exporters); an exporter FLOOR guarantees a
# low-ambiguity symbol (few exporters, so each edge points at a near-unique target) is NEVER folded,
# no matter how widely it is called -- those are high-value edges. Conservative defaults: tune from
# the xref_folded_symbols ledger produced on the real firmware (fold too little -> re-lower;
# fold something specific -> raise). The threshold is overridable via config.
DEFAULT_FOLD_EDGE_THRESHOLD = 25_000
FOLD_MIN_EXPORTERS = 16

# Emit an L0 progress line every this-many caller functions (a large firmware has ~218k), so the
# multi-minute cross-binary pass is visibly running rather than looking hung.
_L0_PROGRESS_EVERY = 20_000


# ── String classification rules (ordered, first-match-wins) ──────────────────
# Ported from history/scripts/06_build_xrefs.py STRING_RULES.
# No trailing \b on crypto_hint — C-style identifiers like AES_set_encrypt_key
# must match (underscore is a word char so \bAES\b would not fire there).
STRING_RULES: list[tuple[str, str]] = [
    (
        "crypto_hint",
        r"(?i)\b(AES|RSA|SHA[-_]?\d*|MD5|3DES|DES|"
        r"HMAC|ECDSA|ECDH|EVP_|SSL_|TLS_|"
        r"openssl|mbedtls|wolfssl|libcrypto)",
    ),
    (
        "ipc_sock",
        r"(?i)(\.sock$|\.socket$|/var/run/\S+|"
        r"\.pipe$|/tmp/\S+\.(sock|pipe|fifo)|PIPE_|\.fifo$)",
    ),
    ("url", r"(?i)(https?://|ftp://|mqtt://|coap://|ws://)"),
    ("path", r"^/[a-zA-Z][a-zA-Z0-9_./\-]{3,}$"),
    ("nvram_key", r"^[A-Z][A-Z0-9_]{2,30}$"),
    ("format_str", r"%[0-9]*[sdifxXpuloO]"),
]

_COMPILED_STRING_RULES: list[tuple[str, re.Pattern[str]]] = [
    (cat, re.compile(pattern)) for cat, pattern in STRING_RULES
]

GENERIC_PATHS = frozenset(
    {
        "/tmp",
        "/var",
        "/proc",
        "/sys",
        "/dev",
        "/etc",
        "/usr",
        "/lib",
        "/bin",
        "/sbin",
        "/usr/lib",
        "/usr/bin",
    }
)


@dataclass
class XrefStats:
    """Returned by build_xrefs, surfaced to AnalyzeResult."""

    layer0_callees_exports: int = 0
    layer1_import_export_func: int = 0
    layer1_import_export_lib: int = 0
    layer2_dt_needed: int = 0
    layer3_string_ipc: int = 0
    strings_classified: int = 0
    # high-fan-out L0 symbols folded + edges suppressed (detail in xref_folded_symbols)
    layer0_folded_symbols: int = 0
    layer0_folded_edges: int = 0

    @property
    def layer1_total(self) -> int:
        return self.layer1_import_export_func + self.layer1_import_export_lib

    @property
    def total_xrefs(self) -> int:
        return (
            self.layer0_callees_exports
            + self.layer1_total
            + self.layer2_dt_needed
            + self.layer3_string_ipc
        )


# ── String classification helpers ─────────────────────────────────────────────


def categorize_string(s: str) -> str:
    """Classify a string into one of the categories defined in STRING_RULES,
    falling back to 'misc' if no rule matches.
    """
    for cat, pattern in _COMPILED_STRING_RULES:
        if pattern.search(s):
            return cat
    return "misc"


def is_useful_ipc_string(s: str) -> bool:
    """Filter for Layer 3 string_ipc: useful IPC-relevant strings only.

    Rejects generic paths, too-short/too-long values, pure digits.
    """
    if len(s) < 8 or len(s) > 150:
        return False
    stripped = s.rstrip("/")
    if stripped in GENERIC_PATHS or s in GENERIC_PATHS:
        return False
    if s.strip().isdigit():
        return False
    return True


# ── Soname resolution helpers ─────────────────────────────────────────────────


def _build_soname_map(cur: sqlite3.Cursor) -> dict[str, int]:
    """Build a {soname → binary_id} index with versioned-soname fallback.

    Handles: libssl.so.1.1 → libssl.so → libssl
    """
    soname_map: dict[str, int] = {}
    for bid, name in cur.execute("SELECT id, name FROM binaries"):
        soname_map[name] = bid
        base = re.sub(r"\.so(\.\d+)+$", ".so", name)
        if base != name:
            soname_map.setdefault(base, bid)
        no_ext = re.sub(r"\.so$", "", base)
        if no_ext != base:
            soname_map.setdefault(no_ext, bid)
    return soname_map


def _resolve_soname(soname: str, soname_map: dict[str, int]) -> int | None:
    """Resolve a soname (possibly versioned) to a binary_id."""
    bid = soname_map.get(soname)
    if bid is not None:
        return bid
    for variant in (
        re.sub(r"\.so(\.\d+)+$", ".so", soname),
        re.sub(r"\.so.*$", "", soname),
    ):
        bid = soname_map.get(variant)
        if bid is not None:
            return bid
    return None


# ── Caller index ──────────────────────────────────────────────────────────────


def _build_caller_index(cur: sqlite3.Cursor, binary_id: int) -> dict[str, list[int]]:
    """Build {callee_name → [caller_func_id, ...]} for one binary.

    Used by Layer 1 to find which specific functions call an imported symbol.
    """
    index: dict[str, list[int]] = defaultdict(list)
    rows = cur.execute(
        "SELECT id, callees FROM functions WHERE binary_id = ?",
        (binary_id,),
    ).fetchall()
    for func_id, callees_json in rows:
        try:
            callees = json.loads(callees_json or "[]")
        except json.JSONDecodeError:
            continue
        for name in callees:
            index[name].append(func_id)
    return index


# ── Main entry point ──────────────────────────────────────────────────────────


_INSERT_XREF = """INSERT INTO xrefs
       (caller_binary_id, caller_func_id, callee_binary_id,
        callee_func_id, xref_type, confidence)
       VALUES (?, ?, ?, ?, ?, ?)"""


def build_xrefs(
    conn: sqlite3.Connection, *, fold_edge_threshold: int = DEFAULT_FOLD_EDGE_THRESHOLD
) -> XrefStats:
    """Wipe and rebuild xrefs (+ the xref_folded_symbols ledger) from current DB state.

    Also classifies all strings whose category is currently NULL.

    Semantics: wipe-and-rebuild.

    Dedup strategy: in-memory set keyed by
    (caller_bid, caller_fid, callee_bid, callee_fid, xref_type).

    ★ Large-firmware scaling (memory is bounded, not the edge count):
      - inserts are FLUSHED every XREF_FLUSH_BATCH rows, so ``pending`` never grows unbounded
        (accumulating tens of millions of edges is what OOMed a 679-binary firmware);
      - L0 folds high-fan-out generic symbols (see _layer0), keeping ``seen`` bounded too and
        recording the constrained edges in xref_folded_symbols instead of silently dropping them.
      The flush is safe with the shared cursor: every layer materializes its outer query with
      .fetchall() first, so a mid-loop executemany cannot invalidate a live cursor iteration.
    """
    stats = XrefStats()
    cur = conn.cursor()

    cur.execute("DELETE FROM xrefs")
    cur.execute("DELETE FROM xref_folded_symbols")
    conn.commit()

    seen: set[tuple[int, int | None, int, int | None, str]] = set()
    pending: list[tuple[int, int | None, int, int | None, str, float]] = []

    def _flush() -> None:
        if pending:
            cur.executemany(_INSERT_XREF, pending)
            pending.clear()

    def _try_add(
        caller_binary_id: int,
        caller_func_id: int | None,
        callee_binary_id: int,
        callee_func_id: int | None,
        xref_type: str,
        confidence: float,
    ) -> bool:
        key = (caller_binary_id, caller_func_id, callee_binary_id, callee_func_id, xref_type)
        if key in seen:
            return False
        seen.add(key)
        pending.append(
            (
                caller_binary_id,
                caller_func_id,
                callee_binary_id,
                callee_func_id,
                xref_type,
                confidence,
            )
        )
        if len(pending) >= XREF_FLUSH_BATCH:
            _flush()  # bound memory: move the batch to the DB and free the Python list
        return True

    soname_map = _build_soname_map(cur)

    folded_ledger: list[tuple[str, int, int, int]] = []
    _layer0_callees_exports(
        cur, _try_add, stats, fold_edge_threshold=fold_edge_threshold, folded_out=folded_ledger
    )
    _layer1_import_export(cur, _try_add, soname_map, stats)
    _layer2_dt_needed(cur, _try_add, soname_map, stats)
    _classify_strings(cur, conn, stats)
    _layer3_string_ipc(cur, _try_add, stats)

    _flush()  # the tail below the last batch boundary
    if folded_ledger:
        cur.executemany(
            "INSERT INTO xref_folded_symbols (symbol, exporters, callers, folded_edges) "
            "VALUES (?, ?, ?, ?)",
            folded_ledger,
        )
    conn.commit()

    logger.info(
        "xrefs: L0=%d (folded %d syms / %d edges) L1=%d (func=%d lib=%d) L2=%d L3=%d, "
        "%d strings classified, total %d xrefs",
        stats.layer0_callees_exports,
        stats.layer0_folded_symbols,
        stats.layer0_folded_edges,
        stats.layer1_total,
        stats.layer1_import_export_func,
        stats.layer1_import_export_lib,
        stats.layer2_dt_needed,
        stats.layer3_string_ipc,
        stats.strings_classified,
        stats.total_xrefs,
    )
    return stats


# ── Layer implementations ─────────────────────────────────────────────────────


def _layer0_callees_exports(
    cur: sqlite3.Cursor,
    add_fn: _AddFn,
    stats: XrefStats,
    *,
    fold_edge_threshold: int = DEFAULT_FOLD_EDGE_THRESHOLD,
    folded_out: list[tuple[str, int, int, int]] | None = None,
) -> None:
    """Layer 0: function.callees × exports exact match.

    Primary layer — works without Ghidra ExternalManager, critical for
    stripped MIPS/ARM IoT firmware.

    NOTE: Outer query uses .fetchall() to materialize the result set before
    iterating — add_fn uses the same cursor internally and would otherwise
    invalidate the outer iteration after the first row (SQLite cursor
    re-entry semantics).

    NOTE: Export index is built with an INNER JOIN, so only exports that have
    a concrete function record are included. PLT thunks (exports with no
    matching function body) are excluded. Including them would bloat the xrefs
    table ~10x with NULL-callee rows that convey no actionable information.

    ★ FOLD (large-firmware scaling): a generic export name exported by MANY binaries and called by
    MANY functions produces caller × exporter low-value edges (which of 300 mallocs? — noise). A
    symbol is FOLDED when its edge contribution (callers × exporters) exceeds the threshold AND it
    clears the exporter floor (FOLD_MIN_EXPORTERS) — the floor guarantees a low-ambiguity
    symbol (few exporters, near-unique target/edge) is never folded. Folded edges are NOT written
    to xrefs, but they are NEVER silently dropped: each folded symbol's (exporters, callers,
    folded_edges) counts go to ``folded_out`` -> the xref_folded_symbols ledger.
    """
    export_index: dict[str, list[tuple[int, int]]] = defaultdict(list)
    rows = cur.execute(
        """SELECT e.binary_id, e.func_name, f.id AS func_id
           FROM exports e
           JOIN functions f
               ON f.binary_id = e.binary_id AND f.name = e.func_name
           WHERE e.func_name IS NOT NULL AND e.func_name != ''"""
    ).fetchall()
    for exp_binary_id, exp_func_name, callee_func_id in rows:
        export_index[exp_func_name].append((exp_binary_id, callee_func_id))

    func_rows = cur.execute(
        """SELECT id, binary_id, callees FROM functions
           WHERE callees IS NOT NULL AND callees != '[]'"""
    ).fetchall()

    # Pass 1: parse callees once, count caller references per exported name (the edge-contribution
    # numerator). ``parsed`` reuses the parse so pass 2 does not re-json.loads 218k rows.
    parsed: list[tuple[int, int, list[str]]] = []
    caller_refs: dict[str, int] = defaultdict(int)
    for caller_func_id, caller_binary_id, callees_json in func_rows:
        try:
            callees = json.loads(callees_json)
        except json.JSONDecodeError:
            continue
        names = [n for n in callees if n in export_index]
        if not names:
            continue
        parsed.append((caller_func_id, caller_binary_id, names))
        for n in names:
            caller_refs[n] += 1

    # Decide the folded set by EDGE CONTRIBUTION, gated by the exporter floor.
    folded_bins: dict[str, set[int]] = {}
    for name, callers in caller_refs.items():
        exporters = len(export_index[name])
        if exporters >= FOLD_MIN_EXPORTERS and callers * exporters > fold_edge_threshold:
            folded_bins[name] = {b for b, _ in export_index[name]}

    # Pass 2: build edges for non-folded names; COUNT (never build) the constrained edges of folded
    # names into the ledger.
    fold_edges: dict[str, int] = defaultdict(int)
    total = len(parsed)
    for done, (caller_func_id, caller_binary_id, names) in enumerate(parsed, 1):
        # ★ periodic progress so a long L0 pass (218k functions on a large firmware) is visibly
        # RUNNING, not hung -- the owner should not need py-spy to tell the difference.
        if done % _L0_PROGRESS_EVERY == 0:
            logger.info(
                "xrefs L0: %d/%d funcs, %d edges so far", done, total, stats.layer0_callees_exports
            )
        for callee_name in names:
            if callee_name in folded_bins:
                exps = folded_bins[callee_name]
                fold_edges[callee_name] += len(export_index[callee_name]) - (
                    1 if caller_binary_id in exps else 0
                )
                continue
            for callee_binary_id, callee_func_id in export_index[callee_name]:
                if callee_binary_id == caller_binary_id:
                    continue
                if add_fn(
                    caller_binary_id,
                    caller_func_id,
                    callee_binary_id,
                    callee_func_id,
                    "callees_exports",
                    1.0,
                ):
                    stats.layer0_callees_exports += 1

    for name in sorted(folded_bins):
        edges = fold_edges[name]
        stats.layer0_folded_symbols += 1
        stats.layer0_folded_edges += edges
        if folded_out is not None:
            folded_out.append((name, len(export_index[name]), caller_refs[name], edges))


def _layer1_import_export(
    cur: sqlite3.Cursor,
    add_fn: _AddFn,
    soname_map: dict[str, int],
    stats: XrefStats,
) -> None:
    """Layer 1: Ghidra imports × exports (fallback).

    Only effective when Ghidra populated imports.lib_soname. On stripped
    MIPS/ARM IoT firmware, imports table is empty — this layer produces 0
    rows. That is expected, not a bug.
    """
    imports = cur.execute(
        """SELECT binary_id, func_name, lib_soname
           FROM imports
           WHERE lib_soname IS NOT NULL AND lib_soname != ''"""
    ).fetchall()

    if not imports:
        return

    by_binary: dict[int, list[tuple[str, str]]] = defaultdict(list)
    for caller_bid, func_name, soname in imports:
        by_binary[caller_bid].append((func_name, soname))

    callee_func_cache: dict[tuple[int, str], int | None] = {}

    for caller_bid, import_list in by_binary.items():
        caller_index = _build_caller_index(cur, caller_bid)

        for func_name, soname in import_list:
            dep_id = _resolve_soname(soname, soname_map)
            if dep_id is None or dep_id == caller_bid:
                continue

            key = (dep_id, func_name)
            if key not in callee_func_cache:
                r = cur.execute(
                    "SELECT id FROM functions WHERE binary_id = ? AND name = ?",
                    (dep_id, func_name),
                ).fetchone()
                callee_func_cache[key] = r[0] if r else None
            callee_func_id = callee_func_cache[key]

            caller_func_ids = caller_index.get(func_name, [])
            if caller_func_ids:
                for cfid in caller_func_ids:
                    if add_fn(caller_bid, cfid, dep_id, callee_func_id, "import_export", 1.0):
                        stats.layer1_import_export_func += 1
            else:
                if add_fn(caller_bid, None, dep_id, callee_func_id, "import_export", 1.0):
                    stats.layer1_import_export_lib += 1


def _layer2_dt_needed(
    cur: sqlite3.Cursor,
    add_fn: _AddFn,
    soname_map: dict[str, int],
    stats: XrefStats,
) -> None:
    """Layer 2: ELF DT_NEEDED → library-level dependency edges."""
    rows = cur.execute("SELECT id, dt_needed FROM binaries WHERE dt_needed != '[]'").fetchall()
    for bid, dt_json in rows:
        try:
            dt_needed = json.loads(dt_json)
        except (json.JSONDecodeError, TypeError):
            continue
        for soname in dt_needed:
            dep_id = _resolve_soname(soname, soname_map)
            if dep_id is None or dep_id == bid:
                continue
            if add_fn(bid, None, dep_id, None, "dt_needed", 0.9):
                stats.layer2_dt_needed += 1


def _classify_strings(cur: sqlite3.Cursor, conn: sqlite3.Connection, stats: XrefStats) -> None:
    """Fill strings.category for rows where it's currently NULL."""
    rows = cur.execute("SELECT id, value FROM strings WHERE category IS NULL").fetchall()
    batch_size = 1000
    for i in range(0, len(rows), batch_size):
        batch = rows[i : i + batch_size]
        updates = [(categorize_string(val or ""), sid) for sid, val in batch]
        cur.executemany("UPDATE strings SET category = ? WHERE id = ?", updates)
        conn.commit()
    stats.strings_classified = len(rows)


def _layer3_string_ipc(
    cur: sqlite3.Cursor,
    add_fn: _AddFn,
    stats: XrefStats,
) -> None:
    """Layer 3: pairwise xrefs for binaries sharing a useful IPC string."""
    ipc_rows = cur.execute(
        """SELECT value, GROUP_CONCAT(DISTINCT binary_id) AS bids
           FROM strings
           WHERE category IN ('ipc_sock', 'path', 'crypto_hint')
           GROUP BY value
           HAVING COUNT(DISTINCT binary_id) >= 2"""
    ).fetchall()
    for val, bids_str in ipc_rows:
        if not is_useful_ipc_string(val or ""):
            continue
        bids = sorted({int(x) for x in bids_str.split(",")})
        for i in range(len(bids)):
            for j in range(i + 1, len(bids)):
                if add_fn(bids[i], None, bids[j], None, "string_ipc", 0.5):
                    stats.layer3_string_ipc += 1
