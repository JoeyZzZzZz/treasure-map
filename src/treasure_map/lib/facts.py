# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Thin, read-only fact accessors over an analysis database — the layer CLI and MCP share.

These functions expose the structured, deterministically re-derivable facts the analysis pass
recorded (pseudocode, cross-references, callees, strings, imports/exports, cross-artifact script
call sites, SBOM components + CVE matches). They are a single read layer so the CLI and the MCP
server are thin wrappers over the SAME query — neither re-implements a lookup.

Discipline (these are public-facing facts, the strictest neutrality applies):
- FACTS ONLY. No interpretation, no prediction, no score. The dropped pre-judgment columns
  (summary / vuln_hint / has_user_input / library_summaries) are never read or reconstructed.
- EVERY returned record carries an anchor (binary + function + address, or script + line) so a
  consumer can locate the evidence; a lookup that resolves nothing returns a "not found" record
  rather than a fabricated answer (the no-anchor-no-output contract).
- The strings / script raw_line values are the artifact's OWN content (analysis evidence), never
  a generated payload. Nothing here produces an attack input.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Literal

from treasure_map.lib.hunt.refs import _norm_addr
from treasure_map.version import UNKNOWN_VERSION

XrefDirection = Literal["callers", "callees", "address_taken"]

# The iron-law note on every address-taken result: it is a FACT (F's entry is referenced as a
# data/pointer value here), NEVER a dispatch/reachability verdict. Whether/how F is then called
# through that stored pointer is the consumer's to trace.
_ADDRTAKEN_NOTE = (
    "address-taken FACTS: each edge is a place F's ENTRY address is referenced as a data/pointer "
    "value (a dispatch-table slot or a literal-pool `ldr =F`), and taken_in_func is the function "
    "that took it. This is NOT proof F is dispatched or reachable — whether and how the stored "
    "pointer is later called is for you to trace (a fact, never a routing verdict)."
)
_ADDRTAKEN_EMPTY_NOTE = (
    "no address-taken sites recorded: F's entry is not referenced as a data/pointer value in this "
    "binary's analysis. That is NOT proof F is uncalled — it may be reached by a direct call "
    "(get_xrefs direction=callers) or a mechanism static analysis did not resolve."
)
_ADDRTAKEN_TRUNC_NOTE = (
    "address-taken list TRUNCATED at the extractor cap: it is a prefix, so a site NOT listed may "
    "still exist; do not read this as the complete set"
)


def open_analysis_ro(db_path: Path | str) -> sqlite3.Connection:
    """Open an analysis database strictly read-only, with a Row factory."""
    conn = sqlite3.connect(f"file:{Path(db_path)}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def list_incomplete_binaries(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Current-scan binaries that produced 0 functions and are NOT legitimately code-free.

    ★ Red-line (degrade must be visible AND explicable): a binary Ghidra failed on holds 0
    functions, so it looks 'clean' to every reader. This surfaces each as ``{binary, reason}`` so a
    consumer knows the analysis is INCOMPLETE for it — and WHY (``timeout`` may finish on a re-scan;
    ``import_failed`` / ``incomplete`` is structural). ``reason`` is None on a failure recorded
    before it was captured. Empty on an older analysis.db predating the columns (degrades)."""
    try:
        rows = conn.execute(
            "SELECT b.name, b.ghidra_status_reason AS reason FROM current_binaries b "
            "WHERE COALESCE(b.ghidra_status, '') != 'ok_empty' "
            "AND NOT EXISTS (SELECT 1 FROM functions f WHERE f.binary_id = b.id) "
            "ORDER BY b.name"
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    return [{"binary": r["name"], "reason": r["reason"]} for r in rows]


def list_folded_xref_symbols(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """High-fan-out L0 export symbols whose per-edge expansion was CONSTRAINED (folded).

    ★ Red-line (constrained edges must be visible): a generic symbol exported by many binaries and
    called by many functions produces a low-value edge explosion; those edges are NOT written to
    xrefs, but they are NOT silently dropped either. This surfaces each folded symbol with
    ``{symbol, exporters, callers, folded_edges}`` so a consumer knows "N edges were suppressed for
    symbol X" and can ask for them if a specific case needs them — absence of an L0 edge to a folded
    symbol is a scaling decision, not proof there is no call. Empty on an older analysis.db that
    predates the ``xref_folded_symbols`` table (the read degrades quietly rather than error)."""
    try:
        rows = conn.execute(
            "SELECT symbol, exporters, callers, folded_edges FROM xref_folded_symbols "
            "ORDER BY folded_edges DESC, symbol"
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    return [dict(r) for r in rows]


# A function large enough that Ghidra should have produced pseudocode. Sub-threshold bodies (thunks,
# PLT stubs, tiny leaf trampolines) are legitimately decompile-free, so an empty one there is NOT a
# failure. Mirrors ExportFunctions' own funcSize>=10 judgement, so this read counts the same set.
_DECOMPILE_MIN_SIZE = 10


def list_partially_incomplete_binaries(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Current-scan binaries that HAVE functions but where some failed to decompile.

    ★ Red-line (partial completeness must be visible): a binary can carry hundreds of functions and
    still read ``ghidra_status='ok'`` while N of its functions never decompiled (empty pseudocode).
    ``list_incomplete_binaries`` only catches the all-or-nothing 0-function failures, so those N
    silently-missing functions look analyzed. This surfaces each such binary with
    ``{binary, functions_total, functions_empty}`` so a consumer knows the candidate set is
    INCOMPLETE on those functions — not that they are clean.

    Only functions at/above ``_DECOMPILE_MIN_SIZE`` bytes count as failures; smaller bodies (thunks,
    PLT stubs) are legitimately pseudocode-free and are excluded, so a normal micro-function is
    never mis-reported as an incomplete decompile. Empty on an older analysis.db lacking columns."""
    try:
        rows = conn.execute(
            "SELECT b.name AS binary, COUNT(*) AS functions_total, "
            "SUM(CASE WHEN f.size_bytes >= ? "
            "         AND (f.pseudocode IS NULL OR f.pseudocode = '') "
            "    THEN 1 ELSE 0 END) AS functions_empty "
            "FROM current_binaries b JOIN functions f ON f.binary_id = b.id "
            "GROUP BY b.id, b.name "
            "HAVING functions_empty > 0 "
            "ORDER BY functions_empty DESC, b.name",
            (_DECOMPILE_MIN_SIZE,),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    return [
        {
            "binary": r["binary"],
            "functions_total": r["functions_total"],
            "functions_empty": r["functions_empty"],
        }
        for r in rows
    ]


def analysis_run_counts(conn: sqlite3.Connection) -> dict[str, Any]:
    """Scan-lineage facts from an analysis.db: binary/function counts + the extraction build hash.

    Written into the atlas ``run`` row so list_runs / ``tmap runs`` can show a scan's size and
    detect a STALE scan. ``build_hash`` is the DISTINCT ``pass_version`` over the current scan's
    binaries (the extraction-pass content hash): one value = a uniform build; ``mixed:<n>`` = the
    scan spans more than one pass version; None when unknown. ``ghidra_version`` is the decompiler
    version behind the scan (see ``_run_ghidra_version``) and is ALWAYS a string, never None.
    ``functions_empty`` reuses the partial-decompile red-line count. Every other field degrades to
    None/0 on an older analysis.db that lacks a column (the lineage is best-effort, never a hard
    failure of the scan)."""
    try:
        binaries = conn.execute("SELECT COUNT(*) FROM current_binaries").fetchone()[0]
        functions = conn.execute(
            "SELECT COUNT(*) FROM functions f JOIN current_binaries b ON b.id = f.binary_id"
        ).fetchone()[0]
    except sqlite3.OperationalError:
        return {
            "binaries": None,
            "functions": None,
            "functions_empty": None,
            "build_hash": None,
            "ghidra_version": UNKNOWN_VERSION,
        }
    functions_empty = sum(b["functions_empty"] for b in list_partially_incomplete_binaries(conn))
    build_hash: str | None
    try:
        versions = [
            r[0]
            for r in conn.execute(
                "SELECT DISTINCT pass_version FROM current_binaries "
                "WHERE pass_version IS NOT NULL ORDER BY pass_version"
            ).fetchall()
        ]
    except sqlite3.OperationalError:
        versions = []
    if len(versions) == 1:
        build_hash = versions[0]
    elif len(versions) > 1:
        build_hash = f"mixed:{len(versions)}"
    else:
        build_hash = None
    return {
        "binaries": binaries,
        "functions": functions,
        "functions_empty": functions_empty,
        "build_hash": build_hash,
        "ghidra_version": _run_ghidra_version(conn),
    }


def _run_ghidra_version(conn: sqlite3.Connection) -> str:
    """The ONE Ghidra version behind this scan's usable output, else the explicit ``unknown``.

    Population = the current scan's binaries whose Ghidra output was usable (``ghidra_ok = 1``);
    rows that produced nothing carry no version and cannot make the run's version un-confirmable.

    Returns a single version ONLY when every row in that population declares the SAME one. A NULL
    among them (produced before this was recorded), more than one distinct value (a scan spanning
    two installations), an empty population, or a missing column all collapse to ``unknown`` --
    which reads downstream as "cannot confirm this run's decompiler version", NOT as "same as the
    other side". The per-binary column keeps the detail a collapsed rollup drops."""
    try:
        rows = conn.execute(
            "SELECT DISTINCT ghidra_version FROM current_binaries WHERE ghidra_ok = 1"
        ).fetchall()
    except sqlite3.OperationalError:
        return UNKNOWN_VERSION
    versions = [r[0] for r in rows]
    if len(versions) == 1 and versions[0]:
        return str(versions[0])
    return UNKNOWN_VERSION


def _anchor(binary: str | None, name: str | None, address: str | None) -> dict[str, Any]:
    return {"binary": binary, "function": name, "address": address}


def _parse_callees(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return [str(x) for x in data] if isinstance(data, list) else []


def _addr_candidates(func: str) -> set[str]:
    """Canonical stored-address forms ``func`` could denote.

    The analysis schema stores a function address as zero-padded 8-digit lowercase hex (e.g.
    ``00038de8``). A consumer may type the same address many ways: ``0x38de8`` / ``38de8`` /
    ``00038de8`` / ``232424`` (decimal) / ``FUN_00038de8`` (the decompiler's address-named symbol).
    Each is normalized to the stored form so any of them resolves the function. An ``0x`` or
    ``FUN_`` prefix marks the token as unambiguously hex; a bare all-digit token is offered as BOTH
    hex and decimal (only the form that actually exists can match, so offering both is safe)."""
    tok = func.strip()
    explicit_hex = False
    if tok[:4].upper() == "FUN_":
        tok = tok[4:]
        explicit_hex = True
    if tok[:2].lower() == "0x":
        tok = tok[2:]
        explicit_hex = True
    out: set[str] = set()
    try:
        out.add(format(int(tok, 16), "08x"))
    except ValueError:
        return out
    if not explicit_hex and tok.isdigit():
        out.add(format(int(tok, 10), "08x"))
    return out


def _match_functions(conn: sqlite3.Connection, func: str, binary: str | None) -> list[sqlite3.Row]:
    """Functions whose name OR address denotes ``func`` (optionally scoped to one binary).

    Address matching is twofold: the literal ``func`` as stored (covers a DB that keeps the typed
    form) AND any normalized 8-hex candidate (covers the zero-padded stored form). ``binary`` is
    matched against the short name OR the full path, so the binary_path a candidate listing returns
    resolves directly."""
    addrs = sorted(_addr_candidates(func))
    where = ["f.name = ?", "f.address = ?"]
    params: list[str] = [func, func]
    if addrs:
        where.append(f"f.address IN ({','.join('?' for _ in addrs)})")
        params.extend(addrs)
    sql = (
        "SELECT f.id, f.binary_id, f.name, f.address, f.size_bytes, f.pseudocode, f.callees, "
        "f.callees_truncated, f.is_exported, f.unresolved_external_calls, "
        "b.name AS binary_name, b.path AS binary_path "
        "FROM functions f JOIN binaries b ON b.id = f.binary_id "
        f"WHERE ({' OR '.join(where)})"  # noqa: S608 -- placeholders only; values stay bound params
    )
    if binary is not None:
        sql += " AND (b.name = ? OR b.path = ?)"
        params.extend([binary, binary])
    sql += " ORDER BY b.name, f.address"
    return conn.execute(sql, params).fetchall()


def _resolve_one(
    conn: sqlite3.Connection, func: str, binary: str | None
) -> tuple[sqlite3.Row | None, dict[str, Any] | None]:
    """Resolve ``func`` to exactly one function row.

    Returns (row, None) on a unique match, or (None, not_found_record) when nothing matches or the
    name is ambiguous across binaries (the record lists the candidate anchors to disambiguate)."""
    rows = _match_functions(conn, func, binary)
    if not rows:
        return None, {"found": False, "query": {"function": func, "binary": binary}}
    if len(rows) > 1:
        return None, {
            "found": False,
            "reason": "ambiguous",
            "query": {"function": func, "binary": binary},
            "candidates": [_anchor(r["binary_name"], r["name"], r["address"]) for r in rows],
        }
    return rows[0], None


# A callee list that hit the extractor cap is a PREFIX, not the whole call graph — said on every
# result that carries a truncated list so the missing edges are never read as "no such callee".
_CALLEES_TRUNC_NOTE = (
    "callees TRUNCATED: this function's callee list hit the extractor cap (a wide dispatcher), so "
    "it is a prefix — a callee NOT listed may still exist; do not read this as the complete set"
)
_UNRESOLVED_EXT_NOTE = (
    "UNCLASSIFIED EXTERNAL CALLS: this function calls a lazy-binding stub the pure-ELF resolver "
    "could not name — a possible unrecognized libc sink (system/exec/…) the decompiler dropped and "
    "the resolver could not recover. A completeness lead, not a verdict; read the pseudocode at "
    "each address before trusting an empty sink list for this function"
)


def _col(row: Any, name: str) -> Any:
    """A column value that tolerates an older analysis.db missing it (returns None)."""
    try:
        return row[name]
    except (IndexError, KeyError):
        return None


def get_pseudocode(
    conn: sqlite3.Connection, *, func: str, binary: str | None = None
) -> dict[str, Any]:
    """Decompiler pseudocode for one function (the default read view), with its anchor.

    ``func`` may be a function name or an address in any common form (``0x38de8`` / ``38de8`` /
    ``00038de8`` / ``232424`` decimal / ``FUN_00038de8``). ``binary`` accepts the short name or the
    full path. Returns a not-found record (never a guess) when the function does not resolve
    uniquely; an ambiguous name lists the candidate anchors to disambiguate."""
    row, miss = _resolve_one(conn, func, binary)
    if row is None:
        assert miss is not None
        return miss
    truncated = bool(row["callees_truncated"])
    result: dict[str, Any] = {
        "found": True,
        "anchor": _anchor(row["binary_name"], row["name"], row["address"]),
        "binary_path": row["binary_path"],
        "size_bytes": row["size_bytes"],
        "is_exported": bool(row["is_exported"]),
        "callees": _parse_callees(row["callees"]),
        "callees_truncated": truncated,
        "pseudocode": row["pseudocode"],
    }
    # Stub calls the ELF resolver could not name: a possible unrecognized libc sink this function
    # makes that is left visible rather than read as an ordinary internal call. Surfaced only when
    # present, so it is never noise on the ordinary case.
    unresolved = _parse_callees(_col(row, "unresolved_external_calls"))
    if unresolved:
        result["unresolved_external_calls"] = unresolved
        result["unresolved_external_calls_note"] = _UNRESOLVED_EXT_NOTE
    if truncated:
        result["note"] = _CALLEES_TRUNC_NOTE
    return result


def get_callees(
    conn: sqlite3.Connection, *, func: str, binary: str | None = None
) -> dict[str, Any]:
    """The direct callee names of one function (intra-binary edges resolved by name).

    Each callee is marked ``resolved`` when a function of that name exists in the SAME binary (so
    a consumer can fetch its pseudocode and follow the chain itself — multi-hop is the consumer's
    to walk, not a tool blind spot)."""
    row, miss = _resolve_one(conn, func, binary)
    if row is None:
        assert miss is not None
        return miss
    binary_name = row["binary_name"]
    same_binary = {
        r["name"]
        for r in conn.execute(
            "SELECT f.name FROM functions f JOIN binaries b ON b.id = f.binary_id "
            "WHERE b.name = ? AND f.name IS NOT NULL",
            (binary_name,),
        )
    }
    callees = _parse_callees(row["callees"])
    truncated = bool(row["callees_truncated"])
    result: dict[str, Any] = {
        "found": True,
        "anchor": _anchor(binary_name, row["name"], row["address"]),
        "callees": [{"name": c, "resolved_in_binary": c in same_binary} for c in callees],
        "callees_truncated": truncated,
    }
    if truncated:
        result["note"] = _CALLEES_TRUNC_NOTE
    return result


def get_xrefs(
    conn: sqlite3.Connection,
    *,
    func: str,
    direction: XrefDirection = "callers",
    binary: str | None = None,
) -> dict[str, Any]:
    """Cross-reference edges for one function.

    direction='callers' returns the functions that reference this one; 'callees' returns the
    functions it references; 'address_taken' returns where this function's ENTRY is referenced as a
    DATA/POINTER value (a dispatch-table slot or a literal-pool ``ldr =F``) and which function took
    it — a fact for locating a function-pointer registration, NEVER a dispatch/reachability verdict.
    Cross-binary edges (an import resolved to another binary's export) are included for callers/
    callees — that is the value over a single decompiler view.

    The xref table only records cross-binary edges, so for 'callers' a same-binary caller is
    recovered as a fallback by reverse-scanning each function's recorded callee list (xref_type
    ``intra_callees``). When that still finds nothing, a ``note`` says so honestly and flags that
    the function may yet be reached via an indirect / dispatch-table / function-pointer call that
    static analysis cannot resolve — a true unresolved caller is NOT silently the same as 'none'."""
    row, miss = _resolve_one(conn, func, binary)
    if row is None:
        assert miss is not None
        return miss
    if direction == "address_taken":
        return _address_taken_xrefs(conn, row)
    fid = row["id"]
    if direction == "callers":
        match_col, other_func, other_bin = "callee_func_id", "caller_func_id", "caller_binary_id"
    else:
        match_col, other_func, other_bin = "caller_func_id", "callee_func_id", "callee_binary_id"
    rows = conn.execute(
        f"SELECT x.{other_func} AS ofid, x.{other_bin} AS obid, x.xref_type "  # noqa: S608
        f"FROM xrefs x WHERE x.{match_col} = ?",  # noqa: S608
        (fid,),
    ).fetchall()
    edges: list[dict[str, Any]] = []
    for r in rows:
        of = conn.execute(
            "SELECT f.name, f.address, b.name AS bn FROM functions f "
            "JOIN binaries b ON b.id = f.binary_id WHERE f.id = ?",
            (r["ofid"],),
        ).fetchone()
        bn = of["bn"] if of else _binary_name(conn, r["obid"])
        edges.append(
            {
                "anchor": _anchor(bn, of["name"] if of else None, of["address"] if of else None),
                "xref_type": r["xref_type"],
                "library_level": of is None,  # NULL func id = a binary/library-level reference
            }
        )
    notes: list[str] = []
    if direction == "callers":
        _append_callee_reverse_callers(conn, row, edges)
        if not edges:
            notes.append(
                "no direct callers found; may be reached via an indirect/dispatch-table/"
                "function-pointer call that static analysis cannot resolve"
            )
        # Same-binary callers are reverse-resolved from callee lists; a caller whose OWN callee list
        # was truncated at the cap may have dropped this target, so it is silently absent here. Warn
        # whenever the binary has any truncated list — an empty/short caller set is not proof.
        if conn.execute(
            "SELECT 1 FROM functions WHERE binary_id = ? AND callees_truncated = 1 LIMIT 1",
            (row["binary_id"],),
        ).fetchone():
            notes.append(
                "some functions in this binary have a TRUNCATED callee list (a wide dispatcher hit "
                "the extractor cap), so a same-binary caller reverse-resolved from callee lists "
                "can be MISSING; an empty or short caller set is not proof of no caller"
            )
    result: dict[str, Any] = {
        "found": True,
        "anchor": _anchor(row["binary_name"], row["name"], row["address"]),
        "direction": direction,
        "edges": edges,
    }
    if notes:
        result["note"] = " | ".join(notes)
    return result


def _address_taken_xrefs(conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    """Address-taken edges for one function F: where F's ENTRY is referenced as a data/pointer value
    (a .data dispatch-table slot or a .text literal-pool ``ldr =F``), and which function took it.

    Reads the per-function ``address_taken`` transport column (Ghidra ``getReferencesTo(F.entry)``
    filtered to non-call, non-flow refs). ``taken_at`` / ``taken_in_func_addr`` are canonicalized
    with the SAME ``_norm_addr`` as evidence_ref, so a re-scan yields byte-identical addresses. IRON
    LAW: a FACT (F's address is taken here, by this function), NEVER a dispatch/reachability verdict
    — the honest note says so and an empty result is an honest empty, never 'uncalled'."""
    r = conn.execute("SELECT address_taken FROM functions WHERE id = ?", (row["id"],)).fetchone()
    raw = r["address_taken"] if r is not None else None
    parsed: dict[str, Any] = {}
    if raw:
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                parsed = obj
        except (ValueError, TypeError):
            parsed = {}
    edges_raw = parsed.get("edges")
    takes = edges_raw if isinstance(edges_raw, list) else []
    edges: list[dict[str, Any]] = []
    for t in takes:
        if not isinstance(t, dict):
            continue
        edges.append(
            {
                "taken_at": _norm_addr(t.get("taken_at")),
                "taken_in_func": t.get("taken_in_func"),
                "taken_in_func_addr": _norm_addr(t.get("taken_in_func_addr")),
                "segment": t.get("segment"),
                "nearby_symbol": t.get("nearby_symbol"),
            }
        )
    notes = [_ADDRTAKEN_NOTE if edges else _ADDRTAKEN_EMPTY_NOTE]
    if parsed.get("truncated"):
        notes.append(_ADDRTAKEN_TRUNC_NOTE)
    return {
        "found": True,
        "anchor": _anchor(row["binary_name"], row["name"], row["address"]),
        "direction": "address_taken",
        "edges": edges,
        "note": " | ".join(notes),
    }


def _append_callee_reverse_callers(
    conn: sqlite3.Connection, row: sqlite3.Row, edges: list[dict[str, Any]]
) -> None:
    """Append same-binary direct callers recovered by reverse-scanning callee lists.

    The xref table carries no intra-binary function->function edge, but ``functions.callees`` does
    (each function's own out-edges). A function whose callee list contains the target by an exact
    name match is a direct caller. ``LIKE`` is only a prefilter; the membership test is on parsed
    JSON elements so a name that is a substring of another callee does not false-match."""
    target = row["name"]
    if not target:
        return
    seen = {(e["anchor"]["function"], e["anchor"]["binary"]) for e in edges}
    for fr in conn.execute(
        "SELECT f.name, f.address, f.callees, b.name AS bn FROM functions f "
        "JOIN binaries b ON b.id = f.binary_id WHERE f.binary_id = ? AND f.callees LIKE ?",
        (row["binary_id"], f"%{target}%"),
    ):
        if target not in _parse_callees(fr["callees"]):
            continue
        key = (fr["name"], fr["bn"])
        if key in seen:
            continue
        seen.add(key)
        edges.append(
            {
                "anchor": _anchor(fr["bn"], fr["name"], fr["address"]),
                "xref_type": "intra_callees",  # reverse-resolved from the caller's callee list
                "library_level": False,
            }
        )


def _binary_name(conn: sqlite3.Connection, binary_id: int | None) -> str | None:
    if binary_id is None:
        return None
    r = conn.execute("SELECT name FROM binaries WHERE id = ?", (binary_id,)).fetchone()
    return r["name"] if r else None


def _binary_id(conn: sqlite3.Connection, binary: str) -> int | None:
    r = conn.execute("SELECT id FROM binaries WHERE name = ?", (binary,)).fetchone()
    return int(r["id"]) if r else None


def _addr_int(address: str | None) -> int | None:
    if not address:
        return None
    try:
        return int(address, 16) if address.lower().startswith("0x") else int(address)
    except ValueError:
        return None


# The schema records each string's own location, never which function references it (Ghidra does
# not export string xrefs). Said honestly on every result so a consumer does not assume a reverse
# lookup the substrate cannot back.
_STRING_REF_NOTE = (
    "string reference sites (which function uses this string) are not indexed; resolve the "
    "address in a disassembler's xref view"
)

# ★ Honesty (declared≠actual): `function` is ECHOED on a strings result but does NOT scope it. A
# differential test confirmed results are binary-wide in BOTH modes: there is no string->function
# reference index, and code-range address filtering cannot reach .rodata string constants (their
# addresses fall outside any code function's range). Surfaced as this note PLUS a machine-readable
# ``func_scope_applied: false`` whenever `function` is passed, so a consumer (machine, which skims
# prose) never reads the echoed `function` field as a scoping guarantee.
_STRING_FUNC_SCOPE_NOTE = (
    "`function` does NOT narrow string results in EITHER mode (by-binary or value). There is no "
    "string->function reference index, and code-range address filtering cannot reach .rodata "
    "string constants — results are binary-wide regardless of `function`. `function` currently "
    "only gates existence in value mode (unresolvable name -> found:false). To scope strings to a "
    "function, resolve the address in a disassembler's xref view."
)
# A SHORT, top-level alert that repeats the note's headline where a consumer skimming the response
# keys sees it (the full detail stays in ``note``). Prominence, not new information — raised because
# the reported pain point was "you must read to the bottom note to learn `function` is a no-op".
_STRING_FUNC_SCOPE_WARNING = (
    "`function` was passed but does NOT scope these strings — results are binary-wide "
    "(func_scope_applied=false; see note). It only gates existence in value mode."
)


def _truncated_binaries(conn: sqlite3.Connection, binary_id: int | None = None) -> list[str]:
    """Names of binaries whose string export was truncated at the extractor cap (scoped to one
    binary when ``binary_id`` is given). A silent-drop guard: a value search over any of these can
    MISS a string dropped past the cap, so the result must say so rather than imply completeness."""
    if binary_id is not None:
        rows = conn.execute(
            "SELECT name FROM binaries WHERE id = ? AND strings_truncated = 1", (binary_id,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT name FROM binaries WHERE strings_truncated = 1 ORDER BY name"
        ).fetchall()
    return [r["name"] for r in rows]


# Default byte budget for ONE fact-tool page. A wide dispatcher's string table (400k+ chars in one
# result) overruns a single MCP return, so a large result is paged LOSSLESSLY by cumulative
# serialized size: the tail stays REACHABLE via next_offset and is NEVER summarized away. A summary
# could drop the exact string the consumer is hunting. Summaries are opt-in only, never
# the default.
_FACT_PAGE_CHARS = 20000


def _byte_page(
    rows: list[dict[str, Any]], offset: int, max_chars: int
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Slice ``rows`` from ``offset`` into a page whose serialized size stays within ``max_chars``.

    Lossless byte-pagination shared across fact tools: pages by ROW INDEX (a stable offset), never
    dropping or summarizing a row, and always emits at least one row so a single oversized row still
    makes progress. Returns (page, envelope) where the envelope is the STABLE shape:
    ``returned`` / ``offset`` / ``next_offset`` / ``truncated`` (this result was byte-paged, a tail
    follows) / ``total_matched`` (rows in the full set) / ``total_chars`` (its serialized size) /
    ``how_to_get_rest``. Distinct from any export-cap ``truncated`` a caller reports up top."""
    lo = max(0, offset)
    total = len(rows)
    total_chars = sum(len(str(r)) for r in rows)
    page: list[dict[str, Any]] = []
    used = 0
    i = lo
    while i < total:
        cost = len(str(rows[i]))
        if page and used + cost > max_chars:
            break
        page.append(rows[i])
        used += cost
        i += 1
    truncated = i < total
    envelope = {
        "returned": len(page),
        "offset": lo,
        "next_offset": i if truncated else None,
        "truncated": truncated,
        "total_matched": total,
        "total_chars": total_chars,
        "how_to_get_rest": (
            f"more rows remain — call again with offset={i} to page the tail losslessly "
            "(no summary; every row is preserved)"
            if truncated
            else None
        ),
    }
    return page, envelope


def get_strings(
    conn: sqlite3.Connection,
    *,
    binary: str | None = None,
    func: str | None = None,
    value: str | None = None,
    offset: int = 0,
    max_chars: int = _FACT_PAGE_CHARS,
) -> dict[str, Any]:
    """Recorded strings (value/address/category), located one step for the consumer.

    Two modes: (1) ``value`` searches by string CONTENT (substring), returning every hit with its
    address + owning binary so a consumer locates "this string lives in <binary> at <address>" in
    one call — optionally narrowed to ``binary``; (2) without ``value``, lists a binary's strings.
    ★ ``func`` does NOT scope the results (there is no string->func index and .rodata addresses fall
    outside code ranges): results are binary-wide, flagged honestly with ``func_scope_applied:
    false`` + a note, and in value mode ``func`` only gates existence (unresolvable name ->
    found:false). Large results are paged LOSSLESSLY by byte size under ``paging`` (``offset`` /
    ``next_offset``) — the tail is reachable, never summarized. The ``note`` also states that the
    reverse "which function references this string" lookup is NOT provided (that index does not
    exist, and we do not fake it)."""
    if value is not None:
        # ★ M6: value mode now honours ``func`` (previously it was silently dropped — a search
        # could not be scoped to a function). Resolve func first; a non-resolving func is SURFACED
        # (not-found / ambiguous), never ignored. func narrows the search to its address range.
        fbin: str | None = None
        lo = hi = None
        if func is not None:
            frow, miss = _resolve_one(conn, func, binary)
            if frow is None:
                assert miss is not None
                return miss
            fbin = frow["binary_name"]
            lo = _addr_int(frow["address"])
            if lo is not None and frow["size_bytes"]:
                hi = lo + int(frow["size_bytes"])
        sql = (
            "SELECT s.value, s.address, s.category, b.name AS bn FROM strings s "
            "JOIN binaries b ON b.id = s.binary_id WHERE s.value LIKE ?"
        )
        params: list[Any] = [f"%{value}%"]
        scope_bin = binary if binary is not None else fbin
        bid: int | None = None
        if scope_bin is not None:
            bid = _binary_id(conn, scope_bin)
            if bid is None:
                return {"found": False, "query": {"binary": scope_bin, "value": value}}
            sql += " AND s.binary_id = ?"
            params.append(bid)
        sql += " ORDER BY b.name, s.address"
        hits: list[dict[str, Any]] = []
        for r in conn.execute(sql, params):
            if lo is not None and hi is not None:
                a = _addr_int(r["address"])
                if a is None or not (lo <= a < hi):
                    continue
            hits.append(
                {
                    "value": r["value"],
                    "address": r["address"],
                    "binary": r["bn"],
                    "category": r["category"],
                }
            )
        page, paging = _byte_page(hits, offset, max_chars)
        result: dict[str, Any] = {
            "found": True,
            "query": {"value": value, "binary": binary, "func": func},
            "strings": page,
            "paging": paging,
            # ★ 3.1 declared≠actual: `func` is echoed but does NOT scope strings (see the note). The
            # boolean is the machine-readable guarantee — false whenever `func` was passed.
            "note": _STRING_FUNC_SCOPE_NOTE if func is not None else _STRING_REF_NOTE,
        }
        if func is not None:
            result["func_scope_applied"] = False
            result["warning"] = _STRING_FUNC_SCOPE_WARNING
        # Silent-drop guard: if a binary in scope was truncated at the export cap, a content search
        # can MISS a hit dropped past the cap — an empty/short result is NOT proof of absence there.
        trunc_bins = _truncated_binaries(conn, bid if scope_bin is not None else None)
        if trunc_bins:
            result["search_may_be_incomplete"] = True
            result["truncated_binaries"] = trunc_bins
            result["truncation_note"] = (
                "string export was TRUNCATED at the extractor cap for: "
                + ", ".join(trunc_bins)
                + " — a value search over a truncated binary can miss hits dropped past the cap, "
                "so no match here does NOT prove the string is absent in that binary"
            )
        return result
    if binary is None:
        return {"found": False, "query": {"binary": binary, "value": value}}
    bid = _binary_id(conn, binary)
    if bid is None:
        return {"found": False, "query": {"binary": binary}}
    rows = conn.execute(
        "SELECT value, address, category FROM strings WHERE binary_id = ? ORDER BY address",
        (bid,),
    ).fetchall()
    lo = hi = None
    if func is not None:
        frow, _ = _resolve_one(conn, func, binary)
        if frow is not None:
            lo = _addr_int(frow["address"])
            if lo is not None and frow["size_bytes"]:
                hi = lo + int(frow["size_bytes"])
    items: list[dict[str, Any]] = []
    for r in rows:
        if lo is not None and hi is not None:
            a = _addr_int(r["address"])
            if a is None or not (lo <= a < hi):
                continue
        items.append({"value": r["value"], "address": r["address"], "category": r["category"]})
    meta = conn.execute(
        "SELECT strings_total, strings_truncated FROM binaries WHERE id = ?", (bid,)
    ).fetchone()
    truncated = bool(meta and meta["strings_truncated"])
    total = int(meta["strings_total"]) if meta and meta["strings_total"] is not None else len(rows)
    # ★ M6: byte-paginate the (func-narrowed) items so a huge by-binary listing (a wide dispatcher's
    # 400k+ of strings) is reachable page by page. ``paging.truncated`` (byte-paging) is DISTINCT
    # from the top-level ``truncated`` below (the export-cap prefix flag) — both can hold at once.
    page_items, paging = _byte_page(items, offset, max_chars)
    out: dict[str, Any] = {
        "found": True,
        "binary": binary,
        "function": func,
        "strings": page_items,
        "paging": paging,
        "stored": len(rows),  # strings held for this binary (before any func-range narrowing)
        "total": total,  # true count of matching defined strings in the binary
        "truncated": truncated,  # EXPORT-CAP prefix flag (not the byte-paging one in ``paging``)
        # ★ 3.1 declared≠actual: `func` is echoed above but does NOT scope strings (see the note).
        "note": _STRING_FUNC_SCOPE_NOTE if func is not None else _STRING_REF_NOTE,
    }
    if func is not None:
        out["func_scope_applied"] = False
        out["warning"] = _STRING_FUNC_SCOPE_WARNING
    # Silent-drop guard: a truncated binary's stored list is only a prefix, so a string NOT listed
    # is NOT proven absent — it may have been dropped past the export cap. Never imply completeness.
    if truncated:
        out["truncation_note"] = (
            f"this binary's string export was TRUNCATED at the extractor cap ({len(rows)} of "
            f"{total} stored): a string NOT listed is NOT proven absent — it may have been dropped "
            "past the cap"
        )
    return out


# A pseudocode substring search is a TEXT match, not a resolved symbol/xref reference: the schema
# indexes no string->function link (Ghidra exports no string xrefs), but functions.pseudocode is
# stored in full, so "which functions mention this text" is answerable by scanning that text. Said
# honestly on every result — the text may occur in a comment or an unrelated string literal, so
# each hit is a lead to confirm, not a proven reference.
_PSEUDO_TEXT_NOTE = (
    "MATCHES BY PSEUDOCODE TEXT SUBSTRING, not a resolved symbol/xref reference: the text may "
    "appear in a comment or an unrelated string literal — confirm each hit in the pseudocode"
)


def _like_escape(text: str) -> str:
    """Escape LIKE wildcards so a literal substring matches literally.

    Function names routinely contain ``_`` (a single-char LIKE wildcard) and code contains ``%``;
    without escaping, ``LIKE`` would over-match. Paired with ``ESCAPE '\\'`` at the call site."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _first_match_line(pseudocode: str | None, text: str) -> str | None:
    """The first pseudocode line containing ``text`` (case-insensitive, mirroring SQLite LIKE),
    trimmed — a locating snippet, not the whole body. None when no single line contains it."""
    if not pseudocode:
        return None
    needle = text.lower()
    for line in pseudocode.splitlines():
        if needle in line.lower():
            return line.strip()
    return None


def get_functions_referencing_string(
    conn: sqlite3.Connection, *, text: str, binary: str | None = None, limit: int = 50
) -> dict[str, Any]:
    """Functions whose pseudocode TEXT contains ``text`` (a substring reverse-lookup).

    The schema stores no string->function link, but functions.pseudocode is kept in full, so this
    answers "which functions mention this text" by scanning that pseudocode — the same manual
    ``LIKE`` reverse-lookup a reviewer runs by hand, wrapped as one call. ``binary`` (short name OR
    full path) narrows to one binary; omitted, it scans every binary. Capped at ``limit`` hits
    (default 50); the result carries ``truncated`` when more exist. HONEST BOUND: this is a TEXT
    match, not a resolved symbol reference — the ``note`` says so; the text can occur in a comment
    or an unrelated string literal, so each hit is a lead to confirm. Each hit carries its anchor
    (binary + function + address) and the first matching pseudocode line."""
    if not text.strip():
        return {"found": False, "reason": "empty search text", "query": {"text": text}}
    lim = max(1, limit)
    sql = (
        "SELECT f.name, f.address, f.pseudocode, b.name AS binary_name, b.path AS binary_path "
        "FROM functions f JOIN binaries b ON b.id = f.binary_id "
        "WHERE f.pseudocode LIKE ? ESCAPE '\\'"
    )
    params: list[Any] = [f"%{_like_escape(text)}%"]
    if binary is not None:
        sql += " AND (b.name = ? OR b.path = ?)"
        params.extend([binary, binary])
    sql += " ORDER BY b.name, f.address LIMIT ?"
    params.append(lim + 1)  # fetch one extra to detect truncation without a second COUNT query
    rows = conn.execute(sql, params).fetchall()
    truncated = len(rows) > lim
    functions = [
        {
            **_anchor(r["binary_name"], r["name"], r["address"]),
            "binary_path": r["binary_path"],
            "match_line": _first_match_line(r["pseudocode"], text),
        }
        for r in rows[:lim]
    ]
    return {
        "found": True,
        "query": {"text": text, "binary": binary},
        "match_kind": "pseudocode_text_substring",  # honest: a text match, not a symbol reference
        "functions": functions,
        "returned": len(functions),
        "limit": lim,
        "truncated": truncated,
        "note": _PSEUDO_TEXT_NOTE,
    }


def get_imports_exports(conn: sqlite3.Connection, *, binary: str) -> dict[str, Any]:
    """The import and export symbol tables of one binary (the cross-binary edge endpoints)."""
    bid = _binary_id(conn, binary)
    if bid is None:
        return {"found": False, "query": {"binary": binary}}
    imports = [
        {"func_name": r["func_name"], "lib_soname": r["lib_soname"]}
        for r in conn.execute(
            "SELECT func_name, lib_soname FROM imports WHERE binary_id = ? ORDER BY func_name",
            (bid,),
        )
    ]
    exports = [
        {"func_name": r["func_name"], "address": r["address"]}
        for r in conn.execute(
            "SELECT func_name, address FROM exports WHERE binary_id = ? ORDER BY func_name",
            (bid,),
        )
    ]
    return {"found": True, "binary": binary, "imports": imports, "exports": exports}


# get_data_bytes standing contract, on EVERY result. The tool hands over bytes; it never reads
# them. Saying so inline keeps the boundary at the point of use, where an agent could otherwise
# mistake an ascii rendering for a claim that the run IS text.
_DATA_BYTES_CONTRACT = (
    "RAW BYTES ONLY. This returns what the data segment stores at an address and attaches NO "
    "reading of it: `ascii` is a mechanical byte-by-byte rendering (non-printable -> '.'), NOT a "
    "claim that the run is text, a key, a charset, or anything else. Deciding what the bytes mean "
    "is yours."
)
# A cap on ONE request, so a single call cannot serialize a whole 4 MiB segment into a response.
# Independent of the exporter's per-block cap: this one bounds the ANSWER, that one the STORE.
_DATA_BYTES_MAX_LENGTH = 4096


def _hex_addr_int(address: str | None) -> int | None:
    """Parse a Ghidra address to int, reading a bare form as HEX.

    NOT ``_addr_int``: that one falls back to decimal for a 0x-less string, which silently misreads
    the bare form an agent copies straight out of pseudocode (``DAT_00174000`` -> "00174000" would
    become decimal 174000, an address in a different block). Hex-first matches ``_norm_addr``, the
    canonicalization every evidence anchor already uses."""
    if not address:
        return None
    a = address.strip().lower().removeprefix("0x")
    try:
        return int(a, 16)
    except ValueError:
        return None


def _ascii_render(raw: bytes) -> str:
    """Mechanical rendering: a printable ASCII byte as itself, anything else as '.'. No judgement
    about whether the run IS text — that reading belongs to the consumer."""
    return "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in raw)


def get_data_bytes(
    conn: sqlite3.Connection, *, binary: str, address: str, length: int
) -> dict[str, Any]:
    """The raw bytes one binary's data segments store at ``address`` (a slicing substrate).

    The decompiler renders a data-segment constant as a bare ``DAT_000174e4`` and drops its
    CONTENT, so the value at that address is simply not in the pseudocode. This reads it back out of
    the stored segment bytes — no Ghidra re-run — and hands over the bytes and nothing else.

    HONEST BOUNDARIES, each a distinct answer a consumer must not conflate:
    - ``data_blocks_not_exported``: this binary has no exported blocks (an analysis.db predating the
      export, or a binary not re-scanned). UNKNOWN — never "this binary has no data".
    - ``address_not_in_any_data_block``: the address falls outside every exported block. It is NOT
      "the bytes are zero" and NOT "nothing is there" — it may be an unexported space.
    - ``address_in_executable_block``: a block DOES cover the address, but it is executable, and
      this export carries data bytes only. Kept distinct from the previous case because it is the
      COMMON one on section-header-stripped firmware, where .rodata rides inside the executable
      PT_LOAD — "the scope excluded it" must never read as "no block covers it".
    - ``uninitialized_bss``: the address lands in a .bss extent, which stores no bytes at all; the
      value exists only at runtime. Distinct from the previous case ON PURPOSE: "reserved but empty"
      and "not in any segment" are different facts.
    - ``truncated``: the returned bytes stop short of what was asked, because the block ends
      (``clamped_to_block_end``), the exporter's cap stored less than the block's extent
      (``cap_truncated``), or the request exceeded this tool's per-call cap
      (``request_length_capped``). NEVER read a truncated answer as "the data ends here".
    """
    if length <= 0:
        return {
            "found": False,
            "query": {"binary": binary, "address": address, "length": length},
            "note": "invalid_length",
            "detail": "length must be >= 1",
            "contract": _DATA_BYTES_CONTRACT,
        }
    query = {"binary": binary, "address": address, "length": length}
    row = conn.execute(
        "SELECT id FROM binaries WHERE name = ? OR path = ? LIMIT 1", (binary, binary)
    ).fetchone()
    if row is None:
        return {
            "found": False,
            "query": query,
            "note": "no_such_binary",
            "contract": _DATA_BYTES_CONTRACT,
        }
    bid = int(row["id"])
    try:
        blocks = conn.execute(
            "SELECT block_name, start_addr, size, bytes, initialized, executable, truncated "
            "FROM data_blocks WHERE binary_id = ? ORDER BY id",
            (bid,),
        ).fetchall()
    except sqlite3.OperationalError:
        blocks = []  # analysis.db predating the table -> the same "not exported" (unknown) answer
    if not blocks:
        return {
            "found": False,
            "query": query,
            "note": "data_blocks_not_exported",
            "detail": (
                "no data-segment blocks are stored for this binary (older analysis.db, or not "
                "re-scanned since the export existed) — UNKNOWN, not 'no data'"
            ),
            "contract": _DATA_BYTES_CONTRACT,
        }
    addr = _hex_addr_int(address)
    if addr is None:
        return {
            "found": False,
            "query": query,
            "note": "unparsable_address",
            "detail": "address must be hex (0x-prefixed or bare, as Ghidra renders it)",
            "contract": _DATA_BYTES_CONTRACT,
        }

    hit = None
    for b in blocks:
        start = _hex_addr_int(b["start_addr"])
        size = int(b["size"] or 0)
        if start is not None and start <= addr < start + size:
            hit = (b, start, size)
            break
    if hit is None:
        return {
            "found": False,
            "query": query,
            "note": "address_not_in_any_data_block",
            "detail": (
                "the address is outside every exported data block — it may be code, or space the "
                "export did not cover; this is NOT 'the bytes are zero'"
            ),
            "contract": _DATA_BYTES_CONTRACT,
        }
    blk, start, size = hit
    block_anchor = {
        "block_name": blk["block_name"],
        "start": blk["start_addr"],
        "block_size": size,
    }
    if blk["executable"]:
        return {
            "found": False,
            "query": query,
            **block_anchor,
            "note": "address_in_executable_block",
            "detail": (
                "the address lands in an EXECUTABLE block, whose bytes this export deliberately "
                "does not carry (data only, never code). On an ELF stripped of section headers "
                "there is one block per PT_LOAD and the read-only data sits inside the executable "
                "one, so a .rodata constant lands here — the bytes exist in the binary, the export "
                "scope is what excludes them. Read them from the binary itself, or widen the "
                "export scope"
            ),
            "contract": _DATA_BYTES_CONTRACT,
        }
    if not blk["initialized"]:
        return {
            "found": False,
            "query": query,
            **block_anchor,
            "note": "uninitialized_bss",
            "detail": "value is runtime-only",
            "contract": _DATA_BYTES_CONTRACT,
        }

    stored: bytes = bytes(blk["bytes"] or b"")
    offset = addr - start
    # Three independent bounds on where the answer can end; the tightest one wins and NAMES itself,
    # so a short answer always says which limit produced it rather than looking like the data's end.
    capped_length = min(length, _DATA_BYTES_MAX_LENGTH)
    end_by_request = offset + capped_length
    end_by_block = size
    end_by_stored = len(stored)
    end_raw = min(end_by_request, end_by_block, end_by_stored)
    end = max(offset, end_raw)  # a store shorter than the offset yields 0 bytes, never a negative
    raw = stored[offset:end]
    result: dict[str, Any] = {
        "found": True,
        "query": query,
        **block_anchor,
        "read_at": f"0x{addr:x}",
        "offset_in_block": offset,
        "bytes": raw.hex(),
        "length_returned": len(raw),
        "ascii": _ascii_render(raw),
        "contract": _DATA_BYTES_CONTRACT,
    }
    if end < offset + length:
        if end_by_stored < end_by_block and end_raw == end_by_stored:
            note, detail = (
                "cap_truncated",
                "the exporter's cap stored fewer bytes than this block's extent; the missing tail "
                "exists in the binary but was not exported — NOT the end of the data",
            )
        elif end_raw == end_by_block:
            note, detail = (
                "clamped_to_block_end",
                "the request ran past the end of this block; bytes beyond it belong to another "
                "block (or none) and were not read here",
            )
        else:
            note, detail = (
                "request_length_capped",
                f"this tool returns at most {_DATA_BYTES_MAX_LENGTH} bytes per call; ask again at "
                "a later address for the tail",
            )
        result["truncated"] = True
        result["note"] = note
        result["detail"] = detail
    else:
        result["truncated"] = False
    if blk["truncated"]:
        # The block itself is a prefix. Said even on a fully-served read: the bytes returned are
        # right, but "nothing more after this block's stored tail" would be wrong.
        result["block_bytes_incomplete"] = True
    return result


def get_script_callsites(conn: sqlite3.Connection, *, binary: str) -> dict[str, Any]:
    """Cross-artifact call sites: rootfs scripts that invoke this binary (entry-reach evidence).

    Each site carries the script path + line + the coarse args_pattern (literal / var_expansion /
    piped) and the raw_line (the script's OWN source line — evidence, never a generated payload).
    A binary referenced by a startup/maintenance script is reachable from that entry point."""
    rows = conn.execute(
        "SELECT f.path AS script, c.command, c.raw_line, c.line_number, c.args_pattern "
        "FROM script_calls c JOIN non_binary_files f ON f.id = c.file_id "
        "ORDER BY f.path, c.line_number"
    ).fetchall()
    name = binary.rsplit("/", 1)[-1]
    sites = [
        {
            "script": r["script"],
            "command": r["command"],
            "line_number": r["line_number"],
            "args_pattern": r["args_pattern"],
            "raw_line": r["raw_line"],
        }
        for r in rows
        if (r["command"] or "").rsplit("/", 1)[-1] == name or (r["command"] or "") == binary
    ]
    return {"found": True, "binary": binary, "callsites": sites}


def get_disassembly(
    conn: sqlite3.Connection, *, func: str, binary: str | None = None
) -> dict[str, Any]:
    """On-demand disassembly for one function (assembly is NOT stored; produced on request).

    HARD CONSTRAINT: on-demand assembly must be same-source aligned with the stored pseudocode
    (same decompiler project / load base) or addresses would not line up and would mislead rather
    than help. This server context does not retain the original decompiler project, so it CANNOT
    establish that alignment — it degrades HONESTLY (``available: False`` with a reason) rather
    than emit possibly-misaligned addresses. The function anchor is still returned so a consumer
    can disassemble it in their own aligned tool."""
    row, miss = _resolve_one(conn, func, binary)
    if row is None:
        assert miss is not None
        return miss
    return {
        "found": True,
        "available": False,
        "reason": (
            "on-demand disassembly requires the original decompiler project for same-source "
            "address alignment, which this server context does not retain; refusing to emit "
            "possibly-misaligned addresses (open the anchor in an aligned tool instead)"
        ),
        "anchor": _anchor(row["binary_name"], row["name"], row["address"]),
    }
