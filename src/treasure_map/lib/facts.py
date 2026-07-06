# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
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

XrefDirection = Literal["callers", "callees"]


def open_analysis_ro(db_path: Path | str) -> sqlite3.Connection:
    """Open an analysis database strictly read-only, with a Row factory."""
    conn = sqlite3.connect(f"file:{Path(db_path)}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def list_incomplete_binaries(conn: sqlite3.Connection) -> list[str]:
    """Current-scan binaries that produced 0 functions and are NOT legitimately code-free.

    ★ Red-line (degrade must be visible): a binary Ghidra failed on holds 0 functions, so it looks
    'clean' to every reader. This surfaces those names so a consumer knows the analysis is
    INCOMPLETE for them — not that there is nothing to find. Empty on an older analysis.db that
    predates the ``ghidra_status`` column (the read degrades quietly rather than error)."""
    try:
        rows = conn.execute(
            "SELECT b.name FROM current_binaries b "
            "WHERE COALESCE(b.ghidra_status, '') != 'ok_empty' "
            "AND NOT EXISTS (SELECT 1 FROM functions f WHERE f.binary_id = b.id) "
            "ORDER BY b.name"
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    return [r["name"] for r in rows]


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
        "f.callees_truncated, f.is_exported, b.name AS binary_name, b.path AS binary_path "
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
    functions it references. Cross-binary edges (an import resolved to another binary's export)
    are included — that is the value over a single decompiler view.

    The xref table only records cross-binary edges, so for 'callers' a same-binary caller is
    recovered as a fallback by reverse-scanning each function's recorded callee list (xref_type
    ``intra_callees``). When that still finds nothing, a ``note`` says so honestly and flags that
    the function may yet be reached via an indirect / dispatch-table / function-pointer call that
    static analysis cannot resolve — a true unresolved caller is NOT silently the same as 'none'."""
    row, miss = _resolve_one(conn, func, binary)
    if row is None:
        assert miss is not None
        return miss
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


def get_strings(
    conn: sqlite3.Connection,
    *,
    binary: str | None = None,
    func: str | None = None,
    value: str | None = None,
) -> dict[str, Any]:
    """Recorded strings (value/address/category), located one step for the consumer.

    Two modes: (1) ``value`` searches by string CONTENT (substring), returning every hit with its
    address + owning binary so a consumer locates "this string lives in <binary> at <address>" in
    one call — optionally narrowed to ``binary``; (2) without ``value``, lists a binary's strings,
    optionally narrowed to ``func``'s address range (best-effort by address; the schema has no
    string->func link). The ``note`` states honestly that the reverse "which function references
    this string" lookup is NOT provided — that index does not exist, and we do not fake it."""
    if value is not None:
        sql = (
            "SELECT s.value, s.address, s.category, b.name AS bn FROM strings s "
            "JOIN binaries b ON b.id = s.binary_id WHERE s.value LIKE ?"
        )
        params: list[Any] = [f"%{value}%"]
        if binary is not None:
            bid = _binary_id(conn, binary)
            if bid is None:
                return {"found": False, "query": {"binary": binary, "value": value}}
            sql += " AND s.binary_id = ?"
            params.append(bid)
        sql += " ORDER BY b.name, s.address"
        hits = [
            {
                "value": r["value"],
                "address": r["address"],
                "binary": r["bn"],
                "category": r["category"],
            }
            for r in conn.execute(sql, params)
        ]
        result: dict[str, Any] = {
            "found": True,
            "query": {"value": value, "binary": binary},
            "strings": hits,
            "note": _STRING_REF_NOTE,
        }
        # Silent-drop guard: if a binary in scope was truncated at the export cap, a content search
        # can MISS a hit dropped past the cap — an empty/short result is NOT proof of absence there.
        trunc_bins = _truncated_binaries(conn, bid if binary is not None else None)
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
    out: dict[str, Any] = {
        "found": True,
        "binary": binary,
        "function": func,
        "strings": items,
        "stored": len(rows),  # strings held for this binary (before any func-range narrowing)
        "total": total,  # true count of matching defined strings in the binary
        "truncated": truncated,
        "note": _STRING_REF_NOTE,
    }
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


def get_components_cves(conn: sqlite3.Connection, *, binary: str) -> dict[str, Any]:
    """SBOM components recognized in a binary + their CVE-table matches (a query result, not a
    judgement that the binary is affected — version-range/config caveats are the consumer's)."""
    bid = _binary_id(conn, binary)
    if bid is None:
        return {"found": False, "query": {"binary": binary}}
    components = [
        {
            "id": r["id"],
            "product": r["product"],
            "version": r["version"],
            "cpe": r["cpe"],
            "source": r["source"],
        }
        for r in conn.execute(
            "SELECT id, product, version, cpe, source FROM components WHERE binary_id = ? "
            "ORDER BY product, version",
            (bid,),
        )
    ]
    cves = [
        {
            "cve_id": r["cve_id"],
            "cvss_score": r["cvss_score"],
            "severity": r["severity"],
            "component_id": r["component_id"],
            "published": r["published"],
            "url": r["url"],
        }
        for r in conn.execute(
            "SELECT cve_id, cvss_score, severity, component_id, published, url "
            "FROM cve_matches WHERE binary_id = ? ORDER BY cvss_score DESC",
            (bid,),
        )
    ]
    return {"found": True, "binary": binary, "components": components, "cve_matches": cves}


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
