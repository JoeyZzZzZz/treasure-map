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


def _match_functions(conn: sqlite3.Connection, func: str, binary: str | None) -> list[sqlite3.Row]:
    """Functions whose name OR address equals ``func`` (optionally scoped to one binary)."""
    sql = (
        "SELECT f.id, f.name, f.address, f.size_bytes, f.pseudocode, f.callees, f.is_exported, "
        "b.name AS binary_name, b.path AS binary_path "
        "FROM functions f JOIN binaries b ON b.id = f.binary_id "
        "WHERE (f.name = ? OR f.address = ?)"
    )
    params: list[str] = [func, func]
    if binary is not None:
        sql += " AND b.name = ?"
        params.append(binary)
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


def get_pseudocode(
    conn: sqlite3.Connection, *, func: str, binary: str | None = None
) -> dict[str, Any]:
    """Decompiler pseudocode for one function (the default read view), with its anchor.

    ``func`` may be a function name or an address. Returns a not-found record (never a guess) when
    the function does not resolve uniquely."""
    row, miss = _resolve_one(conn, func, binary)
    if row is None:
        assert miss is not None
        return miss
    return {
        "found": True,
        "anchor": _anchor(row["binary_name"], row["name"], row["address"]),
        "binary_path": row["binary_path"],
        "size_bytes": row["size_bytes"],
        "is_exported": bool(row["is_exported"]),
        "callees": _parse_callees(row["callees"]),
        "pseudocode": row["pseudocode"],
    }


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
    return {
        "found": True,
        "anchor": _anchor(binary_name, row["name"], row["address"]),
        "callees": [{"name": c, "resolved_in_binary": c in same_binary} for c in callees],
    }


def get_xrefs(
    conn: sqlite3.Connection,
    *,
    func: str,
    direction: XrefDirection = "callers",
    binary: str | None = None,
) -> dict[str, Any]:
    """Cross-reference edges for one function from the xref table.

    direction='callers' returns the functions that reference this one; 'callees' returns the
    functions it references. Cross-binary edges (an import resolved to another binary's export)
    are included — that is the value over a single decompiler view."""
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
    return {
        "found": True,
        "anchor": _anchor(row["binary_name"], row["name"], row["address"]),
        "direction": direction,
        "edges": edges,
    }


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


def get_strings(
    conn: sqlite3.Connection, *, binary: str, func: str | None = None
) -> dict[str, Any]:
    """Recorded strings for a binary (value/address/category).

    When ``func`` is given and the function's address range is known, only strings whose address
    falls in that range are returned (best-effort by address; the schema has no string->func link),
    otherwise all of the binary's strings."""
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
    return {"found": True, "binary": binary, "function": func, "strings": items}


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
