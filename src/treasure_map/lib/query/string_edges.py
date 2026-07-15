# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Read-side view over the string_keyed_edge table (detector B / detector A facts).

A string-keyed edge is a DETERMINISTIC FACT: an attacker-influenceable string key gates or
dispatches to a set of callees (a strcmp ladder, or a {string, func_ptr} table). ★ IRON LAW: these
are ENUMERATED EDGES, never a reachability verdict — a candidate that is an edge callee stays
reachability=unknown; the key is a lead the agent confirms. This module only READS the flattened
rows; it never judges reachability.

Two consumption faces (the same table serves both, superset-friendly):
  * the reachability layer looks up by callee (``edges_reaching_callee``): is this candidate's
    function a callee of some edge? -> annotate the reachability dimension with the key lead.
  * an agent / a cross-version diff enumerates by run + key + from_function
    (get_string_keyed_edges), aligning edges across two builds.
"""

from __future__ import annotations

import sqlite3
from typing import Any

_COLS = (
    "source_run_id, binary, from_function, from_func_addr, key, mechanism, "
    "callee_name, callee_addr, callee_kind, ladder_size, table_addr, "
    "completeness_status, completeness_reason, completeness_scope"
)


def _row_to_edge(r: sqlite3.Row) -> dict[str, Any]:
    """One string_keyed_edge row -> a flat edge dict (callee anchor + fine-grained completeness)."""
    return {
        "binary": r["binary"],
        "from_function": r["from_function"],
        "from_func_addr": r["from_func_addr"],
        "key": r["key"],
        "mechanism": r["mechanism"],
        "callee": {"name": r["callee_name"], "addr": r["callee_addr"], "kind": r["callee_kind"]},
        "ladder_size": r["ladder_size"],
        "table_addr": r["table_addr"],
        "completeness": {
            "status": r["completeness_status"],
            "reason": r["completeness_reason"],
            "scope": r["completeness_scope"],
        },
        "source_run_id": r["source_run_id"],
    }


def edges_reaching_callee(
    conn: sqlite3.Connection, binary: str | None, func_name: str | None
) -> list[dict[str, Any]]:
    """Every string-keyed edge whose CALLEE is ``func_name`` in ``binary`` — the reachability
    layer's lookup ("is this candidate's function gated behind a string key?").

    Matched by callee_name (+ binary when both are known, so a same-named function in another binary
    does not bleed in). A FACT lookup only — the caller must keep reachability=unknown; this returns
    the key lead(s), never a reachability verdict. Empty list when the function is no edge's callee
    (which is NOT proof of unreachability — most functions simply are not string-key-dispatched)."""
    if not func_name:
        return []
    if binary:
        sql = f"SELECT {_COLS} FROM string_keyed_edge WHERE callee_name = ? AND binary = ?"
        params: tuple[str, ...] = (func_name, binary)
    else:
        sql = f"SELECT {_COLS} FROM string_keyed_edge WHERE callee_name = ?"
        params = (func_name,)
    try:
        rows = conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return []  # table absent (older atlas / no re-hunt) -> no edges
    return [_row_to_edge(r) for r in rows]


def get_string_keyed_edges(
    conn: sqlite3.Connection,
    *,
    run_id: str | None = None,
    binary: str | None = None,
    key: str | None = None,
    callee: str | None = None,
    from_function: str | None = None,
    limit: int = 500,
) -> dict[str, Any]:
    """Enumerate string-keyed edges by any anchor (run / binary / key / callee / from_function).

    The agent's drill-down + the cross-version diff's enumeration surface. Any provided filter is
    ANDed; with none, returns the whole table (bounded by ``limit``). Each edge carries the callee
    anchor (name + addr + kind — BinDiff-alignable, not a bare address) and its fine-grained
    completeness. ★ These are enumerated FACTS, never reachability verdicts.
    """
    where: list[str] = []
    params: list[Any] = []
    for col, val in (
        ("source_run_id", run_id),
        ("binary", binary),
        ("key", key),
        ("callee_name", callee),
        ("from_function", from_function),
    ):
        if val is not None:
            where.append(f"{col} = ?")
            params.append(val)
    sql = f"SELECT {_COLS} FROM string_keyed_edge"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY from_function, key, callee_name LIMIT ?"
    params.append(limit)
    try:
        rows = conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return {
            "edges": [],
            "count": 0,
            "truncated": False,
            "note": "string_keyed_edge table absent (older atlas or not re-hunted yet)",
        }
    edges = [_row_to_edge(r) for r in rows]
    return {
        "edges": edges,
        "count": len(edges),
        "truncated": len(edges) >= limit,
        "note": (
            "Enumerated string-keyed edges (a string key gates/dispatches to a callee). A FACT, "
            "NOT a reachability verdict: a candidate that is an edge callee stays reachability="
            "unknown — the key is a lead you confirm. Check each edge's completeness (an "
            "incomplete region means undetected edges may exist)."
        ),
    }
