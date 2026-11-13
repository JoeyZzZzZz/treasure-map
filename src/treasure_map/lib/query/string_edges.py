# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
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

_BASE_COLS = (
    "source_run_id, binary, binary_path, from_function, from_func_addr, key, mechanism, "
    "callee_name, callee_addr, callee_kind, ladder_size, table_addr, "
    "completeness_status, completeness_reason, completeness_scope"
)
# The static-table reading's columns. An atlas written before them has none: each is then read as
# NULL ("no pairing recorded"), never as a pairing.
_PAIRING_COLS = (
    "stride_words",
    "key_phase",
    "handler_offset",
    "pairing_basis",
    "pairing_conflict",
    "column_evidence",
)
# The pairing a candidate row carries: the bytes hold the key and this function in one record, but
# which handler the key is paired with is not settled (one row per reading, none chosen).
UNDETERMINED = "undetermined"


def _cols(conn: sqlite3.Connection) -> str:
    """The select list over this atlas's string_keyed_edge columns (missing pairing columns as
    NULL)."""
    try:
        have = {r[1] for r in conn.execute("PRAGMA table_info(string_keyed_edge)")}
    except sqlite3.Error:
        have = set()
    extra = ", ".join(c if c in have else f"NULL AS {c}" for c in _PAIRING_COLS)
    return f"{_BASE_COLS}, {extra}"


def is_candidate_edge(edge: dict[str, Any]) -> bool:
    """A static-table candidate row: the record holds the key and this function, but its pairing
    is undetermined — never read as "key K dispatches to F"."""
    pairing = edge.get("pairing")
    return isinstance(pairing, dict) and pairing.get("basis") == UNDETERMINED


def _row_to_edge(r: sqlite3.Row) -> dict[str, Any]:
    """One string_keyed_edge row -> a flat edge dict (callee anchor + fine-grained completeness)."""
    return {
        "binary": r["binary"],
        "binary_path": r["binary_path"],
        # WHICH identity this row was matched on. A short name can belong to several binaries, so
        # a row scoped by name alone is a weaker claim than one scoped by path — said per row,
        # because a pre-column row and a current one can sit side by side in one answer.
        "scope_basis": "binary_path" if r["binary_path"] else "short_name (pre-migration row)",
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
        **_pairing(r),
    }


def _pairing(r: sqlite3.Row) -> dict[str, Any]:
    """A static-table row's reading: ``pairing.basis`` is what pairs the key with this handler
    (``code_two_index`` / ``code_helper`` / ``data_terminator``), or ``undetermined`` — a
    CANDIDATE row, one per reading the bytes allow, never a pairing chosen. Absent on a strcmp-gate
    row; ``basis`` null on a row written before the reading was recorded."""
    if r["mechanism"] != "static_string_table":
        return {}
    return {
        "pairing": {
            "basis": r["pairing_basis"],
            "handler_offset": r["handler_offset"],
            "stride_words": r["stride_words"],
            "key_phase": r["key_phase"],
            "conflict": r["pairing_conflict"],
            "column_evidence": r["column_evidence"],
        }
    }


def edges_reaching_callee(
    conn: sqlite3.Connection,
    binary: str | None,
    func_name: str | None,
    *,
    binary_path: str | None = None,
) -> list[dict[str, Any]]:
    """Every string-keyed edge whose CALLEE is ``func_name`` in ``binary`` — the reachability
    layer's lookup ("is this candidate's function gated behind a string key?").

    Matched by callee_name plus the binary, so a same-named function elsewhere does not bleed in.
    ★ The binary scope prefers ``binary_path``: a short name is a label two files in one firmware
    can share, and scoping by it attached one binary's key lead to the other's candidate. Rows
    written before the path column exists carry NULL there and are still matched by name — each
    returned row says which basis it matched on rather than presenting the two as equivalent.

    A FACT lookup only — the caller must keep reachability=unknown; this returns the key lead(s),
    never a reachability verdict. Empty list when the function is no edge's callee (which is NOT
    proof of unreachability — most functions simply are not string-key-dispatched)."""
    if not func_name:
        return []
    if binary_path and binary:
        sql = (
            f"SELECT {_cols(conn)} FROM string_keyed_edge WHERE callee_name = ? "
            "AND (binary_path = ? OR (binary_path IS NULL AND binary = ?))"
        )
        params: tuple[str, ...] = (func_name, binary_path, binary)
    elif binary:
        sql = f"SELECT {_cols(conn)} FROM string_keyed_edge WHERE callee_name = ? AND binary = ?"
        params = (func_name, binary)
    else:
        sql = f"SELECT {_cols(conn)} FROM string_keyed_edge WHERE callee_name = ?"
        params = (func_name,)
    try:
        rows = conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return []  # table absent (older atlas / no re-hunt) -> no edges
    return [_row_to_edge(r) for r in rows]


def _static_table_status(
    conn: sqlite3.Connection,
    run_id: str | None,
    binary: str | None,
    *,
    offset: int = 0,
    limit: int | None = None,
) -> dict[str, Any]:
    """The static-string-table detector's honesty status for the queried scope, so an EMPTY edge
    result carries whether the miss is trustworthy. ★ Scoped to the ``static_string_table``
    mechanism ONLY -- it says NOTHING about ``strcmp_gate`` (detector B, whose own 0-row honesty is
    a separate item). An empty result is a confident 'none' ONLY when a status has scanned=1,
    cap_hit=0, and the form is within supported_scope; otherwise the miss is UNKNOWN, not none.

    There is one status row per scanned binary, so over a whole run (or the whole atlas) the rows
    outgrow any answer. They come in pages — ``limit`` rows from ``offset``, in one total order
    (run, binary, row id), the page the edges beside them are cut at — with ``total_statuses``. The
    reading needs no page: ``supported_scope`` / ``unsupported_note`` describe the PASS, not a
    binary, so they are given once for the block (joined when runs of different tmap versions
    disagree, never one picked); ``status_rows``, ``by_state``, ``found_total`` and
    ``binaries_without_status`` count every row of the scope."""
    where = ["detector = 'string_tables'"]
    params: list[Any] = []
    for col, val in (("source_run_id", run_id), ("binary", binary)):
        if val is not None:
            where.append(f"{col} = ?")
            params.append(val)
    have = {r[1] for r in conn.execute("PRAGMA table_info(detector_scan_status)")}
    unver = "handler_unverified" if "handler_unverified" in have else "NULL AS handler_unverified"
    undet = (
        "pairing_undetermined" if "pairing_undetermined" in have else "NULL AS pairing_undetermined"
    )
    sql = (
        "SELECT source_run_id, binary, binary_path, scanned, supported_scope, unsupported_note, "
        f"cap_hit, found_count, {unver}, {undet} FROM detector_scan_status WHERE "  # noqa: S608
        + " AND ".join(where)  # noqa: S608 -- literal
        + " ORDER BY source_run_id, binary, id"
    )
    try:
        rows = conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        rows = []  # pre-feature atlas / not re-hunted -> no status recorded (also UNKNOWN)
    scopes = {r["supported_scope"] for r in rows if r["supported_scope"]}
    notes = {r["unsupported_note"] for r in rows if r["unsupported_note"]}
    statuses = [
        {
            "run_id": r["source_run_id"],
            "binary": r["binary"],
            "binary_path": r["binary_path"],
            "scanned": r["scanned"],
            "cap_hit": bool(r["cap_hit"]),
            "found_count": r["found_count"],
            # the static-table reader's per-binary counts (NULL on a pre-column status row): the
            # handler slots the ELF could not vouch for; candidate rows (pairing undetermined)
            "handler_unverified": r["handler_unverified"],
            "pairing_undetermined": r["pairing_undetermined"],
        }
        for r in rows
    ]
    lo = max(0, offset)
    return {
        "mechanism_scope": "static_string_table",  # ★ NOT strcmp_gate (detector B) -- no overclaim
        "supported_scope": " | ".join(sorted(scopes)) or None,
        "unsupported_note": " | ".join(sorted(notes)) or None,
        "status_rows": len(rows),
        "by_state": {
            "scanned": sum(1 for r in rows if r["scanned"]),
            "cap_hit": sum(1 for r in rows if r["cap_hit"]),
            "not_scanned": sum(1 for r in rows if not r["scanned"]),
        },
        "found_total": sum(r["found_count"] or 0 for r in rows),
        # ★ the recovery's own honesty: candidate rows (pairing undetermined) and ELF-unverified
        # handlers over the scope, so "how much did it NOT settle" rides with the result.
        "pairing_undetermined_total": sum(r["pairing_undetermined"] or 0 for r in rows),
        "handler_unverified_total": sum(r["handler_unverified"] or 0 for r in rows),
        "binaries_without_status": _binaries_without_status(conn, run_id, binary, rows),
        "statuses": statuses[lo:] if limit is None else statuses[lo : lo + max(0, limit)],
        "total_statuses": len(statuses),
        "note": (
            "Honesty status for the static_string_table mechanism ONLY (NOT strcmp_gate / detector "
            "B). An EMPTY static-table result is a confident 'none' ONLY when a status has "
            "scanned=1, cap_hit=0, and your table form is within supported_scope. scanned=0, "
            "cap_hit=1, or an unsupported form => UNKNOWN, not none. No statuses => no status "
            "recorded (older atlas or not re-hunted) => also UNKNOWN. The counts are over the "
            "whole scope; the per-binary rows page with the edges (next_offset), and "
            "binaries_without_status counts the binaries a run recorded that have no row."
        ),
    }


def _binaries_without_status(
    conn: sqlite3.Connection, run_id: str | None, binary: str | None, rows: list[sqlite3.Row]
) -> int | None:
    """How many binaries the runs in scope recorded that have no status row: each run's binary
    count less its rows (one row per binary). None when the scope names one binary (a short name
    is no count of files) or a run's binary count is not recorded."""
    if binary is not None:
        return None
    sql = "SELECT run_id, binaries FROM run" + (" WHERE run_id = ?" if run_id is not None else "")
    try:
        runs = conn.execute(sql, (run_id,) if run_id is not None else ()).fetchall()
    except sqlite3.OperationalError:
        return None
    per_run: dict[str, int] = {}
    for r in rows:
        per_run[r["source_run_id"]] = per_run.get(r["source_run_id"], 0) + 1
    missing = 0
    for rid, count in runs:
        if count is None:
            return None
        missing += max(0, int(count) - per_run.get(rid, 0))
    return missing


def get_string_keyed_edges(
    conn: sqlite3.Connection,
    *,
    run_id: str | None = None,
    binary: str | None = None,
    key: str | None = None,
    callee: str | None = None,
    from_function: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> dict[str, Any]:
    """Enumerate string-keyed edges by any anchor (run / binary / key / callee / from_function).

    The agent's drill-down + the cross-version diff's enumeration surface. Any provided filter is
    ANDed; with none, returns the whole table (bounded by ``limit``). Paged: ``limit`` edges from
    ``offset`` (every edge when ``limit`` is None), in one total order (the row id breaks a tie;
    a static table's edges have no from_function). ``count`` is the edges returned and
    ``truncated`` that the page reached ``limit``, as before; ``total_edges`` counts every edge
    the filters match; the static-table status rows beside them are cut at the same index, so one
    ``offset`` pages both. Each edge carries the callee
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
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    sql = (
        f"SELECT {_cols(conn)} FROM string_keyed_edge{clause}"  # noqa: S608 -- literal cols + WHERE
        " ORDER BY from_function, key, callee_name, id LIMIT ? OFFSET ?"
    )
    try:
        total = int(
            conn.execute(
                f"SELECT COUNT(*) FROM string_keyed_edge{clause}",  # noqa: S608 -- literal WHERE
                params,
            ).fetchone()[0]
        )
        rows = conn.execute(
            sql, [*params, -1 if limit is None else max(0, limit), max(0, offset)]
        ).fetchall()
    except sqlite3.OperationalError:
        return {
            "edges": [],
            "count": 0,
            "truncated": False,
            "total_edges": 0,
            "note": "string_keyed_edge table absent (older atlas or not re-hunted yet)",
            "static_string_table_status": _static_table_status(
                conn, run_id, binary, offset=offset, limit=limit
            ),
        }
    edges = [_row_to_edge(r) for r in rows]
    return {
        "edges": edges,
        "count": len(edges),
        "truncated": limit is not None and len(edges) >= limit,
        "total_edges": total,
        # ★ static-table honesty travels WITH the result so an EMPTY one is not read as a confident
        # 'none' (scoped to the static_string_table mechanism; strcmp_gate/detector B is separate).
        "static_string_table_status": _static_table_status(
            conn, run_id, binary, offset=offset, limit=limit
        ),
        "note": (
            "Enumerated string-keyed edges (a string key gates/dispatches to a callee). A FACT, "
            "NOT a reachability verdict: a candidate that is an edge callee stays reachability="
            "unknown — the key is a lead you confirm. Check each edge's completeness (an "
            "incomplete region means undetected edges may exist). A static-table edge whose "
            "pairing.basis is 'undetermined' is a CANDIDATE: the record holds the key and this "
            "function, but which handler the key is paired with is not settled."
        ),
    }
