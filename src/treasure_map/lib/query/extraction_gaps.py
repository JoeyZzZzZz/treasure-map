# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""What a run's extraction could not give the hunt, named — read from the analysis.db the scan
stored (and the atlas, for a counterpart), never computed during a hunt.

* ``unfinished_decompiles`` — the functions whose decompile did not finish (timed out, or its
  output passed the decompiler's limit). The hunt reads pseudocode, so such a function holds no
  candidate however many sinks it calls. Each is named with the facts that remain: the sinks its
  call list names (the call list is read from the listing, not the pseudocode, so it is there),
  how many of its callees are unresolved stubs, and — where a diff pairs it — how many candidates
  the same function holds on the other side. That count is given only when the other side's
  decompile of it finished: one that did not finish either (or was never decompiled) holds no
  candidate for the same reason, so its 0 is not measured — ``candidates`` is None and
  ``counterpart_decompile`` names why.
* ``analyzer_degraded_binaries`` — the binaries whose extraction finished while a Ghidra analyzer
  threw (``ghidra_status_reason`` ``analyzer_exception:*``): they hold functions, so no incomplete
  list names them, but their function set may be short.
* ``wrapper_probe_unfinished`` — the binaries where the extractor's command-wrapper probe could
  not decompile a shell-sink caller, so did not decide whether it forwards its argument to the
  shell: counted by body size, an information line (it ranks nothing and adds no candidate).

A reading, not a judgement: counts and names only. It is outside the hunt, so neither the hunt's
stamp nor any other moves with it.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from treasure_map.lib.pattern import classes
from treasure_map.lib.pattern.classes import stub_resolved_name
from treasure_map.lib.ro_db import ro_connect

# The names the hunt recalls candidates for (its sink classes).
HUNT_SINKS: frozenset[str] = (
    classes.FORMAT | classes.CMD | classes.COPY | classes.FMT_STRING | classes.PATH_SINK
)
# How many sink names one function lists (the count is always exact).
SINK_NAME_SAMPLE = 10
_STUB_TOKEN = re.compile(r"FUN_[0-9A-Fa-f]+")
ANALYZER_EXCEPTION_PREFIX = "analyzer_exception:"


def _stub_table(raw: Any) -> dict[int, str] | None:
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    out: dict[int, str] = {}
    for k, v in data.items():
        try:
            out[int(str(k), 16)] = str(v)
        except ValueError:
            continue
    return out


def _callees(raw: Any) -> list[str] | None:
    try:
        data = json.loads(raw) if raw else []
    except (TypeError, ValueError):
        return None
    if not isinstance(data, list):
        return None
    return [x for x in data if isinstance(x, str)]


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def analyzer_degraded_binaries(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """``[{binary, reason}]``: the current binaries whose recorded reason is an analyzer exception
    — whatever their function count or ghidra_ok. Empty on a database without the column."""
    try:
        rows = conn.execute(
            "SELECT name, ghidra_status_reason FROM current_binaries "
            "WHERE ghidra_status_reason GLOB ? ORDER BY name",
            (ANALYZER_EXCEPTION_PREFIX + "*",),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    return [{"binary": r[0], "reason": r[1]} for r in rows]


def wrapper_probe_unfinished(db: Path | str) -> list[dict[str, Any]]:
    """``[{binary, small, large}]``: the current binaries whose wrapper probe left shell-sink
    callers undecided (counted by body size, 8KB the line), in name order. Empty when there are
    none, the column is absent (an older analysis.db: not recorded) or the database cannot be
    read."""
    try:
        conn = ro_connect(Path(db))
    except sqlite3.Error:
        return []
    try:
        rows = conn.execute(
            "SELECT name, wrapper_probe_unfinished FROM current_binaries "
            "WHERE wrapper_probe_unfinished IS NOT NULL ORDER BY name"
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()
    out: list[dict[str, Any]] = []
    for name, raw in rows:
        try:
            counts = json.loads(raw)
        except (TypeError, ValueError):
            continue
        small, large = counts.get("small"), counts.get("large")
        if isinstance(small, int) and isinstance(large, int) and small + large > 0:
            out.append({"binary": name, "small": small, "large": large})
    return out


# What the other side's decompile of a paired function came to (``counterpart_decompile``): "ok" (it
# has pseudocode, so its candidate count is measured), the cause it has none, or "unknown" (the
# other side's analysis.db, binary or function could not be read).
COUNTERPART_FINISHED = "ok"
COUNTERPART_UNKNOWN = "unknown"
# The causes of a decompile that ran and did not finish (``skipped_micro`` never ran).
_UNFINISHED_CAUSES = frozenset({"timeout", "payload_exceeded", "error"})


def _decompile_cause(status: Any, error: Any) -> str:
    """The stored decompile outcome as one word: "ok", "timeout", "payload_exceeded", "error",
    "skipped_micro" (or another recorded status as it is); "unknown" when none is recorded."""
    if not status:
        return COUNTERPART_UNKNOWN
    if status == "error":
        return "payload_exceeded" if error == "payload_exceeded" else "error"
    return str(status)


def _other_side_decompile(
    atlas: sqlite3.Connection,
    run_id: str,
    sha: str,
    addr: str,
    opened: dict[str, sqlite3.Connection | None],
) -> str:
    """The decompile outcome of the function at ``addr`` of the binary ``sha`` in ``run_id``'s
    own analysis.db (``_decompile_cause``); "unknown" when any of it cannot be read. ``opened``
    keeps one read-only connection per run for the caller to close."""
    if run_id not in opened:
        conn: sqlite3.Connection | None = None
        try:
            row = atlas.execute(
                "SELECT analysis_db_path FROM run WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row is not None and row[0]:
                conn = ro_connect(Path(row[0]))
        except sqlite3.Error:
            conn = None
        opened[run_id] = conn
    conn = opened[run_id]
    if conn is None:
        return COUNTERPART_UNKNOWN
    try:
        fcols = _columns(conn, "functions")
        if "decompile_status" not in fcols:
            return COUNTERPART_UNKNOWN
        err = "f.decompile_error" if "decompile_error" in fcols else "NULL"
        found = conn.execute(
            f"SELECT f.decompile_status, {err} FROM functions f JOIN binaries b "  # noqa: S608
            "ON b.id = f.binary_id WHERE b.sha256 = ? AND f.address = ?",
            (sha, addr),
        ).fetchone()
    except sqlite3.Error:
        return COUNTERPART_UNKNOWN
    if found is None:
        return COUNTERPART_UNKNOWN
    return _decompile_cause(found[0], found[1])


def _counterparts(
    atlas: sqlite3.Connection | None,
    run_id: str | None,
    sha: str,
    addr: str,
    opened: dict[str, sqlite3.Connection | None] | None = None,
) -> list[dict[str, Any]]:
    """Per stored diff holding this binary of this run: the function its alignment pairs with
    ``addr`` on the other side, what that side's decompile of it came to, and the candidates it
    holds there — None when that decompile did not finish (no pseudocode: the 0 is not
    measured)."""
    if atlas is None or run_id is None:
        return []
    opened = {} if opened is None else opened
    out: list[dict[str, Any]] = []
    try:
        diffs = atlas.execute(
            "SELECT diff_id, run_a_id, run_b_id, sha256_a, sha256_b FROM diff_meta "
            "WHERE diff_ok = 1 AND ((run_a_id = ? AND sha256_a = ?) OR (run_b_id = ? AND "
            "sha256_b = ?)) ORDER BY diff_id",
            (run_id, sha, run_id, sha),
        ).fetchall()
        for diff_id, run_a, run_b, sha_a, sha_b in diffs:
            here_a = run_a == run_id and sha_a == sha
            col, other_col = ("addr_a", "addr_b") if here_a else ("addr_b", "addr_a")
            row = atlas.execute(
                f"SELECT {other_col}, alignment_state FROM function_alignment "  # noqa: S608
                f"WHERE diff_id = ? AND {col} = ?",
                (diff_id, addr),
            ).fetchone()
            if row is None:
                out.append({"diff_id": diff_id, "address": None, "candidates": None})
                continue
            other_run, other_sha = (run_b, sha_b) if here_a else (run_a, sha_a)
            decompile = _other_side_decompile(
                atlas, str(other_run), str(other_sha), str(row[0]), opened
            )
            entry: dict[str, Any] = {
                "diff_id": diff_id,
                "address": row[0],
                "alignment_state": row[1],
                "counterpart_decompile": decompile,
            }
            if decompile not in (COUNTERPART_FINISHED, COUNTERPART_UNKNOWN):
                entry["candidates"] = None  # no pseudocode there either: nothing was measured
                out.append(entry)
                continue
            prefix = f"{other_run}#{str(other_sha)[:8]}:{row[0]}@"
            n = atlas.execute(
                "SELECT COUNT(*) FROM instance WHERE evidence_ref >= ? AND evidence_ref < ?",
                (prefix, prefix[:-1] + "A"),  # '@' + 1 = 'A': every ref with this prefix
            ).fetchone()[0]
            entry["candidates"] = int(n)
            out.append(entry)
    except sqlite3.OperationalError:
        return []
    return out


def unfinished_decompiles(
    analysis_db: Path | str,
    *,
    atlas: sqlite3.Connection | None = None,
    run_id: str | None = None,
) -> list[dict[str, Any]] | None:
    """The run's functions whose decompile did not finish, each with what remains readable of it
    (see the module docstring); None when the database cannot be read or records no decompile
    status. ``atlas`` + ``run_id`` add the counterpart a stored diff pairs it with."""
    try:
        conn = ro_connect(Path(analysis_db))
    except sqlite3.Error:
        return None
    try:
        fcols = _columns(conn, "functions")
        if not {"decompile_status", "callees"} <= fcols:
            return None
        err = "f.decompile_error" if "decompile_error" in fcols else "NULL"
        trunc = "f.callees_truncated" if "callees_truncated" in fcols else "0"
        stubs = "b.stub_names" if "stub_names" in _columns(conn, "binaries") else "NULL"
        rows = conn.execute(
            f"SELECT b.name, b.sha256, f.address, f.name, f.decompile_status, {err}, "  # noqa: S608
            f"f.callees, {trunc}, {stubs} FROM functions f JOIN current_binaries b "
            "ON b.id = f.binary_id WHERE f.decompile_status = 'timeout' OR "
            f"(f.decompile_status = 'error' AND {err} = 'payload_exceeded') "
            "ORDER BY b.name, f.address"
        ).fetchall()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    out: list[dict[str, Any]] = []
    opened: dict[str, sqlite3.Connection | None] = {}
    try:
        for row in rows:
            out.append(_entry(row, atlas, run_id, opened))
    finally:
        for other in opened.values():
            if other is not None:
                other.close()
    return out


def _entry(
    row: tuple[Any, ...],
    atlas: sqlite3.Connection | None,
    run_id: str | None,
    opened: dict[str, sqlite3.Connection | None],
) -> dict[str, Any]:
    """One unfinished function with what remains readable of it (see the module docstring)."""
    binary, sha, addr, name, status, error, callees_raw, truncated, stub_raw = row
    table = _stub_table(stub_raw)
    callees = _callees(callees_raw)
    entry: dict[str, Any] = {
        "binary": binary,
        "address": addr,
        "name": name,
        "cause": "payload_exceeded" if status == "error" else "timeout",
    }
    if callees is None:
        entry["sink_callees"] = None
    else:
        sinks: set[str] = set()
        unresolved = 0
        for c in callees:
            resolved = stub_resolved_name(c, table) or c
            if resolved in HUNT_SINKS:
                sinks.add(resolved)
            elif _STUB_TOKEN.fullmatch(resolved):
                unresolved += 1
        entry["sink_callees"] = {
            "count": len(sinks),
            "names": sorted(sinks)[:SINK_NAME_SAMPLE],
            "unresolved_stub_callees": unresolved,
            "callees_truncated": bool(truncated),
        }
    entry["counterparts"] = _counterparts(atlas, run_id, str(sha), str(addr), opened)
    return entry


def describe(entry: dict[str, Any]) -> str:
    """One line naming an unfinished function and the facts that remain."""
    head = f"{entry['binary']} {entry['name']} @ {entry['address']}: decompile {entry['cause']}"
    sinks = entry.get("sink_callees")
    if sinks is None:
        head += " — its call list could not be read"
    else:
        named = f" ({', '.join(sinks['names'])})" if sinks["names"] else ""
        head += f" — {sinks['count']} sink callee(s) with no readable body{named}"
        if sinks["unresolved_stub_callees"]:
            head += f", {sinks['unresolved_stub_callees']} unresolved stub callee(s)"
        if sinks["callees_truncated"]:
            head += ", call list cut at its cap"
    for c in entry.get("counterparts") or []:
        if c.get("address") is None:
            head += f"; no counterpart in {c['diff_id']}"
            continue
        head += f"; the same function on the other side ({c['address']}, {c['alignment_state']})"
        decompile = c.get("counterpart_decompile", COUNTERPART_FINISHED)
        if c.get("candidates") is None:
            if decompile in _UNFINISHED_CAUSES:
                head += f": its decompile did not finish either ({decompile})"
            else:
                head += f": it has no pseudocode either ({decompile})"
            head += " — no candidate count"
            continue
        head += f" holds {c['candidates']} candidate(s)"
        if decompile == COUNTERPART_UNKNOWN and not c["candidates"]:
            head += " (whether its decompile finished could not be read)"
    return head
