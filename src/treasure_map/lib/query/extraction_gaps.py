# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""What a run's extraction could not give the hunt, named — read from the analysis.db the scan
stored (and the atlas, for a counterpart), never computed during a hunt.

* ``unfinished_decompiles`` — the functions whose decompile did not finish (timed out, or its
  output passed the decompiler's limit). The hunt reads pseudocode, so such a function holds no
  candidate however many sinks it calls. Each is named with the facts that remain: the sinks its
  call list names (the call list is read from the listing, not the pseudocode, so it is there),
  how many of its callees are unresolved stubs, and — where a diff pairs it — how many candidates
  the same function holds on the other side.
* ``analyzer_degraded_binaries`` — the binaries whose extraction finished while a Ghidra analyzer
  threw (``ghidra_status_reason`` ``analyzer_exception:*``): they hold functions, so no incomplete
  list names them, but their function set may be short.

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


def _counterparts(
    atlas: sqlite3.Connection | None, run_id: str | None, sha: str, addr: str
) -> list[dict[str, Any]]:
    """Per stored diff holding this binary of this run: the function its alignment pairs with
    ``addr`` on the other side, and the candidates that function holds there."""
    if atlas is None or run_id is None:
        return []
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
            prefix = f"{other_run}#{str(other_sha)[:8]}:{row[0]}@"
            n = atlas.execute(
                "SELECT COUNT(*) FROM instance WHERE evidence_ref >= ? AND evidence_ref < ?",
                (prefix, prefix[:-1] + "A"),  # '@' + 1 = 'A': every ref with this prefix
            ).fetchone()[0]
            out.append(
                {
                    "diff_id": diff_id,
                    "address": row[0],
                    "alignment_state": row[1],
                    "candidates": int(n),
                }
            )
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
    for binary, sha, addr, name, status, error, callees_raw, truncated, stub_raw in rows:
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
        entry["counterparts"] = _counterparts(atlas, run_id, str(sha), str(addr))
        out.append(entry)
    return out


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
        else:
            head += (
                f"; the same function on the other side ({c['address']}, {c['alignment_state']}) "
                f"holds {c['candidates']} candidate(s)"
            )
    return head
