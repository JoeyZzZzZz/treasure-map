# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Read-side view over the exec_edge table: who launches a given binary.

An exec edge is a DETERMINISTIC FACT: binary A's code calls a command or exec sink with an
argument that names binary B. ★ IRON LAW: it is an ENUMERATED EDGE, never a reachability verdict.
"A launches B" does not say the callsite runs, does not say an attacker reaches it, and never
downgrades B to unreachable when no edge is found. This module only READS the flattened rows.

Two target layers ride in the same table and must not be read the same way:
  * ``exec_image``   — B is the image the callsite runs (arg0 of an exec* call).
  * ``shell_command`` — B is the first word of a command string handed to a shell. The image the
    kernel actually runs is /bin/sh, which is deliberately not listed as its own edge.
The two families are disjoint, so a row is one or the other and never counted twice.
"""

from __future__ import annotations

import posixpath
import sqlite3
from typing import Any

_COLS = (
    "source_run_id, launcher_binary, launcher_function, launcher_addr, exec_api, sink_addr, "
    "target_layer, shell_wrapped, piped, inner_command_visible, argv_visibility, argv_template, "
    "argv_provenance, target_token, target_resolution, token_form, symlink_ambiguous, "
    "symlink_corrupt, symlink_target_unresolved, target_binary, occurrences"
)

_LAYER_NOTES = {
    "exec_image": (
        "B is the IMAGE this callsite runs (exec* arg0). argv is structurally invisible — only "
        "arg0 was recorded, never reconstructed."
    ),
    "shell_command": (
        "B is the FIRST WORD of a command string handed to a shell. The image the kernel runs is "
        "/bin/sh, which is deliberately not listed as a separate edge; the two target layers do "
        "not overlap, so B is counted once."
    ),
}


def _row_to_edge(r: sqlite3.Row) -> dict[str, Any]:
    """One exec_edge row -> a flat edge dict (launcher anchor + the honesty flags, unabridged)."""
    return {
        "launcher": {
            "binary": r["launcher_binary"],
            "function": r["launcher_function"],
            "addr": r["launcher_addr"],
        },
        "exec_api": r["exec_api"],
        "sink_addr": r["sink_addr"],
        "target_layer": r["target_layer"],
        "target_token": r["target_token"],
        "target_binary": r["target_binary"],
        "target_resolution": r["target_resolution"],
        "token_form": r["token_form"],
        "command": {
            "shell_wrapped": bool(r["shell_wrapped"]),
            "piped": bool(r["piped"]),
            "inner_command_visible": bool(r["inner_command_visible"]),
            "argv_visibility": r["argv_visibility"],
            "argv_template": r["argv_template"],
            "argv_provenance": r["argv_provenance"],
        },
        "symlink": {
            "ambiguous": bool(r["symlink_ambiguous"]),
            "corrupt": bool(r["symlink_corrupt"]),
            "target_unresolved": bool(r["symlink_target_unresolved"]),
        },
        "occurrences": r["occurrences"],
        "source_run_id": r["source_run_id"],
        "note": _LAYER_NOTES.get(str(r["target_layer"]), ""),
    }


def _exec_scan_status(
    conn: sqlite3.Connection, run_id: str | None, binary: str | None
) -> dict[str, Any]:
    """The launch-edge pass's honesty status for the queried scope, so an EMPTY result carries
    whether the silence can be trusted.

    ★ Scoped to the ``exec_argv`` pass only. An empty edge list is a confident 'nothing launches
    this' ONLY when a status row says scanned=1 AND the shapes in ``unsupported_note`` do not
    apply to the code you care about. No status row => not scanned or not re-hunted => UNKNOWN."""
    where = ["detector = 'exec_argv'"]
    params: list[Any] = []
    for col, val in (("source_run_id", run_id), ("binary", binary)):
        if val is not None:
            where.append(f"{col} = ?")
            params.append(val)
    sql = (
        "SELECT source_run_id, binary, scanned, supported_scope, unsupported_note, cap_hit, "
        "found_count FROM detector_scan_status WHERE " + " AND ".join(where)  # noqa: S608 -- literal
    )
    try:
        rows = conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        rows = []  # pre-feature atlas / not re-hunted -> no status recorded (also UNKNOWN)
    # Every row of a run carries the SAME scope and note — they describe the PASS, not the binary.
    # Repeating them per binary made the status dwarf the answer it was attached to (on a real
    # atlas, ~1500 rows each carrying the same ~700 characters), to the point that a count:0 result
    # could not be returned inline. Hoisted to one shared copy; the per-binary rows keep only what
    # actually varies per binary.
    scopes = {r["supported_scope"] for r in rows if r["supported_scope"]}
    notes = {r["unsupported_note"] for r in rows if r["unsupported_note"]}
    return {
        "pass_scope": "exec_argv",
        # Shared across every row. A set with more than one member would mean rows from runs of
        # DIFFERENT tmap versions are being read together, so they are joined rather than one being
        # picked — a silently-dropped scope would understate what the pass cannot see.
        "supported_scope": " | ".join(sorted(scopes)) or None,
        "unsupported_note": " | ".join(sorted(notes)) or None,
        "statuses": [
            {
                "binary": r["binary"],
                "scanned": r["scanned"],
                # KEPT even though a real atlas has never seen it set: this is the honest-degrade
                # channel, and a channel that has not fired is not a channel to delete.
                "cap_hit": bool(r["cap_hit"]),
                "found_count": r["found_count"],
            }
            for r in rows
        ],
        "note": (
            "Honesty status for the exec_argv pass ONLY. An EMPTY launched_by result is a "
            "confident 'nothing in this firmware launches it' ONLY when a status has scanned=1 "
            "and none of the unsupported_note shapes covers the caller you care about. No "
            "statuses => not scanned or not re-hunted => UNKNOWN, never 'nothing launches it'."
        ),
    }


def launched_by(
    conn: sqlite3.Connection,
    target: str,
    *,
    run_id: str | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    """Which binaries' code launches ``target``, and how.

    ``target`` accepts either spelling the table can hold: a binary's SHORT NAME as the inventory
    lists it (``busybox``, ``httpd``), or a launched SCRIPT's path under the firmware root
    (``usr/sbin/getmac``). A script is stored by path — a basename would be ambiguous when two
    directories hold different scripts of the same name — so a short name is matched against the
    stored path's basename too. Asking for ``getmac`` therefore finds the script edge, and when
    several scripts share that basename you get all of them rather than a guess.

    Only edges whose token RESOLVED to the target are returned — a token that matched nothing is in
    the table but belongs to no target, so it can never be silently attributed here. Pass
    ``run_id`` to stay inside one firmware; without it the answer spans every run in the atlas and
    each edge says which run it came from.

    ★ A FACT, NOT a reachability verdict. An edge does not say the callsite runs or that an
    attacker reaches it. An EMPTY result is NOT proof that nothing launches the binary — read the
    accompanying scan status, which names the shapes this pass cannot see (a caller behind a thin
    command wrapper being the sharpest one)."""
    # ★ Exact basename comparison, never a LIKE: a suffix match would answer `getmac` with an
    # unrelated `foogetmac`. Registered per call — the connection is the caller's.
    conn.create_function("tm_basename", 1, lambda p: posixpath.basename(p) if p else p)
    where = ["(target_binary = ? OR tm_basename(target_binary) = ?)"]
    params: list[Any] = [target, target]
    if run_id is not None:
        where.append("source_run_id = ?")
        params.append(run_id)
    sql = (
        f"SELECT {_COLS} FROM exec_edge WHERE "  # noqa: S608 -- column list + WHERE are literals
        + " AND ".join(where)
        + " ORDER BY launcher_binary, launcher_function, sink_addr LIMIT ?"
    )
    params.append(limit)
    try:
        rows = conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return {
            "target": target,
            "edges": [],
            "count": 0,
            "truncated": False,
            "note": "exec_edge table absent (older atlas or not re-hunted yet)",
            "exec_argv_status": _exec_scan_status(conn, run_id, None),
        }
    edges = [_row_to_edge(r) for r in rows]
    return {
        "target": target,
        "edges": edges,
        "count": len(edges),
        "truncated": len(edges) >= limit,
        "launcher_binaries": sorted({str(e["launcher"]["binary"]) for e in edges if e["launcher"]}),
        # ★ The pass's honesty travels WITH the result so an EMPTY one is never read as a
        # confident 'nothing launches this'.
        "exec_argv_status": _exec_scan_status(conn, run_id, None),
        "note": (
            "Enumerated cross-binary launch edges (A's code calls a command/exec sink whose "
            "argument names B). A FACT, NOT a reachability verdict: an edge does not say the "
            "callsite runs, nor that input reaches it — confirm the caller yourself. Read each "
            "edge's target_layer: exec_image means B is the image, shell_command means B is the "
            "command's first word (the /bin/sh image is not listed separately). A target_binary "
            "holding a path is a launched SCRIPT; a short name is a binary. When a symlink "
            "resolved the target, the link's own name is basename(target_token) — derivable, so "
            "it is not stored a second time. A resolution with target_binary NULL means several "
            "candidates shared the name and none was picked: look the basename up in the script "
            "or symlink inventory to see them. Attribution to a callsite is an OVER-APPROXIMATION: "
            "a stack buffer reused by several exec points carries all of its writers at each of "
            "them, so sink_addr means 'some exec point in this function' — 'this function can run "
            "B' holds, 'this callsite runs B' does not. Empty is NOT proof of nothing — check "
            "exec_argv_status."
        ),
    }
