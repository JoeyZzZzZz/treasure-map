# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only query face over the layer-0 function-alignment tables.

The 80%-case workflow: "I found something at A-side address X -- did B patch it?" So a single-side
address resolves to its aligned counterpart, carrying BOTH the raw ``alignment_confidence`` (trust
in the pairing) and ``similarity`` (change magnitude) plus the honest ``alignment_state`` -- never
only the thresholded state (a continuous quantity must not collapse to a binary one). Names ride
along as a pairing SANITY signal a consumer reads, never a verdict the tool draws.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from treasure_map.lib.diff.layer0 import norm_hex

_ALIGN_NOTE = (
    "an ALIGNMENT FACT (BinDiff matched these addresses), NOT a change verdict. "
    "alignment_confidence = trust in the pairing; similarity = how much the pair differs (a "
    "change-magnitude fact, not a verdict). A pair can be similarity=1.0 yet confidence ~0.02 -- "
    "read alignment_state together with the raw confidence, never the state alone. The names are a "
    "pairing sanity signal for you to judge, never a verdict."
)


def _row_to_pair(r: sqlite3.Row) -> dict[str, Any]:
    return {
        "addr_a": r["addr_a"],
        "addr_b": r["addr_b"],
        "name_a": r["name_a"],
        "name_b": r["name_b"],
        "alignment_confidence": r["alignment_confidence"],
        "similarity": r["similarity"],
        "alignment_state": r["alignment_state"],
        "basicblocks": r["basicblocks"],
        "edges": r["edges"],
        "instructions": r["instructions"],
    }


def _align_by_side(atlas: sqlite3.Connection, diff_id: str, addr: str, side: str) -> dict[str, Any]:
    col = "addr_a" if side == "a" else "addr_b"
    norm = norm_hex(addr)
    rows = atlas.execute(
        f"SELECT addr_a, addr_b, name_a, name_b, alignment_confidence, similarity, "  # noqa: S608
        f"alignment_state, basicblocks, edges, instructions "
        f"FROM function_alignment WHERE diff_id = ? AND {col} = ?",  # noqa: S608 -- col is a literal
        (diff_id, norm),
    ).fetchall()
    if not rows:
        return {
            "found": False,
            "diff_id": diff_id,
            "query": {"side": side, "addr": norm},
            "note": (
                "no matched pair for this address in this diff. That is NOT proof the function was "
                "added/removed -- an unmatched function is listed in function_presence, and a diff "
                "covers only the tool's view, never all changes. " + _ALIGN_NOTE
            ),
        }
    return {
        "found": True,
        "diff_id": diff_id,
        "query": {"side": side, "addr": norm},
        "pairs": [_row_to_pair(r) for r in rows],
        "note": _ALIGN_NOTE,
    }


def align_by_a(atlas: sqlite3.Connection, diff_id: str, addr: str) -> dict[str, Any]:
    """Given an A-side (before) address, its aligned B-side counterpart(s) with confidence +
    similarity + state. The forward direction of the "did B patch what I found in A?" workflow."""
    return _align_by_side(atlas, diff_id, addr, "a")


def align_by_b(atlas: sqlite3.Connection, diff_id: str, addr: str) -> dict[str, Any]:
    """Given a B-side (after) address, its aligned A-side counterpart(s). The reverse direction."""
    return _align_by_side(atlas, diff_id, addr, "b")
