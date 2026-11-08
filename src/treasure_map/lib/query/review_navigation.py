# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The pair review's navigation facts, read on demand (``review_pair(..., navigation=True)``): the
dispatch groups (lib/query/dispatch_groups) and the upstream library groups
(lib/query/upstream_version) of a pair, the compact report blocks, the full tables the report file
renders, and the labels a unit (``upstream``) and its must-read entry members (``dispatch``) carry.

Read once here so every face — the MCP answers and ``tmap review report`` — shows the same facts.
Annotations only: nothing here changes a unit, a unit id, ``must_read`` or the order. A part whose
atlas read fails is ``{"unreadable": <why>}`` in its block and labels nothing; the review itself
is never failed by it.

THE COMPACT BLOCKS carry data only: each block's static wording is one short ``note`` here, while
the report file renders the full wording (``DISPATCH_NOTES`` / ``UPSTREAM_NOTES``) and the
start_diff_review description states it. The blocks ride in the answer that hands out the next
unit, so every byte of fixed text in them is a byte taken from that unit's material.

THE DISPATCH GROUPS are cached per process (``_DISPATCH_CACHE``): a pair read again — a ``unit=``
read, the next unit a write hands on — is grouped once, not on every call. The key holds everything
the grouping reads: the atlas file, the run pair, each run's row (build hash, hunt commit, last
update), the pair's ``diff_meta`` rows, the stamp (row count and greatest id) of the pair's
``function_alignment`` rows and of each run's ``string_keyed_edge`` and ``detector_scan_status``
rows (a re-hunt or re-diff replaces them with fresh ids), and the must-read entry members the
units hold. The upstream counts read the review progress, so they are recomputed on every read.
"""

from __future__ import annotations

import copy
import sqlite3
from dataclasses import astuple, dataclass, field
from typing import Any

from treasure_map.lib.query import dispatch_groups as dg
from treasure_map.lib.query import upstream_version as uv
from treasure_map.lib.query.patch_view import _atlas_identity, _BoundedCache

# The short note each compact block carries (code-authored; scanned by the neutrality test).
DISPATCH_NOTE = "a navigation grouping by stored string-keyed edges; uncovered: enumerated by none"
UPSTREAM_NOTE = (
    "navigation only: no unit, unit id or must-read set changes; belonging to an upstream library "
    "is not a safety proof"
)
# The full wording the report file renders beside the tables (and the tool description states).
DISPATCH_NOTES = {
    "mechanism": dg.MECHANISM_NOTE,
    "uncovered": dg._UNCOVERED_NOTE,
    "static_table_detector": dg.DETECTOR_NOTE,
    "counterpart": dg.COUNTERPART_NOTE,
}
UPSTREAM_NOTES = {"groups": uv.GROUPS_NOTE}


@dataclass
class PairNavigation:
    """One pair's navigation facts, as read for one review."""

    run_pair: str
    dispatch: dg.PairDispatch | None = None
    labels: dict[tuple[str, str], list[dict[str, Any]]] = field(default_factory=dict)
    upstream: dict[str, dict[str, Any]] = field(default_factory=dict)
    # every upstream group, each naming all its diffs (the report file's table)
    upstream_rows: list[dict[str, Any]] = field(default_factory=list)
    report: dict[str, Any] = field(default_factory=dict)

    def member_dispatch(self, diff_id: str, entry_id: str | None) -> list[dict[str, Any]] | None:
        """A must-read entry member's ``dispatch`` label, or None when no group names it."""
        if entry_id is None:
            return None
        label = self.labels.get((diff_id, entry_id))
        # A copy: the labels are shared with the process cache, and the answer this goes into is
        # the caller's to change.
        return copy.deepcopy(label) if label is not None else None

    def unit_upstream(self, unit: Any) -> dict[str, Any] | None:
        """A unit's ``upstream`` label (library and each side's version), or None."""
        return uv.label(self.upstream.get(unit.stream))


def _unreadable(exc: Exception) -> dict[str, Any]:
    return {"unreadable": f"{type(exc).__name__}: {exc}"}


def dispatch_block(pd: dg.PairDispatch) -> dict[str, Any]:
    """The compact ``dispatch_groups`` block: dispatch_groups.report_block's data, its static
    wording replaced by ``DISPATCH_NOTE``."""
    block = dg.report_block(pd)
    block.pop("mechanism_note", None)
    for part in ("uncovered", "static_table_detector"):
        if isinstance(block.get(part), dict):
            block[part].pop("note", None)
    block["note"] = DISPATCH_NOTE
    return block


def upstream_block(
    pair: dict[str, dict[str, Any]], units: list[Any], disposed: Any, binary_of: dict[str, Any]
) -> dict[str, Any]:
    """The compact ``upstream_groups`` block: upstream_version.upstream_groups' data, its static
    wording replaced by ``UPSTREAM_NOTE``."""
    block = uv.upstream_groups(pair, units, disposed, binary_of)
    block["note"] = UPSTREAM_NOTE
    return block


# ── the dispatch grouping, cached per process ─────────────────────────────────────────────────

_Grouped = tuple[dg.PairDispatch, dict[tuple[str, str], list[dict[str, Any]]], dict[str, Any]]
_DISPATCH_CACHE: _BoundedCache[tuple[Any, ...], _Grouped] = _BoundedCache(8)


def clear_cache() -> None:
    _DISPATCH_CACHE.clear()


def _stamp(atlas: sqlite3.Connection, sql: str, args: tuple[Any, ...]) -> tuple[Any, ...]:
    """A table's (row count, greatest id) for one selection; None when the table is absent."""
    try:
        row = atlas.execute(sql, args).fetchone()
    except sqlite3.OperationalError:
        return (None,)
    return tuple(row) if row is not None else (None,)


def _dispatch_key(
    atlas: sqlite3.Connection, facts: Any, members: list[dg.MemberRef]
) -> tuple[Any, ...]:
    """Everything dispatch_groups.compute_pair reads for this pair (see the module docstring)."""
    run_a, run_b = facts.run_a, facts.run_b
    runs = tuple(
        tuple(
            atlas.execute(
                "SELECT build_hash, hunt_commit, updated_at FROM run WHERE run_id = ?", (r,)
            ).fetchone()
            or (None,)
        )
        for r in (run_a, run_b)
    )
    diffs = tuple(
        tuple(r)
        for r in atlas.execute(
            "SELECT * FROM diff_meta WHERE run_a_id = ? AND run_b_id = ? ORDER BY diff_id",
            (run_a, run_b),
        )
    )
    align = _stamp(
        atlas,
        "SELECT COUNT(*), MAX(id) FROM function_alignment WHERE diff_id IN "
        "(SELECT diff_id FROM diff_meta WHERE run_a_id = ? AND run_b_id = ?)",
        (run_a, run_b),
    )
    per_run = tuple(
        (
            _stamp(
                atlas,
                "SELECT COUNT(*), MAX(id) FROM string_keyed_edge WHERE source_run_id = ?",
                (r,),
            ),
            _stamp(
                atlas,
                "SELECT COUNT(*), MAX(id) FROM detector_scan_status WHERE source_run_id = ?",
                (r,),
            ),
        )
        for r in (run_a, run_b)
    )
    return (
        _atlas_identity(atlas),
        run_a,
        run_b,
        runs,
        diffs,
        align,
        per_run,
        tuple(astuple(m) for m in members),
    )


def _grouped(atlas: sqlite3.Connection, facts: Any, units: list[Any]) -> _Grouped:
    """The pair's dispatch groups, member labels and compact block, from the cache when every
    input is unchanged. An error is raised, never cached."""
    members = dg.members_from_units(units)
    key = _dispatch_key(atlas, facts, members)
    hit = _DISPATCH_CACHE.get(key)
    if hit is None:
        pd = dg.from_review(atlas, facts, units)
        hit = (pd, dg.member_labels(pd), dispatch_block(pd))
        _DISPATCH_CACHE[key] = hit
    pd, labels, block = hit
    return pd, labels, copy.deepcopy(block)


def read(atlas: sqlite3.Connection, facts: Any, units: list[Any], disposed: Any) -> PairNavigation:
    """The navigation facts of a pair's review (``disposed(unit)``: whether a unit is disposed)."""
    run_pair = f"{facts.run_a}::{facts.run_b}"
    nav = PairNavigation(run_pair)
    try:
        nav.dispatch, nav.labels, nav.report["dispatch_groups"] = _grouped(atlas, facts, units)
    except sqlite3.Error as exc:
        nav.report["dispatch_groups"] = _unreadable(exc)
    binary_of = {d.diff_id: d.binary for d in facts.diffs}
    try:
        nav.upstream = uv.pair_upstream(atlas, facts.run_a, facts.run_b)
    except sqlite3.Error as exc:
        nav.report["upstream_groups"] = _unreadable(exc)
    else:
        nav.upstream_rows = uv.upstream_rows(
            nav.upstream, units, disposed, binary_of, diffs_shown=None
        )
        nav.report["upstream_groups"] = upstream_block(nav.upstream, units, disposed, binary_of)
    return nav
