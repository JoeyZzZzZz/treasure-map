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
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Any

from treasure_map.lib.query import dispatch_groups as dg
from treasure_map.lib.query import upstream_version as uv


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
        return self.labels.get((diff_id, entry_id))

    def unit_upstream(self, unit: Any) -> dict[str, Any] | None:
        """A unit's ``upstream`` label (library and each side's version), or None."""
        return uv.label(self.upstream.get(unit.stream))


def _unreadable(exc: Exception) -> dict[str, Any]:
    return {"unreadable": f"{type(exc).__name__}: {exc}"}


def read(atlas: sqlite3.Connection, facts: Any, units: list[Any], disposed: Any) -> PairNavigation:
    """The navigation facts of a pair's review (``disposed(unit)``: whether a unit is disposed)."""
    run_pair = f"{facts.run_a}::{facts.run_b}"
    nav = PairNavigation(run_pair)
    try:
        nav.dispatch = dg.from_review(atlas, facts, units)
    except sqlite3.Error as exc:
        nav.report["dispatch_groups"] = _unreadable(exc)
    else:
        nav.labels = dg.member_labels(nav.dispatch)
        nav.report["dispatch_groups"] = dg.report_block(nav.dispatch)
    binary_of = {d.diff_id: d.binary for d in facts.diffs}
    try:
        nav.upstream = uv.pair_upstream(atlas, facts.run_a, facts.run_b)
    except sqlite3.Error as exc:
        nav.report["upstream_groups"] = _unreadable(exc)
    else:
        nav.upstream_rows = uv.upstream_rows(
            nav.upstream, units, disposed, binary_of, diffs_shown=None
        )
        nav.report["upstream_groups"] = uv.upstream_groups(nav.upstream, units, disposed, binary_of)
    return nav
