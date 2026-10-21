# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The A/B "same generation?" rule, and that the overlay and the patch view decide it identically.

A diff only makes sense between two runs produced by the same extraction and hunt code. The overlay
(``sink_overlay._generation_mismatch``) and the patch view (``patch_view._gen`` + ``_gen_mismatch``)
each answer this, in two modules that cannot import one another, so the rule is written twice. This
locks the two copies to the same verdict on the same run pairs — a change to one that drifts from
the other fails here — and pins the rule itself: a differing commit with a matching code stamp is
NOT a mismatch (the whole point of stamping by code), while a differing code stamp or scan stamp is.
"""

from __future__ import annotations

import types
from pathlib import Path

import pytest

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query import sink_overlay as so

A = "a" * 40
B = "b" * 40
BH = "beefbeefbeefbeef"
CODE_X = "src-d4d4d4d4d4d4d4d4"
CODE_Y = "src-e5e5e5e5e5e5e5e5"
SCAN_S = '{"code":"src-p","config":{},"deps":{"pyelftools":"0.33"}}'
SCAN_T = '{"code":"src-q","config":{},"deps":{"pyelftools":"0.33"}}'


def _mk(conn, run_id: str, *, build=BH, commit=None, code=None, scan=None) -> None:
    conn.execute(
        "INSERT INTO run (run_id, scan_status, build_hash, hunt_commit, hunt_code_version, "
        "scan_stamp) VALUES (?, 'complete', ?, ?, ?, ?)",
        (run_id, build, commit, code, scan),
    )


def _both_agree(atlas, a: str, b: str) -> bool:
    """The overlay's verdict; also asserts the patch view's verdict is identical."""
    overlay = so._generation_mismatch(atlas, types.SimpleNamespace(run_a=a, run_b=b))
    ga, gb = pv._gen(atlas, a), pv._gen(atlas, b)
    view = pv._gen_mismatch(ga, gb) if ga is not None and gb is not None else False
    assert overlay == view, f"overlay={overlay} view={view} for ({a}, {b})"
    return overlay


@pytest.mark.parametrize(
    ("a_kw", "b_kw", "expected"),
    [
        # different commits but matching code stamp -> SAME generation (the feature's whole point)
        (
            {"commit": A, "code": CODE_X, "scan": SCAN_S},
            {"commit": B, "code": CODE_X, "scan": SCAN_S},
            False,
        ),
        # different hunt code -> mismatch
        ({"code": CODE_X, "scan": SCAN_S}, {"code": CODE_Y, "scan": SCAN_S}, True),
        # same code, different scan stamp -> mismatch
        ({"code": CODE_X, "scan": SCAN_S}, {"code": CODE_X, "scan": SCAN_T}, True),
        # both carry a code stamp but one scan stamp is NULL -> mismatch (cannot confirm same)
        ({"code": CODE_X, "scan": SCAN_S}, {"code": CODE_X, "scan": None}, True),
        # different build_hash is always a mismatch
        (
            {"code": CODE_X, "scan": SCAN_S, "build": BH},
            {"code": CODE_X, "scan": SCAN_S, "build": "0000"},
            True,
        ),
        # old runs (no code stamp): fall back to the commit rule — known and equal -> same
        ({"commit": A}, {"commit": A}, False),
        # old runs: known and different -> mismatch
        ({"commit": A}, {"commit": B}, True),
        # one old run (no code stamp): fall back to commit even though the other has a stamp
        ({"commit": A, "code": CODE_X, "scan": SCAN_S}, {"commit": A}, False),
    ],
)
def test_overlay_and_patch_view_agree_on_the_generation_rule(
    tmp_path: Path, a_kw: dict, b_kw: dict, expected: bool
) -> None:
    conn = open_atlas(tmp_path / "atlas.db")
    try:
        _mk(conn, A, **a_kw)
        _mk(conn, B, **b_kw)
        conn.commit()
        assert _both_agree(conn, A, B) is expected
    finally:
        conn.close()


def test_an_absent_run_proves_no_mismatch(tmp_path: Path) -> None:
    """An absent run cannot be shown to differ — both sides return not-a-mismatch (served)."""
    conn = open_atlas(tmp_path / "atlas.db")
    try:
        _mk(conn, A, code=CODE_X, scan=SCAN_S)
        conn.commit()
        assert _both_agree(conn, A, "missing") is False
    finally:
        conn.close()
