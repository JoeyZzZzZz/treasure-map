# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The diff readers that take a run pair say when the pair is recorded the other way round.

Zero real data. Two runs, diffed with ``new`` as A and ``old`` as B; a reader asked for (old, new)
answers for (old, new) — nothing — and says how many diffs exist the other way round, in its own
parameter names. It never swaps the pair itself.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from treasure_map import mcp_app
from treasure_map.lib.analyze.ghidra_runner import current_pass_version
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.diff.layer0 import make_diff_id
from treasure_map.lib.query import diff_align
from treasure_map.version import UNKNOWN_VERSION

_HINT = ("reverse_direction_diffs", "reverse_direction_note")


@pytest.fixture
def tools(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    # The stale-run gate compares a run's hunt commit with the install's; this one records none.
    monkeypatch.setattr(mcp_app, "_installed_commit", lambda: UNKNOWN_VERSION)
    path = tmp_path / "atlas.db"
    atlas = open_atlas(path)
    for run in ("old", "new"):
        atlas.execute(
            "INSERT INTO run (run_id, build_hash, hunt_commit, scan_status, analysis_db_path) "
            "VALUES (?, ?, 'facade', 'complete', ?)",
            (run, current_pass_version(), str(tmp_path / f"{run}.db")),
        )
    for binary, ok in (("libx", 1), ("liby", 0)):
        atlas.execute(
            "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id, binary_a, binary_b, diff_ok) "
            "VALUES (?, 'new', 'old', ?, ?, ?)",
            (make_diff_id("new", "old", binary), binary, binary, ok),
        )
    atlas.commit()
    atlas.close()
    return mcp_app.make_tools(path)


_CALLS: list[tuple[str, tuple[str, str], tuple[str, str]]] = [
    ("list_diffs", ("run_a_id", "run_b_id"), ("run_a_id", "run_b_id")),
    ("list_diff_blindspots", ("run_a_id", "run_b_id"), ("run_a_id", "run_b_id")),
    ("get_diff_sink_overlay", ("run_a", "run_b"), ("run_a", "run_b")),
]


@pytest.mark.parametrize(("tool", "params", "names"), _CALLS, ids=[c[0] for c in _CALLS])
def test_a_pair_asked_for_the_other_way_round_says_so_and_answers_as_asked(
    tools: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    tool: str,
    params: tuple[str, str],
    names: tuple[str, str],
) -> None:
    """The answer is the one for the pair as passed, plus the count and a note in the tool's own
    parameter names.

    MUTATION (verified RED): swap the pair when diffs exist the other way round -> the rows are the
    other direction's. MUTATION (verified RED): word the overlay's note with run_a_id / run_b_id
    -> not its own parameter names."""
    fn = tools[tool]
    asked = {params[0]: "old", params[1]: "new"}
    out = fn(**asked)
    assert out["reverse_direction_diffs"] == 2
    note = out["reverse_direction_note"]
    assert note.startswith(f"{names[0]} / {names[1]} are the before / after roles; 2 diffs exist")
    if names[0] == "run_a":
        assert "run_a_id" not in note
    # Everything else is what the reader answers without the hint.
    monkeypatch.setattr(mcp_app, "_reverse_direction_diffs", lambda atlas, a, b: 0)
    plain = fn(**asked)
    assert {k: v for k, v in out.items() if k not in _HINT} == plain
    assert not set(_HINT) & set(plain)


@pytest.mark.parametrize(("tool", "params", "names"), _CALLS, ids=[c[0] for c in _CALLS])
def test_a_pair_asked_for_the_recorded_way_round_carries_no_hint(
    tools: dict[str, Any], tool: str, params: tuple[str, str], names: tuple[str, str]
) -> None:
    out = tools[tool](**{params[0]: "new", params[1]: "old"})
    assert not set(_HINT) & set(out)


def test_one_run_alone_carries_no_hint(tools: dict[str, Any]) -> None:
    assert not set(_HINT) & set(tools["list_diffs"](run_a_id="old"))
    assert not set(_HINT) & set(tools["list_diff_blindspots"](run_b_id="new"))


def test_the_count_is_zero_when_the_pair_is_recorded_both_ways(tmp_path: Path) -> None:
    atlas = open_atlas(tmp_path / "atlas.db")
    for a, b in (("new", "old"), ("old", "new")):
        atlas.execute(
            "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id, binary_a, binary_b, diff_ok) "
            "VALUES (?, ?, ?, 'libx', 'libx', 1)",
            (make_diff_id(a, b, "libx"), a, b),
        )
    assert diff_align.reverse_direction_diffs(atlas, "old", "new") == 0
    assert diff_align.reverse_direction_diffs(atlas, "old", "old") == 0
    assert diff_align.pair_diffs(atlas, "new", "old") == (1, make_diff_id("new", "old", "libx"))
    atlas.close()
