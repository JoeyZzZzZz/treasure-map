# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""What was read before a judgement (lib/query/read_basis), from synthetic tool-call log lines."""

from __future__ import annotations

from typing import Any

import pytest

from treasure_map.lib.query import read_basis as rb

ANCHOR = "a::b#function_pair#libx::00401000::00402000"
ENTRY = "pair:00401000:00402000"
FILE = "a::b#non_binary#etc/rc"


def _line(tool: str, **params: Any) -> dict[str, Any]:
    extra = {k: params.pop(k) for k in ("unit", "unit_material_cut", "error") if k in params}
    return {"tool": tool, "params": params, **extra}


@pytest.mark.parametrize(
    ("lines", "kw", "basis"),
    [
        (None, {}, "unknown"),
        ([], {}, "none"),
        ([_line("get_diff_patch_view", diff_id="d", entry_id=ENTRY)], {}, "fetched"),
        ([_line("get_diff_patch_view", diff_id="d", entry_id=ANCHOR)], {}, "fetched"),
        ([_line("get_pseudocode", run_id="a", function="0x00402000")], {}, "fetched"),
        ([_line("get_pseudocode", run_id="a", function="00409999")], {}, "none"),
        ([_line("get_diff_patch_view", diff_id="d", entry_id="pair:1:2")], {}, "none"),
        ([_line("get_diff_patch_view", entry_id=ENTRY, error="no such")], {}, "none"),
        (
            [_line("start_diff_review", unit="u1", unit_material_cut=False)],
            {"unit_id": "u1"},
            "unit_delivered",
        ),
        (
            [_line("start_diff_review", unit="u2", unit_material_cut=False)],
            {"unit_id": "u1"},
            "none",
        ),
        # a cut delivery counts only once something of the unit was read after it
        (
            [_line("start_diff_review", unit="u1", unit_material_cut=True)],
            {"unit_id": "u1"},
            "none",
        ),
        (
            [
                _line("start_diff_review", unit="u1", unit_material_cut=True),
                _line("get_diff_patch_view", entry_id=ENTRY),
            ],
            {"unit_id": "u1"},
            "unit_delivered",
        ),
    ],
    ids=[
        "no_log",
        "empty",
        "entry_by_id",
        "entry_by_anchor",
        "pseudocode",
        "other_function",
        "other_entry",
        "errored_call",
        "delivered",
        "other_unit",
        "cut_not_read_on",
        "cut_read_on",
    ],
)
def test_the_read_basis_of_a_write(
    lines: list[dict[str, Any]] | None, kw: dict[str, Any], basis: str
) -> None:
    """★ unit_delivered when the session was handed the unit (a cut one, only once read on),
    fetched when it read the subject itself, none when it read nothing of it, unknown with no log.

    MUTATION (verified RED): count a cut delivery whatever followed -> cut_not_read_on -> RED;
    match a function by any hex in the anchor's run part -> other_function... (each in its case)."""
    assert rb.infer(lines, anchor_ref=ANCHOR, entry_id=ENTRY, **kw)["basis"] == basis


def test_a_file_is_fetched_by_its_path() -> None:
    lines = [_line("get_file_diff", run_pair="a::b", path="etc/rc")]
    assert rb.infer(lines, anchor_ref=FILE)["basis"] == "fetched"
    assert rb.infer([_line("get_file_diff", path="etc/other")], anchor_ref=FILE)["basis"] == "none"


@pytest.mark.parametrize(
    ("lines", "write_session", "session", "want"),
    [
        ([], "w", "auditor", True),
        ([], "auditor", "auditor", False),  # it wrote the judgement it audits
        ([_line("list_overlays")], "w", "auditor", False),  # it read the verdicts
        (None, "w", "auditor", False),  # no log: cannot be shown blind
        ([], "w", None, False),
    ],
    ids=["blind", "own_write", "read_verdicts", "no_log", "no_session"],
)
def test_a_shadow_is_blind_only_when_shown_so(
    lines: list[dict[str, Any]] | None, write_session: str, session: str | None, want: bool
) -> None:
    """★ A shadow is blind only when its session neither wrote the audited judgement nor read the
    overlay's verdicts — and that can be shown (a log, a session).

    MUTATION (verified RED): ignore list_overlays -> read_verdicts -> RED; ignore the writing
    session -> own_write -> RED."""
    assert rb.blind(lines, write_session, session) is want
