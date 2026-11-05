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


def _call(tool: str, **params: Any) -> dict[str, Any]:
    """A log line as blind() reads it: the input params under ``params`` (where the real log keeps
    them). Unlike ``_line`` above, nothing is lifted to the top level."""
    return {"tool": tool, "params": params}


@pytest.mark.parametrize(
    ("lines", "write_session", "session", "want"),
    [
        ([], "w", "auditor", True),
        ([], "auditor", "auditor", False),  # it wrote the judgement it audits
        (None, "w", "auditor", False),  # no log: cannot be shown blind
        ([], "w", None, False),
        # fail-closed whitelist (G): only a proven-safe fact tool keeps it blind
        ([_call("list_overlays")], "w", "auditor", False),  # reads the verdicts
        ([_call("get_pseudocode", run_id="a", function="0x4000")], "w", "auditor", True),
        ([_call("get_diff_meta", diff_id="d")], "w", "auditor", True),
        # get_diff_patch_view carries review_state: NOT blind-safe (add it to the whitelist -> RED)
        ([_call("get_diff_patch_view", diff_id="d", entry_id="e")], "w", "auditor", False),
        # start_diff_review turns on the unit param: the unit's material is safe, overview is not
        ([_call("start_diff_review", run_pair="a::b", unit="u1")], "w", "auditor", True),
        ([_call("start_diff_review", run_pair="a::b")], "w", "auditor", False),
        # list_candidates turns on overlay: overlay=true shows the scan's own verdicts
        ([_call("list_candidates", run_id="a")], "w", "auditor", True),
        ([_call("list_candidates", run_id="a", overlay=True)], "w", "auditor", False),
        # an unlisted / new tool is not blind-safe (fail-closed)
        ([_call("some_new_tool")], "w", "auditor", False),
        # one unsafe call among safe ones is enough
        (
            [_call("get_pseudocode", run_id="a", function="0x4000"), _call("list_overlays")],
            "w",
            "auditor",
            False,
        ),
    ],
    ids=[
        "blind_empty",
        "own_write",
        "no_log",
        "no_session",
        "read_verdicts",
        "safe_pseudocode",
        "safe_diff_meta",
        "patch_view_not_safe",
        "unit_material_safe",
        "overview_not_safe",
        "list_candidates_safe",
        "list_candidates_overlay_not_safe",
        "unlisted_tool_not_safe",
        "one_unsafe_call",
    ],
)
def test_a_shadow_is_blind_only_when_every_call_is_whitelisted(
    lines: list[dict[str, Any]] | None, write_session: str, session: str | None, want: bool
) -> None:
    """★ G fail-closed whitelist: a shadow is blind only when its session neither wrote the audited
    judgement nor made any call that is not blind-read-safe — and that can be shown (a log, a
    session). Only the proven-safe fact tools keep it blind; list_overlays, a verdict-carrying view
    (get_diff_patch_view), the pair overview, list_candidates(overlay=true) and any unlisted tool
    do not. Two tools turn on a parameter (start_diff_review's unit, list_candidates' overlay).

    MUTATION (verified RED): ignore the writing session -> own_write -> RED; put get_diff_patch_view
    in the whitelist -> patch_view_not_safe -> RED; treat an unlisted tool as safe (blocklist, not
    whitelist) -> unlisted_tool_not_safe -> RED; ignore start_diff_review's unit param ->
    overview_not_safe or unit_material_safe -> RED."""
    assert rb.blind(lines, write_session, session) is want
