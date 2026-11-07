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
    lifted = ("unit", "unit_material_cut", "error", "rows_read")
    extra = {k: params.pop(k) for k in lifted if k in params}
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


def _batch(*whole: str, cut: bool = True) -> dict[str, Any]:
    """A batch's delivery line: the members its material kept (``unit_whole``)."""
    return {
        **_line("start_diff_review", unit="u1", unit_material_cut=cut),
        "unit_whole": list(whole),
    }


@pytest.mark.parametrize(
    ("lines", "want"),
    [
        # listed in the cut batch's material: read with the unit, at once
        ([_batch(ENTRY)], {"basis": "unit_delivered", "material_cut": False}),
        # not listed: the batch did not show it
        ([_batch("pair:1:2")], {"basis": "none"}),
        # a member left out of an UNCUT material (not in the view) is not shown either
        ([_batch("pair:1:2", cut=False)], {"basis": "none"}),
        # fetching ANOTHER member after the cut delivery does not read this one
        (
            [_batch("pair:1:2"), _line("get_diff_patch_view", entry_id="pair:1:2")],
            {"basis": "none"},
        ),
        # fetching this one after it does (logged with the row window it held, as a real read is)
        (
            [_batch("pair:1:2"), _line("get_diff_patch_view", entry_id=ENTRY, rows_read=[0, 0, 0])],
            {"basis": "unit_delivered", "material_cut": True},
        ),
        # a later delivery that lists it counts (any delivery before the write)
        ([_batch("pair:1:2"), _batch(ENTRY)], {"basis": "unit_delivered", "material_cut": False}),
    ],
    ids=["listed", "unlisted", "unlisted_uncut", "other_fetched", "self_fetched", "listed_later"],
)
def test_a_cut_batch_counts_only_the_members_it_showed(
    lines: list[dict[str, Any]], want: dict[str, Any]
) -> None:
    """★ FC01: a delivery reads a member only when its material showed that member whole (listed
    in ``unit_whole``), or the member itself was fetched after it — never because another member
    was.

    MUTATION (verified RED, 3 failed): read a listing delivery by its cut flag alone (ignore
    ``unit_whole``) -> listed, unlisted_uncut and listed_later RED. MUTATION (verified RED, 1
    failed): count a fetch of any delivered member (``_fetched`` of ``unit_whole[0]``) ->
    other_fetched RED."""
    assert rb.infer(lines, anchor_ref=ANCHOR, entry_id=ENTRY, unit_id="u1") == want


def test_a_file_is_fetched_by_its_path() -> None:
    lines = [_line("get_file_diff", run_pair="a::b", path="etc/rc")]
    assert rb.infer(lines, anchor_ref=FILE)["basis"] == "fetched"
    assert rb.infer([_line("get_file_diff", path="etc/other")], anchor_ref=FILE)["basis"] == "none"


def _call(tool: str, **params: Any) -> dict[str, Any]:
    """A log line as blind() reads it: the input params under ``params`` (where the real log keeps
    them). Unlike ``_line`` above, nothing is lifted to the top level."""
    return {"tool": tool, "params": params}


AU = "au1"  # the audit unit a shadow judgement is written on


def _delivered(unit: str = AU, **params: Any) -> dict[str, Any]:
    """start_diff_review(run_pair, unit=...) as logged when its answer handed that unit out."""
    return {**_call("start_diff_review", run_pair="a::b", unit=unit, **params), "unit": unit}


@pytest.mark.parametrize(
    ("lines", "write_session", "session", "want"),
    [
        ([_delivered()], "w", "auditor", True),
        # nothing of the audit unit was read: the shadow rests on nothing read blind
        ([], "w", "auditor", False),
        ([_delivered()], "auditor", "auditor", False),  # it wrote the judgement it audits
        (None, "w", "auditor", False),  # no log: cannot be shown blind
        ([_delivered()], "w", None, False),
        # fail-closed whitelist (G): only a proven-safe fact tool keeps it blind
        ([_delivered(), _call("list_overlays")], "w", "auditor", False),  # reads the verdicts
        (
            [_delivered(), _call("get_pseudocode", run_id="a", function="0x4000")],
            "w",
            "auditor",
            True,
        ),
        ([_delivered(), _call("get_diff_meta", diff_id="d")], "w", "auditor", True),
        # get_diff_patch_view carries review_state: NOT blind-safe (add it to the whitelist -> RED)
        (
            [_delivered(), _call("get_diff_patch_view", diff_id="d", entry_id="e")],
            "w",
            "auditor",
            False,
        ),
        # start_diff_review is safe only for the audit unit itself: another unit's material
        # carries review_state, and so does the pair overview
        ([_delivered(), _delivered("u2")], "w", "auditor", False),
        ([_delivered(), _call("start_diff_review", run_pair="a::b")], "w", "auditor", False),
        # the audit unit named, but its answer handed nothing out: no delivery
        ([_call("start_diff_review", run_pair="a::b", unit=AU)], "w", "auditor", False),
        # list_candidates is never safe: even with overlay off it carries coverage,
        # in_exploit_ledger and verdict_shape
        ([_delivered(), _call("list_candidates", run_id="a")], "w", "auditor", False),
        ([_delivered(), _call("list_candidates", run_id="a", overlay=True)], "w", "auditor", False),
        # an unlisted / new tool is not blind-safe (fail-closed)
        ([_delivered(), _call("some_new_tool")], "w", "auditor", False),
        # one unsafe call among safe ones is enough
        (
            [
                _delivered(),
                _call("get_pseudocode", run_id="a", function="0x4000"),
                _call("list_overlays"),
            ],
            "w",
            "auditor",
            False,
        ),
    ],
    ids=[
        "blind_audit_unit_only",
        "blind_empty",
        "own_write",
        "no_log",
        "no_session",
        "read_verdicts",
        "safe_pseudocode",
        "safe_diff_meta",
        "patch_view_not_safe",
        "other_unit_not_safe",
        "overview_not_safe",
        "audit_unit_not_delivered",
        "list_candidates_not_safe",
        "list_candidates_overlay_not_safe",
        "unlisted_tool_not_safe",
        "one_unsafe_call",
    ],
)
def test_a_shadow_is_blind_only_when_every_call_is_whitelisted(
    lines: list[dict[str, Any]] | None, write_session: str, session: str | None, want: bool
) -> None:
    """★ G fail-closed whitelist: a shadow on audit unit AU is blind only when its session read AU
    (a logged delivery of it), neither wrote the audited judgement nor made any call that is not
    blind-read-safe — and that can be shown (a log, a session). Only the proven-safe fact tools
    keep it blind; list_overlays, a verdict-carrying view (get_diff_patch_view), another unit or
    the pair overview, list_candidates (overlay or not) and any unlisted tool do not.

    MUTATION (verified RED): ignore the writing session -> own_write -> RED; put get_diff_patch_view
    in the whitelist -> patch_view_not_safe -> RED; treat an unlisted tool as safe (blocklist, not
    whitelist) -> unlisted_tool_not_safe -> RED; start_diff_review safe for any unit
    (``params.get("unit") is not None``) -> other_unit_not_safe -> RED; judge an empty log blind
    (drop the delivery check) -> blind_empty -> RED; put back list_candidates' overlay-off
    exemption -> list_candidates_not_safe -> RED."""
    assert rb.blind(lines, write_session, session, AU) is want
