# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""The `in_exploit_ledger` row marker, and whether an agent can discover the annotation layer.

Two things are tested here, and they are the same problem seen from both ends. The marker says a
person already confirmed a candidate, so re-analysing it is wasted effort — worth nothing if the
agent never learns what the key means. And the whole annotation layer had no mention in the
server's own instructions, so the vocabulary, the gates and the ordering built on top of it were
invisible. Both fixes live in channels that reach the agent on every call, not in optional prose.

Reverse mutations — each applied once and observed RED, then restored:

1. drop the lookup: remove the `refs_in_ledger` call (or the `in_ledger=` argument) in
   `list_candidates`. -> `test_row_is_marked_when_a_person_recorded_it` fails — the key never
   appears.
2. gate it on the view: move the marker inside `if overlay:`.
   -> `test_marker_shows_with_the_overlay_off` fails — a tool-side fact would come and go with an
   opt-in view.
3. make membership fuzzy: match on a prefix instead of the exact ref.
   -> `test_membership_is_exact` fails — a near-miss ref is claimed as confirmed.
4. smuggle it into `dimensions`: set `carried["in_exploit_ledger"]` instead of a top-level key.
   -> `test_marker_is_its_own_key_not_a_dimension` fails — a human record would be read as a
   dimension this tool established.
5. drop the RECORD phase from `_AGENT_INSTRUCTIONS`, or the legend line, or annotate's
   when-to-call sentence. -> the three discoverability tests fail, one each.
"""

from __future__ import annotations

from pathlib import Path

from treasure_map import mcp_app
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, add_private_exploit, upsert_pattern
from treasure_map.lib.query.exploit_ledger import refs_in_ledger

_RUN = "run_L"
_REF_A = f"{_RUN}#deadbeef:0x100@cmd"
_REF_B = f"{_RUN}#deadbeef:0x200@cmd"


def _atlas(tmp_path: Path) -> Path:
    """Two candidates in one run, so a marked row can be told apart from an unmarked one."""
    db = tmp_path / "atlas.db"
    con = open_atlas(db)
    for i, ref in enumerate((_REF_A, _REF_B)):
        pid = upsert_pattern(
            con, source_class="param", sink_class="cmd", call_sequence_shape=f"c{i}"
        )
        add_instance(
            con,
            InstanceRow(
                pattern_id=pid,
                source_run_id=_RUN,
                evidence_ref=ref,
                pseudocode_hash=f"h{i}",
                reachability_status="unknown",
                binary_path="usr/sbin/webd",
            ),
        )
    con.close()
    return db


def _record(db: Path, ref: str) -> None:
    con = open_atlas(db)
    try:
        add_private_exploit(
            con,
            evidence_ref=ref,
            pattern="command injection",
            exploit_note="proved by hand on the bench",
            attributed_to="jo",
        )
    finally:
        con.close()


def _rows(db: Path, **kw: object) -> dict[str, dict]:
    tools = mcp_app.make_tools(db)
    res = tools["list_candidates"](run_id=_RUN, limit=200, **kw)
    return {c["evidence_ref"]: c for c in res["candidates"]}


def test_membership_is_exact(tmp_path: Path) -> None:
    # ★ Exact refs only. Claiming a near-miss was confirmed would tell the agent to skip a
    # candidate nobody actually looked at — the most expensive way this marker could be wrong.
    db = _atlas(tmp_path)
    _record(db, _REF_A)
    _record(db, "run_L#deadbeef:0x300@copy")
    con = open_atlas(db)
    try:
        refs = refs_in_ledger(con)
    finally:
        con.close()
    assert refs == {_REF_A, "run_L#deadbeef:0x300@copy"}
    assert _REF_B not in refs
    assert _REF_A[:-1] not in refs  # a prefix of a recorded ref is not a recorded ref
    assert f"{_REF_A}x" not in refs


def test_row_is_marked_when_a_person_recorded_it(tmp_path: Path) -> None:
    db = _atlas(tmp_path)
    assert all("in_exploit_ledger" not in r for r in _rows(db).values())  # nothing recorded yet

    _record(db, _REF_A)
    rows = _rows(db)
    assert rows[_REF_A]["in_exploit_ledger"] is True
    assert "in_exploit_ledger" not in rows[_REF_B]  # absent, not False — the compact-row style


def test_marker_shows_with_the_overlay_off(tmp_path: Path) -> None:
    # ★ Whether a person recorded a candidate is a fact about the world, not a view preference. It
    # must not blink out because the agent left the opt-in ordering off.
    db = _atlas(tmp_path)
    _record(db, _REF_A)
    assert _rows(db, overlay=False)[_REF_A]["in_exploit_ledger"] is True
    assert _rows(db, overlay=True)[_REF_A]["in_exploit_ledger"] is True


def test_marker_is_its_own_key_not_a_dimension(tmp_path: Path) -> None:
    # ★ Three provenance layers on one row, each in its own key: what the tool established
    # (dimensions), what the agent decided (overlay), what a person confirmed (this). The carry
    # loop that builds `dimensions` adopts anything placed there as tool-established fact.
    db = _atlas(tmp_path)
    _record(db, _REF_A)
    row = _rows(db)[_REF_A]
    assert "in_exploit_ledger" in row
    assert "in_exploit_ledger" not in row["dimensions"]
    assert "in_exploit_ledger" not in row["controllability"]


def test_legend_explains_the_marker(tmp_path: Path) -> None:
    # The legend rides on every listing, so this is the one channel that always reaches the agent.
    db = _atlas(tmp_path)
    tools = mcp_app.make_tools(db)
    legend = tools["list_candidates"](run_id=_RUN)["legend"]
    assert "in_exploit_ledger" in legend
    assert "PERSON" in legend or "person" in legend
    # ... and it does not let the marker be over-read as a hardware reproduction
    assert "NOT a claim that anyone" in legend and "hardware" in legend


def test_agent_instructions_name_the_record_phase() -> None:
    # ★ The layer existed for three rounds while the server's own instructions never mentioned it,
    # which is why almost nothing was ever annotated. The loop now has a fourth phase, named in the
    # header too so a client that truncates the tail still shows it.
    text = mcp_app._AGENT_INSTRUCTIONS
    assert "RECALL -> FETCH FACTS -> JUDGE -> RECORD" in text
    assert "(4) RECORD" in text
    for tool in (
        "annotate(",
        "list_candidates(overlay=true)",
        "list_overlays(",
        "in_exploit_ledger",
    ):
        assert tool in text, f"the RECORD phase never names {tool}"
    assert "mark_exploited" not in text  # retired: no agent write path to the ledger


def test_annotate_says_when_to_call_it() -> None:
    # Knowing HOW to write was never the gap; knowing WHEN was. Stated in annotate's own
    # description — a fact tool must not push this at the agent in its results.
    tools = mcp_app.make_tools(Path("/nonexistent/atlas.db"))
    # Collapse the docstring's wrapping so the check is about the wording, not where it broke.
    text = " ".join((tools["annotate"].__doc__ or "").split())
    assert "worth keeping past THIS session" in text
    assert "not on every read" in text
    assert "not for mid-investigation scratch notes" in text
