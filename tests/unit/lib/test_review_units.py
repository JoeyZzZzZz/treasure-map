# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The review of a run pair cut into work units (lib/query/review_units) and its MCP face
(start_diff_review(run_pair=...)): the must-read predicate, the round-robin hand-out order, unit
ids and shards, disposal, the report, and the cache.

Zero real data: the World of test_diff_review (one run pair, diffs of libx and liby), plus
hand-built entries and pair facts where a signal is easier to state than to build."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests.unit.lib.test_diff_review import (  # noqa: F401 — the autouse cache fixture
    DX,
    DY,
    PAIR,
    World,
    _clear_view_caches,
    _pair_anchor,
    a_row,
)
from treasure_map import mcp_app
from treasure_map.lib import overlay
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query import review_units as ru


@pytest.fixture(autouse=True)
def _clear_unit_cache() -> None:
    ru.DIFF_CACHE.clear()


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> World:
    w = World(tmp_path, monkeypatch)
    # libx: an A entry (attention 0), an undetermined pair (R), a changed aligned pair with no
    # candidate (C, attention 2), a function in no pair (P). liby: an R entry and a P entry.
    w.pair(DX, "00001000", "00001000")
    w.rows[DX] = [a_row("00001000")]
    w.pair(DX, "00002000", "00002800", conf=0.5, sim=0.4)
    w.pair(DX, "00003000", "00003000", conf=0.97, sim=0.7)
    w.unpaired(DX, "b", "00004000", "unmatched_analysis_complete")
    w.pair(DY, "00005000", "00005000", conf=0.5, sim=0.6)
    w.unpaired(DY, "a", "00006000", "unmatched_analysis_complete")
    return w


def _review(w: World, k: int = ru.DEFAULT_K, **kw: Any) -> ru.PairReview:
    return ru.review_pair(
        w.atlas,
        "runA",
        "runB",
        k=k,
        pair_staleness={"source_stale": False},
        server_commit="c0",
        **kw,
    )


def _members(r: ru.PairReview) -> dict[str, ru.Member]:
    return {m.entry_id or m.anchor_ref: m for u in r.units for m in u.members}


# ── the order every reader shares ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("diff_id", [DX, DY])
def test_the_listing_is_the_default_page_order_with_its_attention_and_lift(
    world: World, diff_id: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ significance_listing gives the entries in the order, attention and lift_basis of the
    default get_diff_patch_view page — one computation, so the two never part. (libx's C entry is
    read at attention 0 here, through the one significance both read, so the significance order
    and the candidate_tier order differ.)

    MUTATION (verified RED): order the listing by candidate_tier -> the C entry is not first ->
    RED."""
    real = pv.significance

    def floated(e: Any, *a: Any) -> tuple[int, str]:
        if e.entry_id == "pair:00003000:00003000":
            return (0, "test_float")
        return real(e, *a)

    monkeypatch.setattr(pv, "significance", floated)
    listing = pv.significance_listing(world.atlas, diff_id)
    assert listing is not None and not listing.withheld
    page = pv.get_diff_patch_view(world.atlas, diff_id, limit=200)
    got = [(o.entry.entry_id, o.attention, o.lift_basis) for o in listing.entries]
    want = [
        (e["entry_id"], e["significance"]["attention"], e.get("lift_basis"))
        for e in page["entries"]
    ]
    assert got == want
    if diff_id == DX:
        assert got[0][0] == "pair:00003000:00003000"


# ── the predicate ────────────────────────────────────────────────────────────────────────────


def test_each_reason_marks_its_entries_and_the_rest_are_second_tier(world: World) -> None:
    """★ P entries, attention-0 entries and the first k of each diff are must-read; the rest of
    the listed entries are second tier, in a batch per diff and bucket.

    MUTATION (verified RED): drop the P reason -> b:00004000 second tier -> RED; drop the
    attention-0 reason (k=0) -> the A entry second tier -> RED."""
    r = _review(world, k=0)
    m = _members(r)
    assert m["b:00004000"].reasons == ("p_entry",)
    assert m["a:00006000"].reasons == ("p_entry",)
    assert m["pair:00001000:00001000"].reasons == ("attention_0",)
    assert m["pair:00002000:00002800"].reasons == ()
    assert m["pair:00003000:00003000"].reasons == ()
    by_kind = {u.kind for u in r.units if not u.must_read}
    assert by_kind == {ru.SECOND_TIER}
    second = [u for u in r.units if u.kind == ru.SECOND_TIER]
    assert {(u.stream, u.members[0].bucket) for u in second} == {(DX, "R"), (DX, "C"), (DY, "R")}


def test_the_first_k_entries_of_each_diff_are_must_read(world: World) -> None:
    """★ k=2: the first two entries of each diff by its own default order are must-read
    (``top_k``), whatever their bucket; k changes the set, not the order.

    MUTATION (verified RED): never add top_k -> the R entries stay second tier -> RED."""
    r = _review(world, k=2)
    m = _members(r)
    assert "top_k" in m["pair:00002000:00002800"].reasons  # libx's second
    assert "top_k" in m["pair:00005000:00005000"].reasons  # liby's first
    assert "top_k" not in m["pair:00003000:00003000"].reasons  # libx's third
    assert r.report["must_read"]["by_reason"]["top_k"] == 4


def _entry(**kw: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "shown_bucket": "B",
        "pair": SimpleNamespace(aligned=True),
        "sink_candidate_counts": None,
        "sink_callsite_counts": None,
    }
    return SimpleNamespace(**{**base, **kw})


@pytest.mark.parametrize(
    ("entry", "want"),
    [
        # one side not in its scan's inventory, the other naming a sink candidate: an R entry
        (
            _entry(
                shown_bucket="R",
                pair=SimpleNamespace(aligned=False),
                sink_candidate_counts={
                    "delta": [],
                    "unknown": [
                        {"sink": "system", "side": "a", "reason": "function_not_in_scan_inventory"}
                    ],
                },
            ),
            ("side_not_in_inventory",),
        ),
        # the same on a B entry: not the transition clause
        (
            _entry(
                sink_candidate_counts={
                    "delta": [],
                    "unknown": [
                        {"sink": "system", "side": "a", "reason": "function_not_in_scan_inventory"}
                    ],
                }
            ),
            (),
        ),
        # unknown with no sink named: nothing on the other side
        (
            _entry(
                shown_bucket="R",
                pair=SimpleNamespace(aligned=False),
                sink_candidate_counts={
                    "delta": [],
                    "unknown": [
                        {"sink": None, "side": "a", "reason": "function_not_in_scan_inventory"}
                    ],
                },
            ),
            (),
        ),
        # fewer command calls on B
        (
            _entry(sink_callsite_counts={"delta": [{"sink": "system", "a": 2, "b": 1}]}),
            ("command_calls_fewer",),
        ),
        (
            _entry(sink_callsite_counts={"delta": [{"sink": "_eval", "a": 1, "b": 0}]}),
            ("command_calls_fewer",),
        ),
        # equal, more calls, a copy-family sink, a wide-char sink: not
        (_entry(sink_callsite_counts={"delta": [{"sink": "system", "a": 2, "b": 2}]}), ()),
        (_entry(sink_callsite_counts={"delta": [{"sink": "system", "a": 1, "b": 2}]}), ()),
        (_entry(sink_callsite_counts={"delta": [{"sink": "strcpy", "a": 2, "b": 1}]}), ()),
        (_entry(sink_callsite_counts={"delta": [{"sink": "wcscpy", "a": 2, "b": 1}]}), ()),
        # an unknown side is never fewer
        (
            _entry(
                sink_callsite_counts={
                    "delta": [],
                    "unknown": [{"sink": "system", "side": "b", "reason": "text_unavailable"}],
                }
            ),
            (),
        ),
        # an undetermined pairing: not an aligned pair
        (
            _entry(
                pair=SimpleNamespace(aligned=False),
                sink_callsite_counts={"delta": [{"sink": "system", "a": 2, "b": 1}]},
            ),
            (),
        ),
    ],
    ids=[
        "transition_r",
        "transition_not_r",
        "transition_no_sink",
        "fewer_system",
        "fewer_eval",
        "equal",
        "more",
        "copy_sink",
        "wide_char",
        "unknown_side",
        "not_aligned",
    ],
)
def test_the_two_count_clauses(entry: SimpleNamespace, want: tuple[str, ...]) -> None:
    """★ The transition clause (an R entry, one side outside its scan's inventory, a sink named)
    and the command-call clause (an aligned pair, fewer calls on B of the command class, _eval or
    execvpe; never a copy or wide-char sink, never an unknown side).

    MUTATION (verified RED): accept any bucket for the transition clause -> transition_not_r;
    count the wide-char family -> wide_char; drop the aligned check -> not_aligned; read b <= a ->
    equal (each -> RED in its case)."""
    assert ru.entry_reasons(entry, 99, 2, None, 4) == want


# ── units, order, shards ────────────────────────────────────────────────────────────────────


def _facts(**kw: Any) -> ru.PairFacts:
    base: dict[str, Any] = {
        "run_a": "runA",
        "run_b": "runB",
        "diffs": [],
        "presence": None,
        "presence_members": [],
        "pair_files": None,
        "file_members": [],
        "files_unavailable": None,
        "failed_diffs": [],
        "not_diffed_binaries": {},
        "identical_not_diffed": {},
    }
    return ru.PairFacts(**{**base, **kw})


def _m(anchor: str, stream: str, pos: int, bucket: str = "R", reasons: tuple[str, ...] = ()) -> Any:
    kind = {"binary_presence": "binary_presence", "non_binary_file": "non_binary_file"}.get(
        bucket, "entry"
    )
    return ru.Member(
        anchor_ref=anchor,
        kind=kind,
        stream=stream,
        position=pos,
        entry_id=anchor if kind == "entry" else None,
        bucket=bucket,
        reasons=reasons,
    )


def _diff(diff_id: str, members: list[Any]) -> ru.DiffFacts:
    return ru.DiffFacts(diff_id, diff_id, True, False, [], members, {}, "runA", "runB")


def test_units_are_handed_out_round_robin_by_position() -> None:
    """★ Round r hands out the r-th entry of every diff (each in its own order), of the
    binary_presence binaries and of the changed files, before any (r+1)-th: a diff's head is never
    queued behind another diff's long tail.

    MUTATION (verified RED): order units by stream first (diff by diff) -> RED."""
    d1 = _diff("p::d1", [_m(f"d1e{i}", "p::d1", i, reasons=("p_entry",)) for i in range(3)])
    d2 = _diff("p::d2", [_m(f"d2e{i}", "p::d2", i, reasons=("p_entry",)) for i in range(2)])
    facts = _facts(
        diffs=[d2, d1],
        presence_members=[
            _m("bp0", ru.PRESENCE_STREAM, 0, "binary_presence", ("binary_presence",))
        ],
        file_members=[
            _m(f"f{i}", ru.FILE_STREAM, i, "non_binary_file", ("non_binary_file",))
            for i in range(2)
        ],
    )
    order = [u.members[0].anchor_ref for u in ru.cut_units(facts, k=0)]
    assert order == ["d1e0", "d2e0", "bp0", "f0", "d1e1", "d2e1", "f1", "d1e2"]


def test_s_entries_and_the_second_tier_are_batched_and_capped() -> None:
    """Bucket S entries are one batch per diff (must-read), the second tier one per diff and
    bucket; a batch never holds more than one annotate_diff_batch call takes.

    MUTATION (verified RED): drop the cap -> one S batch of 250 -> RED."""
    s = [_m(f"s{i}", "p::d", i, "S", ("bucket_s",)) for i in range(250)]
    c = [_m(f"c{i}", "p::d", 250 + i, "C") for i in range(3)]
    units = ru.cut_units(_facts(diffs=[_diff("p::d", s + c)]), k=0)
    sizes = sorted((u.kind, len(u.members)) for u in units)
    assert sizes == [(ru.S_BATCH, 50), (ru.S_BATCH, ru.BATCH_MAX), (ru.SECOND_TIER, 3)]
    assert all(u.must_read for u in units if u.kind == ru.S_BATCH)


def test_a_unit_id_is_its_kind_members_and_predicate_and_shards_partition_the_units() -> None:
    """★ The id is a hash of the kind, the sorted member anchors and the predicate version (not of
    the order they came in); the shards of n partition the units, read from the id's first 8 hex
    digits — never Python's per-process hash().

    MUTATION (verified RED): leave the predicate version out of the id -> RED; read the shard from
    hash(uid) -> not a partition across processes (and the fixed expectations here) -> RED."""
    assert ru.unit_id("entry", ["b", "a"]) == ru.unit_id("entry", ["a", "b"])
    assert ru.unit_id("entry", ["a"]) != ru.unit_id("s_batch", ["a"])
    assert ru.unit_id("entry", ["a"]) != ru.unit_id("entry", ["a"], predicate_version="v1")
    ids = [ru.unit_id("entry", [str(i)]) for i in range(40)]
    shards = [{u for u in ids if ru.in_shard(u, w, 3)} for w in range(3)]
    assert set().union(*shards) == set(ids)
    assert sum(len(s) for s in shards) == len(ids)
    assert all(ru.in_shard(u, None, None) for u in ids)
    assert ru.in_shard("00000005ffffffff", 2, 3) and not ru.in_shard("00000005ffffffff", 0, 3)


# ── disposal, next unit, the report ─────────────────────────────────────────────────────────


def test_a_judged_member_is_disposed_and_the_next_unit_moves_on(world: World) -> None:
    """★ The next unit is the first in the hand-out order with a member not disposed; a judgement
    (concluded or change_inconclusive) disposes it. must_read_complete needs the must-read units
    only — the second tier keeps ``complete`` false, not it.

    MUTATION (verified RED): count change_inconclusive as not disposed -> RED; let the second tier
    hold must_read_complete -> RED; hand a session the audit of its own judgement -> RED; let an
    open audit leave must_read_complete true -> RED."""
    r = _review(world, k=0)
    first = r.next_unit()
    assert first is not None and first.members[0].entry_id == "pair:00001000:00001000"
    assert r.report["must_read_complete"] is False
    writer = overlay.WriteContext(channel="mcp", session="writer")
    world.judge(DX, _pair_anchor(DX, "00001000", "00001000"), "change_inconclusive", ctx=writer)
    world.judge(DX, _pair_anchor(DX, "00002000", "00002800"), "changed_real")  # second tier
    r = _review(world, k=0)
    # Its audit follows it at once — but not for the session that wrote it (it cannot read it
    # blind): that session moves on.
    audit = r.next_unit()
    assert audit is not None and audit.kind == ru.AUDIT
    nxt = r.next_unit(session="writer")
    assert nxt is not None and nxt.members[0].entry_id != first.members[0].entry_id
    must = [m for u in r.units if u.must_read and u.kind != ru.AUDIT for m in u.members]
    for m in must:
        if m.entry_id and m.entry_id.startswith(("a:", "b:")):
            world.judge(m.stream, m.anchor_ref, "changed_real")
    # The change_inconclusive opened an audit: a blind second reading that agrees closes it.
    assert _review(world, k=0).report["must_read_complete"] is False
    world.judge(
        DX,
        _pair_anchor(DX, "00001000", "00001000"),
        "change_inconclusive",
        shadow=True,
        ctx=overlay.WriteContext(channel="mcp", session="auditor"),
    )
    r = _review(world, k=0)
    assert r.report["must_read_complete"] is True
    assert r.report["complete"] is False  # second tier unjudged
    assert r.report["must_read"]["members_disposed"] == r.report["must_read"]["members"]


def test_a_member_whose_facts_moved_is_not_disposed(world: World) -> None:
    """A judgement whose facts moved reads needs_recheck: not disposed, so its unit comes back.

    MUTATION (verified RED): count needs_recheck as disposed -> RED."""
    anchor = _pair_anchor(DX, "00001000", "00001000")
    world.judge(DX, anchor, "changed_real")
    assert ru.disposed(_review(world, k=0).progress.states[anchor])
    world.rows[DX] = []  # a re-hunt: the A row is gone, the entry's facts moved
    states = _review(world, k=0).progress.states
    assert not ru.disposed(states.get(anchor))


def test_the_coverage_statement_states_the_numbers(world: World) -> None:
    r = _review(world, k=1)
    rep = r.report
    line = rep["coverage_statement"]
    assert line.startswith(
        f"must-read {rep['must_read']['members']} / disposed {rep['must_read']['members_disposed']}"
    )
    assert f"predicate {ru.PREDICATE_VERSION} (k=1)" in line and line.endswith("server c0")


# ── the cache ────────────────────────────────────────────────────────────────────────────────


def test_the_structure_is_cached_by_the_facts_and_a_rehunt_reads_anew(world: World) -> None:
    """★ A second reading serves each diff from the cache; a re-hunt (the runs' stamps move) reads
    every diff anew. A judgement never invalidates it.

    MUTATION (verified RED): key the cache by diff_id alone -> the re-hunt is served the old
    units -> RED."""
    _review(world)
    misses = ru.DIFF_CACHE.misses
    world.judge(DX, _pair_anchor(DX, "00001000", "00001000"), "changed_real")
    _review(world)
    assert ru.DIFF_CACHE.misses == misses
    world.rows[DX] = []  # re-hunt: no candidate row, the pair is no longer an A entry
    r = _review(world)
    assert ru.DIFF_CACHE.misses == misses + 2
    assert _members(r)["pair:00001000:00001000"].bucket != "A"


# ── the MCP face ────────────────────────────────────────────────────────────────────────────


def _tool(w: World) -> Any:
    return mcp_app.make_tools(w.path)["start_diff_review"]


@pytest.mark.parametrize(
    ("kw", "word"),
    [
        ({}, "exactly one"),
        ({"diff_id": DX, "run_pair": PAIR}, "exactly one"),
        ({"diff_id": DX, "unit": "abc"}, "run_pair only"),
        ({"diff_id": DX, "k": 3}, "run_pair only"),
        ({"run_pair": PAIR, "worker": 0}, "together"),
        ({"run_pair": PAIR, "worker": 3, "workers": 3}, "worker must be"),
        ({"run_pair": PAIR, "k": -1}, "k must be"),
        ({"run_pair": PAIR, "limit": 5}, "limit"),
    ],
)
def test_the_two_forms_and_their_arguments_are_checked(
    world: World, kw: dict[str, Any], word: str
) -> None:
    """MUTATION (verified RED): drop the exactly-one check -> {} reaches the diff form -> RED."""
    out = _tool(world)(**kw)
    assert word in str(out.get("error") or ""), out


def test_the_pair_form_reports_and_hands_out_the_next_unit(world: World) -> None:
    """★ run_pair returns the bounded report (coverage_statement, must-read counts) and the next
    unit with its id and material; unit=<id> returns that unit alone; an unknown id says so. Every
    response stays within the byte budget and never lists every unit.

    MUTATION (verified RED): leave next_unit's material out -> RED."""
    tool = _tool(world)
    out = tool(run_pair=PAIR)
    assert "error" not in out, out
    rep = out["report"]
    assert rep["coverage_statement"].startswith("must-read ")
    assert rep["predicate_version"] == ru.PREDICATE_VERSION
    nxt = out["next_unit"]
    assert nxt["kind"] == ru.ENTRY and nxt["members"][0]["entry_id"] == "pair:00001000:00001000"
    assert nxt.get("material", {}).get("entry", {}).get("entry_id") == "pair:00001000:00001000"
    assert len(json.dumps(out)) <= mcp_app._RESPONSE_BYTE_BUDGET
    assert "units" not in out
    one = tool(run_pair=PAIR, unit=nxt["unit_id"])
    assert one["unit"]["unit_id"] == nxt["unit_id"] and one.get("material")
    assert "no unit" in tool(run_pair=PAIR, unit="0" * 16).get("error", "")
    shard = tool(run_pair=PAIR, worker=0, workers=2)
    assert shard["shard"] == {"worker": 0, "workers": 2}
    if shard["next_unit"] is not None:
        assert ru.in_shard(shard["next_unit"]["unit_id"], 0, 2)


def test_the_diff_form_is_unchanged(world: World) -> None:
    """The diff_id form answers as it did: no report, no unit."""
    out = _tool(world)(diff_id=DX)
    assert out["diff_id"] == DX and "headline" in out and "report" not in out


# ── the command line ─────────────────────────────────────────────────────────────────────────


def _cli(w: World, *args: str) -> Any:
    from click.testing import CliRunner

    from treasure_map.cli.review_cli import review

    return CliRunner().invoke(
        review, [*args, "--atlas", str(w.path)] if args[0] == "report" else list(args)
    )


def test_the_terminal_summary_leads_with_the_coverage_statement(world: World) -> None:
    """★ The first line printed is the report's coverage_statement, as the MCP report gives it.

    MUTATION (verified RED): print the header first -> RED."""
    res = _cli(world, "report", PAIR)
    assert res.exit_code == 0, res.output
    want = _review(world).report["coverage_statement"].replace("server c0", "")
    assert res.output.splitlines()[0].startswith(want)
    assert "next units" in res.output


def test_markdown_and_html_write_every_unit_and_html_escapes(
    world: World, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ --md / --html write every unit with its members; the HTML page carries no script and
    escapes what the firmware named.

    MUTATION (verified RED): drop html.escape on a member -> the injected tag survives -> RED."""
    md = tmp_path / "r.md"
    res = _cli(world, "report", PAIR, "--md", "-o", str(md))
    assert res.exit_code == 0, res.output
    text = md.read_text()
    units = _review(world).units
    assert all(u.unit_id in text for u in units)
    real = ru.cut_units

    def tagged(facts: ru.PairFacts, k: int = ru.DEFAULT_K) -> list[ru.Unit]:
        out = real(facts, k)
        m = out[0].members[0]
        bad = ru.Member(**{**m.__dict__, "entry_id": "<script>x</script>"})
        return [ru.Unit(**{**out[0].__dict__, "members": (bad,)}), *out[1:]]

    monkeypatch.setattr(ru, "cut_units", tagged)
    page = tmp_path / "r.html"
    res = _cli(world, "report", PAIR, "--html", "-o", str(page))
    assert res.exit_code == 0, res.output
    body = page.read_text()
    assert "<script" not in body and "&lt;script&gt;" in body
    assert "Content-Security-Policy" in body


@pytest.mark.parametrize(
    "args",
    [("--md",), ("-o", "x.md"), ("--md", "--html", "-o", "x")],
    ids=["md_without_o", "o_without_format", "both_formats"],
)
def test_the_output_options_are_checked(world: World, args: tuple[str, ...]) -> None:
    res = _cli(world, "report", PAIR, *args)
    assert res.exit_code != 0


def test_the_skill_prints_and_installs(tmp_path: Path) -> None:
    """The shipped skill prints as it is and installs as <dir>/tmap-diff-review/SKILL.md."""
    from click.testing import CliRunner

    from treasure_map.cli.review_cli import review

    out = CliRunner().invoke(review, ["skill"])
    assert out.exit_code == 0 and out.output.startswith("---\nname: tmap-diff-review")
    res = CliRunner().invoke(review, ["skill", "--install", str(tmp_path / "skills")])
    assert res.exit_code == 0
    assert (tmp_path / "skills" / "tmap-diff-review" / "SKILL.md").read_text() == out.output


# ── audits and disagreements ─────────────────────────────────────────────────────────────────

A1 = _pair_anchor(DX, "00001000", "00001000")


def _ctx(session: str) -> Any:
    return overlay.WriteContext(channel="mcp", session=session)


def _nrc(anchor: str) -> dict[str, Any]:
    return {"checked": [anchor], "why_unchanged": "same call"}


def test_a_no_real_change_is_audited_blind_and_an_agreeing_reading_closes_it(
    world: World,
) -> None:
    """★ A no_real_change opens an audit unit (its member read without its state); a shadow from
    the session that wrote it is not blind and closes nothing; a blind shadow that agrees closes
    it, and must_read_complete is no longer held by it.

    MUTATION (verified RED): open no audit on no_real_change -> RED; count a non-blind shadow ->
    the writer's own shadow closes it -> RED."""
    world.judge(DX, A1, "no_real_change", verdict_basis=_nrc(A1), ctx=_ctx("writer"))
    r = _review(world, k=0)
    assert len(r.audits.open) == 1
    audit = r.audits.open[0]
    assert audit.sources == ("no_real_change",) and audit.write_session == "writer"
    assert r.report["audits"]["open"] == 1
    own = overlay.WriteContext(
        channel="mcp", session="writer", read_basis={"basis": "fetched", "non_blind": True}
    )
    world.judge(DX, A1, "no_real_change", verdict_basis=_nrc(A1), shadow=True, ctx=own)
    assert len(_review(world, k=0).audits.open) == 1
    world.judge(DX, A1, "no_real_change", verdict_basis=_nrc(A1), shadow=True, ctx=_ctx("auditor"))
    r = _review(world, k=0)
    assert r.audits.open == [] and r.audits.disagreements == []


def test_a_reading_otherwise_is_a_disagreement_that_a_person_settles(world: World) -> None:
    """★ A blind shadow with another verdict is a disagreement (must_read_complete false); a
    person's judgement settles it — and is not itself audited.

    MUTATION (verified RED): let a human write be audited -> an audit remains -> RED; ignore a
    disagreeing shadow -> RED."""
    world.judge(DX, A1, "no_real_change", verdict_basis=_nrc(A1), ctx=_ctx("writer"))
    world.judge(DX, A1, "changed_real", shadow=True, ctx=_ctx("auditor"))
    r = _review(world, k=0)
    assert len(r.audits.disagreements) == 1
    d = r.audits.disagreements[0]
    assert d["why"] == "audit_reads_otherwise" and d["shadow"] == ["changed_real"]
    assert r.report["must_read_complete"] is False
    world.judge(DX, A1, "changed_real", attributed_to="human", ctx=_ctx("person"))
    r = _review(world, k=0)
    assert r.audits.disagreements == [] and r.audits.open == []
    # The person's judgement is the current one; the agent's and the audit's stay in the history.
    row = world.atlas.execute(
        "SELECT verdict, attributed_to FROM overlay WHERE anchor_ref = ?", (A1,)
    ).fetchone()
    assert tuple(row) == ("changed_real", "human")
    events = [
        tuple(e)
        for e in world.atlas.execute(
            "SELECT event, attributed_to FROM overlay_history WHERE anchor_ref = ? ORDER BY id",
            (A1,),
        )
    ]
    assert events == [
        ("insert", "agent-via-mcp"),
        ("shadow", "agent-via-mcp"),
        ("update", "human"),
    ]


def test_an_overwrite_by_another_session_is_a_disagreement(world: World) -> None:
    """★ Two sessions write the same anchor with different verdicts: the later stands and the pair
    is a disagreement; the same session changing its mind is not.

    MUTATION (verified RED): flag only the audit kind -> RED."""
    world.judge(DX, A1, "changed_real", ctx=_ctx("s1"))
    world.judge(DX, A1, "changed_real", ctx=_ctx("s1"))
    assert _review(world, k=0).audits.disagreements == []
    world.judge(DX, A1, "change_inconclusive", ctx=_ctx("s2"))
    found = [x for x in _review(world, k=0).audits.disagreements if x["anchor_ref"] == A1]
    assert len(found) == 1
    assert found[0]["why"] == "overwritten_by_another_session"
    assert found[0]["before"] == "changed_real"


# ── the MCP writes: unit, shadow, read basis ─────────────────────────────────────────────────


def _server_call(server: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
    from tests.unit.test_tool_surface import _call

    return _call(server, name, args)


def test_a_write_naming_its_unit_records_what_was_read_and_hands_on_the_next(
    world: World,
) -> None:
    """★ Through the server: the unit handed out by start_diff_review, judged with its unit_id,
    records read_basis unit_delivered and answers with the next unit; a write on a must-read
    member that read nothing first records unread_before_verdict — which opens an audit.

    MUTATION (verified RED): leave read_basis out of the write's context -> RED; never mark
    unread_before_verdict -> no audit -> RED."""
    server = mcp_app.build_server(world.path)
    head = _server_call(server, "start_diff_review", {"run_pair": PAIR, "k": 0})
    nxt = head["next_unit"]
    anchor = nxt["members"][0]["anchor_ref"]
    out = _server_call(
        server,
        "annotate_diff",
        {
            "anchor_ref": anchor,
            "verdict": "changed_real",
            "rationale": "r",
            "diff_id": DX,
            "unit_id": nxt["unit_id"],
        },
    )
    assert out.get("written") is True, out
    assert (out.get("read_basis") or {}).get("basis") == "unit_delivered"
    assert out["next_unit"]["unit_id"] != nxt["unit_id"]
    hist = world.atlas.execute(
        "SELECT unit_id, read_basis, channel FROM overlay_history WHERE anchor_ref = ?", (anchor,)
    ).fetchone()
    assert hist[0] == nxt["unit_id"] and hist[2] == "mcp"
    assert json.loads(hist[1] or "{}").get("basis") == "unit_delivered"
    p_entry = f"{PAIR}#function_presence#libx::b:00004000"
    blind = _server_call(
        server,
        "annotate_diff",
        {"anchor_ref": p_entry, "verdict": "changed_real", "rationale": "r", "diff_id": DX},
    )
    assert blind.get("written") is True, blind
    assert blind["read_basis"] == {"basis": "none", "unread_before_verdict": True}
    audits = _review(world, k=0).audits.open
    assert any(
        a.member.anchor_ref == p_entry and "unread_before_verdict" in a.sources for a in audits
    )


def test_an_audit_unit_write_is_a_shadow_and_a_person_cannot_be_claimed_over_mcp(
    world: World,
) -> None:
    """★ A write naming an audit unit is a shadow (the current judgement unchanged); a write
    naming a unit it is not a member of is refused; attributed_to='human' is refused over MCP,
    'human-via-agent' is recorded.

    MUTATION (verified RED): write an audit unit's judgement as a normal write -> the current
    verdict changes -> RED; accept 'human' over MCP -> RED."""
    tool = mcp_app.make_tools(world.path)["annotate_diff"]
    world.judge(DX, A1, "no_real_change", verdict_basis=_nrc(A1), ctx=_ctx("writer"))
    opened = _review(world, k=0).audits.open
    assert len(opened) == 1
    uid = opened[0].unit.unit_id
    out = tool(A1, "changed_real", "r", diff_id=DX, unit_id=uid)
    assert out.get("written") is True and "SHADOW" in out["note"]
    row = world.atlas.execute("SELECT verdict FROM overlay WHERE anchor_ref = ?", (A1,)).fetchone()
    assert row[0] == "no_real_change"
    other = _pair_anchor(DX, "00003000", "00003000")
    stray = tool(other, "changed_real", "r", diff_id=DX, unit_id=uid)
    assert stray.get("written") is False and "does not hold" in stray["error"]
    refused = tool(other, "changed_real", "r", diff_id=DX, attributed_to="human")
    assert refused.get("written") is False and "human-via-agent" in refused["error"]
    relayed = tool(other, "changed_real", "r", diff_id=DX, attributed_to="human-via-agent")
    assert relayed.get("written") is True
    who = world.atlas.execute(
        "SELECT attributed_to FROM overlay WHERE anchor_ref = ?", (other,)
    ).fetchone()
    assert who[0] == "human-via-agent"


# ── a person's channels: judge and the worksheet ─────────────────────────────────────────────


def test_judge_takes_a_person_only_on_an_interactive_terminal(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ --by human from a pipe is refused (nothing written); human-via-agent is written so; on a
    terminal with an agent marker set it drops to human-via-agent; on a plain terminal with the
    confirmation typed it is human.

    MUTATION (verified RED): skip the terminal check -> the pipe writes 'human' -> RED; ignore the
    marker -> RED."""
    from click.testing import CliRunner

    from treasure_map.cli import review_cli

    unit = next(u for u in _review(world, k=0).units if len(u.members) == 1)
    anchor = unit.members[0].anchor_ref
    base = [unit.unit_id, PAIR, "--verdict", "changed_real", "--rationale", "r", "--k", "0"]
    base += ["--atlas", str(world.path)]
    run = CliRunner().invoke
    for var in review_cli.AGENT_ENV_MARKERS:
        monkeypatch.delenv(var, raising=False)

    def who() -> str | None:
        row = world.atlas.execute(
            "SELECT attributed_to FROM overlay WHERE anchor_ref = ?", (anchor,)
        ).fetchone()
        return row[0] if row else None

    res = run(review_cli.review, ["judge", *base])
    assert res.exit_code != 0 and "interactive terminal" in res.output and who() is None
    assert run(review_cli.review, ["judge", *base, "--by", "human-via-agent"]).exit_code == 0
    assert who() == "human-via-agent"
    monkeypatch.setattr(review_cli, "_interactive", lambda: True)
    monkeypatch.setenv(review_cli.AGENT_ENV_MARKERS[0], "1")
    res = run(review_cli.review, ["judge", *base])
    assert res.exit_code == 0 and "human-via-agent" in res.output
    monkeypatch.delenv(review_cli.AGENT_ENV_MARKERS[0])
    res = run(review_cli.review, ["judge", *base], input="human\n")
    assert res.exit_code == 0, res.output
    assert who() == "human"


def test_the_worksheet_goes_out_and_comes_back_through_the_same_gates(
    world: World, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ --emit lists the open audits; --apply writes each filled item through annotate_diff (a
    person's attribution, the worksheet channel) and refuses one whose checked names nothing in the
    view — that one is not written.

    MUTATION (verified RED): write the items straight to the overlay (no annotate_diff) -> the bad
    item is taken -> RED."""
    from click.testing import CliRunner

    from treasure_map.cli import review_cli

    for var in review_cli.AGENT_ENV_MARKERS:
        monkeypatch.delenv(var, raising=False)
    a2 = _pair_anchor(DX, "00003000", "00003000")
    world.judge(DX, A1, "change_inconclusive", ctx=_ctx("w"))
    world.judge(DX, a2, "change_inconclusive", ctx=_ctx("w"))
    sheet = tmp_path / "sheet.json"
    run = CliRunner().invoke
    at = ["--atlas", str(world.path)]
    assert run(review_cli.review, ["audit", PAIR, "--emit", str(sheet), *at]).exit_code == 0
    data = json.loads(sheet.read_text())
    items = {it["anchor_ref"]: it for it in data["items"]}
    assert {A1, a2} <= set(items)
    items[A1].update(verdict="changed_real", rationale="the guard is gone")
    items[a2].update(
        verdict="no_real_change",
        why_unchanged="w",
        checked=["runA::runB#function_pair#libx::0dead::0beef"],
    )
    sheet.write_text(json.dumps(data))
    res = run(
        review_cli.review,
        ["audit", PAIR, "--apply", str(sheet), "--by", "human-via-agent", *at],
    )
    assert res.exit_code == 0, res.output
    assert "written 1, refused 1" in res.output
    rows = dict(
        world.atlas.execute(
            "SELECT anchor_ref, verdict FROM overlay WHERE anchor_ref IN (?, ?)", (A1, a2)
        ).fetchall()
    )
    assert rows == {A1: "changed_real", a2: "change_inconclusive"}
    ch = world.atlas.execute(
        "SELECT channel, attributed_to FROM overlay_history WHERE anchor_ref = ? "
        "ORDER BY id DESC LIMIT 1",
        (A1,),
    ).fetchone()
    assert tuple(ch) == ("worksheet", "human-via-agent")


def test_a_batch_naming_its_unit_records_it_and_hands_on_the_next(world: World) -> None:
    """annotate_diff_batch with unit_id writes every item with the unit in its history and answers
    with the next unit; an item outside the unit refuses the batch, nothing written.

    MUTATION (verified RED): drop the context in the batch's write -> no unit_id in the history ->
    RED."""
    tool = mcp_app.make_tools(world.path)["annotate_diff_batch"]
    unit = next(u for u in _review(world).units if u.kind == ru.ENTRY)
    item = {"anchor_ref": unit.members[0].anchor_ref, "verdict": "changed_real", "rationale": "r"}
    out = tool([item], diff_id=unit.stream, unit_id=unit.unit_id)
    assert out.get("written") is True, out
    assert "next_unit" in out
    got = world.atlas.execute(
        "SELECT unit_id FROM overlay_history WHERE anchor_ref = ?", (item["anchor_ref"],)
    ).fetchone()
    assert got is not None and got[0] == unit.unit_id
    other = next(
        m
        for u in _review(world).units
        for m in u.members
        if m.stream == unit.stream and m.anchor_ref != item["anchor_ref"]
    )
    stray = dict(item, anchor_ref=other.anchor_ref)
    bad = tool([stray], diff_id=unit.stream, unit_id=unit.unit_id)
    assert bad.get("written") is False
