"""Candidate-level sink overlay (lib/query/sink_overlay).

Zero real data: every ref / run / binary name here is synthetic placeholder hex. Exercises the
atlas+BinDiff backend's honest four-state engine across every presence path, both judging
directions, the co-claim fold on both sides, the coverage invariant and the run-pair mode.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.query import sink_overlay as so

SHA_A = "a" * 64
SHA_B = "b" * 64
DIFF_ID = "runA::runB::libx"
BANCHOR = "deadbeef"  # synthetic binary-content-hash prefix used in the ref
DEG = '{"callsite_located": false, "anchor_degraded": "out_of_body"}'


def _ref(run: str, func_entry: str, sink: str, offset: str | None = None) -> str:
    """Synthetic evidence_ref in the real shape: {run}#{banchor}:{func_entry}@{sink}[@{offset}]."""
    tail = f"{sink}@{offset}" if offset is not None else sink
    return f"{run}#{BANCHOR}:{func_entry}@{tail}"


def _deg(callsite_addr: str | None) -> str:
    """flow_evidence of a degraded (out-of-body) candidate, with the recovered address if any."""
    flow: dict[str, object] = {"callsite_located": False, "anchor_degraded": "out_of_body"}
    if callsite_addr is not None:
        flow["callsite_addr"] = callsite_addr
    return json.dumps(flow)


def _pattern(conn: sqlite3.Connection, sink_class: str) -> int:
    row = conn.execute(
        "SELECT pattern_id FROM pattern WHERE structural_fingerprint = ?", (f"fp_{sink_class}",)
    ).fetchone()
    if row is not None:
        return int(row[0])
    cur = conn.execute(
        "INSERT INTO pattern (source_class, sink_class, call_sequence_shape, "
        "structural_fingerprint, fingerprint_algo_version) VALUES "
        "('external_input', ?, 'source->sink', ?, 'v1')",
        (sink_class, f"fp_{sink_class}"),
    )
    return int(cur.lastrowid or 0)


def _inst(
    conn: sqlite3.Connection,
    run: str,
    sha: str,
    ref: str,
    sink_class: str,
    flow: str | None = None,
    *,
    sink: str | None = None,
    path: str = "/fw/sbin/libx",
) -> None:
    conn.execute(
        "INSERT INTO instance (pattern_id, evidence_ref, source_run_id, binary_content_hash, "
        "binary_path, sink_anchor, flow_evidence) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (_pattern(conn, sink_class), ref, run, sha, path, sink or sink_class, flow),
    )


def _falign(
    conn: sqlite3.Connection, fa: str, fb: str, conf: float, state: str, diff_id: str = DIFF_ID
) -> None:
    conn.execute(
        "INSERT INTO function_alignment (diff_id, addr_a, addr_b, alignment_confidence, "
        "alignment_state) VALUES (?, ?, ?, ?, ?)",
        (diff_id, fa, fb, conf, state),
    )


def _fpres(conn: sqlite3.Connection, side: str, addr: str, state: str) -> None:
    conn.execute(
        "INSERT INTO function_presence (diff_id, side, addr, presence_state) VALUES (?, ?, ?, ?)",
        (DIFF_ID, side, addr, state),
    )


def _imatch(conn: sqlite3.Connection, aa: str, ab: str, fa: str) -> None:
    conn.execute(
        "INSERT INTO instruction_match (diff_id, func_addr_a, addr_a, addr_b) VALUES (?, ?, ?, ?)",
        (DIFF_ID, fa, aa, ab),
    )


def _diff_meta(
    conn: sqlite3.Connection, diff_id: str, binary: str, sha_a: str | None, sha_b: str | None
) -> None:
    conn.execute(
        "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id, binary_a, binary_b, sha256_a, "
        "sha256_b, diff_ok, version_skew) VALUES (?, 'runA', 'runB', ?, ?, ?, ?, 1, 0)",
        (diff_id, binary, binary, sha_a, sha_b),
    )


def _runs(conn: sqlite3.Connection) -> None:
    for run in ("runA", "runB"):
        conn.execute(
            "INSERT INTO run (run_id, hunt_commit, build_hash, hunt_instances) "
            "VALUES (?, 'c0ffee', 'feedface', 10)",
            (run,),
        )


@pytest.fixture
def atlas(tmp_path: Path) -> sqlite3.Connection:
    conn = open_atlas(tmp_path / "atlas.db")
    _runs(conn)
    _diff_meta(conn, DIFF_ID, "libx", SHA_A, SHA_B)

    # F1 aligned (0.97): four tier-1 callsites exercising the callee-verification outcomes.
    _falign(conn, "00001000", "00002000", 0.97, "aligned")
    _inst(conn, "runA", SHA_A, _ref("runA", "00001000", "cmd", "0x000010"), "cmd")  # persisted
    _inst(conn, "runA", SHA_A, _ref("runA", "00001000", "cmd", "0x000020"), "cmd")  # diff callee
    _inst(conn, "runA", SHA_A, _ref("runA", "00001000", "cmd", "0x000030"), "cmd")  # not cand.
    _inst(conn, "runA", SHA_A, _ref("runA", "00001000", "cmd", "0x000040"), "cmd")  # unmatched
    _imatch(conn, "00001010", "00002010", "00001000")
    _imatch(conn, "00001020", "00002020", "00001000")
    _imatch(conn, "00001030", "00002030", "00001000")  # 0x40 deliberately NOT matched
    _inst(conn, "runB", SHA_B, _ref("runB", "00002000", "cmd", "0x000010"), "cmd")  # same sink
    _inst(conn, "runB", SHA_B, _ref("runB", "00002000", "format", "0x000020"), "format")
    # 0x2030: no B candidate -> counterpart_not_candidate

    # F2 aligned LOW confidence -> alignment_low_confidence
    _falign(conn, "00003000", "00004000", 0.50, "alignment_undetermined")
    _inst(conn, "runA", SHA_A, _ref("runA", "00003000", "cmd", "0x000008"), "cmd")

    # F3 A-side unmatched, analysis complete -> removed
    _fpres(conn, "a", "00005000", "unmatched_analysis_complete")
    _inst(conn, "runA", SHA_A, _ref("runA", "00005000", "cmd", "0x000004"), "cmd")

    # F4 A-side unmatched, analysis INCOMPLETE -> undetermined (no_counterpart_undetermined)
    _fpres(conn, "a", "00006000", "unmatched_analysis_incomplete")
    _inst(conn, "runA", SHA_A, _ref("runA", "00006000", "cmd", "0x000004"), "cmd")

    # F5 aligned: tier-3 function_fallback (no offset). copy present both sides -> persisted;
    # a path_sink only on A -> no_counterpart_undetermined.
    _falign(conn, "00007000", "00008000", 0.95, "aligned")
    _inst(conn, "runA", SHA_A, _ref("runA", "00007000", "copy"), "copy")
    _inst(conn, "runA", SHA_A, _ref("runA", "00007000", "path_sink"), "path_sink")
    _inst(conn, "runB", SHA_B, _ref("runB", "00008000", "copy"), "copy")

    # F6 aligned: wrapper, present both sides -> persisted
    _falign(conn, "00009000", "0000a000", 0.95, "aligned")
    _inst(conn, "runA", SHA_A, _ref("runA", "00009000", "cmd_via_wrapper"), "cmd")
    _inst(conn, "runB", SHA_B, _ref("runB", "0000a000", "cmd_via_wrapper"), "cmd")

    # F7 aligned: tier-2. (copy) A=2 B=2 -> persisted; (format) A=2 B=1 -> mismatch
    _falign(conn, "0000b000", "0000c000", 0.95, "aligned")
    for _ in range(2):
        _inst(conn, "runA", SHA_A, _ref("runA", "0000b000", "copy"), "copy", DEG)
        _inst(conn, "runB", SHA_B, _ref("runB", "0000c000", "copy"), "copy", DEG)
    for _ in range(2):
        _inst(conn, "runA", SHA_A, _ref("runA", "0000b000", "format"), "format", DEG)
    _inst(conn, "runB", SHA_B, _ref("runB", "0000c000", "format"), "format", DEG)  # only 1 on B

    # F8 B-side unmatched complete -> added
    _fpres(conn, "b", "0000d000", "unmatched_analysis_complete")
    _inst(conn, "runB", SHA_B, _ref("runB", "0000d000", "cmd", "0x000004"), "cmd")

    conn.commit()
    return conn


def _rows(atlas: sqlite3.Connection, **kw: object) -> list[so.SinkOverlayRow]:
    return so.compute_sink_overlay(atlas, DIFF_ID, **kw).rows  # type: ignore[arg-type]


def _by(rows: list[so.SinkOverlayRow], a_off: str | None = None, b_off: str | None = None):
    """Find a row by a distinctive substring of its a_ref / b_ref."""
    for r in rows:
        if a_off and r.a_ref and a_off in r.a_ref:
            return r
        if b_off and r.b_ref and b_off in r.b_ref:
            return r
    return None


def _assert_full_coverage(res: so.SinkOverlayResult) -> None:
    cov = res.coverage
    assert cov.a_total > 0 and cov.b_total > 0  # a check over nothing proves nothing
    assert cov.a_represented == cov.a_total and cov.b_represented == cov.b_total, cov
    assert cov.coverage_violation is False and cov.unrepresented_refs == []


# ── the original engine paths ──────────────────────────────────────────────────────────


def test_tier1_persisted_same_callee(atlas: sqlite3.Connection) -> None:
    r = _by(_rows(atlas), a_off="@0x000010")
    assert r is not None and r.presence == "persisted"
    assert r.match_basis == "instruction" and r.key_granularity == "callsite"
    assert r.b_ref is not None and r.presence_reason is None


def test_tier1_present_different_callee(atlas: sqlite3.Connection) -> None:
    r = _by(_rows(atlas), a_off="@0x000020")
    assert r is not None and r.presence == "presence_undetermined"
    assert r.presence_reason == "present_different_callee"
    assert r.counterpart_call == "present_different_callee" and r.b_ref is not None


def test_tier1_counterpart_not_candidate(atlas: sqlite3.Connection) -> None:
    r = _by(_rows(atlas), a_off="@0x000030")
    assert r is not None and r.presence == "presence_undetermined"
    assert r.presence_reason == "counterpart_not_candidate" and r.b_ref is None


def test_tier1_instruction_unmatched(atlas: sqlite3.Connection) -> None:
    """Instruction data exists for this diff but not for this callsite: an export gap and a changed
    basic block look the same here, so the neutral name is used, never ``callsite_not_exported``."""
    r = _by(_rows(atlas), a_off="@0x000040")
    assert r is not None and r.presence == "presence_undetermined"
    assert r.presence_reason == "instruction_unmatched"
    assert all(x.presence_reason != "callsite_not_exported" for x in _rows(atlas))


def test_tier1_no_instruction_data_is_degraded(atlas: sqlite3.Connection) -> None:
    atlas.execute("DELETE FROM instruction_match")
    r = _by(_rows(atlas), a_off="@0x000010")
    assert r is not None and r.presence_reason == "crossside_match_degraded"


def test_alignment_low_confidence(atlas: sqlite3.Connection) -> None:
    r = _by(_rows(atlas), a_off=":00003000@")
    assert r is not None and r.presence == "presence_undetermined"
    assert r.presence_reason == "alignment_low_confidence"


def test_function_removed(atlas: sqlite3.Connection) -> None:
    r = _by(_rows(atlas), a_off=":00005000@")
    assert r is not None and r.presence == "removed" and r.match_basis == "function_level"


def test_function_unmatched_incomplete_undetermined(atlas: sqlite3.Connection) -> None:
    r = _by(_rows(atlas), a_off=":00006000@")
    assert r is not None and r.presence == "presence_undetermined"
    assert r.presence_reason == "no_counterpart_undetermined"


def test_tier3_persisted_and_undetermined(atlas: sqlite3.Connection) -> None:
    rows = _rows(atlas)
    cp = _by(rows, a_off=":00007000@copy")
    assert cp is not None and cp.presence == "persisted" and cp.match_basis == "function_level"
    ps = _by(rows, a_off=":00007000@path_sink")
    assert ps is not None and ps.presence == "presence_undetermined"


def test_wrapper_persisted(atlas: sqlite3.Connection) -> None:
    r = _by(_rows(atlas), a_off="cmd_via_wrapper")
    assert r is not None and r.presence == "persisted" and r.key_granularity == "wrapper"


def test_tier2_count_match_and_mismatch(atlas: sqlite3.Connection) -> None:
    rows = [r for r in _rows(atlas) if r.key_granularity == "degraded_out_of_body"]
    copy_row = next(r for r in rows if r.sink_class == "copy")
    assert copy_row.presence == "persisted" and copy_row.a_n == 2 and copy_row.b_n == 2
    fmt_row = next(r for r in rows if r.sink_class == "format")
    assert fmt_row.presence == "presence_undetermined"
    assert (
        fmt_row.presence_reason == "crossside_count_mismatch"
        and fmt_row.a_n == 2
        and fmt_row.b_n == 1
    )


def test_function_added(atlas: sqlite3.Connection) -> None:
    r = _by(_rows(atlas), b_off=":0000d000@")
    assert r is not None and r.presence == "added" and r.a_ref is None and r.b_ref is not None


def test_never_collapses_to_unchanged(atlas: sqlite3.Connection) -> None:
    # Honesty: no row is 'unchanged'; every non-persisted/added/removed is undetermined.
    for r in _rows(atlas):
        assert r.presence in ("added", "removed", "persisted", "presence_undetermined")
        if r.presence == "presence_undetermined":
            assert r.presence_reason is not None  # always a machine-readable reason


def test_filters(atlas: sqlite3.Connection) -> None:
    only_persisted = _rows(atlas, presence="persisted")
    assert only_persisted and all(r.presence == "persisted" for r in only_persisted)
    only_cmd = _rows(atlas, sink_class="cmd")
    assert only_cmd and all(r.sink_class == "cmd" for r in only_cmd)
    # coverage describes the whole diff, never the filtered slice
    _assert_full_coverage(so.compute_sink_overlay(atlas, DIFF_ID, sink_class="cmd"))


# ── B-side scan + coverage invariant ─────────────────────────────────────────────────


def test_b_only_callsite_in_aligned_function_is_emitted(atlas: sqlite3.Connection) -> None:
    """A callsite-tier candidate B has and A lacks, inside an aligned function pair, must be a row
    of its own (a_ref None) — the A pass never names it.

    MUTATION (verified RED): drop the B pass (``_judge_pass(out, db, ...)``) in ``_compute`` -> the
    B-only callsite appears in no row."""
    b_only = _ref("runB", "00002000", "cmd", "0x000050")
    _inst(atlas, "runB", SHA_B, b_only, "cmd")
    res = so.compute_sink_overlay(atlas, DIFF_ID)
    rows = [r for r in res.rows if r.b_ref == b_only]
    assert len(rows) == 1
    r = rows[0]
    assert r.a_ref is None and r.presence == "presence_undetermined"
    assert r.presence_reason == "instruction_unmatched" and r.key_granularity == "callsite"
    _assert_full_coverage(res)


def test_b_only_in_aligned_function_reason_table(atlas: sqlite3.Connection) -> None:
    """The B-side reasons mirror the A side: low-confidence pair, no instruction data at all,
    function-level key A lacks — each undetermined, never added."""
    low = _ref("runB", "00004000", "cmd", "0x000020")  # F2's B function: low confidence
    fn = _ref("runB", "00008000", "unlink_sink")  # F5's B function: tier-3 key A lacks
    _inst(atlas, "runB", SHA_B, low, "cmd")
    _inst(atlas, "runB", SHA_B, fn, "unlink_sink")
    rows = _rows(atlas)
    r_low, r_fn = _by(rows, b_off=low), _by(rows, b_off=fn)
    assert r_low is not None and r_low.presence_reason == "alignment_low_confidence"
    assert r_fn is not None and r_fn.presence_reason == "no_counterpart_undetermined"
    assert r_low.a_ref is None and r_fn.a_ref is None
    atlas.execute("DELETE FROM instruction_match")
    b_only = _ref("runB", "00002000", "cmd", "0x000050")
    _inst(atlas, "runB", SHA_B, b_only, "cmd")
    r = _by(_rows(atlas), b_off=b_only)
    assert r is not None and r.presence_reason == "crossside_match_degraded"


def test_coverage_invariant_holds(atlas: sqlite3.Connection, monkeypatch) -> None:
    """Every candidate of both sides is represented — across all four tiers, a fold on each side and
    B-only rows — and a dropped candidate is REPORTED, not raised and not hidden.

    MUTATION (verified RED): make ``_coverage`` count every candidate as represented (``a_rep =
    len(a_ids)``) -> the dropped-row half stays green on violation=False and fails."""
    _fold_scenario(atlas)
    b_only = _ref("runB", "00002000", "cmd", "0x000050")
    _inst(atlas, "runB", SHA_B, b_only, "cmd")
    res = so.compute_sink_overlay(atlas, DIFF_ID)
    _assert_full_coverage(res)
    tiers = {r.key_granularity for r in res.rows}
    assert tiers == {"callsite", "degraded_out_of_body", "function_fallback", "wrapper"}

    real_emit = so._Out.emit

    def dropping_emit(self, row, a=None, b=None):  # type: ignore[no-untyped-def]
        if row.b_ref == b_only and row.a_ref is None:
            return len(self.rows) - 1  # the row (and its coverage) silently vanish
        return real_emit(self, row, a, b)

    monkeypatch.setattr(so._Out, "emit", dropping_emit)
    broken = so.compute_sink_overlay(atlas, DIFF_ID)
    cov = broken.coverage
    assert cov.coverage_violation is True
    assert cov.b_represented == cov.b_total - 1 and cov.a_represented == cov.a_total
    assert cov.unrepresented_refs == [b_only]


def test_diff_failed_emits_b_side(atlas: sqlite3.Connection) -> None:
    """A failed diff makes every candidate of BOTH sides visible as undetermined.

    MUTATION (verified RED): emit only the A side in the diff_failed branch -> no b_ref row."""
    atlas.execute("UPDATE diff_meta SET diff_ok = 0 WHERE diff_id = ?", (DIFF_ID,))
    res = so.compute_sink_overlay(atlas, DIFF_ID)
    assert res.rows and all(
        r.presence == "presence_undetermined" and r.presence_reason == "diff_failed"
        for r in res.rows
    )
    b_refs = {r.b_ref for r in res.rows if r.b_ref}
    assert _ref("runB", "0000d000", "cmd", "0x000004") in b_refs
    _assert_full_coverage(res)
    deg = [r for r in res.rows if r.key_granularity == "degraded_out_of_body" and r.b_ref]
    assert sorted((r.sink_class, r.b_n) for r in deg) == [("copy", 2), ("format", 1)]


def test_missing_sha_emits_both_sides(atlas: sqlite3.Connection) -> None:
    atlas.execute("UPDATE diff_meta SET sha256_a = NULL WHERE diff_id = ?", (DIFF_ID,))
    res = so.compute_sink_overlay(atlas, DIFF_ID)
    assert res.rows and all(r.presence_reason == "diff_meta_missing_sha" for r in res.rows)
    assert any(r.b_ref for r in res.rows) and any(r.a_ref for r in res.rows)
    _assert_full_coverage(res)


def test_legacy_anchor_is_counted_not_dropped(atlas: sqlite3.Connection) -> None:
    _inst(atlas, "runA", SHA_A, "runA#fn12@cmd", "cmd")
    cov = so.compute_sink_overlay(atlas, DIFF_ID).coverage
    assert cov.excluded_legacy == 1 and cov.coverage_violation is False


# ── callee verification (tier-1 persisted) ────────────────────────────────────────────


def test_same_class_different_callee_is_not_persisted(atlas: sqlite3.Connection) -> None:
    """Two calls of the same sink CLASS but different callees, matched instruction-to-instruction,
    are not the same call: undetermined, never persisted. A same-callee pair whose class labels
    differ IS the same call.

    MUTATION (verified RED): compare ``o.sink_class == cand.sink_class`` instead of the sink name
    in ``_tier1_verdict`` -> the copy/copy pair reads persisted."""
    _inst(
        atlas, "runA", SHA_A, _ref("runA", "00001000", "copy", "0x000070"), "copy", sink="strncpy"
    )
    _inst(
        atlas, "runB", SHA_B, _ref("runB", "00002000", "copy", "0x000070"), "copy", sink="memmove"
    )
    _imatch(atlas, "00001070", "00002070", "00001000")
    a_fmt = _ref("runA", "00001000", "format", "0x000080")
    b_fmt = _ref("runB", "00002000", "fmt_string", "0x000080")
    _inst(atlas, "runA", SHA_A, a_fmt, "format", sink="snprintf")
    _inst(atlas, "runB", SHA_B, b_fmt, "fmt_string", sink="snprintf")
    _imatch(atlas, "00001080", "00002080", "00001000")
    rows = _rows(atlas)
    r = _by(rows, a_off="@copy@0x000070")
    assert r is not None and r.presence == "presence_undetermined"
    assert r.presence_reason == "present_different_callee"
    assert r.counterpart_call == "present_different_callee"
    assert r.b_ref == _ref("runB", "00002000", "copy", "0x000070")
    same = _by(rows, a_off=a_fmt)
    assert same is not None and same.presence == "persisted" and same.b_ref == b_fmt


def test_matched_only_to_degraded_is_crossgranularity(atlas: sqlite3.Connection) -> None:
    """The matched B address is claimed only by a degraded (function-level) candidate: that is
    never the persisted object of a callsite match."""
    _falign(atlas, "00014000", "00024000", 0.95, "aligned")
    _inst(atlas, "runA", SHA_A, _ref("runA", "00001000", "cmd", "0x000060"), "cmd")
    _imatch(atlas, "00001060", "00002060", "00001000")
    _inst(atlas, "runB", SHA_B, _ref("runB", "00024000", "cmd"), "cmd", _deg("0x2060"))
    res = so.compute_sink_overlay(atlas, DIFF_ID)
    r = _by(res.rows, a_off="@cmd@0x000060")
    assert r is not None and r.presence == "presence_undetermined"
    assert r.presence_reason == "crossgranularity_unresolved" and r.b_ref is None
    _assert_full_coverage(res)


# ── co-claim fold, both sides ─────────────────────────────────────────────────────────


def _fold_scenario(conn: sqlite3.Connection) -> None:
    """One tier-1 copy call per side (matched, same callee), each side with a degraded candidate in
    a second aligned function that co-claims that call's address, plus one unaddressed degraded
    copy per side in that second function."""
    _falign(conn, "00010000", "00020000", 0.95, "aligned")
    _falign(conn, "00011000", "00021000", 0.95, "aligned")
    _inst(conn, "runA", SHA_A, _ref("runA", "00010000", "copy", "0x000010"), "copy", sink="memcpy")
    _inst(conn, "runB", SHA_B, _ref("runB", "00020000", "copy", "0x000010"), "copy", sink="memcpy")
    _imatch(conn, "00010010", "00020010", "00010000")
    _inst(conn, "runA", SHA_A, _ref("runA", "00011000", "copy"), "copy", _deg("0x10010"))
    _inst(conn, "runA", SHA_A, _ref("runA", "00011000", "copy"), "copy", _deg(None))
    _inst(conn, "runB", SHA_B, _ref("runB", "00021000", "copy"), "copy", _deg("0x20010"))
    _inst(conn, "runB", SHA_B, _ref("runB", "00021000", "copy"), "copy", _deg(None))


def test_degraded_fold_is_symmetric(atlas: sqlite3.Connection) -> None:
    """Both sides fold their co-claiming degraded candidate into the tier-1 row; the remaining
    counts are equal, so the key persists — not a mismatch produced by folding one side only.

    MUTATION (verified RED): fold only the A side (``folded`` empty for B in ``_index``) -> B keeps
    2 against A's 1 -> crossside_count_mismatch."""
    _fold_scenario(atlas)
    res = so.compute_sink_overlay(atlas, DIFF_ID)
    key = _by(res.rows, a_off=":00011000@copy")
    assert key is not None and key.key_granularity == "degraded_out_of_body"
    assert key.presence == "persisted" and (key.a_n, key.b_n) == (1, 1)
    t1 = _by(res.rows, a_off=":00010000@copy@0x000010")
    assert t1 is not None and t1.presence == "persisted"
    assert t1.coclaimed_by == ["00011000"] and t1.coclaimed_by_b == ["00021000"]
    _assert_full_coverage(res)


def test_unowned_multi_claim_is_coclaim_unresolved(atlas: sqlite3.Connection) -> None:
    """Two functions' degraded candidates claim one callsite and no tier-1 candidate owns it: which
    function really holds the call is unknown, so neither key is counted.

    MUTATION (verified RED): make ``unresolved_ids`` always empty in ``_index`` -> both keys read
    persisted on their equal 1/1 counts."""
    for fa, fb in (("00012000", "00022000"), ("00013000", "00023000")):
        _falign(atlas, fa, fb, 0.95, "aligned")
        _inst(atlas, "runA", SHA_A, _ref("runA", fa, "copy"), "copy", _deg("0x12090"))
        _inst(atlas, "runB", SHA_B, _ref("runB", fb, "copy"), "copy", _deg(None))
    res = so.compute_sink_overlay(atlas, DIFF_ID)
    for fa in ("00012000", "00013000"):
        r = _by(res.rows, a_off=f":{fa}@copy")
        assert r is not None and r.presence == "presence_undetermined"
        assert r.presence_reason == "coclaim_unresolved"
    _assert_full_coverage(res)


def test_b_only_degraded_key_has_its_own_row(atlas: sqlite3.Connection) -> None:
    _inst(atlas, "runB", SHA_B, _ref("runB", "0000c000", "path_sink"), "path_sink", DEG)
    res = so.compute_sink_overlay(atlas, DIFF_ID)
    r = _by(res.rows, b_off=":0000c000@path_sink")
    assert r is not None and r.a_ref is None and (r.a_n, r.b_n) == (0, 1)
    assert r.presence_reason == "crossside_count_mismatch"
    _assert_full_coverage(res)


# ── diff-wide comparability ───────────────────────────────────────────────────────────


def test_version_skew_makes_every_row_undetermined(atlas: sqlite3.Connection) -> None:
    """MUTATION (verified RED): drop the diff-wide override in ``_compute`` -> persisted rows."""
    atlas.execute("UPDATE diff_meta SET version_skew = 1 WHERE diff_id = ?", (DIFF_ID,))
    rows = _rows(atlas)
    assert rows and all(
        r.presence == "presence_undetermined" and r.presence_reason == "version_skew" for r in rows
    )


def test_extraction_generation_mismatch(atlas: sqlite3.Connection) -> None:
    atlas.execute("UPDATE run SET build_hash = 'facade' WHERE run_id = 'runB'")
    rows = _rows(atlas)
    assert rows and all(r.presence_reason == "extraction_generation_mismatch" for r in rows)


def test_hunt_commit_mismatch_only_when_both_known(atlas: sqlite3.Connection) -> None:
    atlas.execute("UPDATE run SET hunt_commit = 'unknown' WHERE run_id = 'runB'")
    assert any(r.presence == "persisted" for r in _rows(atlas))  # unknown proves nothing
    atlas.execute("UPDATE run SET hunt_commit = 'decade' WHERE run_id = 'runB'")
    assert all(r.presence_reason == "extraction_generation_mismatch" for r in _rows(atlas))


# ── run-pair mode ──────────────────────────────────────────────────────────────────


def test_run_pair_reports_undiffed_binary(atlas: sqlite3.Connection) -> None:
    """A binary with no diff row in the run pair still has its candidates on the map.

    MUTATION (verified RED): skip the undiffed emission in ``compute_sink_overlay_runs`` -> the
    liby candidate is in no row (and coverage breaks)."""
    liby = "runA#cafecafe:00001000@cmd@0x000010"
    _inst(atlas, "runA", "c" * 64, liby, "cmd", path="/fw/sbin/liby")
    res = so.compute_sink_overlay_runs(atlas, "runA", "runB")
    r = _by(res.rows, a_off=liby)
    assert r is not None and r.diff_id is None and r.binary == "liby"
    assert r.presence == "presence_undetermined" and r.presence_reason == "binary_not_diffed"
    assert any(x.diff_id == DIFF_ID for x in res.rows)
    _assert_full_coverage(res)


def test_run_pair_reports_name_shadowed_binary(atlas: sqlite3.Connection) -> None:
    """A second binary sharing the diffed binary's NAME but not its content was never compared.

    MUTATION (verified RED): label every undiffed candidate ``binary_not_diffed`` -> RED."""
    shadow = "runB#beefbeef:00001000@cmd@0x000010"
    _inst(atlas, "runB", "e" * 64, shadow, "cmd", path="/fw/usr/lib/libx")
    res = so.compute_sink_overlay_runs(atlas, "runA", "runB")
    r = _by(res.rows, b_off=shadow)
    assert r is not None and r.diff_id is None and r.a_ref is None
    assert r.presence_reason == "shadowed_by_name_collision"
    _assert_full_coverage(res)


def test_run_pair_coverage_counts_legacy_separately(atlas: sqlite3.Connection) -> None:
    _inst(atlas, "runB", SHA_B, "runB#fn7@cmd", "cmd")
    cov = so.compute_sink_overlay_runs(atlas, "runA", "runB").coverage
    assert cov.excluded_legacy == 1 and cov.coverage_violation is False


# ── persistence + baseline staleness ─────────────────────────────────────────────────


def test_persist_roundtrip_and_idempotent(atlas: sqlite3.Connection) -> None:
    from treasure_map.lib.query import diff_align

    _fold_scenario(atlas)
    live = _rows(atlas)
    n1 = so.persist_sink_overlay(atlas, DIFF_ID)
    assert n1 == len(live)
    stored = atlas.execute(
        "SELECT presence, subject_kind, delta_kind, undetermined_reason, coclaimed_by "
        "FROM dimension_delta WHERE diff_id = ? AND subject_kind = 'candidate'",
        (DIFF_ID,),
    ).fetchall()
    assert len(stored) == len(live)
    # delta_kind projection is CHECK-safe and matches presence
    for presence, kind, dk, reason, _cob in stored:
        assert kind == "candidate"
        assert dk in ("layer_changed", "layer_unchanged", "delta_undetermined")
        if presence == "presence_undetermined":
            assert dk == "delta_undetermined" and reason is not None
    # both sides' co-claimers survive, side-tagged
    assert sorted(json.loads(c) for *_x, c in stored if c) == [["a:00011000", "b:00021000"]]
    # idempotent: persisting again replaces, not duplicates
    n2 = so.persist_sink_overlay(atlas, DIFF_ID)
    assert n2 == n1
    assert (
        atlas.execute(
            "SELECT COUNT(*) FROM dimension_delta WHERE diff_id=? AND subject_kind='candidate'",
            (DIFF_ID,),
        ).fetchone()[0]
        == n1
    )
    # get_diff_deltas must NOT surface candidate rows
    deltas = diff_align.get_diff_deltas(atlas, DIFF_ID, limit=10000)
    assert all(d["subject_kind"] != "candidate" for d in deltas["deltas"])


def test_persist_diff_failed_with_repeated_degraded_refs(atlas: sqlite3.Connection) -> None:
    """Degraded candidates share a bare ref; a failed diff must still persist (one key row each)."""
    atlas.execute("UPDATE diff_meta SET diff_ok = 0 WHERE diff_id = ?", (DIFF_ID,))
    assert so.persist_sink_overlay(atlas, DIFF_ID) == len(_rows(atlas))


def test_candidate_survives_edge_delete(atlas: sqlite3.Connection) -> None:
    from treasure_map.lib.atlas.writer import delete_dimension_delta

    n = so.persist_sink_overlay(atlas, DIFF_ID)
    assert n > 0
    delete_dimension_delta(atlas, DIFF_ID, subject_kind="edge")  # a layer-2 refresh
    remaining = atlas.execute(
        "SELECT COUNT(*) FROM dimension_delta WHERE diff_id=? AND subject_kind='candidate'",
        (DIFF_ID,),
    ).fetchone()[0]
    assert remaining == n  # candidate rows untouched by the edge-scoped delete


@pytest.mark.parametrize("commit", [None, "unknown", ""])
def test_persist_refuses_uncheckable_stamps(atlas: sqlite3.Connection, commit: str | None) -> None:
    """A baseline stamped with no real hunt commit could never be checked for staleness.

    MUTATION (verified RED): drop the hunt_commit gate in ``persist_sink_overlay`` -> rows land."""
    atlas.execute("UPDATE run SET hunt_commit = ? WHERE run_id = 'runB'", (commit,))
    with pytest.raises(so.SinkOverlayBaselineError, match="hunt_commit"):
        so.persist_sink_overlay(atlas, DIFF_ID)
    n = atlas.execute(
        "SELECT COUNT(*) FROM dimension_delta WHERE subject_kind = 'candidate'"
    ).fetchone()[0]
    assert n == 0


def test_persist_refuses_incomplete_overlay(atlas: sqlite3.Connection, monkeypatch) -> None:
    real_emit = so._Out.emit
    target = _ref("runB", "0000d000", "cmd", "0x000004")

    def dropping_emit(self, row, a=None, b=None):  # type: ignore[no-untyped-def]
        if row.b_ref == target:
            return len(self.rows) - 1
        return real_emit(self, row, a, b)

    monkeypatch.setattr(so._Out, "emit", dropping_emit)
    with pytest.raises(so.SinkOverlayBaselineError, match="unrepresented"):
        so.persist_sink_overlay(atlas, DIFF_ID)


def test_baseline_read_refuses_after_rehunt(atlas: sqlite3.Connection) -> None:
    """A stored baseline whose run was re-hunted since describes candidates that may be gone.

    MUTATION (verified RED): compare only hunt_commit in ``read_sink_overlay_baseline`` -> the
    hunt_instances change passes and rows are served."""
    n = so.persist_sink_overlay(atlas, DIFF_ID)
    fresh = so.read_sink_overlay_baseline(atlas, DIFF_ID)
    assert fresh["stale_baseline"] is False and len(fresh["rows"]) == n
    atlas.execute("UPDATE run SET hunt_instances = 11 WHERE run_id = 'runA'")
    stale = so.read_sink_overlay_baseline(atlas, DIFF_ID)
    assert stale["stale_baseline"] is True and stale["rows"] is None
    assert stale["mismatched_fields"] == ["hunt_instances_a"]


# ── layer-0 instruction persistence ──────────────────────────────────────────────────


def _bindiff(path: Path, pairs: list[tuple[int, int]]) -> Path:
    """A synthetic .BinDiff in the real BinDiff schema (function / basicblock / instruction,
    BIGINT-decimal addresses): one matched function 0x1000 <-> 0x2000 holding ``pairs``."""
    bd = sqlite3.connect(path)
    bd.execute(
        "CREATE TABLE function (id INT, address1 BIGINT, name1 TEXT, address2 BIGINT, name2 TEXT)"
    )
    bd.execute("CREATE TABLE basicblock (id INT, functionid INT, address1 BIGINT, address2 BIGINT)")
    bd.execute("CREATE TABLE instruction (basicblockid INT, address1 BIGINT, address2 BIGINT)")
    bd.execute("INSERT INTO function VALUES (1, 4096, 'f', 8192, 'f')")
    bd.execute("INSERT INTO basicblock VALUES (1, 1, 4096, 8192)")
    for a1, a2 in pairs:
        bd.execute("INSERT INTO instruction VALUES (1, ?, ?)", (a1, a2))
    bd.commit()
    bd.close()
    return path


def test_persist_instruction_matches(tmp_path: Path) -> None:
    """layer-0 instruction persistence: an A candidate callsite's match is stored, 1:1 on the A
    address; an instruction neither side flags is not."""
    from treasure_map.lib.diff.layer0 import persist_instruction_matches

    # 0x1010(4112) <-> 0x2010(8208) is the candidate callsite; 0x1018 is noise (no candidate)
    bindiff = _bindiff(tmp_path / "t.BinDiff", [(0x1010, 0x2010), (0x1018, 0x2018)])
    atlas = open_atlas(tmp_path / "atlas.db")
    _inst(atlas, "runA", SHA_A, _ref("runA", "00001000", "cmd", "0x000010"), "cmd")
    atlas.commit()
    n = persist_instruction_matches(
        atlas,
        bindiff_path=bindiff,
        diff_id=DIFF_ID,
        run_a_id="runA",
        sha_a=SHA_A,
        run_b_id="runB",
        sha_b=SHA_B,
        commit=True,
    )
    assert n == 1
    row = atlas.execute(
        "SELECT func_addr_a, addr_a, addr_b FROM instruction_match WHERE diff_id = ?", (DIFF_ID,)
    ).fetchone()
    assert tuple(row) == ("00001000", "00001010", "00002010")


def test_instruction_match_keeps_b_candidate_pairs(tmp_path: Path) -> None:
    """A pair whose B address is a B candidate but whose A address is not is stored too, so the
    overlay can say "B's call matched an A instruction that is not a candidate"
    (a_counterpart_not_candidate) instead of "B's call matched nothing" (instruction_unmatched).

    MUTATION (verified RED): keep only ``addr_a in candidate_addrs_a`` pairs in
    ``parse_instruction_matches`` -> one row stored, reason instruction_unmatched."""
    from treasure_map.lib.diff.layer0 import persist_instruction_matches

    bindiff = _bindiff(tmp_path / "t.BinDiff", [(0x1010, 0x2010), (0x1060, 0x2060)])
    atlas = open_atlas(tmp_path / "atlas.db")
    _runs(atlas)
    _diff_meta(atlas, DIFF_ID, "libx", SHA_A, SHA_B)
    _falign(atlas, "00001000", "00002000", 0.97, "aligned")
    _inst(atlas, "runA", SHA_A, _ref("runA", "00001000", "cmd", "0x000010"), "cmd")
    _inst(atlas, "runB", SHA_B, _ref("runB", "00002000", "cmd", "0x000010"), "cmd")
    b_only = _ref("runB", "00002000", "cmd", "0x000060")
    _inst(atlas, "runB", SHA_B, b_only, "cmd")
    atlas.commit()
    n = persist_instruction_matches(
        atlas,
        bindiff_path=bindiff,
        diff_id=DIFF_ID,
        run_a_id="runA",
        sha_a=SHA_A,
        run_b_id="runB",
        sha_b=SHA_B,
        commit=True,
    )
    assert n == 2
    pairs = atlas.execute(
        "SELECT addr_a, addr_b FROM instruction_match WHERE diff_id = ? ORDER BY addr_a", (DIFF_ID,)
    ).fetchall()
    assert [tuple(p) for p in pairs] == [("00001010", "00002010"), ("00001060", "00002060")]
    res = so.compute_sink_overlay(atlas, DIFF_ID)
    r = _by(res.rows, b_off=b_only)
    assert r is not None and r.a_ref is None and r.presence == "presence_undetermined"
    assert r.presence_reason == "a_counterpart_not_candidate"
    assert r.counterpart_call == "counterpart_not_candidate"
    _assert_full_coverage(res)


# ── MCP surface ─────────────────────────────────────────────────────────────────────


def _servable(atlas: sqlite3.Connection) -> None:
    """Runs whose hunt and extraction cannot be compared with the answering install are served."""
    atlas.execute("UPDATE run SET hunt_commit = 'unknown', build_hash = NULL")
    atlas.commit()


def test_mcp_modes_and_coverage(atlas: sqlite3.Connection, tmp_path: Path) -> None:
    from treasure_map import mcp_app

    _servable(atlas)
    tool = mcp_app.make_tools(tmp_path / "atlas.db")["get_diff_sink_overlay"]
    one = tool(DIFF_ID)
    assert one["diff_id"] == DIFF_ID and one["count"] == len(one["rows"]) > 0
    cov = one["coverage"]
    assert cov["coverage_violation"] is False and cov["b_represented"] == cov["b_total"] > 0
    pair = tool(run_a="runA", run_b="runB")
    assert (pair["run_a"], pair["run_b"]) == ("runA", "runB") and "coverage" in pair
    for bad in ({}, {"diff_id": DIFF_ID, "run_a": "runA", "run_b": "runB"}, {"run_a": "runA"}):
        assert "error" in tool(**bad), bad


def test_mcp_run_pair_refuses_a_stale_side(atlas: sqlite3.Connection, tmp_path: Path) -> None:
    from treasure_map import mcp_app

    _servable(atlas)
    atlas.execute("UPDATE run SET build_hash = '0000staleaaaa000' WHERE run_id = 'runB'")
    atlas.commit()
    out = mcp_app.make_tools(tmp_path / "atlas.db")["get_diff_sink_overlay"](
        run_a="runA", run_b="runB"
    )
    assert out["stale_scan"]["axis"] == "extraction" and out["resolved_run"] == "runB"
