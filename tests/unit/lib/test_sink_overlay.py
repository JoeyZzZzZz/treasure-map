"""Candidate-level sink overlay (lib/query/sink_overlay).

Zero real data: every ref / run / binary name here is synthetic placeholder hex. Exercises the
atlas+BinDiff backend's honest engine (persisted | presence_undetermined) across every path, both
judging directions, the co-claim fold on both sides, the coverage invariant and the run-pair mode.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
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

    # F3 A-side unmatched, analysis complete -> undetermined (function_unmatched), never 'removed'
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

    # F8 B-side unmatched complete -> undetermined (function_unmatched), never 'added'
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
    """Matched to an other-side instruction with no candidate: the candidates-only reading says
    counterpart_not_candidate; the default reading looks for call-site facts and, with none
    recorded for the diff, says they are absent."""
    r = _by(_rows(atlas, callee_backend="atlas_candidates"), a_off="@0x000030")
    assert r is not None and r.presence == "presence_undetermined"
    assert r.presence_reason == "counterpart_not_candidate" and r.b_ref is None
    d = _by(_rows(atlas), a_off="@0x000030")
    assert d is not None and d.presence_reason == "counterpart_call_facts_absent"
    assert d.counterpart_call == "unknown" and d.b_ref is None


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


def test_function_unmatched_a_side(atlas: sqlite3.Connection) -> None:
    """A whole A function with no B counterpart is not evidence of a deletion: undetermined."""
    r = _by(_rows(atlas), a_off=":00005000@")
    assert r is not None and r.presence == "presence_undetermined"
    assert r.presence_reason == "function_unmatched" and r.match_basis == "function_level"
    assert r.a_ref is not None and r.b_ref is None


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


def test_wrapper_fallback_persisted(atlas: sqlite3.Connection) -> None:
    """The function-level wrapper fallback (bare axis ref, no call located) keeps its own tier and
    matches the same (function, axis) key on the other side."""
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


def test_function_unmatched_b_side(atlas: sqlite3.Connection) -> None:
    """A whole B function with no A counterpart is not evidence of an addition: undetermined."""
    r = _by(_rows(atlas), b_off=":0000d000@")
    assert r is not None and r.presence == "presence_undetermined"
    assert r.presence_reason == "function_unmatched" and r.match_basis == "function_level"
    assert r.a_ref is None and r.b_ref is not None


def test_never_collapses_to_unchanged(atlas: sqlite3.Connection) -> None:
    # Honesty: no row is 'unchanged'; every non-persisted row is undetermined.
    for r in _rows(atlas):
        assert r.presence in ("persisted", "presence_undetermined")
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
    function-level key A lacks — each undetermined."""
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
    res = so.compute_sink_overlay(atlas, DIFF_ID, callee_backend="atlas_candidates")
    r = _by(res.rows, b_off=b_only)
    assert r is not None and r.a_ref is None and r.presence == "presence_undetermined"
    assert r.presence_reason == "a_counterpart_not_candidate"
    assert r.counterpart_call == "counterpart_not_candidate"
    _assert_full_coverage(res)
    d = _by(so.compute_sink_overlay(atlas, DIFF_ID).rows, b_off=b_only)
    assert d is not None and d.presence_reason == "counterpart_call_facts_absent"


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
    assert one["diff_id"] == DIFF_ID and one["summary"]["total_rows"] > 0
    assert "by_binary" not in one["summary"]  # one diff = one binary
    cov = one["coverage"]
    assert cov["coverage_violation"] is False and cov["b_represented"] == cov["b_total"] > 0
    pair = tool(run_a="runA", run_b="runB")
    assert (pair["run_a"], pair["run_b"]) == ("runA", "runB") and "coverage" in pair
    assert pair["summary"]["by_binary"] == {"libx": pair["summary"]["total_rows"]}
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


# ── reading a large result: summary by default, stable pages ───────────────────────────


def _tool(atlas: sqlite3.Connection, tmp_path: Path):  # type: ignore[no-untyped-def]
    from treasure_map import mcp_app

    _servable(atlas)
    return mcp_app.make_tools(tmp_path / "atlas.db")["get_diff_sink_overlay"]


def _key(r: dict) -> tuple:  # type: ignore[type-arg]
    return (
        r["diff_id"] or "",
        r["binary"] or "",
        r["key_granularity"],
        r["sink_class"],
        r["a_ref"] or "",
        r["b_ref"] or "",
    )


def _walk(tool, limit: int, **kw: object) -> list[dict]:  # type: ignore[no-untyped-def, type-arg]
    rows: list[dict] = []  # type: ignore[type-arg]
    offset: int | None = 0
    while offset is not None:
        page = tool(DIFF_ID, detail="rows", limit=limit, offset=offset, **kw)
        assert len(page["rows"]) <= limit
        rows.extend(page["rows"])
        offset = page["next_offset"]
    return rows


def test_default_detail_returns_no_rows(atlas: sqlite3.Connection, tmp_path: Path) -> None:
    """The default answer is counts, never the row dump.

    MUTATION (verified RED): default ``detail="rows"`` in the MCP signature -> ``rows`` is back."""
    out = _tool(atlas, tmp_path)(DIFF_ID)
    assert "rows" not in out and out["detail"] == "summary"
    s = out["summary"]
    assert s["total_rows"] == len(_rows(atlas)) > 0
    assert sum(s["by_presence"].values()) == s["total_rows"]
    assert sum(s["by_presence_reason"].values()) == s["total_rows"]
    assert s["by_presence_reason"]["persisted|-"] == s["by_presence"]["persisted"]


def test_paging_covers_every_row_once(atlas: sqlite3.Connection, tmp_path: Path) -> None:
    """Walking ``next_offset`` to the end yields every row exactly once — here over 2.5 pages.

    MUTATION (verified RED): ``next_offset = end - 1`` in ``page_overlay`` (an off-by-one) ->
    duplicated rows."""
    total = len(_rows(atlas))
    while total % 5:  # pad to a multiple of 5 so the row count is exactly 2.5 pages
        _inst(
            atlas, "runB", SHA_B, _ref("runB", "0000d000", "cmd", f"0x{0x100 + total:06x}"), "cmd"
        )
        atlas.commit()
        total += 1
    limit = total * 2 // 5
    tool = _tool(atlas, tmp_path)
    got = _walk(tool, limit)
    assert len(got) == total == len(_rows(atlas))
    dumped = [json.dumps(r, sort_keys=True) for r in got]
    assert len(set(dumped)) == total  # no duplicate
    every = sorted(json.dumps(asdict(r), sort_keys=True) for r in _rows(atlas))
    assert sorted(dumped) == every  # nothing missing


def test_page_overlay_pure_walk_two_and_a_half_pages() -> None:
    rows = [
        so.SinkOverlayRow(
            diff_id="d",
            binary="b",
            sink_class="cmd",
            a_ref=f"r#{i:03d}",
            b_ref=None,
            key_granularity="callsite",
            presence="presence_undetermined",
            presence_reason="instruction_unmatched",
            match_basis="instruction",
            counterpart_call=None,
            alignment_confidence=None,
        )
        for i in range(25)
    ]
    seen: list[str] = []
    offset: int | None = 0
    while offset is not None:
        page = so.page_overlay(rows, limit=10, offset=offset)
        assert page["total_rows"] == 25
        seen.extend(r.a_ref or "" for r in page["rows"])
        offset = page["next_offset"]
    assert seen == [f"r#{i:03d}" for i in range(25)]
    with pytest.raises(ValueError):
        so.page_overlay(rows, limit=0, offset=0)


def test_paging_order_is_deterministic(atlas: sqlite3.Connection, tmp_path: Path) -> None:
    """The same page twice is byte-identical, and the order is the documented neutral key — not the
    compute order (which here differs: the B-side rows are computed after the A side).

    MUTATION (verified RED): drop the sort in ``page_overlay`` (``ordered = list(rows)``) -> the
    page follows compute order instead of the key."""
    computed = [asdict(r) for r in _rows(atlas)]
    assert [_key(r) for r in computed] != sorted(_key(r) for r in computed)  # fixture is unsorted
    tool = _tool(atlas, tmp_path)
    p1 = tool(DIFF_ID, detail="rows", limit=7, offset=7)
    p2 = tool(DIFF_ID, detail="rows", limit=7, offset=7)
    assert json.dumps(p1, sort_keys=True) == json.dumps(p2, sort_keys=True)
    walked = _walk(tool, 7)
    assert [_key(r) for r in walked] == sorted(_key(r) for r in computed)


def test_filters_narrow_summary_not_coverage(atlas: sqlite3.Connection, tmp_path: Path) -> None:
    tool = _tool(atlas, tmp_path)
    full = tool(DIFF_ID)
    narrow = tool(DIFF_ID, presence="persisted")
    assert 0 < narrow["summary"]["total_rows"] < full["summary"]["total_rows"]
    assert narrow["summary"]["by_presence"] == {"persisted": narrow["summary"]["total_rows"]}
    assert narrow["coverage"] == full["coverage"]


def test_reason_filter(atlas: sqlite3.Connection, tmp_path: Path) -> None:
    """MUTATION (verified RED): ignore ``reason`` (``filter_by_reason`` returns every row) -> other
    reasons leak into the page."""
    tool = _tool(atlas, tmp_path)
    page = tool(DIFF_ID, detail="rows", limit=2000, reason="present_different_callee")
    assert page["total_rows"] == len(page["rows"]) > 0
    assert {r["presence_reason"] for r in page["rows"]} == {"present_different_callee"}
    summ = tool(DIFF_ID, reason="present_different_callee")["summary"]
    assert list(summ["by_presence_reason"]) == ["presence_undetermined|present_different_callee"]


def test_detail_and_limit_validation(atlas: sqlite3.Connection, tmp_path: Path) -> None:
    """Bad paging arguments are an answer (an ``error``), never an exception."""
    tool = _tool(atlas, tmp_path)
    for bad in (
        {"detail": "everything"},
        {"detail": "rows", "limit": 0},
        {"detail": "rows", "limit": 2001},
        {"detail": "rows", "offset": -1},
    ):
        out = tool(DIFF_ID, **bad)
        assert "error" in out and "rows" not in out, bad
    assert "error" not in tool(DIFF_ID, detail="rows", limit=2000)
    assert "error" not in tool(DIFF_ID, detail="rows", limit=1, offset=10_000)


# ── no removed / added; logic-versioned baselines ────────────────────────────────────

# The run-pair summary of the fixture, keyed by SINK_OVERLAY_LOGIC_VERSION. When a logic change
# moves this summary, ADD a new version key with the new value and bump the constant — never edit
# an existing key's value (it records what that logic version computed).
_GOLDEN: dict[str, dict[str, object]] = {
    "2": {
        "total_rows": 13,
        "by_presence": {"persisted": 4, "presence_undetermined": 9},
        "by_presence_reason": {
            "persisted|-": 4,
            "presence_undetermined|alignment_low_confidence": 1,
            "presence_undetermined|counterpart_not_candidate": 1,
            "presence_undetermined|crossside_count_mismatch": 1,
            "presence_undetermined|function_unmatched": 2,
            "presence_undetermined|instruction_unmatched": 1,
            "presence_undetermined|no_counterpart_undetermined": 2,
            "presence_undetermined|present_different_callee": 1,
        },
        "by_key_granularity": {
            "callsite": 8,
            "degraded_out_of_body": 2,
            "function_fallback": 2,
            "wrapper": 1,
        },
        "by_sink_class": {"cmd": 9, "copy": 2, "format": 1, "path_sink": 1},
        "by_binary": {"libx": 13},
    },
    # logic 3 adds the wrapper_callsite tier; this fixture holds no call to a wrapper, so its
    # summary is unchanged (the wrapper tier is pinned by the wrapper tests below)
    "3": {
        "total_rows": 13,
        "by_presence": {"persisted": 4, "presence_undetermined": 9},
        "by_presence_reason": {
            "persisted|-": 4,
            "presence_undetermined|alignment_low_confidence": 1,
            "presence_undetermined|counterpart_not_candidate": 1,
            "presence_undetermined|crossside_count_mismatch": 1,
            "presence_undetermined|function_unmatched": 2,
            "presence_undetermined|instruction_unmatched": 1,
            "presence_undetermined|no_counterpart_undetermined": 2,
            "presence_undetermined|present_different_callee": 1,
        },
        "by_key_granularity": {
            "callsite": 8,
            "degraded_out_of_body": 2,
            "function_fallback": 2,
            "wrapper": 1,
        },
        "by_sink_class": {"cmd": 9, "copy": 2, "format": 1, "path_sink": 1},
        "by_binary": {"libx": 13},
    },
    # logic 4: the call-site facts; recorded on the base fixture + _golden_v4 (wrapper calls and
    # facts), so it also pins the wrapper_callsite tier and the side split
    "4": {
        "total_rows": 19,
        "by_presence": {"persisted": 5, "presence_undetermined": 14},
        "by_presence_reason": {
            "persisted|-": 5,
            "presence_undetermined|alignment_low_confidence": 1,
            "presence_undetermined|callee_unreadable": 1,
            "presence_undetermined|counterpart_different_callee": 1,
            "presence_undetermined|counterpart_no_call_fact": 1,
            "presence_undetermined|counterpart_same_callee": 2,
            "presence_undetermined|crossside_count_mismatch": 1,
            "presence_undetermined|function_unmatched": 2,
            "presence_undetermined|instruction_unmatched": 1,
            "presence_undetermined|no_counterpart_undetermined": 2,
            "presence_undetermined|present_different_callee": 2,
        },
        "by_presence_reason_side": {
            "persisted|-|both": 5,
            "presence_undetermined|alignment_low_confidence|a_only": 1,
            "presence_undetermined|callee_unreadable|both": 1,
            "presence_undetermined|counterpart_different_callee|a_only"
            "|same_callee_candidate_elsewhere=false": 1,
            "presence_undetermined|counterpart_no_call_fact|b_only": 1,
            "presence_undetermined|counterpart_same_callee|a_only": 2,
            "presence_undetermined|crossside_count_mismatch|both": 1,
            "presence_undetermined|function_unmatched|a_only": 1,
            "presence_undetermined|function_unmatched|b_only": 1,
            "presence_undetermined|instruction_unmatched|a_only": 1,
            "presence_undetermined|no_counterpart_undetermined|a_only": 2,
            "presence_undetermined|present_different_callee|both": 2,
        },
        "by_key_granularity": {
            "callsite": 10,
            "degraded_out_of_body": 2,
            "function_fallback": 2,
            "wrapper": 1,
            "wrapper_callsite": 4,
        },
        "by_sink_class": {"cmd": 15, "copy": 2, "format": 1, "path_sink": 1},
        "by_binary": {"libx": 19},
    },
}


def test_golden_summary_matches_logic_version(atlas: sqlite3.Connection) -> None:
    """From logic "4" on, the golden fixture adds wrapper calls (same W, another W, an unaligned W)
    and call-site facts (``_golden_v4``) to the base fixture "2"/"3" were recorded on."""
    _golden_v4(atlas)
    rows = so.compute_sink_overlay_runs(atlas, "runA", "runB").rows
    summary = so.summarize_overlay(rows, by_binary=True)
    assert summary == _GOLDEN[so.SINK_OVERLAY_LOGIC_VERSION]
    assert "wrapper_callsite" in summary["by_key_granularity"]


def test_candidates_only_reading_reproduces_logic_3(atlas: sqlite3.Connection) -> None:
    """The candidates-only reading of the base fixture is still exactly what logic "3" recorded."""
    rows = so.compute_sink_overlay_runs(
        atlas, "runA", "runB", callee_backend="atlas_candidates"
    ).rows
    summary = so.summarize_overlay(rows, by_binary=True)
    assert {k: summary[k] for k in _GOLDEN["3"]} == _GOLDEN["3"]


def test_degraded_key_in_unmatched_function_is_function_unmatched(
    atlas: sqlite3.Connection,
) -> None:
    """The degraded key row has its own entry into the unmatched-function verdict.

    MUTATION (verified RED): in ``_key_row`` replace the ``_function_unmatched`` call with the old
    ``("removed", None)`` -> this key reads removed."""
    _fpres(atlas, "a", "00015000", "unmatched_analysis_complete")
    _inst(atlas, "runA", SHA_A, _ref("runA", "00015000", "copy"), "copy", _deg(None))
    res = so.compute_sink_overlay(atlas, DIFF_ID)
    r = _by(res.rows, a_off=":00015000@copy")
    assert r is not None and r.key_granularity == "degraded_out_of_body"
    assert r.presence == "presence_undetermined" and r.presence_reason == "function_unmatched"
    _assert_full_coverage(res)


def test_inlined_helper_is_not_removed(atlas: sqlite3.Connection) -> None:
    """An inlined helper: A's helper holds a cmd call and has no B counterpart, while its caller
    is aligned and B's caller now holds a call to the same sink. The helper's candidate is
    undetermined — the unmatched function is not evidence that the call went away.

    MUTATION (verified RED): make ``_function_unmatched`` return ``("removed", None)`` for an
    analysis-complete function -> the helper's candidate reads removed."""
    _fpres(atlas, "a", "00030000", "unmatched_analysis_complete")  # the helper
    helper = _ref("runA", "00030000", "cmd", "0x000010")
    _inst(atlas, "runA", SHA_A, helper, "cmd", sink="system")
    _falign(atlas, "00031000", "00041000", 0.95, "aligned")  # the caller pair
    _inst(atlas, "runB", SHA_B, _ref("runB", "00041000", "cmd", "0x000010"), "cmd", sink="system")
    r = _by(_rows(atlas), a_off=helper)
    assert r is not None and r.presence == "presence_undetermined"
    assert r.presence_reason == "function_unmatched" and r.b_ref is None


def test_no_row_is_ever_added_or_removed(atlas: sqlite3.Connection) -> None:
    _fold_scenario(atlas)
    _inst(atlas, "runA", "c" * 64, "runA#cafecafe:00001000@cmd@0x000010", "cmd", path="/x/liby")
    single = so.compute_sink_overlay(atlas, DIFF_ID).rows
    pair = so.compute_sink_overlay_runs(atlas, "runA", "runB").rows
    assert single and pair
    assert {r.presence for r in single + pair} <= {"persisted", "presence_undetermined"}


@pytest.mark.parametrize("bad", ["removed", "added"])
def test_presence_filter_rejects_states_never_emitted(atlas: sqlite3.Connection, bad: str) -> None:
    """A filter the layer can never satisfy is an error, not an empty answer that reads as "none".

    MUTATION (verified RED): make ``_check_presence_filter`` a no-op -> empty lists, no error."""
    with pytest.raises(ValueError, match="function_unmatched"):
        so.compute_sink_overlay(atlas, DIFF_ID, presence=bad)
    with pytest.raises(ValueError, match="function_unmatched"):
        so.compute_sink_overlay_runs(atlas, "runA", "runB", presence=bad)


def test_persist_stamps_logic_version(atlas: sqlite3.Connection) -> None:
    """MUTATION (verified RED): drop ``overlay_version=`` from ``persist_sink_overlay`` -> NULL."""
    n = so.persist_sink_overlay(atlas, DIFF_ID)
    versions = atlas.execute(
        "SELECT overlay_version FROM dimension_delta WHERE subject_kind = 'candidate'"
    ).fetchall()
    assert len(versions) == n > 0
    assert {v[0] for v in versions} == {so.SINK_OVERLAY_LOGIC_VERSION}


@pytest.mark.parametrize("stored", ["1", "3", None])
def test_baseline_from_other_logic_is_stale(atlas: sqlite3.Connection, stored: str | None) -> None:
    """A baseline written by other overlay logic (or before the stamp existed: NULL) is stale.

    MUTATION (verified RED): drop the overlay_version comparison in
    ``read_sink_overlay_baseline`` -> rows are served."""
    so.persist_sink_overlay(atlas, DIFF_ID)
    assert so.read_sink_overlay_baseline(atlas, DIFF_ID)["stale_baseline"] is False
    atlas.execute(
        "UPDATE dimension_delta SET overlay_version = ? WHERE id = "
        "(SELECT MIN(id) FROM dimension_delta WHERE subject_kind = 'candidate')",
        (stored,),
    )
    out = so.read_sink_overlay_baseline(atlas, DIFF_ID)
    assert out["stale_baseline"] is True and out["rows"] is None
    assert out["mismatched_fields"] == ["overlay_version"]


# ── wrapper candidates lined up per call ──────────────────────────────────────────────────────


def _wflow(name: str | None, addr: str | None, deg: str | None = None, located: bool = True) -> str:
    """flow_evidence of a wrapper candidate: the wrapper hop, optionally a degraded call."""
    wrapper: dict[str, object] = {"wrapped_sink": "system"}
    if name is not None:
        wrapper["name"] = name
    if addr is not None:
        wrapper["addr"] = addr
    flow: dict[str, object] = {"flow_path": {"sink_via_wrapper": True, "wrapper": wrapper}}
    if not located:
        flow["callsite_located"] = False
        flow["anchor_degraded"] = "out_of_body"
        if deg is not None:
            flow["callsite_addr"] = deg
    return json.dumps(flow)


W_A, W_B = "00050000", "00060000"  # a thin wrapper's entry on each side


def _wrapper_pair(
    conn: sqlite3.Connection,
    *,
    a: tuple[str | None, str | None] = ("do_cmd", W_A),
    b: tuple[str | None, str | None] = ("do_cmd", W_B),
    b_sink: str = "system",
    align_w: bool = True,
) -> tuple[str, str]:
    """One call to a wrapper in F1 on each side, matched instruction-to-instruction at +0x90."""
    if align_w:
        _falign(conn, W_A, W_B, 0.95, "aligned")
    a_ref = _ref("runA", "00001000", "cmd_via_wrapper", "0x000090")
    b_ref = _ref("runB", "00002000", "cmd_via_wrapper", "0x000090")
    _inst(conn, "runA", SHA_A, a_ref, "cmd", _wflow(*a), sink="system")
    _inst(conn, "runB", SHA_B, b_ref, "cmd", _wflow(*b), sink=b_sink)
    _imatch(conn, "00001090", "00002090", "00001000")
    return a_ref, b_ref


def test_wrapper_call_with_aligned_wrapper_persists(atlas: sqlite3.Connection) -> None:
    """MUTATION (verified RED): leave wrapper_callsite out of ``t1_at`` in ``_index`` -> the B call
    is not found at the matched address."""
    a_ref, b_ref = _wrapper_pair(atlas)
    res = so.compute_sink_overlay(atlas, DIFF_ID)
    r = _by(res.rows, a_off=a_ref)
    assert r is not None and r.key_granularity == "wrapper_callsite"
    assert r.presence == "persisted" and r.b_ref == b_ref and r.match_basis == "instruction"
    _assert_full_coverage(res)


def test_wrapper_identity_is_its_aligned_address_not_its_name(atlas: sqlite3.Connection) -> None:
    """Two stripped wrappers named after their own (different) addresses are the same function when
    the alignment pairs them; the names would have said otherwise.

    MUTATION (verified RED): compare ``callee_name`` before the address in ``_same_callee`` -> the
    differing ``FUN_`` names read as a different callee."""
    a_ref, _ = _wrapper_pair(atlas, a=(f"FUN_{W_A}", W_A), b=(f"FUN_{W_B}", W_B))
    r = _by(_rows(atlas), a_off=a_ref)
    assert r is not None and r.presence == "persisted"


def test_wrapper_without_alignment_is_unreadable(atlas: sqlite3.Connection) -> None:
    a_ref, _ = _wrapper_pair(atlas, align_w=False)
    r = _by(_rows(atlas), a_off=a_ref)
    assert r is not None and r.presence_reason == "callee_unreadable"


def test_wrapper_aligned_elsewhere_is_a_different_callee(atlas: sqlite3.Connection) -> None:
    """A's wrapper aligns to some OTHER B function than the one B's call reaches.

    MUTATION (verified RED): treat any aligned wrapper address as the same callee (return True
    whenever an alignment exists) -> persisted."""
    a_ref, _ = _wrapper_pair(atlas, b=("do_cmd", "00080000"))
    r = _by(_rows(atlas), a_off=a_ref)
    assert r is not None and r.presence_reason == "present_different_callee"
    assert r.counterpart_call == "present_different_callee"


def test_same_wrapper_forwarding_to_another_sink_is_a_different_callee(
    atlas: sqlite3.Connection,
) -> None:
    """MUTATION (verified RED): drop the wrapped-sink comparison for wrappers in
    ``_same_callee`` -> the same aligned W reads persisted."""
    a_ref, _ = _wrapper_pair(atlas, b_sink="popen")
    r = _by(_rows(atlas), a_off=a_ref)
    assert r is not None and r.presence_reason == "present_different_callee"


def test_wrapper_against_direct_sink_is_a_different_callee(atlas: sqlite3.Connection) -> None:
    """A wrapper call matched to a direct call of the same sink (the wrapper was inlined, or
    introduced) is a different callee, in either orientation.

    MUTATION (verified RED): drop the type check in ``_same_callee`` -> the direct-vs-wrapper
    orientation compares sink names only and reads persisted."""
    _falign(atlas, W_A, W_B, 0.95, "aligned")
    inl_a = _ref("runA", "00001000", "cmd_via_wrapper", "0x0000a0")
    _inst(atlas, "runA", SHA_A, inl_a, "cmd", _wflow("do_cmd", W_A), sink="system")
    _inst(atlas, "runB", SHA_B, _ref("runB", "00002000", "cmd", "0x0000a0"), "cmd", sink="system")
    _imatch(atlas, "000010a0", "000020a0", "00001000")
    intro_a = _ref("runA", "00001000", "cmd", "0x0000b0")
    _inst(atlas, "runA", SHA_A, intro_a, "cmd", sink="system")
    wb = _ref("runB", "00002000", "cmd_via_wrapper", "0x0000b0")
    _inst(atlas, "runB", SHA_B, wb, "cmd", _wflow("do_cmd", W_B), sink="system")
    _imatch(atlas, "000010b0", "000020b0", "00001000")
    rows = _rows(atlas)
    for ref in (inl_a, intro_a):
        r = _by(rows, a_off=ref)
        assert r is not None and r.presence_reason == "present_different_callee", ref


def test_wrapper_with_no_recorded_callee_is_unreadable(atlas: sqlite3.Connection) -> None:
    a_ref, _ = _wrapper_pair(atlas, a=(None, None))
    r = _by(_rows(atlas), a_off=a_ref)
    assert r is not None and r.presence_reason == "callee_unreadable"


def test_wrapper_names_decide_only_when_no_address_is_recorded(atlas: sqlite3.Connection) -> None:
    """An older hunt recorded the wrapper's name only: same name, same sink -> persisted."""
    a_ref, _ = _wrapper_pair(atlas, a=("do_cmd", None), b=("do_cmd", None), align_w=False)
    r = _by(_rows(atlas), a_off=a_ref)
    assert r is not None and r.presence == "persisted"


def test_wrapper_and_direct_degraded_keys_stay_apart(atlas: sqlite3.Connection) -> None:
    """A degraded wrapper call and a degraded direct call of the same sink class in one function
    are different keys (the wrapper's key class is its axis).

    MUTATION (verified RED): key ``_degraded_keys`` by sink_class again -> one key of count 2."""
    _inst(atlas, "runA", SHA_A, _ref("runA", "0000b000", "cmd"), "cmd", DEG)
    _inst(
        atlas,
        "runA",
        SHA_A,
        _ref("runA", "0000b000", "cmd_via_wrapper"),
        "cmd",
        _wflow("do_cmd", W_A, located=False),
    )
    res = so.compute_sink_overlay(atlas, DIFF_ID)
    keys = sorted(
        (r.a_ref or "", r.a_n)
        for r in res.rows
        if r.key_granularity == "degraded_out_of_body" and r.sink_class == "cmd"
    )
    assert keys == [
        (_ref("runA", "0000b000", "cmd"), 1),
        (_ref("runA", "0000b000", "cmd_via_wrapper"), 1),
    ]
    _assert_full_coverage(res)


def test_degraded_wrapper_call_folds_into_the_wrapper_callsite(atlas: sqlite3.Connection) -> None:
    """A degraded wrapper candidate whose recovered call address is a wrapper_callsite on the same
    side folds into that row, and every candidate stays represented."""
    a_ref, _ = _wrapper_pair(atlas)
    _falign(atlas, "00016000", "00026000", 0.95, "aligned")
    deg = _ref("runA", "00016000", "cmd_via_wrapper")
    _inst(atlas, "runA", SHA_A, deg, "cmd", _wflow("do_cmd", W_A, deg="0x1090", located=False))
    res = so.compute_sink_overlay(atlas, DIFF_ID)
    r = _by(res.rows, a_off=a_ref)
    assert r is not None and r.coclaimed_by == ["00016000"]
    assert not [x for x in res.rows if x.a_ref == deg]
    _assert_full_coverage(res)


def test_layer0_collects_wrapper_call_addresses(tmp_path: Path) -> None:
    """MUTATION (verified RED): drop the ``wrapper_call_abs_addr`` fallback in
    ``_candidate_callsite_addrs`` -> the wrapper call's instruction pair is not kept."""
    from treasure_map.lib.diff.layer0 import _candidate_callsite_addrs

    atlas = open_atlas(tmp_path / "atlas.db")
    _inst(atlas, "runA", SHA_A, _ref("runA", "00001000", "cmd_via_wrapper", "0x000090"), "cmd")
    _inst(atlas, "runA", SHA_A, _ref("runA", "00001000", "cmd", "0x000010"), "cmd")
    assert _candidate_callsite_addrs(atlas, "runA", SHA_A) == {"00001090", "00001010"}


# ── matched to a non-candidate instruction: the call-site facts ─────────────────────────────


def _fj(*callees: tuple[str, str | None, str], targets: list[str] | None = None) -> str:
    """A call-site facts JSON: ``(name, addr, kind)`` identities + the BinExport targets."""
    return json.dumps(
        {"callees": [{"name": n, "addr": a, "kind": k} for n, a, k in callees], "targets": targets}
    )


def _facts_meta(
    conn: sqlite3.Connection,
    *,
    state: str | None = "read",
    hash_: str = "feedface",
    stub: str = "not_applicable",
) -> None:
    """Both sides' call-site facts state on the diff (the fixture runs' build_hash is feedface)."""
    conn.execute(
        "UPDATE diff_meta SET callsite_facts_a = ?, callsite_facts_b = ?, "
        "callsite_facts_hash_a = ?, callsite_facts_hash_b = ?, stub_state_a = ?, stub_state_b = ? "
        "WHERE diff_id = ?",
        (state, state, hash_, hash_, stub, stub, DIFF_ID),
    )


def _aplus(
    conn: sqlite3.Connection,
    direction: str,
    facts: str | None,
    *,
    sink: str = "system",
    flow: str | None = None,
    sink_class: str = "cmd",
    offset: str = "0x000070",
) -> str:
    """One candidate on side ``direction`` in F1, matched to an instruction on the OTHER side that
    holds no candidate, whose call-site facts are ``facts``. Returns the candidate's ref."""
    off = int(offset, 16)
    addr_a, addr_b = f"{0x1000 + off:08x}", f"{0x2000 + off:08x}"
    suffix = "cmd_via_wrapper" if flow else sink_class
    if direction == "a":
        ref = _ref("runA", "00001000", suffix, offset)
        _inst(conn, "runA", SHA_A, ref, sink_class, flow, sink=sink)
        fa, fb = None, facts
    else:
        ref = _ref("runB", "00002000", suffix, offset)
        _inst(conn, "runB", SHA_B, ref, sink_class, flow, sink=sink)
        fa, fb = facts, None
    conn.execute(
        "INSERT INTO instruction_match (diff_id, func_addr_a, addr_a, addr_b, facts_a, facts_b) "
        "VALUES (?, '00001000', ?, ?, ?, ?)",
        (DIFF_ID, addr_a, addr_b, fa, fb),
    )
    return ref


def _row_of(conn: sqlite3.Connection, ref: str, **kw: object) -> so.SinkOverlayRow:
    rows = [r for r in _rows(conn, **kw) if ref in (r.a_ref, r.b_ref)]
    assert len(rows) == 1, rows
    return rows[0]


_DIRECT_CASES = [
    # (callees, state, hash, stub_state, reason, counterpart_call)
    ([("system", None, "name_only")], "not_read", "feedface", "not_applicable",
     "counterpart_call_facts_absent", "unknown"),
    ([("system", None, "name_only")], "bridge_absent", "feedface", "not_applicable",
     "counterpart_call_facts_absent", "unknown"),
    ([("system", None, "name_only")], "read", "facade", "not_applicable",
     "counterpart_facts_stale", "unknown"),
    ([], "read", "feedface", "not_applicable", "counterpart_no_call_fact", "unknown"),
    ([("system", None, "name_only"), ("popen", None, "name_only")], "read", "feedface",
     "not_applicable", "counterpart_call_ambiguous", "unknown"),
    ([("FUN_00000400", "00000400", "stub_unresolved")], "read", "feedface", "read",
     "counterpart_callee_unresolved", "unknown"),
    ([("FUN_00000400", "00000400", "fun_name_parsed")], "read", "feedface", "not_determined",
     "counterpart_callee_unresolved", "unknown"),
    ([("FUN_00000400", "00000400", "fun_name_parsed")], "read", "feedface", "read",
     "counterpart_different_callee", "present_different_callee"),
    ([("system", "00000400", "stub_resolved")], "read", "feedface", "read",
     "counterpart_same_callee", "present_same_callee"),
    ([("__system_chk", None, "name_only")], "read", "feedface", "not_applicable",
     "counterpart_different_callee", "present_different_callee"),
]  # fmt: skip


@pytest.mark.parametrize("direction", ["a", "b"])
@pytest.mark.parametrize(("callees", "state", "hash_", "stub", "reason", "call"), _DIRECT_CASES)
def test_facts_reading_for_a_direct_sink(
    atlas: sqlite3.Connection,
    direction: str,
    callees: list[tuple[str, str | None, str]],
    state: str,
    hash_: str,
    stub: str,
    reason: str,
    call: str,
) -> None:
    """The seven outcomes, both directions, for a direct sink compared by exact name — an
    unresolved stub, or a ``FUN_<hex>`` name where the stub table was never determined, is unknown
    rather than "different".

    MUTATION (verified RED): drop the stub_unresolved / not_determined guards in
    ``_fact_same_callee`` -> those two cases read counterpart_different_callee."""
    _facts_meta(atlas, state=state, hash_=hash_, stub=stub)
    ref = _aplus(atlas, direction, _fj(*callees))
    r = _row_of(atlas, ref)
    assert (r.presence, r.presence_reason, r.counterpart_call) == (
        "presence_undetermined",
        reason,
        call,
    )
    assert r.match_basis == "instruction"
    assert (r.b_ref if direction == "a" else r.a_ref) is None  # the other side names no candidate
    if reason in ("counterpart_same_callee", "counterpart_different_callee"):
        assert r.counterpart_callee is not None
        assert r.counterpart_callee["callees"][0]["name"] == callees[0][0]
        assert ("same_callee_candidate_elsewhere" in r.counterpart_callee) == (
            reason == "counterpart_different_callee"
        )
    else:
        assert r.counterpart_callee is None


def test_facts_column_missing_for_a_pair_is_absent(atlas: sqlite3.Connection) -> None:
    _facts_meta(atlas)
    ref = _aplus(atlas, "a", None)
    assert _row_of(atlas, ref).presence_reason == "counterpart_call_facts_absent"


def test_fortified_variant_is_a_different_callee(atlas: sqlite3.Connection) -> None:
    _facts_meta(atlas)
    ref = _aplus(
        atlas, "a", _fj(("__strcpy_chk", None, "name_only")), sink="strcpy", sink_class="copy"
    )
    assert _row_of(atlas, ref).presence_reason == "counterpart_different_callee"


@pytest.mark.parametrize(
    ("facts", "align_w", "cand_addr", "reason"),
    [
        (_fj(("do_cmd", W_B, "table_entry")), True, W_A, "counterpart_same_callee"),
        (_fj(("other", "00080000", "table_entry")), True, W_A, "counterpart_different_callee"),
        (_fj(("do_cmd", W_B, "table_entry")), False, W_A, "counterpart_callee_unresolved"),
        # the BinExport target disagrees with the derived address: no address, unknown
        (_fj(("do_cmd", W_B, "table_entry"), targets=["00090000"]), True, W_A,
         "counterpart_callee_unresolved"),
        # no derived address, but one BinExport target: compared by the target
        (_fj(("do_cmd", None, "name_ambiguous"), targets=[W_B]), True, W_A,
         "counterpart_same_callee"),
        # the candidate's own W has no address: never compared by name
        (_fj(("do_cmd", W_B, "table_entry")), True, None, "counterpart_callee_unresolved"),
    ],
)  # fmt: skip
def test_facts_reading_for_a_wrapper_call(
    atlas: sqlite3.Connection,
    facts: str,
    align_w: bool,
    cand_addr: str | None,
    reason: str,
) -> None:
    """A wrapper call compares ``W`` by entry address through the function alignment: the address
    the facts derived, or the one BinExport target when nothing was derived — and a disagreement
    between the two is unknown, never settled for either.

    MUTATION (verified RED): settle an X/Z conflict in favour of the BinExport target in
    ``_merge_addr`` -> the conflicting case reads counterpart_different_callee."""
    _facts_meta(atlas)
    if align_w:
        _falign(atlas, W_A, W_B, 0.95, "aligned")
    ref = _aplus(atlas, "a", facts, flow=_wflow("do_cmd", cand_addr))
    r = _row_of(atlas, ref)
    assert r.key_granularity == "wrapper_callsite"
    assert r.presence == "presence_undetermined" and r.presence_reason == reason


def test_merge_addr_table() -> None:
    assert so._merge_addr("00001000", None) == ("00001000", "x")
    assert so._merge_addr("00001000", []) == ("00001000", "x")
    assert so._merge_addr(None, None) == (None, None)
    assert so._merge_addr(None, ["00002000"]) == ("00002000", "binexport")
    assert so._merge_addr("00002000", ["00002000"]) == ("00002000", "both")
    assert so._merge_addr("00001000", ["00002000"]) == (None, "conflict")
    assert so._merge_addr("00001000", ["00002000", "00003000"]) == (None, "binexport_ambiguous")


def test_a_direct_sink_is_compared_by_name_whatever_binexport_says(
    atlas: sqlite3.Connection,
) -> None:
    _facts_meta(atlas)
    ref = _aplus(atlas, "a", _fj(("system", "00000400", "table_entry"), targets=["00099999"]))
    assert _row_of(atlas, ref).presence_reason == "counterpart_same_callee"


def test_stale_facts_never_touch_a_persisted_row(atlas: sqlite3.Connection) -> None:
    """Facts read from an older extraction are stale for the rows they would decide; a row decided
    by candidates is unaffected.

    MUTATION (verified RED): ignore the stamp in ``_facts_stale`` (always fresh) -> the stale row
    reads counterpart_same_callee."""
    _facts_meta(atlas, hash_="facade")
    ref = _aplus(atlas, "a", _fj(("system", None, "name_only")))
    assert _row_of(atlas, ref).presence_reason == "counterpart_facts_stale"
    persisted = _by(_rows(atlas), a_off="@0x000010")
    assert persisted is not None and persisted.presence == "persisted"
    _facts_meta(atlas)
    assert _row_of(atlas, ref).presence_reason == "counterpart_same_callee"


def test_mixed_wrapper_addresses_are_unreadable(atlas: sqlite3.Connection) -> None:
    """One side's W is pinned by address and the other's is not: the names cannot decide it.

    MUTATION (verified RED): drop the mixed-address branch in ``_same_callee`` -> the equal names
    read persisted."""
    a_ref, _ = _wrapper_pair(atlas, a=("do_cmd", W_A), b=("do_cmd", None))
    r = _by(_rows(atlas), a_off=a_ref)
    assert r is not None and r.presence_reason == "callee_unreadable"


def test_different_callee_says_whether_the_callee_is_still_elsewhere(
    atlas: sqlite3.Connection,
) -> None:
    """``same_callee_candidate_elsewhere``: True when the paired function still holds a candidate
    with this callee, False when it holds none, None when a candidate there is unreadable; the
    summary splits the different-callee rows by it.

    MUTATION (verified RED): always answer False in ``_same_callee_elsewhere``."""
    _facts_meta(atlas)
    # F1's B function holds a cmd candidate (sink "cmd") but no "system" one
    still = _aplus(atlas, "a", _fj(("popen", None, "name_only")), sink="cmd", offset="0x000070")
    gone = _aplus(atlas, "a", _fj(("popen", None, "name_only")), sink="system", offset="0x000074")
    rows = _rows(atlas)
    by = {r.a_ref: r for r in rows}
    assert by[still].counterpart_callee["same_callee_candidate_elsewhere"] is True  # type: ignore[index]
    assert by[gone].counterpart_callee["same_callee_candidate_elsewhere"] is False  # type: ignore[index]
    # the original different-callee row carries it too
    orig = _by(rows, a_off="@0x000020")
    assert orig is not None and orig.presence_reason == "present_different_callee"
    assert orig.counterpart_callee is not None
    assert (
        orig.counterpart_callee["same_callee_candidate_elsewhere"] is True
    )  # B still has cmd@0x10
    s = so.summarize_overlay(rows, by_binary=False)["by_presence_reason_side"]
    assert (
        s[
            "presence_undetermined|counterpart_different_callee|a_only|same_callee_candidate_elsewhere=true"
        ]
        == 1
    )
    assert (
        s[
            "presence_undetermined|counterpart_different_callee|a_only|same_callee_candidate_elsewhere=false"
        ]
        == 1
    )
    atlas.execute("UPDATE instance SET sink_anchor = NULL WHERE evidence_ref LIKE 'runB%@format@%'")
    unknown = {r.a_ref: r for r in _rows(atlas)}[gone]
    assert unknown.counterpart_callee["same_callee_candidate_elsewhere"] is None  # type: ignore[index]


def test_elsewhere_is_unknown_when_the_function_is_not_paired(atlas: sqlite3.Connection) -> None:
    cand = so._Cand(
        iid=1, ref="r", sink_class="cmd", sink="system", sha=None, binary_name=None,
        func_entry="00009999", tier="callsite", callsite_addr="00009990",
    )  # fmt: skip
    side = so._index([])
    d = so._Dir(
        side="a", this=side, other=side, align={}, presence={}, imatch={}, imatch_present=True,
        no_cand_reason="counterpart_not_candidate",
    )  # fmt: skip
    assert so._same_callee_elsewhere(cand, d) is None


def test_row_side_and_side_filter(atlas: sqlite3.Connection) -> None:
    """MUTATION (verified RED): read ``both`` as ``a_only`` in ``_row_side``."""
    base = dict(
        diff_id=None, binary=None, sink_class="cmd", key_granularity="callsite",
        presence="presence_undetermined", presence_reason="x", match_basis=None,
        counterpart_call=None, alignment_confidence=None,
    )  # fmt: skip
    rows = [
        so.SinkOverlayRow(a_ref="a", b_ref=None, **base),  # type: ignore[arg-type]
        so.SinkOverlayRow(a_ref=None, b_ref="b", **base),  # type: ignore[arg-type]
        so.SinkOverlayRow(a_ref="a", b_ref="b", **base),  # type: ignore[arg-type]
        so.SinkOverlayRow(a_ref=None, b_ref=None, **base),  # type: ignore[arg-type]
    ]
    assert [so._row_side(r) for r in rows] == ["a_only", "b_only", "both", "neither"]
    for side in ("a_only", "b_only", "both"):
        assert len(so.filter_by_side(rows, side)) == 1
    with pytest.raises(ValueError):
        so.filter_by_side(rows, "neither")
    full = _rows(atlas)
    s = so.summarize_overlay(full, by_binary=False)["by_presence_reason_side"]
    for side in ("a_only", "b_only", "both"):
        assert sum(n for k, n in s.items() if k.split("|")[2] == side) == len(
            so.filter_by_side(full, side)
        )


def test_no_row_claims_not_a_call_and_facts_never_persist(atlas: sqlite3.Connection) -> None:
    _golden_v4(atlas)
    rows = so.compute_sink_overlay_runs(atlas, "runA", "runB").rows
    assert not [r for r in rows if r.counterpart_call in ("not_a_call", "absent")]
    assert not [
        r
        for r in rows
        if (r.presence_reason or "").startswith("counterpart_")
        and r.presence != "presence_undetermined"
    ]
    assert any((r.presence_reason or "").startswith("counterpart_") for r in rows)


def test_facts_only_refine_the_not_candidate_rows(atlas: sqlite3.Connection) -> None:
    """The two readings agree on every row except, at most, the reason / call / callee of the rows
    the candidates-only reading leaves as counterpart_not_candidate / a_counterpart_not_candidate.

    MUTATION (verified RED): make the facts reading also change a persisted row (judge every
    tier-1 row through the facts) -> rows outside that bucket differ."""
    _golden_v4(atlas)
    facts = so.compute_sink_overlay_runs(atlas, "runA", "runB")
    cands = so.compute_sink_overlay_runs(atlas, "runA", "runB", callee_backend="atlas_candidates")
    assert facts.coverage == cands.coverage

    def key(r: so.SinkOverlayRow) -> tuple:  # type: ignore[type-arg]
        return (r.diff_id, r.a_ref, r.b_ref, r.key_granularity, r.sink_class, r.binary)

    fmap, cmap = {key(r): r for r in facts.rows}, {key(r): r for r in cands.rows}
    assert fmap.keys() == cmap.keys() and len(fmap) == len(facts.rows)
    refined = 0
    for k, c in cmap.items():
        f = fmap[k]
        same = ("presence", "match_basis", "alignment_confidence", "coclaimed_by",
                "coclaimed_by_b", "a_n", "b_n")  # fmt: skip
        assert all(getattr(f, n) == getattr(c, n) for n in same), k
        if c.presence_reason in ("counterpart_not_candidate", "a_counterpart_not_candidate"):
            refined += 1
            continue
        assert (f.presence_reason, f.counterpart_call, f.counterpart_callee) == (
            c.presence_reason,
            c.counterpart_call,
            c.counterpart_callee,
        ), k
    assert refined > 0


def test_persist_writes_the_counterpart_callee(atlas: sqlite3.Connection) -> None:
    _facts_meta(atlas)
    _aplus(atlas, "a", _fj(("popen", None, "name_only")))
    so.persist_sink_overlay(atlas, DIFF_ID)
    raw = [
        r[0]
        for r in atlas.execute(
            "SELECT counterpart_callee FROM dimension_delta WHERE subject_kind = 'candidate' "
            "AND undetermined_reason = 'counterpart_different_callee'"
        )
    ]
    assert raw and all(v is not None for v in raw), raw
    stored = [json.loads(v) for v in raw]
    assert stored and stored[0]["callees"][0]["name"] == "popen"
    versions = {r[0] for r in atlas.execute("SELECT overlay_version FROM dimension_delta")}
    assert versions == {"4"}


def _golden_v4(conn: sqlite3.Connection) -> None:
    """The base fixture plus wrapper calls and call-site facts: a same W, another W, an unaligned
    W, a wrapper and a direct sink judged by facts (same / different), and a B-side candidate whose
    matched A instruction records no call."""
    _facts_meta(conn)
    conn.execute(
        "UPDATE instruction_match SET facts_b = ? WHERE diff_id = ? AND addr_a = '00001030'",
        (_fj(("cmd", None, "name_only")), DIFF_ID),
    )
    _falign(conn, W_A, W_B, 0.95, "aligned")
    for off, wa, wb in (("0x000090", W_A, W_B), ("0x0000a0", W_A, "00080000"),
                        ("0x0000b0", "00070000", W_B)):  # fmt: skip
        _inst(conn, "runA", SHA_A, _ref("runA", "00001000", "cmd_via_wrapper", off), "cmd",
              _wflow("do_cmd", wa), sink="system")  # fmt: skip
        _inst(conn, "runB", SHA_B, _ref("runB", "00002000", "cmd_via_wrapper", off), "cmd",
              _wflow("do_cmd", wb), sink="system")  # fmt: skip
        o = int(off, 16)
        _imatch(conn, f"{0x1000 + o:08x}", f"{0x2000 + o:08x}", "00001000")
    _aplus(conn, "a", _fj(("do_cmd", W_B, "table_entry")), flow=_wflow("do_cmd", W_A),
           offset="0x0000c0")  # fmt: skip
    _aplus(conn, "a", _fj(("popen", None, "name_only")), offset="0x0000d0")
    _aplus(conn, "b", _fj(), sink="cmd", offset="0x0000e0")
