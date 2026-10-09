"""C7 candidate-level sink overlay (lib/query/sink_overlay).

Zero real data: every ref / run / binary name here is synthetic placeholder hex. Exercises the
atlas+BinDiff backend's honest four-state engine across every presence path.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.query import sink_overlay as so

SHA_A = "a" * 64
SHA_B = "b" * 64
DIFF_ID = "runA::runB::libx"
BANCHOR = "deadbeef"  # synthetic binary-content-hash prefix used in the ref


def _ref(run: str, func_entry: str, sink: str, offset: str | None = None) -> str:
    """Synthetic evidence_ref in the real shape: {run}#{banchor}:{func_entry}@{sink}[@{offset}]."""
    tail = f"{sink}@{offset}" if offset is not None else sink
    return f"{run}#{BANCHOR}:{func_entry}@{tail}"


@pytest.fixture
def atlas(tmp_path: Path) -> sqlite3.Connection:
    conn = open_atlas(tmp_path / "atlas.db")
    pat: dict[str, int] = {}

    def pattern(sink_class: str) -> int:
        if sink_class not in pat:
            cur = conn.execute(
                "INSERT INTO pattern (source_class, sink_class, call_sequence_shape, "
                "structural_fingerprint, fingerprint_algo_version) VALUES "
                "('external_input', ?, 'source->sink', ?, 'v1')",
                (sink_class, f"fp_{sink_class}"),
            )
            pat[sink_class] = cur.lastrowid
        return pat[sink_class]

    def inst(run: str, sha: str, ref: str, sink_class: str, flow: str | None = None) -> None:
        conn.execute(
            "INSERT INTO instance (pattern_id, evidence_ref, source_run_id, binary_content_hash, "
            "binary_path, sink_anchor, flow_evidence) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (pattern(sink_class), ref, run, sha, "/fw/sbin/libx", sink_class, flow),
        )

    def falign(fa: str, fb: str, conf: float, state: str) -> None:
        conn.execute(
            "INSERT INTO function_alignment (diff_id, addr_a, addr_b, alignment_confidence, "
            "alignment_state) VALUES (?, ?, ?, ?, ?)",
            (DIFF_ID, fa, fb, conf, state),
        )

    def fpres(side: str, addr: str, state: str) -> None:
        conn.execute(
            "INSERT INTO function_presence (diff_id, side, addr, presence_state) "
            "VALUES (?, ?, ?, ?)",
            (DIFF_ID, side, addr, state),
        )

    def imatch(aa: str, ab: str, fa: str) -> None:
        conn.execute(
            "INSERT INTO instruction_match (diff_id, func_addr_a, addr_a, addr_b) "
            "VALUES (?, ?, ?, ?)",
            (DIFF_ID, fa, aa, ab),
        )

    conn.execute(
        "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id, binary_a, binary_b, "
        "sha256_a, sha256_b, "
        "diff_ok, version_skew) VALUES (?, 'runA', 'runB', 'libx', 'libx', ?, ?, 1, 0)",
        (DIFF_ID, SHA_A, SHA_B),
    )

    # F1 aligned (0.97): four tier-1 callsites exercising the callee-verification outcomes.
    falign("00001000", "00002000", 0.97, "aligned")
    inst("runA", SHA_A, _ref("runA", "00001000", "cmd", "0x000010"), "cmd")  # -> persisted
    inst(
        "runA", SHA_A, _ref("runA", "00001000", "cmd", "0x000020"), "cmd"
    )  # -> present_different_callee
    inst(
        "runA", SHA_A, _ref("runA", "00001000", "cmd", "0x000030"), "cmd"
    )  # -> counterpart_not_candidate
    inst(
        "runA", SHA_A, _ref("runA", "00001000", "cmd", "0x000040"), "cmd"
    )  # -> callsite_not_exported
    imatch("00001010", "00002010", "00001000")
    imatch("00001020", "00002020", "00001000")
    imatch("00001030", "00002030", "00001000")  # 0x40 deliberately NOT matched
    inst("runB", SHA_B, _ref("runB", "00002000", "cmd", "0x000010"), "cmd")  # same sink @0x2010
    inst(
        "runB", SHA_B, _ref("runB", "00002000", "format", "0x000020"), "format"
    )  # diff sink @0x2020
    # 0x2030: no B candidate -> counterpart_not_candidate

    # F2 aligned LOW confidence -> alignment_low_confidence
    falign("00003000", "00004000", 0.50, "alignment_undetermined")
    inst("runA", SHA_A, _ref("runA", "00003000", "cmd", "0x000008"), "cmd")

    # F3 A-side unmatched, analysis complete -> removed
    fpres("a", "00005000", "unmatched_analysis_complete")
    inst("runA", SHA_A, _ref("runA", "00005000", "cmd", "0x000004"), "cmd")

    # F4 A-side unmatched, analysis INCOMPLETE -> undetermined (no_counterpart_undetermined)
    fpres("a", "00006000", "unmatched_analysis_incomplete")
    inst("runA", SHA_A, _ref("runA", "00006000", "cmd", "0x000004"), "cmd")

    # F5 aligned: tier-3 function_fallback (no offset). copy present both sides -> persisted;
    # a path_sink only on A -> no_counterpart_undetermined.
    falign("00007000", "00008000", 0.95, "aligned")
    inst("runA", SHA_A, _ref("runA", "00007000", "copy"), "copy")
    inst("runA", SHA_A, _ref("runA", "00007000", "path_sink"), "path_sink")
    inst("runB", SHA_B, _ref("runB", "00008000", "copy"), "copy")

    # F6 aligned: wrapper, present both sides -> persisted
    falign("00009000", "0000a000", 0.95, "aligned")
    inst("runA", SHA_A, _ref("runA", "00009000", "cmd_via_wrapper"), "cmd")
    inst("runB", SHA_B, _ref("runB", "0000a000", "cmd_via_wrapper"), "cmd")

    # F7 aligned: tier-2. (copy) A=2 B=2 -> persisted; (format) A=2 B=1 -> mismatch
    falign("0000b000", "0000c000", 0.95, "aligned")
    deg = '{"callsite_located": false, "anchor_degraded": "out_of_body"}'
    for _ in range(2):
        inst("runA", SHA_A, _ref("runA", "0000b000", "copy"), "copy", deg)
        inst("runB", SHA_B, _ref("runB", "0000c000", "copy"), "copy", deg)
    for _ in range(2):
        inst("runA", SHA_A, _ref("runA", "0000b000", "format"), "format", deg)
    inst("runB", SHA_B, _ref("runB", "0000c000", "format"), "format", deg)  # only 1 on B

    # F8 B-side unmatched complete -> added
    fpres("b", "0000d000", "unmatched_analysis_complete")
    inst("runB", SHA_B, _ref("runB", "0000d000", "cmd", "0x000004"), "cmd")

    conn.commit()
    return conn


def _by(rows: list[so.SinkOverlayRow], a_off: str | None = None, b_off: str | None = None):
    """Find a row by a distinctive offset in its a_ref/b_ref."""
    for r in rows:
        if a_off and r.a_ref and a_off in r.a_ref:
            return r
        if b_off and r.b_ref and b_off in r.b_ref:
            return r
    return None


def test_tier1_persisted_same_callee(atlas: sqlite3.Connection) -> None:
    rows = so.compute_sink_overlay(atlas, DIFF_ID)
    r = _by(rows, a_off="@0x000010")
    assert r is not None and r.presence == "persisted"
    assert r.match_basis == "instruction" and r.key_granularity == "callsite"
    assert r.b_ref is not None and r.presence_reason is None


def test_tier1_present_different_callee(atlas: sqlite3.Connection) -> None:
    r = _by(so.compute_sink_overlay(atlas, DIFF_ID), a_off="@0x000020")
    assert r is not None and r.presence == "presence_undetermined"
    assert r.presence_reason == "present_different_callee"
    assert r.counterpart_call == "present_different_callee" and r.b_ref is not None


def test_tier1_counterpart_not_candidate(atlas: sqlite3.Connection) -> None:
    r = _by(so.compute_sink_overlay(atlas, DIFF_ID), a_off="@0x000030")
    assert r is not None and r.presence == "presence_undetermined"
    assert r.presence_reason == "counterpart_not_candidate" and r.b_ref is None


def test_tier1_callsite_not_exported(atlas: sqlite3.Connection) -> None:
    r = _by(so.compute_sink_overlay(atlas, DIFF_ID), a_off="@0x000040")
    assert r is not None and r.presence == "presence_undetermined"
    assert r.presence_reason == "callsite_not_exported"


def test_alignment_low_confidence(atlas: sqlite3.Connection) -> None:
    r = _by(so.compute_sink_overlay(atlas, DIFF_ID), a_off=":00003000@")
    assert r is not None and r.presence == "presence_undetermined"
    assert r.presence_reason == "alignment_low_confidence"


def test_function_removed(atlas: sqlite3.Connection) -> None:
    r = _by(so.compute_sink_overlay(atlas, DIFF_ID), a_off=":00005000@")
    assert r is not None and r.presence == "removed" and r.match_basis == "function_level"


def test_function_unmatched_incomplete_undetermined(atlas: sqlite3.Connection) -> None:
    r = _by(so.compute_sink_overlay(atlas, DIFF_ID), a_off=":00006000@")
    assert r is not None and r.presence == "presence_undetermined"
    assert r.presence_reason == "no_counterpart_undetermined"


def test_tier3_persisted_and_undetermined(atlas: sqlite3.Connection) -> None:
    rows = so.compute_sink_overlay(atlas, DIFF_ID)
    cp = _by(rows, a_off=":00007000@copy")
    assert cp is not None and cp.presence == "persisted" and cp.match_basis == "function_level"
    ps = _by(rows, a_off=":00007000@path_sink")
    assert ps is not None and ps.presence == "presence_undetermined"


def test_wrapper_persisted(atlas: sqlite3.Connection) -> None:
    r = _by(so.compute_sink_overlay(atlas, DIFF_ID), a_off="cmd_via_wrapper")
    assert r is not None and r.presence == "persisted" and r.key_granularity == "wrapper"


def test_tier2_count_match_and_mismatch(atlas: sqlite3.Connection) -> None:
    rows = [
        r
        for r in so.compute_sink_overlay(atlas, DIFF_ID)
        if r.key_granularity == "degraded_out_of_body"
    ]
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
    r = _by(so.compute_sink_overlay(atlas, DIFF_ID), b_off=":0000d000@")
    assert r is not None and r.presence == "added" and r.a_ref is None and r.b_ref is not None


def test_never_collapses_to_unchanged(atlas: sqlite3.Connection) -> None:
    # Honesty: no row is 'unchanged'; every non-persisted/added/removed is undetermined.
    for r in so.compute_sink_overlay(atlas, DIFF_ID):
        assert r.presence in ("added", "removed", "persisted", "presence_undetermined")
        if r.presence == "presence_undetermined":
            assert r.presence_reason is not None  # always a machine-readable reason


def test_diff_failed_all_undetermined(atlas: sqlite3.Connection) -> None:
    atlas.execute("UPDATE diff_meta SET diff_ok = 0 WHERE diff_id = ?", (DIFF_ID,))
    rows = so.compute_sink_overlay(atlas, DIFF_ID)
    assert rows and all(
        r.presence == "presence_undetermined" and r.presence_reason == "diff_failed" for r in rows
    )


def test_missing_sha_all_undetermined(atlas: sqlite3.Connection) -> None:
    atlas.execute("UPDATE diff_meta SET sha256_a = NULL WHERE diff_id = ?", (DIFF_ID,))
    rows = so.compute_sink_overlay(atlas, DIFF_ID)
    assert rows and all(r.presence_reason == "diff_meta_missing_sha" for r in rows)


def test_filters(atlas: sqlite3.Connection) -> None:
    only_persisted = so.compute_sink_overlay(atlas, DIFF_ID, presence="persisted")
    assert only_persisted and all(r.presence == "persisted" for r in only_persisted)
    only_cmd = so.compute_sink_overlay(atlas, DIFF_ID, sink_class="cmd")
    assert only_cmd and all(r.sink_class == "cmd" for r in only_cmd)


def test_persist_roundtrip_and_idempotent(atlas: sqlite3.Connection) -> None:
    from treasure_map.lib.query import diff_align

    live = so.compute_sink_overlay(atlas, DIFF_ID)
    n1 = so.persist_sink_overlay(atlas, DIFF_ID)
    assert n1 == len(live)
    stored = atlas.execute(
        "SELECT presence, subject_kind, delta_kind, undetermined_reason FROM dimension_delta "
        "WHERE diff_id = ? AND subject_kind = 'candidate'",
        (DIFF_ID,),
    ).fetchall()
    assert len(stored) == len(live)
    # delta_kind projection is CHECK-safe and matches presence
    for presence, kind, dk, reason in stored:
        assert kind == "candidate"
        assert dk in ("layer_changed", "layer_unchanged", "delta_undetermined")
        if presence == "presence_undetermined":
            assert dk == "delta_undetermined" and reason is not None
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


def test_persist_instruction_matches(tmp_path: Path) -> None:
    """layer-0 instruction persistence: a synthetic .BinDiff (real BinDiff schema: function /
    basicblock / instruction, BIGINT-decimal addresses) + an atlas candidate -> an instruction_match
    row scoped to the candidate callsite, 1:1 on the A address."""
    from treasure_map.lib.diff.layer0 import persist_instruction_matches

    bindiff = tmp_path / "t.BinDiff"
    bd = sqlite3.connect(bindiff)
    bd.execute(
        "CREATE TABLE function (id INT, address1 BIGINT, name1 TEXT, address2 BIGINT, name2 TEXT)"
    )
    bd.execute("CREATE TABLE basicblock (id INT, functionid INT, address1 BIGINT, address2 BIGINT)")
    bd.execute("CREATE TABLE instruction (basicblockid INT, address1 BIGINT, address2 BIGINT)")
    bd.execute("INSERT INTO function VALUES (1, 4096, 'f', 8192, 'f')")  # 0x1000 <-> 0x2000
    bd.execute("INSERT INTO basicblock VALUES (1, 1, 4096, 4200)")
    # 0x1010(4112) <-> 0x2010(8208) is the candidate callsite; 0x1018 is noise (no candidate)
    bd.execute("INSERT INTO instruction VALUES (1, 4112, 8208)")
    bd.execute("INSERT INTO instruction VALUES (1, 4120, 8216)")
    bd.commit()
    bd.close()

    atlas = open_atlas(tmp_path / "atlas.db")
    atlas.execute(
        "INSERT INTO pattern (source_class, sink_class, call_sequence_shape, "
        "structural_fingerprint, "
        "fingerprint_algo_version) VALUES ('external_input','cmd','s->s','fp','v1')"
    )
    pid = atlas.execute("SELECT pattern_id FROM pattern").fetchone()[0]
    atlas.execute(
        "INSERT INTO instance (pattern_id, evidence_ref, source_run_id, binary_content_hash, "
        "sink_anchor) VALUES (?, ?, 'runA', ?, 'system')",
        (pid, _ref("runA", "00001000", "cmd", "0x000010"), SHA_A),
    )
    atlas.commit()

    n = persist_instruction_matches(
        atlas, bindiff_path=bindiff, diff_id=DIFF_ID, run_a_id="runA", sha_a=SHA_A, commit=True
    )
    assert n == 1
    row = atlas.execute(
        "SELECT func_addr_a, addr_a, addr_b FROM instruction_match WHERE diff_id = ?", (DIFF_ID,)
    ).fetchone()
    assert tuple(row) == ("00001000", "00001010", "00002010")
    # the non-candidate instruction (0x1018) was NOT stored (scoped to candidate callsites only)
    assert atlas.execute("SELECT COUNT(*) FROM instruction_match").fetchone()[0] == 1
