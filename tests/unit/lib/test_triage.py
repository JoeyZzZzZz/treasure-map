# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for lib/query/triage — the read-only review-ordering of atlas candidates.

Builds a synthetic atlas directly (no analyzer), then asserts the deterministic ranking,
the presentation-only relabel (raw schema field stays confirmed/blocked/unknown), the
gated fold in the CLI, the evidence_ref anchor on every row, and that triage writes nothing.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from click.testing import CliRunner

from treasure_map.cli.hunt_cli import triage as triage_cmd
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, upsert_pattern
from treasure_map.lib.query import review_score, triage

_FID = [0]


def _pattern(
    conn: sqlite3.Connection,
    fp: str,
    *,
    sink_class: str = "cmd",
    source_class: str = "external_input",
) -> int:
    return upsert_pattern(
        conn,
        source_class=source_class,
        sink_class=sink_class,
        call_sequence_shape="source->...->sink",
        structural_fingerprint=fp,
        fingerprint_algo_version="callseq-v1",
    )


def _inst(
    conn: sqlite3.Connection,
    pattern_id: int,
    *,
    status: str = "unknown",
    run_id: str = "run_1",
    origin: str = "unknown",
    blocking: str | None = None,
    fn: str = "fn",
    sink_anchor: str = "system",
    binary_path: str | None = None,
    entry_reach: str | None = None,
) -> None:
    _FID[0] += 1
    provenance = "L1" if status in {"confirmed", "blocked"} else "L0"
    # entry_reach (None -> no flow_evidence; else a minimal entry_reach.status payload).
    flow_evidence = None
    if entry_reach is not None:
        flow_evidence = json.dumps({"entry_reach": {"status": entry_reach, "sites": []}})
    add_instance(
        conn,
        InstanceRow(
            pattern_id=pattern_id,
            pseudocode_hash=f"h{_FID[0]}",
            source_anchor=fn,
            sink_anchor=sink_anchor,
            source_run_id=run_id,
            reachability_status=status,
            blocking_mechanism=blocking,
            provenance_level=provenance,
            evidence_ref=f"{run_id}#fn{_FID[0]}",
            scope_origin="intra",
            origin=origin,
            binary_path=binary_path,
            flow_evidence=flow_evidence,
        ),
    )


def _atlas(tmp_path: Path) -> sqlite3.Connection:
    return open_atlas(tmp_path / "atlas.db")


# ── ranking ───────────────────────────────────────────────────────────────────────


def test_strong_lead_ranks_above_weak_lead(tmp_path: Path) -> None:
    conn = _atlas(tmp_path)
    strong_p = _pattern(conn, "fp_strong", sink_class="cmd", source_class="external_input")
    weak_p = _pattern(conn, "fp_weak", sink_class="format", source_class="unknown")
    # strong: custom code, no filter, external input, cmd sink, unknown(=to-verify).
    _inst(conn, strong_p, status="unknown", origin="custom", blocking=None, fn="strong_fn")
    # weak: recognized stock OSS, a filter on the path, unclassified source, format sink.
    _inst(
        conn,
        weak_p,
        status="unknown",
        origin="stock_oss_known",
        blocking="length_check",
        fn="weak_fn",
    )

    ranked = triage(conn)
    assert [c.function for c in ranked] == ["strong_fn", "weak_fn"]
    assert ranked[0].score > ranked[1].score
    conn.close()


def test_confirmed_ranks_above_same_class_unknown(tmp_path: Path) -> None:
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp", sink_class="cmd", source_class="external_input")
    # identical fine signals; only the reachability tier differs.
    _inst(conn, p, status="unknown", origin="custom", fn="u_fn")
    _inst(conn, p, status="confirmed", origin="custom", fn="c_fn")

    ranked = triage(conn)
    assert [c.function for c in ranked] == ["c_fn", "u_fn"]  # reachable above to-verify
    conn.close()


# ── entry-reach ranking (v2 lever, factor 6b): proven promotes, unknown never demotes ──


def test_entry_reach_found_promotes_within_tier(tmp_path: Path) -> None:
    # Two same-class same-status candidates differing ONLY in entry-reach: the one with a proven
    # rootfs entry path (network/script-reachable) ranks above the local-only/unknown one.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp", sink_class="fmt_string", source_class="external_input")
    _inst(conn, p, status="unknown", fn="local_only", entry_reach="unknown")
    _inst(conn, p, status="unknown", fn="net_reachable", entry_reach="found")

    ranked = triage(conn)
    assert [c.function for c in ranked] == ["net_reachable", "local_only"]
    assert next(c for c in ranked if c.function == "net_reachable").entry_reach == "found"
    conn.close()


def test_entry_reach_does_not_reverse_sink_class_order(tmp_path: Path) -> None:
    # A proven-entry COPY must not overtake an unknown-entry CMD of the same status: entry-reach is
    # a SECOND-LEVEL key, smaller than the sink-class gap.
    conn = _atlas(tmp_path)
    cmd_p = _pattern(conn, "fp_cmd", sink_class="cmd", source_class="external_input")
    copy_p = _pattern(conn, "fp_copy", sink_class="copy", source_class="external_input")
    _inst(conn, cmd_p, status="unknown", fn="cmd_no_entry", entry_reach="unknown")
    _inst(conn, copy_p, status="unknown", fn="copy_found", entry_reach="found")

    ranked = triage(conn)
    assert [c.function for c in ranked] == ["cmd_no_entry", "copy_found"]
    conn.close()


def test_entry_reach_unknown_is_never_demoted(tmp_path: Path) -> None:
    # ★ prove-the-asymmetry: an external_input candidate with entry_reach=unknown must NOT score
    # below the same candidate scored WITHOUT any entry-reach lever (only ``found`` ever adds).
    base = review_score("unknown", None, "custom", "external_input", "cmd")
    as_unknown = review_score("unknown", None, "custom", "external_input", "cmd", "unknown")
    as_found = review_score("unknown", None, "custom", "external_input", "cmd", "found")
    assert as_unknown == base  # unknown is strictly neutral — no demotion
    assert as_found >= as_unknown  # found can only promote
    # the weight table itself carries no negative entry-reach contribution
    from treasure_map.lib.query.triage import _ENTRY_REACH_WEIGHT

    assert all(w >= 0.0 for w in _ENTRY_REACH_WEIGHT.values())
    assert _ENTRY_REACH_WEIGHT.get("unknown", 0.0) == 0.0


def test_entry_reach_unknown_external_lead_not_buried(tmp_path: Path) -> None:
    # An entry_reach=unknown but external_input cmd lead still ranks above a found-but-weaker
    # (format-sink, stock-oss, filtered) lead — the lever does not bury an unknown real lead.
    conn = _atlas(tmp_path)
    strong = _pattern(conn, "fp_s", sink_class="cmd", source_class="external_input")
    weak = _pattern(conn, "fp_w", sink_class="format", source_class="unknown")
    _inst(
        conn,
        strong,
        status="unknown",
        origin="custom",
        fn="unknown_entry_lead",
        entry_reach="unknown",
    )
    _inst(
        conn,
        weak,
        status="unknown",
        origin="stock_oss_known",
        blocking="length_check",
        fn="found_but_weak",
        entry_reach="found",
    )

    ranked = triage(conn)
    assert ranked[0].function == "unknown_entry_lead"
    conn.close()


def test_blocked_sinks_to_the_bottom(tmp_path: Path) -> None:
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp", sink_class="cmd", source_class="external_input")
    # a "best possible" blocked vs a "worst possible" unknown: blocked must still be last.
    _inst(conn, p, status="blocked", origin="custom", blocking="char_filter", fn="blk_best")
    _inst(
        conn, p, status="unknown", origin="stock_oss_known", blocking="length_check", fn="unk_worst"
    )

    ranked = triage(conn)
    assert ranked[-1].function == "blk_best"  # gated sinks below any to-verify
    assert ranked[-1].review_status == "gated"
    conn.close()


# ── presentation relabel (raw field UNCHANGED) ──────────────────────────────────────


def test_review_status_relabel_does_not_touch_stored_field(tmp_path: Path) -> None:
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp")
    _inst(conn, p, status="unknown", fn="u")
    _inst(conn, p, status="confirmed", fn="c")
    _inst(conn, p, status="blocked", fn="b")

    by_fn = {c.function: c for c in triage(conn)}
    assert by_fn["u"].review_status == "to-verify"
    assert by_fn["c"].review_status == "reachable"
    assert by_fn["b"].review_status == "gated"

    # The atlas itself still holds the raw mechanism values — the relabel is presentation-only.
    stored = {
        r["source_anchor"]: r["reachability_status"]
        for r in conn.execute("SELECT source_anchor, reachability_status FROM instance")
    }
    assert stored == {"u": "unknown", "c": "confirmed", "b": "blocked"}
    conn.close()


# ── evidence_ref anchor on every row ─────────────────────────────────────────────────


def test_every_candidate_carries_evidence_ref(tmp_path: Path) -> None:
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp")
    _inst(conn, p, status="unknown", run_id="run_x")
    _inst(conn, p, status="confirmed", run_id="run_x")

    for c in triage(conn):
        assert c.evidence_ref is not None
        assert c.evidence_ref.startswith("run_x#fn")
    conn.close()


# ── determinism ─────────────────────────────────────────────────────────────────────


def test_score_is_deterministic() -> None:
    args = ("unknown", None, "custom", "external_input", "cmd")
    assert review_score(*args) == review_score(*args)


# ── read-only: triage writes nothing ─────────────────────────────────────────────────


def test_triage_does_not_write_back(tmp_path: Path) -> None:
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp")
    _inst(conn, p, status="unknown", origin="custom")
    _inst(conn, p, status="blocked", blocking="char_filter")
    before = [tuple(r) for r in conn.execute("SELECT * FROM instance ORDER BY instance_id")]

    triage(conn)  # pure read
    triage(conn, run_id="run_1")

    after = [tuple(r) for r in conn.execute("SELECT * FROM instance ORDER BY instance_id")]
    assert before == after  # not one byte changed
    conn.close()


# ── CLI: gated folded by default, shown on demand ───────────────────────────────────


def _seed_for_cli(tmp_path: Path) -> Path:
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp")
    _inst(conn, p, status="unknown", origin="custom", fn="tv_fn", run_id="run_cli")
    _inst(conn, p, status="confirmed", origin="custom", fn="rc_fn", run_id="run_cli")
    _inst(conn, p, status="blocked", blocking="char_filter", fn="gt_fn", run_id="run_cli")
    conn.close()
    return tmp_path / "atlas.db"


def test_cli_folds_gated_by_default(tmp_path: Path) -> None:
    atlas = _seed_for_cli(tmp_path)
    result = CliRunner().invoke(triage_cmd, ["run_cli", "--atlas", str(atlas)])
    assert result.exit_code == 0, result.output
    assert "gt_fn" not in result.output  # gated row folded
    assert "1 hidden" in result.output  # but counted as hidden
    assert "tv_fn" in result.output and "rc_fn" in result.output


def test_cli_include_gated_shows_gated(tmp_path: Path) -> None:
    atlas = _seed_for_cli(tmp_path)
    result = CliRunner().invoke(triage_cmd, ["run_cli", "--include-gated", "--atlas", str(atlas)])
    assert result.exit_code == 0, result.output
    assert "gt_fn" in result.output  # gated now visible

    result_all = CliRunner().invoke(
        triage_cmd, ["run_cli", "--status", "all", "--atlas", str(atlas)]
    )
    assert result_all.exit_code == 0, result_all.output
    assert "gt_fn" in result_all.output


# ── CLI: global ranking (highest score first), stable rank, --explain by # ──────────


def _rank_of(output: str, fn: str) -> int | None:
    for line in output.splitlines():
        if f" {fn} (" in line:
            return int(line.split()[0])
    return None


def _first_data_fn(output: str) -> str | None:
    # the first row after the column header line
    lines = output.splitlines()
    for i, line in enumerate(lines):
        if line.lstrip().startswith("#") and "score" in line:
            return lines[i + 1].split()[3]  # rank, score, status, function
    return None


def test_cli_highest_score_floats_to_top(tmp_path: Path) -> None:
    # rc_fn (confirmed -> reachable, top score) must be rank 1 and the first row, ABOVE the
    # lower-scored to-verify rows — the bug was reachable getting buried below to-verify.
    atlas = _seed_for_cli(tmp_path)
    result = CliRunner().invoke(triage_cmd, ["run_cli", "--atlas", str(atlas)])
    assert result.exit_code == 0, result.output
    assert _rank_of(result.output, "rc_fn") == 1
    assert _first_data_fn(result.output) == "rc_fn"
    assert result.output.index("rc_fn") < result.output.index("tv_fn")


def test_cli_rank_is_stable_across_filters(tmp_path: Path) -> None:
    atlas = _seed_for_cli(tmp_path)
    out_all = CliRunner().invoke(triage_cmd, ["run_cli", "--status", "all", "--atlas", str(atlas)])
    out_reach = CliRunner().invoke(
        triage_cmd, ["run_cli", "--status", "reachable", "--atlas", str(atlas)]
    )
    out_top = CliRunner().invoke(triage_cmd, ["run_cli", "--top", "5", "--atlas", str(atlas)])
    out_gated = CliRunner().invoke(
        triage_cmd, ["run_cli", "--status", "gated", "--atlas", str(atlas)]
    )
    # rc_fn's global rank is identical no matter the filter/top.
    assert _rank_of(out_all.output, "rc_fn") == 1
    assert _rank_of(out_reach.output, "rc_fn") == 1
    assert _rank_of(out_top.output, "rc_fn") == 1
    # a gated-only view keeps the GLOBAL rank (3), not a per-view #1.
    assert _rank_of(out_gated.output, "gt_fn") == 3


def test_cli_top_n_is_global_front(tmp_path: Path) -> None:
    # --top 1 shows the single highest-scored candidate globally (rc_fn), not "1 per section".
    atlas = _seed_for_cli(tmp_path)
    result = CliRunner().invoke(triage_cmd, ["run_cli", "--top", "1", "--atlas", str(atlas)])
    assert result.exit_code == 0, result.output
    assert "rc_fn" in result.output
    assert "tv_fn" not in result.output


def test_cli_explain_by_rank_matches_ref(tmp_path: Path) -> None:
    atlas = _seed_for_cli(tmp_path)
    conn = open_atlas(atlas)
    try:
        ref0 = triage(conn, run_id="run_cli")[0].evidence_ref  # rank-1 candidate's ref
    finally:
        conn.close()
    by_rank = CliRunner().invoke(triage_cmd, ["run_cli", "--explain", "1", "--atlas", str(atlas)])
    by_ref = CliRunner().invoke(
        triage_cmd, ["run_cli", "--explain", str(ref0), "--atlas", str(atlas)]
    )
    assert by_rank.exit_code == 0, by_rank.output
    assert by_ref.exit_code == 0, by_ref.output
    assert by_rank.output == by_ref.output  # --explain N resolves to the same candidate as its ref


def test_cli_explain_rank_out_of_range_errors(tmp_path: Path) -> None:
    atlas = _seed_for_cli(tmp_path)
    result = CliRunner().invoke(triage_cmd, ["run_cli", "--explain", "999", "--atlas", str(atlas)])
    assert result.exit_code != 0
    assert "out of range" in result.output


# ── CLI: candidate locatability (binary path) + intended-use notice ─────────────────


def _seed_with_location(tmp_path: Path) -> Path:
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp")
    _inst(
        conn,
        p,
        status="unknown",
        origin="custom",
        fn="tv_fn",
        run_id="run_loc",
        binary_path="usr/sbin/webd",
    )
    conn.close()
    return tmp_path / "atlas.db"


def test_cli_triage_shows_binary_location(tmp_path: Path) -> None:
    atlas = _seed_with_location(tmp_path)
    result = CliRunner().invoke(triage_cmd, ["run_loc", "--atlas", str(atlas)])
    assert result.exit_code == 0, result.output
    assert "usr/sbin/webd" in result.output  # the binary to open is shown, actionable


def test_cli_triage_json_includes_binary_path(tmp_path: Path) -> None:
    import json

    atlas = _seed_with_location(tmp_path)
    result = CliRunner().invoke(triage_cmd, ["run_loc", "--json", "--atlas", str(atlas)])
    assert result.exit_code == 0, result.output
    rows = json.loads(result.output)  # --json must be clean JSON (no notice framing)
    assert rows[0]["binary_path"] == "usr/sbin/webd"


def test_cli_triage_prints_intended_use_notice(tmp_path: Path) -> None:
    atlas = _seed_with_location(tmp_path)
    result = CliRunner().invoke(triage_cmd, ["run_loc", "--atlas", str(atlas)])
    assert result.exit_code == 0, result.output
    assert "defensive firmware-audit" in result.output
    assert "your responsibility" in result.output


def test_cli_triage_json_omits_notice(tmp_path: Path) -> None:
    atlas = _seed_with_location(tmp_path)
    result = CliRunner().invoke(triage_cmd, ["run_loc", "--json", "--atlas", str(atlas)])
    assert result.exit_code == 0, result.output
    assert "defensive firmware-audit" not in result.output  # notice suppressed under --json


# ── CLI: view entry — default cap, --all, --sink (recall must stay visible) ─────────


def _seed_many(tmp_path: Path, n_system: int = 25, n_copy: int = 3) -> Path:
    conn = _atlas(tmp_path)
    p_cmd = _pattern(conn, "fp_cmd", sink_class="cmd")
    p_copy = _pattern(conn, "fp_copy", sink_class="copy")
    for i in range(n_system):
        _inst(
            conn,
            p_cmd,
            status="unknown",
            origin="custom",
            fn=f"sys_fn{i}",
            sink_anchor="system",
            run_id="run_v",
        )
    for i in range(n_copy):
        _inst(
            conn,
            p_copy,
            status="unknown",
            origin="custom",
            fn=f"cp_fn{i}",
            sink_anchor="strcpy",
            run_id="run_v",
        )
    conn.close()
    return tmp_path / "atlas.db"


def _data_fns(output: str) -> list[str]:
    fns = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0].isdigit() and "(" in line:
            fns.append(parts[3])
    return fns


def test_cli_default_caps_at_20(tmp_path: Path) -> None:
    atlas = _seed_many(tmp_path)
    result = CliRunner().invoke(triage_cmd, ["run_v", "--atlas", str(atlas)])
    assert result.exit_code == 0, result.output
    assert len(_data_fns(result.output)) == 20  # default cap
    assert "showing top 20 of 28" in result.output  # tells the operator more exist


def test_cli_all_shows_everything(tmp_path: Path) -> None:
    atlas = _seed_many(tmp_path)
    result = CliRunner().invoke(triage_cmd, ["run_v", "--all", "--atlas", str(atlas)])
    assert result.exit_code == 0, result.output
    assert len(_data_fns(result.output)) == 28  # 25 system + 3 copy, uncapped


def test_cli_sink_filter_uncapped_and_typed(tmp_path: Path) -> None:
    atlas = _seed_many(tmp_path)
    # --sink system: every one of the 25 system candidates, NOT capped at 20.
    sys_out = CliRunner().invoke(triage_cmd, ["run_v", "--sink", "system", "--atlas", str(atlas)])
    assert sys_out.exit_code == 0, sys_out.output
    sys_fns = _data_fns(sys_out.output)
    assert len(sys_fns) == 25
    assert all(f.startswith("sys_fn") for f in sys_fns)
    # --sink copy: filter by sink class; only the copy candidates.
    cp_out = CliRunner().invoke(triage_cmd, ["run_v", "--sink", "copy", "--atlas", str(atlas)])
    assert [f for f in _data_fns(cp_out.output)] == ["cp_fn0", "cp_fn1", "cp_fn2"]


def test_cli_sink_filter_surfaces_gated(tmp_path: Path) -> None:
    # A gated (blocked) system candidate is hidden by the default fold but must appear under
    # --sink system — recall stays visible by sink even when low/gated.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp", sink_class="cmd")
    _inst(
        conn,
        p,
        status="unknown",
        origin="custom",
        fn="live_sys",
        sink_anchor="system",
        run_id="run_g",
    )
    _inst(
        conn,
        p,
        status="blocked",
        blocking="char_filter",
        fn="gated_sys",
        sink_anchor="system",
        run_id="run_g",
    )
    conn.close()
    atlas = tmp_path / "atlas.db"
    result = CliRunner().invoke(triage_cmd, ["run_g", "--sink", "system", "--atlas", str(atlas)])
    assert result.exit_code == 0, result.output
    assert "gated_sys" in result.output  # gated, but surfaced by the sink filter


def test_cli_rank_stable_under_sink_filter(tmp_path: Path) -> None:
    # The global rank is assigned before the --sink filter; a filtered row keeps its global #.
    atlas = _seed_many(tmp_path, n_system=2, n_copy=1)
    full = CliRunner().invoke(triage_cmd, ["run_v", "--all", "--atlas", str(atlas)])
    cp = CliRunner().invoke(triage_cmd, ["run_v", "--sink", "copy", "--atlas", str(atlas)])
    assert _rank_of(cp.output, "cp_fn0") == _rank_of(full.output, "cp_fn0")


def test_cli_explain_shows_binary_location(tmp_path: Path) -> None:
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp")
    _inst(
        conn,
        p,
        status="unknown",
        origin="custom",
        fn="tv_fn",
        run_id="run_e",
        binary_path="usr/sbin/webd",
    )
    conn.close()
    atlas = tmp_path / "atlas.db"
    result = CliRunner().invoke(triage_cmd, ["run_e", "--explain", "1", "--atlas", str(atlas)])
    assert result.exit_code == 0, result.output
    assert "usr/sbin/webd" in result.output
