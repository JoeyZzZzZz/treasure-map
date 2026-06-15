# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for lib/query/triage — the read-only review-ordering of atlas candidates.

Builds a synthetic atlas directly (no analyzer), then asserts the deterministic ranking,
the presentation-only relabel (raw schema field stays confirmed/blocked/unknown), the
gated fold in the CLI, the evidence_ref anchor on every row, and that triage writes nothing.
"""

from __future__ import annotations

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
) -> None:
    _FID[0] += 1
    provenance = "L1" if status in {"confirmed", "blocked"} else "L0"
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
