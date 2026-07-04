# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the triage --explain single-candidate view.

Proves the score breakdown is honest (items sum to the real score), the reachability bound
footnote is present (and no self-declared verdict), evidence_ref resolves exactly (friendly
error otherwise), no triggering-input/weapon vocabulary leaks, and the view is read-only.
"""

from __future__ import annotations

import re
from pathlib import Path

from click.testing import CliRunner

from treasure_map.cli.hunt_cli import triage as triage_cmd
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, upsert_pattern
from treasure_map.lib.query import explain_candidate, review_score, score_breakdown
from treasure_map.lib.query.triage import _SCORE_HI, _SCORE_LO

_FID = [0]

_WEAPON_WORDS = ("payload", "exploit", "send", "poc", "rce")  # checked as whole words
_SELF_VERDICT = ("high-confidence vulnerability", "confirmed exploit", "confirmed vulnerability")


def _has_weapon_word(text: str) -> str | None:
    """Return the first weapon word present as a whole word (so 'source' doesn't match 'rce')."""
    low = text.lower()
    for w in _WEAPON_WORDS:
        if re.search(rf"\b{re.escape(w)}\b", low):
            return w
    return None


def _seed(
    tmp_path: Path,
    *,
    status: str = "confirmed",
    origin: str = "unknown",
    source_kind: str | None = None,
) -> Path:
    conn = open_atlas(tmp_path / "atlas.db")
    p = upsert_pattern(
        conn,
        source_class="external_input",
        sink_class="copy",
        call_sequence_shape="source->copy",
        structural_fingerprint="fp",
        fingerprint_algo_version="callseq-v1",
    )
    _FID[0] += 1
    import json

    flow_evidence = json.dumps({"source_kind": source_kind}) if source_kind is not None else None
    add_instance(
        conn,
        InstanceRow(
            pattern_id=p,
            pseudocode_hash=f"h{_FID[0]}",
            source_anchor="fn_handle",
            sink_anchor="memcpy",
            source_run_id="run_x",
            reachability_status=status,
            blocking_mechanism=None,
            provenance_level="L1" if status in {"confirmed", "blocked"} else "L0",
            evidence_ref="run_x#fn7",
            scope_origin="intra",
            origin=origin,
            flow_evidence=flow_evidence,
        ),
    )
    conn.close()
    return tmp_path / "atlas.db"


# ── 1. breakdown is honest: items sum, normalized, to the real score ────────────────


def test_breakdown_sums_to_score() -> None:
    cases = [
        ("confirmed", None, "custom", "external_input", "cmd"),
        ("unknown", "length_check", "stock_oss_known", "unknown", "format"),
        ("blocked", "char_filter", "vendor_modified_oss", "external_input", "copy"),
    ]
    for args in cases:
        comps = score_breakdown(*args)
        raw = sum(c.weight for c in comps)
        norm = round(min(1.0, max(0.0, (raw - _SCORE_LO) / (_SCORE_HI - _SCORE_LO))), 2)
        assert norm == review_score(*args)  # every item maps to a real weight; sum reproduces score


def test_explanation_score_matches_breakdown(tmp_path: Path) -> None:
    atlas = _seed(tmp_path, status="confirmed")
    conn = open_atlas(atlas)
    try:
        ex = explain_candidate(conn, "run_x#fn7")
    finally:
        conn.close()
    assert ex is not None
    assert abs(sum(c.weight for c in ex.components) - ex.raw_score) < 1e-9
    norm = round(min(1.0, max(0.0, (ex.raw_score - ex.score_lo) / (ex.score_hi - ex.score_lo))), 2)
    assert norm == ex.score == ex.candidate.score


# ── 2. honest reachability bound present; no self-declared verdict ──────────────────


def test_confirmed_explanation_states_bounds_not_verdict(tmp_path: Path) -> None:
    atlas = _seed(tmp_path, status="confirmed")
    conn = open_atlas(atlas)
    try:
        ex = explain_candidate(conn, "run_x#fn7")
    finally:
        conn.close()
    assert ex is not None
    reach = next(c for c in ex.components if c.signal == "reachability")
    note = reach.note.lower()
    assert "one function" in note  # single-function bound
    assert "cross-function" in note  # explicitly not cross-function
    assert "caller" in note  # caller not confirmed
    blob = (reach.note + " ".join(ex.claims_does) + " ".join(ex.claims_does_not)).lower()
    for phrase in _SELF_VERDICT:
        assert phrase not in blob


# ── 3. evidence_ref resolves exactly; friendly error otherwise ──────────────────────


def test_explain_resolves_exact_ref(tmp_path: Path) -> None:
    atlas = _seed(tmp_path)
    conn = open_atlas(atlas)
    try:
        ex = explain_candidate(conn, "run_x#fn7")
        miss = explain_candidate(conn, "run_x#fn999")
    finally:
        conn.close()
    assert ex is not None and ex.candidate.evidence_ref == "run_x#fn7"
    assert miss is None


def test_cli_explain_unknown_ref_errors(tmp_path: Path) -> None:
    atlas = _seed(tmp_path)
    result = CliRunner().invoke(
        triage_cmd, ["run_x", "--explain", "run_x#fn999", "--atlas", str(atlas)]
    )
    assert result.exit_code != 0
    assert "no candidate with evidence_ref run_x#fn999" in result.output
    assert "tmap triage run_x" in result.output  # friendly hint to list refs


# ── 4. no triggering-input / weapon vocabulary in text or JSON ──────────────────────


def test_cli_explain_text_has_no_weapon_vocab(tmp_path: Path) -> None:
    atlas = _seed(tmp_path, status="confirmed")
    result = CliRunner().invoke(
        triage_cmd, ["run_x", "--explain", "run_x#fn7", "--atlas", str(atlas)]
    )
    assert result.exit_code == 0, result.output
    assert _has_weapon_word(result.output) is None
    # it still has to be useful: breakdown + verify checklist present
    out = result.output.lower()
    assert "score" in out and "verify" in out and "memcpy" in result.output


def test_cli_explain_json_is_structured_without_payload(tmp_path: Path) -> None:
    import json

    atlas = _seed(tmp_path, status="confirmed")
    result = CliRunner().invoke(
        triage_cmd, ["run_x", "--explain", "run_x#fn7", "--json", "--atlas", str(atlas)]
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["evidence_ref"] == "run_x#fn7"
    assert {s["signal"] for s in data["score_breakdown"]} == {
        "reachability",
        "filter",
        "origin",
        "source_class",
        "sink_class",
        "entry_reach",
    }
    assert "verify" in data and "claims_does_not" in data
    assert _has_weapon_word(json.dumps(data)) is None
    # no input-construction field smuggled in
    assert not any(k in data for k in ("payload", "input", "trigger", "poc"))


# ── source_kind / source_class surfaced at the explanation TOP LEVEL (缺口③ bug fix) ──


def test_explanation_surfaces_source_signals_at_top_level(tmp_path: Path) -> None:
    # The bug: source_kind was reachable only via ex.candidate, invisible at the top level a
    # consumer (the MCP asdict, an agent) reads. Pin BOTH source signals on the CandidateExplanation
    # itself, echoing the same-named candidate fields.
    atlas = _seed(tmp_path, status="unknown", source_kind="free_string")
    conn = open_atlas(atlas)
    try:
        ex = explain_candidate(conn, "run_x#fn7")
    finally:
        conn.close()
    assert ex is not None
    assert ex.source_kind == "free_string"  # top-level field, not only ex.candidate.source_kind
    assert ex.source_class == "external_input"  # coarse class also top-level
    assert ex.source_kind == ex.candidate.source_kind  # echoes the candidate, no divergence
    assert ex.source_class == ex.candidate.source_class


def test_explanation_source_kind_defaults_unknown_at_top_level(tmp_path: Path) -> None:
    # No source_kind in flow_evidence -> top-level "unknown" (never fabricated); source_class stays.
    atlas = _seed(tmp_path, status="unknown")  # no flow_evidence at all
    conn = open_atlas(atlas)
    try:
        ex = explain_candidate(conn, "run_x#fn7")
    finally:
        conn.close()
    assert ex is not None
    assert ex.source_kind == "unknown"
    assert ex.source_class == "external_input"


# ── 5. read-only: --explain changes nothing in the atlas ────────────────────────────


def test_explain_is_read_only(tmp_path: Path) -> None:
    atlas = _seed(tmp_path)
    conn = open_atlas(atlas)
    before = [tuple(r) for r in conn.execute("SELECT * FROM instance ORDER BY instance_id")]
    try:
        explain_candidate(conn, "run_x#fn7")
        explain_candidate(conn, "run_x#fn999")
    finally:
        conn.close()
    conn2 = open_atlas(atlas)
    after = [tuple(r) for r in conn2.execute("SELECT * FROM instance ORDER BY instance_id")]
    conn2.close()
    assert before == after


# ── 6. committed render strings carry no self-declared verdict ──────────────────────


def test_render_sources_carry_no_self_verdict() -> None:
    src = Path(__file__).resolve().parents[3] / "src" / "treasure_map"
    targets = [src / "cli" / "hunt_cli.py", src / "lib" / "query" / "triage.py"]
    for path in targets:
        text = path.read_text().lower()
        for phrase in _SELF_VERDICT:
            assert phrase not in text, f"self-verdict phrase {phrase!r} in {path.name}"
