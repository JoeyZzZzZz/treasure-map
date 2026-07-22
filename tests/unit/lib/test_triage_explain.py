# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the triage --explain single-candidate map view.

Proves every dimension layer is surfaced as an honest three-state fact (no collapsed score), the
honest reachability/cross-function bound is stated (and no self-declared verdict), evidence_ref
resolves exactly (friendly error otherwise), no triggering-input/weapon vocabulary leaks, and the
view is read-only.
"""

from __future__ import annotations

import re
from pathlib import Path

from click.testing import CliRunner

from treasure_map.cli.hunt_cli import triage as triage_cmd
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, upsert_pattern
from treasure_map.lib.query import explain_candidate

_FID = [0]

_WEAPON_WORDS = ("payload", "exploit", "send", "poc", "rce")  # checked as whole words
_SELF_VERDICT = ("high-confidence vulnerability", "confirmed exploit", "confirmed vulnerability")

_DIMENSION_NAMES = {
    "controllability",
    "source",
    "source_writability",
    "reachability",
    "filtering",
    "sink_impact",
    "writer",
    "completeness",
}


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


# ── 1. every dimension layer is surfaced as a three-state fact (no score) ────────────


def test_explanation_carries_all_dimension_layers(tmp_path: Path) -> None:
    atlas = _seed(tmp_path, status="confirmed")
    conn = open_atlas(atlas)
    try:
        ex = explain_candidate(conn, "run_x#fn7")
    finally:
        conn.close()
    assert ex is not None
    names = {d.name for d in ex.dimensions}
    assert names == _DIMENSION_NAMES  # all eight layers present (source = orthogonal param axis)
    for d in ex.dimensions:  # each layer is an honest fact (likely = optimistic, structural = lead)
        assert d.state in {"proven", "likely", "structural", "excluded", "unknown"}
        assert d.value and d.source
    # top-level echoes of the two most-consulted layers
    assert ex.controllability == ex.candidate.dim("controllability").value
    assert ex.sink_impact == ex.candidate.sink_class
    # there is no score attribute anywhere on the explanation
    assert not hasattr(ex, "score")
    assert not hasattr(ex, "raw_score")


def test_explanation_surfaces_lens_and_caveats(tmp_path: Path) -> None:
    # The explain view carries the active lens label and the honest phase-1 caveats so it never
    # reads as complete (optimistic 'free', near-always-'?' filtering, no-reduction).
    atlas = _seed(tmp_path)
    conn = open_atlas(atlas)
    try:
        ex = explain_candidate(conn, "run_x#fn7")
    finally:
        conn.close()
    assert ex is not None
    assert "sink-impact" in ex.lens_label
    blob = " ".join(ex.caveats).lower()
    assert "optimistic" in blob  # 'free' is optimistic
    assert "?" in blob  # filtering is near-always '?'


# ── 2. honest reachability / cross-function bound present; no self-declared verdict ──


def test_confirmed_explanation_states_bounds_not_verdict(tmp_path: Path) -> None:
    atlas = _seed(tmp_path, status="confirmed")
    conn = open_atlas(atlas)
    try:
        ex = explain_candidate(conn, "run_x#fn7")
    finally:
        conn.close()
    assert ex is not None
    # the honest bound lives in claims_does_not: cross-function flow is NOT traced, and a '?' is
    # never proven safe.
    does_not = " ".join(ex.claims_does_not).lower()
    assert "cross-function" in does_not
    assert "coverage gap" in does_not or "never 'safe'" in does_not
    # the reachability layer states 'unknown != unreachable'.
    reach = ex.candidate.dim("reachability")
    assert reach.state == "unknown"
    assert "unreachable" in reach.note.lower()
    blob = (does_not + " " + " ".join(ex.claims_does)).lower()
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
    # it still has to be useful: dimension layers + verify checklist present
    out = result.output.lower()
    assert "dimension layers" in out and "verify" in out and "memcpy" in result.output


def test_cli_explain_json_is_structured_without_payload(tmp_path: Path) -> None:
    import json

    atlas = _seed(tmp_path, status="confirmed")
    result = CliRunner().invoke(
        triage_cmd, ["run_x", "--explain", "run_x#fn7", "--json", "--atlas", str(atlas)]
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["evidence_ref"] == "run_x#fn7"
    assert {d["name"] for d in data["dimensions"]} == _DIMENSION_NAMES
    assert "score" not in data and "score_breakdown" not in data  # the collapsed score is gone
    assert "verify" in data and "claims_does_not" in data and "caveats" in data
    assert _has_weapon_word(json.dumps(data)) is None
    # no input-construction field smuggled in
    assert not any(k in data for k in ("payload", "input", "trigger", "poc"))


# ── source_kind / source_class / controllability surfaced at explanation TOP LEVEL ──


def test_explanation_surfaces_source_signals_at_top_level(tmp_path: Path) -> None:
    # source_kind / source_class / controllability / sink_impact are pinned on the explanation
    # itself so a consumer (the MCP asdict, an agent) reads them without descending into candidate.
    atlas = _seed(tmp_path, status="unknown", source_kind="free_string")
    conn = open_atlas(atlas)
    try:
        ex = explain_candidate(conn, "run_x#fn7")
    finally:
        conn.close()
    assert ex is not None
    assert ex.source_kind == "free_string"
    assert ex.source_class == "external_input"
    # ★ 1.3: the BARE flat value is UNCHANGED (no in-place wire change to "likely:free" that would
    # break a consumer reading == "free"); the labeled sibling carries the honest state so a bare
    # "free" read alone never hides the optimistic 'likely'.
    assert ex.controllability == "free"  # bare value, back-compat — NOT rewritten in place
    assert ex.controllability_labeled == "likely:free"  # honest state:value sibling
    assert ex.sink_impact == "copy"
    assert ex.sink_impact_labeled == "proven:copy"
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
    assert ex.controllability == "unknown"  # no free/nvram signal -> unknown, never fabricated


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
