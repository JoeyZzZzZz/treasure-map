# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for lib/query/triage — the read-only dimension MAP of atlas candidates.

Builds a synthetic atlas directly (no analyzer), then asserts the default-lens ordering (spine
on sink-impact, band by impact x controllability, only-up promotes, demotion iron law), the
presentation-only relabel (raw schema field stays confirmed/blocked/unknown), the gated fold in
the CLI, the evidence_ref anchor on every row, and that triage writes nothing.

There is NO collapsed score: ordering is a lens over first-class dimension layers, and a '?' layer
never sinks a candidate.
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
from treasure_map.lib.query import sort_candidates, triage

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


def _entry_sites(spec: str) -> list[dict[str, object]]:
    """Build entry_reach.sites for a requested reachability outcome, so the read view derives the
    matching mechanistic label from real site kinds. ``found`` is a legacy alias for a lone web
    endpoint; ``entry:web`` / ``entry:script`` / ``entry:web+script`` build the named kinds;
    ``unknown`` builds none."""
    kinds: set[str] = set()
    if spec == "found":
        kinds = {"web"}
    elif spec.startswith("entry:"):
        kinds = set(spec[len("entry:") :].split("+"))
    sites: list[dict[str, object]] = []
    if "web" in kinds:
        sites.append(
            {"kind": "web_endpoint", "method": "POST", "endpoint": "/apply.cgi", "asset": "www/x"}
        )
    if "script" in kinds:
        sites.append({"kind": "script_call", "script": "/etc/init.d/rcS", "line": 3})
    return sites


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
    source_kind: str | None = None,
) -> None:
    _FID[0] += 1
    provenance = "L1" if status in {"confirmed", "blocked"} else "L0"
    # flow_evidence: None when neither signal is set; else the minimal payload for whichever of
    # entry_reach.sites / source_kind was requested (both parsed back by the read view). entry_reach
    # is now derived from the sites' kinds, so the fixture builds real sites (web_endpoint /
    # script_call) rather than only a status word.
    evidence: dict[str, object] = {}
    if entry_reach is not None:
        sites = _entry_sites(entry_reach)
        evidence["entry_reach"] = {"status": "found" if sites else "unknown", "sites": sites}
    if source_kind is not None:
        evidence["source_kind"] = source_kind
    flow_evidence = json.dumps(evidence) if evidence else None
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


def _ctrl(c: object) -> str:
    return c.dim("controllability").value  # type: ignore[attr-defined]


# ── default-lens ordering ───────────────────────────────────────────────────────────


def test_high_impact_lead_ranks_above_low_impact_lead(tmp_path: Path) -> None:
    # Default lens spines on sink-impact: a cmd (RCE, tier 3) sink ranks above a format (tier 1)
    # sink of the same everything-else — impact is the pivot axis.
    conn = _atlas(tmp_path)
    strong_p = _pattern(conn, "fp_strong", sink_class="cmd", source_class="external_input")
    weak_p = _pattern(conn, "fp_weak", sink_class="format", source_class="unknown")
    _inst(conn, strong_p, status="unknown", origin="custom", fn="strong_fn")
    _inst(conn, weak_p, status="unknown", origin="stock_oss_known", fn="weak_fn")

    ranked = triage(conn)
    assert [c.function for c in ranked] == ["strong_fn", "weak_fn"]
    conn.close()


def test_free_controllability_ranks_above_unknown_within_a_tier(tmp_path: Path) -> None:
    # Within one impact tier, controllability certainty bands the map: a free source ranks above an
    # unknown one (the composite key's second axis). Neither is sunk — both stay active.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp", sink_class="cmd", source_class="external_input")
    _inst(conn, p, fn="unknown_src")  # no source_kind -> controllability unknown
    _inst(conn, p, fn="free_src", source_kind="free_string")  # -> controllability free

    ranked = triage(conn)
    assert [c.function for c in ranked] == ["free_src", "unknown_src"]
    assert _ctrl(ranked[0]) == "free"
    assert _ctrl(ranked[1]) == "unknown"
    conn.close()


# ── reachability dimension (entry_reach): proven promotes, ? never demotes ──


def test_entry_reach_found_promotes_within_tier(tmp_path: Path) -> None:
    # Two same-impact same-controllability candidates differing ONLY in entry-reach: the one with a
    # proven rootfs entry ranks above the unknown-entry one (an only-up tertiary promote).
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp", sink_class="fmt_string", source_class="external_input")
    _inst(conn, p, status="unknown", fn="local_only", entry_reach="unknown")
    _inst(conn, p, status="unknown", fn="net_reachable", entry_reach="entry:web")

    ranked = triage(conn)
    assert [c.function for c in ranked] == ["net_reachable", "local_only"]
    assert next(c for c in ranked if c.function == "net_reachable").entry_reach == "entry:web"
    conn.close()


def test_entry_reach_does_not_reverse_sink_impact_order(tmp_path: Path) -> None:
    # A proven-entry COPY must not overtake an unknown-entry CMD: entry-reach is an only-up tertiary
    # key, ranked BELOW the impact spine and the controllability band.
    conn = _atlas(tmp_path)
    cmd_p = _pattern(conn, "fp_cmd", sink_class="cmd", source_class="external_input")
    copy_p = _pattern(conn, "fp_copy", sink_class="copy", source_class="external_input")
    _inst(conn, cmd_p, status="unknown", fn="cmd_no_entry", entry_reach="unknown")
    _inst(conn, copy_p, status="unknown", fn="copy_found", entry_reach="entry:web")

    ranked = triage(conn)
    assert [c.function for c in ranked] == ["cmd_no_entry", "copy_found"]
    conn.close()


def test_unknown_reachability_is_never_demoted(tmp_path: Path) -> None:
    # ★ prove-the-asymmetry: a found rootfs entry only ever PROMOTES; an 'unknown' (a '?') is
    # strictly neutral and is never demoted below an otherwise-identical no-signal candidate.
    from treasure_map.lib.query.triage import _candidate, _reach_is_entry, _reach_rank

    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp", sink_class="cmd", source_class="external_input")
    _inst(conn, p, fn="unknown_entry", entry_reach="unknown")
    _inst(conn, p, fn="no_signal")  # no entry_reach at all -> also 'unknown'
    _inst(conn, p, fn="found_entry", entry_reach="entry:web")
    ranked = triage(conn)
    order = [c.function for c in ranked]
    # an entry promotes to the top; unknown and no-signal tie (neither demoted) below it.
    assert order[0] == "found_entry"
    assert set(order[1:]) == {"unknown_entry", "no_signal"}
    # the asymmetry: an entry outranks unknown, but unknown is strictly neutral (never negative).
    assert _reach_rank("entry:web") > _reach_rank("unknown")
    assert _reach_rank("unknown") >= 1  # a ? carries no negative reachability contribution
    assert _reach_is_entry("entry:web") and not _reach_is_entry("unknown")
    assert _candidate  # imported symbol still present (dimension builder entry point)
    conn.close()


def test_unknown_entry_external_lead_not_buried(tmp_path: Path) -> None:
    # An entry_reach=unknown cmd lead still ranks above a found-but-lower-impact (format) lead — the
    # promote lever does not let a proven-entry weak sink bury an unknown-entry strong one.
    conn = _atlas(tmp_path)
    strong = _pattern(conn, "fp_s", sink_class="cmd", source_class="external_input")
    weak = _pattern(conn, "fp_w", sink_class="format", source_class="unknown")
    _inst(conn, strong, fn="unknown_entry_lead", entry_reach="unknown")
    _inst(conn, weak, fn="found_but_weak", entry_reach="entry:web")

    ranked = triage(conn)
    assert ranked[0].function == "unknown_entry_lead"
    conn.close()


# ── reachability honest split: entry:web / entry:script / entry:web+script / unknown (step 2) ──


def _reach_by_fn(conn: sqlite3.Connection) -> dict[str, str]:
    return {c.function: c.dim("reachability").value for c in triage(conn)}  # type: ignore[misc]


def test_reachability_splits_found_by_site_kind(tmp_path: Path) -> None:
    # The old collapsed 'found' splits into an honest, multi-valued mechanistic label read from the
    # site kinds: web endpoint -> entry:web, boot script -> entry:script, none -> unknown.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp", sink_class="cmd", source_class="external_input")
    _inst(conn, p, fn="web_fn", entry_reach="entry:web")
    _inst(conn, p, fn="script_fn", entry_reach="entry:script")
    _inst(conn, p, fn="none_fn", entry_reach="unknown")
    reach = _reach_by_fn(conn)
    assert reach["web_fn"] == "entry:web"
    assert reach["script_fn"] == "entry:script"
    assert reach["none_fn"] == "unknown"
    conn.close()


def test_reachability_multi_value_not_collapsed_to_single_kind(tmp_path: Path) -> None:
    # A binary referenced by BOTH a web endpoint and a boot script is reported as entry:web+script —
    # both kinds stated together, neither preferred over the other (collapsing recreates 'found').
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp", sink_class="cmd", source_class="external_input")
    _inst(conn, p, fn="both_fn", entry_reach="entry:web+script")
    (c,) = triage(conn)
    assert c.dim("reachability").value == "entry:web+script"  # not collapsed to entry:web
    conn.close()


def test_reachability_only_ever_proven_or_unknown_four_state(tmp_path: Path) -> None:
    # ★ contract C4/C7: the reachability axis uses only proven (any sound entry) or unknown (a
    # coverage gap) — never a fifth state, and never 'likely' (that tier is controllability's).
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp", sink_class="cmd", source_class="external_input")
    for i, val in enumerate(("entry:web", "entry:script", "entry:web+script", "unknown")):
        _inst(conn, p, fn=f"fn{i}", entry_reach=val)
    for c in triage(conn):
        d = c.dim("reachability")
        assert d.state in {"proven", "unknown"}  # never likely / excluded on this axis
        assert (d.state == "proven") == d.value.startswith("entry:")
        assert "sink:" not in d.value  # entry-level only — never asserts sink-level reachability


def test_reachability_web_note_carries_endpoint_and_method(tmp_path: Path) -> None:
    # entry:web / entry:web+script presentation names the triggering endpoint + method so the
    # consumer can confirm the dispatch themselves.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp", sink_class="cmd", source_class="external_input")
    _inst(conn, p, fn="web_fn", entry_reach="entry:web")
    (c,) = triage(conn)
    note = c.dim("reachability").note
    assert "POST" in note and "/apply.cgi" in note
    conn.close()


def test_reachability_entry_note_has_two_caveats_and_no_pre_auth(tmp_path: Path) -> None:
    # ★ seam (contract C7 note, mechanistic-label invariant): an entry:web note carries BOTH the
    # standard-flow caveat (textual reference != dispatch proof) and the completeness caveat
    # (service-dispatch/notify_rc unmodeled), and NEVER a pre-auth/attack-surface claim.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp", sink_class="cmd", source_class="external_input")
    _inst(conn, p, fn="web_fn", entry_reach="entry:web")
    _inst(conn, p, fn="script_fn", entry_reach="entry:script")
    by_fn = {c.function: c for c in triage(conn)}
    for fn in ("web_fn", "script_fn"):
        note = by_fn[fn].dim("reachability").note.lower()
        assert "not proof" in note or "textual reference" in note  # standard-flow caveat
        assert "notify_rc" in note and "not modeled" in note  # completeness caveat
        assert "pre-auth" not in note  # mechanistic label, never a pre-auth attack-surface claim
    # entry:script must NOT read as 'probably unreachable' (a gap is not lower reachability).
    assert "probably unreachable" not in by_fn["script_fn"].dim("reachability").note.lower()
    conn.close()


def test_reachability_filter_axis_matches_by_kind_without_reducing_map(tmp_path: Path) -> None:
    # ★ reachability is an orthogonal filter axis: entry:web matches entry:web AND entry:web+script;
    # entry:script matches entry:script AND entry:web+script. The underlying map is never reduced —
    # filtering is a lens over the same candidates.
    from treasure_map.lib.query.triage import filter_by_dimension

    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp", sink_class="cmd", source_class="external_input")
    _inst(conn, p, fn="web_fn", entry_reach="entry:web")
    _inst(conn, p, fn="script_fn", entry_reach="entry:script")
    _inst(conn, p, fn="both_fn", entry_reach="entry:web+script")
    _inst(conn, p, fn="none_fn", entry_reach="unknown")
    cands = triage(conn)
    assert len(cands) == 4  # the full map
    web = {c.function for c in filter_by_dimension(cands, "reachability", "entry:web")}
    script = {c.function for c in filter_by_dimension(cands, "reachability", "entry:script")}
    unknown = {c.function for c in filter_by_dimension(cands, "reachability", "unknown")}
    assert web == {"web_fn", "both_fn"}  # web+script has web among its kinds
    assert script == {"script_fn", "both_fn"}
    assert unknown == {"none_fn"}
    assert len(triage(conn)) == 4  # the map itself is unchanged by any filter
    conn.close()


def test_reachability_does_not_change_default_sort_web_vs_script(tmp_path: Path) -> None:
    # ★ contract C5: reachability does not tiebreak — entry:web and entry:script are equal on the
    # sort. Two otherwise-identical candidates keep the deterministic (function-name) order
    # regardless of which entry kind each carries.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp", sink_class="cmd", source_class="external_input")
    _inst(conn, p, fn="aaa_script", entry_reach="entry:script")
    _inst(conn, p, fn="bbb_web", entry_reach="entry:web")
    order = [c.function for c in triage(conn)]
    assert order == ["aaa_script", "bbb_web"]  # web not lifted above script; tiebreak is the name
    conn.close()


def test_reachability_source_has_no_pre_auth_vocabulary() -> None:
    # ★ mechanistic-label red line (grep): no reachability-axis string attaches a 'pre-auth attack
    # surface' claim to an entry reference (scoped to the reachability strings — other axes may
    # legitimately note a wan-daemon's pre-auth exposure on the controllability side).
    import importlib

    mod = importlib.import_module("treasure_map.lib.query.triage")  # module, not the shadowed fn
    reach_strings = " ".join(
        [
            mod._REACH_CAVEAT_STANDARD_FLOW,
            mod._REACH_CAVEAT_COMPLETENESS,
            mod.VIEWS["reachable-only"]["desc"],
        ]
    ).lower()
    assert "pre-auth" not in reach_strings
    assert "attack surface" not in reach_strings


# ── source_kind exposure -> controllability layer ──


def test_source_kind_parsed_from_flow_evidence(tmp_path: Path) -> None:
    # The read view surfaces the source_kind the evidence layer stored, verbatim.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp")
    _inst(conn, p, fn="free_fn", source_kind="free_string")
    _inst(conn, p, fn="charset_fn", source_kind="charset_maybe")
    by_fn = {c.function: c for c in triage(conn)}
    assert by_fn["free_fn"].source_kind == "free_string"
    assert by_fn["charset_fn"].source_kind == "charset_maybe"
    conn.close()


def test_source_kind_defaults_to_unknown_when_absent(tmp_path: Path) -> None:
    # flow_evidence present but with no source_kind, and flow_evidence absent entirely: both report
    # "unknown" — a missing signal is never fabricated into a class.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp")
    _inst(conn, p, fn="entry_only", entry_reach="entry:web")  # evidence present, no source_kind
    _inst(conn, p, fn="no_evidence")  # no flow_evidence at all
    by_fn = {c.function: c for c in triage(conn)}
    assert by_fn["entry_only"].source_kind == "unknown"
    assert by_fn["no_evidence"].source_kind == "unknown"
    conn.close()


def test_source_kind_parser_is_conservative() -> None:
    # The parser never raises and never fabricates: bad JSON, a non-dict, a non-string value, and a
    # missing key all degrade to "unknown"; a real string passes through verbatim.
    from treasure_map.lib.query.triage import _source_kind_from_evidence

    assert _source_kind_from_evidence(json.dumps({"source_kind": "free_string"})) == "free_string"
    assert _source_kind_from_evidence(None) == "unknown"
    assert _source_kind_from_evidence("") == "unknown"
    assert _source_kind_from_evidence("{not json") == "unknown"
    assert _source_kind_from_evidence(json.dumps(["list", "not", "dict"])) == "unknown"
    assert _source_kind_from_evidence(json.dumps({"source_kind": 7})) == "unknown"
    assert _source_kind_from_evidence(json.dumps({"entry_reach": {}})) == "unknown"


def test_source_kind_drives_controllability(tmp_path: Path) -> None:
    # ★ the map USES source_kind (unlike the old score, which ignored it): a free_string source is
    # controllability=free and ranks at or above the unknown-source candidate of the same tier.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp", sink_class="cmd", source_class="external_input")
    _inst(conn, p, fn="free_fn", source_kind="free_string")
    _inst(conn, p, fn="unknown_fn", source_kind="unknown")
    by_fn = {c.function: c for c in triage(conn)}
    assert _ctrl(by_fn["free_fn"]) == "free"
    assert _ctrl(by_fn["unknown_fn"]) == "unknown"
    ranked = [c.function for c in triage(conn)]
    assert ranked.index("free_fn") < ranked.index("unknown_fn")
    conn.close()


# ── gating is a presentation fold, NOT a sort demotion ──


def test_blocked_is_relabelled_gated_not_sunk(tmp_path: Path) -> None:
    # A blocked candidate is relabelled review_status='gated' (folded in the CLI), but the MAP still
    # orders it by its dimensions — gating is presentation; the sort never reads the raw status
    # (the sort key contains no reachability_status term at all).
    conn = _atlas(tmp_path)
    cmd_p = _pattern(conn, "fp_cmd", sink_class="cmd", source_class="external_input")
    copy_p = _pattern(conn, "fp_copy", sink_class="copy", source_class="external_input")
    _inst(conn, cmd_p, status="blocked", blocking="char_filter", fn="blk_cmd")
    _inst(conn, copy_p, status="unknown", fn="live_copy")

    ranked = triage(conn)
    by_fn = {c.function: c for c in ranked}
    assert by_fn["blk_cmd"].review_status == "gated"
    # the gated cmd (impact 3) still sorts ABOVE the live copy (impact 2) — not sunk by its status.
    assert [c.function for c in ranked] == ["blk_cmd", "live_copy"]
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


def test_sort_is_deterministic(tmp_path: Path) -> None:
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp", sink_class="cmd")
    for i in range(5):
        _inst(conn, p, fn=f"fn{i}", source_kind="free_string" if i % 2 else None)
    cands = triage(conn)
    a = [c.evidence_ref for c in sort_candidates(cands)]
    b = [c.evidence_ref for c in sort_candidates(cands)]
    assert a == b  # same input -> byte-identical order
    conn.close()


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
    # A dimension-driven ranking: rc_fn (cmd + free + found) is the clear #1; tv_fn (cmd, unknown)
    # #2; gt_fn (copy sink, blocked -> gated) #3 and folded by default.
    conn = _atlas(tmp_path)
    cmd_p = _pattern(conn, "fp_cmd", sink_class="cmd")
    copy_p = _pattern(conn, "fp_copy", sink_class="copy")
    _inst(
        conn,
        cmd_p,
        status="confirmed",
        origin="custom",
        fn="rc_fn",
        run_id="run_cli",
        source_kind="free_string",
        entry_reach="entry:web",
    )
    _inst(conn, cmd_p, status="unknown", origin="custom", fn="tv_fn", run_id="run_cli")
    _inst(
        conn,
        copy_p,
        status="blocked",
        blocking="char_filter",
        fn="gt_fn",
        sink_anchor="strcpy",
        run_id="run_cli",
    )
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


# ── CLI: lens ordering (dimension-driven), stable rank, --explain by # ──────────


def _rank_of(output: str, fn: str) -> int | None:
    for line in output.splitlines():
        if f" {fn} (" in line:
            return int(line.split()[0])
    return None


def _first_data_fn(output: str) -> str | None:
    # the first row after the column header line (header names the sink(impact) column)
    lines = output.splitlines()
    for i, line in enumerate(lines):
        if line.lstrip().startswith("#") and "sink(impact)" in line:
            return lines[i + 1].split()[-2]  # ... function (evidence_ref)
    return None


def test_cli_top_lead_floats_to_top(tmp_path: Path) -> None:
    # rc_fn (cmd + free + found) is the dimension-driven #1 and the first row, above tv_fn.
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
    # --top 1 shows the single highest-ranked candidate globally (rc_fn), not "1 per section".
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
    atlas = _seed_with_location(tmp_path)
    result = CliRunner().invoke(triage_cmd, ["run_loc", "--json", "--atlas", str(atlas)])
    assert result.exit_code == 0, result.output
    rows = json.loads(result.output)  # --json must be clean JSON (no notice framing)
    assert rows[0]["binary_path"] == "usr/sbin/webd"


def test_cli_triage_json_carries_dimensions_not_score(tmp_path: Path) -> None:
    atlas = _seed_with_location(tmp_path)
    result = CliRunner().invoke(triage_cmd, ["run_loc", "--json", "--atlas", str(atlas)])
    assert result.exit_code == 0, result.output
    rows = json.loads(result.output)
    assert "score" not in rows[0]  # the collapsed score is gone
    names = {d["name"] for d in rows[0]["dimensions"]}
    assert "controllability" in names and "sink_impact" in names
    for d in rows[0]["dimensions"]:  # every layer is a four-state fact (likely = M2 tier)
        assert d["state"] in {"proven", "likely", "excluded", "unknown"}


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
        # a data row starts with the rank number and ends with "function (evidence_ref)".
        if len(parts) >= 7 and parts[0].isdigit() and "(" in line:
            fns.append(parts[-2])
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
    assert sorted(_data_fns(cp_out.output)) == ["cp_fn0", "cp_fn1", "cp_fn2"]


def test_cli_sink_filter_surfaces_gated(tmp_path: Path) -> None:
    # A gated (blocked) system candidate is hidden by the default fold but must appear under
    # --sink system — recall stays visible by sink even when gated.
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


# ── CLI: the switchable lens (spine / view / filter) re-ranks, never reduces ──


def test_cli_sort_by_reachability_preserves_iron_law(tmp_path: Path) -> None:
    # Switching the spine to reachability must NOT bury an unknown-reachability candidate: the only
    # thing that ever sinks is a proven-safe (constant) controllability, under EVERY spine.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp", sink_class="cmd", source_class="external_input")
    _inst(conn, p, fn="found_lead", entry_reach="entry:web", run_id="run_s")
    _inst(conn, p, fn="unknown_lead", entry_reach="unknown", run_id="run_s")
    conn.close()
    atlas = tmp_path / "atlas.db"
    out = CliRunner().invoke(
        triage_cmd, ["run_s", "--sort-by", "reachability", "--all", "--atlas", str(atlas)]
    )
    assert out.exit_code == 0, out.output
    # both are still listed (re-ranked, never reduced); found leads, unknown is not dropped.
    assert _rank_of(out.output, "found_lead") is not None
    assert _rank_of(out.output, "unknown_lead") is not None
    assert "lens:" in out.output  # the active lens is named
    assert "spine=reachability" in out.output


def test_cli_filter_does_not_reduce_reachability(tmp_path: Path) -> None:
    # --filter controllability=free narrows the view but the underlying map is unchanged: a free
    # candidate shows, a non-free one does not appear under that filter.
    conn = _atlas(tmp_path)
    p = _pattern(conn, "fp", sink_class="cmd", source_class="external_input")
    _inst(conn, p, fn="free_lead", source_kind="free_string", run_id="run_f")
    _inst(conn, p, fn="opaque_lead", run_id="run_f")  # controllability unknown
    conn.close()
    atlas = tmp_path / "atlas.db"
    out = CliRunner().invoke(
        triage_cmd, ["run_f", "--filter", "controllability=free", "--all", "--atlas", str(atlas)]
    )
    assert out.exit_code == 0, out.output
    assert "free_lead" in out.output
    assert "opaque_lead" not in out.output
    assert "filter=controllability=free" in out.output  # the lens is labelled


# ── every preset view states WHEN to use it (and reachable-only states its honest limit) ──


def test_every_view_carries_a_when_to_use_note() -> None:
    from treasure_map.lib.query import VIEWS

    for name, preset in VIEWS.items():
        assert preset.get("desc"), f"view {name} is missing a when-to-use desc"
        assert "spine" in preset
    # reachable-only must be honest that it is a mechanistic reference (web-asset endpoint or boot
    # script), NOT call-graph reachability, and an INCOMPLETE slice (service-dispatch bridges like
    # notify_rc are unmodeled) — so an agent does not mistake it for 'all reachable candidates'.
    ro = VIEWS["reachable-only"]["desc"].lower()
    assert "web-asset" in ro
    assert "not call-graph reachability" in ro
    assert "incomplete" in ro and "notify_rc" in ro  # names the unmodeled service-dispatch gap
    assert "drops" in ro  # states that it can drop service-dispatch-only candidates
    assert "pre-auth" not in ro  # mechanistic label, never a pre-auth attack-surface claim


def test_cli_view_help_lists_when_to_use() -> None:
    result = CliRunner().invoke(triage_cmd, ["--help"])
    assert result.exit_code == 0, result.output
    out = result.output.lower()
    assert "hunt" in out  # "hunting goal" phrasing present
    assert "nvram-mediated" in out  # nvram-source usage surfaced
    assert "not call-graph reachability" in out  # reachable-only honest limit surfaced
