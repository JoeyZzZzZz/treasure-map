# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for sink_arg_provenance surfacing (design: the Ghidra def-use fact of where a
command/format sink's argument comes from, merged into flow_evidence and read back by the triage
explain summary + the get_sink_provenance detail tool).

Covers: one compact summary entry per sink (summary-first, no full writer set inline); every source
kind's summary shape; get_sink_provenance returns the full writers/fmt/vararg detail (and reports
unknown ref / out-of-range honestly); and the boundary invariant that an unresolved origin never
changes a candidate's score or drops it (a surfaced fact, never a verdict or a score input).
"""

from __future__ import annotations

import json
from pathlib import Path

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, upsert_pattern
from treasure_map.lib.query import explain_candidate, get_sink_provenance
from treasure_map.lib.query.triage import _sink_provenance_summary

# One representative record per source kind (the JSON contract ExportFunctions emits).
_PROV = [
    {
        "sink_idx": 0,
        "sink": "system",
        "sink_addr": "0x100",
        "arg_idx": 0,
        "provenance": {"kind": "constant", "value": "reboot"},
    },
    {
        "sink_idx": 1,
        "sink": "system",
        "sink_addr": "0x200",
        "arg_idx": 0,
        "provenance": {"kind": "call_return", "callee": "nvram_get", "const_args": ["lan_ifname"]},
    },
    {
        "sink_idx": 2,
        "sink": "popen",
        "sink_addr": "0x300",
        "arg_idx": 0,
        "provenance": {"kind": "param", "name": "param_1"},
    },
    {
        "sink_idx": 3,
        "sink": "system",
        "sink_addr": "0x400",
        "arg_idx": 0,
        "provenance": {
            "kind": "stack_buf",
            "stack_key": "frame[84]+0x10",
            "writer_count": 2,
            "nearest_dominating_writer": "snprintf@0x3f0",
            "writers": [
                {
                    "writer": "snprintf@0x3f0",
                    "dominates_sink": True,
                    "fmt": "run %s",
                    "varargs": [
                        {"pos": 2, "spec": "%s", "source": {"kind": "param", "name": "param_2"}}
                    ],
                },
                {"writer": "snprintf@0x2a0", "dominates_sink": False, "fmt": "cfg", "varargs": []},
            ],
            "attribution": "chk_dominance",
        },
    },
    {
        "sink_idx": 4,
        "sink": "fprintf",
        "sink_addr": "0x500",
        "arg_idx": 1,
        "provenance": {"kind": "global_buf", "data_ref": "DAT_00080", "text": "%s"},
    },
    {
        "sink_idx": 5,
        "sink": "system",
        "sink_addr": "0x600",
        "arg_idx": 0,
        "provenance": {
            "kind": "multiple",
            "sources": [{"kind": "constant", "value": "a"}, {"kind": "param", "name": "p"}],
        },
    },
    {
        "sink_idx": 6,
        "sink": "system",
        "sink_addr": "0x700",
        "arg_idx": 0,
        "provenance": {
            "kind": "tokenizer_output",
            "tokenizer": "strtok_r@0x6f0",
            "input_source": {"kind": "call_return", "callee": "strsep", "const_args": []},
            "sink_to_token": "resolved",
        },
    },
    {
        "sink_idx": 7,
        "sink": "system",
        "sink_addr": "0x800",
        "arg_idx": 0,
        "provenance": {
            "kind": "indirect_unresolved",
            "reason": "call_clobbered_stack_slot",
            "last_writer": "strtok_r@0x7f0",
        },
    },
]


def _seed(
    tmp_path: Path,
    *,
    ref: str = "run_x#fn7@cmd",
    provenance: list[dict[str, object]] | None = _PROV,
    source_kind: str = "free_string",
    status: str = "confirmed",
) -> Path:
    """Seed one atlas instance whose flow_evidence carries the given sink_arg_provenance list."""
    conn = open_atlas(tmp_path / "atlas.db")
    p = upsert_pattern(
        conn,
        source_class="external_input",
        sink_class="cmd",
        call_sequence_shape="source->cmd",
        structural_fingerprint="fp",
        fingerprint_algo_version="callseq-v1",
    )
    ev: dict[str, object] = {"source_kind": source_kind}
    if provenance is not None:
        ev["sink_arg_provenance"] = provenance
    add_instance(
        conn,
        InstanceRow(
            pattern_id=p,
            pseudocode_hash="h1",
            source_anchor="fn_handle",
            sink_anchor="system",
            source_run_id="run_x",
            reachability_status=status,
            blocking_mechanism=None,
            provenance_level="L1" if status in {"confirmed", "blocked"} else "L0",
            evidence_ref=ref,
            scope_origin="intra",
            origin="unknown",
            flow_evidence=json.dumps(ev, sort_keys=True),
        ),
    )
    conn.close()
    return tmp_path / "atlas.db"


# ── summary-first: one compact entry per sink; no full writer set inline ─────────────


def test_explain_summary_one_entry_per_sink_and_compact(tmp_path: Path) -> None:
    atlas = _seed(tmp_path)
    conn = open_atlas(atlas)
    try:
        ex = explain_candidate(conn, "run_x#fn7@cmd")
    finally:
        conn.close()
    assert ex is not None
    summary = ex.sink_arg_provenance_summary
    assert len(summary) == len(_PROV)  # one entry per sink
    for s in summary:
        # summary carries the routing keys + kind + resolved, never the heavy writer/vararg detail
        assert set(s).issubset(
            {
                "sink_idx",
                "sink",
                "sink_addr",
                "kind",
                "resolved",
                "writer_count",
                "nearest_dominating_writer",
            }
        )
        assert "writers" not in s
        assert "varargs" not in s
    # the stack_buf sink surfaces the sound nearest dominating writer in the summary
    sb = next(s for s in summary if s["kind"] == "stack_buf")
    assert sb["nearest_dominating_writer"] == "snprintf@0x3f0"
    assert sb["writer_count"] == 2


def test_summary_kind_and_resolved_per_kind(tmp_path: Path) -> None:
    summary = _sink_provenance_summary(json.dumps({"sink_arg_provenance": _PROV}))
    by_idx = {s["sink_idx"]: s for s in summary}
    assert by_idx[0]["kind"] == "constant" and by_idx[0]["resolved"] is True
    assert by_idx[1]["kind"] == "call_return"
    assert by_idx[2]["kind"] == "param"
    assert by_idx[3]["kind"] == "stack_buf" and by_idx[3]["resolved"] is True
    assert by_idx[4]["kind"] == "global_buf"
    assert by_idx[5]["kind"] == "multiple"
    assert by_idx[6]["kind"] == "tokenizer_output"
    # the honest boundary: unresolved is reported as resolved=False, NOT dropped or hidden
    assert by_idx[7]["kind"] == "indirect_unresolved" and by_idx[7]["resolved"] is False


def test_absent_provenance_yields_empty_summary(tmp_path: Path) -> None:
    atlas = _seed(tmp_path, provenance=None)
    conn = open_atlas(atlas)
    try:
        ex = explain_candidate(conn, "run_x#fn7@cmd")
    finally:
        conn.close()
    assert ex is not None
    assert ex.sink_arg_provenance_summary == ()


# ── on-demand full detail via get_sink_provenance ───────────────────────────────────


def test_get_sink_provenance_returns_full_writer_detail(tmp_path: Path) -> None:
    atlas = _seed(tmp_path)
    conn = open_atlas(atlas)
    try:
        one = get_sink_provenance(conn, "run_x#fn7@cmd", 3)
        allrecs = get_sink_provenance(conn, "run_x#fn7@cmd")
    finally:
        conn.close()
    assert one["found"] is True and one["sink_idx"] == 3
    prov = one["record"]["provenance"]
    # the heavy detail summary-first omitted is present here in full
    assert prov["kind"] == "stack_buf"
    assert len(prov["writers"]) == 2
    dom = next(w for w in prov["writers"] if w["dominates_sink"])
    assert dom["writer"] == "snprintf@0x3f0" and dom["fmt"] == "run %s"
    assert dom["varargs"][0]["spec"] == "%s"
    assert allrecs["found"] is True and len(allrecs["records"]) == len(_PROV)


def test_get_sink_provenance_unknown_ref_and_out_of_range(tmp_path: Path) -> None:
    atlas = _seed(tmp_path)
    conn = open_atlas(atlas)
    try:
        miss = get_sink_provenance(conn, "run_x#nope", 0)
        oob = get_sink_provenance(conn, "run_x#fn7@cmd", 99)
    finally:
        conn.close()
    assert miss["found"] is False and miss["note"] == "no_such_evidence_ref"
    assert oob["found"] is False and oob["note"] == "sink_idx_out_of_range"
    assert 7 in oob["available_sink_idx"]


def test_get_sink_provenance_no_provenance_reported_honestly(tmp_path: Path) -> None:
    atlas = _seed(tmp_path, provenance=None)
    conn = open_atlas(atlas)
    try:
        res = get_sink_provenance(conn, "run_x#fn7@cmd")
    finally:
        conn.close()
    assert res["found"] is False and res["note"] == "no_sink_provenance"


# ── the non-scoring boundary invariant: provenance never changes score or drops a lead ──


def test_unresolved_provenance_does_not_change_score_or_drop(tmp_path: Path) -> None:
    # Two candidates identical in every scoring input, differing ONLY in provenance: one fully
    # resolved (stack_buf with a dominating writer), one fully unresolved.
    resolved = [_PROV[3]]  # stack_buf, resolved
    unresolved = [_PROV[7]]  # indirect_unresolved

    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    _seed(a, provenance=resolved)
    _seed(b, provenance=unresolved)

    ca = open_atlas(a / "atlas.db")
    cb = open_atlas(b / "atlas.db")
    try:
        ex_a = explain_candidate(ca, "run_x#fn7@cmd")
        ex_b = explain_candidate(cb, "run_x#fn7@cmd")
    finally:
        ca.close()
        cb.close()
    assert ex_a is not None and ex_b is not None
    # provenance resolution must not move the review score
    assert ex_a.score == ex_b.score
    assert ex_a.raw_score == ex_b.raw_score
    # and the unresolved candidate is still a surfaced lead (never silently dropped)
    assert ex_b.sink_arg_provenance_summary[0]["resolved"] is False


def test_provenance_is_not_a_score_component(tmp_path: Path) -> None:
    atlas = _seed(tmp_path)
    conn = open_atlas(atlas)
    try:
        ex = explain_candidate(conn, "run_x#fn7@cmd")
    finally:
        conn.close()
    assert ex is not None
    # no score component is derived from provenance — it is evidence, not a weighted signal
    signals = " ".join(c.signal for c in ex.components).lower()
    assert "provenance" not in signals
    assert "writer" not in signals
