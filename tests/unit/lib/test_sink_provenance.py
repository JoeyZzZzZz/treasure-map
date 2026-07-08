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
from typing import Any

import pytest

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, upsert_pattern
from treasure_map.lib.query import explain_candidate, get_sink_provenance
from treasure_map.lib.query.triage import (
    _fmt_arity,
    _is_proven_safe,
    _sink_provenance_summary,
    _writer_args_class,
)

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
                "dominating_writer_count",
                "nearest_dominating_writer",
                "nearest_dominating_writer_fmt",
                "fmt_args_provenance",
            }
        )
        assert "writers" not in s
        assert "varargs" not in s
    # the stack_buf sink surfaces the sound nearest dominating writer in the summary
    sb = next(s for s in summary if s["kind"] == "stack_buf")
    assert sb["nearest_dominating_writer"] == "snprintf@0x3f0"
    assert sb["writer_count"] == 2


def test_summary_kind_and_resolved_per_kind(tmp_path: Path) -> None:
    conn = open_atlas(tmp_path / "atlas.db")
    summary = _sink_provenance_summary(conn, json.dumps({"sink_arg_provenance": _PROV}))
    conn.close()
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


def test_call_return_unresolved_args_flag_survives_to_agent(tmp_path: Path) -> None:
    # Honesty (缺口 A): a getter callsite with a non-constant argument omits it from const_args
    # but flags has_unresolved_args + arg_count (ExportFunctions). The read side must pass BOTH
    # through verbatim so the agent never reads const_args as the FULL argument list — e.g.
    # custom_get("some_key", param_2) where param_2 is caller-controlled.
    prov = [
        {
            "sink_idx": 0,
            "sink": "system",
            "sink_addr": "0x100",
            "arg_idx": 0,
            "provenance": {
                "kind": "call_return",
                "callee": "custom_get",
                "const_args": ["some_key"],
                "arg_count": 2,
                "has_unresolved_args": True,
            },
        }
    ]
    atlas = _seed(tmp_path, provenance=prov)
    conn = open_atlas(atlas)
    try:
        full = get_sink_provenance(conn, "run_x#fn7@cmd", 0)
    finally:
        conn.close()
    assert full["found"] is True
    p = full["record"]["provenance"]
    assert p["kind"] == "call_return" and p["const_args"] == ["some_key"]
    # the honesty signals are NOT dropped by the read-side presentation
    assert p["arg_count"] == 2
    assert p["has_unresolved_args"] is True


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


def test_unresolved_provenance_feeds_writer_layer_never_sinks_or_drops(tmp_path: Path) -> None:
    # Two candidates identical except provenance: one resolved (stack_buf + dominating writer), one
    # fully unresolved. Provenance feeds the WRITER dimension, not a score.
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
    # resolution moves the WRITER layer (located vs not_traced), not a collapsed score.
    assert ex_a.candidate.dim("writer").value == "located"
    assert ex_b.candidate.dim("writer").value == "not_traced"
    # an unresolved writer is a '?' — a coverage gap that NEVER sinks the candidate.
    assert ex_b.candidate.dim("writer").state == "unknown"
    assert not _is_proven_safe(ex_a.candidate) and not _is_proven_safe(ex_b.candidate)
    # and the unresolved candidate is still a surfaced lead (never silently dropped)
    assert ex_b.sink_arg_provenance_summary[0]["resolved"] is False


def test_provenance_is_surfaced_as_writer_layer_not_a_score(tmp_path: Path) -> None:
    atlas = _seed(tmp_path)
    conn = open_atlas(atlas)
    try:
        ex = explain_candidate(conn, "run_x#fn7@cmd")
    finally:
        conn.close()
    assert ex is not None
    # provenance is EVIDENCE surfaced as the writer dimension (a three-state fact), never a weight.
    writer = ex.candidate.dim("writer")
    assert writer.name == "writer"
    assert writer.value in {"located", "via_wrapper", "not_traced"}
    assert writer.state in {"proven", "unknown"}
    # there is no collapsed score / weighted component anywhere on the explanation.
    assert not hasattr(ex, "components")
    assert not hasattr(ex, "score")


# ── polish: readability of a reused-buffer stack_buf (dominating count / inline fmt / ordering /
#    fmt-arity vararg trim) ───────────────────────────────────────────────────────────────────

# A reused scratch buffer: 16 writers, only 3 sound-dominating (placed AFTER the noise to exercise
# reordering). The nearest dominating writer carries an echo fmt with 2 conversions but 4 varargs
# (the last two are uninitialized-slot noise, to exercise the fmt-arity trim).
_NEAREST = "snprintf@0x0f0"
_STACK16 = [
    {
        "sink_idx": 0,
        "sink": "system",
        "sink_addr": "0x100",
        "arg_idx": 0,
        "provenance": {
            "kind": "stack_buf",
            "stack_key": "frame[84]+0x10",
            "writer_count": 16,
            "nearest_dominating_writer": _NEAREST,
            "writers": (
                [
                    {
                        "writer": f"snprintf@0x{i:03x}",
                        "dominates_sink": False,
                        "fmt": "noise",
                        "varargs": [],
                    }
                    for i in range(1, 14)  # 13 mutually-exclusive branch writers (noise)
                ]
                + [
                    {"writer": "snprintf@0x0a0", "dominates_sink": True, "fmt": "a", "varargs": []},
                    {"writer": "snprintf@0x0c0", "dominates_sink": True, "fmt": "b", "varargs": []},
                    {
                        "writer": _NEAREST,
                        "dominates_sink": True,
                        "fmt": "echo %s to %s",
                        "varargs": [
                            {"pos": 3, "spec": "%s", "source": {"kind": "constant", "value": "x"}},
                            {"pos": 4, "spec": "%s", "source": {"kind": "param", "name": "p"}},
                            {"pos": 5, "source": {"kind": "indirect_unresolved"}},  # past arity
                            {"pos": 6, "source": {"kind": "indirect_unresolved"}},  # past arity
                        ],
                    },
                ]
            ),
            "attribution": "chk_dominance",
        },
    }
]


def test_summary_has_dominating_writer_count(tmp_path: Path) -> None:
    # 16 raw writers but only 3 sound-dominating — the summary must show both so a high writer_count
    # reads as "resolved to 3", not "ambiguous among 16".
    conn = open_atlas(tmp_path / "atlas.db")
    summary = _sink_provenance_summary(conn, json.dumps({"sink_arg_provenance": _STACK16}))
    conn.close()
    s = summary[0]
    assert s["writer_count"] == 16
    assert s["dominating_writer_count"] == 3


def test_summary_inlines_only_nearest_dominating_fmt(tmp_path: Path) -> None:
    conn = open_atlas(tmp_path / "atlas.db")
    summary = _sink_provenance_summary(conn, json.dumps({"sink_arg_provenance": _STACK16}))
    conn.close()
    s = summary[0]
    # the nearest dominating writer's fmt is inlined (judge controllability with zero extra fetch)
    assert s["nearest_dominating_writer_fmt"] == "echo %s to %s"
    # summary-first: no full writer list / other writers' fmts leak into the summary
    assert "writers" not in s
    assert "b" not in s.values()  # a different writer's fmt is not present


def test_get_sink_provenance_dominating_first_and_only(tmp_path: Path) -> None:
    atlas = _seed(tmp_path, provenance=_STACK16, ref="run_x#fn7@cmd")
    conn = open_atlas(atlas)
    try:
        full = get_sink_provenance(conn, "run_x#fn7@cmd", 0)
        only = get_sink_provenance(conn, "run_x#fn7@cmd", 0, dominating_only=True)
    finally:
        conn.close()
    fw = full["record"]["provenance"]["writers"]
    assert len(fw) == 16
    # the 3 dominating writers lead the array (read the sound ones without scanning to the tail)
    assert [w["dominates_sink"] for w in fw[:3]] == [True, True, True]
    assert all(not w["dominates_sink"] for w in fw[3:])
    ow = only["record"]["provenance"]["writers"]
    assert len(ow) == 3 and all(w["dominates_sink"] for w in ow)


def test_get_sink_provenance_trims_varargs_to_fmt_arity(tmp_path: Path) -> None:
    atlas = _seed(tmp_path, provenance=_STACK16, ref="run_x#fn7@cmd")
    conn = open_atlas(atlas)
    try:
        one = get_sink_provenance(conn, "run_x#fn7@cmd", 0, dominating_only=True)
    finally:
        conn.close()
    nearest = next(w for w in one["record"]["provenance"]["writers"] if w["writer"] == _NEAREST)
    # 'echo %s to %s' consumes 2 args; the 2 noise varargs past arity are dropped, marked honestly
    assert len(nearest["varargs"]) == 2
    assert nearest["varargs_trimmed_to_fmt_arity"] is True
    assert [v["spec"] for v in nearest["varargs"]] == ["%s", "%s"]


def test_fmt_arity_counts_conversions_and_star_args() -> None:
    assert _fmt_arity("echo %s to %s") == 2
    assert _fmt_arity("%d%% done %s") == 2  # %% is a literal, not an argument
    assert _fmt_arity("%*d") == 2  # width from an argument + the value
    assert _fmt_arity("plain text") == 0
    assert _fmt_arity("%05.2f %-10s") == 2


# ── _writer_args_class: the SINGLE classifier (const / controllable / unknown), value_kind-aware ─
# This is where the single verdict's de-optimism is pinned: a bare call_return / param is NO LONGER
# controllable (only a web-settable key or a named external reader is). Uses an EMPTY atlas conn —
# no web-settable keys — so a getter's key reads as uncertain, never a false 'controllable'.


@pytest.fixture
def acon(tmp_path: Path) -> Any:
    conn = open_atlas(tmp_path / "atlas.db")
    yield conn
    conn.close()


def _lit(value: str, spec: str = "%s") -> dict[str, Any]:  # confirmed literal-string constant
    src = {"kind": "constant", "value": value, "value_kind": "literal_string"}
    return {"spec": spec, "source": src}


def _amb(spec: str, value: str = "0x432f") -> dict[str, Any]:  # ambiguous_0x constant
    src = {"kind": "constant", "value": value, "value_kind": "ambiguous_0x"}
    return {"spec": spec, "source": src}


def _src(kind: str, spec: str = "%s", **extra: Any) -> dict[str, Any]:  # a vararg of a source kind
    return {"spec": spec, "source": {"kind": kind, **extra}}


def test_wac_all_literal_strings_is_const(acon: Any) -> None:
    assert _writer_args_class(acon, "%s to %s", [_lit("wl"), _lit("down")]) == "const"


def test_wac_no_varargs_literal_fmt_is_const(acon: Any) -> None:
    assert _writer_args_class(acon, "reboot now", []) == "const"


def test_wac_bare_call_return_and_param_are_unknown_not_controllable(acon: Any) -> None:
    # THE de-optimism: an arbitrary call_return (getpid-shape) or a bare param is NOT controllable.
    assert _writer_args_class(acon, "%s", [_src("call_return")]) == "unknown"
    assert _writer_args_class(acon, "run %s", [_src("param")]) == "unknown"


def test_wac_named_external_reader_is_controllable(acon: Any) -> None:
    # A named external input (getenv / recv) IS controllable — the legit 'free' is not downgraded.
    assert _writer_args_class(acon, "%s", [_src("call_return", callee="getenv")]) == "controllable"
    assert _writer_args_class(acon, "%s", [_src("external_input")]) == "controllable"


def test_wac_unresolved_and_stack_buf_are_unknown(acon: Any) -> None:
    assert _writer_args_class(acon, "%s", [_src("unresolved")]) == "unknown"
    assert _writer_args_class(acon, "%s", [_src("stack_buf")]) == "unknown"


def test_wac_ambiguous0x_under_integer_spec_is_const(acon: Any) -> None:
    # %d + ambiguous_0x = a known INTEGER literal (value pinned by the spec) -> const.
    assert (
        _writer_args_class(acon, "[%s:(%d)]", [_lit("handle_notifications"), _amb("%d", "0x432f")])
        == "const"
    )
    assert _writer_args_class(acon, "%x", [_amb("%x", "0xf002")]) == "const"


def test_wac_ambiguous0x_under_string_spec_is_unknown(acon: Any) -> None:
    # %s + ambiguous_0x = a constant POINTER, pointee unknown -> unknown (the red line).
    assert _writer_args_class(acon, "%s", [_amb("%s", "0x1525f0")]) == "unknown"


def test_wac_ambiguous0x_with_no_spec_is_unknown(acon: Any) -> None:
    va = {"source": {"kind": "constant", "value": "0x1234", "value_kind": "ambiguous_0x"}}
    assert _writer_args_class(acon, "%s and more", [va]) == "unknown"


def test_wac_arity_shortfall_is_unknown(acon: Any) -> None:
    assert _writer_args_class(acon, "%s and %s", [_lit("only_one")]) == "unknown"


def test_wac_controllable_wins_over_unknown(acon: Any) -> None:
    assert (
        _writer_args_class(acon, "%s %s", [_src("external_input"), _src("unresolved")])
        == "controllable"
    )


def test_wac_missing_source_is_unknown(acon: Any) -> None:
    assert _writer_args_class(acon, "%s", [{"spec": "%s"}]) == "unknown"


def test_wac_bare_0x_without_value_kind_falls_back(acon: Any) -> None:
    amb_d = {"spec": "%d", "source": {"kind": "constant", "value": "0x432f"}}  # no value_kind
    amb_s = {"spec": "%s", "source": {"kind": "constant", "value": "0x1525f0"}}  # no value_kind
    assert _writer_args_class(acon, "%d", [amb_d]) == "const"  # %d -> integer
    assert _writer_args_class(acon, "%s", [amb_s]) == "unknown"  # %s -> pointer, unknown


def test_get_sink_provenance_detail_surfaces_value_kind(tmp_path: Path) -> None:
    # Part 3 honesty: the detail view must pass value_kind through, so an agent reading a vararg's
    # source sees "this 0x is int-or-pointer undecided", not a bare constant it misreads as certain.
    prov = [
        {
            "sink_idx": 0,
            "sink": "system",
            "sink_addr": "0x100",
            "arg_idx": 0,
            "provenance": {
                "kind": "stack_buf",
                "nearest_dominating_writer": "snprintf@0xa0",
                "writers": [
                    {
                        "writer": "snprintf@0xa0",
                        "dominates_sink": True,
                        "fmt": "[%d]",
                        "varargs": [_amb("%d", "0x432f")],
                    }
                ],
            },
        }
    ]
    atlas = _seed(tmp_path, provenance=prov, ref="run_x#fn7@cmd")
    conn = open_atlas(atlas)
    try:
        detail = get_sink_provenance(conn, "run_x#fn7@cmd", 0)
    finally:
        conn.close()
    va = detail["record"]["provenance"]["writers"][0]["varargs"][0]
    assert va["source"]["value_kind"] == "ambiguous_0x"  # not stripped — the limitation is visible
