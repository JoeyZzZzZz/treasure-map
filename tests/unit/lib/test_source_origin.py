# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the source_origin axis — the origin fragments the lower layers already found.

Four candidates in five carry `source_kind=unknown`, yet underneath the analysis had often already
recovered something: which dispatch key routes here, which nvram accessor produced the value, which
call it came back from. Those fragments sat in the stored evidence unread. This layer turns them
into one honest fact per candidate, at READ time, writing nothing.

The load-bearing property is not what it surfaces but what it cannot touch. It is derived from
stored evidence and never writes any, so the three keys the controllability verdict reads —
sink_arg_provenance, flow_path, source_kind — are unreachable from it. The first test below is the
one that matters: the same candidate reads the same verdict with or without origin fragments.

Verified against a real atlas while building this: the Dimension tuples digest identically with the
layer present and absent, and a deliberately broken build — one where a verdict exit consults the
origin — moves a large share of candidates, so the guard is anchored independently of this code
rather than certifying itself.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow, NvramDefaultRow, WebFormFieldRow
from treasure_map.lib.atlas.writer import (
    add_instance,
    add_nvram_default_rows,
    add_web_form_field_rows,
    upsert_pattern,
)
from treasure_map.lib.query.triage import (
    _dim_controllability,
    _nvram_wrapper_names,
    source_origin,
)

_LEAD = {
    "hops": 1,
    "key": "relay",
    "mechanism": "strcmp_gate",
    "through": "FUN_0001437c",
    "via": "string_keyed_edge",
}


def _atlas(tmp_path: Path) -> sqlite3.Connection:
    return open_atlas(tmp_path / "atlas.db")


def _origin(conn: sqlite3.Connection, evidence: dict[str, Any] | None) -> dict[str, Any] | None:
    return source_origin(
        conn,
        json.dumps(evidence) if evidence is not None else None,
        wrapper_names=_nvram_wrapper_names(conn),
    )


def _nvram_source(callee: str, key: str | None) -> dict[str, Any]:
    src: dict[str, Any] = {"kind": "call_return", "callee": callee}
    if key is not None:
        src["const_args"] = [key]
    return src


# ── the invariance that makes the whole layer safe ───────────────────────────────────


_EXIT_CASES: list[tuple[str, dict[str, Any], str | None]] = [
    # (label, flow_evidence, blocking_mechanism) — one per controllability exit that can be
    # reached without seeding the SaTC cross, so the invariance is checked across the ladder
    # rather than at one point on it.
    (
        "prov_const",
        {
            "sink_arg_provenance": [
                {
                    "sink": "system",
                    "sink_idx": 0,
                    "provenance": {
                        "kind": "constant",
                        "value": "/sbin/reboot",
                        "value_kind": "literal_string",
                    },
                }
            ]
        },
        None,
    ),
    ("marker_const", {"source_kind": "unknown"}, "const_sink_arg"),
    ("marker_constrained", {"source_kind": "unknown"}, "numeric_sanitized"),
    ("charset_safe", {"source_kind": "charset_safe"}, None),
    ("free", {"source_kind": "free_string"}, None),
    ("unknown", {"source_kind": "unknown"}, None),
    (
        "wrapper_empty",
        {
            "source_kind": "unknown",
            "flow_path": {
                "sink_via_wrapper": True,
                "wrapper": {"name": "do_cmd", "wrapped_sink": "system"},
            },
        },
        None,
    ),
]


@pytest.mark.parametrize("label,evidence,blocking", _EXIT_CASES, ids=[c[0] for c in _EXIT_CASES])
def test_source_origin_never_changes_the_verdict(
    tmp_path: Path, label: str, evidence: dict[str, Any], blocking: str | None
) -> None:
    """★ THE guard. Adding origin fragments to a candidate must leave its controllability reading
    byte-identical — same state, value, source, note and evidence.

    Checked across the ladder rather than at one exit, because a leak into any one of them is a
    leak. The layer writes nothing, so this holds by construction; the test exists so that stops
    being a claim about today's code.

    MUTATION (must go RED, verified by deliberately breaking the build): make any verdict exit in
    `_controllability_reading` consult `source_origin`. On a real atlas that moved 1685 candidates
    into proven:controllable; here it changes at least the case whose evidence carries a lead."""
    conn = _atlas(tmp_path)
    try:
        without = _dim_controllability(
            conn,
            flow_evidence=json.dumps(evidence),
            sink_anchor="system",
            source_kind=evidence.get("source_kind", "unknown"),
            blocking_mechanism=blocking,
        )
        with_leads = _dim_controllability(
            conn,
            flow_evidence=json.dumps({**evidence, "reachability_leads": [_LEAD]}),
            sink_anchor="system",
            source_kind=evidence.get("source_kind", "unknown"),
            blocking_mechanism=blocking,
        )
    finally:
        conn.close()
    assert (without.state, without.value, without.source, without.note, without.evidence) == (
        with_leads.state,
        with_leads.value,
        with_leads.source,
        with_leads.note,
        with_leads.evidence,
    ), label


def test_no_verdict_moves_into_a_safe_reading(tmp_path: Path) -> None:
    # The demotion half of the same invariance, stated on its own: nothing this layer sees may
    # push a candidate INTO the two readings that sink it out of the first screen.
    conn = _atlas(tmp_path)
    try:
        for label, evidence, blocking in _EXIT_CASES:
            dim = _dim_controllability(
                conn,
                flow_evidence=json.dumps({**evidence, "reachability_leads": [_LEAD]}),
                sink_anchor="system",
                source_kind=evidence.get("source_kind", "unknown"),
                blocking_mechanism=blocking,
            )
            plain = _dim_controllability(
                conn,
                flow_evidence=json.dumps(evidence),
                sink_anchor="system",
                source_kind=evidence.get("source_kind", "unknown"),
                blocking_mechanism=blocking,
            )
            moved_in = dim.value in ("constant", "constrained") and plain.value not in (
                "constant",
                "constrained",
            )
            assert not moved_in, label
    finally:
        conn.close()


# ── what it surfaces, and how honestly ───────────────────────────────────────────────


def test_absent_when_nothing_was_resolved(tmp_path: Path) -> None:
    """No fragments yields None, not an empty list.

    Mirrors `reachability_leads`, which is absent rather than empty when there are none. An empty
    `origins: []` would read as "we looked and this value has no origin", which is the opposite of
    what an unresolved candidate means."""
    conn = _atlas(tmp_path)
    try:
        assert _origin(conn, {"source_kind": "unknown"}) is None
        assert _origin(conn, None) is None
        assert _origin(conn, {"sink_arg_provenance": []}) is None
    finally:
        conn.close()


def test_dispatch_origin_carries_the_leads_real_fields(tmp_path: Path) -> None:
    """The lead's OWN field names, read off real data rather than inferred.

    ★ This is pinned because it was got wrong twice on paper: a lead carries
    `hops / key / mechanism / through / via` and nothing else — no `binary`, no `from_function`, no
    `callees`. Reading a field that does not exist yields a silent None, so a projection built on
    guessed names looks like it works and quietly surfaces nulls.

    Note `via` on a lead means the lead's own kind (`string_keyed_edge`), NOT the dispatch
    mechanism — hence `lead_via`, so the two cannot be confused by a consumer."""
    conn = _atlas(tmp_path)
    try:
        out = _origin(conn, {"reachability_leads": [_LEAD]})
    finally:
        conn.close()
    assert out is not None
    (origin,) = out["origins"]
    assert origin == {
        "axis": "dispatch",
        "endpoint": "relay",
        "mechanism": "strcmp_gate",
        "through": "FUN_0001437c",
        "lead_via": "string_keyed_edge",
        "hops": 1,
    }


def test_nvram_origin_names_the_key_and_says_so_when_it_cannot(tmp_path: Path) -> None:
    # A recognised accessor whose key argument resolved to a constant names it. One whose key did
    # not resolve still surfaces — "an nvram value, key unknown" is a usable lead, and dropping it
    # would read as "no nvram involved".
    conn = _atlas(tmp_path)
    try:
        named = _origin(
            conn,
            {
                "sink_arg_provenance": [
                    {"sink": "system", "provenance": _nvram_source("nvram_get", "wan_proto")}
                ]
            },
        )
        unnamed = _origin(
            conn,
            {
                "sink_arg_provenance": [
                    {"sink": "system", "provenance": _nvram_source("nvram_get", None)}
                ]
            },
        )
    finally:
        conn.close()
    assert named is not None and unnamed is not None
    assert named["origins"][0]["axis"] == "nvram"
    assert named["origins"][0]["key"] == "wan_proto"
    assert "note" not in named["origins"][0]
    assert unnamed["origins"][0]["key"] is None
    assert "not a resolved constant" in unnamed["origins"][0]["note"]


def test_nvram_origin_found_inside_a_writer_vararg(tmp_path: Path) -> None:
    # Where an nvram value actually enters: snprintf("...%s", nvram_get(key)) into the sink buffer.
    # Walking only the record's top-level provenance would miss the common case entirely.
    conn = _atlas(tmp_path)
    try:
        out = _origin(
            conn,
            {
                "sink_arg_provenance": [
                    {
                        "sink": "system",
                        "provenance": {
                            "kind": "stack_buf",
                            "writers": [
                                {
                                    "writer": "snprintf@0x1",
                                    "dominates_sink": True,
                                    "fmt": "route %s",
                                    "varargs": [
                                        {
                                            "pos": 3,
                                            "spec": "%s",
                                            "source": _nvram_source("nvram_get", "lan_ipaddr"),
                                        }
                                    ],
                                }
                            ],
                        },
                    }
                ]
            },
        )
    finally:
        conn.close()
    assert out is not None
    assert out["origins"][0] == {
        "axis": "nvram",
        "key": "lan_ipaddr",
        "accessor": "nvram_get",
        "via_wrapper": None,
    }


def test_call_return_origin_is_stated_unresolved(tmp_path: Path) -> None:
    """A call nobody has classified is still an origin — and is marked unresolved rather than
    dressed up. Real data makes the point: the commonest such callees are `get_wanx_ifname`,
    `dcgettext`, `strsep`. Naming where a value came back from is a lead; deciding what that means
    is the reader's, and `resolved: false` is what keeps the two apart."""
    conn = _atlas(tmp_path)
    try:
        out = _origin(
            conn,
            {
                "sink_arg_provenance": [
                    {
                        "sink": "system",
                        "provenance": {"kind": "call_return", "callee": "get_wanx_ifname"},
                    }
                ]
            },
        )
    finally:
        conn.close()
    assert out is not None
    assert out["origins"][0] == {
        "axis": "call_return",
        "callee": "get_wanx_ifname",
        "resolved": False,
    }


def test_cross_reference_states_membership_not_control(tmp_path: Path) -> None:
    """The cross-reference says a NAME APPEARS IN A TABLE, and is named to say only that.

    A key that appears in the nvram defaults, or an endpoint that matches a web form field, is a
    thread worth pulling — it is not the proven front-to-back cross the controllability layer makes
    on its own terms. Calling the field `web_settable` would let a consumer read a name collision
    as a verdict, which is exactly the confusion this layer must not add.

    MUTATION (must go RED): rename either flag to a control-claiming name, or set it for a name
    absent from the table."""
    conn = _atlas(tmp_path)
    try:
        add_nvram_default_rows(
            conn,
            [
                NvramDefaultRow(
                    source_run_id="run_1",
                    key="wan_proto",
                    default_value="dhcp",
                    flags=0,
                    member_index=0,
                    binary="libshared",
                )
            ],
        )
        add_web_form_field_rows(
            conn,
            [
                WebFormFieldRow(
                    source_run_id="run_1",
                    field_keyword="relay",
                    source_asset="Advanced.asp",
                    source_rule="input",
                )
            ],
        )
        hit = _origin(
            conn,
            {
                "reachability_leads": [_LEAD],
                "sink_arg_provenance": [
                    {"sink": "system", "provenance": _nvram_source("nvram_get", "wan_proto")}
                ],
            },
        )
        miss = _origin(
            conn,
            {
                "sink_arg_provenance": [
                    {"sink": "system", "provenance": _nvram_source("nvram_get", "never_seen_key")}
                ]
            },
        )
    finally:
        conn.close()
    assert hit is not None and miss is not None
    by_axis = {o["axis"]: o for o in hit["origins"]}
    assert by_axis["nvram"]["name_in_nvram_defaults"] is True
    assert by_axis["dispatch"]["name_in_web_form_fields"] is True
    # a control-claiming spelling must not exist on any origin
    for origin in hit["origins"]:
        assert not any("settable" in k or "controllable" in k for k in origin)
    # and a name that is NOT in either table gets no flag at all
    assert "name_in_nvram_defaults" not in miss["origins"][0]
    assert "name_in_web_form_fields" not in miss["origins"][0]


def test_completeness_note_always_rides_along(tmp_path: Path) -> None:
    # The list is resolved-only and must never read as exhaustive: one hop, intra-procedural, and
    # blind to dispatch forms the extractor does not recognise. An origin missing from it was not
    # ruled out — it was not recovered.
    conn = _atlas(tmp_path)
    try:
        out = _origin(conn, {"reachability_leads": [_LEAD]})
    finally:
        conn.close()
    assert out is not None
    assert out["completeness"] == "resolved_only"
    assert "not an exhaustive list" in out["note"]
    assert "was NOT ruled out" in out["note"]


def test_surfaced_by_both_consumers(tmp_path: Path) -> None:
    # The point of the layer is that an agent meets it. Both read paths carry it.
    from treasure_map.lib.query import explain_candidate, get_sink_provenance

    conn = _atlas(tmp_path)
    try:
        pid = upsert_pattern(
            conn,
            source_class="unknown",
            sink_class="cmd",
            call_sequence_shape="s->cmd",
            structural_fingerprint="fp_origin",
            fingerprint_algo_version="callseq-v1",
        )
        evidence = {
            "source_kind": "unknown",
            "reachability_leads": [_LEAD],
            "sink_arg_provenance": [
                {
                    "sink": "system",
                    "sink_idx": 0,
                    "provenance": _nvram_source("nvram_get", "wan_proto"),
                }
            ],
        }
        add_instance(
            conn,
            InstanceRow(
                pattern_id=pid,
                pseudocode_hash="h1",
                source_anchor="fn",
                sink_anchor="system",
                source_run_id="run_1",
                reachability_status="unknown",
                blocking_mechanism=None,
                provenance_level="L0",
                evidence_ref="run_1#fn@cmd",
                scope_origin="intra",
                origin="unknown",
                flow_evidence=json.dumps(evidence),
            ),
        )
        prov = get_sink_provenance(conn, "run_1#fn@cmd")
        ex = explain_candidate(conn, "run_1#fn@cmd")
    finally:
        conn.close()
    assert prov["source_origin"]["origins"]
    assert ex is not None and ex.source_origin is not None
    assert {o["axis"] for o in ex.source_origin["origins"]} == {"dispatch", "nvram"}
