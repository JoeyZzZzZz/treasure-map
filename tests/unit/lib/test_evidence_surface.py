# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for evidence_surface — the length / format / exec-shape facts nobody read.

Three analyses run for every candidate and write their result into the stored evidence. Part is
consumed by the controllability verdict; the rest is produced and read by nobody. Confirmed against
the tree: the query layer greps ZERO for size_kind, size_flow, clamp_seen, trace_boundary,
fmt_arg_pos and fmt_arg_literal, and of the form notes the producers emit, three
(no_shell_exec, clamp_size, pointer_guard_size) appear in no marker set the verdict reads.

Two of these facts are shaped like reassurance and are not, which is why the wording is the safety
property here rather than a nicety:

  * a clamp SHAPE is not a limit — the producer stamps every one it records `coverage: unjudged`
    because it did not decide whether the shape restricts the write. Nothing downstream reads a
    clamp, so this surface is the first and only place in the chain where "a limit was checked"
    could be asserted.
  * `no_shell_exec` is not "no command injection" — it says the command runs without a shell, so
    shell metacharacters stop mattering while the argv and the program path do not.

Checked against a real atlas while building this: the Dimension digest is identical with the
layer present and absent, and both deliberately-broken builds move it — wiring a clamp into a
verdict gate turns constrained readings into a large multiple of themselves, and adding
no_shell_exec to the constant markers calls more candidates constant. So the invariance check is
anchored independently of this code rather than certifying itself.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, upsert_pattern
from treasure_map.lib.pattern.classes import FMT_STRING, FMT_STRING_ARG
from treasure_map.lib.query.sink_impact import CONSTRAINED_MARKERS, PROVABLY_CONSTANT_MARKERS
from treasure_map.lib.query.triage import _dim_controllability, evidence_surface

# Words that would turn a shape into a promise. Kept out of the output entirely — not even inside a
# disclaimer — so that searching for them over this layer's output is a meaningful check instead of
# one that trips over its own negations.
_REASSURING = ("safe", "bounded", "not injectable", "no injection", "secure", "mitigat")

_CLAMP_EVIDENCE = {
    "size_kind": "clamp",
    "size_flow": {"size_arg": "sVar2", "size_var": "sVar2", "one_hop": ["param_1"]},
    "clamp_seen": [{"coverage": "unjudged", "shape": "if (CONST <= v)"}],
    "trace_boundary": "copy_alias_untraced",
}


def _surface(evidence: dict[str, Any] | None, sink_class: str, marker: str | None = None):  # type: ignore[no-untyped-def]
    return evidence_surface(
        json.dumps(evidence) if evidence is not None else None, sink_class, marker
    )


# ── the invariance that lets this layer exist at all ─────────────────────────────────


_VERDICT_CASES: list[tuple[str, dict[str, Any], str | None]] = [
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
    ("exec_shape", {"source_kind": "unknown"}, "no_shell_exec"),
]


@pytest.mark.parametrize(
    "label,evidence,marker", _VERDICT_CASES, ids=[c[0] for c in _VERDICT_CASES]
)
def test_surfaced_facts_never_change_the_verdict(
    tmp_path: Path, label: str, evidence: dict[str, Any], marker: str | None
) -> None:
    """Adding the surfaced facts to a candidate leaves its controllability reading byte-identical.

    Checked across the ladder rather than at one exit, because a leak into any one of them is a
    leak. The layer is read-only and its output is handed to no verdict, so this holds by
    construction; the test exists so that stops being a claim about today's code.

    MUTATION (must go RED, verified by deliberately breaking the build): have any verdict exit
    consult the surface — reading clamp_seen there moves candidates into constrained."""
    conn = open_atlas(tmp_path / "atlas.db")
    try:
        plain = _dim_controllability(
            conn,
            flow_evidence=json.dumps(evidence),
            sink_anchor="system",
            source_kind=evidence.get("source_kind", "unknown"),
            blocking_mechanism=marker,
        )
        enriched = _dim_controllability(
            conn,
            flow_evidence=json.dumps({**evidence, **_CLAMP_EVIDENCE, "fmt_arg_pos": 1}),
            sink_anchor="system",
            source_kind=evidence.get("source_kind", "unknown"),
            blocking_mechanism=marker,
        )
    finally:
        conn.close()
    assert (plain.state, plain.value, plain.source, plain.note, plain.evidence) == (
        enriched.state,
        enriched.value,
        enriched.source,
        enriched.note,
        enriched.evidence,
    ), label


def test_no_verdict_moves_into_a_settled_reading(tmp_path: Path) -> None:
    # The demotion half: nothing surfaced here may push a candidate into the two readings that sink
    # it out of the first screen.
    conn = open_atlas(tmp_path / "atlas.db")
    try:
        for label, evidence, marker in _VERDICT_CASES:
            enriched = _dim_controllability(
                conn,
                flow_evidence=json.dumps({**evidence, **_CLAMP_EVIDENCE}),
                sink_anchor="system",
                source_kind=evidence.get("source_kind", "unknown"),
                blocking_mechanism=marker,
            )
            plain = _dim_controllability(
                conn,
                flow_evidence=json.dumps(evidence),
                sink_anchor="system",
                source_kind=evidence.get("source_kind", "unknown"),
                blocking_mechanism=marker,
            )
            moved = enriched.value in ("constant", "constrained") and plain.value not in (
                "constant",
                "constrained",
            )
            assert not moved, label
    finally:
        conn.close()


def test_orphan_form_notes_stay_out_of_every_marker_set() -> None:
    """The three form notes no verdict reads must stay unread.

    A lock on the present state rather than a discovery: they are outside the marker sets today, so
    this is green now and its job is to fail the day someone wires one in. What it would cost was
    measured — adding no_shell_exec to the constant markers makes the map call more candidates
    constant, which is the misreading this whole layer exists to prevent.

    MUTATION (must go RED): add any of the three to either marker set."""
    read = PROVABLY_CONSTANT_MARKERS | CONSTRAINED_MARKERS
    for orphan in ("no_shell_exec", "clamp_size", "pointer_guard_size"):
        assert orphan not in read, orphan


# ── copy: the length picture ─────────────────────────────────────────────────────────


def test_clamp_is_surfaced_with_the_producers_own_unjudged_marking(tmp_path: Path) -> None:
    """The clamp entries are passed through verbatim, coverage marking and all.

    Re-summarising them is exactly how "seen, not verified" would quietly become "checked" — and
    since nothing downstream reads a clamp, there is no second reader to catch it.

    MUTATION (must go RED): drop or rewrite the coverage field while copying clamp_seen across."""
    out = _surface(_CLAMP_EVIDENCE, "copy")
    assert out is not None
    assert out["clamp_seen"] == [{"coverage": "unjudged", "shape": "if (CONST <= v)"}]
    assert out["size_kind"] == "clamp"
    assert "NOT decided" in out["not_asserted"]
    blob = json.dumps(out).lower()
    assert not [w for w in _REASSURING if w in blob], blob


@pytest.mark.parametrize(
    "kind", ["const", "sizeof", "variable", "source_len", "clamp", "pointer_guard", "untraced"]
)
def test_every_length_kind_gets_a_reading_and_none_of_them_reassure(kind: str) -> None:
    # Each recorded kind says what shape was found and stops there. `untraced` in particular is the
    # absence of a fact and says so — on one real image a third of copy candidates are in it.
    out = _surface({"size_kind": kind, "clamp_seen": [], "trace_boundary": "reached_sink"}, "copy")
    assert out is not None
    assert out["reading"] and "not one this reader knows" not in out["reading"], kind
    blob = json.dumps(out).lower()
    assert not [w for w in _REASSURING if w in blob], (kind, blob)


def test_a_stopped_trace_says_it_stopped(tmp_path: Path) -> None:
    # Where the analysis ran out is reported as running out, never as nothing being there.
    stopped = _surface({"size_kind": "variable", "trace_boundary": "size_arg_untraced"}, "copy")
    reached = _surface({"size_kind": "variable", "trace_boundary": "reached_sink"}, "copy")
    assert stopped is not None and reached is not None
    assert "stopping is not a clearing" in stopped["trace_incomplete"]
    assert "trace_incomplete" not in reached


def test_copy_without_a_length_picture_is_absent_not_empty() -> None:
    """A copy candidate whose length analysis recorded nothing gets None.

    Not a shape full of nulls: `size_kind: null` invites reading a missing analysis as a finished
    one, and candidates really are in this state — it is a normal case, not a corner."""
    assert _surface({"source_kind": "unknown"}, "copy") is None
    assert _surface(None, "copy") is None


# ── fmt: the format position ─────────────────────────────────────────────────────────


def test_format_position_is_reported_and_an_unknown_one_says_unknown() -> None:
    """An unestablished format position is its own state — NOT argument 0, NOT 'no format'.

    ★ Note which state the real candidates are in: those recovered through a thin wrapper have the
    keys ABSENT, because the wrapper path runs the general evidence builder, which does not run
    format analysis at all. They return None from the surface, and never reach the position branch.
    That branch guards a different thing — the format-sink set drifting apart from the position map
    — and is pinned by the subset assertion below rather than by any candidate being in it.

    MUTATION (must go RED): default a missing fmt_arg_pos to 0."""
    known = _surface({"fmt_arg_pos": 1, "fmt_arg_literal": False}, "fmt_string")
    unknown = _surface({"fmt_arg_pos": None, "fmt_arg_literal": False}, "fmt_string")
    assert known is not None and unknown is not None
    assert known["fmt_arg_pos"] == 1 and "argument 1" in known["reading"]
    assert unknown["fmt_arg_pos"] is None
    assert "NOT established" in unknown["reading"]
    # ★ the real population: a wrapper-recovered candidate has NEITHER key, so it gets no surface
    # at all rather than one describing an unresolved position
    assert _surface({"source_kind": "unknown"}, "fmt_string") is None


def test_every_format_sink_has_a_position_mapping() -> None:
    """The invariant the position branch is kept for, made mechanical.

    That branch fires only if a format sink exists with no entry in the position map, and NOTHING
    else enforces that the two stay in step — which is what makes keeping a currently-unreachable
    branch reasonable, and what makes leaving the invariant unchecked unreasonable.

    ★ Subset, not equality. What the branch needs is that every format sink HAS a position; a
    position registered ahead of its sink is harmless, and demanding equality would fail an
    innocent edit with a message pointing at the wrong thing.

    MUTATION (must go RED): add a sink to the format set without a position for it."""
    assert set(FMT_STRING) <= set(FMT_STRING_ARG), (
        "a format sink has no position mapping — the format-position branch would start firing"
    )


# ── cmd / path: the exec shape ───────────────────────────────────────────────────────


@pytest.mark.parametrize("sink_class", ["cmd", "path_sink"])
def test_exec_shape_arrives_with_a_frame_around_it(sink_class: str) -> None:
    """The one command form note no verdict reads gets a frame instead of arriving bare.

    Every other note this producer emits is consumed by the controllability layer and shows up
    there with a state and a reading attached. This one reaches a reader only as a bare string
    whose NAME reads like an all-clear, with nothing qualifying it.

    MUTATION (must go RED): drop coverage or not_asserted from the object, or let it claim the
    command cannot be injected."""
    out = _surface({"source_kind": "unknown"}, sink_class, "no_shell_exec")
    assert out is not None
    assert out["exec_shape"] == "no_shell_exec"
    assert out["coverage"] == "unjudged"
    assert "does NOT rule out command injection" in out["not_asserted"]
    assert "argv" in out["not_asserted"]  # names what is still reachable
    blob = json.dumps(out).lower()
    assert not [w for w in _REASSURING if w in blob], blob


def test_form_notes_the_verdict_already_reads_are_not_repeated() -> None:
    # A note the controllability layer consumes already reaches the reader there, with its state.
    # Echoing it here would be a second, stateless copy of the same signal.
    for marker in ("const_sink_arg", "caller_constant", "numeric_sanitized", "charset_constrained"):
        assert _surface({"source_kind": "unknown"}, "cmd", marker) is None, marker
    assert _surface({"source_kind": "unknown"}, "cmd", None) is None


def test_a_class_with_no_such_analysis_gets_nothing() -> None:
    assert _surface({"size_kind": "const"}, "nvram_set") is None


# ── the read paths ───────────────────────────────────────────────────────────────────


def test_explain_carries_the_surface_for_every_class(tmp_path: Path) -> None:
    """The hook is reached for every candidate class — the point of hanging it here.

    An earlier design hung it on the deep-provenance reader, which returns early for a candidate
    with no def-use records. Copy candidates never have any, so that hook would have been
    unreachable for the whole class it was built for."""
    from treasure_map.lib.query import explain_candidate

    conn = open_atlas(tmp_path / "atlas.db")
    try:
        for i, (cls, evidence, marker) in enumerate(
            [
                ("copy", _CLAMP_EVIDENCE, None),
                ("fmt_string", {"fmt_arg_pos": 0, "fmt_arg_literal": False}, None),
                ("cmd", {"source_kind": "unknown"}, "no_shell_exec"),
                ("path_sink", {"source_kind": "unknown"}, "no_shell_exec"),
            ]
        ):
            pid = upsert_pattern(
                conn,
                source_class="unknown",
                sink_class=cls,
                call_sequence_shape=f"s->{cls}",
                structural_fingerprint=f"fp_{cls}",
                fingerprint_algo_version="callseq-v1",
            )
            add_instance(
                conn,
                InstanceRow(
                    pattern_id=pid,
                    pseudocode_hash=f"h{i}",
                    source_anchor=f"fn{i}",
                    sink_anchor="system",
                    source_run_id="run_1",
                    reachability_status="unknown",
                    blocking_mechanism=marker,
                    provenance_level="L0",
                    evidence_ref=f"run_1#fn{i}@{cls}",
                    scope_origin="intra",
                    origin="unknown",
                    flow_evidence=json.dumps(evidence),
                ),
            )
            ex = explain_candidate(conn, f"run_1#fn{i}@{cls}")
            assert ex is not None
            assert hasattr(ex, "evidence_surface")
            assert ex.evidence_surface is not None, cls
    finally:
        conn.close()


def test_the_blanket_note_now_names_the_bare_form_note() -> None:
    """The explain payload expands the candidate, so blocking_mechanism reaches a reader as a bare
    string. The standing note that tells a reader what is derived did not name it, which left the
    one form note with no frame anywhere. It does now.

    Honest bound, stated rather than glossed: naming it in the blanket note is a MITIGATION. The
    real fix is not serialising a judgement-shaped bare string at all, which belongs with a change
    to how the candidate is serialised."""
    from treasure_map.mcp_app import _BARE_FORM_NOTE_CAVEAT, _DERIVED_SIGNAL_NOTE

    # the standing note names the field, so a reader of any payload knows it is derived…
    assert "blocking_mechanism" in _DERIVED_SIGNAL_NOTE
    # …and the detail rides only on the payload where the bare value actually appears. It is NOT on
    # the standing note: that one is attached to every list response, which does not contain the
    # field at all, and spending the response budget there overflowed it by 49 bytes.
    assert "no_shell_exec" not in _DERIVED_SIGNAL_NOTE
    assert "no_shell_exec" in _BARE_FORM_NOTE_CAVEAT
    assert "NOT that it cannot be injected" in _BARE_FORM_NOTE_CAVEAT
