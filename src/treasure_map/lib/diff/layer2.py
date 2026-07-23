# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Layer-2 dimension delta: PROJECT two already-computed layer annotations into a per-dimension,
per-subject difference. It ONLY projects; it never re-analyzes and never judges quality.

Every row says "this annotation differs / is unchanged / is undetermined" for one subject between
two runs -- NEVER "the change fixed / broke / regressed anything". delta_kind is tri-state and
``layer_unchanged`` is asserted ONLY when both sides are present, comparable and equal; anything
unresolved is ``delta_undetermined`` (never collapsed into unchanged). ``state_a``/``state_b`` are
carried as OPAQUE evidence and compared ONLY for existence/equality -- never branched on by content
(that would make this a second verdict engine).

Layer-2a implements the one function-level dimension that is computable today
(``reachability.string_keyed_edge``); candidate-level dimensions are gated on candidate alignment
(a later layer) and appear here as ``delta_supported=0`` capability rows, never silently absent.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from treasure_map.lib.atlas.models import DimensionCapabilityStateRow, DimensionDeltaRow
from treasure_map.lib.atlas.writer import (
    add_dimension_capability_states,
    add_dimension_deltas,
    delete_dimension_delta,
)

# ── the layer-2 DELTA-capability declaration (a property of THIS code version, NOT of a run) ──
# What this layer version can (or explicitly cannot yet) delta. This is legitimately code-declared:
# a delta needs a handler, and having a handler is a fact about the code, not a hardcoded slice of
# the open-ended ANALYSIS sub-dimension namespace (that comes from run_capability, never hardcoded).
# Unmodeled reachability sub-dimensions (an auth-boundary check, a dispatch-resolution check, ...)
# are deliberately NOT named here -- they must be DISCOVERED from run_capability, never hardcoded.


@dataclass(frozen=True)
class DimensionSpec:
    name: str
    delta_supported: bool
    # analysis capability source: True = a read-time label always computed (entry_mechanism, the
    # triage candidate dimensions), so 'present' on every run; False = look it up in run_capability.
    always_present: bool


DECLARED_DELTA_DIMENSIONS: tuple[DimensionSpec, ...] = (
    # the one function-level delta implemented today (analysis lives in run_capability)
    DimensionSpec("reachability.string_keyed_edge", delta_supported=True, always_present=False),
    # analysis exists (a read-time entry mechanism label) but no delta is built -> delta_supported=0
    DimensionSpec("reachability.entry_mechanism", delta_supported=False, always_present=True),
    # candidate-level dimensions: analysis exists (triage computes them read-time) but the delta is
    # gated on candidate-level alignment (a later layer) -> visible here as delta_supported=0
    DimensionSpec("controllability", delta_supported=False, always_present=True),
    DimensionSpec("filtering", delta_supported=False, always_present=True),
    DimensionSpec("source_writability", delta_supported=False, always_present=True),
    DimensionSpec("sink_impact", delta_supported=False, always_present=True),
    # same class as the four above (triage read-time candidate dimensions); declared with
    # delta_supported=0 so they are VISIBLE, never absent-by-omission. Whether 'completeness' (an
    # analysis-completeness meta-dimension) ever warrants a delta is a later call -- but 'later' is
    # not 'gone from the universe'.
    DimensionSpec("writer", delta_supported=False, always_present=True),
    DimensionSpec("completeness", delta_supported=False, always_present=True),
)


def _uncovered_triage_dimension(
    triage_dimensions: frozenset[str], declared: frozenset[str]
) -> str | None:
    """The first triage dimension NOT covered by the declared layer-2 set, or None when all are
    covered. A triage dimension is covered when it appears verbatim OR when a declared sub-dimension
    prefixes it (``name.``) -- reachability is one triage dimension but two layer-2 sub-dimensions.
    A triage dimension absent from the layer-2 universe is invisible to a consumer (no capability
    row, no view row), so this is the mechanical check that a new triage dimension is never left to
    vanish by absence -- the exact gap-by-absence this layer exists to kill."""
    for name in sorted(triage_dimensions):
        if name in declared or any(d.startswith(f"{name}.") for d in declared):
            continue
        return name
    return None


# subjects whose function-anchor alignment is low-confidence: the layer-0 state that means "aligned,
# but do not trust the pairing" (mirrors function_alignment.alignment_state).
_LOW_CONF_STATE = "alignment_undetermined"


def _analysis_capability(atlas: sqlite3.Connection, run_id: str, dimension: str) -> str:
    """A run's ANALYSIS capability for a dimension, three-state: 'present' (a run_capability row
    with present=1) / 'declared_absent' (present=0) / 'registration_unknown' (NO row). A missing
    row is NEVER declared_absent -- that is the empty!=absent trap at the capability layer."""
    row = atlas.execute(
        "SELECT present FROM run_capability WHERE run_id = ? AND capability = ?",
        (run_id, dimension),
    ).fetchone()
    if row is None:
        return "registration_unknown"
    return "present" if row[0] == 1 else "declared_absent"


# ── string_keyed_edge delta (the layer-2a handler) ──────────────────────────────────────────

_EDGE_COLS = (
    "binary, from_function, from_func_addr, key, mechanism, callee_name, callee_addr, "
    "callee_kind, table_addr, completeness_status, completeness_scope"
)


def _load_edges(atlas: sqlite3.Connection, run_id: str) -> list[dict[str, Any]]:
    atlas.row_factory = sqlite3.Row
    rows = atlas.execute(
        f"SELECT {_EDGE_COLS} FROM string_keyed_edge WHERE source_run_id = ?",  # noqa: S608 -- literal cols
        (run_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def _load_alignment(
    atlas: sqlite3.Connection, diff_id: str
) -> tuple[dict[str, tuple[str, float, str]], dict[str, tuple[str, float, str]]]:
    """Two lookup dicts over function_alignment: addr_a -> (addr_b, confidence, state) and the
    reverse. Alignment is ALWAYS by ADDRESS -- names (FUN_xxxxxxxx) are address-derived and change
    across versions, so they are never used for any cross-version comparison."""
    a2b: dict[str, tuple[str, float, str]] = {}
    b2a: dict[str, tuple[str, float, str]] = {}
    for r in atlas.execute(
        "SELECT addr_a, addr_b, alignment_confidence, alignment_state "
        "FROM function_alignment WHERE diff_id = ?",
        (diff_id,),
    ):
        a2b[r[0]] = (r[1], r[2], r[3])
        b2a[r[1]] = (r[0], r[2], r[3])
    return a2b, b2a


@dataclass
class _SubjectSide:
    """One side of one edge subject: its callees + region completeness + the raw func addr."""

    callees: list[dict[str, Any]]
    completeness: set[str]
    from_func_addr: str | None
    table_addr: str | None


def _canonical_and_key(
    edge: dict[str, Any], side: str, b2a: dict[str, tuple[str, float, str]]
) -> tuple[tuple[str, str, str, str | None], str] | None:
    """(canonical grouping key in A-space, stored subject_key string) for one edge, or None when the
    key is unresolvable. static_string_table has NULL from_function -> anchor is None (measured 0%
    key collision). strcmp_gate MUST include the function anchor (measured collision is high)."""
    binary = edge["binary"] or ""
    mech = edge["mechanism"] or ""
    key = edge["key"]
    if key is None or key == "":
        return None  # unresolvable key -> caller flags key_unresolved
    if mech == "static_string_table":
        return (binary, mech, key, None), f"{binary}|{mech}|{key}"
    faddr = edge["from_func_addr"]
    if side == "a":
        anchor = faddr  # already A-space
        return (binary, mech, key, anchor), f"{binary}|{mech}|{key}|{anchor}"
    # side b: map the func anchor back to A-space via alignment; unaligned -> a b: sentinel anchor
    aligned = b2a.get(faddr) if faddr is not None else None
    if aligned is not None:
        anchor_a = aligned[0]
        return (binary, mech, key, anchor_a), f"{binary}|{mech}|{key}|{anchor_a}"
    return (binary, mech, key, f"b:{faddr}"), f"{binary}|{mech}|{key}|b:{faddr}"


_Canonical = tuple[str, str, str, "str | None"]


def _group(
    edges: list[dict[str, Any]], side: str, b2a: dict[str, tuple[str, float, str]]
) -> tuple[dict[_Canonical, _SubjectSide], dict[_Canonical, str], list[str]]:
    """Group edge rows into subjects. Returns (subjects, subject_key_strings, unresolved_key_subjs).
    An edge with an unresolvable key gets a stable func-anchored subject_key so it is never dropped
    (empty != absent) -- it becomes a key_unresolved undetermined row, never a silent omission."""
    subjects: dict[_Canonical, _SubjectSide] = {}
    key_strings: dict[_Canonical, str] = {}
    unresolved: list[str] = []
    for e in edges:
        ck = _canonical_and_key(e, side, b2a)
        if ck is None:
            unresolved.append(f"{e['binary'] or ''}|{e['mechanism'] or ''}|?|{e['from_func_addr']}")
            continue
        canonical, key_str = ck
        s = subjects.get(canonical)
        if s is None:
            s = _SubjectSide([], set(), e["from_func_addr"], e["table_addr"])
            subjects[canonical] = s
            key_strings[canonical] = key_str
        s.callees.append(
            {"name": e["callee_name"], "addr": e["callee_addr"], "kind": e["callee_kind"]}
        )
        s.completeness.add(e["completeness_status"] or "")
    return subjects, key_strings, unresolved


def _und(
    diff_id: str,
    subject_key: str,
    reason: str,
    *,
    state_a: str | None = None,
    state_b: str | None = None,
    conf: float | None = None,
) -> DimensionDeltaRow:
    return DimensionDeltaRow(
        diff_id=diff_id,
        dimension="reachability.string_keyed_edge",
        subject_kind="edge",
        subject_key=subject_key,
        state_a=state_a,
        state_b=state_b,
        delta_kind="delta_undetermined",
        undetermined_scope="data",
        undetermined_reason=reason,
        alignment_confidence=conf,
    )


def _aligned_callee_set(
    callees: list[dict[str, Any]], a2b: dict[str, tuple[str, float, str]], side: str
) -> tuple[frozenset[str] | None, str | None, float | None]:
    """The callee set projected into a common (B) space, or (None, reason, conf) when any callee is
    unalignable / low-confidence. A callees are mapped forward via a2b; B callees use their own addr
    (a brand-new B callee is a real difference, not an alignment failure)."""
    out: set[str] = set()
    min_conf: float | None = None
    for c in callees:
        addr = c.get("addr")
        if not addr:
            return None, "callee_unalignable", None
        if side == "a":
            aligned = a2b.get(addr)
            if aligned is None:
                return None, "callee_unalignable", None
            if aligned[2] == _LOW_CONF_STATE:
                return None, "callee_alignment_low_confidence", aligned[1]
            out.add(aligned[0])
            min_conf = aligned[1] if min_conf is None else min(min_conf, aligned[1])
        else:
            out.add(addr)  # B callee already in B space; a real address is all comparison needs
    return frozenset(out), None, min_conf


def _version_skew_rows(
    atlas: sqlite3.Connection, diff_id: str, run_a: str, run_b: str
) -> list[DimensionDeltaRow]:
    """★ Iron law 6 (edge form): an edge dimension is written at HUNT time, so it cannot be
    recomputed at diff time. Under a version skew the two sides' edges may be the product of
    DIFFERENT detector versions, so 'edge changed' and 'detector changed' are INDISTINGUISHABLE. Per
    rule, indistinguishable is undetermined: every subject is delta_undetermined(scope=data,
    reason=version_skew), never changed/unchanged. The completeness guard cannot catch this -- a
    region self-reported 'complete' by an OLD detector and 'complete' by a NEW one are two different
    completes with no version stamp."""
    _, b2a = _load_alignment(atlas, diff_id)
    _, keys_a, unres_a = _group(_load_edges(atlas, run_a), "a", b2a)
    _, keys_b, unres_b = _group(_load_edges(atlas, run_b), "b", b2a)
    subject_keys = set(keys_a.values()) | set(keys_b.values()) | set(unres_a) | set(unres_b)
    return [_und(diff_id, k, "version_skew") for k in sorted(subject_keys)]


def _string_keyed_edge_delta(
    atlas: sqlite3.Connection,
    diff_id: str,
    run_a: str,
    run_b: str,
    cap_a: str,
    cap_b: str,
    version_skew: bool,
) -> list[DimensionDeltaRow]:
    """Project the string_keyed_edge dimension. Guards (G1 key/anchor, G2 callee alignability, G3
    completeness) run FIRST in order; only a subject that clears ALL guards has its callee sets
    compared. Any guard trip -> delta_undetermined (never changed/unchanged)."""
    dim = "reachability.string_keyed_edge"
    if cap_a != "present" or cap_b != "present":
        # analysis absent on a side is a deeper gap than a version skew -> capability scope
        return _capability_asymmetry(atlas, diff_id, dim, run_a, run_b, cap_a, cap_b)
    if version_skew:
        return _version_skew_rows(atlas, diff_id, run_a, run_b)

    a2b, b2a = _load_alignment(atlas, diff_id)
    edges_a = _load_edges(atlas, run_a)
    edges_b = _load_edges(atlas, run_b)
    subj_a, keys_a, unres_a = _group(edges_a, "a", b2a)
    subj_b, keys_b, unres_b = _group(edges_b, "b", b2a)
    # per-function region completeness in A-space (a region is complete iff every edge row there is
    # 'complete'); used to verify BOTH regions of a vanished/new edge, not only the present side.
    region_a = _region_complete(subj_a)
    region_b = _region_complete(subj_b)

    rows: list[DimensionDeltaRow] = []
    # unresolvable-key edges are never dropped: each is an explicit key_unresolved row
    for uk in sorted(set(unres_a) | set(unres_b)):
        rows.append(_und(diff_id, uk, "key_unresolved"))
    for canonical in sorted(
        set(subj_a) | set(subj_b), key=lambda c: (c[0], c[1], c[2], c[3] or "")
    ):
        key_str = keys_a.get(canonical) or keys_b.get(canonical) or "?"
        a = subj_a.get(canonical)
        b = subj_b.get(canonical)
        mech = canonical[1]

        # G1 anchor alignment (gate only; static has anchor None and a version-stable key identity)
        if mech == "strcmp_gate":
            g1 = _anchor_guard(canonical, a, b, a2b, b2a, key_str, diff_id)
            if g1 is not None:
                rows.append(g1)
                continue
        # G3 completeness on BOTH regions (present side must be complete; counterpart region must be
        # complete too -- an unverifiable counterpart region is not a proven layer_changed)
        g3 = _completeness_guard(canonical, a, b, region_a, region_b, key_str, diff_id)
        if g3 is not None:
            rows.append(g3)
            continue
        # G2 callee alignability, then compare
        set_a, reason_a, conf_a = (
            _aligned_callee_set(a.callees, a2b, "a") if a else (frozenset(), None, None)
        )
        set_b, reason_b, conf_b = (
            _aligned_callee_set(b.callees, a2b, "b") if b else (frozenset(), None, None)
        )
        if set_a is None or set_b is None:
            rows.append(
                _und(
                    diff_id,
                    key_str,
                    reason_a or reason_b or "callee_unalignable",
                    conf=conf_a or conf_b,
                )
            )
            continue
        state_a = _state_str(a)
        state_b = _state_str(b)
        conf = _anchor_conf(canonical, a2b, b2a)
        kind = "layer_unchanged" if (a and b and set_a == set_b) else "layer_changed"
        rows.append(
            DimensionDeltaRow(
                diff_id=diff_id,
                dimension=dim,
                subject_kind="edge",
                subject_key=key_str,
                state_a=state_a,
                state_b=state_b,
                delta_kind=kind,
                alignment_confidence=conf,
            )
        )
    return rows


def _region_complete(
    subjects: dict[tuple[str, str, str, str | None], _SubjectSide],
) -> dict[str, bool]:
    """func_anchor (A-space) -> whether every edge row in that region reported 'complete'. Static
    tables (anchor None) are keyed by their own subject and handled inline, not here."""
    out: dict[str, bool] = {}
    for canonical, s in subjects.items():
        anchor = canonical[3]
        if anchor is None:
            continue
        complete = s.completeness == {"complete"}
        out[anchor] = out.get(anchor, True) and complete
    return out


def _anchor_guard(
    canonical: tuple[str, str, str, str | None],
    a: _SubjectSide | None,
    b: _SubjectSide | None,
    a2b: dict[str, tuple[str, float, str]],
    b2a: dict[str, tuple[str, float, str]],
    key_str: str,
    diff_id: str,
) -> DimensionDeltaRow | None:
    """G1: the gate's function anchor must align across versions (by address, never name). Returns a
    delta_undetermined row when it does not, else None."""
    if a is not None and a.from_func_addr is not None:
        al = a2b.get(a.from_func_addr)
        if al is None:
            return _und(diff_id, key_str, "from_function_unaligned")
        if al[2] == _LOW_CONF_STATE:
            return _und(diff_id, key_str, "from_function_alignment_low_confidence", conf=al[1])
    if a is None and b is not None and b.from_func_addr is not None:
        # B-only edge: its function must align back to A, else we cannot even place it
        if b2a.get(b.from_func_addr) is None:
            return _und(diff_id, key_str, "from_function_unaligned")
    return None


def _completeness_guard(
    canonical: tuple[str, str, str, str | None],
    a: _SubjectSide | None,
    b: _SubjectSide | None,
    region_a: dict[str, bool],
    region_b: dict[str, bool],
    key_str: str,
    diff_id: str,
) -> DimensionDeltaRow | None:
    """G3 (three-value): a diff is allowed ONLY when both relevant regions are self-reported
    'complete'. A present side that is incomplete/partial, or a counterpart region with no
    verifiable completeness record, blocks the diff. Honesty boundary: this catches SELF-REPORTED
    gaps only, not an edge a detector silently missed inside a 'complete' region.

    ★ STATIC-TABLE-SPECIFIC boundary (weaker): a static_string_table edge has anchor=None and no
    per-function region, so the counterpart side's completeness CANNOT be verified -- only the
    present side is checked. A static-table edge that one side's table detector silently missed can
    therefore read as layer_changed. (Small blast radius -- ~546 rows -- and the present side is
    still completeness-checked, but omitting it would be dishonest.)"""
    anchor = canonical[3]
    # present side(s) must be complete
    if a is not None and a.completeness != {"complete"}:
        return _und(diff_id, key_str, "completeness_not_complete", state_a=_state_str(a))
    if b is not None and b.completeness != {"complete"}:
        return _und(diff_id, key_str, "completeness_not_complete", state_b=_state_str(b))
    if anchor is None:
        return (
            None  # static table: no per-function counterpart region to verify (see boundary above)
        )
    # counterpart region (the side lacking this subject) must be verifiably complete
    if a is None and region_a.get(anchor) is not True:
        return _und(diff_id, key_str, "completeness_not_complete", state_b=_state_str(b))
    if b is None and region_b.get(anchor) is not True:
        return _und(diff_id, key_str, "completeness_not_complete", state_a=_state_str(a))
    return None


def _anchor_conf(
    canonical: tuple[str, str, str, str | None],
    a2b: dict[str, tuple[str, float, str]],
    b2a: dict[str, tuple[str, float, str]],
) -> float | None:
    anchor = canonical[3]
    if anchor is None or anchor.startswith("b:"):
        return None
    al = a2b.get(anchor)
    return al[1] if al is not None else None


def _state_str(side: _SubjectSide | None) -> str | None:
    """An OPAQUE evidence summary of a side's callee set (sorted names) -- carried for the reader,
    compared only for existence/equality upstream, never branched on by content."""
    if side is None:
        return None
    names = sorted(str(c.get("name") or c.get("addr") or "?") for c in side.callees)
    return "callees=" + ",".join(names)


def _capability_asymmetry(
    atlas: sqlite3.Connection,
    diff_id: str,
    dim: str,
    run_a: str,
    run_b: str,
    cap_a: str,
    cap_b: str,
) -> list[DimensionDeltaRow]:
    """One side lacks the analysis: every PRESENT-side subject is capability-scoped undetermined,
    identically (constant per subject -- a whole-dimension gap, never a per-subject data gap)."""
    _, b2a = _load_alignment(atlas, diff_id)
    if cap_a == "present":
        present_run, side = run_a, "a"
        reason = (
            "capability_absent_b"
            if cap_b == "declared_absent"
            else "capability_registration_unknown"
        )
    elif cap_b == "present":
        present_run, side = run_b, "b"
        reason = (
            "capability_absent_a"
            if cap_a == "declared_absent"
            else "capability_registration_unknown"
        )
    else:
        return []  # neither side has the analysis: no subjects; the capability_state row carries it
    _, keys, _ = _group(_load_edges(atlas, present_run), side, b2a)
    return [
        DimensionDeltaRow(
            diff_id=diff_id,
            dimension=dim,
            subject_kind="edge",
            subject_key=key_str,
            delta_kind="delta_undetermined",
            undetermined_scope="capability",
            undetermined_reason=reason,
            capability_ref=dim,
        )
        for key_str in sorted(keys.values())
    ]


_DELTA_HANDLERS: dict[str, Callable[..., list[DimensionDeltaRow]]] = {
    "reachability.string_keyed_edge": _string_keyed_edge_delta,
}


def declared_delta_dimension_names() -> frozenset[str]:
    return frozenset(d.name for d in DECLARED_DELTA_DIMENSIONS)


@dataclass(frozen=True)
class Layer2Result:
    diff_id: str
    delta_rows: int
    capability_rows: int


def run_layer2_delta(
    atlas: sqlite3.Connection,
    *,
    diff_id: str,
    run_a_id: str,
    run_b_id: str,
    commit: bool = True,
) -> Layer2Result:
    """Project every dimension in the universe (declared delta dimensions UNION the analysis
    sub-dimensions discovered in run_capability) into dimension_capability_state + dimension_delta.

    Replace-by-diff (idempotent). A dimension neither side can delta is a VISIBLE capability row,
    never silently absent; a delta-supported dimension whose sides both have the analysis runs its
    handler; one side missing the analysis yields capability-scoped undetermined per present edge.

    ★ Iron law 6 (version skew): edge dimensions cannot be recomputed at diff time, so under a
    version skew they are degraded to version_skew undetermined (see _version_skew_rows). ``skew``
    is read from diff_meta (layer-0 computes it from tool_version, NOT firmware hash); a MISSING /
    unreadable diff_meta row is treated AS a skew (cannot-confirm-same-version != confirmed-same,
    empty != absent on the version axis). BOUNDARY: version_skew only compares the ANALYSIS-TOOL
    version -- it does NOT catch a detector-logic change within one tool_version, nor build-side
    compiler/inlining skew between the two firmware; not all comparability risk."""
    skew_row = atlas.execute(
        "SELECT version_skew FROM diff_meta WHERE diff_id = ?", (diff_id,)
    ).fetchone()
    version_skew = skew_row is None or skew_row[0] is None or bool(skew_row[0])
    declared = {d.name: d for d in DECLARED_DELTA_DIMENSIONS}
    # discovered analysis sub-dimensions (never hardcoded): whatever run_capability actually holds
    discovered = {
        r[0]
        for r in atlas.execute(
            "SELECT DISTINCT capability FROM run_capability WHERE run_id IN (?, ?)",
            (run_a_id, run_b_id),
        )
    }
    universe = sorted(set(declared) | discovered)

    cap_rows: list[DimensionCapabilityStateRow] = []
    delta_rows: list[DimensionDeltaRow] = []
    for dim in universe:
        spec = declared.get(dim)
        delta_supported = 1 if (spec and spec.delta_supported) else 0
        if spec and spec.always_present:
            state_a = state_b = "present"
        else:
            state_a = _analysis_capability(atlas, run_a_id, dim)
            state_b = _analysis_capability(atlas, run_b_id, dim)
        cap_rows.append(
            DimensionCapabilityStateRow(
                diff_id=diff_id,
                dimension=dim,
                state_a=state_a,
                state_b=state_b,
                delta_supported=delta_supported,
            )
        )
        handler = _DELTA_HANDLERS.get(dim)
        if delta_supported and handler is not None:
            delta_rows.extend(
                handler(atlas, diff_id, run_a_id, run_b_id, state_a, state_b, version_skew)
            )

    delete_dimension_delta(atlas, diff_id, commit=False)
    add_dimension_capability_states(atlas, cap_rows, commit=False)
    add_dimension_deltas(atlas, delta_rows, commit=False)
    if commit:
        atlas.commit()
    return Layer2Result(diff_id=diff_id, delta_rows=len(delta_rows), capability_rows=len(cap_rows))
