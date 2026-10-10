"""Candidate-level sink overlay (Layer 0.5).

On top of BinDiff's function-level alignment, line up the A/B sink candidates of one diff (or of
every diff between two runs), or mark them honestly as not lined-up. EVIDENCE ONLY: two states
plus undetermined (persisted | presence_undetermined), never a fix-status verdict, never a
path/taint engine.

Callee source. BinDiff's instruction table pairs addresses POSITIONALLY and carries no callee. The
callee is verified from BOTH sides' atlas candidate records first (``instance.sink_anchor``, the
called sink's name; a wrapper's ``W``). Where the other side has NO candidate at the matched
address, the call-site facts written beside the pair are read instead: the callee identities the
other run's own call tokens record at that instruction, and the call targets its BinExport recorded
(see lib/diff/callsite_facts). They refine that one case only — no other row changes, and every row
they decide stays ``presence_undetermined``: what the matched instruction calls is a fact about
it, never a claim that the candidate's call persisted, went away or is new. They need an
instruction pair, so a candidate BinDiff matched to nothing is untouched.

What the facts do NOT do: infer that an instruction is not a call because no call is recorded at
it (a register-indirect call records none, and a function the bridge did not cover records nothing
at all). That needs the disassembly itself and is left to a backend that reads it.

★ ``present_different_callee`` / ``counterpart_different_callee`` mean "the instruction BinDiff
matched to this call calls something else" — NOT "the callee was replaced": the call may still be
there, matched elsewhere. ``counterpart_callee.same_callee_candidate_elsewhere`` says whether the
paired function holds another candidate with the same callee.

HONESTY LINE (backend-independent): this layer emits only ``persisted`` and
``presence_undetermined``. Anything BinExport/BinDiff could not export or match is
``presence_undetermined`` with a machine-readable reason — NEVER collapsed to unchanged /
persisted. A whole function with no counterpart is ``presence_undetermined`` /
``function_unmatched``: the function may have been deleted, inlined into a caller, moved to another
binary, or fallen into an analysis hole, and this layer cannot tell which. A candidate that merely
"looks gone" or "looks new" inside an aligned function pair stays ``presence_undetermined`` too
(tmap can miss-render a real call, and that extraction blindspot cannot be ruled out under this
backend — safe direction).

KEY GRANULARITY (``key_granularity``): ``callsite`` (a direct sink call, lined up by its address),
``wrapper_callsite`` (a call to a thin wrapper ``W`` that forwards to the sink one hop away, lined
up by the address of the call to ``W``), ``degraded_out_of_body`` (a call located in the text but
not pinned to an in-body address; compared per (function, key class) by count),
``function_fallback`` and ``wrapper`` (function-level, compared per (function, key class)). The key
class of a wrapper candidate is its axis (``cmd_via_wrapper``, …), so a wrapper is never lined up
against a direct sink of the same sink class.

CALLEE (the two callsite tiers): a pair is the same call only when both are the same TYPE (direct
sink vs wrapper) and call the same thing. For a direct sink that is the sink's name. For a wrapper
the callee is ``W`` and the sink it forwards to: a different ``W``, or the same ``W`` now forwarding
to a different sink, is a different callee. ``W`` is compared by its ENTRY ADDRESS through this
diff's function alignment, not by name — a stripped binary names many wrappers ``FUN_<addr>``, and
two of those names agreeing (or disagreeing) says nothing about whether they are the same function.
A ``W`` with no high-confidence alignment cannot be compared: ``callee_unreadable``. Only a row
whose flow records no wrapper address on either side falls back to comparing names.

COMPLETENESS: every candidate of both sides is represented — named as a row's ``a_ref``/``b_ref``,
folded into a row's ``coclaimed_by`` / ``coclaimed_by_b``, or counted in a degraded key row's
``a_n``/``b_n``. ``SinkOverlayResult.coverage`` checks that invariant on every call and reports a
breach as ``coverage_violation`` (never an exception, never silence). Legacy ``#fn<N>`` anchors
carry no function address and cannot be lined up; they are counted as ``excluded_legacy``.

``presence_reason`` values (an enum that may grow; do not branch on it):
  diff-wide: ``diff_meta_missing_sha``, ``diff_failed``, ``version_skew`` (the two runs' analysis
  tools are not confirmed equal), ``extraction_generation_mismatch`` (the two runs differ in
  ``build_hash``, or in a known ``hunt_commit``). The MCP layer already refuses a diff whose side is
  a provably stale scan (``_refuse_stale_diff``); the two generation reasons here are the compute
  layer's own guard for callers that bypass that refusal, and apply to every row of the diff.
  run-pair only: ``binary_not_diffed``, ``shadowed_by_name_collision`` (a same-named binary with a
  different content hash was diffed instead).
  function level: ``function_unmatched`` (no counterpart function; this side's analysis is
  complete), ``counterpart_not_analyzed``, ``no_counterpart_undetermined``,
  ``alignment_low_confidence``.
  callsite level: ``crossside_match_degraded`` (this diff has no instruction-match data at all),
  ``instruction_unmatched`` (instruction data exists but this callsite was not matched — an export
  gap or a changed basic block; this backend cannot tell which), ``present_different_callee``,
  ``crossgranularity_unresolved`` (the other side has the same call only at a different key
  granularity), ``callee_unreadable`` (a sink name is missing, or a wrapper cannot be compared).
  matched to a non-candidate instruction (read from the call-site facts, either direction):
  ``counterpart_call_facts_absent`` (no readable facts for that side), ``counterpart_facts_stale``
  (read from an older extraction than that run's current one), ``counterpart_no_call_fact`` (no
  call recorded at that instruction), ``counterpart_call_ambiguous`` (more than one callee there),
  ``counterpart_callee_unresolved`` (a callee that cannot be compared — e.g. an unresolved stub),
  ``counterpart_same_callee``, ``counterpart_different_callee``. The candidates-only reading
  (``callee_backend="atlas_candidates"``) leaves that case as ``counterpart_not_candidate`` /
  ``a_counterpart_not_candidate`` instead; the default reading no longer emits those two.
  degraded keys: ``crossside_count_mismatch``, ``coclaim_unresolved`` (one physical callsite claimed
  by two or more functions' degraded candidates with no callsite-tier candidate there to own it).
  ``callsite_not_exported`` is reserved for a backend that can prove an export gap and is NOT
  emitted by this one.

NOT IMPLEMENTED (registered): ``callees_truncated`` — the atlas does not record which functions had
their callee list truncated at extraction; a candidate in such a function may read as
``no_counterpart_undetermined`` / ``instruction_unmatched`` where the real cause is truncation.

★ GENERATION: ``instruction_match`` is built at diff time from the A/B candidate callsites as they
were then. A re-hunt that changes a run's candidate set or callsite addresses (a new candidate
shape, a re-split callsite) must be followed by re-running the affected diffs.

COST: the run-pair computation is not incremental — it recomputes every diff of the pair, which
takes on the order of ten-plus seconds for a large pair. A large result is read through
``summarize_overlay`` (counts) and ``page_overlay`` (a stable, ordered page), never in one piece.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field, replace
from typing import Any

from treasure_map.lib.callsite_ref import (
    callsite_abs_addr,
    is_wrapper_class,
    ref_suffix_parts,
    wrapper_call_abs_addr,
)
from treasure_map.lib.errors import TreasureMapError
from treasure_map.version import UNKNOWN_VERSION

ALIGN_THRESHOLD = 0.9  # mirrors lib/diff/layer0.ALIGN_THRESHOLD; a pair below it is undetermined

# key_granularity values
_G_CALLSITE = "callsite"
_G_DEGRADED = "degraded_out_of_body"
_G_FUNCTION_FALLBACK = "function_fallback"
_G_WRAPPER = "wrapper"
_G_WRAPPER_CALLSITE = "wrapper_callsite"
_CALLSITE_TIERS = (_G_CALLSITE, _G_WRAPPER_CALLSITE)

# presence: persisted | presence_undetermined (this layer never claims a call is gone or new)
_P_PERSISTED = "persisted"
_P_UNDET = "presence_undetermined"
_PRESENCE_VALUES = (_P_PERSISTED, _P_UNDET)

# presence -> delta_kind projection (CHECK-safe), so existing delta_kind consumers keep working
_DELTA_KIND = {
    _P_PERSISTED: "layer_unchanged",
    _P_UNDET: "delta_undetermined",
}

# The logic version stamped on every persisted baseline row. Bump it whenever the way a row is
# computed changes (a verdict, a reason, a key, a fold): a baseline written by other logic is then
# read as stale instead of being compared as if it were current.
SINK_OVERLAY_LOGIC_VERSION = "4"

# Where the callee of a matched other-side instruction that is NOT a candidate comes from.
# ``callsite_facts`` (the default) reads the call-site facts stored beside instruction_match;
# ``atlas_candidates`` reads candidates only and leaves that case as ``counterpart_not_candidate`` /
# ``a_counterpart_not_candidate`` — kept to check that the facts only refine that one case.
_BACKEND_FACTS = "callsite_facts"
_BACKEND_CANDIDATES = "atlas_candidates"
_CALLEE_BACKENDS = (_BACKEND_FACTS, _BACKEND_CANDIDATES)

# The direction a row speaks for: which side's candidate it names.
_SIDES = ("a_only", "b_only", "both")
_FUN_NAME_RE = re.compile(r"FUN_[0-9a-fA-F]+")

_UNREPRESENTED_SAMPLE = 20  # refs listed when the coverage invariant breaks (diagnosis, not a dump)


@dataclass(frozen=True)
class SinkOverlayRow:
    """One cross-side overlay result. Each carries an evidence_ref anchor (the side with no
    counterpart is None) so it traces back to the fact layer. ``diff_id`` is None only for a
    run-pair row about a binary that has no diff."""

    diff_id: str | None
    binary: str | None
    sink_class: str
    a_ref: str | None
    b_ref: str | None
    key_granularity: str  # callsite|wrapper_callsite|degraded_out_of_body|function_fallback|wrapper
    presence: str  # persisted | presence_undetermined
    presence_reason: str | None  # machine-readable; only when presence_undetermined
    match_basis: str | None  # instruction | function_level
    # tier-1 only: present_same_callee | present_different_callee | unknown (or, from the
    # candidates-only backend, counterpart_not_candidate)
    counterpart_call: str | None
    alignment_confidence: float | None
    coclaimed_by: list[str] | None = None  # A-side degraded co-claimers' function entries
    coclaimed_by_b: list[str] | None = None  # B-side degraded co-claimers' function entries
    a_n: int | None = None
    b_n: int | None = None
    # On a same/different-callee row: what the matched other-side instruction calls —
    # ``{"matched_addr", "callees": [...], "same_callee_candidate_elsewhere": bool|None}`` (the last
    # key only on a different-callee row). None otherwise.
    counterpart_callee: dict[str, Any] | None = None


@dataclass(frozen=True)
class SinkOverlayCoverage:
    """Whether every candidate of both sides is represented by the rows (see module docstring).

    ``coverage_violation`` is True iff a side's represented count falls short of its total;
    ``unrepresented_refs`` then names a sorted sample of the missing candidates."""

    a_total: int
    a_represented: int
    b_total: int
    b_represented: int
    excluded_legacy: int
    coverage_violation: bool
    unrepresented_refs: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SinkOverlayResult:
    rows: list[SinkOverlayRow]
    coverage: SinkOverlayCoverage


class SinkOverlayBaselineError(TreasureMapError):
    """A durable overlay baseline was refused: it could not later be checked for staleness, or
    the overlay it would store is incomplete."""


@dataclass
class _Cand:
    """A sink candidate, parsed from one instance row."""

    iid: int  # instance_id: the identity coverage is tracked by (degraded refs repeat)
    ref: str
    sink_class: str
    sink: str | None  # instance.sink_anchor: the called sink's name
    sha: str | None
    binary_name: str | None  # basename of binary_path
    func_entry: str  # normalized hex string of the containing function entry
    tier: str  # key_granularity
    # normalized hex of the candidate's call (the sink call, or for a wrapper the call to W); None
    # at function level
    callsite_addr: str | None
    wrapper_axis: str | None = None  # the wrapper class (``cmd_via_wrapper``, …); None if direct
    callee_name: str | None = None  # direct: the sink's name; wrapper: W's name (flow evidence)
    callee_addr: str | None = None  # wrapper only: W's entry, normalized hex (flow evidence)


# ── ref parsing ──────────────────────────────────────────────────────────────────────


def _norm_addr(value: int) -> str:
    """tmap canonical 8-wide lower hex, matching function_alignment.addr_* and instruction_match."""
    return f"{value:08x}"


def _func_entry_hex(ref: str) -> str | None:
    """The containing function entry, as the normalized hex string BinDiff keys alignments by.

    ref shape ``{run}#{bin_anchor}:{func_entry_hex}@{suffix}``; the function entry is the hex run
    between the last ``:`` and the first following ``@``. None when the ref carries no ``:…@`` (a
    legacy ``#fn<N>`` anchor, which has no address and is excluded)."""
    if ":" not in ref or "@" not in ref:
        return None
    after_colon = ref.rsplit(":", 1)[1]
    head = after_colon.split("@", 1)[0]
    if not head:
        return None
    try:
        return _norm_addr(int(head, 16))
    except ValueError:
        return None


def _classify(ref: str, flow: dict[str, Any]) -> tuple[str, str | None]:
    """(key_granularity, callsite_addr_hex|None) for a candidate, from ref shape + flow markers.

    Wrapper class (``<axis>_via_wrapper``):
    - wrapper_callsite: the ref carries an offset -> the address of the call to the wrapper.
    - degraded_out_of_body: flow.callsite_located is False (as for a direct sink, below).
    - wrapper: everything else (the function-level fallback).
    Direct sink class:
    - callsite: ref has an addressed suffix ``@<class>@<offset>`` -> callsite_addr from the ref.
    - degraded_out_of_body: flow.callsite_located is False -> address iff the backfill wrote
      flow.callsite_addr (pre-backfill it is None and the row stays function-level).
    - function_fallback: everything else at function level (no marker, no address).
    """
    parts = ref_suffix_parts(ref)
    if parts is not None and is_wrapper_class(parts[0]):
        waddr = wrapper_call_abs_addr(ref)
        if waddr is not None:
            return _G_WRAPPER_CALLSITE, _norm_addr(waddr)
        if flow.get("callsite_located") is False:
            return _degraded(flow)
        return _G_WRAPPER, None
    addr = callsite_abs_addr(ref)
    if addr is not None:
        return _G_CALLSITE, _norm_addr(addr)
    if flow.get("callsite_located") is False:
        return _degraded(flow)
    return _G_FUNCTION_FALLBACK, None


def _degraded(flow: dict[str, Any]) -> tuple[str, str | None]:
    """A located-in-text call not pinned to an in-body address: degraded, with the address the
    hunt recovered into flow.callsite_addr when it could."""
    ca = flow.get("callsite_addr")  # hunt-side callsite_addr backfill; None pre-backfill
    if isinstance(ca, str) and ca:
        try:
            return _G_DEGRADED, _norm_addr(int(ca, 16))
        except ValueError:
            return _G_DEGRADED, None
    if isinstance(ca, int):
        return _G_DEGRADED, _norm_addr(ca)
    return _G_DEGRADED, None


def _parse_flow(flow_evidence: str | None) -> dict[str, Any]:
    if not flow_evidence:
        return {}
    try:
        data = json.loads(flow_evidence)
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


# ── candidate loading ─────────────────────────────────────────────────────────────────

_CAND_SELECT = (
    "SELECT i.instance_id, i.evidence_ref, p.sink_class, i.sink_anchor, i.binary_content_hash, "
    "i.binary_path, i.flow_evidence "
    "FROM instance i JOIN pattern p ON i.pattern_id = p.pattern_id "
)


@dataclass
class _Loaded:
    cands: list[_Cand]
    legacy: int  # rows with no function address (legacy ``#fn<N>`` / unanchored): excluded


def _parse_rows(rows: list[Any], name_filter: str | None = None) -> _Loaded:
    out: list[_Cand] = []
    legacy = 0
    for iid, ref, sink_class, sink, csha, bpath, fe in rows:
        bname = bpath.rsplit("/", 1)[-1] if bpath else None
        if name_filter is not None and bname != name_filter:
            continue
        func_entry = _func_entry_hex(ref) if ref else None
        if func_entry is None:
            legacy += 1  # no address to line up by -> excluded, and counted (never silently)
            continue
        flow = _parse_flow(fe)
        tier, callsite_addr = _classify(ref, flow)
        parts = ref_suffix_parts(ref)
        wrapper_axis = parts[0] if parts is not None and is_wrapper_class(parts[0]) else None
        callee_name, callee_addr = (
            _wrapper_callee(flow) if wrapper_axis is not None else (sink or None, None)
        )
        out.append(
            _Cand(
                iid=iid,
                ref=ref,
                sink_class=sink_class or "",
                sink=sink or None,
                sha=csha,
                binary_name=bname,
                func_entry=func_entry,
                tier=tier,
                callsite_addr=callsite_addr,
                wrapper_axis=wrapper_axis,
                callee_name=callee_name,
                callee_addr=callee_addr,
            )
        )
    return _Loaded(out, legacy)


def _wrapper_callee(flow: dict[str, Any]) -> tuple[str | None, str | None]:
    """(W's name, W's normalized entry) from a wrapper candidate's ``flow_path.wrapper``; each is
    None when the flow does not record it (an older hunt has the name only)."""
    path = flow.get("flow_path")
    wrapper = path.get("wrapper") if isinstance(path, dict) else None
    if not isinstance(wrapper, dict):
        return None, None
    name = wrapper.get("name")
    raw = wrapper.get("addr")
    addr: str | None = None
    if isinstance(raw, str) and raw:
        try:
            addr = _norm_addr(int(raw, 16))
        except ValueError:
            addr = None
    return (name if isinstance(name, str) and name else None), addr


def _load_candidates(atlas: sqlite3.Connection, run_id: str, sha: str) -> _Loaded:
    """Every sink candidate of one run's binary (joined to its content hash), parsed."""
    rows = atlas.execute(
        _CAND_SELECT
        + "WHERE i.source_run_id = ? AND i.binary_content_hash = ? ORDER BY i.instance_id",
        (run_id, sha),
    ).fetchall()
    return _parse_rows(rows)


def _load_candidates_by_name(
    atlas: sqlite3.Connection, run_id: str, binary_short: str | None
) -> _Loaded:
    """Fallback loader for a diff side with no content hash: scope candidates by run + binary short
    name (basename of binary_path). Fuzzy by design — used only to make that side's candidates
    VISIBLE as undetermined, never to judge them."""
    if not binary_short:
        return _Loaded([], 0)
    rows = atlas.execute(
        _CAND_SELECT + "WHERE i.source_run_id = ? ORDER BY i.instance_id", (run_id,)
    ).fetchall()
    return _parse_rows(rows, name_filter=binary_short)


def _load_run_candidates(atlas: sqlite3.Connection, run_id: str) -> _Loaded:
    rows = atlas.execute(
        _CAND_SELECT + "WHERE i.source_run_id = ? ORDER BY i.instance_id", (run_id,)
    ).fetchall()
    return _parse_rows(rows)


# ── per-diff context ───────────────────────────────────────────────────────────────────


@dataclass
class _DiffCtx:
    diff_id: str
    binary: str | None
    binary_b: str | None
    run_a: str
    run_b: str
    sha_a: str | None
    sha_b: str | None
    diff_ok: bool
    version_skew: int
    # function alignment: A-func-entry -> (b_func_entry, confidence, state); and the B view
    align_a: dict[str, tuple[str, float, str]]
    align_b: dict[str, tuple[str, float, str]]
    # function presence (unmatched functions): side -> {func_addr: presence_state}
    presence_a: dict[str, str]
    presence_b: dict[str, str]
    # instruction matches at candidate callsites, both directions; and whether ANY exist
    imatch: dict[str, str]
    imatch_b: dict[str, str]
    imatch_present: bool
    # call-site facts at each side's matched addresses (address -> parsed JSON, None when that
    # side's column is NULL), each side's facts state, the build hash read from, its stub state
    facts_a: dict[str, dict[str, Any] | None] = field(default_factory=dict)
    facts_b: dict[str, dict[str, Any] | None] = field(default_factory=dict)
    facts_state_a: str | None = None
    facts_state_b: str | None = None
    facts_hash_a: str | None = None
    facts_hash_b: str | None = None
    stub_state_a: str | None = None
    stub_state_b: str | None = None


def _load_diff_ctx(atlas: sqlite3.Connection, diff_id: str) -> _DiffCtx | None:
    meta = atlas.execute(
        "SELECT run_a_id, run_b_id, binary_a, binary_b, sha256_a, sha256_b, diff_ok, version_skew, "
        "callsite_facts_a, callsite_facts_b, callsite_facts_hash_a, callsite_facts_hash_b, "
        "stub_state_a, stub_state_b FROM diff_meta WHERE diff_id = ?",
        (diff_id,),
    ).fetchone()
    if meta is None:
        return None
    run_a, run_b, binary_a, binary_b, sha_a, sha_b, diff_ok, version_skew = meta[:8]
    fs_a, fs_b, fh_a, fh_b, ss_a, ss_b = meta[8:]
    align_a: dict[str, tuple[str, float, str]] = {}
    align_b: dict[str, tuple[str, float, str]] = {}
    for addr_a, addr_b, conf, state in atlas.execute(
        "SELECT addr_a, addr_b, alignment_confidence, alignment_state "
        "FROM function_alignment WHERE diff_id = ?",
        (diff_id,),
    ):
        align_a[addr_a] = (addr_b, conf, state)
        align_b[addr_b] = (addr_a, conf, state)
    presence_a: dict[str, str] = {}
    presence_b: dict[str, str] = {}
    for side, addr, pstate in atlas.execute(
        "SELECT side, addr, presence_state FROM function_presence WHERE diff_id = ?",
        (diff_id,),
    ):
        (presence_a if side == "a" else presence_b)[addr] = pstate
    imatch: dict[str, str] = {}
    imatch_b: dict[str, str] = {}
    facts_a: dict[str, dict[str, Any] | None] = {}
    facts_b: dict[str, dict[str, Any] | None] = {}
    for addr_a, addr_b, fa, fb in atlas.execute(
        "SELECT addr_a, addr_b, facts_a, facts_b FROM instruction_match WHERE diff_id = ?",
        (diff_id,),
    ):
        imatch[addr_a] = addr_b
        imatch_b[addr_b] = addr_a
        facts_a[addr_a] = _parse_facts(fa)
        facts_b[addr_b] = _parse_facts(fb)
    return _DiffCtx(
        diff_id=diff_id,
        binary=binary_a,
        binary_b=binary_b,
        run_a=run_a,
        run_b=run_b,
        sha_a=sha_a,
        sha_b=sha_b,
        diff_ok=bool(diff_ok),
        version_skew=int(version_skew or 0),
        align_a=align_a,
        align_b=align_b,
        presence_a=presence_a,
        presence_b=presence_b,
        imatch=imatch,
        imatch_b=imatch_b,
        imatch_present=bool(imatch),
        facts_a=facts_a,
        facts_b=facts_b,
        facts_state_a=fs_a,
        facts_state_b=fs_b,
        facts_hash_a=fh_a,
        facts_hash_b=fh_b,
        stub_state_a=ss_a,
        stub_state_b=ss_b,
    )


def _parse_facts(raw: str | None) -> dict[str, Any] | None:
    """One side's call-site facts JSON at a matched address, or None when absent / unreadable."""
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("callees"), list):
        return None
    return data


def _gen_stamps(
    atlas: sqlite3.Connection, run_id: str
) -> tuple[str | None, str | None, int | None] | None:
    """(hunt_commit, build_hash, hunt_instances) for a run, from run; None if the run is absent."""
    row = atlas.execute(
        "SELECT hunt_commit, build_hash, hunt_instances FROM run WHERE run_id = ?", (run_id,)
    ).fetchone()
    if row is None:
        return None
    return row[0], row[1], row[2]


def _known_commit(commit: str | None) -> bool:
    return bool(commit) and commit != UNKNOWN_VERSION


def _generation_mismatch(atlas: sqlite3.Connection, ctx: _DiffCtx) -> bool:
    """True when the two runs' candidates were provably produced by different extraction or hunt
    code: build_hash differs, or both hunt_commits are known and differ. An absent run proves
    nothing either way."""
    sa, sb = _gen_stamps(atlas, ctx.run_a), _gen_stamps(atlas, ctx.run_b)
    if sa is None or sb is None:
        return False
    if sa[1] != sb[1]:
        return True
    return _known_commit(sa[0]) and _known_commit(sb[0]) and sa[0] != sb[0]


# ── per-side indexes ─────────────────────────────────────────────────────────────────


def _key_class(cand: _Cand) -> str:
    """The matching key dimension: for a wrapper candidate (any tier) the AXIS, e.g.
    ``cmd_via_wrapper``, so a wrapper never shares a key with a direct sink of the same sink_class;
    for everything else the sink_class."""
    return cand.wrapper_axis or cand.sink_class


@dataclass
class _Side:
    """One side's candidates, indexed for the cross-side lookups, plus its co-claim fold."""

    cands: list[_Cand]
    t1_at: dict[str, list[_Cand]]  # callsite addr -> callsite / wrapper_callsite candidates
    deg_at: dict[str, list[_Cand]]  # callsite addr -> degraded candidates with a recovered addr
    fn_key: dict[tuple[str, str], list[_Cand]]  # (func, key_class) -> function_fallback / wrapper
    class_at_func: set[tuple[str, str]]  # (func, sink_class) of every direct-sink candidate
    folded: dict[str, list[_Cand]]  # callsite addr -> degraded candidates folded into it
    folded_ids: set[int]
    unresolved_ids: set[int]  # degraded candidates at a multi-claimed, unowned callsite
    by_func: dict[str, list[_Cand]] = field(default_factory=dict)  # func entry -> candidates


def _index(cands: list[_Cand]) -> _Side:
    t1_at: dict[str, list[_Cand]] = {}
    deg_at: dict[str, list[_Cand]] = {}
    fn_key: dict[tuple[str, str], list[_Cand]] = {}
    class_at_func: set[tuple[str, str]] = set()
    for c in cands:
        if c.tier in _CALLSITE_TIERS and c.callsite_addr is not None:
            t1_at.setdefault(c.callsite_addr, []).append(c)
        elif c.tier == _G_DEGRADED and c.callsite_addr is not None:
            deg_at.setdefault(c.callsite_addr, []).append(c)
        if c.tier in (_G_FUNCTION_FALLBACK, _G_WRAPPER):
            fn_key.setdefault((c.func_entry, _key_class(c)), []).append(c)
        if c.wrapper_axis is None:
            class_at_func.add((c.func_entry, c.sink_class))
    # co-claim fold (callsite_addr-gated): a degraded candidate whose recovered address is also a
    # callsite-tier candidate's address on the SAME side is folded into that candidate's row, never
    # double-counted. Pre-backfill no degraded candidate has an address, so nothing folds.
    folded: dict[str, list[_Cand]] = {}
    folded_ids: set[int] = set()
    claims: dict[str, list[_Cand]] = {}
    for addr, degs in deg_at.items():
        if addr in t1_at:
            folded[addr] = list(degs)
            folded_ids.update(d.iid for d in degs)
        else:
            claims[addr] = degs
    # one physical callsite claimed by >=2 different functions, with no callsite-tier owner: which
    # function really holds the call is unresolved, so those candidates' keys are never counted.
    unresolved_ids = {
        d.iid for degs in claims.values() if len({d.func_entry for d in degs}) >= 2 for d in degs
    }
    by_func: dict[str, list[_Cand]] = {}
    for c in cands:
        by_func.setdefault(c.func_entry, []).append(c)
    return _Side(
        cands, t1_at, deg_at, fn_key, class_at_func, folded, folded_ids, unresolved_ids, by_func
    )


@dataclass
class _Dir:
    """One judging direction: candidates of side ``this`` looked up on side ``other``."""

    side: str  # "a" | "b"
    this: _Side
    other: _Side
    align: dict[str, tuple[str, float, str]]  # this side's func -> (other func, conf, state)
    presence: dict[str, str]  # this side's unmatched-function presence states
    imatch: dict[str, str]  # this side's callsite addr -> other side's matched addr
    imatch_present: bool
    no_cand_reason: (
        str  # matched instruction on the other side is not a candidate (candidates-only)
    )
    backend: str = _BACKEND_FACTS
    # the OTHER side's call-site facts at its matched addresses, their state, whether they are from
    # an older extraction than that run's current one, and its stub-table state
    other_facts: dict[str, dict[str, Any] | None] = field(default_factory=dict)
    other_facts_state: str | None = None
    other_facts_stale: bool = False
    other_stub_state: str | None = None


# (presence, reason, match_basis, counterpart_call, other-side candidate or None,
#  counterpart_callee or None)
_Verdict = tuple[str, str | None, str | None, str | None, _Cand | None, dict[str, Any] | None]


def _function_unmatched(fe: str, d: _Dir) -> tuple[str, str | None]:
    """(presence, reason) for a candidate whose function has no counterpart on the other side —
    ALWAYS undetermined.

    ``unmatched_analysis_complete`` says only that THIS side's function exists and was decompiled.
    On the other side the function may have been deleted, inlined into a caller, moved to another
    binary, or fallen into an analysis hole; this layer cannot tell which, so it is never read as a
    removal or an addition: ``function_unmatched``. With no presence record at all the counterpart
    was never analysed; an incomplete analysis or an inventory mismatch is undetermined as well."""
    pstate = d.presence.get(fe)
    if pstate == "unmatched_analysis_complete":
        return _P_UNDET, "function_unmatched"
    if pstate is None:
        return _P_UNDET, "counterpart_not_analyzed"
    return _P_UNDET, "no_counterpart_undetermined"


def _callee_readable(cand: _Cand) -> bool:
    """Can this candidate's own callee be compared at all?"""
    if cand.wrapper_axis is None:
        return cand.sink is not None
    return cand.sink is not None and (cand.callee_addr is not None or cand.callee_name is not None)


def _same_callee(cand: _Cand, o: _Cand, d: _Dir) -> bool | None:
    """Is ``o`` (the other side, at the matched address) the same callee as ``cand``? None when it
    cannot be told.

    Different types (a wrapper call against a direct sink call — e.g. the wrapper was inlined) are
    different callees. Two direct sinks compare by sink name. Two wrapper calls are different when
    they forward to different sinks; otherwise ``W`` is compared by entry address through this
    diff's function alignment (only a high-confidence pair counts — anything else is unknown), and
    by name only when neither flow records an address. A missing sink name is unknown."""
    if (cand.wrapper_axis is None) != (o.wrapper_axis is None):
        return False
    if cand.sink is None or o.sink is None:
        return None
    if cand.wrapper_axis is None:
        return cand.sink == o.sink
    if cand.sink != o.sink:
        return False
    if cand.callee_addr is not None and o.callee_addr is not None:
        aligned = d.align.get(cand.callee_addr)
        if aligned is None or aligned[2] != "aligned":
            return None
        return aligned[0] == o.callee_addr
    if cand.callee_addr is not None or o.callee_addr is not None:
        return None  # one side's W is pinned by address, the other's is not: not comparable
    if cand.callee_name is not None and o.callee_name is not None:
        return cand.callee_name == o.callee_name
    return None


def _tier1_verdict(cand: _Cand, d: _Dir) -> _Verdict:
    """A callsite / wrapper_callsite candidate in an aligned, high-confidence function pair.

    persisted only when the instruction matched AND the other side has a callsite-tier candidate at
    the matched address with the SAME callee (``_same_callee``: same type, same sink by name — a
    same-name pair of different sink classes is still the same call — and for a wrapper the same
    ``W``, judged by its aligned entry address). A wrapper's callee is ``W`` together with the sink
    it forwards to, so "different" covers both a call to another ``W`` and the same ``W`` now
    forwarding to another sink. The address, not the name, decides ``W``: in a stripped binary
    ``FUN_<addr>`` names would otherwise state a false fact either way. If the comparison is
    unknown for any candidate there, or this one's own callee is unreadable: callee_unreadable."""
    ca = cand.callsite_addr
    if ca is None:  # a callsite tier with no address should not happen; stay honest
        return _P_UNDET, "crossside_match_degraded", "instruction", None, None, None
    other_addr = d.imatch.get(ca)
    if other_addr is None:
        # No instruction data at all -> the degraded period before layer-0 instruction persistence
        # was re-run. Data present but not this callsite -> an export gap OR a changed basic block
        # BinDiff did not pair; this backend cannot tell which, so it names neither.
        reason = "instruction_unmatched" if d.imatch_present else "crossside_match_degraded"
        return _P_UNDET, reason, "instruction", None, None, None
    t1 = d.other.t1_at.get(other_addr, [])
    if t1:
        verdicts = [(o, _same_callee(cand, o, d)) for o in t1]
        if not _callee_readable(cand) or any(v is None for _o, v in verdicts):
            return _P_UNDET, "callee_unreadable", "instruction", None, t1[0], None
        same = [o for o, v in verdicts if v]
        if same:
            same.sort(key=lambda o: o.sink_class != cand.sink_class)  # same class first
            return _P_PERSISTED, None, "instruction", None, same[0], None
        callee = {
            "matched_addr": other_addr,
            "callees": [_candidate_callee(o) for o in t1],
            "same_callee_candidate_elsewhere": _same_callee_elsewhere(cand, d),
        }
        return (
            _P_UNDET,
            "present_different_callee",
            "instruction",
            "present_different_callee",
            t1[0],
            callee,
        )
    if d.other.deg_at.get(other_addr):
        # only a degraded (function-level) candidate claims that address: never the persisted
        # object of a callsite-tier match.
        return _P_UNDET, "crossgranularity_unresolved", "instruction", None, None, None
    if d.backend == _BACKEND_CANDIDATES:
        # candidates only: the other side's callee there is unreadable -> honest undetermined
        return (
            _P_UNDET,
            d.no_cand_reason,
            "instruction",
            "counterpart_not_candidate",
            None,
            None,
        )
    return _facts_verdict(cand, d, other_addr)


# ── the matched instruction is not a candidate: read the call-site facts ─────────────────


@dataclass(frozen=True)
class _Ident:
    """One callee identity recorded at the other side's matched instruction, with the address it
    is compared by (``effective_addr``) and where that address came from (``addr_source``)."""

    name: str
    addr: str | None
    kind: str
    effective_addr: str | None
    addr_source: str | None

    def as_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "addr": self.addr,
            "kind": self.kind,
            "addr_source": self.addr_source,
        }


def _merge_addr(x: str | None, targets: list[str] | None) -> tuple[str | None, str | None]:
    """(effective_addr, addr_source) from the identity's own address ``x`` and the instruction's
    BinExport targets. A disagreement is NOT settled in favour of either: no address."""
    distinct = sorted(set(targets or []))
    if not distinct:
        return (x, "x") if x is not None else (None, None)
    if len(distinct) > 1:
        return None, "binexport_ambiguous"
    (target,) = distinct
    if x is None:
        return target, "binexport"
    if x == target:
        return target, "both"
    return None, "conflict"


def _idents(facts: dict[str, Any]) -> list[_Ident]:
    raw_targets = facts.get("targets")
    targets = [str(v) for v in raw_targets] if isinstance(raw_targets, list) else None
    seen: dict[tuple[str, str | None, str], _Ident] = {}
    for c in facts.get("callees") or []:
        if not isinstance(c, dict) or not isinstance(c.get("name"), str):
            continue
        name, kind = c["name"], str(c.get("kind") or "")
        addr = c.get("addr") if isinstance(c.get("addr"), str) else None
        eff, src = _merge_addr(addr, targets)
        seen.setdefault((name, addr, kind), _Ident(name, addr, kind, eff, src))
    return [seen[k] for k in sorted(seen, key=lambda k: (k[0], k[1] or "", k[2]))]


def _fact_same_callee(cand: _Cand, ident: _Ident, d: _Dir) -> bool | None:
    """Does the other side's instruction call ``cand``'s callee? Only its DIRECT callee is read.

    A direct sink compares by name, exactly (``strcpy`` is not ``__strcpy_chk``) — but a call
    through a stub the other side could not resolve is printed ``FUN_<stub>`` and would read as a
    different callee while it may well be the same import, so it is unknown: an unresolved stub, or
    any ``FUN_<hex>`` name where that side's stub table was never determined. A wrapper compares
    ``W`` by entry address through this diff's function alignment, never by name; with no address
    on either side, or no high-confidence alignment for ``W``, it is unknown."""
    if cand.wrapper_axis is None:
        if cand.sink is None or ident.kind == "stub_unresolved":
            return None
        if _FUN_NAME_RE.fullmatch(ident.name) and d.other_stub_state == "not_determined":
            return None
        return ident.name == cand.sink
    if cand.sink is None or cand.callee_addr is None or ident.effective_addr is None:
        return None
    aligned = d.align.get(cand.callee_addr)
    if aligned is None or aligned[2] != "aligned":
        return None
    return aligned[0] == ident.effective_addr


def _facts_verdict(cand: _Cand, d: _Dir, other_addr: str) -> _Verdict:
    """The matched other-side instruction carries no candidate: judge it by the call-site facts.

    Seven outcomes, all ``presence_undetermined`` — what the instruction calls is a fact about it,
    never a claim that the candidate's call persisted, went away or is new. In order: no readable
    facts for that side (``counterpart_call_facts_absent``); facts from an older extraction than
    that run's current one (``counterpart_facts_stale``); no CALL recorded at that address
    (``counterpart_no_call_fact`` — NOT "it is not a call": a register-indirect call records none);
    two or more different callees there (``counterpart_call_ambiguous``); a callee that cannot be
    compared (``counterpart_callee_unresolved``); the same callee (``counterpart_same_callee``);
    a different one (``counterpart_different_callee``)."""
    facts = d.other_facts.get(other_addr)
    if d.other_facts_state != "read" or facts is None:
        return _P_UNDET, "counterpart_call_facts_absent", "instruction", "unknown", None, None
    if d.other_facts_stale:
        return _P_UNDET, "counterpart_facts_stale", "instruction", "unknown", None, None
    idents = _idents(facts)
    if not idents:
        return _P_UNDET, "counterpart_no_call_fact", "instruction", "unknown", None, None
    if len(idents) > 1:
        return _P_UNDET, "counterpart_call_ambiguous", "instruction", "unknown", None, None
    same = _fact_same_callee(cand, idents[0], d)
    if same is None:
        return _P_UNDET, "counterpart_callee_unresolved", "instruction", "unknown", None, None
    callee: dict[str, Any] = {"matched_addr": other_addr, "callees": [idents[0].as_json()]}
    if same:
        return (
            _P_UNDET,
            "counterpart_same_callee",
            "instruction",
            "present_same_callee",
            None,
            callee,
        )
    callee["same_callee_candidate_elsewhere"] = _same_callee_elsewhere(cand, d)
    return (
        _P_UNDET,
        "counterpart_different_callee",
        "instruction",
        "present_different_callee",
        None,
        callee,
    )


def _candidate_callee(o: _Cand) -> dict[str, Any]:
    """A matched other-side CANDIDATE as a callee entry (its sink, or its wrapper ``W``)."""
    if o.wrapper_axis is None:
        return {"name": o.sink, "addr": None, "kind": "candidate", "addr_source": None}
    return {"name": o.callee_name, "addr": o.callee_addr, "kind": "candidate", "addr_source": None}


def _same_callee_elsewhere(cand: _Cand, d: _Dir) -> bool | None:
    """Does ANOTHER candidate in the other side's paired function have ``cand``'s callee?

    A different callee at the instruction BinDiff matched is not the same thing as "the callee was
    replaced": the call may well still be there, matched elsewhere. True = such a candidate exists;
    False = the paired function holds no candidate with this callee; None = it cannot be told (the
    function is not paired, or a candidate there could match but its callee is unreadable). Reads
    the candidate records only."""
    paired = d.align.get(cand.func_entry)
    if paired is None or paired[2] != "aligned" or cand.sink is None:
        return None
    peers = d.other.by_func.get(paired[0], [])
    unknown = False
    if cand.wrapper_axis is None:
        for o in peers:
            if o.wrapper_axis is not None:
                continue
            if o.sink is None:
                unknown = True
            elif o.sink == cand.sink:
                return True
        return None if unknown else False
    w = d.align.get(cand.callee_addr) if cand.callee_addr is not None else None
    if w is None or w[2] != "aligned":
        return None
    for o in peers:
        if o.wrapper_axis is None or o.sink != cand.sink:
            continue
        if o.callee_addr is None:
            unknown = True
        elif o.callee_addr == w[0]:
            return True
    return None if unknown else False


def _funclevel_verdict(cand: _Cand, other_fe: str, d: _Dir) -> _Verdict:
    """A function_fallback / wrapper candidate in an aligned, high-confidence function pair: the
    other side carries the same (function, key_class) at the same function-level granularity ->
    persisted. Otherwise undetermined — a candidate that merely looks gone/new inside an aligned
    function is never read as gone or new (the safe direction)."""
    peers = d.other.fn_key.get((other_fe, _key_class(cand)), [])
    if peers:
        return _P_PERSISTED, None, "function_level", None, peers[0], None
    if cand.tier == _G_FUNCTION_FALLBACK and (other_fe, cand.sink_class) in d.other.class_at_func:
        return _P_UNDET, "crossgranularity_unresolved", "function_level", None, None, None
    return _P_UNDET, "no_counterpart_undetermined", "function_level", None, None, None


def _verdict(cand: _Cand, d: _Dir) -> tuple[_Verdict, float | None]:
    fe = cand.func_entry
    if fe not in d.align:
        p, reason = _function_unmatched(fe, d)
        return (p, reason, "function_level", None, None, None), None
    other_fe, conf, state = d.align[fe]
    if state != "aligned":
        return (_P_UNDET, "alignment_low_confidence", None, None, None, None), conf
    if cand.tier in _CALLSITE_TIERS:
        return _tier1_verdict(cand, d), conf
    return _funclevel_verdict(cand, other_fe, d), conf


# ── row emission ─────────────────────────────────────────────────────────────────────


class _Out:
    """Rows plus the instance ids each side's rows represent (the coverage ledger)."""

    def __init__(self) -> None:
        self.rows: list[SinkOverlayRow] = []
        self.covered_a: set[int] = set()
        self.covered_b: set[int] = set()

    def emit(
        self, row: SinkOverlayRow, a: list[_Cand] | None = None, b: list[_Cand] | None = None
    ) -> int:
        self.rows.append(row)
        self.covered_a.update(c.iid for c in a or ())
        self.covered_b.update(c.iid for c in b or ())
        return len(self.rows) - 1


def _coclaimers(cands: list[_Cand]) -> list[str]:
    return sorted(c.func_entry for c in cands)


def _judge_pass(
    out: _Out, d: _Dir, diff_id: str, binary: str | None, b_row_of: dict[int, int] | None
) -> None:
    """Emit one row per non-degraded candidate of ``d.this`` not already represented.

    The A pass (``b_row_of`` given) records which row named each B candidate, so the B side's
    co-claim fold can join that row. The B pass skips every B candidate an A row already named."""
    covered_this = out.covered_a if d.side == "a" else out.covered_b
    for c in d.this.cands:
        if c.tier == _G_DEGRADED or c.iid in covered_this:
            continue
        (p, reason, mb, cc, other, callee), conf = _verdict(c, d)
        # a fold joins the first row of its callsite only (one listing, never double-counted)
        fold = [
            f for f in d.this.folded.get(c.callsite_addr or "", []) if f.iid not in covered_this
        ]
        this_ref, other_ref = c.ref, (other.ref if other else None)
        a_ref, b_ref = (this_ref, other_ref) if d.side == "a" else (other_ref, this_ref)
        row = SinkOverlayRow(
            diff_id=diff_id,
            binary=binary,
            sink_class=c.sink_class,
            a_ref=a_ref,
            b_ref=b_ref,
            key_granularity=c.tier,
            presence=p,
            presence_reason=reason,
            match_basis=mb,
            counterpart_call=cc,
            alignment_confidence=conf,
            coclaimed_by=(_coclaimers(fold) or None) if d.side == "a" else None,
            coclaimed_by_b=(_coclaimers(fold) or None) if d.side == "b" else None,
            counterpart_callee=callee,
        )
        mine = [c, *fold]
        theirs = [other] if other else []
        if d.side == "a":
            idx = out.emit(row, a=mine, b=theirs)
            if other is not None and b_row_of is not None:
                b_row_of.setdefault(other.iid, idx)
        else:
            out.emit(row, a=theirs, b=mine)


def _attach_b_folds_to_a_rows(out: _Out, b: _Side, b_row_of: dict[int, int]) -> None:
    """A B callsite-tier candidate the A pass already named carries its own B-side co-claim fold:
    merge it into THAT row (the B pass, which skips such candidates, never sees it)."""
    for addr, fold in b.folded.items():
        idx = next((b_row_of[o.iid] for o in b.t1_at.get(addr, []) if o.iid in b_row_of), None)
        if idx is None:
            continue  # no A row named this callsite's B candidate: the B pass carries the fold
        out.rows[idx] = replace(out.rows[idx], coclaimed_by_b=_coclaimers(fold))
        out.covered_b.update(c.iid for c in fold)


def _degraded_keys(side: _Side) -> dict[tuple[str, str], list[_Cand]]:
    keys: dict[tuple[str, str], list[_Cand]] = {}
    for c in side.cands:
        if c.tier == _G_DEGRADED and c.iid not in side.folded_ids:
            keys.setdefault((c.func_entry, _key_class(c)), []).append(c)
    return keys


def _key_row(
    out: _Out,
    d: _Dir,
    diff_id: str,
    binary: str | None,
    mine: list[_Cand],
    theirs: list[_Cand],
    paired: bool,
) -> None:
    """One degraded (function, sink_class) key row: the folded counts of both sides, compared."""
    rep, other_rep = mine[0], (theirs[0] if theirs else None)
    fe = rep.func_entry
    conf = d.align[fe][1] if fe in d.align else None
    poisoned = any(c.iid in d.this.unresolved_ids for c in mine) or any(
        c.iid in d.other.unresolved_ids for c in theirs
    )
    n_mine, n_theirs = len(mine), (len(theirs) if paired else None)
    p: str
    reason: str | None
    if poisoned:
        p, reason = _P_UNDET, "coclaim_unresolved"
    elif fe not in d.align:
        p, reason = _function_unmatched(fe, d)
    elif d.align[fe][2] != "aligned":
        p, reason = _P_UNDET, "alignment_low_confidence"
    elif n_mine == n_theirs:
        p, reason = _P_PERSISTED, None
    else:
        p, reason = _P_UNDET, "crossside_count_mismatch"
    this_ref, other_ref = rep.ref, (other_rep.ref if other_rep else None)
    a_ref, b_ref = (this_ref, other_ref) if d.side == "a" else (other_ref, this_ref)
    a_n, b_n = (n_mine, n_theirs) if d.side == "a" else (n_theirs, n_mine)
    row = SinkOverlayRow(
        diff_id=diff_id,
        binary=binary,
        sink_class=rep.sink_class,
        a_ref=a_ref,
        b_ref=b_ref,
        key_granularity=_G_DEGRADED,
        presence=p,
        presence_reason=reason,
        match_basis="function_level",
        counterpart_call=None,
        alignment_confidence=conf,
        a_n=a_n,
        b_n=b_n,
    )
    if d.side == "a":
        out.emit(row, a=mine, b=theirs)
    else:
        out.emit(row, a=theirs, b=mine)


def _tier2_rows(out: _Out, da: _Dir, db: _Dir, diff_id: str, binary: str | None) -> None:
    """Degraded (tier-2) rows: ONE row per (function, sink_class) key, carrying the folded A/B
    counts. Both sides are folded the same way before counting. Equal -> persisted; unequal ->
    crossside_count_mismatch; a key present on one side only gets its own row (count 0 on the
    other); a key touching an unresolved co-claim -> coclaim_unresolved, not counted."""
    a_keys, b_keys = _degraded_keys(da.this), _degraded_keys(db.this)
    consumed_b: set[tuple[str, str]] = set()
    for (fa, sc), mine in a_keys.items():
        if fa in da.align:
            kb = (da.align[fa][0], sc)
            consumed_b.add(kb)
            _key_row(out, da, diff_id, binary, mine, b_keys.get(kb, []), paired=True)
        else:
            _key_row(out, da, diff_id, binary, mine, [], paired=False)
    for kb, mine in b_keys.items():
        if kb in consumed_b:
            continue
        _key_row(out, db, diff_id, binary, mine, [], paired=kb[0] in db.align)


def _emit_flat(
    out: _Out,
    cands: list[_Cand],
    side: str,
    *,
    diff_id: str | None,
    binary: str | None,
    reason: str,
) -> None:
    """Every candidate of one side as presence_undetermined with one reason (no cross-side
    judgement possible): one row per candidate, the degraded ones one row per (binary, function,
    sink_class) key with their count — the same key shape the judged path uses."""
    keys: dict[tuple[str | None, str | None, str, str], list[_Cand]] = {}
    for c in cands:
        if c.tier == _G_DEGRADED:
            keys.setdefault((c.sha, c.binary_name, c.func_entry, _key_class(c)), []).append(c)
            continue
        out.emit(
            SinkOverlayRow(
                diff_id=diff_id,
                binary=binary if binary is not None else c.binary_name,
                sink_class=c.sink_class,
                a_ref=c.ref if side == "a" else None,
                b_ref=c.ref if side == "b" else None,
                key_granularity=c.tier,
                presence=_P_UNDET,
                presence_reason=reason,
                match_basis=None,
                counterpart_call=None,
                alignment_confidence=None,
            ),
            a=[c] if side == "a" else None,
            b=[c] if side == "b" else None,
        )
    for members in keys.values():
        rep = members[0]
        out.emit(
            SinkOverlayRow(
                diff_id=diff_id,
                binary=binary if binary is not None else rep.binary_name,
                sink_class=rep.sink_class,
                a_ref=rep.ref if side == "a" else None,
                b_ref=rep.ref if side == "b" else None,
                key_granularity=_G_DEGRADED,
                presence=_P_UNDET,
                presence_reason=reason,
                match_basis=None,
                counterpart_call=None,
                alignment_confidence=None,
                a_n=len(members) if side == "a" else None,
                b_n=len(members) if side == "b" else None,
            ),
            a=members if side == "a" else None,
            b=members if side == "b" else None,
        )


# ── compute ──────────────────────────────────────────────────────────────────────────


@dataclass
class _Computed:
    out: _Out
    a: _Loaded
    b: _Loaded


def _facts_stale(atlas: sqlite3.Connection, run_id: str, read_from: str | None) -> bool:
    """Were a side's call-site facts read from another extraction than its run's current one?
    Compared with the run row's ``build_hash``; a missing value on either end cannot be shown
    current, so it counts as stale (the outcome is undetermined either way)."""
    stamps = _gen_stamps(atlas, run_id)
    current = stamps[1] if stamps is not None else None
    return read_from is None or current is None or read_from != current


def _compute(
    atlas: sqlite3.Connection, diff_id: str, *, callee_backend: str = _BACKEND_FACTS
) -> _Computed | None:
    if callee_backend not in _CALLEE_BACKENDS:
        raise ValueError(
            f"callee_backend must be one of {_CALLEE_BACKENDS}, got {callee_backend!r}"
        )
    ctx = _load_diff_ctx(atlas, diff_id)
    if ctx is None:
        return None
    out = _Out()

    # diff-level honesty short-circuits: never collapse to unchanged. A side with no content hash
    # is loaded by name, only so its candidates stay visible.
    if ctx.sha_a is None or ctx.sha_b is None:
        a = (
            _load_candidates(atlas, ctx.run_a, ctx.sha_a)
            if ctx.sha_a
            else _load_candidates_by_name(atlas, ctx.run_a, ctx.binary)
        )
        b = (
            _load_candidates(atlas, ctx.run_b, ctx.sha_b)
            if ctx.sha_b
            else _load_candidates_by_name(atlas, ctx.run_b, ctx.binary_b or ctx.binary)
        )
        for side, ld in (("a", a), ("b", b)):
            _emit_flat(
                out,
                ld.cands,
                side,
                diff_id=diff_id,
                binary=ctx.binary,
                reason="diff_meta_missing_sha",
            )
        return _Computed(out, a, b)
    a = _load_candidates(atlas, ctx.run_a, ctx.sha_a)
    b = _load_candidates(atlas, ctx.run_b, ctx.sha_b)
    if not ctx.diff_ok:
        for side, ld in (("a", a), ("b", b)):
            _emit_flat(
                out, ld.cands, side, diff_id=diff_id, binary=ctx.binary, reason="diff_failed"
            )
        return _Computed(out, a, b)

    sa, sb = _index(a.cands), _index(b.cands)
    da = _Dir(
        side="a",
        this=sa,
        other=sb,
        align=ctx.align_a,
        presence=ctx.presence_a,
        imatch=ctx.imatch,
        imatch_present=ctx.imatch_present,
        no_cand_reason="counterpart_not_candidate",
        backend=callee_backend,
        other_facts=ctx.facts_b,
        other_facts_state=ctx.facts_state_b,
        other_facts_stale=_facts_stale(atlas, ctx.run_b, ctx.facts_hash_b),
        other_stub_state=ctx.stub_state_b,
    )
    db = _Dir(
        side="b",
        this=sb,
        other=sa,
        align=ctx.align_b,
        presence=ctx.presence_b,
        imatch=ctx.imatch_b,
        imatch_present=ctx.imatch_present,
        no_cand_reason="a_counterpart_not_candidate",
        backend=callee_backend,
        other_facts=ctx.facts_a,
        other_facts_state=ctx.facts_state_a,
        other_facts_stale=_facts_stale(atlas, ctx.run_a, ctx.facts_hash_a),
        other_stub_state=ctx.stub_state_a,
    )
    b_row_of: dict[int, int] = {}
    _judge_pass(out, da, diff_id, ctx.binary, b_row_of)
    _attach_b_folds_to_a_rows(out, sb, b_row_of)
    _judge_pass(out, db, diff_id, ctx.binary, None)
    _tier2_rows(out, da, db, diff_id, ctx.binary)

    # diff-wide comparability: a skewed or cross-generation pair cannot support ANY presence claim.
    wide = None
    if ctx.version_skew:
        wide = "version_skew"
    elif _generation_mismatch(atlas, ctx):
        wide = "extraction_generation_mismatch"
    if wide is not None:
        out.rows = [replace(r, presence=_P_UNDET, presence_reason=wide) for r in out.rows]
    return _Computed(out, a, b)


def _coverage(a: _Loaded, b: _Loaded, out: _Out) -> SinkOverlayCoverage:
    a_ids = {c.iid for c in a.cands}
    b_ids = {c.iid for c in b.cands}
    a_rep = len(a_ids & out.covered_a)
    b_rep = len(b_ids & out.covered_b)
    violation = a_rep != len(a_ids) or b_rep != len(b_ids)
    missing: list[str] = []
    if violation:
        missing = sorted(
            {c.ref for c in a.cands if c.iid not in out.covered_a}
            | {c.ref for c in b.cands if c.iid not in out.covered_b}
        )[:_UNREPRESENTED_SAMPLE]
    return SinkOverlayCoverage(
        a_total=len(a_ids),
        a_represented=a_rep,
        b_total=len(b_ids),
        b_represented=b_rep,
        excluded_legacy=a.legacy + b.legacy,
        coverage_violation=violation,
        unrepresented_refs=missing,
    )


def _check_presence_filter(presence: str | None) -> None:
    """Reject a presence filter this layer can never satisfy, instead of answering an empty list
    that would read as "none found"."""
    if presence is not None and presence not in _PRESENCE_VALUES:
        raise ValueError(
            f"presence must be None, 'persisted' or 'presence_undetermined', got {presence!r}: "
            "this backend never emits added/removed; a whole function with no counterpart is "
            "presence_undetermined with reason='function_unmatched'"
        )


def compute_sink_overlay(
    atlas: sqlite3.Connection,
    diff_id: str,
    *,
    binary: str | None = None,
    sink_class: str | None = None,
    presence: str | None = None,
    min_alignment_confidence: float | None = None,
    callee_backend: str = _BACKEND_FACTS,
) -> SinkOverlayResult:
    """Live-compute the candidate-level sink overlay for one diff. Reads function_alignment +
    function_presence + instruction_match (with its call-site facts) + both runs' candidate tables;
    writes nothing. The filters narrow the rows only; ``coverage`` always describes the whole diff.
    ``callee_backend`` is for checking the facts against the candidates-only reading."""
    _check_presence_filter(presence)
    comp = _compute(atlas, diff_id, callee_backend=callee_backend)
    if comp is None:
        empty = _Loaded([], 0)
        return SinkOverlayResult([], _coverage(empty, empty, _Out()))
    rows = _filter(comp.out.rows, binary, sink_class, presence, min_alignment_confidence)
    return SinkOverlayResult(rows, _coverage(comp.a, comp.b, comp.out))


def compute_sink_overlay_runs(
    atlas: sqlite3.Connection,
    run_a: str,
    run_b: str,
    *,
    binary: str | None = None,
    sink_class: str | None = None,
    presence: str | None = None,
    min_alignment_confidence: float | None = None,
    callee_backend: str = _BACKEND_FACTS,
) -> SinkOverlayResult:
    """The overlay over EVERY diff between two runs, plus every candidate no diff covers.

    A candidate whose binary (by content hash) has no diff row in this pair is still a row:
    ``shadowed_by_name_collision`` when a same-named binary with a different content hash WAS
    diffed (the name-keyed diff picked the other one), else ``binary_not_diffed``. Those rows have
    no diff_id and are never persisted. ``coverage`` is over both runs' whole candidate sets."""
    _check_presence_filter(presence)
    diffs = atlas.execute(
        "SELECT diff_id, sha256_a, sha256_b, binary_a, binary_b FROM diff_meta "
        "WHERE run_a_id = ? AND run_b_id = ? ORDER BY diff_id",
        (run_a, run_b),
    ).fetchall()
    out = _Out()
    for diff_id, *_rest in diffs:
        comp = _compute(atlas, diff_id, callee_backend=callee_backend)
        if comp is None:
            continue
        out.rows.extend(comp.out.rows)
        out.covered_a |= comp.out.covered_a
        out.covered_b |= comp.out.covered_b
    a = _load_run_candidates(atlas, run_a)
    b = _load_run_candidates(atlas, run_b)
    for side, ld, sha_i, name_i in (("a", a, 1, 3), ("b", b, 2, 4)):
        covered = out.covered_a if side == "a" else out.covered_b
        diffed_sha = {d[sha_i] for d in diffs if d[sha_i]}
        diffed_names = {d[name_i] for d in diffs if d[name_i]}
        groups: dict[str, list[_Cand]] = {}
        for c in ld.cands:
            if c.iid in covered or (c.sha is not None and c.sha in diffed_sha):
                continue  # represented by a diff (or a breach the coverage check will name)
            reason = (
                "shadowed_by_name_collision"
                if c.binary_name in diffed_names
                else "binary_not_diffed"
            )
            groups.setdefault(reason, []).append(c)
        for reason, cands in groups.items():
            _emit_flat(out, cands, side, diff_id=None, binary=None, reason=reason)
    rows = _filter(out.rows, binary, sink_class, presence, min_alignment_confidence)
    return SinkOverlayResult(rows, _coverage(a, b, out))


def _filter(
    rows: list[SinkOverlayRow],
    binary: str | None,
    sink_class: str | None,
    presence: str | None,
    min_conf: float | None,
) -> list[SinkOverlayRow]:
    out = rows
    if binary is not None:
        out = [r for r in out if r.binary == binary]
    if sink_class is not None:
        out = [r for r in out if r.sink_class == sink_class]
    if presence is not None:
        out = [r for r in out if r.presence == presence]
    if min_conf is not None:
        out = [
            r
            for r in out
            if r.alignment_confidence is not None and r.alignment_confidence >= min_conf
        ]
    return out


# ── reading a large result: reason filter, counts, stable pages ──────────────────────────


def filter_by_reason(rows: list[SinkOverlayRow], reason: str | None) -> list[SinkOverlayRow]:
    """Rows whose ``presence_reason`` equals ``reason``; all rows when ``reason`` is None."""
    if reason is None:
        return rows
    return [r for r in rows if r.presence_reason == reason]


def _row_order_key(r: SinkOverlayRow) -> tuple[str, str, str, str, str, str]:
    """A neutral, total-enough order for paging: by location and anchors only — never by presence
    or any notion of importance (the overlay is a map, not a ranking). Ties keep the compute order,
    which is itself deterministic, so the order is stable across calls."""
    return (
        r.diff_id or "",
        r.binary or "",
        r.key_granularity,
        r.sink_class,
        r.a_ref or "",
        r.b_ref or "",
    )


def _row_side(r: SinkOverlayRow) -> str:
    """Which side's candidate a row speaks for: ``a_only`` / ``b_only`` (one ref), ``both``, or
    ``neither`` (no ref — not produced by construction; counted, never dropped, if it appears)."""
    if r.a_ref and r.b_ref:
        return "both"
    if r.a_ref:
        return "a_only"
    if r.b_ref:
        return "b_only"
    return "neither"


def check_side_filter(side: str | None) -> None:
    """Reject a side filter other than ``a_only`` / ``b_only`` / ``both``."""
    if side is not None and side not in _SIDES:
        raise ValueError(f"side must be one of {_SIDES} or None, got {side!r}")


def filter_by_side(rows: list[SinkOverlayRow], side: str | None) -> list[SinkOverlayRow]:
    """Rows whose direction (``_row_side``) equals ``side``; all rows when ``side`` is None."""
    check_side_filter(side)
    if side is None:
        return rows
    return [r for r in rows if _row_side(r) == side]


def _reason_side_key(r: SinkOverlayRow) -> str:
    key = f"{r.presence}|{r.presence_reason or '-'}|{_row_side(r)}"
    if r.presence_reason == "counterpart_different_callee":
        elsewhere = (r.counterpart_callee or {}).get("same_callee_candidate_elsewhere")
        key += f"|same_callee_candidate_elsewhere={json.dumps(elsewhere)}"
    return key


def summarize_overlay(rows: list[SinkOverlayRow], *, by_binary: bool) -> dict[str, Any]:
    """Counts over ``rows`` (already filtered): total, and per presence, presence|reason, key
    granularity and sink class; per binary too when ``by_binary`` (run-pair mode, where a row's
    binary varies; a row with none counts under ``(none)``). ``by_presence_reason_side`` adds the
    row's direction (``presence|reason|side``), and splits ``counterpart_different_callee`` by
    ``same_callee_candidate_elsewhere``. Counts only — nothing is truncated."""

    def count(keys: list[str]) -> dict[str, int]:
        out: dict[str, int] = {}
        for k in keys:
            out[k] = out.get(k, 0) + 1
        return dict(sorted(out.items()))

    summary: dict[str, Any] = {
        "total_rows": len(rows),
        "by_presence": count([r.presence for r in rows]),
        "by_presence_reason": count([f"{r.presence}|{r.presence_reason or '-'}" for r in rows]),
        "by_presence_reason_side": count([_reason_side_key(r) for r in rows]),
        "by_key_granularity": count([r.key_granularity for r in rows]),
        "by_sink_class": count([r.sink_class for r in rows]),
    }
    if by_binary:
        summary["by_binary"] = count([r.binary or "(none)" for r in rows])
    return summary


def page_overlay(rows: list[SinkOverlayRow], *, limit: int, offset: int) -> dict[str, Any]:
    """One page of ``rows`` in the neutral order (``_row_order_key``): the page's rows, the total,
    and ``next_offset`` (None on the last page). Walking every page with the same arguments yields
    each row exactly once."""
    if limit < 1 or offset < 0:
        raise ValueError(f"page_overlay needs limit >= 1 and offset >= 0, got {limit}, {offset}")
    ordered = sorted(rows, key=_row_order_key)
    end = offset + limit
    return {
        "rows": ordered[offset:end],
        "total_rows": len(ordered),
        "offset": offset,
        "limit": limit,
        "next_offset": end if end < len(ordered) else None,
    }


# ── persistence (durable candidate-level baseline) ──────────────────────────────────────

_SENTINEL = "(none)"  # explicit non-NULL stand-in for the unmatched side in subject_key
_STAMP_FIELDS = ("hunt_commit", "build_hash", "hunt_instances")


def _subject_key(r: SinkOverlayRow) -> str:
    return f"{r.key_granularity}|{r.sink_class}|{r.a_ref or _SENTINEL}|{r.b_ref or _SENTINEL}"


def _coclaim_json(r: SinkOverlayRow) -> str | None:
    """Both sides' co-claimers in one JSON list, each entry side-tagged (``a:`` / ``b:``): the two
    sides' function entries live in different address spaces and must not be mixed untagged."""
    tagged = [f"a:{f}" for f in r.coclaimed_by or ()] + [f"b:{f}" for f in r.coclaimed_by_b or ()]
    return json.dumps(tagged) if tagged else None


def persist_sink_overlay(atlas: sqlite3.Connection, diff_id: str, *, commit: bool = True) -> int:
    """Compute the overlay for one diff and write it to dimension_delta as subject_kind='candidate'
    rows (the durable baseline). Replace-by-diff scoped to 'candidate' so a layer-2 edge refresh is
    untouched and vice versa. Returns the row count.

    REFUSED (SinkOverlayBaselineError, nothing written) when either run's ``hunt_commit`` is absent
    or ``unknown`` — the generation stamps could never be checked against a later hunt — or when the
    overlay breaks its coverage invariant (a baseline missing candidates would read as complete).

    Writes the diff layer: run it only after the runs are re-hunted and the diff re-run. The read
    API (get_diff_sink_overlay) computes live and does NOT need this. Re-run it after every re-run
    of this diff: the diff re-run deletes these rows with the rest of the diff."""
    from treasure_map.lib.atlas.models import DimensionDeltaRow
    from treasure_map.lib.atlas.writer import add_dimension_deltas, delete_dimension_delta

    ctx = _load_diff_ctx(atlas, diff_id)
    if ctx is None:
        raise SinkOverlayBaselineError(f"no diff {diff_id!r} in this atlas")
    stamps: dict[str, tuple[str | None, str | None, int | None]] = {}
    for side, run_id in (("a", ctx.run_a), ("b", ctx.run_b)):
        st = _gen_stamps(atlas, run_id)
        if st is None or not _known_commit(st[0]):
            got = None if st is None else st[0]
            raise SinkOverlayBaselineError(
                f"run {side.upper()} ({run_id!r}) has hunt_commit {got!r}: a baseline stamped "
                "with it could never be checked for staleness. Re-hunt it from an installed "
                "(non-editable) build first."
            )
        stamps[side] = st
    comp = _compute(atlas, diff_id)
    assert comp is not None  # ctx exists
    cov = _coverage(comp.a, comp.b, comp.out)
    if cov.coverage_violation:
        raise SinkOverlayBaselineError(
            f"overlay for {diff_id!r} leaves candidates unrepresented "
            f"(A {cov.a_represented}/{cov.a_total}, B {cov.b_represented}/{cov.b_total}); "
            "refusing to store an incomplete baseline"
        )
    (hc_a, bh_a, hi_a), (hc_b, bh_b, hi_b) = stamps["a"], stamps["b"]
    dd_rows: list[DimensionDeltaRow] = []
    for r in comp.out.rows:
        dd_rows.append(
            DimensionDeltaRow(
                diff_id=diff_id,
                dimension="presence",
                subject_kind="candidate",
                subject_key=_subject_key(r),
                delta_kind=_DELTA_KIND[r.presence],
                binary=r.binary,
                undetermined_scope="data" if r.presence == _P_UNDET else None,
                undetermined_reason=r.presence_reason if r.presence == _P_UNDET else None,
                alignment_confidence=r.alignment_confidence,
                presence=r.presence,
                key_granularity=r.key_granularity,
                match_basis=r.match_basis,
                counterpart_call=r.counterpart_call,
                coclaimed_by=_coclaim_json(r),
                a_n=r.a_n,
                b_n=r.b_n,
                hunt_commit_a=hc_a,
                hunt_commit_b=hc_b,
                build_hash_a=bh_a,
                build_hash_b=bh_b,
                hunt_instances_a=hi_a,
                hunt_instances_b=hi_b,
                overlay_version=SINK_OVERLAY_LOGIC_VERSION,
                counterpart_callee=(
                    json.dumps(r.counterpart_callee, sort_keys=True)
                    if r.counterpart_callee is not None
                    else None
                ),
            )
        )
    keys = [d.subject_key for d in dd_rows]
    if len(set(keys)) != len(keys):
        raise SinkOverlayBaselineError(f"overlay for {diff_id!r} has duplicate subject keys")
    delete_dimension_delta(atlas, diff_id, subject_kind="candidate", commit=False)
    add_dimension_deltas(atlas, dd_rows, commit=False)
    if commit:
        atlas.commit()
    return len(dd_rows)


def read_sink_overlay_baseline(atlas: sqlite3.Connection, diff_id: str) -> dict[str, Any]:
    """Read a diff's persisted candidate baseline, refusing it when stale.

    Every stored row's generation stamps (hunt_commit / build_hash / hunt_instances, both sides)
    are compared with the runs' CURRENT values. Any difference means a run was re-hunted or
    re-scanned after the baseline was written, so its rows describe candidates that may no longer
    exist. Its ``overlay_version`` is compared with SINK_OVERLAY_LOGIC_VERSION: rows written by
    other overlay logic would not match a live computation. Either way the answer is
    ``stale_baseline: true`` with the differing fields, and no rows."""
    ctx = _load_diff_ctx(atlas, diff_id)
    if ctx is None:
        return {"diff_id": diff_id, "error": "no such diff"}
    stored = atlas.execute(
        "SELECT subject_key, presence, undetermined_reason, key_granularity, match_basis, "
        "counterpart_call, coclaimed_by, a_n, b_n, alignment_confidence, binary, "
        "hunt_commit_a, hunt_commit_b, build_hash_a, build_hash_b, "
        "hunt_instances_a, hunt_instances_b, overlay_version "
        "FROM dimension_delta WHERE diff_id = ? AND subject_kind = 'candidate' ORDER BY id",
        (diff_id,),
    ).fetchall()
    if not stored:
        return {"diff_id": diff_id, "stale_baseline": False, "baseline_rows": 0, "rows": []}
    current: dict[str, tuple[str | None, str | None, int | None] | None] = {
        "a": _gen_stamps(atlas, ctx.run_a),
        "b": _gen_stamps(atlas, ctx.run_b),
    }
    mismatched: set[str] = set()
    for row in stored:
        for side, offset in (("a", 11), ("b", 12)):
            cur = current[side]
            for i, name in enumerate(_STAMP_FIELDS):
                stored_val = row[offset + 2 * i]
                if cur is None or stored_val != cur[i]:
                    mismatched.add(f"{name}_{side}")
        if row[17] != SINK_OVERLAY_LOGIC_VERSION:  # NULL (a pre-stamp baseline) is stale too
            mismatched.add("overlay_version")
    if mismatched:
        return {
            "diff_id": diff_id,
            "stale_baseline": True,
            "mismatched_fields": sorted(mismatched),
            "baseline_rows": len(stored),
            "rows": None,
        }
    cols = (
        "subject_key",
        "presence",
        "presence_reason",
        "key_granularity",
        "match_basis",
        "counterpart_call",
        "coclaimed_by",
        "a_n",
        "b_n",
        "alignment_confidence",
        "binary",
    )
    return {
        "diff_id": diff_id,
        "stale_baseline": False,
        "baseline_rows": len(stored),
        "rows": [dict(zip(cols, row[: len(cols)], strict=True)) for row in stored],
    }
