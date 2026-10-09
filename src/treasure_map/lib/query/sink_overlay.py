"""C7 — candidate-level sink overlay (Layer 0.5).

On top of BinDiff's function-level alignment, line up the A/B sink candidates of one diff, or mark
them honestly as not lined-up. EVIDENCE ONLY: four states (added / removed / persisted /
presence_undetermined), never a fix-status verdict, never a path/taint engine.

Callee backend = atlas + BinDiff (the only data available without re-reading a .BinExport proto or
a run's analysis.db). BinDiff's instruction table pairs addresses POSITIONALLY and carries no
callee, so the callee is verified from BOTH sides' atlas candidate records. Where B has no
candidate at the matched address the callee is simply unreadable here, and the result is an honest
``presence_undetermined`` (reason ``counterpart_not_candidate``) — NEVER a guessed removed.

★ BACKEND SEAM (registered, not built): a future backend could supply the B-side callee and upgrade
the ``counterpart_not_candidate`` bucket into a richer counterpart split (a persisting same-callee
call that B no longer flags -> removed; a B address that is not a call -> its own reason; ...). Two
candidates:
  * backend B  — read the .BinExport2 protobuf's disassembly for the matched instruction's callee;
  * backend A+ — materialise tmap's own analysis.db call_tokens as the callee source for BOTH sides.
Either only reclassifies the "B has no candidate" bucket; neither reworks the model below. A+ is
likely more complete than B on MIPS (the fact layer sees calls BinExport drops). Trigger: a consumer
that needs trustworthy candidate-level ``removed``, after the backfill proves A+ feasible.
this module stays on the atlas+BinDiff backend and leaves that bucket undetermined.

HONESTY LINE (nailed, backend-independent): anything BinExport/BinDiff could not export or match
(callsite_not_exported / diff_failed / binary_not_diffed / crossside_match_degraded /
counterpart_not_candidate / counterpart_not_analyzed / alignment_low_confidence / ...) is
``presence_undetermined`` with a machine-readable reason — NEVER collapsed to unchanged / persisted
/ removed. ``removed``/``added`` are emitted ONLY at the function level (a whole function unmatched
on the other side with ``unmatched_analysis_complete``); a candidate that merely "looks gone" inside
an aligned function pair stays ``presence_undetermined`` (tmap can miss-render a real
call, and that extraction blindspot cannot be ruled out under this backend — safe direction).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any

from treasure_map.lib.query.triage import _callsite_addr

ALIGN_THRESHOLD = 0.9  # mirrors lib/diff/layer0.ALIGN_THRESHOLD; a pair below it is undetermined

# key_granularity values
_G_CALLSITE = "callsite"
_G_DEGRADED = "degraded_out_of_body"
_G_FUNCTION_FALLBACK = "function_fallback"
_G_WRAPPER = "wrapper"

# presence four-state
_P_ADDED = "added"
_P_REMOVED = "removed"
_P_PERSISTED = "persisted"
_P_UNDET = "presence_undetermined"

# presence -> delta_kind projection (CHECK-safe), so existing delta_kind consumers keep working
_DELTA_KIND = {
    _P_ADDED: "layer_changed",
    _P_REMOVED: "layer_changed",
    _P_PERSISTED: "layer_unchanged",
    _P_UNDET: "delta_undetermined",
}


@dataclass(frozen=True)
class SinkOverlayRow:
    """One candidate's cross-side overlay result. Each carries an evidence_ref anchor (the side with
    no counterpart is None) so it traces back to the fact layer."""

    diff_id: str
    binary: str | None
    sink_class: str
    a_ref: str | None
    b_ref: str | None
    key_granularity: str
    presence: str  # added | removed | persisted | presence_undetermined
    presence_reason: str | None  # machine-readable; only when presence_undetermined
    match_basis: str | None  # instruction | function_level | ordinal_singleton
    counterpart_call: str | None  # present_different_callee | counterpart_not_candidate (tier-1)
    alignment_confidence: float | None
    coclaimed_by: list[str] | None = None
    a_n: int | None = None
    b_n: int | None = None


@dataclass
class _Cand:
    """A sink candidate, parsed from one instance row."""

    ref: str
    sink_class: str
    sha: str | None
    func_entry: str | None  # normalized hex string of the containing function entry
    tier: str  # key_granularity
    callsite_addr: str | None  # normalized hex of the sink callsite; None at function level
    flow: dict[str, Any] = field(default_factory=dict)


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

    - wrapper: ref ends ``_via_wrapper`` -> no address.
    - callsite: ref has an addressed suffix ``@<class>@<offset>`` -> callsite_addr from the ref.
    - degraded_out_of_body: flow.callsite_located is False -> address iff the backfill wrote
      flow.callsite_addr (pre-backfill it is None and the row stays function-level).
    - function_fallback: everything else at function level (no marker, no address).
    """
    if ref.endswith("_via_wrapper"):
        return _G_WRAPPER, None
    addr = _callsite_addr(ref)
    if addr is not None:
        return _G_CALLSITE, _norm_addr(addr)
    if flow.get("callsite_located") is False:
        ca = flow.get("callsite_addr")  # hunt-side callsite_addr backfill; None pre-backfill
        if isinstance(ca, str) and ca:
            try:
                return _G_DEGRADED, _norm_addr(int(ca, 16))
            except ValueError:
                return _G_DEGRADED, None
        if isinstance(ca, int):
            return _G_DEGRADED, _norm_addr(ca)
        return _G_DEGRADED, None
    return _G_FUNCTION_FALLBACK, None


def _parse_flow(flow_evidence: str | None) -> dict[str, Any]:
    if not flow_evidence:
        return {}
    try:
        data = json.loads(flow_evidence)
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def _load_candidates(atlas: sqlite3.Connection, run_id: str, sha: str) -> list[_Cand]:
    """Every sink candidate of one run's binary (joined to its sha), parsed. Excludes legacy
    ``#fn<N>`` anchors (no address, no lineage) — they resolve to no function entry."""
    rows = atlas.execute(
        "SELECT i.evidence_ref, p.sink_class, i.binary_content_hash, i.flow_evidence "
        "FROM instance i JOIN pattern p ON i.pattern_id = p.pattern_id "
        "WHERE i.source_run_id = ? AND i.binary_content_hash = ?",
        (run_id, sha),
    ).fetchall()
    out: list[_Cand] = []
    for ref, sink_class, csha, fe in rows:
        if not ref:
            continue
        flow = _parse_flow(fe)
        func_entry = _func_entry_hex(ref)
        if func_entry is None:
            continue  # legacy / unparseable anchor -> excluded (visible by its absence here)
        tier, callsite_addr = _classify(ref, flow)
        out.append(
            _Cand(
                ref=ref,
                sink_class=sink_class or "",
                sha=csha,
                func_entry=func_entry,
                tier=tier,
                callsite_addr=callsite_addr,
                flow=flow,
            )
        )
    return out


# ── per-diff context ───────────────────────────────────────────────────────────────────


@dataclass
class _DiffCtx:
    diff_id: str
    binary: str | None
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
    # instruction matches at candidate callsites: A addr -> B addr; and whether ANY exist
    imatch: dict[str, str]
    imatch_present: bool


def _split_diff_id(diff_id: str) -> tuple[str, str, str]:
    run_a, run_b, binary = diff_id.split("::", 2)
    return run_a, run_b, binary


def _load_diff_ctx(atlas: sqlite3.Connection, diff_id: str) -> _DiffCtx | None:
    meta = atlas.execute(
        "SELECT run_a_id, run_b_id, binary_a, sha256_a, sha256_b, diff_ok, version_skew "
        "FROM diff_meta WHERE diff_id = ?",
        (diff_id,),
    ).fetchone()
    if meta is None:
        return None
    run_a, run_b, binary_a, sha_a, sha_b, diff_ok, version_skew = meta
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
    for addr_a, addr_b in atlas.execute(
        "SELECT addr_a, addr_b FROM instruction_match WHERE diff_id = ?", (diff_id,)
    ):
        imatch[addr_a] = addr_b
    return _DiffCtx(
        diff_id=diff_id,
        binary=binary_a,
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
        imatch_present=bool(imatch),
    )


# ── B-side candidate indexes (for callee verification + function-level presence) ───────


def _key_class(cand: _Cand) -> str:
    """The function-level matching key dimension: for a wrapper candidate the AXIS (the ref suffix,
    e.g. ``cmd_via_wrapper``), so a wrapper never matches a direct sink of the same sink_class; for
    everything else the sink_class."""
    if cand.tier == _G_WRAPPER:
        return cand.ref.rsplit("@", 1)[-1]
    return cand.sink_class


@dataclass
class _BIndex:
    by_callsite: dict[str, list[_Cand]]  # B callsite addr -> candidates
    by_func_class: dict[tuple[str, str], list[_Cand]]  # (b_func_entry, key_class) -> candidates
    by_func: dict[str, list[_Cand]]  # b_func_entry -> candidates


def _index_b(cands: list[_Cand]) -> _BIndex:
    by_callsite: dict[str, list[_Cand]] = {}
    by_func_class: dict[tuple[str, str], list[_Cand]] = {}
    by_func: dict[str, list[_Cand]] = {}
    for c in cands:
        if c.callsite_addr is not None:
            by_callsite.setdefault(c.callsite_addr, []).append(c)
        if c.func_entry is not None:
            by_func_class.setdefault((c.func_entry, _key_class(c)), []).append(c)
            by_func.setdefault(c.func_entry, []).append(c)
    return _BIndex(by_callsite, by_func_class, by_func)


def _removed_if_function_unmatched(cand: _Cand, ctx: _DiffCtx) -> tuple[str, str | None] | None:
    """If the candidate's function is unmatched on the B side, return the (presence, reason) for the
    A-side direction; else None (the function is aligned, judge at the callsite/function level).

    removed ONLY when B has no counterpart AND the B-side analysis is complete. An unmatched
    function whose analysis is incomplete, or an inventory mismatch, is undetermined, never removed.
    """
    fe = cand.func_entry
    if fe is None or fe in ctx.align_a:
        return None  # aligned (or no entry) -> not a function-level removal
    pstate = ctx.presence_a.get(fe)
    if pstate == "unmatched_analysis_complete":
        return _P_REMOVED, None
    if pstate is None:
        return _P_UNDET, "counterpart_not_analyzed"
    # unmatched_analysis_incomplete / inventory_mismatch -> existence undetermined
    return _P_UNDET, "no_counterpart_undetermined"


# ── per-candidate presence (aligned-function cases) ────────────────────────────────────


def _tier1_presence(
    cand: _Cand, ctx: _DiffCtx, b_index: _BIndex
) -> tuple[str, str | None, str, str | None, str | None]:
    """(presence, reason, match_basis, counterpart_call, b_ref) for a tier-1 (callsite) candidate in
    an aligned, high-confidence function pair."""
    ca = cand.callsite_addr
    if ca is None:  # a callsite tier with no address should not happen; stay honest
        return _P_UNDET, "crossside_match_degraded", "instruction", None, None
    addr_b = ctx.imatch.get(ca)
    if addr_b is None:
        # The diff WITH instruction persistence has matches but not this callsite -> it was not
        # exported/matched (MIPS non-PIC stub holes etc.). No instruction data at all -> the whole
        # degraded period, before layer-0 instruction persistence was re-run.
        reason = "callsite_not_exported" if ctx.imatch_present else "crossside_match_degraded"
        return _P_UNDET, reason, "instruction", None, None
    b_cands = b_index.by_callsite.get(addr_b, [])
    same = [b for b in b_cands if b.sink_class == cand.sink_class]
    if same:
        return _P_PERSISTED, None, "instruction", None, same[0].ref
    diff = [b for b in b_cands if b.sink_class != cand.sink_class]
    if diff:
        return (
            _P_UNDET,
            "present_different_callee",
            "instruction",
            "present_different_callee",
            diff[0].ref,
        )
    # instruction matched, but B has no candidate at addr_b: the B-side callee is unreadable under
    # the atlas+BinDiff backend -> honest undetermined, never a guessed removed/persisted.
    return _P_UNDET, "counterpart_not_candidate", "instruction", "counterpart_not_candidate", None


def _funclevel_presence(
    cand: _Cand, ctx: _DiffCtx, b_index: _BIndex
) -> tuple[str, str | None, str, str | None, str | None]:
    """(presence, reason, match_basis, counterpart_call, b_ref) for a tier-3/4 function-level
    candidate in an aligned function pair: both sides carry the (function, key_class) key ->
    persisted; only the A side -> undetermined (a candidate that merely 'looks gone' inside an
    aligned function is NEVER removed — the safe direction)."""
    b_fe = ctx.align_a[cand.func_entry][0]  # type: ignore[index]
    peers = b_index.by_func_class.get((b_fe, _key_class(cand)), [])
    if peers:
        return _P_PERSISTED, None, "function_level", None, peers[0].ref
    return _P_UNDET, "no_counterpart_undetermined", "function_level", None, None


def _aligned_undetermined(
    cand: _Cand, ctx: _DiffCtx
) -> tuple[str, str | None, float | None] | None:
    """If the candidate's function is aligned but LOW confidence, return (presence, reason, conf);
    else None (either not aligned — handled by the removed path — or aligned high-confidence)."""
    fe = cand.func_entry
    if fe is None or fe not in ctx.align_a:
        return None
    _b_fe, conf, state = ctx.align_a[fe]
    if state != "aligned":
        return _P_UNDET, "alignment_low_confidence", conf
    return None


def _row(
    cand: _Cand,
    ctx: _DiffCtx,
    *,
    presence: str,
    reason: str | None,
    match_basis: str | None,
    counterpart_call: str | None,
    b_ref: str | None,
    a_ref: str | None = None,
    a_n: int | None = None,
    b_n: int | None = None,
    coclaimed_by: list[str] | None = None,
) -> SinkOverlayRow:
    conf = ctx.align_a.get(cand.func_entry, (None, None, None))[1] if cand.func_entry else None
    return SinkOverlayRow(
        diff_id=ctx.diff_id,
        binary=ctx.binary,
        sink_class=cand.sink_class,
        a_ref=cand.ref if a_ref is None else a_ref,
        b_ref=b_ref,
        key_granularity=cand.tier,
        presence=presence,
        presence_reason=reason,
        match_basis=match_basis,
        counterpart_call=counterpart_call,
        alignment_confidence=conf,
        coclaimed_by=coclaimed_by,
        a_n=a_n,
        b_n=b_n,
    )


def compute_sink_overlay(
    atlas: sqlite3.Connection,
    diff_id: str,
    *,
    binary: str | None = None,
    sink_class: str | None = None,
    presence: str | None = None,
    min_alignment_confidence: float | None = None,
) -> list[SinkOverlayRow]:
    """Live-compute the candidate-level sink overlay for one diff. Reads function_alignment +
    function_presence + instruction_match + both runs' candidate tables; writes nothing."""
    ctx = _load_diff_ctx(atlas, diff_id)
    if ctx is None:
        return []
    rows: list[SinkOverlayRow] = []

    # diff-level honesty short-circuits: never collapse to unchanged.
    if ctx.sha_a is None or ctx.sha_b is None:
        for c in _load_candidates_by_name(atlas, ctx.run_a, ctx.binary):
            rows.append(
                _row(
                    c,
                    ctx,
                    presence=_P_UNDET,
                    reason="diff_meta_missing_sha",
                    match_basis=None,
                    counterpart_call=None,
                    b_ref=None,
                )
            )
        return _filter(rows, binary, sink_class, presence, min_alignment_confidence)
    a_cands = _load_candidates(atlas, ctx.run_a, ctx.sha_a)
    b_cands = _load_candidates(atlas, ctx.run_b, ctx.sha_b)
    if not ctx.diff_ok:
        for c in a_cands:
            rows.append(
                _row(
                    c,
                    ctx,
                    presence=_P_UNDET,
                    reason="diff_failed",
                    match_basis=None,
                    counterpart_call=None,
                    b_ref=None,
                )
            )
        return _filter(rows, binary, sink_class, presence, min_alignment_confidence)

    b_index = _index_b(b_cands)

    # co-claim fold (callsite_addr-gated): a degraded candidate whose address is also a tier-1
    # callsite in A is folded into that tier-1 row (co-claim), never double-counted. Pre-backfill no
    # degraded row has an address, so this set is empty and every degraded row stays function-level.
    a_tier1_addrs = {c.callsite_addr for c in a_cands if c.tier == _G_CALLSITE and c.callsite_addr}
    coclaim: dict[str, list[str]] = {}
    folded_degraded: set[int] = set()
    for i, c in enumerate(a_cands):
        if c.tier == _G_DEGRADED and c.callsite_addr and c.callsite_addr in a_tier1_addrs:
            coclaim.setdefault(c.callsite_addr, []).append(c.func_entry or "")
            folded_degraded.add(i)

    for i, cand in enumerate(a_cands):
        if cand.tier == _G_DEGRADED:
            continue  # tier-2 handled in aggregate below
        rm = _removed_if_function_unmatched(cand, ctx)
        if rm is not None:
            p, reason = rm
            rows.append(
                _row(
                    cand,
                    ctx,
                    presence=p,
                    reason=reason,
                    match_basis="function_level",
                    counterpart_call=None,
                    b_ref=None,
                )
            )
            continue
        low = _aligned_undetermined(cand, ctx)
        if low is not None:
            p, reason, _conf = low
            rows.append(
                _row(
                    cand,
                    ctx,
                    presence=p,
                    reason=reason,
                    match_basis=None,
                    counterpart_call=None,
                    b_ref=None,
                )
            )
            continue
        if cand.tier == _G_CALLSITE:
            p, reason, mb, cc, bref = _tier1_presence(cand, ctx, b_index)
            cob = coclaim.get(cand.callsite_addr or "") or None
            rows.append(
                _row(
                    cand,
                    ctx,
                    presence=p,
                    reason=reason,
                    match_basis=mb,
                    counterpart_call=cc,
                    b_ref=bref,
                    coclaimed_by=cob,
                )
            )
        else:  # function_fallback / wrapper
            p, reason, mb, cc, bref = _funclevel_presence(cand, ctx, b_index)
            rows.append(
                _row(
                    cand,
                    ctx,
                    presence=p,
                    reason=reason,
                    match_basis=mb,
                    counterpart_call=cc,
                    b_ref=bref,
                )
            )

    rows.extend(_tier2_rows(a_cands, b_cands, ctx, b_index, folded_degraded))
    rows.extend(_added_rows(b_cands, ctx))
    return _filter(rows, binary, sink_class, presence, min_alignment_confidence)


def _load_candidates_by_name(
    atlas: sqlite3.Connection, run_id: str, binary_short: str | None
) -> list[_Cand]:
    """Fallback loader for the diff_meta_missing_sha case: no sha to join on, so scope A candidates
    by run + binary short name (basename of binary_path). Fuzzy by design — used only to make the
    missing-sha binary's candidates VISIBLE as undetermined, never to judge them."""
    if not binary_short:
        return []
    rows = atlas.execute(
        "SELECT i.evidence_ref, p.sink_class, i.binary_content_hash, i.binary_path, "
        "i.flow_evidence "
        "FROM instance i JOIN pattern p ON i.pattern_id = p.pattern_id "
        "WHERE i.source_run_id = ?",
        (run_id,),
    ).fetchall()
    out: list[_Cand] = []
    for ref, sink_class, csha, bpath, fe in rows:
        if not ref or not bpath or bpath.rsplit("/", 1)[-1] != binary_short:
            continue
        flow = _parse_flow(fe)
        func_entry = _func_entry_hex(ref)
        if func_entry is None:
            continue
        tier, callsite_addr = _classify(ref, flow)
        out.append(
            _Cand(
                ref=ref,
                sink_class=sink_class or "",
                sha=csha,
                func_entry=func_entry,
                tier=tier,
                callsite_addr=callsite_addr,
                flow=flow,
            )
        )
    return out


def _tier2_rows(
    a_cands: list[_Cand], b_cands: list[_Cand], ctx: _DiffCtx, b_index: _BIndex, folded: set[int]
) -> list[SinkOverlayRow]:
    """Tier-2 (degraded_out_of_body) function-level rows: ONE row per (function, sink_class) key,
    carrying the folded A/B counts. Counts compared AFTER the co-claim fold (folded rows excluded).
    Equal -> persisted; unequal (incl. B absent) -> crossside_count_mismatch."""
    a_groups: dict[tuple[str, str], int] = {}
    a_rep: dict[tuple[str, str], _Cand] = {}
    for i, c in enumerate(a_cands):
        if c.tier != _G_DEGRADED or i in folded or c.func_entry is None:
            continue
        k = (c.func_entry, c.sink_class)
        a_groups[k] = a_groups.get(k, 0) + 1
        a_rep.setdefault(k, c)
    b_groups: dict[tuple[str, str], int] = {}
    b_rep: dict[tuple[str, str], _Cand] = {}
    for c in b_cands:
        if c.tier != _G_DEGRADED or c.func_entry is None:
            continue
        k = (c.func_entry, c.sink_class)
        b_groups[k] = b_groups.get(k, 0) + 1
        b_rep.setdefault(k, c)
    rows: list[SinkOverlayRow] = []
    for (fe, sc), a_n in a_groups.items():
        rep = a_rep[(fe, sc)]
        rm = _removed_if_function_unmatched(rep, ctx)
        if rm is not None:
            p, reason = rm
            rows.append(
                _row(
                    rep,
                    ctx,
                    presence=p,
                    reason=reason,
                    match_basis="function_level",
                    counterpart_call=None,
                    b_ref=None,
                    a_n=a_n,
                )
            )
            continue
        low = _aligned_undetermined(rep, ctx)
        if low is not None:
            p, reason, _conf = low
            rows.append(
                _row(
                    rep,
                    ctx,
                    presence=p,
                    reason=reason,
                    match_basis=None,
                    counterpart_call=None,
                    b_ref=None,
                    a_n=a_n,
                )
            )
            continue
        b_fe = ctx.align_a[fe][0]
        b_n = b_groups.get((b_fe, sc), 0)
        bref = b_rep[(b_fe, sc)].ref if (b_fe, sc) in b_rep else None
        if b_n == a_n:
            rows.append(
                _row(
                    rep,
                    ctx,
                    presence=_P_PERSISTED,
                    reason=None,
                    match_basis="function_level",
                    counterpart_call=None,
                    b_ref=bref,
                    a_n=a_n,
                    b_n=b_n,
                )
            )
        else:
            rows.append(
                _row(
                    rep,
                    ctx,
                    presence=_P_UNDET,
                    reason="crossside_count_mismatch",
                    match_basis="function_level",
                    counterpart_call=None,
                    b_ref=bref,
                    a_n=a_n,
                    b_n=b_n,
                )
            )
    return rows


def _added_rows(b_cands: list[_Cand], ctx: _DiffCtx) -> list[SinkOverlayRow]:
    """B candidates whose containing function is UNMATCHED on the A side: added when the A-side
    presence is analysis-complete, else undetermined. B candidates inside aligned functions
    are NOT emitted here (the A-side pass already represents them)."""
    rows: list[SinkOverlayRow] = []
    for c in b_cands:
        fe = c.func_entry
        if fe is None or fe in ctx.align_b:
            continue
        pstate = ctx.presence_b.get(fe)
        if pstate == "unmatched_analysis_complete":
            presence, reason = _P_ADDED, None
        elif pstate is None:
            presence, reason = _P_UNDET, "counterpart_not_analyzed"
        else:  # unmatched_analysis_incomplete / inventory_mismatch
            presence, reason = _P_UNDET, "no_counterpart_undetermined"
        rows.append(
            SinkOverlayRow(
                diff_id=ctx.diff_id,
                binary=ctx.binary,
                sink_class=c.sink_class,
                a_ref=None,
                b_ref=c.ref,
                key_granularity=c.tier,
                presence=presence,
                presence_reason=reason,
                match_basis="function_level",
                counterpart_call=None,
                alignment_confidence=None,
            )
        )
    return rows


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


# ── persistence (durable candidate-level baseline) ──────────────────────────────────────

_SENTINEL = "(none)"  # explicit non-NULL stand-in for the unmatched side in subject_key


def _gen_stamps(
    atlas: sqlite3.Connection, run_id: str
) -> tuple[str | None, str | None, int | None]:
    """(hunt_commit, build_hash, hunt_instances) for a run, from run; all None if absent."""
    row = atlas.execute(
        "SELECT hunt_commit, build_hash, hunt_instances FROM run WHERE run_id = ?", (run_id,)
    ).fetchone()
    if row is None:
        return None, None, None
    return row[0], row[1], row[2]


def persist_sink_overlay(atlas: sqlite3.Connection, diff_id: str, *, commit: bool = True) -> int:
    """Compute the overlay for one diff and write it to dimension_delta as subject_kind='candidate'
    rows (the durable baseline + the read-time staleness guard). Replace-by-diff scoped to
    'candidate' so a layer-2 edge refresh is untouched and vice versa. Returns the row count.

    OWNER-GATED (writes the diff layer): run only after the two data regens have landed and passed
    their trust gates. The read API (get_diff_sink_overlay) computes live and does NOT need this."""
    import json as _json

    from treasure_map.lib.atlas.models import DimensionDeltaRow
    from treasure_map.lib.atlas.writer import add_dimension_deltas, delete_dimension_delta

    ctx = _load_diff_ctx(atlas, diff_id)
    rows = compute_sink_overlay(atlas, diff_id)
    hc_a, bh_a, hi_a = _gen_stamps(atlas, ctx.run_a) if ctx else (None, None, None)
    hc_b, bh_b, hi_b = _gen_stamps(atlas, ctx.run_b) if ctx else (None, None, None)
    dd_rows: list[DimensionDeltaRow] = []
    for r in rows:
        subject_key = f"{r.key_granularity}|{r.a_ref or _SENTINEL}|{r.b_ref or _SENTINEL}"
        dd_rows.append(
            DimensionDeltaRow(
                diff_id=diff_id,
                dimension="presence",
                subject_kind="candidate",
                subject_key=subject_key,
                delta_kind=_DELTA_KIND[r.presence],
                binary=r.binary,
                undetermined_scope="data" if r.presence == _P_UNDET else None,
                undetermined_reason=r.presence_reason if r.presence == _P_UNDET else None,
                alignment_confidence=r.alignment_confidence,
                presence=r.presence,
                key_granularity=r.key_granularity,
                match_basis=r.match_basis,
                counterpart_call=r.counterpart_call,
                coclaimed_by=_json.dumps(r.coclaimed_by) if r.coclaimed_by else None,
                a_n=r.a_n,
                b_n=r.b_n,
                hunt_commit_a=hc_a,
                hunt_commit_b=hc_b,
                build_hash_a=bh_a,
                build_hash_b=bh_b,
                hunt_instances_a=hi_a,
                hunt_instances_b=hi_b,
            )
        )
    delete_dimension_delta(atlas, diff_id, subject_kind="candidate", commit=False)
    add_dimension_deltas(atlas, dd_rows, commit=False)
    if commit:
        atlas.commit()
    return len(dd_rows)
