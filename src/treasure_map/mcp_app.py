# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Treasure Map MCP server — exposes the trustworthy fact substrate to an AI client.

This is the AI-facing surface of the analysis knowledge base. It is NOT an arbitrary
disassembly proxy: its value is the full, cross-artifact, deterministically re-derivable
structure (pseudocode / xrefs / callees / strings / imports-exports / cross-artifact script
call sites / SBOM + CVE) plus the derived, evidence-backed review-ordering signals — so an AI
can chase a lead across an entire firmware faster, more completely, and reproducibly, and make
the judgement itself.

The server is a THIN wrapper: every tool delegates to ``treasure_map.lib`` (facts + query), the
same layer the CLI uses — neither side re-implements a query. Two output contracts hold on every
tool:
  1. No anchor, no output — every result carries an evidence pointer (binary+function+address, or
     script+line); a lookup that resolves nothing returns a "not found" record, never a guess.
  2. Facts + chains + reachability evidence + honest bounds + trigger CONDITIONS only — the server
     never emits a payload / trigger bytes / PoC. (An AI reasoning over the facts we return may
     reach its own conclusion — that is the point; we do not write the attack input for it.)

Derived signals (the review-ordering score, entry-reach, blocking_mechanism) are always labelled
DERIVED, EVIDENCE-BACKED, NOT A VERDICT. No interpretation/prediction field (the dropped
summary / vuln_hint / has_user_input) is ever produced.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from treasure_map.lib import facts
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.notice import LEGAL_NOTICE
from treasure_map.lib.query import DEFAULT_LENS_LABEL as _LENS_LABEL
from treasure_map.lib.query import PHASE1_CAVEATS as _LENS_CAVEATS
from treasure_map.lib.query import VIEWS as _VIEWS
from treasure_map.lib.query import apply_view as _apply_view
from treasure_map.lib.query import canonical_view as _canonical_view
from treasure_map.lib.query import density as _density
from treasure_map.lib.query import dormant as _dormant
from treasure_map.lib.query import explain_candidate as _explain_candidate
from treasure_map.lib.query import filter_candidates as _filter_candidates
from treasure_map.lib.query import filter_match_count as _filter_match_count
from treasure_map.lib.query import get_nvram_key_flow as _get_nvram_key_flow
from treasure_map.lib.query import get_sink_provenance as _get_sink_provenance
from treasure_map.lib.query import ledger as _ledger
from treasure_map.lib.query import only_refusal as _only_refusal
from treasure_map.lib.query import parse_impact_order as _parse_impact_order
from treasure_map.lib.query import triage as _triage
from treasure_map.lib.query import twins as _twins

# A standing reminder attached to every candidate-listing / aggregation result: the ordering and
# recurrence signals are derived from neutral stored facts, carry their evidence, and are NOT a
# security verdict.
_DERIVED_SIGNAL_NOTE = (
    "the dimension layers / entry_reach / device_spread / lens ordering are DERIVED, "
    "evidence-backed facts — NOT a verdict. A candidate is a lead to verify, never a confirmed "
    "issue; a '?' layer is a coverage gap, never 'safe'."
)

# Hard cap on a single list_candidates page so an over-large limit cannot blow up the context.
_MAX_LIMIT = 200

# The server's standing instruction to an AI client: the working loop, not legalese. The legal
# notice stays reachable via the legal_notice tool (B4).
_AGENT_INSTRUCTIONS = (
    "Treasure Map exposes a firmware analysis knowledge base as read-only fact tools. Work the "
    "loop: RECALL -> FETCH FACTS -> JUDGE. (1) list_candidates is a multi-dimensional map: each "
    "lead carries an honest three-state annotation on every layer (controllability / "
    "source_writability / reachability / filtering / sink_impact / writer / completeness), ordered "
    "by a SWITCHABLE lens (sort_by / view / filters / impact_order) whose default sinks only "
    "provably-safe candidates and NEVER buries a '?'. It is NOT a verdict — recall is deliberately "
    "wide, so expect false positives and DEMOTE a candidate yourself once the pseudocode shows it "
    "benign. (2) For a lead, follow its evidence_ref (the "
    "cross-tool anchor). explain_candidate carries a sink_arg_provenance_summary (per sink: where "
    "the sink argument's value comes from, by Ghidra def-use — kind, whether it resolved, and the "
    "sound nearest_dominating_writer for a reused stack buffer); get_sink_provenance(evidence_ref, "
    "sink_idx) then pulls that sink's full writers + format string + vararg sources, so you read "
    "the value origin from a table instead of rebuilding it by hand. get_nvram_key_flow(key) gives "
    "one nvram key's cross-binary writers/readers (exact constant matches + separately flagged "
    "parametric template matches), each writer's value_source, and an honest completeness flag "
    "when caller-supplied keys could also touch it. Read facts: get_pseudocode "
    "(func = a name OR an address in any form; "
    "binary = short name OR full path), get_callees / get_xrefs to walk the call chain (an empty "
    "caller set may mean an indirect/dispatch-table call, not 'unreachable'), get_strings, "
    "get_functions_referencing_string (which functions mention a string, by pseudocode text "
    "match — not a resolved symbol xref), get_imports_exports, get_script_callsites, "
    "get_components_cves. (3) Judge value with the "
    "cross-firmware signals: cross_firmware_patterns (a pattern recurring across many firmware "
    "images) and get_components_cves (known-CVE components). Prefer narrow filters (run_id / sink "
    "/ status) and paging over pulling everything; fetch detail per evidence_ref. The tools draw "
    "no conclusion and emit no payload/PoC — that judgement is yours."
)


def _dimension_dict(d: Any) -> dict[str, Any]:
    """One map-layer annotation as a flat record: the honest three-state, value, source, note."""
    return {"name": d.name, "state": d.state, "value": d.value, "source": d.source, "note": d.note}


def _candidate_dict(c: Any, current_run_id: str | None = None) -> dict[str, Any]:
    """One candidate as a flat, JSON-serializable map point: anchor + every dimension layer.

    There is NO score — ``dimensions`` carries the honest per-layer three-state facts, and the
    listing order is the current lens (see the top-level ``lens`` field). Each layer is a FACT."""
    return {
        "evidence_ref": c.evidence_ref,  # the anchor
        "function": c.function,
        "binary_path": c.binary_path,
        "sink_anchor": c.sink_anchor,
        "sink_class": c.sink_class,
        "source_class": c.source_class,
        # fine-grained controllability of the source reaching the sink argument (free_string /
        # charset_safe / charset_maybe / unknown), surfaced from the candidate's flow_evidence.
        "source_kind": c.source_kind,
        # the nvram key feeding the sink (when the def-use provenance resolved an nvram getter);
        # None otherwise. Its web-settability drives the controllability layer.
        "nvram_source_key": c.nvram_source_key,
        # the honest map layers — every dimension a first-class annotation {state, value, source,
        # note}, NOT buried in flow_evidence. This REPLACES the old collapsed score.
        "dimensions": [_dimension_dict(d) for d in c.dimensions],
        "reachability_status": c.reachability_status,  # raw mechanism state (unknown/confirmed/…)
        "review_status": c.review_status,  # presentation relabel (to-verify / reachable / gated)
        "blocking_mechanism": c.blocking_mechanism,
        "origin": c.origin,
        "entry_reach": c.entry_reach,
        # The pattern fingerprint — pivot a cross_firmware_patterns hit to its instances via the
        # list_candidates(fingerprint=…) filter (same key density / ledger group by).
        "structural_fingerprint": c.structural_fingerprint,
        "source_run_id": c.source_run_id,
        # True when this candidate belongs to the firmware run the server is bound to (None when
        # the server is not bound to a specific run, e.g. explicit db paths with no run pointer).
        "is_current_run": (None if current_run_id is None else c.source_run_id == current_run_id),
    }


def _run_summary(candidates: list[Any]) -> list[dict[str, Any]]:
    """Per-run candidate counts, so an unisolated listing still shows the firmware split."""
    counts: dict[str | None, int] = {}
    for c in candidates:
        counts[c.source_run_id] = counts.get(c.source_run_id, 0) + 1
    return [
        {"source_run_id": run, "count": n}
        for run, n in sorted(counts.items(), key=lambda kv: (-kv[1], str(kv[0])))
    ]


def _parse_dim_filters(spec: str | None) -> list[tuple[str, str]]:
    """Parse a ``"dim=value,dim2=value2"`` filter string into (dim, value) pairs; blank/None -> [].

    Used for the map's dimension filters (controllability=free / sink_impact=cmd / source=nvram /
    reachability=entry:web ...). Malformed fragments (no '=') are skipped, never guessed."""
    if not spec:
        return []
    out: list[tuple[str, str]] = []
    for part in spec.split(","):
        d, sep, v = part.strip().partition("=")
        if sep and d.strip() and v.strip():
            out.append((d.strip(), v.strip()))
    return out


def _effective_spine(sort_by: str | None, view: str | None) -> str:
    """The pivot axis actually in force: explicit sort_by wins, else the view preset's spine, else
    the default 'impact' spine. A deprecated view alias is resolved first."""
    if sort_by:
        return sort_by
    resolved = _canonical_view(view)
    if resolved and resolved in _VIEWS:
        return str(_VIEWS[resolved]["spine"])
    return "impact"


def _page(rows: list[Any], limit: int, offset: int) -> tuple[list[Any], dict[str, Any]]:
    """Slice ``rows`` to a page and return (page, paging-meta) with explicit paging parity with
    list_candidates: ``count`` (full total), ``returned``, ``offset``, ``truncated``, and
    ``next_offset`` so the capped tail is REACHABLE — a limited aggregation never silently hides
    rows past the cap (the tail was previously counted but unreachable)."""
    lo = max(0, offset)
    hi = lo + max(0, limit)
    page = rows[lo:hi]
    truncated = hi < len(rows)
    meta = {
        "count": len(rows),
        "returned": len(page),
        "offset": lo,
        "truncated": truncated,
        "next_offset": hi if truncated else None,
    }
    return page, meta


def make_tools(
    analysis_db: Path | str, atlas_db: Path | str, run_id: str | None = None
) -> dict[str, Callable[..., Any]]:
    """Build the tool callables bound to one workspace's databases (and optionally one run).

    ``run_id`` is the firmware this server is bound to; list_candidates defaults to it so a shared
    cross-firmware atlas does not mix another image's leads into this session. Returned as plain
    functions so the CLI, the MCP registration, and the tests all invoke the SAME code path
    (parity by construction)."""
    analysis_path = Path(analysis_db)
    atlas_path = Path(atlas_db)
    current_run_id = run_id

    def _with_analysis(
        fn: Callable[[sqlite3.Connection], dict[str, Any]],
    ) -> dict[str, Any]:
        conn = facts.open_analysis_ro(analysis_path)
        try:
            return fn(conn)
        finally:
            conn.close()

    def _incomplete_binaries() -> list[str]:
        """Names of current-scan binaries whose analysis is incomplete (0 functions, not code-free).

        ★ Red-line: attached to the candidate/aggregation views so a consumer never mistakes a
        binary Ghidra failed on for one with nothing to find. Empty when the DB is unreadable."""
        try:
            conn = facts.open_analysis_ro(analysis_path)
        except sqlite3.OperationalError:
            return []
        try:
            return facts.list_incomplete_binaries(conn)
        finally:
            conn.close()

    def _partially_incomplete_binaries() -> list[dict[str, Any]]:
        """Current-scan binaries analyzed 'ok' but with some functions that never decompiled.

        ★ Red-line: complements _incomplete_binaries (which only catches 0-function total failures).
        Each entry is {binary, functions_total, functions_empty} so a consumer knows a binary was
        analyzed yet is INCOMPLETE on those N functions — a candidate there is not proof of
        cleanliness. Empty when the DB is unreadable."""
        try:
            conn = facts.open_analysis_ro(analysis_path)
        except sqlite3.OperationalError:
            return []
        try:
            return facts.list_partially_incomplete_binaries(conn)
        finally:
            conn.close()

    def list_candidates(
        run_id: str | None = None,
        sink: str | None = None,
        sink_class: str | None = None,
        status: str | None = None,
        include_gated: bool = False,
        fingerprint: str | None = None,
        sort_by: str | None = None,
        view: str | None = None,
        filters: str | None = None,
        only: str | None = None,
        impact_order: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """A multi-dimensional map of recall candidates, ordered by a switchable lens.

        Every candidate carries a three-state annotation on each dimension layer (controllability /
        source_writability / reachability / filtering / sink_impact / writer / completeness) —
        there is NO collapsed score. The DEFAULT lens spines on sink-impact, bands by
        impact x controllability, and sinks ONLY provably-safe candidates out of the first screen; a
        '?' never sinks (the demotion iron law rides under EVERY lens).

        Switch the lens (the list is re-ranked, never reduced — every candidate stays queryable):
        - ``sort_by``: pivot axis — impact (default) / controllability / reachability / by-sink.
        - ``view``: preset lens for a hunting goal — ``default`` (balanced start), ``by-sink``
          (sweep one sink class, e.g. all system()), ``nvram-source`` (hunt nvram-mediated bugs —
          the router-bug hotspot), ``reachable-first`` (FLOATS candidates with a direct rootfs entry
          reference to the top — MECHANISTIC, NOT call-graph reachability, an INCOMPLETE slice that
          misses the notify_rc bridge; the corpus stays whole; ``reachable-only`` is a deprecated
          alias). ``available_views`` lists each.
        - ``filters``: circle-and-weight dimension filters, ``"dim=value,dim2=value2"``
          (controllability=free / sink_impact=cmd / source=nvram / reachability=entry:web ...).
          Matches FLOAT to the first screen; the corpus is NEVER reduced (``corpus`` stays the full
          total, ``filter_match`` counts how many matched). "No match" is not "absent".
        - ``only``: SWEEP mode — prune the view to ``"dim=value"`` (e.g. sink_class=cmd). ``total``
          becomes the pruned view, but ``corpus`` stays whole. Accepted ONLY on a ground-truth
          dimension (sink_class/sink_impact); refused on an optimistic one (controllability / source
          / ...) with guidance to use ``filters`` instead. Combinable with ``filters``.
        - ``impact_order``: override the impact tiers, e.g. ``"cmd=fmt_string,copy,log"``.

        Legacy filters still apply: ``sink`` (callee OR class), ``sink_class`` (exact), ``status``
        (to-verify / reachable / gated / all), ``fingerprint`` (pivot from cross_firmware_patterns).
        Paged (``limit`` capped 200 + ``offset``). The result's ``lens`` names the active view and
        ``caveats`` states the honest phase-1 blind spots (optimistic 'free', near-always-'?'
        filtering). DERIVED facts, NOT a verdict — read the head, then fetch detail per ref."""
        effective = run_id if run_id is not None else current_run_id
        conn = open_atlas(atlas_path)
        try:
            ranked = _triage(conn, run_id=effective)
            isolated_to = effective
            # A stale/mismatched pointer can isolate to a run with no candidates. Rather than show
            # an empty list, fall back to all runs and annotate which one is current (B1 fallback).
            if run_id is None and current_run_id is not None and not ranked:
                ranked = _triage(conn, run_id=None)
                isolated_to = None
        finally:
            conn.close()
        ranked = _filter_candidates(ranked, sink=sink, status=status, include_gated=include_gated)
        if sink_class is not None:
            ranked = [c for c in ranked if c.sink_class == sink_class]
        if fingerprint is not None:
            ranked = [c for c in ranked if c.structural_fingerprint == fingerprint]
        # Apply the map lens: --filter dimensions circle-and-weight FLOAT (corpus never reduced); an
        # --only sweep prunes, refused on an optimistic/null-bearing dimension (which would silently
        # hide candidates). The composite key and demotion iron law ride under any spine.
        dim_filters = _parse_dim_filters(filters)
        only_filters = _parse_dim_filters(only)
        refusal = _only_refusal(only_filters, ranked)
        if refusal is not None:
            return {"note": _DERIVED_SIGNAL_NOTE, "error": refusal, "corpus": len(ranked)}
        corpus = len(ranked)  # the invariant total — a --filter float never changes it
        overrides = _parse_impact_order(impact_order) if impact_order else None
        ranked = _apply_view(
            ranked,
            view=view,
            sort_by=sort_by,
            dim_filters=dim_filters,
            only_filters=only_filters,
            impact_overrides=overrides or None,
        )
        total = len(ranked)
        filter_match = _filter_match_count(ranked, dim_filters) if dim_filters else None
        lim = max(0, min(limit, _MAX_LIMIT))
        off = max(0, offset)
        page = ranked[off : off + lim]
        end = off + len(page)
        return {
            "note": _DERIVED_SIGNAL_NOTE,
            # The active lens: a good default that does not lock the agent in. Switch it with
            # sort_by / view / filters / impact_order; the demotion iron law holds under them all.
            "lens": {
                "label": _LENS_LABEL,
                "spine": _effective_spine(sort_by, view),
                "view": view or "default",
                "filters": [f"{d}={v}" for d, v in dim_filters],
                # --filter circle-and-weights (floats matches, corpus whole); --only sweeps (prunes,
                # ground-truth dims only). filter_match = how many the --filter matched.
                "filter_match": filter_match,
                "only": [f"{d}={v}" for d, v in only_filters],
                "impact_order": impact_order or "default (cmd=fmt_string>copy>log)",
                "switchable": "sort_by / view / filters (float) / only (sweep) — re-ranks; "
                "--filter never reduces the corpus, --only prunes the view but corpus stays whole",
            },
            # The preset lenses the agent can switch to, each with its when-to-use note, so views
            # are DISCOVERABLE from the result itself (not only from this tool's docstring).
            "available_views": [
                {"view": name, "spine": preset["spine"], "when_to_use": preset["desc"]}
                for name, preset in _VIEWS.items()
            ],
            # The honest phase-1 blind spots — surfaced so the map is never read as complete.
            "caveats": list(_LENS_CAVEATS),
            "current_run_id": current_run_id,
            "isolated_to_run": isolated_to,
            # the firmware split, shown only when NOT isolated to a single run (else all one run)
            "runs": _run_summary(ranked) if isolated_to is None else None,
            # ★ Red-line: binaries whose analysis is incomplete (0 functions, not code-free) — a
            # non-empty list means the firmware is NOT fully analyzed, so absence of a candidate is
            # not proof of cleanliness. Re-run `tmap scan --reanalyze` to recover them.
            "incomplete_binaries": _incomplete_binaries(),
            # ★ Red-line: binaries analyzed 'ok' but where some functions never decompiled —
            # {binary, functions_total, functions_empty}. The candidate set is incomplete on those
            # functions, so absence of a candidate there is likewise not proof of cleanliness.
            "partially_incomplete_binaries": _partially_incomplete_binaries(),
            # ``corpus`` is the INVARIANT candidate total — a --filter float never changes it. Under
            # an --only sweep, ``total`` is the (smaller) pruned view; ``corpus`` still shows the
            # whole set so "no match" is never read as "absent".
            "corpus": corpus,
            "total": total,
            "returned": len(page),
            "offset": off,
            "limit": lim,
            "truncated": end < total,
            "next_offset": end if end < total else None,
            "candidates": [_candidate_dict(c, current_run_id) for c in page],
        }

    def cross_firmware_patterns(limit: int = 50, offset: int = 0) -> dict[str, Any]:
        """Per-pattern recurrence ledger — the highest-value cross-firmware signal.

        For each pattern: ``device_spread`` (how many distinct firmware runs it appears in) and
        ``pattern_breadth`` (distinct fine fingerprints). A candidate whose pattern recurs across
        many firmware images is worth reviewing sooner. Paged (``offset`` + ``truncated`` +
        ``next_offset``) so the tail past ``limit`` is reachable. DERIVED, NOT a verdict."""
        conn = open_atlas(atlas_path)
        try:
            rows = _ledger(conn)
        finally:
            conn.close()
        page, meta = _page(rows, limit, offset)
        return {
            "note": _DERIVED_SIGNAL_NOTE,
            "incomplete_binaries": _incomplete_binaries(),  # analysis-completeness honesty flag
            "partially_incomplete_binaries": _partially_incomplete_binaries(),  # partial-decompile
            **meta,
            "patterns": [asdict(r) for r in page],
        }

    def pattern_density(limit: int = 100, offset: int = 0) -> dict[str, Any]:
        """Candidate-instance density per (run, sink_class, fingerprint).

        A count difference for the same fingerprint across runs (e.g. present in one build, absent
        in another) is an early recurrence signal. Paged (``offset`` + ``truncated`` +
        ``next_offset``). DERIVED counts only, NOT a verdict."""
        conn = open_atlas(atlas_path)
        try:
            rows = _density(conn)
        finally:
            conn.close()
        page, meta = _page(rows, limit, offset)
        return {
            "note": _DERIVED_SIGNAL_NOTE,
            "incomplete_binaries": _incomplete_binaries(),  # analysis-completeness honesty flag
            "partially_incomplete_binaries": _partially_incomplete_binaries(),  # partial-decompile
            **meta,
            "density": [asdict(r) for r in page],
        }

    def pattern_twins(limit: int = 100, offset: int = 0) -> dict[str, Any]:
        """Fingerprints seen with BOTH a blocked and a non-blocked instance (same shape, mixed).

        A mixed-reachability fingerprint can flag a guard present in one place and absent in
        another. May be empty depending on the atlas's firmware mix. Paged (``offset`` +
        ``truncated`` + ``next_offset``). DERIVED, NOT a verdict."""
        conn = open_atlas(atlas_path)
        try:
            rows = _twins(conn)
        finally:
            conn.close()
        page, meta = _page(rows, limit, offset)
        return {
            "note": _DERIVED_SIGNAL_NOTE,
            **meta,
            "twins": [asdict(r) for r in page],
        }

    def dormant_candidates(limit: int = 100, offset: int = 0) -> dict[str, Any]:
        """Candidates whose in-function path carries an identified guard (blocked, L0/L1).

        Useful to spot a guard that may be absent elsewhere. May be empty depending on the atlas's
        firmware mix. Paged (``offset`` + ``truncated`` + ``next_offset``). Each row is a lead, NOT
        a confirmed mitigation. DERIVED, NOT a verdict."""
        conn = open_atlas(atlas_path)
        try:
            rows = _dormant(conn)
        finally:
            conn.close()
        page, meta = _page(rows, limit, offset)
        return {
            "note": _DERIVED_SIGNAL_NOTE,
            **meta,
            "dormant": [dict(r) for r in page],
        }

    def explain_candidate(evidence_ref: str) -> dict[str, Any]:
        """Single-candidate fact view: every dimension layer's honest three-state annotation
        (controllability / source_writability / reachability / filtering / sink_impact / writer /
        completeness), the lens caveats, the claim bounds, and where to verify — no score.

        Returns a not-found record when no instance carries ``evidence_ref`` (no fabrication)."""
        conn = open_atlas(atlas_path)
        try:
            ex = _explain_candidate(conn, evidence_ref)
        finally:
            conn.close()
        if ex is None:
            return {"found": False, "evidence_ref": evidence_ref}
        data = asdict(ex)
        data["found"] = True
        data["note"] = _DERIVED_SIGNAL_NOTE
        return data

    def get_sink_provenance(
        evidence_ref: str, sink_idx: int | None = None, dominating_only: bool = False
    ) -> dict[str, Any]:
        """Full sink-argument def-use provenance for a candidate — the on-demand detail behind the
        explain_candidate summary (which stays compact to fit the token budget).

        Omit ``sink_idx`` to get every sink's record for the function; pass one (the sink_idx from
        the explain summary) for a single sink's full detail: the writer set with sound CHK
        dominance ordering (``dominates_sink`` + ``nearest_dominating_writer``), each writer's
        format string and vararg sources, getter ``const_args``, or an honest ``unresolved``.
        Writers come dominating-first (the sound ones lead; the branch-noise tail follows) with each
        writer's varargs trimmed to what its format string actually consumes; pass
        ``dominating_only`` to return only the dominating writers. A surfaced Ghidra def-use FACT of
        where a sink argument's value comes from — never a verdict, and an unreachable origin is
        stated (``resolved: false``/``indirect_unresolved``), never dropped."""
        conn = open_atlas(atlas_path)
        try:
            result: dict[str, Any] = _get_sink_provenance(
                conn, evidence_ref, sink_idx, dominating_only=dominating_only
            )
        finally:
            conn.close()
        result["note"] = _DERIVED_SIGNAL_NOTE
        return result

    def get_nvram_key_flow(key: str) -> dict[str, Any]:
        """Cross-binary nvram key graph: who WRITES and who READS one nvram key (gap② phase 2).

        Turns "trace this config value across processes" from two manual reverse-lookups into one
        table read. For the concrete ``key``: ``writers`` / ``readers`` are EXACT (constant-key)
        matches, each carrying its binary + func + api and, for a writer, ``value_source`` (the
        Ghidra def-use origin of the written value — a controllability signal, so you see at a
        glance whether a caller-controlled value reaches this key). ``template_matches`` lists
        PARAMETRIC templates the key satisfies (e.g. ``wl%d_ssid`` for ``wl0_ssid``) — a POSSIBLE
        match flagged ``match:"template"``, never an exact connection; confirm the wildcard
        yourself. ``completeness`` is ``may_be_incomplete`` when unresolved-key ops exist
        (``unresolved_note`` says how many): a key that came from a caller could touch ANY key, so
        the writers/readers here may be incomplete — never read an empty result as "unused". Each
        entry carries ``source_run_id`` so a cross-firmware atlas stays legible. A surfaced FACT,
        never a verdict."""
        conn = open_atlas(atlas_path)
        try:
            result = _get_nvram_key_flow(conn, key)
        finally:
            conn.close()
        result["note"] = _DERIVED_SIGNAL_NOTE
        return result

    def get_pseudocode(function: str, binary: str | None = None) -> dict[str, Any]:
        """Decompiler pseudocode for one function (name or address); the default read view."""
        return _with_analysis(lambda c: facts.get_pseudocode(c, func=function, binary=binary))

    def get_callees(function: str, binary: str | None = None) -> dict[str, Any]:
        """Direct callee names of one function (intra-binary edges flagged resolved to follow)."""
        return _with_analysis(lambda c: facts.get_callees(c, func=function, binary=binary))

    def get_xrefs(
        function: str, direction: str = "callers", binary: str | None = None
    ) -> dict[str, Any]:
        """Cross-reference edges: direction='callers' or 'callees' (includes cross-binary edges)."""
        d: facts.XrefDirection = "callees" if direction == "callees" else "callers"
        return _with_analysis(
            lambda c: facts.get_xrefs(c, func=function, direction=d, binary=binary)
        )

    def get_strings(
        binary: str | None = None, function: str | None = None, value: str | None = None
    ) -> dict[str, Any]:
        """Recorded strings: by binary, narrowed to a function's range, or searched by ``value``.

        ``value`` searches string CONTENT and returns each hit with its address + owning binary
        (one-call locate); reference-site (which function uses a string) is not indexed — the
        result says so honestly. HONEST BOUND: a binary's string export is capped, so results carry
        ``truncated`` / ``total`` (by-binary) or ``search_may_be_incomplete`` (by-value) when a
        scanned binary was capped — a string NOT found there is NOT proven absent."""
        return _with_analysis(
            lambda c: facts.get_strings(c, binary=binary, func=function, value=value)
        )

    def get_imports_exports(binary: str) -> dict[str, Any]:
        """Import and export symbol tables of one binary (cross-binary edge endpoints)."""
        return _with_analysis(lambda c: facts.get_imports_exports(c, binary=binary))

    def get_functions_referencing_string(text: str, binary: str | None = None) -> dict[str, Any]:
        """Functions whose pseudocode TEXT contains a string (substring reverse-lookup).

        The schema indexes no string->function link, but functions.pseudocode is stored in full, so
        this answers "which functions mention this text". ``binary`` (short name or full path)
        narrows the scan; omitted, it scans every binary. Capped (``truncated`` when more exist).
        HONEST BOUND: a TEXT match, not a resolved symbol reference — the text may sit in a comment
        or an unrelated string literal; confirm each hit in the pseudocode."""
        return _with_analysis(
            lambda c: facts.get_functions_referencing_string(c, text=text, binary=binary)
        )

    def get_script_callsites(binary: str) -> dict[str, Any]:
        """Rootfs scripts that invoke this binary — entry-reach evidence (script + line + args)."""
        return _with_analysis(lambda c: facts.get_script_callsites(c, binary=binary))

    def get_components_cves(binary: str) -> dict[str, Any]:
        """SBOM components recognized in a binary + their CVE-table matches (a query result)."""
        return _with_analysis(lambda c: facts.get_components_cves(c, binary=binary))

    def get_disassembly(function: str, binary: str | None = None) -> dict[str, Any]:
        """On-demand disassembly — same-source aligned, or an honest 'unavailable' (never wrong)."""
        return _with_analysis(lambda c: facts.get_disassembly(c, func=function, binary=binary))

    def legal_notice() -> dict[str, Any]:
        """The tool's intended-use / legal notice."""
        return {"notice": LEGAL_NOTICE}

    return {
        "list_candidates": list_candidates,
        "explain_candidate": explain_candidate,
        "get_sink_provenance": get_sink_provenance,
        "get_nvram_key_flow": get_nvram_key_flow,
        "cross_firmware_patterns": cross_firmware_patterns,
        "pattern_density": pattern_density,
        "pattern_twins": pattern_twins,
        "dormant_candidates": dormant_candidates,
        "get_pseudocode": get_pseudocode,
        "get_callees": get_callees,
        "get_xrefs": get_xrefs,
        "get_strings": get_strings,
        "get_functions_referencing_string": get_functions_referencing_string,
        "get_imports_exports": get_imports_exports,
        "get_script_callsites": get_script_callsites,
        "get_components_cves": get_components_cves,
        "get_disassembly": get_disassembly,
        "legal_notice": legal_notice,
    }


def build_server(analysis_db: Path | str, atlas_db: Path | str, run_id: str | None = None) -> Any:
    """Construct a FastMCP server exposing the fact tools bound to one workspace.

    The server's standing instructions are the agent workflow guide; the legal notice stays
    reachable via the legal_notice tool. ``mcp`` is a core dependency (the server is the
    substrate's primary consumer), so FastMCP is imported at module top level, not lazily."""
    server = FastMCP("treasure-map", instructions=_AGENT_INSTRUCTIONS)
    for fn in make_tools(analysis_db, atlas_db, run_id).values():
        server.add_tool(fn)
    return server


def main() -> None:
    """Entry point: serve over stdio.

    DB paths and run id come from TREASURE_MAP_ANALYSIS_DB / _ATLAS_DB / _RUN_ID; when the db env
    vars are unset, fall back to the last-run pointer a prior scan recorded."""
    from treasure_map.lib.last_run import read_last_run

    analysis_db = os.environ.get("TREASURE_MAP_ANALYSIS_DB")
    atlas_db = os.environ.get("TREASURE_MAP_ATLAS_DB")
    run_id = os.environ.get("TREASURE_MAP_RUN_ID")
    if analysis_db is None or atlas_db is None:
        ptr = read_last_run()
        if ptr is not None:
            analysis_db = analysis_db or str(ptr.analysis_db)
            atlas_db = atlas_db or str(ptr.atlas_db)
            run_id = run_id or ptr.run_id
    build_server(analysis_db or "analysis.db", atlas_db or "atlas.db", run_id).run()


if __name__ == "__main__":
    main()
