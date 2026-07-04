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
from treasure_map.lib.query import density as _density
from treasure_map.lib.query import dormant as _dormant
from treasure_map.lib.query import explain_candidate as _explain_candidate
from treasure_map.lib.query import filter_candidates as _filter_candidates
from treasure_map.lib.query import get_sink_provenance as _get_sink_provenance
from treasure_map.lib.query import ledger as _ledger
from treasure_map.lib.query import triage as _triage
from treasure_map.lib.query import twins as _twins

# A standing reminder attached to every candidate-listing / aggregation result: the ordering and
# recurrence signals are derived from neutral stored facts, carry their evidence, and are NOT a
# security verdict.
_DERIVED_SIGNAL_NOTE = (
    "score / entry_reach / device_spread / blocking_mechanism are DERIVED, evidence-backed "
    "review-ordering signals — NOT a verdict. A candidate is a lead to verify, never a confirmed "
    "issue."
)

# Hard cap on a single list_candidates page so an over-large limit cannot blow up the context.
_MAX_LIMIT = 200

# The server's standing instruction to an AI client: the working loop, not legalese. The legal
# notice stays reachable via the legal_notice tool (B4).
_AGENT_INSTRUCTIONS = (
    "Treasure Map exposes a firmware analysis knowledge base as read-only fact tools. Work the "
    "loop: RECALL -> FETCH FACTS -> JUDGE. (1) list_candidates gives leads ranked by a derived "
    "review-ordering score for the firmware this server is bound to (the current run); it is NOT "
    "a verdict — recall is deliberately wide, so expect false positives and DEMOTE a candidate "
    "yourself once the pseudocode shows it benign. (2) For a lead, follow its evidence_ref (the "
    "cross-tool anchor). explain_candidate carries a sink_arg_provenance_summary (per sink: where "
    "the sink argument's value comes from, by Ghidra def-use — kind, whether it resolved, and the "
    "sound nearest_dominating_writer for a reused stack buffer); get_sink_provenance(evidence_ref, "
    "sink_idx) then pulls that sink's full writers + format string + vararg sources, so you read "
    "the value origin from a table instead of rebuilding it by hand. Read facts: get_pseudocode "
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


def _candidate_dict(c: Any, current_run_id: str | None = None) -> dict[str, Any]:
    """One triage candidate as a flat, JSON-serializable record (anchor + derived signals)."""
    return {
        "evidence_ref": c.evidence_ref,  # the anchor
        "function": c.function,
        "binary_path": c.binary_path,
        "sink_anchor": c.sink_anchor,
        "sink_class": c.sink_class,
        "source_class": c.source_class,
        # fine-grained controllability of the source reaching the sink argument (free_string /
        # charset_safe / charset_maybe / unknown), surfaced from the candidate's flow_evidence —
        # the signal source_class folds away. DERIVED evidence, NOT a verdict.
        "source_kind": c.source_kind,
        "reachability_status": c.reachability_status,  # raw mechanism state (unknown/confirmed/…)
        "review_status": c.review_status,  # presentation relabel (to-verify / reachable / gated)
        "blocking_mechanism": c.blocking_mechanism,
        "origin": c.origin,
        "entry_reach": c.entry_reach,  # found promotes within tier; unknown is neutral
        "score": c.score,  # derived review-ordering signal, NOT a verdict
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

    def list_candidates(
        run_id: str | None = None,
        sink: str | None = None,
        sink_class: str | None = None,
        status: str | None = None,
        include_gated: bool = False,
        fingerprint: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """List recall candidates with their derived, evidence-backed review-ordering signals.

        Defaults to the firmware this server is bound to (the current run), so a shared atlas does
        not surface another image's leads. Filters mirror `tmap triage`: ``sink`` (a concrete
        callee like ``syslog`` OR a class like ``cmd``), ``sink_class`` (exact class), ``status``
        (to-verify / reachable / gated / all — default folds gated unless ``include_gated``).
        ``fingerprint`` narrows to one pattern's structural_fingerprint — pivot here from a
        cross_firmware_patterns hit to see its instances. Paged: ``limit`` (capped at 200) +
        ``offset``; the result carries ``total`` / ``returned`` / ``truncated`` / ``next_offset``.
        Each candidate carries its anchor (evidence_ref), structural_fingerprint, and
        is_current_run. Signals are DERIVED, NOT a verdict. Prefer a narrow filter and the head of
        the list, then fetch detail per evidence_ref — do not pull the whole list at once."""
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
        total = len(ranked)
        lim = max(0, min(limit, _MAX_LIMIT))
        off = max(0, offset)
        page = ranked[off : off + lim]
        end = off + len(page)
        return {
            "note": _DERIVED_SIGNAL_NOTE,
            "current_run_id": current_run_id,
            "isolated_to_run": isolated_to,
            # the firmware split, shown only when NOT isolated to a single run (else all one run)
            "runs": _run_summary(ranked) if isolated_to is None else None,
            # ★ Red-line: binaries whose analysis is incomplete (0 functions, not code-free) — a
            # non-empty list means the firmware is NOT fully analyzed, so absence of a candidate is
            # not proof of cleanliness. Re-run `tmap scan --reanalyze` to recover them.
            "incomplete_binaries": _incomplete_binaries(),
            "total": total,
            "returned": len(page),
            "offset": off,
            "limit": lim,
            "truncated": end < total,
            "next_offset": end if end < total else None,
            "candidates": [_candidate_dict(c, current_run_id) for c in page],
        }

    def cross_firmware_patterns(limit: int = 50) -> dict[str, Any]:
        """Per-pattern recurrence ledger — the highest-value cross-firmware signal.

        For each pattern: ``device_spread`` (how many distinct firmware runs it appears in) and
        ``pattern_breadth`` (distinct fine fingerprints). A candidate whose pattern recurs across
        many firmware images is worth reviewing sooner. DERIVED, evidence-backed, NOT a verdict."""
        conn = open_atlas(atlas_path)
        try:
            rows = _ledger(conn)
        finally:
            conn.close()
        return {
            "note": _DERIVED_SIGNAL_NOTE,
            "incomplete_binaries": _incomplete_binaries(),  # analysis-completeness honesty flag
            "count": len(rows),
            "patterns": [asdict(r) for r in rows[: max(0, limit)]],
        }

    def pattern_density(limit: int = 100) -> dict[str, Any]:
        """Candidate-instance density per (run, sink_class, fingerprint).

        A count difference for the same fingerprint across runs (e.g. present in one build, absent
        in another) is an early recurrence signal. DERIVED counts only, NOT a verdict."""
        conn = open_atlas(atlas_path)
        try:
            rows = _density(conn)
        finally:
            conn.close()
        return {
            "note": _DERIVED_SIGNAL_NOTE,
            "incomplete_binaries": _incomplete_binaries(),  # analysis-completeness honesty flag
            "count": len(rows),
            "density": [asdict(r) for r in rows[: max(0, limit)]],
        }

    def pattern_twins(limit: int = 100) -> dict[str, Any]:
        """Fingerprints seen with BOTH a blocked and a non-blocked instance (same shape, mixed).

        A mixed-reachability fingerprint can flag a guard present in one place and absent in
        another. May be empty depending on the atlas's firmware mix. DERIVED, NOT a verdict."""
        conn = open_atlas(atlas_path)
        try:
            rows = _twins(conn)
        finally:
            conn.close()
        return {
            "note": _DERIVED_SIGNAL_NOTE,
            "count": len(rows),
            "twins": [asdict(r) for r in rows[: max(0, limit)]],
        }

    def dormant_candidates(limit: int = 100) -> dict[str, Any]:
        """Candidates whose in-function path carries an identified guard (blocked, L0/L1).

        Useful to spot a guard that may be absent elsewhere. May be empty depending on the atlas's
        firmware mix. Each row is a lead, NOT a confirmed mitigation. DERIVED, NOT a verdict."""
        conn = open_atlas(atlas_path)
        try:
            rows = _dormant(conn)
        finally:
            conn.close()
        return {
            "note": _DERIVED_SIGNAL_NOTE,
            "count": len(rows),
            "dormant": [dict(r) for r in rows[: max(0, limit)]],
        }

    def explain_candidate(evidence_ref: str) -> dict[str, Any]:
        """Single-candidate fact view: score breakdown, honest claim bounds, where to verify.

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
        result says so honestly."""
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
