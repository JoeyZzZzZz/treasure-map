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
from treasure_map.lib.atlas.models import PublicCvePatternRow, RunRow
from treasure_map.lib.atlas.writer import add_private_exploit as _add_private_exploit
from treasure_map.lib.atlas.writer import add_public_cve_patterns as _add_public_cve_patterns
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
from treasure_map.lib.query import get_run as _get_run
from treasure_map.lib.query import get_sink_provenance as _get_sink_provenance
from treasure_map.lib.query import get_string_keyed_edges as _get_string_keyed_edges
from treasure_map.lib.query import ledger as _ledger
from treasure_map.lib.query import list_cve_patterns as _list_cve_patterns
from treasure_map.lib.query import list_moat as _list_moat
from treasure_map.lib.query import list_runs as _list_runs
from treasure_map.lib.query import only_refusal as _only_refusal
from treasure_map.lib.query import parse_impact_order as _parse_impact_order
from treasure_map.lib.query import runs_where_function_exists as _runs_where_function_exists
from treasure_map.lib.query import state_value_label as _state_value_label
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
    "when caller-supplied keys could also touch it. The fact tools are RUN-AWARE: a shared atlas "
    "holds many firmware, so pass run_id (from list_runs) OR an evidence_ref (a candidate row's "
    "anchor, which self-resolves the run + binary + function); there is NO ambient default. Every "
    "result echoes resolved_run + run_lineage (build/scanned_at/scan_status) so you see which "
    "scan answered and whether it is stale — check list_runs before trusting an old scan. Read "
    "facts: get_pseudocode (func = a name OR an address in any form; "
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


# Dimensions promoted to a top-level spine label on the compact row: ALWAYS shown (even
# unknown:unknown), so the carry loop skips them to avoid emitting the same axis twice. Only
# controllability is promoted — every OTHER axis rides the axis-agnostic carry rule below, so a new
# Dimension (e.g. a future source=param axis) joins the row automatically without editing this set.
_SPINE_DIMENSIONS = frozenset({"controllability"})

# The compact-list legend (C8-6): a compact row OMITS any dimension whose state is ``unknown``,
# and an omitted dimension is a coverage gap — NEVER proven safe. Surfaced
# once on the envelope so a careless reader does not misread "not shown" as "no problem"
# (the per-row '?' reminder of the verbose view is gone; this restores it globally).
_COMPACT_ROW_LEGEND = (
    "compact rows = spine facts + every dimension with an ESTABLISHED state (state:value, no "
    "note). A dimension NOT shown on a row is state=unknown: a coverage gap, NOT proven safe. "
    "Fetch explain_candidate(evidence_ref) for that candidate's full per-dimension note."
)


# A one-line legend on the list envelope (M-A3): how to pull ANY row's code without typing three
# args. evidence_ref is already on every row and self-resolves run+binary+function, so this replaces
# a per-row fetch hint (which would bloat the list and go stale against the tool signature).
_FETCH_CODE_LEGEND = (
    "to read any candidate's code/callees/xrefs, pass that row's evidence_ref: "
    "get_pseudocode(evidence_ref=<row.evidence_ref>) — it resolves the run + binary + function for "
    "you (no need to retype run_id). Or pass run_id + function explicitly."
)


def _dim_label(d: Any) -> str:
    """One dimension compressed to a single ``state:value`` label (no note) for the compact row —
    the same honest ``state:value`` format the explain rollup's labeled fields use (one source)."""
    return _state_value_label(d)


def _lineage_inline(run: RunRow) -> dict[str, Any]:
    """The run's scan lineage, inlined on EVERY fact return (M6) so a consumer spots a STALE scan
    without a separate list_runs call (a stale scan is silent — the lineage must be printed, not
    fetched). ``resolved`` is False for a pre-existing run with no lineage row."""
    return {
        "build_hash": run.build_hash,
        "scanned_at": run.scanned_at,
        "scan_status": run.scan_status,
        "tool_version": run.tool_version,
        "resolved": run.resolved,
    }


def _short_binary(binary_path: str | None) -> str | None:
    """The binary's short name (last path segment) for the compact row; None passes through."""
    if binary_path is None:
        return None
    return binary_path.rsplit("/", 1)[-1] or binary_path


def _candidate_row(c: Any, rank: int) -> dict[str, Any]:
    """One candidate as a COMPACT triage row (the compact-row carry contract C1-C3).

    Spine facts (always present) + every non-spine dimension whose state is ESTABLISHED
    (``state != "unknown"``), each compressed to one ``state:value`` label with NO note — the full
    per-dimension note lives in explain_candidate. The carry loop is AXIS-AGNOSTIC: it walks
    ``c.dimensions`` and never hardcodes a dimension whitelist, so any future axis that is a
    Dimension with an established state joins the row automatically (the anti-'hidden marker'
    invariant). The baseline it omits is the UNKNOWN semantics (not proven safe), never a
    per-firmware modal value.

    ``run`` names the candidate's firmware run (source_run_id) explicitly — a shared atlas mixes
    firmware, so a row must carry its own run rather than lean on an ambient 'current run' (the
    ambient marker was the run-binding hazard; there is no is_current_run flag any more)."""
    carried = {
        d.name: _dim_label(d)
        for d in c.dimensions
        if d.name not in _SPINE_DIMENSIONS and d.state != "unknown"
    }
    return {
        # the anchor — pass to explain_candidate / get_sink_provenance / get_pseudocode(ref)
        "evidence_ref": c.evidence_ref,
        # position under the current lens (0-based, absolute; re-ranked on a lens switch)
        "rank": rank,
        "sink_class": c.sink_class,
        "sink": c.sink_anchor,
        # controllability is spine: ALWAYS present as one state:value label, even unknown:unknown.
        "controllability": _dim_label(c.dim("controllability")),
        "nvram_source_key": c.nvram_source_key,  # the key feeding the sink (spots an nvram cluster)
        "run": c.source_run_id,  # this candidate's firmware run (explicit; no ambient current run)
        "binary": _short_binary(c.binary_path),
        "function": c.function,
        "structural_fingerprint": c.structural_fingerprint,
        # Non-spine dimensions with an established state, each "state:value" (no note). A dimension
        # NOT here is state=unknown — a coverage gap, NOT proven safe (see the envelope legend).
        "dimensions": carried,
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
    atlas_db: Path | str, *, workspaces_root: Path | str | None = None
) -> dict[str, Callable[..., Any]]:
    """Build the tool callables bound to ONE atlas (not one firmware).

    The server binds the shared, persistent atlas — NOT a single analysis.db. A run-aware fact tool
    resolves ``run_id`` -> analysis.db through the atlas ``run`` table (the stored resolver), so one
    server serves every firmware in the atlas and never silently answers from the wrong scan. There
    is NO ambient 'current run' default: a fact tool takes an explicit ``run_id`` or an
    ``evidence_ref`` (which self-resolves the run), else it errors. ``workspaces_root`` is an
    OPTIONAL fallback resolver (``<root>/<run_id>/analysis.db``) for the common
    run_id==workspace-name case; the run table is the authority. Returned as plain functions so the
    CLI, the MCP registration, and the tests all invoke the SAME code path (parity by
    construction)."""
    atlas_path = Path(atlas_db)
    ws_root = Path(workspaces_root) if workspaces_root is not None else None

    def _error(atlas: sqlite3.Connection, msg: str) -> dict[str, Any]:
        """A hard-error fact result: never a silent empty. Carries ``runs_in_atlas`` (M-A1) so the
        consumer can immediately see which runs DO exist and re-issue against the right one."""
        return {
            "found": False,
            "error": msg,
            "runs_in_atlas": [r.run_id for r in _list_runs(atlas)],
            "note": _DERIVED_SIGNAL_NOTE,
        }

    def _resolve_ref(
        atlas: sqlite3.Connection, evidence_ref: str
    ) -> tuple[str | None, str | None, str | None] | None:
        """An evidence_ref -> (run_id, binary, function) from its atlas instance, or None if absent.

        Lets a fact tool take a candidate row's evidence_ref and self-resolve the run + binary +
        function (no retyping) — the same anchor explain_candidate resolves, reused here."""
        row = atlas.execute(
            "SELECT source_run_id, binary_path, source_anchor FROM instance "
            "WHERE evidence_ref = ? ORDER BY instance_id LIMIT 1",
            (evidence_ref,),
        ).fetchone()
        if row is None:
            return None
        return (row["source_run_id"], _short_binary(row["binary_path"]), row["source_anchor"])

    def _resolve_locus(
        atlas: sqlite3.Connection,
        run_id: str | None,
        evidence_ref: str | None,
        function: str | None,
        binary: str | None,
    ) -> dict[str, Any]:
        """Resolve the target run (+ effective function/binary) with NO ambient default.

        evidence_ref (via_ref) self-resolves run+binary+function; else an explicit run_id; else a
        hard error. Returns {run, run_source, function, binary, warning} or an error dict (has
        'error'). A run absent from the atlas is the run-not-found hard error (G3)."""
        fn, bn, warning = function, binary, None
        if evidence_ref is not None:
            ref = _resolve_ref(atlas, evidence_ref)
            if ref is None:
                return _error(
                    atlas,
                    f"evidence_ref '{evidence_ref}' does not anchor any candidate in this atlas.",
                )
            ref_run, ref_bin, ref_fn = ref
            if run_id is not None and run_id != ref_run:
                warning = (
                    f"⚠ run_id='{run_id}' but evidence_ref belongs to run '{ref_run}'; "
                    f"using the ref's run '{ref_run}'."
                )
            target_run, run_source = ref_run, "via_ref"
            fn = function if function is not None else ref_fn
            bn = binary if binary is not None else ref_bin
        elif run_id is not None:
            target_run, run_source = run_id, "explicit"
        else:
            return _error(
                atlas,
                "no run_id and no evidence_ref — a fact tool needs one (no ambient default "
                "binding). Pass run_id=<id> (see list_runs) or evidence_ref=<a candidate's ref>.",
            )
        if target_run is None:
            return _error(
                atlas, "evidence_ref resolved to a null run — its instance has no run id."
            )
        run = _get_run(atlas, target_run)
        if run is None:
            avail = [r.run_id for r in _list_runs(atlas)]
            return _error(atlas, f"run '{target_run}' not in this atlas; available runs: {avail}")
        return {
            "run": run,
            "run_source": run_source,
            "function": fn,
            "binary": bn,
            "warning": warning,
        }

    def _resolve_db(atlas: sqlite3.Connection, run: RunRow) -> Path | dict[str, Any]:
        """The run's analysis.db Path, or a hard error (G4) — never a silent empty.

        ★ Honesty red-line (non-match must not collapse into absent): a run in the atlas but with NO
        recorded analysis.db (``analysis_db_path`` empty = a pre-existing scan never trustworthily
        analyzed by this tool chain) short-circuits to re-scan BEFORE any db is opened. A residual
        old analysis.db sitting in the workspaces root carries NO lineage backing (unknown build /
        status / completeness); reviving it via the ws_root fallback and then MISSING a function
        would masquerade UNKNOWN ("never analyzed") as NO ("analyzed and absent") — the exact
        collapse this tool exists to prevent. So the ws_root fallback ONLY recovers a run that HAS a
        lineage row whose authoritative path file moved (a legitimate migration), never a no-lineage
        run."""
        if not run.analysis_db_path:
            return _error(
                atlas,
                f"run '{run.run_id}' has no recorded analysis.db (a pre-existing scan with no "
                "lineage row) — re-scan it to enable fact tools on this run.",
            )
        authoritative = Path(run.analysis_db_path)
        if authoritative.exists():
            return authoritative
        # The authoritative path was recorded but the file is gone (a legitimate move) — the ws_root
        # fallback may recover THE SAME run's db; else it is honestly 'moved', never 'no findings'.
        if ws_root is not None and (ws_root / run.run_id / "analysis.db").exists():
            return ws_root / run.run_id / "analysis.db"
        return _error(
            atlas,
            f"analysis.db for run '{run.run_id}' not found at {authoritative} (moved, or the "
            "workspace deleted?) — re-scan to restore it. NOT read as 'no findings'.",
        )

    def _augment_cross_run(
        atlas: sqlite3.Connection,
        result: dict[str, Any],
        run_id: str,
        function: str,
        binary: str | None,
    ) -> None:
        """Distinguish "wrong run" from "no such function" on a function miss (Q1-a vs Q1-b).

        If ``function`` was not found in ``run_id`` but its instances appear in OTHER runs, name
        them (you are likely querying the wrong run). If it is in NO run, say so (a typo / a
        function with no recorded candidate). A cheap atlas-index diagnosis, best-effort — never a
        decompile."""
        hits = _runs_where_function_exists(atlas, binary=binary, function=function)
        others = [h for h in hits if h != run_id]
        if others:
            result["found_in_runs"] = others
            result["cross_run_note"] = (
                f"'{function}' was not found in run '{run_id}', but its instances appear in "
                f"run(s): {others} — you may be querying the wrong run."
            )
        elif not hits:
            result["cross_run_note"] = (
                f"'{function}' is not in ANY run in this atlas — check the name/binary (a typo, or "
                "a function that carries no recorded candidate)."
            )

    def _fact(
        call: Callable[[sqlite3.Connection, str | None, str | None], dict[str, Any]],
        *,
        run_id: str | None,
        evidence_ref: str | None,
        function: str | None = None,
        binary: str | None = None,
        diagnose: bool = False,
    ) -> dict[str, Any]:
        """Run one analysis.db fact under run-aware routing (the shared body of every fact tool).

        Resolves the run (or errors), opens THAT run's analysis.db (or errors), runs ``call`` with
        the effective (function, binary), then stamps ``resolved_run`` + ``run_source`` + inline
        ``run_lineage`` (M6) so the consumer sees which scan answered and whether it is stale.
        ``diagnose`` turns on the wrong-run/no-such-function cross-run note for function lookups."""
        atlas = open_atlas(atlas_path)
        try:
            locus = _resolve_locus(atlas, run_id, evidence_ref, function, binary)
            if "error" in locus:
                return locus
            run = locus["run"]
            fn, bn = locus["function"], locus["binary"]
            if diagnose and fn is None:
                # A function-anchored tool with no function (and no ref supplying one) — a usage
                # error, not a silent empty. The run IS resolved, so stamp it.
                err = _error(
                    atlas,
                    "this tool needs function=<name/addr> (or an evidence_ref that supplies one).",
                )
                err["resolved_run"] = run.run_id
                err["run_lineage"] = _lineage_inline(run)
                return err
            db = _resolve_db(atlas, run)
            if isinstance(db, dict):  # hard error (G4) — still stamped with the run it refers to
                db["resolved_run"] = run.run_id
                db["run_lineage"] = _lineage_inline(run)
                return db
            conn = facts.open_analysis_ro(db)
            try:
                result = call(conn, fn, bn)
            finally:
                conn.close()
            if diagnose and fn is not None and result.get("found") is False:
                if result.get("reason") != "ambiguous":  # ambiguous == it IS in this run
                    _augment_cross_run(atlas, result, run.run_id, fn, bn)
            result["atlas"] = str(atlas_path)
            result["resolved_run"] = run.run_id
            result["run_source"] = locus["run_source"]
            result["run_lineage"] = _lineage_inline(run)
            if locus.get("warning"):
                # MERGE, never clobber: a fact-layer warning (e.g. get_strings' func-scope alert)
                # must not be silently overwritten by the run-locus warning — both are honest.
                existing = result.get("warning")
                result["warning"] = (
                    f"{existing} | {locus['warning']}" if existing else locus["warning"]
                )
            return result
        finally:
            atlas.close()

    def _incomplete_for_run(
        atlas: sqlite3.Connection, run_id: str | None
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """The analysis-completeness red-lines for a SINGLE resolved run (they are a per-scan fact):
        incomplete binaries, partially-incomplete binaries, and folded high-fan-out xref symbols
        (whose constrained L0 edges are visible here, never silently dropped).

        Computed only when list_candidates is scoped to one resolvable run; empty across an all-runs
        listing (the red-line is per firmware, not a single value over a shared atlas)."""
        if run_id is None:
            return [], [], []
        run = _get_run(atlas, run_id)
        if run is None:
            return [], [], []
        db = _resolve_db(atlas, run)
        if isinstance(db, dict):
            return [], [], []
        conn = facts.open_analysis_ro(db)
        try:
            return (
                facts.list_incomplete_binaries(conn),
                facts.list_partially_incomplete_binaries(conn),
                facts.list_folded_xref_symbols(conn),
            )
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
        verbose: bool = True,
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
        filtering).

        Rows are COMPACT: spine facts (evidence_ref / rank / sink_class / sink / controllability /
        nvram_source_key / binary / function / structural_fingerprint) plus each dimension whose
        state is ESTABLISHED, as one ``state:value`` label — the per-dimension note is dropped here
        to keep the list directly readable, and fetched on demand via ``explain_candidate``. A
        dimension NOT shown on a row is state=unknown (a coverage gap, NOT proven safe) — see the
        result's ``legend``. DERIVED facts, NOT a verdict — read the head, then explain per ref.

        ``verbose`` (default True) prints the full ``available_views`` enumeration. Pass
        ``verbose=False`` to drop ONLY that navigational boilerplate (it repeats each call) and save
        tokens — the honest ``caveats``, the ``legend``, and the one-line ``lens.switchable``
        pointer ALWAYS stay, so the map is never read as complete and the lens stays switchable."""
        atlas = open_atlas(atlas_path)
        try:
            # run_id scopes the listing to one firmware; None spans every run in the atlas. There is
            # NO ambient 'current run' fallback — the old current_run_id binding (which could
            # silently isolate to the wrong scan) is gone; each row carries its own ``run``.
            ranked = _triage(atlas, run_id=run_id)
            runs_in_atlas = [r.run_id for r in _list_runs(atlas)]
            incomplete, partially_incomplete, folded_xref = _incomplete_for_run(atlas, run_id)
        finally:
            atlas.close()
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
            # ★ C8-6: rows are compact (spine + established dimensions only); an omitted dimension
            # is state=unknown, NOT proven safe. Said once on the envelope, not per row.
            "legend": _COMPACT_ROW_LEGEND,
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
            # are DISCOVERABLE from the result itself. Navigational boilerplate only (it does not
            # vary with the candidates), so ``verbose=False`` drops it to save tokens — the one-line
            # ``lens.switchable`` pointer above still says the lens IS switchable (never a silent
            # 'this is all there is'). The honest caveats below are NEVER dropped.
            **(
                {
                    "available_views": [
                        {"view": name, "spine": preset["spine"], "when_to_use": preset["desc"]}
                        for name, preset in _VIEWS.items()
                    ]
                }
                if verbose
                else {
                    "available_views_note": (
                        "omitted (verbose=false) — pass verbose=true to list every preset lens; "
                        "the lens is switchable now via sort_by / view / filters / only"
                    )
                }
            ),
            # The honest phase-1 blind spots — surfaced so the map is never read as complete. ALWAYS
            # present (honesty is never traded for tokens), regardless of ``verbose``.
            "caveats": list(_LENS_CAVEATS),
            # ★ M7: the run this listing was scoped to (None = every run), the canonical name every
            # tool uses. The old ambient current_run_id + per-row is_current_run are GONE — an
            # ambient 'current run' was the run-binding hazard; each row carries its own ``run``.
            "resolved_run": run_id,
            # ★ M-A1: the bare run-id list — ALWAYS present (even when scoped) so switching firmware
            # is one glance; ``runs`` is the per-run count split of THIS listing.
            "runs_in_atlas": runs_in_atlas,
            "runs": _run_summary(ranked),
            # ★ M-A3: pull any row's code without retyping args — its evidence_ref self-resolves.
            "how_to_fetch": _FETCH_CODE_LEGEND,
            # ★ Red-line (per-scan fact): binaries with incomplete/partial analysis, so absence of a
            # candidate is not proof of cleanliness. Only meaningful when scoped to one resolvable
            # run (empty across an all-runs listing — the red-line is per firmware, not one value).
            "incomplete_binaries": incomplete,
            "partially_incomplete_binaries": partially_incomplete,
            # ★ Red-line (scaling): high-fan-out L0 symbols whose constrained edges were NOT
            # materialized -- visible with per-symbol counts so a suppressed edge is a known
            # decision, never a silent drop. Empty unless scoped to one resolvable run.
            "folded_xref_symbols": folded_xref,
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
            # ★ compact rows (M1): spine facts + established dimensions, no per-dimension note. The
            # full per-candidate note is on demand via explain_candidate(evidence_ref) (M2);
            # ``rank`` is the absolute position under the active lens.
            "candidates": [_candidate_row(c, off + i) for i, c in enumerate(page)],
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
            # The analysis-completeness red-line is a per-SCAN fact; it is surfaced per run via
            # list_candidates(run_id=…), not on this cross-run aggregation (no single analysis.db).
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
            # Per-scan completeness rides list_candidates(run_id=…); this aggregation is cross-run.
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

        Returns a not-found record when no instance carries ``evidence_ref`` (no fabrication).
        Echoes the canonical ``resolved_run`` + inline ``run_lineage`` (M6/M7): a ref anchors ONE
        firmware run, so the explanation names the scan it came from (never an ambient run)."""
        conn = open_atlas(atlas_path)
        try:
            ex = _explain_candidate(conn, evidence_ref)
            ref = _resolve_ref(conn, evidence_ref)
            run = _get_run(conn, ref[0]) if ref is not None and ref[0] is not None else None
        finally:
            conn.close()
        if ex is None:
            return {"found": False, "evidence_ref": evidence_ref, "atlas": str(atlas_path)}
        data = asdict(ex)
        data["found"] = True
        data["note"] = _DERIVED_SIGNAL_NOTE
        data["atlas"] = str(atlas_path)
        if run is not None:
            data["resolved_run"] = run.run_id
            data["run_lineage"] = _lineage_inline(run)
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
            ref = _resolve_ref(conn, evidence_ref)
            run = _get_run(conn, ref[0]) if ref is not None and ref[0] is not None else None
        finally:
            conn.close()
        result["note"] = _DERIVED_SIGNAL_NOTE
        result["atlas"] = str(atlas_path)
        # ★ G1/verification 1b: this reads the atlas by ref, so it routes to the RIGHT firmware even
        # under a mismatched session — echo the canonical resolved_run + lineage to prove it.
        if run is not None:
            result["resolved_run"] = run.run_id
            result["run_lineage"] = _lineage_inline(run)
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

    def get_string_keyed_edges(
        binary: str | None = None,
        key: str | None = None,
        callee: str | None = None,
        from_function: str | None = None,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        """Enumerate STRING-KEYED EDGES — an attacker-influenceable string key gates/dispatches to a
        callee, recovered structurally (a same-variable strcmp ladder, or a {string, func_ptr}
        table). Answers "what does string key X reach?" and "is function Y reached via a string-key
        dispatch?" from a table instead of hand-tracing an empty-xref dispatcher.

        Filter by any of: ``key`` (the gating string), ``callee`` (a Ghidra function name — find
        the edges that dispatch to it), ``from_function`` (the dispatcher), ``binary``, ``run_id``.
        Each edge carries the callee anchor (name + addr + kind — alignable across a recompile, not
        a bare address), ``ladder_size`` / ``table_addr``, and a fine-grained ``completeness`` (an
        incomplete region — e.g. an unparsed switch — means undetected edges may exist there).

        ★ These are ENUMERATED FACTS, NOT a reachability verdict: a candidate that is an edge callee
        stays reachability=unknown — the key is a lead you confirm, tmap does not judge whether the
        input actually arrives. Empty is NOT proof of unreachability (most functions are simply not
        string-key-dispatched)."""
        conn = open_atlas(atlas_path)
        try:
            result = _get_string_keyed_edges(
                conn,
                run_id=run_id,
                binary=binary,
                key=key,
                callee=callee,
                from_function=from_function,
            )
        finally:
            conn.close()
        return result

    def get_pseudocode(
        function: str | None = None,
        binary: str | None = None,
        run_id: str | None = None,
        evidence_ref: str | None = None,
    ) -> dict[str, Any]:
        """Decompiler pseudocode for one function (name or address); the default read view.

        Run-aware: pass ``run_id`` (see list_runs) + ``function``, OR just ``evidence_ref`` (a
        candidate row's ref self-resolves run + binary + function). Every result echoes
        ``resolved_run`` + ``run_lineage`` so you always see which scan answered (and if it is
        stale). A miss says whether the function lives in a DIFFERENT run or in none."""
        return _fact(
            lambda c, fn, bn: facts.get_pseudocode(c, func=fn or "", binary=bn),
            run_id=run_id,
            evidence_ref=evidence_ref,
            function=function,
            binary=binary,
            diagnose=True,
        )

    def get_callees(
        function: str | None = None,
        binary: str | None = None,
        run_id: str | None = None,
        evidence_ref: str | None = None,
    ) -> dict[str, Any]:
        """Direct callee names of one function (intra-binary edges flagged resolved to follow).

        Run-aware: ``run_id`` + ``function`` or ``evidence_ref``; echoes ``resolved_run``."""
        return _fact(
            lambda c, fn, bn: facts.get_callees(c, func=fn or "", binary=bn),
            run_id=run_id,
            evidence_ref=evidence_ref,
            function=function,
            binary=binary,
            diagnose=True,
        )

    def get_xrefs(
        function: str | None = None,
        direction: str = "callers",
        binary: str | None = None,
        run_id: str | None = None,
        evidence_ref: str | None = None,
    ) -> dict[str, Any]:
        """Cross-reference edges: direction='callers' / 'callees' (both include cross-binary edges),
        or 'address_taken'.

        direction='address_taken' returns where this function's ENTRY address is referenced as a
        DATA/POINTER value — a .data dispatch-table slot or a .text literal-pool ``ldr =F`` — and
        which function took it (``taken_in_func``). Use it to locate WHERE a handler is registered
        into a function-pointer table when direction='callers' comes back empty ('maybe dispatch').
        It is a FACT (F's address is stored here), NEVER proof F is dispatched/reachable — trace the
        call yourself.

        Run-aware: ``run_id`` + ``function`` or ``evidence_ref``; echoes ``resolved_run``."""
        d: facts.XrefDirection = (
            "callees"
            if direction == "callees"
            else "address_taken"
            if direction == "address_taken"
            else "callers"
        )
        return _fact(
            lambda c, fn, bn: facts.get_xrefs(c, func=fn or "", direction=d, binary=bn),
            run_id=run_id,
            evidence_ref=evidence_ref,
            function=function,
            binary=binary,
            diagnose=True,
        )

    def get_strings(
        binary: str | None = None,
        function: str | None = None,
        value: str | None = None,
        offset: int = 0,
        run_id: str | None = None,
        evidence_ref: str | None = None,
    ) -> dict[str, Any]:
        """Recorded strings: by binary, or searched by ``value`` (substring).

        ★ ``function`` does NOT scope the results — DO NOT pass it expecting a per-function slice.
        There is no string->function index and .rodata addresses fall outside code ranges, so the
        results are binary-wide regardless; passing it only adds a top-level ``warning`` +
        ``func_scope_applied: false`` (and in value mode it just gates existence: bad name -> none).

        Run-aware: pass ``run_id`` (or an ``evidence_ref`` that supplies run + binary). ``value``
        searches string CONTENT and returns each hit with its address + owning binary (one-call
        locate); reference-site (which function uses a string) is not indexed — the result says so
        honestly. Large results are paged LOSSLESSLY by byte size under
        ``paging``: pass ``offset`` = ``paging.next_offset`` to page the tail (never summarized).
        HONEST BOUND: a binary's string export is capped, so results carry ``truncated`` / ``total``
        (by-binary) or ``search_may_be_incomplete`` (by-value) when a scanned binary was capped — a
        string NOT found there is NOT proven absent."""
        return _fact(
            lambda c, fn, bn: facts.get_strings(c, binary=bn, func=fn, value=value, offset=offset),
            run_id=run_id,
            evidence_ref=evidence_ref,
            function=function,
            binary=binary,
        )

    def get_imports_exports(
        binary: str | None = None,
        run_id: str | None = None,
        evidence_ref: str | None = None,
    ) -> dict[str, Any]:
        """Import and export symbol tables of one binary (cross-binary edge endpoints).

        Run-aware: ``run_id`` + ``binary`` or ``evidence_ref``; echoes ``resolved_run``."""
        return _fact(
            lambda c, fn, bn: facts.get_imports_exports(c, binary=bn or ""),
            run_id=run_id,
            evidence_ref=evidence_ref,
            binary=binary,
        )

    def get_functions_referencing_string(
        text: str,
        binary: str | None = None,
        run_id: str | None = None,
        evidence_ref: str | None = None,
    ) -> dict[str, Any]:
        """Functions whose pseudocode TEXT contains a string (substring reverse-lookup).

        Run-aware: ``run_id`` (or an ``evidence_ref``). The schema indexes no string->function link,
        but functions.pseudocode is stored in full, so this answers "which functions mention this
        text". ``binary`` (short name or full path) narrows the scan; omitted, it scans every
        binary. Capped (``truncated`` when more exist). HONEST BOUND: a TEXT match, not a resolved
        symbol reference — the text may sit in a comment or unrelated literal; confirm each hit."""
        return _fact(
            lambda c, fn, bn: facts.get_functions_referencing_string(c, text=text, binary=bn),
            run_id=run_id,
            evidence_ref=evidence_ref,
            binary=binary,
        )

    def get_script_callsites(
        binary: str | None = None,
        run_id: str | None = None,
        evidence_ref: str | None = None,
    ) -> dict[str, Any]:
        """Rootfs scripts that invoke this binary — entry-reach evidence (script + line + args).

        Run-aware: ``run_id`` + ``binary`` or ``evidence_ref``; echoes ``resolved_run``."""
        return _fact(
            lambda c, fn, bn: facts.get_script_callsites(c, binary=bn or ""),
            run_id=run_id,
            evidence_ref=evidence_ref,
            binary=binary,
        )

    def get_components_cves(
        binary: str | None = None,
        run_id: str | None = None,
        evidence_ref: str | None = None,
    ) -> dict[str, Any]:
        """SBOM components recognized in a binary + their CVE-table matches (a query result).

        Run-aware: ``run_id`` + ``binary`` or ``evidence_ref``; echoes ``resolved_run``."""
        return _fact(
            lambda c, fn, bn: facts.get_components_cves(c, binary=bn or ""),
            run_id=run_id,
            evidence_ref=evidence_ref,
            binary=binary,
        )

    def get_disassembly(
        function: str | None = None,
        binary: str | None = None,
        run_id: str | None = None,
        evidence_ref: str | None = None,
    ) -> dict[str, Any]:
        """On-demand disassembly — same-source aligned, or an honest 'unavailable' (never wrong).

        Run-aware: ``run_id`` + ``function`` or ``evidence_ref``; echoes ``resolved_run``."""
        return _fact(
            lambda c, fn, bn: facts.get_disassembly(c, func=fn or "", binary=bn),
            run_id=run_id,
            evidence_ref=evidence_ref,
            function=function,
            binary=binary,
            diagnose=True,
        )

    def list_runs() -> dict[str, Any]:
        """Every firmware run (scan) in this atlas + its lineage — the switch + staleness face.

        Each run carries ``scan_status`` (in_progress / complete / partial / failed / unknown),
        ``build_hash`` (extraction pass_version — differing build_hash for the same firmware means a
        STALE scan), ``scanned_at``, counts, and ``resolved`` (False for a pre-existing run with no
        lineage row: visible but its analysis.db is not recorded — re-scan to enable fact tools).
        Use this to pick a ``run_id`` for the fact tools and to catch "auditing an old scan"."""
        atlas = open_atlas(atlas_path)
        try:
            runs = _list_runs(atlas)
        finally:
            atlas.close()
        return {
            "note": _DERIVED_SIGNAL_NOTE,
            "atlas": str(atlas_path),
            "count": len(runs),
            "runs": [asdict(r) for r in runs],
        }

    def mark_exploited(evidence_ref: str, pattern: str, exploit_note: str) -> dict[str, Any]:
        """Record ONE hole you PROVED reachable into the private exploited-hole ledger — the ONE
        write tool here (every other tool is read-only).

        The admission bar is EXPLOITED: ``exploit_note`` must carry the proof (how it triggers, the
        effect obtained, the guard bypassed). The tool rejects a blank/whitespace proof or pattern,
        but it does NOT verify the exploit is real — that judgement is YOURS, never asserted here.
        ``evidence_ref`` anchors the candidate (a stable handle that survives a re-scan). The ref is
        resolved for the echo and INHERITS the no-lineage honesty: if it does not resolve, or points
        at a run with no recorded analysis.db, the row is STILL written (recording before a scan is
        allowed) but the result carries an explicit ``warning`` — a blind write is never silent."""
        if not (evidence_ref and evidence_ref.strip()):
            return {"written": False, "error": "evidence_ref must be non-blank."}
        if not (pattern and pattern.strip()):
            return {"written": False, "error": "pattern must be non-blank."}
        if not (exploit_note and exploit_note.strip()):
            return {
                "written": False,
                "error": "exploit_note must be non-blank — the bar is a PROVEN hole; record how it "
                "triggers / the effect / the guard bypassed. (No proof, no write.)",
            }
        atlas = open_atlas(atlas_path)
        try:
            ref = _resolve_ref(atlas, evidence_ref)
            resolved_label: str | None = None
            warning: str | None = None
            if ref is None:
                warning = (
                    f"evidence_ref '{evidence_ref}' is not in this atlas — BLIND WRITE "
                    "(recording before the scan exists?). The row is written anyway."
                )
            else:
                ref_run, ref_bin, ref_fn = ref
                resolved_label = f"{ref_fn or '?'}@{ref_bin or '?'} (run {ref_run})"
                run = _get_run(atlas, ref_run) if ref_run is not None else None
                if run is None or not run.analysis_db_path:
                    warning = (
                        f"evidence_ref '{evidence_ref}' points at run '{ref_run}' with no recorded "
                        "analysis.db (a pre-existing / un-scanned run) — BLIND WRITE. Row written."
                    )
            new_id = _add_private_exploit(
                atlas,
                evidence_ref=evidence_ref,
                pattern=pattern,
                exploit_note=exploit_note,
                attributed_to=None,  # no clean operator identity here — NULL, never fabricated
            )
        finally:
            atlas.close()
        result: dict[str, Any] = {
            "written": True,
            "id": new_id,
            "evidence_ref": evidence_ref.strip(),
            "atlas": str(atlas_path),
            "note": "recorded into the private exploited-hole ledger. The tool checked the proof "
            "field is non-blank, NOT that the exploit is real — that is your judgement.",
        }
        if resolved_label is not None:
            result["resolved"] = resolved_label
        if warning is not None:
            result["warning"] = warning
        return result

    def list_moat(reveal: bool = False) -> dict[str, Any]:
        """The private exploited-hole ledger: ``holes`` (barrier depth = distinct candidates) +
        ``records`` (rows). Each entry carries its pattern + a has_exploit_evidence flag; the full
        ``exploit_note`` (the closest thing to an exploit method) is WITHHELD unless reveal=True.

        ★ reveal=True is the ONE reveal channel and a DISCIPLINE path, not a protected one: the full
        text it returns still lands in your context / the transcript, so 'exploit methods do not
        leave the system' holds for the DEFAULT path only — on reveal it rides your own care."""
        atlas = open_atlas(atlas_path)
        try:
            result = _list_moat(atlas, reveal=reveal)
        finally:
            atlas.close()
        result["note"] = _DERIVED_SIGNAL_NOTE
        return result

    def list_cve_patterns(cve_id: str | None = None, sink: str | None = None) -> dict[str, Any]:
        """The public-CVE exploit-form list (front-stage material, NOT counted in barrier depth).

        Filter by exact ``cve_id`` and/or a ``sink`` substring — deterministic lookup, no fuzzy
        match. Public data — separate table from the private exploited-hole ledger."""
        atlas = open_atlas(atlas_path)
        try:
            result = _list_cve_patterns(atlas, cve_id=cve_id, sink=sink)
        finally:
            atlas.close()
        result["note"] = _DERIVED_SIGNAL_NOTE
        return result

    def import_cve_patterns(patterns: list[dict[str, Any]]) -> dict[str, Any]:
        """Idempotent import of public-CVE exploit forms into the public (front-stage) table.

        Each item is a dict with ``pattern`` (required) + optional ``cve_id`` / ``source`` /
        ``sink`` / ``ref`` / ``notes``. A row whose (cve_id, pattern, source, sink) already exists
        is SKIPPED, so re-running the same import never doubles. Returns {inserted, skipped}. A thin
        INSERT path for public data — no matching or dedup logic beyond exact-identity
        idempotency."""
        rows = [
            PublicCvePatternRow(
                pattern=str(p.get("pattern", "")),
                cve_id=p.get("cve_id"),
                source=p.get("source"),
                sink=p.get("sink"),
                ref=p.get("ref"),
                notes=p.get("notes"),
            )
            for p in patterns
        ]
        atlas = open_atlas(atlas_path)
        try:
            counts = _add_public_cve_patterns(atlas, rows)
        finally:
            atlas.close()
        return {**counts, "note": _DERIVED_SIGNAL_NOTE}

    def legal_notice() -> dict[str, Any]:
        """The tool's intended-use / legal notice."""
        return {"notice": LEGAL_NOTICE}

    return {
        "list_candidates": list_candidates,
        "list_runs": list_runs,
        "explain_candidate": explain_candidate,
        "get_sink_provenance": get_sink_provenance,
        "get_nvram_key_flow": get_nvram_key_flow,
        "get_string_keyed_edges": get_string_keyed_edges,
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
        "mark_exploited": mark_exploited,
        "list_moat": list_moat,
        "list_cve_patterns": list_cve_patterns,
        "import_cve_patterns": import_cve_patterns,
        "legal_notice": legal_notice,
    }


def build_server(atlas_db: Path | str, *, workspaces_root: Path | str | None = None) -> Any:
    """Construct a FastMCP server exposing the fact tools bound to one ATLAS (not one firmware).

    A fact tool resolves run_id -> analysis.db through the atlas ``run`` table; ``workspaces_root``
    is an optional fallback resolver. The server's standing instructions are the agent workflow
    guide; the legal notice stays reachable via the legal_notice tool. ``mcp`` is a core dependency
    (the server is the substrate's primary consumer), so FastMCP is imported at top level."""
    server = FastMCP("treasure-map", instructions=_AGENT_INSTRUCTIONS)
    for fn in make_tools(atlas_db, workspaces_root=workspaces_root).values():
        server.add_tool(fn)
    return server


def main() -> None:
    """Entry point: serve over stdio.

    The atlas path comes from TREASURE_MAP_ATLAS_DB (else the last-run pointer's atlas); the
    optional workspaces root from TREASURE_MAP_WORKSPACES_ROOT (a fallback run_id -> analysis.db
    resolver). The server binds the ATLAS, not one firmware — a fact tool routes by run_id."""
    from treasure_map.lib.last_run import read_last_run

    atlas_db = os.environ.get("TREASURE_MAP_ATLAS_DB")
    workspaces_root = os.environ.get("TREASURE_MAP_WORKSPACES_ROOT")
    if atlas_db is None:
        ptr = read_last_run()
        if ptr is not None:
            atlas_db = str(ptr.atlas_db)
    build_server(atlas_db or "atlas.db", workspaces_root=workspaces_root).run()


if __name__ == "__main__":
    main()
