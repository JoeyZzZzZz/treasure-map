# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
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

import json
import os
import sqlite3
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from treasure_map.lib import facts
from treasure_map.lib.analyze.ghidra_runner import current_pass_version as _current_pass_version
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import PublicCvePatternRow, RunRow
from treasure_map.lib.atlas.writer import add_public_cve_patterns as _add_public_cve_patterns
from treasure_map.lib.errors import ConfigError
from treasure_map.lib.notice import LEGAL_NOTICE
from treasure_map.lib.overlay import clear_overlay as _clear_overlay
from treasure_map.lib.overlay import list_overlays as _list_overlays
from treasure_map.lib.overlay import upsert_overlay as _upsert_overlay
from treasure_map.lib.query import DEFAULT_LENS_LABEL as _LENS_LABEL
from treasure_map.lib.query import PHASE1_CAVEATS as _LENS_CAVEATS
from treasure_map.lib.query import VIEWS as _VIEWS
from treasure_map.lib.query import apply_overlay_view as _apply_overlay_view
from treasure_map.lib.query import apply_view as _apply_view
from treasure_map.lib.query import canonical_view as _canonical_view
from treasure_map.lib.query import coverage_report as _coverage_report
from treasure_map.lib.query import density as _density
from treasure_map.lib.query import dormant as _dormant
from treasure_map.lib.query import effective_float_filters as _effective_float_filters
from treasure_map.lib.query import explain_candidate as _explain_candidate
from treasure_map.lib.query import filter_candidates as _filter_candidates
from treasure_map.lib.query import filter_match_count as _filter_match_count
from treasure_map.lib.query import get_nvram_key_flow as _get_nvram_key_flow
from treasure_map.lib.query import get_run as _get_run
from treasure_map.lib.query import get_sink_provenance as _get_sink_provenance
from treasure_map.lib.query import get_string_keyed_edges as _get_string_keyed_edges
from treasure_map.lib.query import launched_by as _launched_by
from treasure_map.lib.query import ledger as _ledger
from treasure_map.lib.query import list_cve_patterns as _list_cve_patterns
from treasure_map.lib.query import list_runs as _list_runs
from treasure_map.lib.query import list_verified_exploits as _list_verified_exploits
from treasure_map.lib.query import load_coverage_index as _load_coverage_index
from treasure_map.lib.query import only_refusal as _only_refusal
from treasure_map.lib.query import parse_impact_order as _parse_impact_order
from treasure_map.lib.query import refs_in_ledger as _refs_in_ledger
from treasure_map.lib.query import run_staleness as _run_staleness
from treasure_map.lib.query import runs_where_function_exists as _runs_where_function_exists
from treasure_map.lib.query import state_value_label as _state_value_label
from treasure_map.lib.query import triage as _triage
from treasure_map.lib.query import twins as _twins
from treasure_map.lib.query import unknown_dimension_refusal as _unknown_dim_refusal
from treasure_map.lib.query.diff_align import align_by_a as _align_by_a
from treasure_map.lib.query.diff_align import align_by_b as _align_by_b
from treasure_map.lib.query.diff_align import get_diff_capabilities as _get_diff_capabilities
from treasure_map.lib.query.diff_align import get_diff_deltas as _get_diff_deltas
from treasure_map.lib.query.diff_align import get_diff_meta as _get_diff_meta
from treasure_map.lib.query.diff_align import list_diff_blindspots as _list_diff_blindspots
from treasure_map.lib.query.diff_align import list_diffs as _list_diffs
from treasure_map.version import installed_commit as _installed_commit

# A standing reminder attached to every candidate-listing / aggregation result: the ordering and
# recurrence signals are derived from neutral stored facts, carry their evidence, and are NOT a
# security verdict.
_DERIVED_SIGNAL_NOTE = (
    "the dimension layers / entry_reach / device_spread / lens ordering / blocking_mechanism are "
    "DERIVED, evidence-backed facts — NOT a verdict. A candidate is a lead to verify, never a "
    "confirmed issue; a '?' layer is a coverage gap, never 'safe'."
)

# The bare form note only reaches a reader through explain, which expands the whole candidate. It
# is NOT in a list row, so this caveat is attached there and not to the standing note — putting it
# on every list response would spend the response budget explaining a field that response does not
# contain. (Adding it to the standing note overflowed that budget by 49 bytes, which is how the
# placement got settled.)
_BARE_FORM_NOTE_CAVEAT = (
    "blocking_mechanism is a raw form note and its NAME can read like an all-clear: no_shell_exec "
    "says the command runs without a shell, NOT that it cannot be injected — the argv and the "
    "program path are untouched by it. Read the dimension it feeds, or evidence_surface, never the "
    "bare string."
)

# Hard cap on a single list_candidates page so an over-large limit cannot blow up the context.
_MAX_LIMIT = 200

# A ceiling on the whole list_candidates response, in bytes. The candidates array is ~86% of the
# body and grows linearly with the page, so a wide-row query (path_sink rows run ~440 bytes) at a
# large limit produced a ~95KB response that overflowed to a file. This bounds the response by
# TRIMMING THE PAGE — not by dropping honesty: every trimmed row is still reachable by paging on
# (next_offset), the totals stay exact, and the trim is announced (candidates_truncated). Chosen
# well under the observed overflow point; one constant to raise if the transport allows more.
_RESPONSE_BYTE_BUDGET = 48_000


def _fit_candidates(
    envelope: dict[str, Any], rows: list[dict[str, Any]], budget: int
) -> tuple[list[dict[str, Any]], bool]:
    """The prefix of ``rows`` whose serialization keeps the whole response within ``budget`` bytes.

    Byte-aware on purpose: a fixed row count cannot bound the response when row width varies by
    sink class and path length. The envelope's own size (legend, caveats, coverage, the folded
    red-line) is measured first, then rows are added while they fit. At least one row is always
    returned — a single oversized row is trimmed-to-one and flagged, never silently dropped, and
    never turned into an empty page that reads as 'nothing here'.

    Returns ``(kept_rows, truncated_by_bytes)``. ``truncated_by_bytes`` is True only when the byte
    ceiling cut the page shorter than the rows handed in — a row-count limit reaching its end is a
    different thing, tracked by the caller's paging fields."""
    running = len(json.dumps({**envelope, "candidates": []}))
    kept: list[dict[str, Any]] = []
    for row in rows:
        # json.dumps' default item separator is ", " (2 chars), added only BETWEEN elements — so
        # the first row carries no separator and each later one carries two, matching the real
        # serialized size exactly rather than approximating it.
        cost = len(json.dumps(row)) + (2 if kept else 0)
        if kept and running + cost > budget:
            return kept, True
        kept.append(row)
        running += cost
    return kept, False


# The server's standing instruction to an AI client: the working loop, not legalese. The legal
# notice stays reachable via the legal_notice tool (B4).
_AGENT_INSTRUCTIONS = (
    "Treasure Map exposes a firmware analysis knowledge base as read-only fact tools. Work the "
    "loop: RECALL -> FETCH FACTS -> JUDGE -> RECORD. (1) list_candidates is a multi-dimensional "
    "map: each lead carries an honest three-state annotation on every layer (controllability / "
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
    "scan answered and whether it is stale — check list_runs before trusting an old scan. A run "
    "PROVEN to have been hunted by different code than is answering is refused on EVERY tool, "
    "candidates included (stale_scan + remedy; on a cross-run reader its rows are dropped and it "
    "is named under stale_runs_refused); an unprovable mismatch is served with its reason stated, "
    "never refused. Read "
    "facts: get_pseudocode (func = a name OR an address in any form; "
    "binary = sha256 (or >=8-hex prefix) OR full path OR short name. A short name shared by "
    "several binaries returns reason='ambiguous' listing each candidate's binary_path and "
    "sha256 — re-issue with one of them; ambiguous is not an error, it is what the firmware "
    "actually contains. When func is given, the function's own binary is used), "
    "get_callees / get_xrefs to walk the call chain (an empty "
    "caller set may mean an indirect/dispatch-table call, not 'unreachable'), get_strings, "
    "get_functions_referencing_string (which functions mention a string, by pseudocode text "
    "match — wide and noisy, hits comments too), get_string_reference_anchors (the PARSED "
    "sibling: where a string is referenced by a RESOLVED Ghidra data reference — no comment "
    "noise, but only defined strings and resolved refs), get_imports_exports, "
    "get_script_callsites, "
    "get_data_bytes (the RAW bytes a data segment stores at an address — the content the "
    "decompiler drops when it renders a bare DAT_00xxxxxx; bytes only, the reading is "
    "yours). "
    "(3) Judge value with the cross-firmware signal cross_firmware_patterns (a pattern "
    "recurring across many firmware images). Prefer narrow filters (run_id / sink "
    "/ status) and paging over pulling everything; fetch detail per evidence_ref. The tools draw "
    "no conclusion and emit no payload/PoC — that judgement is yours. (4) RECORD a conclusion "
    "worth keeping past this session, so the next one inherits it instead of starting over: "
    "annotate(evidence_ref, verdict, rationale) writes YOUR judgement onto an overlay — "
    "suspicious/exploitable float a real lead the base map had sunk, excluded/safe sink noise you "
    "have cleared (safe must say what blocks it, where, and why). list_candidates(overlay=true) "
    "then re-ranks by your own conclusions; it is off by default and the base map is unchanged "
    "with it off. list_overlays(run_id=...) reviews what you concluded last time and flags any "
    "whose underlying facts have since moved. A row already marked in_exploit_ledger was confirmed "
    "by a person — you cannot write that (people do, from the command line), and it is usually not "
    "worth re-verifying."
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
    "Fetch explain_candidate(evidence_ref) for that candidate's full per-dimension note. "
    "A row carrying in_exploit_ledger:true was written into the exploit ledger by a PERSON at the "
    "command line, against a proven-exploit bar — the highest-trust marker here, and usually not "
    "worth re-verifying. It means the logic was proven and recorded; it is NOT a claim that anyone "
    "reproduced it on real hardware."
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


def _overlay_marker(o: dict[str, Any]) -> dict[str, Any]:
    """One annotation as the row's OWN top-level entry — never merged into a tool-derived field.

    The overlay is the agent's own layer; the dimensions are what tmap itself established. Keeping
    the annotation in its own key is what makes the two structurally distinguishable on every row:
    a candidate the base map read as provably constant and the agent floated as suspicious shows
    BOTH readings side by side, so neither silently overwrites the other.

    A basis that has MOVED (or cannot be verified) is flagged right here for re-review, naming what
    moved — the annotation is never quietly re-served as if it still rested on the same facts.
    """
    marker = {
        "verdict": o["verdict"],
        "attributed_to": o["attributed_to"],  # coarse authorship; never fabricated as a human
        "basis_state": o["basis_state"],
    }
    if o["basis_state"] != "unchanged":
        delta = o.get("basis_delta") or {}
        moved = sorted(
            {d for m in delta.get("dimensions", {}).get("moves", []) for d in m["moved"]}
        )
        marker["re_review"] = (
            f"was {o['verdict']} — the basis moved ({o['basis_state']}); re-review before trusting"
        )
        marker["basis_moved"] = {
            "pseudocode": delta.get("pseudocode"),
            "dimensions": moved,
            "detail": "full delta via list_overlays",
        }
    return marker


def _candidate_row(
    c: Any,
    rank: int,
    overlay: dict[str, Any] | None = None,
    *,
    in_ledger: bool = False,
    coverage: str = "none",
) -> dict[str, Any]:
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
    ambient marker was the run-binding hazard; there is no is_current_run flag any more).

    ``overlay`` (only with the overlay-on view) is the agent's own annotation for this candidate.
    It lands in its own top-level ``overlay`` key — see ``_overlay_marker`` — never inside
    ``dimensions``; with the overlay off the key is absent and the row is a pure base-map row.

    ``coverage`` says whether this candidate has been looked at, and it is present either way —
    a tool-side fact about the annotation layer's state, like the ledger marker beside it, and
    like it NEVER a dimension. It carries no annotation content: ``none`` means nothing has been
    recorded here, which is the state a reader needs to see without asking for the overlay."""
    carried = {
        d.name: _dim_label(d)
        for d in c.dimensions
        if d.name not in _SPINE_DIMENSIONS and d.state != "unknown"
    }
    row: dict[str, Any] = {
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
        # Has anyone been through this one? A fact about the annotation layer, never a dimension
        # and never the annotation's content — unconditional, so "nobody has looked at this" is
        # visible without turning a view on.
        "coverage": coverage,
    }
    if overlay is not None:
        # ★ The agent's judgement rides in its OWN key. NEVER inside ``dimensions`` — that carry
        # loop is axis-agnostic, so a verdict placed there would be auto-adopted as if it were a
        # tmap-established dimension — and never merged into ``controllability``. Two layers, two
        # keys, so a row always answers "did the tool establish this, or did the agent decide it?".
        row["overlay"] = _overlay_marker(overlay)
    if in_ledger:
        # A THIRD provenance layer, in its own key like ``overlay`` — and for the same reason. It is
        # neither a dimension this tool established nor the agent's own judgement: a PERSON put this
        # candidate in the exploit ledger from the command line, which is the highest-trust marker
        # here and usually means re-verifying it is wasted effort. It says the logic was proven and
        # recorded, NOT that anyone reproduced it on hardware.
        row["in_exploit_ledger"] = True
    return row


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


def _float_empty_note(float_filters: list[tuple[str, str]], total: int, corpus: int) -> str:
    """The message for a lens that floats something and matched none of it.

    ★ Every effective filter is named, and more than one is called out as a conjunction. The match
    count is an AND over all of them, so pointing at just one would report "this dimension matched
    nothing" when the truth is "nothing matched all of them together" — a wrong reason, handed to
    someone who came here because the ordering surprised them.

    ★ The denominator is the count the match was taken over — the view AFTER any prune — not the
    whole corpus. Quoting the corpus beside a numerator computed on the pruned view is a fraction
    with two different bases, and this is a sentence a person reads and trusts.

    ★ Says what it is: a coverage fact about this run. Zero matches means nothing here carried that
    combination — a statement about what the analysis attributed, not about what the firmware
    contains, and not a conclusion about anything. The reassuring vocabulary is kept out of the
    text entirely, disclaimers included, so that searching this layer's output for it stays a
    meaningful check instead of one that trips over its own caveats."""
    named = ", ".join(f"{d}={v}" for d, v in float_filters)
    what = f"ALL of: {named}" if len(float_filters) > 1 else named
    scope = f"0 of {total} in this view" + (f" (whole corpus {corpus})" if total != corpus else "")
    return (
        f"this lens floats candidates matching {what}, but {scope} matched on this run — nothing "
        "floats, so the order you are seeing is the default lens's. That is a COVERAGE fact about "
        "this run: no candidate here carried that combination. It says nothing about whether the "
        "firmware contains sources of that kind — only that the analysis attributed none — and it "
        "is not a conclusion about anything."
    )


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

    def _stale_refusal(atlas: sqlite3.Connection, run: RunRow) -> dict[str, Any] | None:
        """The refusal for a PROVABLY stale run, or None when it is servable.

        Only a proven mismatch gets here (see run_staleness): the stored run was demonstrably
        produced by different code than is answering now, so every fact it would return is an
        artifact of a pipeline that no longer exists, served with the same confidence as a current
        one. Refusing is the point — a caller that cannot tell the two apart will not ask, and a
        caveat buried in a large result does not get read.

        ★ This is a COVERAGE surface, not a rule. The bar for refusing (proven, never merely
        unconfirmable) is decided once, in run_staleness; what belongs here is every entry point a
        caller can arrive through. A gate reachable from one tool and not another is not a weaker
        gate, it is an open door beside a locked one, and the caller has no way to know which they
        walked through.
        """
        stale = _run_staleness(run, build_hash=_current_pass_version(), commit=_installed_commit())
        if not stale.stale:
            return None
        err = _error(atlas, f"run '{run.run_id}' is a STALE scan ({stale.axis}): {stale.detail}")
        err["stale_scan"] = {"axis": stale.axis, "detail": stale.detail}
        err["remedy"] = stale.remedy
        return err

    def _refuse_stale_run(atlas: sqlite3.Connection, run_id: str | None) -> dict[str, Any] | None:
        """The refusal for a tool call SCOPED to one run, or None (unscoped, unknown, or servable).

        An unknown run_id is left alone: "no such run in this atlas" is a different answer, and
        each tool already gives it in its own shape. The refusal carries the run + lineage so the
        caller can see WHICH scan was declined without a second call."""
        if run_id is None:
            return None
        run = _get_run(atlas, run_id)
        if run is None:
            return None
        err = _stale_refusal(atlas, run)
        if err is not None:
            err["resolved_run"] = run.run_id
            err["run_lineage"] = _lineage_inline(run)
        return err

    def _refused_entries(
        index: dict[str, dict[str, Any]], counts: dict[str, int] | None
    ) -> list[dict[str, Any]]:
        """``stale_runs_refused`` rows: which runs were refused and how many of their rows went.

        ``counts`` None means the reader could not take those rows out — an aggregate computed
        ACROSS runs has no per-run row to remove — so ``candidates_excluded`` is null rather than
        zero. Null and 0 are different answers here: 0 says the run contributed nothing, null says
        its contribution is still in the numbers below and could not be separated out."""
        return [
            {**entry, "candidates_excluded": (None if counts is None else counts.get(rid, 0))}
            for rid, entry in sorted(index.items())
        ]

    def _refuse_stale_diff(atlas: sqlite3.Connection, diff_id: str) -> dict[str, Any] | None:
        """The refusal for a diff whose A or B side is a PROVABLY stale run, else None.

        A diff is a claim about two scans, so it is only as current as the older of them: reading a
        delta between one run graded by this code and one graded by code that no longer exists
        gives a difference whose cause cannot be told apart from the difference in the graders. The
        refusal names WHICH side, because they need separate re-scans. An unknown diff_id passes
        through — 'no such diff' is each tool's own answer."""
        row = atlas.execute(
            "SELECT run_a_id, run_b_id FROM diff_meta WHERE diff_id = ?", (diff_id,)
        ).fetchone()
        if row is None:
            return None
        for side, run_id in (("a", row["run_a_id"]), ("b", row["run_b_id"])):
            run = _get_run(atlas, run_id) if run_id else None
            if run is None:
                continue
            err = _stale_refusal(atlas, run)
            if err is not None:
                err["stale_scan"]["diff_side"] = side
                err["diff_id"] = diff_id
                err["run_lineage"] = _lineage_inline(run)
                return err
        return None

    def _stale_run_index(atlas: sqlite3.Connection) -> dict[str, dict[str, Any]]:
        """Every PROVABLY stale run in this atlas, keyed by run_id, each with its refusal detail.

        For the cross-run readers, which serve many firmware at once and so cannot answer with a
        single refusal: they drop the stale runs' rows and report them under ``stale_runs_refused``
        instead. Naming them is the whole point — rows that silently disappear from an aggregate
        read as rows that were never there."""
        build = _current_pass_version()
        commit = _installed_commit()
        index: dict[str, dict[str, Any]] = {}
        for r in _list_runs(atlas):
            stale = _run_staleness(r, build_hash=build, commit=commit)
            if stale.stale:
                index[r.run_id] = {
                    "run_id": r.run_id,
                    "axis": stale.axis,
                    "detail": stale.detail,
                    "remedy": stale.remedy,
                }
        return index

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
        refusal = _stale_refusal(atlas, run)
        if refusal is not None:
            return refusal
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

    def _coverage_block(
        scope: list[Any],
        whole_run: list[Any],
        index: Any,
        incomplete: list[Any],
        partially_incomplete: list[Any],
        folded_xref: list[Any],
    ) -> dict[str, Any]:
        """Coverage for the listed scope, with everything needed to read it honestly attached.

        ★ The completion signal NEVER travels alone. It sits in the same object as the run's
        blind-spot ledger and as the shape of the verdicts reached, because each of them can turn
        "this scope is covered" into something false: binaries that never produced candidates are
        not covered by having read the candidates, and a scope cleared entirely by the cheapest
        dismissal is covered only in the bookkeeping sense.

        ``outside_this_scope`` is the same count over every candidate NOT in this listing's scope —
        the answer to "I finished cmd, am I done?", which is no. It spans the resolved run, or
        every run in the atlas when the listing was not scoped to one."""
        report = _coverage_report(scope, index)
        in_scope = {getattr(c, "evidence_ref", None) for c in scope}
        rest = [c for c in whole_run if getattr(c, "evidence_ref", None) not in in_scope]
        rest_report = _coverage_report(rest, index)
        return {
            "total": report.total,
            "looked_at": report.seen,
            "not_looked_at": report.unseen,
            "page_size": report.page_size,
            "pages_total": report.pages_total,
            "pages_remaining": report.pages_remaining,
            # Exhaustive over this scope: every candidate is in exactly one of these.
            "states": report.states,
            # ★ What the conclusions COST to assert. `safe` carries a structured evidence basis;
            # `excluded` needs only a sentence. A scope cleared entirely by the second is a visible
            # shape here — which is the only thing that makes it visible at all.
            "verdict_shape": report.verdict_shape,
            # ★ Named at CANDIDATE level, not "the ones on page 4": the point is that the ones
            # nobody has been through can be opened directly from here.
            "next_page": report.next_page,
            # Annotations whose candidate is no longer in this set — a conclusion with nothing left
            # to attach to. Reported, never counted as a conclusion and never dropped.
            "dangling_annotations": report.dangling,
            "outside_this_scope": {
                "not_looked_at": rest_report.unseen,
                "pages_remaining": rest_report.pages_remaining,
            },
            # ★ Inseparable from the numbers above: candidates were never generated for these, so
            # reading every candidate does not reach them.
            #
            # ``folded_xref_symbols`` is NOT repeated in full here. Its authoritative copy is the
            # top-level ``folded_xref_symbols`` field, which is a per-scan red-line present on EVERY
            # response — so the full symbol list and its per-symbol suppressed-edge counts are
            # always reachable there. This carries the count and a pointer, not a second copy: the
            # authority lives in the container that cannot be absent, never in this one, which some
            # response shapes may not produce.
            "blind_spots": {
                "incomplete_binaries": incomplete,
                "partially_incomplete_binaries": partially_incomplete,
                "folded_xref_symbols": {
                    "count": len(folded_xref),
                    "see": "folded_xref_symbols (top-level) — the full list + per-symbol counts",
                },
            },
            "complete": report.unseen == 0,
            "note": (
                "Progress is per PAGE, and the remainder is stated every time — working through a "
                "page is not working through the class. A candidate counts as looked at when an "
                "annotation exists for it, per candidate, unaffected by the lens or by annotating "
                "anything else. 'complete' means nothing in THIS scope is unread; it is not a "
                "statement about the firmware — read blind_spots beside it, and note that a sink "
                "that never became a candidate is not in this set at all. When you cannot settle "
                "one, record 'inconclusive' with the next step: it is a real conclusion and it "
                "stays in view. 'excluded' means you have a reason it cannot be reached — it is "
                "not the way to clear a page."
            ),
        }

    def _incomplete_for_run(
        atlas: sqlite3.Connection, run_id: str | None
    ) -> tuple[
        list[dict[str, Any]],
        list[dict[str, Any]],
        list[dict[str, Any]],
        int,
        dict[str, Any] | None,
    ]:
        """The analysis-completeness red-lines for a SINGLE resolved run (they are a per-scan fact):
        incomplete binaries, partially-incomplete binaries, folded high-fan-out xref symbols
        (whose constrained L0 edges are visible here, never silently dropped), and the COUNT of
        dependency edges whose soname named more than one binary (the same shape: an edge that was
        not written, surfaced as a number with a pointer to the detail, never a silent absence).

        Computed only when list_candidates is scoped to one resolvable run; empty across an all-runs
        listing (the red-line is per firmware, not a single value over a shared atlas).

        ★ The FOURTH return value is what keeps the other three honest. These red-lines exist so an
        absent candidate is not read as a clean binary — which means an empty list has to mean
        "looked, found none". Every way of failing to look (no run, no recorded analysis.db, the
        file gone, a refusal) used to land on the same three empty lists as a clean scan, so the
        one reading that most needed saying was the one that could not be said. ``unavailable``
        carries WHY the check did not run, and is None only when it did.
        """
        if run_id is None:
            # Unscoped: not a failure, and not a clean bill either — the red-line is a property of
            # one scan, and there is no single one here.
            return [], [], [], 0, None
        run = _get_run(atlas, run_id)
        if run is None:
            return [], [], [], 0, {"reason": "unknown_run", "run_id": run_id}
        db = _resolve_db(atlas, run)
        if isinstance(db, dict):
            # The resolver's own error, passed through whole: it already says whether the run has
            # no recorded analysis.db, the file has moved, or the scan is refused as stale, and
            # each needs a different fix.
            return [], [], [], 0, db
        conn = facts.open_analysis_ro(db)
        try:
            return (
                facts.list_incomplete_binaries(conn),
                facts.list_partially_incomplete_binaries(conn),
                facts.list_folded_xref_symbols(conn),
                facts.count_unresolved_soname_edges(conn),
                None,
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
        overlay: bool = False,
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
        Paged (``limit`` capped 200 + ``offset``). The page is ALSO bounded by response size:
        a wide-row page is trimmed to fit the transport, and ``candidates_truncated`` says so
        — read ``total`` for the true count and page on with ``next_offset``, which resumes
        exactly where the byte trim stopped. The result's ``lens`` names the active view and
        ``caveats`` states the honest phase-1 blind spots (optimistic 'free', near-always-'?'
        filtering).

        A row may also carry ``in_exploit_ledger`` — a person recorded that candidate in the
        exploit ledger from the command line. It is a tool-side fact, not an opt-in view, so it
        shows whether or not ``overlay`` is on, and it is the highest-trust marker on the row.

        Rows are COMPACT: spine facts (evidence_ref / rank / sink_class / sink / controllability /
        nvram_source_key / binary / function / structural_fingerprint) plus each dimension whose
        state is ESTABLISHED, as one ``state:value`` label — the per-dimension note is dropped here
        to keep the list directly readable, and fetched on demand via ``explain_candidate``. A
        dimension NOT shown on a row is state=unknown (a coverage gap, NOT proven safe) — see the
        result's ``legend``. DERIVED facts, NOT a verdict — read the head, then explain per ref.

        ``verbose`` (default True) prints the full ``available_views`` enumeration. Pass
        ``verbose=False`` to drop ONLY that navigational boilerplate (it repeats each call) and save
        tokens — the honest ``caveats``, the ``legend``, and the one-line ``lens.switchable``
        pointer ALWAYS stay, so the map is never read as complete and the lens stays switchable.

        ``overlay`` (default False) turns on YOUR OWN annotation layer as the OUTERMOST ordering
        band: what you marked ``suspicious`` floats, ``excluded``/``safe`` sinks, and a dismissal
        whose basis has since moved floats back for re-review. Each annotated row then carries an
        ``overlay`` key (verdict + attribution + basis freshness) alongside — never merged into —
        the tool-derived fields, so your judgement and tmap's facts stay distinguishable. It
        RE-RANKS, never reduces: a sunk candidate stays in the corpus and is still filterable. Being
        outermost, a candidate you marked suspicious outranks an unannotated ``filters`` match —
        that is the point of the view; with ``overlay=False`` the base-map order is unchanged."""
        atlas = open_atlas(atlas_path)
        try:
            # ★ The stale gate stands HERE, before any candidate is read — this is the entry an
            # agent is told to start from, so a scan proven to have been graded by other code has
            # to be refused here or the refusal does not exist. Scoped to one run it is a refusal;
            # unscoped it cannot be (the map spans firmware), so those runs are dropped from the
            # corpus and NAMED below instead.
            scoped_refusal = _refuse_stale_run(atlas, run_id)
            if scoped_refusal is not None:
                return scoped_refusal
            # run_id scopes the listing to one firmware; None spans every run in the atlas. There is
            # NO ambient 'current run' fallback — the old current_run_id binding (which could
            # silently isolate to the wrong scan) is gone; each row carries its own ``run``.
            ranked = _triage(atlas, run_id=run_id)
            stale_index = _stale_run_index(atlas) if run_id is None else {}
            refused_rows: dict[str, list[Any]] = {}
            if stale_index:
                # BEFORE whole_run and before corpus: every later count is derived from this list,
                # so a row removed after the fact would still be counted in the totals a reader
                # uses to judge how much is left. The removed rows are KEPT here, not just counted,
                # because how many of them there "are" depends on this call's own filters — and
                # saying corpus excludes N of them is only true if N was measured the same way.
                servable = []
                for c in ranked:
                    if c.source_run_id in stale_index:
                        refused_rows.setdefault(c.source_run_id, []).append(c)
                    else:
                        servable.append(c)
                ranked = servable
            # Kept before any filtering: the cross-scope remainder is measured against the WHOLE
            # run, so finishing one class is never read as finishing the firmware.
            whole_run = list(ranked)
            runs_in_atlas = [r.run_id for r in _list_runs(atlas)]
            (
                incomplete,
                partially_incomplete,
                folded_xref,
                unresolved_sonames,
                completeness_unavailable,
            ) = _incomplete_for_run(atlas, run_id)
            # Read the annotations while the atlas is still open (each row's basis freshness is
            # re-derived against the live base map). Overlay OFF -> nothing is read at all.
            overlays = _list_overlays(atlas)["overlays"] if overlay else []
            # Read unconditionally, unlike the overlays above: whether a person put a candidate in
            # the ledger is a fact about the world, not an opt-in view, so it shows either way.
            ledger_refs = _refs_in_ledger(atlas)
            # Same footing, same reason: whether a candidate has been LOOKED AT is a fact about the
            # annotation layer's state, not a view to opt into. Only the ref, its verdict and its
            # live basis freshness are read here — the annotation's content (who, on what basis,
            # how it re-ranks) still arrives only with overlay=true. Sized by how many annotations
            # exist, never by how many candidates.
            coverage_index = _load_coverage_index(atlas)
        finally:
            atlas.close()

        def _narrow(rows: list[Any]) -> list[Any]:
            rows = _filter_candidates(rows, sink=sink, status=status, include_gated=include_gated)
            if sink_class is not None:
                rows = [c for c in rows if c.sink_class == sink_class]
            if fingerprint is not None:
                rows = [c for c in rows if c.structural_fingerprint == fingerprint]
            return rows

        ranked = _narrow(ranked)
        # The refused rows are narrowed by the SAME filters before being counted, so ``corpus`` and
        # ``candidates_excluded`` are measured on one basis and the note's arithmetic holds. Count
        # them raw and a caller who filtered to one sink class would be told the corpus excludes
        # rows that would not have been in it either way.
        refused_counts = {rid: len(_narrow(rows)) for rid, rows in refused_rows.items()}
        stale_runs_refused = [
            {**entry, "candidates_excluded": refused_counts.get(rid, 0)}
            for rid, entry in sorted(stale_index.items())
        ]
        # Apply the map lens: --filter dimensions circle-and-weight FLOAT (corpus never reduced); an
        # --only sweep prunes, refused on an optimistic/null-bearing dimension (which would silently
        # hide candidates). The composite key and demotion iron law ride under any spine.
        dim_filters = _parse_dim_filters(filters)
        only_filters = _parse_dim_filters(only)
        # Refuse a dimension name that does not exist BEFORE anything reads it. Unrecognised names
        # match every candidate, so letting one through returns the whole corpus labelled as
        # matched — indistinguishable from a filter that genuinely matched everything.
        refusal = _unknown_dim_refusal(dim_filters) or _unknown_dim_refusal(only_filters)
        if refusal is not None:
            return {"note": _DERIVED_SIGNAL_NOTE, "error": refusal, "corpus": len(ranked)}
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
        # ★ The overlay band is the OUTERMOST ordering pass, deliberately applied AFTER _apply_view:
        # that call re-sorts the whole list from scratch, so any re-rank done before it would be
        # silently discarded. Stable, so each band keeps the lens order inside it. With the overlay
        # off, by_ref is empty, this is skipped, and the order is the base map's, unchanged.
        by_ref = {o["anchor_ref"]: o for o in overlays}
        if overlay:
            ranked = _apply_overlay_view(ranked, by_ref)
        total = len(ranked)
        # ★ Count against the filters the lens ACTUALLY floats — a preset view's own filter
        # included, not just the ones typed on the command line. Counting only the explicit ones
        # meant a view whose whole promise is "these float to the top" reported nothing at all when
        # nothing matched: the caller saw the default order back, with no way to tell a lens that
        # found nothing from a lens that had nothing to do.
        float_filters = _effective_float_filters(view, dim_filters)
        # None and 0 are different answers and stay different: None is "no lens filter was applied",
        # 0 is "one was, and it matched nothing". Collapsing them loses exactly the distinction this
        # is for.
        filter_match = _filter_match_count(ranked, float_filters) if float_filters else None
        lim = max(0, min(limit, _MAX_LIMIT))
        off = max(0, offset)
        page = ranked[off : off + lim]
        candidate_rows = [
            _candidate_row(
                c,
                off + i,
                by_ref.get(c.evidence_ref),
                in_ledger=c.evidence_ref in ledger_refs,
                coverage=coverage_index.state_for(c.evidence_ref),
            )
            for i, c in enumerate(page)
        ]
        envelope: dict[str, Any] = {
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
                # Only when a lens promised to float something and matched none of it. With matches
                # the ordering speaks for itself; with no filter at all there is nothing to explain.
                **(
                    {"float_empty": _float_empty_note(float_filters, total, corpus)}
                    if float_filters and filter_match == 0
                    else {}
                ),
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
            # ★ Red-line (same family): library-dependency edges NOT written because their soname
            # names more than one binary in this firmware. A count plus where the detail lives —
            # the candidates are per depending binary, so they belong on that binary's own read.
            "unresolved_soname_edges": {
                "count": unresolved_sonames,
                "see": "get_imports_exports(binary).dt_needed_unresolved",
            },
            # ★ Whether the three lists above were COMPUTED. They are the reason an absent
            # candidate is not read as a clean binary, so an empty list has to be able to mean only
            # one thing. ``unavailable`` is null when the check ran; otherwise it carries why it
            # did not, and the note says in words that the empty lists are silence, not a result.
            "analysis_completeness": {
                "unavailable": completeness_unavailable,
                "note": (
                    "incomplete_binaries / partially_incomplete_binaries / folded_xref_symbols "
                    "COULD NOT BE COMPUTED for this listing — the empty lists above are "
                    "UNAVAILABLE, not clean. See unavailable.error for what to do."
                    if completeness_unavailable is not None
                    else (
                        "computed for this run."
                        if run_id is not None
                        else "not computed: these are per-scan facts and this listing spans every "
                        "run — pass run_id to get them."
                    )
                ),
            },
            # ★ Runs whose stored result was PROVEN to have been graded by different code than is
            # answering. Their candidates are not in this listing; they are counted here instead,
            # by name, so the reader can tell a firmware that produced nothing from one that was
            # not served. Always present — an empty list is the statement that none were refused.
            "stale_runs_refused": stale_runs_refused,
            # Stated only when it applies, because it changes how ``corpus`` reads: the refused
            # rows are outside the denominator rather than inside it at zero, so a float count of
            # "0 of N" is measured against rows that could actually have been served.
            "corpus_note": (
                f"corpus excludes {sum(refused_counts.values())} candidates from "
                f"{len(stale_runs_refused)} refused run(s), counted under the same filters as "
                "corpus — see stale_runs_refused"
                if stale_runs_refused
                else None
            ),
            # ``corpus`` is the INVARIANT candidate total — a --filter float never changes it. Under
            # an --only sweep, ``total`` is the (smaller) pruned view; ``corpus`` still shows the
            # whole set so "no match" is never read as "absent".
            # ★ How far through this scope a reader is, measured in PAGES. A class of thousands
            # cannot be finished in one sitting, and demanding it be would only reward clearing the
            # board. Every number is recomputed here from the annotations — no page number and no
            # "done" flag is stored anywhere, so the answer cannot drift from what was recorded.
            "coverage": _coverage_block(
                ranked, whole_run, coverage_index, incomplete, partially_incomplete, folded_xref
            ),
            "corpus": corpus,
            "total": total,
            "offset": off,
            "limit": lim,
        }
        # ★ Fit the candidate array to the response byte budget — a wide-row page at a large limit
        # would otherwise overflow the transport. Paging fields are set from what ACTUALLY fit, not
        # from the row limit, so next_offset resumes exactly where the bytes stopped and no row is
        # skipped. candidates_truncated distinguishes a byte cut from a row-limit end; ``truncated``
        # / ``next_offset`` mean "there is more, page on" for either reason.
        kept, truncated_by_bytes = _fit_candidates(envelope, candidate_rows, _RESPONSE_BYTE_BUDGET)
        returned_end = off + len(kept)
        more = returned_end < total
        envelope["candidates"] = kept
        envelope["returned"] = len(kept)
        envelope["truncated"] = more
        envelope["next_offset"] = returned_end if more else None
        # Announced, never silent: the page was cut by SIZE, so a reader knows the shortfall is the
        # budget and not the corpus, and pages on with next_offset. total/corpus stay exact.
        envelope["candidates_truncated"] = truncated_by_bytes
        return envelope

    def cross_firmware_patterns(limit: int = 50, offset: int = 0) -> dict[str, Any]:
        """Per-pattern recurrence ledger — the highest-value cross-firmware signal.

        For each pattern: ``device_spread`` (how many distinct firmware runs it appears in) and
        ``pattern_breadth`` (distinct fine fingerprints). A candidate whose pattern recurs across
        many firmware images is worth reviewing sooner. Paged (``offset`` + ``truncated`` +
        ``next_offset``) so the tail past ``limit`` is reachable. DERIVED, NOT a verdict."""
        conn = open_atlas(atlas_path)
        try:
            rows = _ledger(conn)
            stale_index = _stale_run_index(conn)
        finally:
            conn.close()
        page, meta = _page(rows, limit, offset)
        result = {
            "note": _DERIVED_SIGNAL_NOTE,
            # The analysis-completeness red-line is a per-SCAN fact; it is surfaced per run via
            # list_candidates(run_id=…), not on this cross-run aggregation (no single analysis.db).
            **meta,
            # Same reason as pattern_twins: device_spread IS a count of runs, so removing one is
            # re-deriving the ledger, not filtering it. Named, with a null count.
            "stale_runs_refused": _refused_entries(stale_index, None),
            "patterns": [asdict(r) for r in page],
        }
        if stale_index:
            result["stale_runs_note"] = (
                "device_spread still COUNTS the refused runs listed in stale_runs_refused: it is "
                "a distinct-run count over each pattern's instances and cannot be filtered without "
                "re-deriving the ledger. Read it as an upper bound on servable scans."
            )
        return result

    def pattern_density(limit: int = 100, offset: int = 0) -> dict[str, Any]:
        """Candidate-instance density per (run, sink_class, fingerprint).

        A count difference for the same fingerprint across runs (e.g. present in one build, absent
        in another) is an early recurrence signal. Paged (``offset`` + ``truncated`` +
        ``next_offset``). DERIVED counts only, NOT a verdict."""
        conn = open_atlas(atlas_path)
        try:
            rows = _density(conn)
            stale_index = _stale_run_index(conn)
        finally:
            conn.close()
        counts: dict[str, int] = {}
        if stale_index:
            kept = []
            for r in rows:
                if r.source_run_id in stale_index:
                    counts[r.source_run_id] = counts.get(r.source_run_id, 0) + r.instance_count
                else:
                    kept.append(r)
            rows = kept
        page, meta = _page(rows, limit, offset)
        return {
            "note": _DERIVED_SIGNAL_NOTE,
            # Per-scan completeness rides list_candidates(run_id=…); this aggregation is cross-run.
            **meta,
            "stale_runs_refused": _refused_entries(stale_index, counts),
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
            stale_index = _stale_run_index(conn)
        finally:
            conn.close()
        page, meta = _page(rows, limit, offset)
        result = {
            "note": _DERIVED_SIGNAL_NOTE,
            **meta,
            # Named but NOT removed: a twin row is a count over every run at once and carries no
            # run of its own, so a refused run's instances cannot be taken back out of it without
            # re-deriving the aggregation. Saying which runs are in there beats a silently mixed
            # count — and null (not 0) is what says their contribution is still included.
            "stale_runs_refused": _refused_entries(stale_index, None),
            "twins": [asdict(r) for r in page],
        }
        if stale_index:
            result["stale_runs_note"] = (
                "blocked_count / non_blocked_count still INCLUDE the refused runs listed in "
                "stale_runs_refused: these counts aggregate across every run and carry no run "
                "column to filter on. Scope per run with list_candidates(run_id=…) to read only "
                "servable scans."
            )
        return result

    def dormant_candidates(limit: int = 100, offset: int = 0) -> dict[str, Any]:
        """Candidates whose in-function path carries an identified guard (blocked, L0/L1).

        Useful to spot a guard that may be absent elsewhere. May be empty depending on the atlas's
        firmware mix. Paged (``offset`` + ``truncated`` + ``next_offset``). Each row is a lead, NOT
        a confirmed mitigation. DERIVED, NOT a verdict."""
        conn = open_atlas(atlas_path)
        try:
            rows = _dormant(conn)
            stale_index = _stale_run_index(conn)
        finally:
            conn.close()
        # Dropped BEFORE paging, so the page counts describe rows that could actually be served.
        counts: dict[str, int] = {}
        if stale_index:
            kept = []
            for r in rows:
                rid = r["source_run_id"]
                if rid in stale_index:
                    counts[rid] = counts.get(rid, 0) + 1
                else:
                    kept.append(r)
            rows = kept
        page, meta = _page(rows, limit, offset)
        return {
            "note": _DERIVED_SIGNAL_NOTE,
            **meta,
            "stale_runs_refused": _refused_entries(stale_index, counts),
            "dormant": [dict(r) for r in page],
        }

    def explain_candidate(evidence_ref: str) -> dict[str, Any]:
        """Single-candidate fact view: every dimension layer's honest three-state annotation
        (controllability / source_writability / reachability / filtering / sink_impact / writer /
        completeness), the lens caveats, the claim bounds, and where to verify — no score.

        Returns a not-found record when no instance carries ``evidence_ref`` (no fabrication).
        Echoes the canonical ``resolved_run`` + inline ``run_lineage`` (M6/M7): a ref anchors ONE
        firmware run, so the explanation names the scan it came from (never an ambient run).

        Carries ``coverage``: whether a conclusion has been recorded for this candidate. When none
        has, it says where to put one and why that is worth doing for the reader's own sake."""
        conn = open_atlas(atlas_path)
        try:
            ref = _resolve_ref(conn, evidence_ref)
            run = _get_run(conn, ref[0]) if ref is not None and ref[0] is not None else None
            # ★ Same gate as list_candidates, on the tool the map's rows point AT. A ref resolves
            # its own run, so the refusal needs no argument from the caller — and without it the
            # refusal is one hop from useless: every candidate row carries a ref, and following one
            # is the documented next step.
            if run is not None:
                refusal = _stale_refusal(conn, run)
                if refusal is not None:
                    refusal["resolved_run"] = run.run_id
                    refusal["run_lineage"] = _lineage_inline(run)
                    refusal["evidence_ref"] = evidence_ref
                    return refusal
            ex = _explain_candidate(conn, evidence_ref)
            coverage_state = _load_coverage_index(conn).state_for(evidence_ref)
        finally:
            conn.close()
        if ex is None:
            return {"found": False, "evidence_ref": evidence_ref, "atlas": str(atlas_path)}
        data = asdict(ex)
        data["found"] = True
        data["note"] = _DERIVED_SIGNAL_NOTE
        # This payload expands the candidate, so the raw form note reaches the reader as a bare
        # string. Frame it here, where it actually appears.
        data["blocking_mechanism_note"] = _BARE_FORM_NOTE_CAVEAT
        data["atlas"] = str(atlas_path)
        data["coverage"] = coverage_state
        if coverage_state == "none":
            # ★ Stated as a fact about this candidate, the same way an unknown dimension is, and
            # argued from the reader's OWN interest rather than from tidiness. A conclusion kept
            # outside the overlay is a conclusion nothing can re-check: when the source is
            # re-scanned and the code underneath moves, it quietly becomes a stale belief that
            # something was fine. Recorded here, the same change surfaces it for another look.
            data["coverage_hint"] = (
                "No conclusion recorded for this candidate. Record one with annotate(evidence_ref, "
                "verdict, rationale) — it is one call, and it is what makes your conclusion "
                "survive a re-scan: when the code underneath moves, an annotation is flagged for "
                "re-review, while a conclusion held anywhere else silently goes stale. If you "
                "looked and could not settle it, 'inconclusive' with the next step IS the "
                "conclusion — it stays in view. 'excluded' means you have a reason it cannot be "
                "reached, not that you are done looking."
            )
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
            ref = _resolve_ref(conn, evidence_ref)
            run = _get_run(conn, ref[0]) if ref is not None and ref[0] is not None else None
            if run is not None:
                refusal = _stale_refusal(conn, run)
                if refusal is not None:
                    refusal["resolved_run"] = run.run_id
                    refusal["run_lineage"] = _lineage_inline(run)
                    refusal["evidence_ref"] = evidence_ref
                    return refusal
            result: dict[str, Any] = _get_sink_provenance(
                conn, evidence_ref, sink_idx, dominating_only=dominating_only
            )
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

    def get_nvram_key_flow(key: str, run_id: str | None = None) -> dict[str, Any]:
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
        never a verdict.

        ``run_id`` narrows the whole graph to one firmware. Omitted (the default), it spans every
        firmware you have scanned — often what you want, since a key's behaviour across devices is
        the interesting part, and every row names its own run. Pass it when you are auditing ONE
        image and do not want another device's rows in the answer. Scoping also scopes the
        completeness caveat: it then means "may be incomplete within THIS run"."""
        conn = open_atlas(atlas_path)
        try:
            refusal = _refuse_stale_run(conn, run_id)
            if refusal is not None:
                return refusal
            result = _get_nvram_key_flow(conn, key, run_id=run_id)
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
            refusal = _refuse_stale_run(conn, run_id)
            if refusal is not None:
                return refusal
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

    def launched_by(
        target: str,
        run_id: str | None = None,
        limit: int = 200,
    ) -> dict[str, Any]:
        """Which binaries' CODE launches ``target`` — the cross-binary "A execs B" edge. Answers
        "who starts this daemon?" and "is this binary only ever run by that one caller?" from a
        table, instead of grepping every command string by hand.

        ``target`` takes either a binary's SHORT NAME as the inventory lists it (``busybox``,
        ``httpd``) or a launched SCRIPT's path under the firmware root (``usr/sbin/getmac``).
        Scripts are stored by path, and a short name is matched against that path's basename too,
        so ``getmac`` finds the script edge either way. Pass ``run_id`` to stay inside one
        firmware; without it the answer spans every run in the atlas and each edge names its own.
        Each edge carries the launcher (binary + function + address), the API, whether a shell
        wraps it, and the command template when one is visible.

        Read ``target_layer``: ``exec_image`` means the target IS the image being run;
        ``shell_command`` means it is the first word of a command string, whose actual image is
        /bin/sh (deliberately not listed as its own edge). The two never overlap.

        ★ These are ENUMERATED FACTS, NOT a reachability verdict: an edge does not say the
        callsite runs, nor that an attacker's input reaches it — you confirm the caller. An EMPTY
        result is NOT proof that nothing launches the binary: read ``exec_argv_status``, which
        names what this pass cannot see (most sharply, a caller whose command sink sits behind a
        thin forwarding wrapper — that callsite is invisible here)."""
        conn = open_atlas(atlas_path)
        try:
            refusal = _refuse_stale_run(conn, run_id)
            if refusal is not None:
                return refusal
            return _launched_by(conn, target, run_id=run_id, limit=limit)
        finally:
            conn.close()

    def get_diff_deltas(
        diff_id: str,
        binary: str | None = None,
        dimension: str | None = None,
        delta_kind: str | None = None,
        limit: int = 100,
        offset: int = 0,
        verbose: bool = False,
    ) -> dict[str, Any]:
        """The tri-state dimension DELTAS a version diff produced, for one ``diff_id`` (a diff_id is
        ``{run_a}::{run_b}::{binary}`` — it already identifies ONE binary; use list_diffs to find
        the ids). Filter by ``binary`` (redundant with the id, kept as a check), ``dimension``,
        ``delta_kind``; page with ``limit``/``offset``.

        ★ A delta is a PROJECTION of two already-computed annotations, NOT a change/quality verdict.
        ``layer_changed`` = the patch changed this aligned function's edge set -- NOT proof the
        change matters, you judge that. ``delta_undetermined`` is NOT 'unchanged' -- always read
        its ``undetermined_reason`` (an enum that may grow; do not branch on it). ``state_a`` /
        ``state_b`` are OPAQUE strings you interpret. An EMPTY result is NOT 'no changes' -- call
        get_diff_capabilities to see which dimensions this diff can even delta. ``verbose=false``
        keeps the payload to rows + paging; ``verbose=true`` adds the note + legend."""
        conn = open_atlas(atlas_path)
        try:
            refusal = _refuse_stale_diff(conn, diff_id)
            if refusal is not None:
                return refusal
            return _get_diff_deltas(
                conn,
                diff_id,
                binary=binary,
                dimension=dimension,
                delta_kind=delta_kind,
                limit=limit,
                offset=offset,
                verbose=verbose,
            )
        finally:
            conn.close()

    def get_diff_meta(diff_id: str) -> dict[str, Any]:
        """The meta facts of one version diff (``diff_id`` = ``{run_a}::{run_b}::{binary}``, one per
        binary — see list_diffs): binary scope, tool/decompiler versions, alignment + presence.

        ★ ``version_skew=1`` means every delta in this diff is version_skew undetermined -- do not
        read it as 'no change'; it compares only the analysis-tool version, not the firmware. A NULL
        ``ghidra_version`` = that side recorded none. ``unmatched_b`` = B-side functions with no
        A-side match (the presence layer, the WEAKEST signal -- to find changes look at
        ``layer_changed`` via get_diff_deltas, not this). ★ ``diff_ok=0`` means this binary did NOT
        diff (``diff_status='failed'``, ``diff_status_reason`` = why, ``diff_attempts`` = tries): an
        empty get_diff_deltas for it is a BLIND SPOT, never 'no change' (list_diff_blindspots)."""
        conn = open_atlas(atlas_path)
        try:
            refusal = _refuse_stale_diff(conn, diff_id)
            if refusal is not None:
                return refusal
            return _get_diff_meta(conn, diff_id)
        finally:
            conn.close()

    def get_function_alignment(diff_id: str, addr: str, side: str = "a") -> dict[str, Any]:
        """The BinDiff-aligned counterpart of one function address in a diff. ``side="a"`` resolves
        an A-side (before) address to its B-side match; ``side="b"`` the reverse. The core "I found
        something at address X -- did the other version patch it?" lookup.

        ★ Returns an ALIGNMENT FACT, never a verdict: ``alignment_confidence`` = trust in the
        pairing, ``similarity`` = how much the pair differs (a pair can be similarity=1.0 yet
        confidence ~0.02). ``alignment_undetermined`` means the alignment ITSELF is uncertain --
        neither 'not matched' nor 'changed'. No match here is NOT proof the function was added or
        removed (see function_presence)."""
        conn = open_atlas(atlas_path)
        try:
            refusal = _refuse_stale_diff(conn, diff_id)
            if refusal is not None:
                return refusal
            if side == "b":
                return _align_by_b(conn, diff_id, addr)
            return _align_by_a(conn, diff_id, addr)
        finally:
            conn.close()

    def get_diff_capabilities(diff_id: str) -> dict[str, Any]:
        """Per-dimension capability state for a diff (``diff_id`` = ``{run_a}::{run_b}::{binary}``,
        one per binary): which dimensions each side could analyse and whether it can delta them.

        ★ ``delta_supported=0`` for a dimension is an EXPLICIT non-judgement -- the dimension is
        VISIBLE but this diff produces no per-subject delta for it, never a silent omission. Read
        this alongside an empty get_diff_deltas: empty there + delta_supported=0 here = 'this diff
        does not delta that dimension', which is NOT the same as 'nothing changed'. ``state_a`` /
        ``state_b`` are each side's analysis capability (present / declared_absent /
        registration_unknown)."""
        conn = open_atlas(atlas_path)
        try:
            refusal = _refuse_stale_diff(conn, diff_id)
            if refusal is not None:
                return refusal
            return _get_diff_capabilities(conn, diff_id)
        finally:
            conn.close()

    def list_diffs(run_a_id: str | None = None, run_b_id: str | None = None) -> dict[str, Any]:
        """Browse the version diffs in the atlas: one row per binary diffed between two runs, with
        its change profile (matched_pairs, layer_changed / unchanged / undetermined, version_skew)
        AND its diff status (diff_ok / diff_status / diff_status_reason / diff_attempts). Optionally
        filter to a run-pair. The entry point after a full diff — see which binaries were compared,
        how much each moved, and which FAILED to diff, then open one with get_diff_deltas /
        get_diff_meta.

        ★ Counts are tri-state PROJECTIONS, never verdicts or a ranking: ``layer_changed`` is not
        proof the change matters, and an EMPTY list means no diff has been run for that filter --
        not 'nothing changed'. ★ A ``diff_ok=0`` row is a BLIND SPOT (the binary did not diff --
        diff_status_reason says why): its zero counts are 'unknown', NOT 'no change'. Use
        list_diff_blindspots to focus just the un-diffed binaries."""
        conn = open_atlas(atlas_path)
        try:
            return _list_diffs(conn, run_a_id, run_b_id)
        finally:
            conn.close()

    def list_diff_blindspots(
        run_a_id: str | None = None, run_b_id: str | None = None
    ) -> dict[str, Any]:
        """The binaries a full diff could NOT analyse between two runs (``diff_ok=0``) — the
        explicit blind-spot listing that keeps an un-diffed binary from masquerading as 'no change'.
        Optionally filter to a run-pair.

        ★ UNKNOWN is not SAFE: a binary missing from the deltas may simply have FAILED to diff. Each
        row gives ``diff_status_reason`` (why it failed — e.g. binexport_ghidra_crash likely
        transient, bindiff_flowgraph likely a hard boundary), ``diff_attempts`` (how many tries),
        and ``suspected_hard`` (1 = hit the retry cap, so later full diffs skip it unless
        force_retry; a HINT from repeated identical-content failures, never proof the binary is
        undiffable — its content changing resets the count). Read this alongside get_diff_deltas so
        a consumer of the change map always sees the coverage gaps too."""
        conn = open_atlas(atlas_path)
        try:
            return _list_diff_blindspots(conn, run_a_id, run_b_id)
        finally:
            conn.close()

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
        stale). A miss says whether the function lives in a DIFFERENT run or in none.

        ``binary`` is a SELECTOR: a sha256 (a >=8-hex prefix works), a full path, or a
        short name. A short name is a label and can name several binaries in one firmware;
        when it does, the result is ``reason='ambiguous'`` listing each candidate's
        ``binary_path`` and ``sha256`` — re-issue with one of them. That is an answer about
        the firmware, not an error.
        When ``func`` resolves, ITS binary is used and ``binary`` does not re-select."""
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

        Run-aware: ``run_id`` + ``function`` or ``evidence_ref``; echoes ``resolved_run``.

        ``binary`` is a SELECTOR: a sha256 (a >=8-hex prefix works), a full path, or a
        short name. A short name is a label and can name several binaries in one firmware;
        when it does, the result is ``reason='ambiguous'`` listing each candidate's
        ``binary_path`` and ``sha256`` — re-issue with one of them. That is an answer about
        the firmware, not an error.
        When ``func`` resolves, ITS binary is used and ``binary`` does not re-select."""
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

        Run-aware: ``run_id`` + ``function`` or ``evidence_ref``; echoes ``resolved_run``.

        ``binary`` is a SELECTOR: a sha256 (a >=8-hex prefix works), a full path, or a
        short name. A short name is a label and can name several binaries in one firmware;
        when it does, the result is ``reason='ambiguous'`` listing each candidate's
        ``binary_path`` and ``sha256`` — re-issue with one of them. That is an answer about
        the firmware, not an error.
        When ``func`` resolves, ITS binary is used and ``binary`` does not re-select."""
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
        string NOT found there is NOT proven absent.

        ``binary`` is a SELECTOR: a sha256 (a >=8-hex prefix works), a full path, or a
        short name. A short name is a label and can name several binaries in one firmware;
        when it does, the result is ``reason='ambiguous'`` listing each candidate's
        ``binary_path`` and ``sha256`` — re-issue with one of them. That is an answer about
        the firmware, not an error.
        When ``func`` resolves, ITS binary is used and ``binary`` does not re-select."""
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

        Run-aware: ``run_id`` + ``binary`` or ``evidence_ref``; echoes ``resolved_run``.

        ``binary`` is a SELECTOR: a sha256 (a >=8-hex prefix works), a full path, or a
        short name. A short name is a label and can name several binaries in one firmware;
        when it does, the result is ``reason='ambiguous'`` listing each candidate's
        ``binary_path`` and ``sha256`` — re-issue with one of them. That is an answer about
        the firmware, not an error."""
        return _fact(
            lambda c, fn, bn: facts.get_imports_exports(c, binary=bn or ""),
            run_id=run_id,
            evidence_ref=evidence_ref,
            binary=binary,
        )

    def get_data_bytes(
        address: str,
        length: int = 64,
        binary: str | None = None,
        run_id: str | None = None,
        evidence_ref: str | None = None,
    ) -> dict[str, Any]:
        """RAW bytes stored at a data-segment ``address`` (what a bare ``DAT_000174e4`` hides).

        The decompiler renders a data-segment constant as a name and DROPS its content, so the
        value is simply absent from the pseudocode. This reads it back from the segment bytes
        recorded at scan time (no Ghidra re-run). ``address`` is hex, in any form Ghidra shows
        (``0x174e4`` / ``000174e4``); ``length`` is bytes to return.

        ★ BYTES ONLY — no interpretation travels with them. ``ascii`` is a mechanical rendering
        (non-printable -> '.'), NOT a claim that the run is text/a key/a charset; that reading is
        yours to make. Misses are distinct on purpose and none of them means "the bytes are zero":
        ``uninitialized_bss`` (a reserved .bss extent whose value exists only at runtime),
        ``address_not_in_any_data_block`` (outside every exported block), and
        ``data_blocks_not_exported`` (this binary was not scanned since the export existed —
        UNKNOWN, not "no data"). ``truncated`` names which limit stopped the read and never means
        the data ends there.

        ★ ``bytes_from_executable_segment: true`` + ``warning``: the bytes came out of an RX block.
        Executable blocks ARE covered, because on a section-header-stripped ELF (the common case in
        firmware) Ghidra makes one block per PT_LOAD and .rodata rides inside the executable one —
        without that reach a .rodata address would be unanswerable there. The cost is that .rodata
        and .text are then indistinguishable: treat such a run as possibly INSTRUCTIONS until the
        address is confirmed to be a data constant.

        Run-aware: ``run_id`` + ``binary`` or ``evidence_ref``; echoes ``resolved_run``.

        ``binary`` is a SELECTOR: a sha256 (a >=8-hex prefix works), a full path, or a
        short name. A short name is a label and can name several binaries in one firmware;
        when it does, the result is ``reason='ambiguous'`` listing each candidate's
        ``binary_path`` and ``sha256`` — re-issue with one of them. That is an answer about
        the firmware, not an error."""
        return _fact(
            lambda c, fn, bn: facts.get_data_bytes(
                c, binary=bn or "", address=address, length=length
            ),
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
        symbol reference — the text may sit in a comment or unrelated literal; confirm each hit.

        ``binary`` is a SELECTOR: a sha256 (a >=8-hex prefix works), a full path, or a
        short name. A short name is a label and can name several binaries in one firmware;
        when it does, the result is ``reason='ambiguous'`` listing each candidate's
        ``binary_path`` and ``sha256`` — re-issue with one of them. That is an answer about
        the firmware, not an error."""
        return _fact(
            lambda c, fn, bn: facts.get_functions_referencing_string(c, text=text, binary=bn),
            run_id=run_id,
            evidence_ref=evidence_ref,
            binary=binary,
        )

    def get_string_reference_anchors(
        text: str,
        binary: str | None = None,
        limit: int = 50,
        run_id: str | None = None,
        evidence_ref: str | None = None,
    ) -> dict[str, Any]:
        """Where a string is REFERENCED, by RESOLVED Ghidra data references (parsed, not text).

        The parsed sibling of get_functions_referencing_string. That one searches decompiled TEXT
        for a substring, so it also matches comments, longer strings containing this one, and
        unrelated literals — wide and noisy. This one reports references Ghidra actually resolved to
        the string's address, so that noise cannot appear. The trade is coverage: only DEFINED
        strings, only references the analysis recovered, and ``text`` matches the string value
        EXACTLY (locate the exact literal with get_strings(value=…) first). Use both.

        Each anchor is {ref_at, ref_in_func, ref_in_func_addr, segment} — the referencing
        instruction, the function containing it (null for a bare table slot in no function), and the
        segment as METADATA ONLY (an ARM literal-pool ``ldr =S`` is a data reference living in an
        executable block, so segment never filters). A FACT (the string is referenced here), NEVER a
        dispatch/reachability verdict.

        HONEST BOUNDS: ``no_resolved_dataref`` = the export ran and resolved nothing here — the
        same "empty is not a proof" shape as an empty caller set, NOT "this string is unreferenced"
        (indirect/computed references escape resolution). ``string_refs_not_exported`` = no export
        for this scope at all (older scan / not re-scanned) — UNKNOWN, not "no references".

        Run-aware: ``run_id`` + optional ``binary`` (or an ``evidence_ref``); echoes
        ``resolved_run``.

        ``binary`` is a SELECTOR: a sha256 (a >=8-hex prefix works), a full path, or a
        short name. A short name is a label and can name several binaries in one firmware;
        when it does, the result is ``reason='ambiguous'`` listing each candidate's
        ``binary_path`` and ``sha256`` — re-issue with one of them. That is an answer about
        the firmware, not an error."""
        return _fact(
            lambda c, fn, bn: facts.get_string_reference_anchors(
                c, text=text, binary=bn, limit=limit
            ),
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

    def get_disassembly(
        function: str | None = None,
        binary: str | None = None,
        run_id: str | None = None,
        evidence_ref: str | None = None,
    ) -> dict[str, Any]:
        """On-demand disassembly — same-source aligned, or an honest 'unavailable' (never wrong).

        Run-aware: ``run_id`` + ``function`` or ``evidence_ref``; echoes ``resolved_run``.

        ``binary`` is a SELECTOR: a sha256 (a >=8-hex prefix works), a full path, or a
        short name. A short name is a label and can name several binaries in one firmware;
        when it does, the result is ``reason='ambiguous'`` listing each candidate's
        ``binary_path`` and ``sha256`` — re-issue with one of them. That is an answer about
        the firmware, not an error.
        When ``func`` resolves, ITS binary is used and ``binary`` does not re-select."""
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

    def list_verified_exploits(reveal: bool = False) -> dict[str, Any]:
        """The private exploit records: ``distinct_exploits`` (distinct candidates) +
        ``records`` (rows). Each entry carries its pattern + a has_exploit_evidence flag; the full
        ``exploit_note`` (the closest thing to an exploit method) is WITHHELD unless reveal=True.

        ★ reveal=True is the ONE reveal channel and a DISCIPLINE path, not a protected one: the full
        text it returns still lands in your context / the transcript, so 'exploit methods do not
        leave the system' holds for the DEFAULT path only — on reveal it rides your own care."""
        atlas = open_atlas(atlas_path)
        try:
            result = _list_verified_exploits(atlas, reveal=reveal)
        finally:
            atlas.close()
        result["note"] = _DERIVED_SIGNAL_NOTE
        return result

    def list_cve_patterns(cve_id: str | None = None, sink: str | None = None) -> dict[str, Any]:
        """The public-CVE exploit-form list (public material, NOT counted in ``distinct_exploits``).

        Filter by exact ``cve_id`` and/or a ``sink`` substring — deterministic lookup, no fuzzy
        match. Public data — a separate table from the private exploit records."""
        atlas = open_atlas(atlas_path)
        try:
            result = _list_cve_patterns(atlas, cve_id=cve_id, sink=sink)
        finally:
            atlas.close()
        result["note"] = _DERIVED_SIGNAL_NOTE
        return result

    def import_cve_patterns(patterns: list[dict[str, Any]]) -> dict[str, Any]:
        """Idempotent import of public-CVE exploit forms into the public table.

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

    def annotate(
        evidence_ref: str,
        verdict: str,
        rationale: str,
        block_source: str | None = None,
        block_point: str | None = None,
        block_why: str | None = None,
        chain: str | None = None,
        verification_gaps: list[str] | None = None,
        shared_prereq: str | None = None,
    ) -> dict[str, Any]:
        """Record YOUR OWN judgement about one candidate onto the overlay — the annotation layer
        over the read-only map. This is YOUR decision, not a tool fact; the base map
        (list_candidates) is unchanged whether the overlay is empty or full, and reads identically
        with the overlay off.

        ``verdict`` is one of:

        * ``inconclusive`` — you looked and nothing decisive could be established from what this
          tool can see. Put the next step in the rationale; the candidate stays where it was.
        * ``suspicious`` — worth digging into further. Floats up.
        * ``excluded`` — noise, or not relevant. Sinks.
        * ``safe`` — you judged it cannot be reached or exploited. Sinks, and REQUIRES all three of
          ``block_source`` (what input you traced), ``block_point`` (where it is stopped — name the
          function/check), ``block_why`` (why that stop covers EVERY path in and cannot be worked
          around). The third is the load-bearing one. This is the judgement that takes a candidate
          off the table, and a wrong one only comes back if the CODE changes — never because the
          judgement was wrong — so it is recorded as a claim someone can review.
        * ``exploitable`` — a tier above suspicious: the digging is done and only real-machine
          confirmation is left. Floats ABOVE every suspicious candidate. Strongly recommended (not
          yet required) to pass ``chain`` — the path, citing code, e.g.
          "mqtt topic -> handler_parse_cmd -> build_cmd (0x4a12) -> system" — plus
          ``verification_gaps``, two or more things still to confirm on hardware, e.g.
          ["needs a device on the same mesh segment", "unclear whether the daemon runs as root"].
          Optional ``shared_prereq`` names a precondition shared with other candidates. With those
          filled the record survives as a re-usable description of the shape, not just a label.

        Call this when you have reached a conclusion about a candidate worth keeping past THIS
        session — not on every read, and not for mid-investigation scratch notes.

        ``rationale`` is required (why + next step + confidence). One annotation per candidate:
        re-annotating OVERWRITES (last write wins; the echo names whom you overwrote). The write
        snapshots the candidate's basis (its pseudocode + dimensions) so list_overlays can flag it
        for re-review if the base map moved. A blind write is honest: an unresolved
        ``evidence_ref`` is still recorded, with a warning."""
        if not (evidence_ref and evidence_ref.strip()):
            return {"written": False, "error": "evidence_ref must be non-blank."}
        if not (rationale and rationale.strip()):
            return {
                "written": False,
                "error": "rationale must be non-blank — record why + the next step + confidence.",
            }
        # Assemble the per-verdict justification from the named arguments. Only the fields that
        # belong to the verdict being written are collected; anything supplied that does not belong
        # is passed through so the layer below can refuse it by name rather than dropping it.
        supplied = {
            "block_source": block_source,
            "block_point": block_point,
            "block_why": block_why,
            "chain": chain,
            "verification_gaps": verification_gaps,
            "shared_prereq": shared_prereq,
        }
        given = {k: v for k, v in supplied.items() if v is not None}
        verdict_basis: dict[str, Any] | None = given or None

        atlas = open_atlas(atlas_path)
        try:
            ref = _resolve_ref(atlas, evidence_ref)
            try:
                res = _upsert_overlay(
                    atlas,
                    evidence_ref=evidence_ref,
                    verdict=verdict,
                    rationale=rationale,
                    attributed_to="agent-via-mcp",
                    verdict_basis=verdict_basis,
                )
            except ConfigError as exc:
                return {"written": False, "error": str(exc)}
        finally:
            atlas.close()
        result: dict[str, Any] = {
            "written": True,
            "action": res.action,  # 'inserted' | 'updated'
            "id": res.id,
            "evidence_ref": evidence_ref.strip(),
            "verdict": verdict,
            "atlas": str(atlas_path),
            "note": "recorded on the overlay (an AGENT annotation, never a tool fact). The base "
            "is unchanged. list_overlays resumes these + flags any whose basis has since moved.",
        }
        if verdict == "safe":
            result["note"] = (
                "recorded as a reviewable defensive claim. You are asserting the thing this tool "
                "deliberately will not assert for you: that nothing gets through. A wrong 'safe' "
                "is a real hole gone quiet — it only re-surfaces when the CODE changes, never "
                "because the judgement itself was wrong."
            )
        elif verdict == "exploitable" and verdict_basis is None:
            result["note"] = (
                "recorded. Consider adding chain + verification_gaps: with them this survives as a "
                "re-usable description of the shape, rather than a label only you can interpret."
            )
        if res.action == "updated":
            result["overwrote"] = {
                "attributed_to": res.prior_attributed_to,
                "updated_at": res.prior_updated_at,
            }
        if ref is None or not res.basis_resolved:
            result["warning"] = (
                f"evidence_ref '{evidence_ref}' does not resolve to a candidate in this atlas — "
                "BLIND WRITE (annotating before the scan exists?). Recorded anyway; basis cannot "
                "be snapshotted, so staleness cannot be checked until the ref resolves."
            )
        return result

    def list_overlays(verdict: str | None = None, run_id: str | None = None) -> dict[str, Any]:
        """Your overlay annotations, optionally filtered to one ``verdict`` — the resume view: "what
        did I mark ``inconclusive`` / ``suspicious`` / ``excluded``". Each row carries its live
        ``basis_state``: ``unchanged`` (the pseudocode + dimensions it rested on have not moved),
        ``changed`` (they have — RE-REVIEW; the delta names what moved), ``unverifiable`` (no
        pseudocode hash to compare — an honest can't-say, never a clean bill), or
        ``anchor_unresolved`` (the ref no longer resolves). Stale rows are surfaced, never dropped.

        ``run_id`` narrows to ONE firmware — the atlas accumulates across every scan, so without it
        a multi-firmware audit reads back one mixed pile. Each row also carries its own ``run_id``.
        Both filters AND together.

        ★ These are AGENT decisions on the overlay, not tool facts. ``bias`` is the opt-in
        overlay-on view's float(+1)/sink(-1); the base map's own ordering is untouched."""
        atlas = open_atlas(atlas_path)
        try:
            refusal = _refuse_stale_run(atlas, run_id)
            if refusal is not None:
                return refusal
            return _list_overlays(atlas, verdict=verdict, run_id=run_id)
        finally:
            atlas.close()

    def clear_overlay(run_id: str | None = None, evidence_ref: str | None = None) -> dict[str, Any]:
        """Delete overlay annotations and report how many went. The base map is untouched either
        way — it reads byte-identical afterward. This is scratch space you own.

        With NO argument this wipes every annotation, across every firmware. Pass ONE scope to
        clear less: ``run_id`` drops just that firmware's annotations, ``evidence_ref`` drops the
        single annotation on one candidate — the one to reach for when retiring an entry you no
        longer stand behind, rather than starting over. The two scopes cannot be combined."""
        atlas = open_atlas(atlas_path)
        try:
            removed = _clear_overlay(atlas, run_id=run_id, evidence_ref=evidence_ref)
        except ConfigError as exc:
            return {"cleared": 0, "error": str(exc)}
        finally:
            atlas.close()
        if evidence_ref is not None:
            scope = f"the annotation on {evidence_ref}"
        elif run_id is not None:
            scope = f"annotations for run {run_id}"
        else:
            scope = "EVERY annotation, across every firmware"
        return {
            "cleared": removed,
            "scope": {"run_id": run_id, "evidence_ref": evidence_ref},
            "note": f"removed {scope}; the read-only base map is unchanged.",
        }

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
        "launched_by": launched_by,
        "get_diff_deltas": get_diff_deltas,
        "get_diff_meta": get_diff_meta,
        "get_function_alignment": get_function_alignment,
        "get_diff_capabilities": get_diff_capabilities,
        "list_diffs": list_diffs,
        "list_diff_blindspots": list_diff_blindspots,
        "cross_firmware_patterns": cross_firmware_patterns,
        "pattern_density": pattern_density,
        "pattern_twins": pattern_twins,
        "dormant_candidates": dormant_candidates,
        "get_pseudocode": get_pseudocode,
        "get_callees": get_callees,
        "get_xrefs": get_xrefs,
        "get_strings": get_strings,
        "get_functions_referencing_string": get_functions_referencing_string,
        "get_string_reference_anchors": get_string_reference_anchors,
        "get_imports_exports": get_imports_exports,
        "get_data_bytes": get_data_bytes,
        "get_script_callsites": get_script_callsites,
        "get_disassembly": get_disassembly,
        "annotate": annotate,
        "list_overlays": list_overlays,
        "clear_overlay": clear_overlay,
        "list_verified_exploits": list_verified_exploits,
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
