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

from treasure_map.lib import facts
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.notice import LEGAL_NOTICE
from treasure_map.lib.query import explain_candidate as _explain_candidate
from treasure_map.lib.query import triage as _triage

# A standing reminder attached to every candidate-listing result: the ordering signals are derived
# from neutral stored facts, carry their evidence, and are NOT a security verdict.
_DERIVED_SIGNAL_NOTE = (
    "score / entry_reach / blocking_mechanism are DERIVED, evidence-backed review-ordering "
    "signals — NOT a verdict. A candidate is a lead to verify, never a confirmed issue."
)


def _candidate_dict(c: Any) -> dict[str, Any]:
    """One triage candidate as a flat, JSON-serializable record (anchor + derived signals)."""
    return {
        "evidence_ref": c.evidence_ref,  # the anchor
        "function": c.function,
        "binary_path": c.binary_path,
        "sink_anchor": c.sink_anchor,
        "sink_class": c.sink_class,
        "source_class": c.source_class,
        "reachability_status": c.reachability_status,  # raw mechanism state (unknown/confirmed/…)
        "review_status": c.review_status,  # presentation relabel (to-verify / reachable / gated)
        "blocking_mechanism": c.blocking_mechanism,
        "origin": c.origin,
        "entry_reach": c.entry_reach,  # found promotes within tier; unknown is neutral
        "score": c.score,  # derived review-ordering signal, NOT a verdict
        "source_run_id": c.source_run_id,
    }


def make_tools(analysis_db: Path | str, atlas_db: Path | str) -> dict[str, Callable[..., Any]]:
    """Build the tool callables bound to one workspace's databases.

    Returned as plain functions so the CLI, the MCP registration, and the tests all invoke the
    SAME code path (parity by construction)."""
    analysis_path = Path(analysis_db)
    atlas_path = Path(atlas_db)

    def _with_analysis(
        fn: Callable[[sqlite3.Connection], dict[str, Any]],
    ) -> dict[str, Any]:
        conn = facts.open_analysis_ro(analysis_path)
        try:
            return fn(conn)
        finally:
            conn.close()

    def list_candidates(
        run_id: str | None = None, sink_class: str | None = None, limit: int = 50
    ) -> dict[str, Any]:
        """List recall candidates with their derived, evidence-backed review-ordering signals.

        Each candidate carries its anchor (evidence_ref), sink/source class, reachability status,
        blocking_mechanism, entry_reach, and the review score. Signals are DERIVED and NOT a
        verdict. Optional ``sink_class`` filter (cmd / fmt_string / copy / format) and ``limit``."""
        conn = open_atlas(atlas_path)
        try:
            ranked = _triage(conn, run_id=run_id)
        finally:
            conn.close()
        if sink_class is not None:
            ranked = [c for c in ranked if c.sink_class == sink_class]
        return {
            "note": _DERIVED_SIGNAL_NOTE,
            "count": len(ranked),
            "candidates": [_candidate_dict(c) for c in ranked[: max(0, limit)]],
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
        "get_pseudocode": get_pseudocode,
        "get_callees": get_callees,
        "get_xrefs": get_xrefs,
        "get_strings": get_strings,
        "get_imports_exports": get_imports_exports,
        "get_script_callsites": get_script_callsites,
        "get_components_cves": get_components_cves,
        "get_disassembly": get_disassembly,
        "legal_notice": legal_notice,
    }


def build_server(analysis_db: Path | str, atlas_db: Path | str) -> Any:
    """Construct a FastMCP server exposing the fact tools bound to one workspace.

    Imported lazily so the rest of the package does not require the ``mcp`` dependency."""
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("treasure-map", instructions=LEGAL_NOTICE)
    for fn in make_tools(analysis_db, atlas_db).values():
        server.add_tool(fn)
    return server


def main() -> None:
    """Entry point: serve over stdio. DB paths from TREASURE_MAP_ANALYSIS_DB / _ATLAS_DB."""
    analysis_db = os.environ.get("TREASURE_MAP_ANALYSIS_DB", "analysis.db")
    atlas_db = os.environ.get("TREASURE_MAP_ATLAS_DB", "atlas.db")
    build_server(analysis_db, atlas_db).run()


if __name__ == "__main__":
    main()
