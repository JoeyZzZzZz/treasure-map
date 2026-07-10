# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""CLI wrappers over the shared fact layer + the MCP server launcher.

These commands delegate to ``treasure_map.lib.facts`` — the SAME read layer the MCP server uses
— so a fact fetched on the command line and the same fact fetched over MCP are identical by
construction (the CLI and MCP are two thin wrappers over one query, never two implementations).
"""

from __future__ import annotations

import json

import click

from treasure_map.lib import facts


def _emit(record: dict[str, object]) -> None:
    click.echo(json.dumps(record, indent=2, sort_keys=True))


@click.group(name="fact")
def fact() -> None:
    """Read structured facts from an analysis database (the layer MCP also serves)."""


@fact.command(name="pseudocode")
@click.argument("function")
@click.option("--binary", default=None, help="Scope to one binary (disambiguates a shared name).")
@click.option("--analysis-db", default="analysis.db", help="Path to the analysis database.")
def pseudocode(function: str, binary: str | None, analysis_db: str) -> None:
    """Print the decompiler pseudocode for FUNCTION (name or address)."""
    conn = facts.open_analysis_ro(analysis_db)
    try:
        _emit(facts.get_pseudocode(conn, func=function, binary=binary))
    finally:
        conn.close()


@fact.command(name="callees")
@click.argument("function")
@click.option("--binary", default=None, help="Scope to one binary.")
@click.option("--analysis-db", default="analysis.db", help="Path to the analysis database.")
def callees(function: str, binary: str | None, analysis_db: str) -> None:
    """Print the direct callees of FUNCTION (intra-binary edges flagged resolved)."""
    conn = facts.open_analysis_ro(analysis_db)
    try:
        _emit(facts.get_callees(conn, func=function, binary=binary))
    finally:
        conn.close()


@fact.command(name="xrefs")
@click.argument("function")
@click.option(
    "--direction",
    type=click.Choice(["callers", "callees"]),
    default="callers",
    help="callers = who references this function; callees = what it references.",
)
@click.option("--binary", default=None, help="Scope to one binary.")
@click.option("--analysis-db", default="analysis.db", help="Path to the analysis database.")
def xrefs(function: str, direction: str, binary: str | None, analysis_db: str) -> None:
    """Print the cross-reference edges for FUNCTION."""
    d: facts.XrefDirection = "callees" if direction == "callees" else "callers"
    conn = facts.open_analysis_ro(analysis_db)
    try:
        _emit(facts.get_xrefs(conn, func=function, direction=d, binary=binary))
    finally:
        conn.close()


@fact.command(name="script-callsites")
@click.argument("binary")
@click.option("--analysis-db", default="analysis.db", help="Path to the analysis database.")
def script_callsites(binary: str, analysis_db: str) -> None:
    """Print the rootfs scripts that invoke BINARY (entry-reach evidence)."""
    conn = facts.open_analysis_ro(analysis_db)
    try:
        _emit(facts.get_script_callsites(conn, binary=binary))
    finally:
        conn.close()


def _resolve_mcp_target(
    atlas_db: str | None, workspaces_root: str | None
) -> tuple[str, str | None]:
    """Resolve (atlas_db, workspaces_root) from explicit args, the last-run pointer, and config.

    The server binds the ATLAS, not one firmware — a fact tool routes run_id -> analysis.db through
    the atlas ``run`` table (there is no single bound analysis.db, and no ambient 'current run').
    Explicit ``--atlas`` wins; else the last-run pointer's atlas; else the configured atlas.db.
    ``workspaces_root`` (an OPTIONAL fallback resolver, ``<root>/<run_id>/analysis.db``) is
    ``--workspaces-root``, else the configured workspace directory."""
    from treasure_map.lib.config.config import load_config
    from treasure_map.lib.last_run import read_last_run

    cfg = load_config(None)
    atlas = atlas_db
    if atlas is None:
        ptr = read_last_run()
        atlas = str(ptr.atlas_db) if ptr is not None else str(cfg.atlas.db_path)
    ws = workspaces_root if workspaces_root is not None else str(cfg.workspace_dir)
    return atlas, ws


@click.command(name="mcp")
@click.option(
    "--atlas",
    "atlas_db",
    default=None,
    help="Atlas DB path (default: the last run's atlas, else the configured atlas.db).",
)
@click.option(
    "--workspaces-root",
    default=None,
    help="Fallback root for resolving run_id -> <root>/<run_id>/analysis.db "
    "(default: the configured workspace directory). The atlas run table is the authority.",
)
def mcp_serve(atlas_db: str | None, workspaces_root: str | None) -> None:
    """Run the Treasure Map MCP server over stdio (exposes the fact substrate to an AI client).

    Binds the ATLAS (not one firmware): a fact tool routes run_id -> analysis.db through the atlas
    run table, so one server serves every scanned firmware. No firmware is preselected. Launch this
    from an MCP client, not by hand — it speaks JSON-RPC on stdin/stdout.
    """
    atlas_db, workspaces_root = _resolve_mcp_target(atlas_db, workspaces_root)
    # `mcp` is a core dependency, so build_server is imported like any other module. A missing
    # `mcp` here means a corrupted install, not an unselected extra — let it surface as a normal
    # ImportError (the same as a missing click/pyelftools), never a "go install the extra" hint.
    from treasure_map.mcp_app import build_server

    server = build_server(atlas_db, workspaces_root=workspaces_root)
    # Tell a human who ran this by hand what is happening — on stderr, so stdout stays clean
    # JSON-RPC for the client.
    click.echo(
        "treasure-map MCP server (stdio). Binds the atlas; fact tools route by run_id (see "
        f"list_runs). Launch from an MCP client, e.g.:  claude mcp add treasure-map -- tmap mcp "
        f"--atlas {atlas_db}   — now waiting for JSON-RPC on stdin (Ctrl-C to exit).",
        err=True,
    )
    server.run()
