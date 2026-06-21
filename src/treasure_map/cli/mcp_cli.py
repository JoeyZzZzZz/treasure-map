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


@click.command(name="mcp-serve")
@click.option("--analysis-db", default="analysis.db", help="Path to the analysis database.")
@click.option("--atlas", "atlas_db", default="atlas.db", help="Path to the atlas database.")
def mcp_serve(analysis_db: str, atlas_db: str) -> None:
    """Run the Treasure Map MCP server over stdio (exposes the fact substrate to an AI client)."""
    from treasure_map.mcp_app import build_server

    build_server(analysis_db, atlas_db).run()
