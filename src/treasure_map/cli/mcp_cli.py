# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""CLI wrappers over the shared fact layer + the MCP server launcher.

These commands delegate to ``treasure_map.lib.facts`` — the SAME read layer the MCP server uses
— so a fact fetched on the command line and the same fact fetched over MCP are identical by
construction (the CLI and MCP are two thin wrappers over one query, never two implementations).
"""

from __future__ import annotations

import json
from pathlib import Path

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
    analysis_db: str | None, atlas_db: str | None
) -> tuple[str, str, str | None]:
    """Resolve (analysis_db, atlas_db, run_id) from explicit args or the last-run pointer.

    Explicit paths always win. When either is omitted, the pointer a prior `tmap scan` recorded
    fills it in (the common "I just scanned, now serve it" case). The run id is bound only when
    the resolved analysis.db matches the recorded run, so list_candidates isolates to the right
    firmware. A missing pointer with no explicit path is a friendly error, not a traceback."""
    from treasure_map.lib.last_run import read_last_run

    ptr = read_last_run()
    if (analysis_db is None or atlas_db is None) and ptr is None:
        raise click.ClickException(
            "no --analysis-db given and no recorded run found. Run `tmap scan <firmware>` first, "
            "or pass --analysis-db <path> --atlas <path>."
        )
    a = analysis_db or (str(ptr.analysis_db) if ptr else None)
    x = atlas_db or (str(ptr.atlas_db) if ptr else None)
    assert a is not None and x is not None  # guaranteed by the check above
    bound = ptr is not None and Path(a).resolve() == ptr.analysis_db.resolve()
    run_id = ptr.run_id if bound and ptr is not None else None
    return a, x, run_id


@click.command(name="mcp")
@click.option(
    "--analysis-db",
    default=None,
    help="Path to the analysis database (default: the last `tmap scan`'s analysis.db).",
)
@click.option(
    "--atlas",
    "atlas_db",
    default=None,
    help="Path to the atlas database (default: the last run's atlas).",
)
def mcp_serve(analysis_db: str | None, atlas_db: str | None) -> None:
    """Run the Treasure Map MCP server over stdio (exposes the fact substrate to an AI client).

    With no paths, serves the last `tmap scan`'s databases (recorded pointer). Launch this from an
    MCP client, not by hand — it speaks JSON-RPC on stdin/stdout.
    """
    import sys

    analysis_db, atlas_db, run_id = _resolve_mcp_target(analysis_db, atlas_db)
    try:
        from treasure_map.mcp_app import build_server

        server = build_server(analysis_db, atlas_db, run_id)
    except ModuleNotFoundError as exc:
        # The `mcp` SDK is an optional extra; missing it should be a one-liner, not a traceback.
        if exc.name and exc.name.split(".")[0] == "mcp":
            click.echo(
                "MCP support isn't installed. Install it with:  "
                "uv tool install treasure-map --with mcp   "
                '(or, with pip:  pip install "treasure-map[mcp]")',
                err=True,
            )
            sys.exit(2)
        raise
    # Tell a human who ran this by hand what is happening — on stderr, so stdout stays clean
    # JSON-RPC for the client.
    click.echo(
        "treasure-map MCP server (stdio). Launch this from an MCP client, e.g.:  "
        f"claude mcp add treasure-map -- tmap mcp --analysis-db {analysis_db} --atlas {atlas_db}"
        "   — now waiting for JSON-RPC on stdin (Ctrl-C to exit).",
        err=True,
    )
    server.run()
