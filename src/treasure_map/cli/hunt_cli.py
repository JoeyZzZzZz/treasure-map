# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""CLI wrapper for the diff-driven analyzer (A1).

Thin Click wrapper only — all logic lives in lib/hunt/analyzer1.py. One top-level
analysis command; not a file-per-analyzer.
"""

from __future__ import annotations

import logging
from pathlib import Path

import click

logger = logging.getLogger(__name__)


@click.command("hunt-diff")
@click.argument("db_a", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("db_b", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--axis",
    type=click.Choice(["version", "mod", "sibling"]),
    default="version",
    help="Neutral comparison axis recorded as scope_origin (no vendor/version identity).",
)
@click.option("--run-id-a", required=True, help="Neutral run id for the baseline (db_a).")
@click.option("--run-id-b", required=True, help="Neutral run id for the comparison (db_b).")
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to config.yaml (overrides ~/.treasure-map/config.yaml).",
)
@click.option(
    "--atlas",
    "atlas_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Atlas DB path (defaults to the configured atlas.db_path).",
)
def hunt_diff(
    db_a: Path,
    db_b: Path,
    axis: str,
    run_id_a: str,
    run_id_b: str,
    config: Path | None,
    atlas_path: Path | None,
) -> None:
    """Diff two analysis databases, grade reachability, and write neutral atlas instances.

    Writes graded leads at provenance L0/L1 only. public_finding is expected to be EMPTY
    in M2 (no external L2+ anchor) — that is the path-required discipline, not a failure.
    """
    from treasure_map.lib.config.config import load_config
    from treasure_map.lib.errors import TreasureMapError
    from treasure_map.lib.hunt import run_analyzer1
    from treasure_map.lib.llm.factory import build_router
    from treasure_map.lib.llm.types import Tier

    cfg = load_config(config)
    if cfg.llm is None:
        raise click.ClickException("LLM not configured: hunt-diff needs an M-tier and L-tier key.")

    resolved_atlas = atlas_path if atlas_path is not None else cfg.atlas.db_path
    ledger_path = resolved_atlas.parent / "cost_ledger.json"

    try:
        router = build_router(cfg.llm, ledger_path, tiers=[Tier.M, Tier.L])
        stats = run_analyzer1(
            db_a,
            db_b,
            axis,  # type: ignore[arg-type]  # Click constrains to the Axis literals
            resolved_atlas,
            router,
            run_id_a=run_id_a,
            run_id_b=run_id_b,
        )
    except TreasureMapError as exc:
        raise click.ClickException(f"{type(exc).__name__}: {exc}") from exc

    click.echo(f"Atlas: {resolved_atlas}")
    click.echo(f"  Change leads      : {stats.leads}")
    click.echo(f"  Instances written : {stats.instances_written}")
    click.echo(
        "  By reachability   : "
        f"confirmed={stats.by_status.get('confirmed', 0)}, "
        f"blocked={stats.by_status.get('blocked', 0)}, "
        f"unknown={stats.by_status.get('unknown', 0)}"
    )
    click.echo(f"  public_finding    : {stats.public_findings}")
    click.echo(
        "Note: public_finding is expected to be empty in M2 — A1 writes L0/L1 only "
        "(no external anchor), so a confirmed result at L2 or above cannot arise here."
    )
