# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""CLI wrappers for the analyzers (A1 diff-driven, A2 pattern-driven) and atlas views.

Thin Click wrappers only — all logic lives in lib/hunt/ and lib/query/. A small set of
top-level commands; not a file-per-analyzer.
"""

from __future__ import annotations

import logging
from pathlib import Path

import click

logger = logging.getLogger(__name__)


@click.command("hunt-diff", short_help="Diff two analysis.db builds; grade reachability.")
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


@click.command("hunt-pattern", short_help="Find call-sequence shape candidates in a build.")
@click.argument("db", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--run-id", required=True, help="Neutral per-run id (the recurrence unit).")
@click.option(
    "--device-category",
    default=None,
    help="Optional GENERIC category (router/camera/nas) — never a vendor/model name.",
)
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
def hunt_pattern(
    db: Path,
    run_id: str,
    device_category: str | None,
    config: Path | None,
    atlas_path: Path | None,
) -> None:
    """Scan one analysis.db for call-sequence shape candidates and write atlas instances.

    Hermetic (no LLM / no key needed). OSS is excluded at scan time. Writes graded leads at
    provenance L0/L1 only; every instance is a candidate/lead, not a confirmed result.
    """
    from treasure_map.lib.config.config import load_config
    from treasure_map.lib.hunt import run_analyzer2

    cfg = load_config(config)
    resolved_atlas = atlas_path if atlas_path is not None else cfg.atlas.db_path
    stats = run_analyzer2(db, resolved_atlas, source_run_id=run_id, device_category=device_category)

    click.echo(f"Atlas: {resolved_atlas}")
    click.echo(f"  Functions scanned : {stats.scanned}")
    click.echo(f"  Shape candidates  : {stats.matches}")
    click.echo(f"  Instances written : {stats.instances_written}")
    click.echo(f"  OSS binaries excluded : {stats.oss_excluded}")
    click.echo(
        "  By reachability   : "
        f"confirmed={stats.by_status.get('confirmed', 0)}, "
        f"blocked={stats.by_status.get('blocked', 0)}, "
        f"unknown={stats.by_status.get('unknown', 0)}"
    )
    click.echo(
        "Note: every instance is a candidate/lead, not a confirmed result. With one firmware "
        "the recurrence stays ~1 — cross-device recurrence needs more devices (future)."
    )


@click.command("atlas-view", short_help="Neutral cross-firmware atlas aggregation views.")
@click.argument("view", type=click.Choice(["dormant", "density", "twins"]))
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
def atlas_view(view: str, config: Path | None, atlas_path: Path | None) -> None:
    """Print a neutral atlas aggregation view. Every row is a lead/candidate, not a result."""
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.config.config import load_config
    from treasure_map.lib.query import density, dormant, twins

    cfg = load_config(config)
    resolved_atlas = atlas_path if atlas_path is not None else cfg.atlas.db_path
    conn = open_atlas(resolved_atlas)
    try:
        if view == "dormant":
            rows = dormant(conn)
            click.echo(f"dormant candidates (blocked, L0/L1): {len(rows)}")
            for r in rows:
                click.echo(
                    f"  instance {r['instance_id']} pattern {r['pattern_id']} "
                    f"| {r['reachability_status']} {r['provenance_level']} "
                    f"| mechanism: {r['blocking_mechanism']}"
                )
        elif view == "density":
            drows = density(conn)
            click.echo(f"density (count per run / sink_class / fingerprint): {len(drows)}")
            for d in drows:
                click.echo(
                    f"  run={d.source_run_id} sink_class={d.sink_class} "
                    f"fp={d.structural_fingerprint} count={d.instance_count}"
                )
        else:  # twins
            trows = twins(conn)
            click.echo(f"twins (same shape, mixed reachability status): {len(trows)}")
            for t in trows:
                click.echo(
                    f"  fp={t.structural_fingerprint} sink_class={t.sink_class} "
                    f"blocked={t.blocked_count} non_blocked={t.non_blocked_count}"
                )
    finally:
        conn.close()
    click.echo("Note: rows are leads/candidates, not findings; interpretation is out of scope.")
