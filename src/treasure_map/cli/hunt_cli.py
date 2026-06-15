# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""CLI wrappers for the analyzers (A1 diff-driven, A2 pattern-driven) and atlas views.

Thin Click wrappers only — all logic lives in lib/hunt/ and lib/query/. A small set of
top-level commands; not a file-per-analyzer.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

import click

if TYPE_CHECKING:
    from treasure_map.lib.query import TriageCandidate

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
@click.option("--run-id", required=True, help="Neutral per-run id (the device_spread unit).")
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
        "device_spread stays ~1 — cross-device spread needs more devices (future)."
    )


_SECTION_ORDER = ("to-verify", "reachable", "gated")
_SECTION_HEADER = {
    "to-verify": "TO-VERIFY  (ranked — start reverse-engineering from the top)",
    "reachable": "REACHABLE  (already path-confirmed within one function — verify by hand)",
    "gated": "GATED  (a filter/guard was identified — likely dormant/false)",
}


def _render_triage(
    candidates: list[TriageCandidate],
    *,
    run_label: str,
    top_n: int,
    status: str | None,
    include_gated: bool,
    as_json: bool,
) -> None:
    """Render a ranked triage candidate list. Shared by `tmap triage` and `tmap scan` so the
    two emit byte-identical output (single source of truth, no drift)."""
    import json

    counts = {"reachable": 0, "to-verify": 0, "gated": 0}
    for c in candidates:
        counts[c.review_status] = counts.get(c.review_status, 0) + 1

    # Decide which review statuses to display.
    if status == "all":
        shown_statuses = set(_SECTION_ORDER)
    elif status is not None:
        shown_statuses = {status}
    else:
        shown_statuses = {"to-verify", "reachable"}
        if include_gated:
            shown_statuses.add("gated")

    visible = [c for c in candidates if c.review_status in shown_statuses][:top_n]

    if as_json:
        click.echo(
            json.dumps(
                [
                    {
                        "score": c.score,
                        "review_status": c.review_status,
                        "reachability_status": c.reachability_status,
                        "function": c.function,
                        "source_class": c.source_class,
                        "sink_class": c.sink_class,
                        "sink_anchor": c.sink_anchor,
                        "blocking_mechanism": c.blocking_mechanism,
                        "origin": c.origin,
                        "source_run_id": c.source_run_id,
                        "evidence_ref": c.evidence_ref,
                    }
                    for c in visible
                ],
                indent=2,
            )
        )
        return

    click.echo(
        f"triage: {run_label}   ({len(candidates)} candidates: "
        f"{counts['reachable']} reachable, {counts['to-verify']} to-verify, "
        f"{counts['gated']} gated)"
    )
    rank = 0
    for section in _SECTION_ORDER:
        if section not in shown_statuses:
            continue
        rows = [c for c in visible if c.review_status == section]
        if not rows:
            continue
        click.echo(f"\n  {_SECTION_HEADER[section]}")
        click.echo("  #   score  status      function (evidence_ref)        source->sink   filter")
        for c in rows:
            rank += 1
            fltr = c.blocking_mechanism if c.blocking_mechanism else "none"
            click.echo(
                f"  {rank:<3} {c.score:<5.2f}  {c.review_status:<10}  "
                f"{c.function or '?'} ({c.evidence_ref or '?'})   "
                f"{c.source_class} -> {c.sink_anchor or '?'}   {fltr}"
            )
    if "gated" not in shown_statuses and counts["gated"]:
        click.echo(f"\n  (gated: {counts['gated']} hidden; --include-gated to show)")
    click.echo(
        "\nNote: candidates are leads for manual review, ranked by how much they warrant "
        "reverse-engineering — NOT confirmed results."
    )


@click.command("triage", short_help="Rank to-verify candidates for manual reverse-engineering.")
@click.argument("run_id", required=False, default=None)
@click.option("--run", "run_opt", default=None, help="Restrict to one run id (overrides RUN_ID).")
@click.option("--top", "top_n", type=int, default=20, help="Show at most N candidates.")
@click.option(
    "--status",
    type=click.Choice(["to-verify", "reachable", "gated", "all"]),
    default=None,
    help="Show only this review status. Default shows to-verify + reachable (gated folded).",
)
@click.option(
    "--include-gated",
    is_flag=True,
    default=False,
    help="Also show gated candidates (folded by default — they are likely dormant/false).",
)
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit structured JSON.")
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
def triage(
    run_id: str | None,
    run_opt: str | None,
    top_n: int,
    status: str | None,
    include_gated: bool,
    as_json: bool,
    config: Path | None,
    atlas_path: Path | None,
) -> None:
    """Rank atlas candidates by how much they warrant manual reverse-engineering.

    Read-only: nothing is written back to the atlas and no field is altered. Each row carries
    its evidence_ref ({run_id}#fn{func_id}) — the anchor to jump back to analysis.db / Ghidra.
    Candidates are leads for manual review, NOT confirmed results.
    """
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.config.config import load_config
    from treasure_map.lib.query import triage as run_triage

    selected_run = run_opt if run_opt is not None else run_id
    cfg = load_config(config)
    resolved_atlas = atlas_path if atlas_path is not None else cfg.atlas.db_path
    conn = open_atlas(resolved_atlas)
    try:
        candidates = run_triage(conn, run_id=selected_run)
    finally:
        conn.close()

    _render_triage(
        candidates,
        run_label=selected_run if selected_run is not None else "all runs",
        top_n=top_n,
        status=status,
        include_gated=include_gated,
        as_json=as_json,
    )


@click.command("atlas-view", short_help="Neutral cross-firmware atlas aggregation views.")
@click.argument("view", type=click.Choice(["dormant", "density", "twins", "ledger"]))
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
    from treasure_map.lib.query import density, dormant, ledger, twins

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
        elif view == "twins":
            trows = twins(conn)
            click.echo(f"twins (same shape, mixed reachability status): {len(trows)}")
            for t in trows:
                click.echo(
                    f"  fp={t.structural_fingerprint} sink_class={t.sink_class} "
                    f"blocked={t.blocked_count} non_blocked={t.non_blocked_count}"
                )
        else:  # ledger
            lrows = ledger(conn)
            click.echo(f"pattern ledger (device_spread vs pattern_breadth): {len(lrows)} patterns")
            for lr in lrows:
                click.echo(
                    f"  pattern {lr.pattern_id} sink_class={lr.sink_class} "
                    f"fp={lr.structural_fingerprint} "
                    f"device_spread={lr.device_spread} pattern_breadth={lr.pattern_breadth} "
                    f"algo={lr.fine_fp_algo_version}"
                )
    finally:
        conn.close()
    click.echo("Note: rows are leads/candidates, not findings; interpretation is out of scope.")


@click.command("scan", short_help="One command: analyze -> hunt -> triage, ending in a list.")
@click.argument("fs_root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--workspace",
    "-w",
    type=str,
    default=None,
    help="Workspace as a NAME (managed under your base) or a PATH (verbatim). Omitted: auto name.",
)
@click.option(
    "--run-id",
    "run_id",
    default=None,
    help="Neutral per-run id written to the atlas. Defaults to the workspace name.",
)
@click.option(
    "--device-category",
    default=None,
    help="Optional GENERIC category (router/camera/nas) — never a vendor/model name.",
)
@click.option("--top", "top_n", type=int, default=20, help="Show at most N candidates.")
@click.option(
    "--status",
    type=click.Choice(["to-verify", "reachable", "gated", "all"]),
    default=None,
    help="Show only this review status. Default shows to-verify + reachable (gated folded).",
)
@click.option(
    "--include-gated",
    is_flag=True,
    default=False,
    help="Also show gated candidates (folded by default — they are likely dormant/false).",
)
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit triage list as JSON.")
@click.option(
    "--skip-non-binary",
    is_flag=True,
    default=False,
    help="Skip the non-binary file analysis stage entirely.",
)
@click.option(
    "--skip-ingester",
    "skip_ingesters",
    multiple=True,
    help="Skip a specific ingester by kind (e.g. shell_script). Repeatable.",
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
def scan(
    fs_root: Path,
    workspace: str | None,
    run_id: str | None,
    device_category: str | None,
    top_n: int,
    status: str | None,
    include_gated: bool,
    as_json: bool,
    skip_non_binary: bool,
    skip_ingesters: tuple[str, ...],
    config: Path | None,
    atlas_path: Path | None,
) -> None:
    """Run the whole main path on one extracted firmware: analyze -> hunt -> triage.

    Ends by printing the same ranked, evidence_ref-anchored triage list as `tmap triage`. The
    three sub-commands stay independent for re-running a single step; this is the one-shot path.
    Slow stage is analyze (one Ghidra JVM per binary) — progress is shown per stage.
    """
    import asyncio
    from typing import Any

    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.config.config import load_config
    from treasure_map.lib.errors import GhidraNotFoundError, TreasureMapError
    from treasure_map.lib.hunt import run_analyzer2
    from treasure_map.lib.query import triage as run_triage
    from treasure_map.lib.workspace.resolver import resolve_workspace
    from treasure_map.lib.workspace.workspace import Workspace

    cfg = load_config(config)
    try:
        resolved = resolve_workspace(workspace, workspace_dir=cfg.workspace_dir, fs_root=fs_root)
    except TreasureMapError as exc:
        raise click.ClickException(str(exc)) from exc
    ws_path = resolved.path

    effective_run_id = run_id if run_id is not None else ws_path.name
    resolved_atlas = atlas_path if atlas_path is not None else cfg.atlas.db_path

    def _progress(step: str, meta: dict[str, Any]) -> None:
        click.echo(f"  [{step}] {meta}")

    click.echo(
        f"note: re-scanning run-id '{effective_run_id}' appends to atlas; "
        "use a fresh run-id per device+version"
    )

    # [1/3] analyze — reuse the analyze command's resolve_workspace + Workspace + asyncio.run path.
    click.echo("\n[1/3] analyzing firmware (Ghidra) …")
    from treasure_map.lib.analyze.pipeline import run_analyze

    try:
        with Workspace(ws_path, progress_callback=_progress) as ws:
            result = asyncio.run(
                run_analyze(
                    fs_root,
                    ws,
                    cfg,
                    _progress,
                    skip_non_binary=skip_non_binary,
                    skip_ingesters=frozenset(skip_ingesters),
                )
            )
    except KeyboardInterrupt:
        click.echo("\nAborted by user — all Ghidra processes terminated.", err=True)
        raise SystemExit(130) from None
    except GhidraNotFoundError as exc:
        raise click.ClickException(str(exc)) from exc
    except TreasureMapError as exc:
        raise click.ClickException(f"{type(exc).__name__}: {exc}") from exc
    click.echo(
        f"      → analysis.db: {result.binary_count} binaries, "
        f"{result.functions_ingested} functions"
    )

    # [2/3] hunt call-sequence shapes -> atlas.
    click.echo(f"\n[2/3] hunting call-sequence shapes → atlas (run-id={effective_run_id}) …")
    try:
        h = run_analyzer2(
            result.db_path,
            resolved_atlas,
            source_run_id=effective_run_id,
            device_category=device_category,
        )
    except TreasureMapError as exc:
        raise click.ClickException(f"{type(exc).__name__}: {exc}") from exc
    click.echo(
        f"      → {h.instances_written} candidates written "
        f"(confirmed={h.by_status.get('confirmed', 0)}, "
        f"blocked={h.by_status.get('blocked', 0)}, "
        f"unknown={h.by_status.get('unknown', 0)})"
    )

    # [3/3] triage — the readable, ranked candidate list (same renderer as `tmap triage`).
    click.echo("\n[3/3] triage — ranked candidates for manual review:\n")
    conn = open_atlas(resolved_atlas)
    try:
        candidates = run_triage(conn, run_id=effective_run_id)
    finally:
        conn.close()
    _render_triage(
        candidates,
        run_label=effective_run_id,
        top_n=top_n,
        status=status,
        include_gated=include_gated,
        as_json=as_json,
    )
