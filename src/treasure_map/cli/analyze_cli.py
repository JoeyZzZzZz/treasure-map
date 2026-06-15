# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""CLI wrapper for the analyze capability.

Thin Click wrapper only — all logic lives in lib/analyze/pipeline.py.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

import click

logger = logging.getLogger(__name__)

_ANALYZE_EPILOG = """\
Examples:

\b
  tmap analyze ./_fw.extracted -w router_v1          # managed name -> <base>/router_v1
  tmap analyze ./_fw.extracted -w /mnt/scratch/fw1   # literal path (large/scratch disk)
  tmap analyze ./_fw.extracted                       # auto name (re-run resumes)

Re-running with the same -w (same name or path) resumes from the last checkpoint.
"""


@click.command(
    "analyze",
    short_help="Analyze an extracted firmware filesystem.",
    epilog=_ANALYZE_EPILOG,
)
@click.argument("fs_root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--workspace",
    "-w",
    type=str,
    default=None,
    help=(
        "Workspace as a NAME (managed under your workspace base, e.g. -w router_v1) or a "
        "PATH (used verbatim if it has a '/', '~', leading '.', or is absolute, e.g. "
        "-w /mnt/scratch/fw1). Omitted: a deterministic auto name under the base. Re-run "
        "with the same value to resume."
    ),
)
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to config.yaml (overrides ~/.treasure-map/config.yaml).",
)
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
    "--summarize",
    is_flag=True,
    default=False,
    help=(
        "After analysis, fill functions.summary via the S-tier LLM. Opt-in; needs an "
        "S-tier key. Skips with a message (analysis still succeeds) if the key is absent."
    ),
)
@click.option(
    "--summary-limit",
    "summary_limit",
    type=int,
    default=None,
    help="Limit summarization to N functions (use for prompt calibration).",
)
def analyze(
    fs_root: Path,
    workspace: str | None,
    config: Path | None,
    skip_non_binary: bool,
    skip_ingesters: tuple[str, ...],
    summarize: bool,
    summary_limit: int | None,
) -> None:
    """Analyze an extracted firmware filesystem root.

    Produces an analysis.db in the workspace directory. -w/--workspace takes a NAME
    (managed under your workspace base) or a PATH (used verbatim); omitted, a deterministic
    auto name is derived from the firmware dir. Resume-safe: re-running with the same -w
    skips completed steps.
    """
    from treasure_map.lib.analyze.pipeline import run_analyze
    from treasure_map.lib.config.config import load_config
    from treasure_map.lib.errors import GhidraNotFoundError, TreasureMapError
    from treasure_map.lib.workspace.resolver import resolve_workspace
    from treasure_map.lib.workspace.workspace import Workspace

    cfg = load_config(config)

    try:
        resolved = resolve_workspace(workspace, workspace_dir=cfg.workspace_dir, fs_root=fs_root)
    except TreasureMapError as exc:
        raise click.ClickException(str(exc)) from exc
    ws_path = resolved.path

    def _progress(step: str, meta: dict[str, Any]) -> None:
        click.echo(f"  [{step}] {meta}")

    if resolved.kind == "path":
        click.echo(f"Workspace: {ws_path}  (explicit path)")
    elif resolved.kind == "auto":
        click.echo(f"Workspace: '{ws_path.name}'  (auto) → {ws_path}")
    else:
        click.echo(f"Workspace: '{workspace}' → {ws_path}")

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

    click.echo(f"\nDone in {result.elapsed:.1f}s")
    click.echo(f"  Binaries : {result.binary_count}")
    click.echo(f"  Dirty    : {result.dirty_count}")
    click.echo(f"  Ghidra OK: {result.ghidra_ok}")
    click.echo(f"  Failed   : {result.ghidra_failed}")
    click.echo(f"  Skipped  : {result.ghidra_skipped} (cache hit)")
    click.echo(f"  Functions ingested: {result.functions_ingested}")
    click.echo(f"  Imports   ingested: {result.imports_ingested}")
    click.echo(f"  Exports   ingested: {result.exports_ingested}")
    click.echo(f"  Strings   ingested: {result.strings_ingested}")
    click.echo(f"  Xrefs (L0 callees×exports): {result.layer0_xrefs}")
    click.echo(f"  Xrefs (L1 import×export):   {result.layer1_xrefs}")
    click.echo(f"  Xrefs (L2 dt_needed):       {result.layer2_xrefs}")
    click.echo(f"  Xrefs (L3 string_ipc):      {result.layer3_xrefs}")
    click.echo(f"  Strings classified: {result.strings_classified}")
    click.echo(f"  Total xrefs: {result.total_xrefs}")
    click.echo(f"  Non-binary files: {result.non_binary_files_ingested}")
    click.echo(f"  Script calls: {result.script_calls_ingested}")
    click.echo(f"  Config entries: {result.config_entries_ingested}")
    click.echo(f"  Credentials: {result.credentials_ingested}")
    click.echo(f"  Web endpoints: {result.web_endpoints_ingested}")
    click.echo(f"  DB       : {result.db_path}")

    if summarize:
        _summarize(cfg, ws_path, result.db_path, summary_limit)


def _summarize(cfg: Any, workspace: Path, db_path: Path, limit: int | None) -> None:
    """Opt-in post-step: fill functions.summary via the S-tier router.

    Never raises out of analyze — a missing/invalid S-tier key logs one message and
    returns. The key-less analyze path never reaches here (gated on --summarize).
    """
    from treasure_map.lib.analyze.summarize import summarize_functions
    from treasure_map.lib.errors import ConfigError
    from treasure_map.lib.llm.factory import build_router
    from treasure_map.lib.llm.types import Tier
    from treasure_map.lib.storage.connection import open_db

    if cfg.llm is None:
        click.echo("summary skipped: LLM not configured")
        return
    try:
        router = build_router(cfg.llm, workspace / "cost_ledger.json", tiers=[Tier.S])
    except ConfigError:
        click.echo("summary skipped: S-tier key not configured")
        return

    def _on_progress(done: int, total: int) -> None:
        # Generic counter only — never pseudocode/summary/firmware strings. Rewrites a
        # single stderr line so it does not interleave with the final summary block; the
        # \r is harmless when piped to a non-TTY log.
        click.echo(f"\r  summarizing functions: {done}/{total}", nl=False, err=True)

    conn = open_db(db_path)
    try:
        stats = asyncio.run(summarize_functions(conn, router, limit=limit, progress=_on_progress))
    finally:
        conn.close()
    click.echo("", err=True)  # finish the progress line with a newline

    click.echo(
        f"  Summaries: {stats.summarized} written, "
        f"{stats.skipped_no_pseudocode} skipped (no pseudocode), {stats.failed} failed"
    )
