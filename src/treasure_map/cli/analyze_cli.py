# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""CLI wrapper for the analyze capability.

Thin Click wrapper only — all logic lives in lib/analyze/pipeline.py.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from pathlib import Path
from typing import Any

import click

logger = logging.getLogger(__name__)


@click.command("analyze")
@click.argument("fs_root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--workspace",
    "-w",
    type=click.Path(path_type=Path),
    default=None,
    help="Workspace directory (created if absent). Defaults to ~/.treasure-map/workspaces/<auto>.",
)
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to config.yaml (overrides ~/.treasure-map/config.yaml).",
)
@click.option("--max-cost", type=float, default=None, help="Override max_cost_per_run_usd.")
def analyze(
    fs_root: Path, workspace: Path | None, config: Path | None, max_cost: float | None
) -> None:
    """Analyze an extracted firmware filesystem root.

    Produces an analysis.db in the workspace directory.
    Resume-safe: re-running with the same --workspace skips completed steps.
    """
    from treasure_map.lib.analyze.pipeline import run_analyze
    from treasure_map.lib.config.config import load_config
    from treasure_map.lib.errors import GhidraNotFoundError
    from treasure_map.lib.workspace.workspace import Workspace

    cfg = load_config(config)
    # max_cost will wire into LLM cost guard in Week 3 (no LLM calls yet)

    if workspace is None:
        ws_name = f"analyze_{fs_root.name}_{uuid.uuid4().hex[:8]}"
        workspace = cfg.workspace_dir / ws_name

    def _progress(step: str, meta: dict[str, Any]) -> None:
        click.echo(f"  [{step}] {meta}")

    click.echo(f"Workspace: {workspace}")

    try:
        with Workspace(workspace, progress_callback=_progress) as ws:
            result = asyncio.run(run_analyze(fs_root, ws, cfg, _progress))
    except GhidraNotFoundError as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(f"\nDone in {result.elapsed:.1f}s")
    click.echo(f"  Binaries : {result.binary_count}")
    click.echo(f"  Ghidra OK: {result.ghidra_ok}")
    click.echo(f"  Ghidra ✗ : {result.ghidra_failed}")
    click.echo(f"  DB       : {result.db_path}")
