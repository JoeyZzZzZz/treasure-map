# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""CLI wrapper for the analyze capability.

Actual analysis logic lives in lib/analyze/pipeline.py.
This file is a thin Click wrapper only.
"""
from __future__ import annotations

import logging
from pathlib import Path

import click

logger = logging.getLogger(__name__)


@click.command("analyze")
@click.argument("fs_root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--workspace", "-w",
    type=click.Path(path_type=Path),
    default=None,
    help="Workspace directory (created if absent). Defaults to ~/.treasure-map/workspaces/<auto>.",
)
@click.option(
    "--config", "-c",
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
    """
    from treasure_map.lib.config.config import load_config

    cfg = load_config(config)
    logger.info("Starting analysis: fs_root=%s", fs_root)

    # Workspace setup
    if workspace is None:
        import uuid
        ws_name = f"analyze_{fs_root.name}_{uuid.uuid4().hex[:8]}"
        workspace = (cfg.workspace_dir / ws_name)

    from treasure_map.lib.workspace.workspace import Workspace

    def _progress(step: str, meta: dict) -> None:
        click.echo(f"  [{step}] {meta}")

    with Workspace(workspace, progress_callback=_progress):
        click.echo(f"Workspace: {workspace}")
        # Analyze pipeline will be wired in Week 2 (lib/analyze/pipeline.py)
        click.echo("analyze pipeline: not yet implemented (Week 2)")
