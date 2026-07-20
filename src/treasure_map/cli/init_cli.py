# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""CLI wrapper for tmap init — thin Click layer; logic lives in lib/setup/initializer.py."""

from __future__ import annotations

import click

from treasure_map.lib.errors import TreasureMapError
from treasure_map.lib.setup.initializer import run_init


@click.command("init", short_help="Initialize tmap (run this first)")
@click.option("--force", is_flag=True, default=False, help="Overwrite existing config.yaml.")
@click.option(
    "--non-interactive",
    "non_interactive",
    is_flag=True,
    default=False,
    help="Skip prompts; write .env with no keys.",
)
@click.option(
    "--check-only",
    "check_only",
    is_flag=True,
    default=False,
    help="Run preflight checks only; write nothing.",
)
def init(force: bool, non_interactive: bool, check_only: bool) -> None:
    """Set up ~/.treasure-map/ with config, secrets, and preflight checks."""

    def _prompt_fn(msg: str) -> str:
        return str(click.prompt(msg, default="", show_default=False))

    try:
        result = run_init(
            force=force,
            non_interactive=non_interactive,
            check_only=check_only,
            prompt=_prompt_fn,
            echo=click.echo,
        )
    except FileExistsError as exc:
        raise click.ClickException(str(exc)) from exc
    except TreasureMapError as exc:
        raise click.ClickException(f"{type(exc).__name__}: {exc}") from exc

    if not check_only:
        click.echo(f"  Config : {result.config_path}")
        click.echo(f"  Secrets: {result.env_path}")
        click.echo(f"  Atlas  : {result.atlas_dir}")
        click.echo("")

    click.echo("Preflight checks:")
    any_red = False
    for name, ok, detail in result.checks:
        icon = "✅" if ok else "❌"
        click.echo(f"  {icon} {name}: {detail}")
        if not ok:
            any_red = True

    if check_only and any_red:
        raise SystemExit(1)
