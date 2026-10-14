# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""CLI wrapper for tmap doctor — the same checks as ``tmap init --check-only``."""

from __future__ import annotations

import click

from treasure_map.cli.init_cli import _prompt_fn, _run, render_checks, runs_currency


@click.command("doctor", short_help="Check the toolchain, config and agents (writes nothing)")
def doctor() -> None:
    """Same as ``tmap init --check-only``: every check, nothing written. Exits 1 when any check
    is missing, wrong or unknown."""
    result = _run(check_only=True, prompt=_prompt_fn, echo=click.echo, runs_probe=runs_currency)
    if render_checks(result):
        raise SystemExit(1)
