# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""CLI wrapper for tmap update — thin Click layer; logic lives in lib/setup/update.py."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click


@click.command("update", short_help="Update tmap to the newest version and remove the old one")
@click.option("--check", is_flag=True, help="Only say whether a newer version exists.")
@click.option("--yes", "-y", "assume_yes", is_flag=True, help="Do not ask to confirm the plan.")
def update(check: bool, assume_yes: bool) -> None:
    """Install the newest tmap, remove the old tmap, then run the new version's ``tmap init``.

    Works on a tmap installed with ``uv tool install tmap-agents`` (the one-line installer does
    that). Another kind of install is told how to update itself and left as it is. Exits 1 when
    the newest version cannot be learned (``--check`` included)."""
    from treasure_map.lib.setup import update as up
    from treasure_map.lib.setup.clients import tmap_executable
    from treasure_map.lib.setup.discover import current_host
    from treasure_map.lib.setup.platform import detect_platform
    from treasure_map.version import __version__

    host = current_host(detect_platform())
    try:
        latest: str | None = up.fetch_latest_version()
    except Exception as exc:  # network, proxy, PyPI answer
        if getattr(exc, "code", None) == 404:
            click.echo(f"{up.DIST} is not published on PyPI yet", err=True)
        else:
            click.echo(f"could not reach PyPI: {exc}", err=True)
        latest = None
    plan = up.plan_update(
        current=__version__,
        latest=latest,
        prefix=Path(sys.prefix),
        home=Path.home(),
        path_env=os.environ.get("PATH", ""),
        which=host.which,
        run=host.run,
        tmap_command=tmap_executable(),
    )
    click.echo("Update plan:")
    for line in up.plan_lines(plan):
        click.echo(f"  {line}")
    if latest is None:
        # The newest version could not be learned: no answer to give, --check included.
        if not plan.from_uv_tool:
            click.echo(up.manual_update_hint())
        raise SystemExit(1)
    if not plan.from_uv_tool:
        click.echo(up.manual_update_hint())
        return
    if check:
        return
    if not plan.has_work:
        click.echo("tmap is up to date.")
        return
    if not assume_yes and not click.confirm("Proceed?", default=True):
        click.echo("Nothing changed.")
        return

    target = plan.latest if plan.newer and plan.latest is not None else plan.current
    ok, why = up.run_steps([plan.install_argv(target)], host.run)
    if not ok:
        click.echo(f"✗ {why}", err=True)
        back_ok, _ = up.run_steps([plan.install_argv(plan.current)], host.run)
        click.echo(
            f"tmap {plan.current} was "
            + ("put back." if back_ok else "NOT put back: run the install command above by hand."),
            err=True,
        )
        raise SystemExit(1)
    click.echo(f"✓ tmap {target} installed")
    for p in plan.shadowing:
        click.echo(f"note: {p} is another tmap on PATH and may run instead of the new one")
    tmap = tmap_executable()
    if tmap is None:
        click.echo("next: tmap init")
        return
    sys.stdout.flush()
    sys.stderr.flush()
    # Hand over to the NEW program: nothing of the old one runs past this point.
    os.execvp(str(tmap), [str(tmap), "init"])
