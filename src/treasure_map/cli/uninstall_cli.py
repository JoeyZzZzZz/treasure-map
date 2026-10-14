# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""CLI wrapper for tmap uninstall — thin Click layer; logic lives in lib/setup/uninstall.py."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click


@click.command("uninstall", short_help="Remove what tmap init installed (keeps your data)")
@click.option("--purge-data", is_flag=True, help="Also delete the atlas and workspaces.")
@click.option("--yes", "-y", "assume_yes", is_flag=True, help="Do not ask to confirm the plan.")
@click.option("--dry-run", is_flag=True, help="Print the plan; change nothing.")
def uninstall(purge_data: bool, assume_yes: bool, dry_run: bool) -> None:
    """Remove tmap's agent registrations, the toolchain tmap downloaded, and — when it was
    installed with ``uv tool`` — the tmap program itself (the last step, after you confirm).

    Only what the install ledger records is removed — never a JDK, Ghidra or BinDiff you
    installed yourself. config.yaml, .env, the atlas and the workspaces stay unless
    --purge-data is given and you type the confirmation phrase (--yes does not stand in for it).
    """
    from treasure_map.lib.config.config import load_config
    from treasure_map.lib.errors import ConfigError
    from treasure_map.lib.setup import clients as cl
    from treasure_map.lib.setup import uninstall as un
    from treasure_map.lib.setup.discover import current_host
    from treasure_map.lib.setup.ledger import LEDGER_NAME, Ledger
    from treasure_map.lib.setup.platform import detect_platform

    home = Path.home()
    tm_home = home / ".treasure-map"
    host = current_host(detect_platform())
    chost = cl.ClientHost(
        home=home, environ=host.environ, platform=host.platform, which=host.which, run=host.run
    )
    tmap = cl.tmap_executable()
    try:
        cfg = load_config(None)
    except ConfigError as exc:
        click.echo(f"warning: {exc}; using default data locations", err=True)
        from treasure_map.lib.config.config import Config

        cfg = Config()
    try:
        ledger = Ledger.load(tm_home / "toolchain" / LEDGER_NAME)
    except ConfigError as exc:
        raise click.ClickException(str(exc)) from exc
    survey = cl.survey(chost, tmap)
    self_argv = un.uv_self_uninstall(Path(sys.prefix), home, host.which, host.run)
    click.echo("Uninstall plan:")
    for line in un.plan_lines(ledger, survey, toolchain_dir=tm_home / "toolchain", home=home):
        click.echo(f"  • {line}")
    if self_argv is not None:
        click.echo(f"  • last: remove the tmap program itself ({' '.join(self_argv[1:])})")
    data = un.data_paths(cfg.atlas.db_path, cfg.workspace_dir)
    if purge_data:
        click.echo("  • --purge-data: delete (after you type the phrase):")
        for line in un.describe_data(data):
            click.echo(f"      {line}")
    if dry_run:
        click.echo("Dry run: nothing changed.")
        return
    if not assume_yes and not click.confirm("Proceed?", default=True):
        click.echo("Nothing changed.")
        return
    report = un.uninstall(
        home=home,
        tm_home=tm_home,
        client_host=chost,
        tmap=tmap,
        config_path=tm_home / "config.yaml",
        echo=click.echo,
    )
    for line in report.removed:
        click.echo(f"  ✓ {line}")
    for line in report.refused + report.manual:
        click.echo(f"  ✗ {line}")
    purged = False
    if purge_data and data:
        answer = click.prompt(
            f'Type "{un.PURGE_PHRASE}" to delete the data above', default="", show_default=False
        )
        purged = un.purge_data(data, answer)
        click.echo("  ✓ data deleted" if purged else "  data kept (phrase not entered)")
    kept = [
        tm_home / "config.yaml",
        tm_home / ".env",
        tm_home / "last_run.json",
    ]
    click.echo("kept:")
    for p in kept:
        if p.exists():
            click.echo(f"  {p}")
    if not purged:
        for p in data:
            click.echo(f"  {p}")
    click.echo("  any JDK / Ghidra / BinDiff tmap did not install")
    if self_argv is None:
        click.echo(
            "the tmap program stays: it was not installed with `uv tool install tmap-agents`; "
            "remove it the way you installed it"
        )
        if report.failed:
            raise SystemExit(1)
        return
    if report.failed:
        click.echo(
            f"the tmap program stays until the items above are fixed; then: {' '.join(self_argv)}"
        )
        raise SystemExit(1)
    if assume_yes or click.confirm(
        f"Also remove the tmap program itself ({' '.join(self_argv[1:])})?", default=True
    ):
        sys.stdout.flush()
        sys.stderr.flush()
        # Replace this process: uv then removes the environment tmap was running from, with no
        # tmap process left inside it.
        os.execvp(self_argv[0], self_argv)
    click.echo(f"now run: {' '.join(self_argv)}")
