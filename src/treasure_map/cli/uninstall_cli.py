# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""CLI wrapper for tmap uninstall — thin Click layer; logic lives in lib/setup/uninstall.py."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click


@click.command("uninstall", short_help="Remove what tmap init installed (keeps your data)")
@click.option(
    "--purge-data",
    is_flag=True,
    help="Also delete the atlas and what tmap wrote in the workspaces.",
)
@click.option("--yes", "-y", "assume_yes", is_flag=True, help="Do not ask to confirm the plan.")
@click.option("--dry-run", is_flag=True, help="Print the plan; change nothing.")
def uninstall(purge_data: bool, assume_yes: bool, dry_run: bool) -> None:
    """Remove tmap's agent registrations, the toolchain tmap downloaded, and — when it was
    installed with ``uv tool`` — the tmap program itself (the last step, after you confirm).

    Only what the install ledger records is removed — never a JDK, Ghidra or BinDiff you
    installed yourself. config.yaml, .env, the atlas and the workspaces stay unless
    --purge-data is given and you type the confirmation phrase (--yes does not stand in for it);
    even then only what is provably tmap's goes: the atlas when it is tmap's database, what a scan
    wrote in each workspace whose analysis.db is tmap's, config.yaml and .env when tmap init wrote
    them. Everything else is kept and listed.
    """
    try:
        _uninstall(purge_data, assume_yes, dry_run)
    except OSError as exc:  # a file tmap could not read or write that no step above expected
        raise click.ClickException(f"stopped: {exc}") from exc


def _uninstall(purge_data: bool, assume_yes: bool, dry_run: bool) -> None:
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
    data = un.purge_plan(
        tm_home=tm_home, atlas=cfg.atlas.db_path, workspace_dir=cfg.workspace_dir, home=home
    )
    if purge_data:
        click.echo("  • --purge-data: delete (after you type the phrase):")
        for line in un.describe_data(data.delete):
            click.echo(f"      {line}")
        for line in data.keep:
            click.echo(f"      keep {line}")
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
    if purge_data and data.delete:
        answer = click.prompt(
            f'Type "{un.PURGE_PHRASE}" to delete the data above', default="", show_default=False
        )
        purged = un.purge_data(data, answer)
        click.echo("  ✓ data deleted" if purged else "  data kept (phrase not entered)")
    click.echo("kept:")
    if purged:
        for line in data.keep:
            click.echo(f"  {line}")
    else:
        for p in (tm_home / "config.yaml", tm_home / ".env", tm_home / "last_run.json"):
            if p.exists() and p not in data.delete:
                click.echo(f"  {p}")
        for p in data.delete:
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
