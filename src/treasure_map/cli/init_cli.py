# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""CLI wrapper for tmap init / tmap doctor — thin Click layer; logic lives in lib/setup/."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING

import click

from treasure_map.cli.interrupts import interrupt_exit_code
from treasure_map.lib.errors import TreasureMapError
from treasure_map.lib.setup.initializer import (
    InitAbortedError,
    InitResult,
    PlatformUnsupportedError,
    run_init,
)

if TYPE_CHECKING:
    from treasure_map.lib.config.config import Config
    from treasure_map.lib.setup.doctor import RunsCurrency

_CLIENT_CHOICES = ("claude-code", "codex", "cursor", "claude-desktop", "dsh")


def runs_currency(cfg: Config | None) -> RunsCurrency:
    """How many runs in the atlas an older tmap made — the same classifier ``tmap rescan`` uses,
    read through a READ-ONLY connection (init never migrates the atlas)."""
    from treasure_map.cli.hunt_cli import _live_instance_counts, _staleness_tiers
    from treasure_map.lib.analyze.ghidra_runner import current_pass_version
    from treasure_map.lib.config.config import Config as _Config
    from treasure_map.lib.query import list_runs
    from treasure_map.lib.setup.doctor import RunsCurrency
    from treasure_map.version import installed_commit

    atlas = (cfg or _Config()).atlas.db_path
    if not atlas.exists():
        return RunsCurrency(None, absent=True)
    # Read without writing a byte: a WAL database read through mode=ro creates -wal and -shm beside
    # it and leaves them. With neither present (the atlas was closed cleanly) nothing can be
    # mid-write, so it is opened immutable; with them present, mode=ro reads the live state.
    side = [atlas.with_name(atlas.name + s) for s in ("-wal", "-shm")]
    flag = "mode=ro" if any(p.exists() for p in side) else "immutable=1"
    try:
        conn = sqlite3.connect(f"{atlas.resolve().as_uri()}?{flag}", uri=True)
    except sqlite3.Error as exc:
        return RunsCurrency(None, why=f"cannot open {atlas} read-only: {exc}")
    conn.row_factory = sqlite3.Row
    try:
        runs = list_runs(conn)
        live = _live_instance_counts(conn)
    except sqlite3.Error:
        return RunsCurrency(None, why="atlas needs migration; any tmap command will migrate it")
    finally:
        conn.close()
    tiers, _current = _staleness_tiers(
        runs, current_build=current_pass_version(), commit=installed_commit(), live=live
    )
    return RunsCurrency(sum(len(v) for v in tiers.values()))


def _prompt_fn(msg: str) -> str:
    return str(click.prompt(msg, default="", show_default=False))


def render_checks(result: InitResult) -> bool:
    """Print the doctor's findings; True when any of them fails the run."""
    click.echo("Preflight checks:")
    any_red = False
    for c in result.checks:
        state = getattr(c, "state", "ok" if c[1] else "wrong")
        icon = {"ok": "✅", "warn": "⚠", "info": "·", "unknown": "?"}.get(state, "❌")
        click.echo(f"  {icon} {c[0]}: {c[2]}")
        if not c[1]:
            any_red = True
    return any_red


# What to say to the agent, written out in full (one sentence per line) so it can be copied as is.
_AUDIT_PROMPT = (
    "Audit firmware my-fw using treasure-map.",
    "Choose for yourself which views of its candidate map to review",
    "(by sink, by data source, or by any other layer) and find the issues in them:",
    "open a lead's pseudocode, trace where its input comes from, and judge it yourself.",
    "The candidates are leads to verify, not confirmed bugs.",
    "Record each conclusion with annotate so the next session starts from it.",
)
_DIFF_PROMPT = (
    "Review the diff fw-v1 → fw-v2 using treasure-map.",
    "Start from the function patch view (get_diff_patch_view):",
    "for each changed function, compare the pseudocode of both versions",
    "and decide whether the change does something real, such as a new check or a changed bound.",
    "Record each judgement with annotate_diff.",
)


def _next_steps(result: InitResult, any_red: bool) -> None:
    runs = result.runs
    if result.needs_you or any_red:
        click.echo("")
        click.echo("Needs you:")
        for item in result.needs_you:
            first, *rest = item.splitlines()
            click.echo(f"  - {first}")
            for line in rest:
                click.echo(f"      {line}")
        for c in result.checks:
            if not c[1]:
                click.echo(f"  - {c[0]}: {c[2]}")
    upgrade = [
        "After upgrading tmap (tmap update):",
        "   tmap rescan                                   "
        "# re-scan every run made by an older tmap",
        "   tmap diff --before fw-v1 --after fw-v2        "
        "# re-runs the diff; stale runs are rescanned first",
    ]
    click.echo("")
    if runs is not None and not runs.absent and runs.count is None:
        click.echo(f"runs: unknown ({runs.why})")
    stale_first = runs is not None and runs.count is not None and runs.count > 0
    if stale_first:
        click.echo(f"{runs.count} runs predate this tmap.")
        for line in upgrade:
            click.echo(line)
        click.echo("")
    click.echo("Ready. Two things you can do:" if not any_red else "Once that is done:")
    click.echo("")
    click.echo("① Audit one firmware")
    click.echo("   tmap scan ./fw.extracted -w my-fw")
    click.echo("   Then in your agent:")
    for line in _AUDIT_PROMPT:
        click.echo(f"     {line}")
    click.echo("")
    click.echo("② Find what a firmware update changed (patch diff)")
    click.echo("   tmap scan ./fw_v1.extracted -w fw-v1")
    click.echo("   tmap scan ./fw_v2.extracted -w fw-v2")
    click.echo("   tmap diff --before fw-v1 --after fw-v2")
    click.echo("   Then in your agent:")
    for line in _DIFF_PROMPT:
        click.echo(f"     {line}")
    if not stale_first:
        click.echo("")
        for line in upgrade:
            click.echo(line)
    if result.registered:
        click.echo("")
        click.echo(f"Restart {', '.join(result.registered)} so they load treasure-map.")


def _run(**kwargs: object) -> InitResult:
    try:
        return run_init(**kwargs)  # type: ignore[arg-type]
    except PlatformUnsupportedError as exc:
        raise click.ClickException(str(exc)) from exc
    except InitAbortedError as exc:
        click.echo(str(exc), err=True)
        raise SystemExit(interrupt_exit_code()) from exc
    except FileExistsError as exc:
        raise click.ClickException(str(exc)) from exc
    except TreasureMapError as exc:
        raise click.ClickException(f"{type(exc).__name__}: {exc}") from exc
    except OSError as exc:  # ~/.treasure-map itself cannot be written: say what, no traceback
        raise click.ClickException(str(exc)) from exc
    except (KeyboardInterrupt, click.exceptions.Abort) as exc:
        # Ctrl-C at a raw-mode key, or at any line prompt (click turns that into Abort): the same
        # interruption, the same 130.
        click.echo("\ninterrupted; staging cleaned up — run tmap init again to continue", err=True)
        raise SystemExit(interrupt_exit_code()) from exc


@click.command("init", short_help="Set up tmap: toolchain, config, agents (run this first)")
@click.option(
    "--yes", "-y", "assume_yes", is_flag=True, help="No questions; download what is missing."
)
@click.option("--dry-run", is_flag=True, help="Print the plan; write nothing.")
@click.option(
    "--client",
    "clients",
    multiple=True,
    type=click.Choice(_CLIENT_CHOICES),
    help="Register with this agent (repeatable); with --yes / --non-interactive only these.",
)
@click.option("--ghidra", type=click.Path(path_type=Path), help="Use this Ghidra 11.4.3.")
@click.option("--java-home", type=click.Path(path_type=Path), help="Use this JDK 21.")
@click.option("--bindiff", type=click.Path(path_type=Path), help="Use this bindiff executable.")
@click.option("--mirror", help="Fetch the pinned archives from BASE/<file name> instead.")
@click.option(
    "--offline",
    type=click.Path(path_type=Path, file_okay=False),
    help="Read the pinned archives from DIR/<file name>; no network.",
)
@click.option("--force", is_flag=True, default=False, help="Rebuild config.yaml from defaults.")
@click.option(
    "--check-only",
    "check_only",
    is_flag=True,
    default=False,
    help="Run the doctor only; write nothing.",
)
@click.option(
    "--non-interactive",
    "non_interactive",
    is_flag=True,
    default=False,
    help="No questions and no downloads; write .env with no keys.",
)
def init(
    assume_yes: bool,
    dry_run: bool,
    clients: tuple[str, ...],
    ghidra: Path | None,
    java_home: Path | None,
    bindiff: Path | None,
    mirror: str | None,
    offline: Path | None,
    force: bool,
    check_only: bool,
    non_interactive: bool,
) -> None:
    """Set up ~/.treasure-map/, the Ghidra / BinExport / BinDiff toolchain, and your agents.

    Existing installs are reused when they check out; anything missing is downloaded from pinned,
    checksummed archives after you confirm the plan."""
    result = _run(
        force=force,
        non_interactive=non_interactive,
        check_only=check_only,
        prompt=_prompt_fn,
        echo=click.echo,
        assume_yes=assume_yes,
        dry_run=dry_run,
        clients=clients,
        ghidra=ghidra,
        java_home=java_home,
        bindiff=bindiff,
        mirror=mirror,
        offline=offline,
        runs_probe=runs_currency,
    )
    if result.dry_run:
        return
    if not check_only:
        click.echo("")
        click.echo(f"  Config : {result.config_path}")
        click.echo(f"  .env   : {result.env_path}")
        click.echo(f"  Atlas  : {result.atlas_dir}")
        click.echo("")
    any_red = render_checks(result)
    if check_only:
        if any_red:
            raise SystemExit(1)
        return
    _next_steps(result, any_red)
    # Unattended (--yes / --non-interactive) a script reads the exit code alone, so a machine left
    # not ready is a failure there. Interactively the person has read the checks above.
    if result.failed or (any_red and (assume_yes or non_interactive)):
        raise SystemExit(1)
