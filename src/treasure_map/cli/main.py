# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import logging

import click

from treasure_map.cli.analyze_cli import analyze
from treasure_map.cli.doctor_cli import doctor
from treasure_map.cli.exploit_cli import exploit
from treasure_map.cli.hunt_cli import (
    atlas_view,
    hunt_diff,
    hunt_pattern,
    rescan,
    runs,
    scan,
    triage,
)
from treasure_map.cli.init_cli import init
from treasure_map.cli.mcp_cli import fact, mcp_serve
from treasure_map.cli.uninstall_cli import uninstall
from treasure_map.cli.update_cli import update
from treasure_map.version import __version__


class _AliasGroup(click.Group):
    """Top-level group that resolves pre-rename names and lays out --help in three groups.

    The commands were shortened (hunt-pattern -> hunt, hunt-diff -> diff, mcp-serve -> mcp). The
    old names stay resolvable for back-compat with existing scripts/notes, but are NOT listed in
    --help (they are mapped here, never registered as their own commands).

    ``format_commands`` groups the listing to make tmap's human/agent division legible: the Main
    group is where a person hands tmap the work only a person can decide (set up, scan firmware,
    compare versions, see what was scanned); analysis is recommended via an agent over MCP; the
    Advanced group is for inspecting results yourself or re-running one stage. The Main group stays
    deliberately terse (what each command does, not how); the Advanced group says more because a
    reader reaching for a single stage needs to know which stage it is."""

    _ALIASES = {"hunt-pattern": "hunt", "hunt-diff": "diff", "mcp-serve": "mcp"}

    # (section title, ordered command names). A person drives the Main group; an agent over MCP is
    # the recommended way to do the analysis itself; Advanced is manual inspection / single-stage.
    _GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
        (
            "Main",
            ("init", "scan", "rescan", "diff", "runs", "exploit", "doctor", "update", "uninstall"),
        ),
        ("Analysis (recommended)", ("mcp",)),
        (
            "Advanced (inspect results yourself / re-run a single step)",
            ("analyze", "hunt", "triage", "atlas-view", "fact"),
        ),
    )

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.Command | None:
        return super().get_command(ctx, self._ALIASES.get(cmd_name, cmd_name))

    def format_commands(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        grouped = {name for _, names in self._GROUPS for name in names}
        # Any registered command not placed in a group is still shown (never silently dropped from
        # --help) under a trailing "Other" section — so a future command cannot vanish by omission.
        leftover = [n for n in self.list_commands(ctx) if n not in grouped]
        sections = [*self._GROUPS, *([("Other", tuple(leftover))] if leftover else [])]

        all_names = [n for _, names in sections for n in names]
        if not all_names:
            return
        limit = formatter.width - 6 - max(len(n) for n in all_names)
        for title, names in sections:
            rows = []
            for name in names:
                cmd = self.get_command(ctx, name)
                if cmd is None or cmd.hidden:
                    continue
                rows.append((name, cmd.get_short_help_str(limit)))
            if rows:
                with formatter.section(title):
                    formatter.write_dl(rows)


@click.group(cls=_AliasGroup, context_settings={"max_content_width": 100})
@click.version_option(version=__version__, prog_name="tmap", message="%(prog)s %(version)s")
@click.option("--debug", is_flag=True, default=False, help="Enable debug logging.")
def main(debug: bool) -> None:
    """A firmware map for your AI agent. Treasure Map draws the map; your agent finds the treasure.

    It turns an extracted firmware filesystem into facts your agent reads through the bundled MCP
    server (`tmap mcp`). It runs no model of its own: deciding which lead is a real bug is your
    agent's job. Start with `tmap init`.
    """
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")
    # Third-party request logs (one "HTTP/1.1 200 OK" per call) are noise at INFO; keep them
    # at WARNING so our own treasure_map.* INFO lines still show. --debug leaves them verbose.
    if not debug:
        for noisy in ("httpx", "httpcore", "openai", "anthropic"):
            logging.getLogger(noisy).setLevel(logging.WARNING)
    _apply_configured_toolchain()


def _apply_configured_toolchain() -> None:
    """Put the JDK / BinDiff named in config.yaml first in this process's environment, so every
    command (``tmap mcp`` started by a GUI client with a bare PATH included) runs the toolchain
    ``tmap init`` chose. A broken config must not stop ``tmap init`` from repairing it, so it is a
    warning here, not an error."""
    from treasure_map.lib.config.config import load_config
    from treasure_map.lib.errors import ConfigError
    from treasure_map.lib.setup.toolchain_env import apply_toolchain_env

    try:
        notes = apply_toolchain_env(load_config(None))
    except ConfigError as exc:
        click.echo(f"warning: {exc}; toolchain paths from config not applied", err=True)
        return
    for note in notes:
        if note.endswith("not used"):
            logging.getLogger(__name__).warning("%s", note)


main.add_command(scan)
main.add_command(rescan)
main.add_command(analyze)
main.add_command(init)
main.add_command(hunt_diff)
main.add_command(hunt_pattern)
main.add_command(triage)
main.add_command(runs)
main.add_command(atlas_view)
main.add_command(fact)
main.add_command(mcp_serve)
main.add_command(exploit)
main.add_command(doctor)
main.add_command(uninstall)
main.add_command(update)

if __name__ == "__main__":
    main()
