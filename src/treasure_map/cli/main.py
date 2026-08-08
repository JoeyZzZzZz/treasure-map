# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import logging

import click

from treasure_map.cli.analyze_cli import analyze
from treasure_map.cli.exploit_cli import exploit
from treasure_map.cli.hunt_cli import atlas_view, hunt_diff, hunt_pattern, runs, scan, triage
from treasure_map.cli.init_cli import init
from treasure_map.cli.mcp_cli import fact, mcp_serve


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
        ("Main", ("init", "scan", "diff", "runs", "exploit")),
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
@click.option("--debug", is_flag=True, default=False, help="Enable debug logging.")
def main(debug: bool) -> None:
    """Treasure Map — IoT firmware exploit-path discovery."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")
    # Third-party request logs (one "HTTP/1.1 200 OK" per call) are noise at INFO; keep them
    # at WARNING so our own treasure_map.* INFO lines still show. --debug leaves them verbose.
    if not debug:
        for noisy in ("httpx", "httpcore", "openai", "anthropic"):
            logging.getLogger(noisy).setLevel(logging.WARNING)


main.add_command(scan)
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

if __name__ == "__main__":
    main()
