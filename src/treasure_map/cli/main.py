# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import logging

import click

from treasure_map.cli.analyze_cli import analyze
from treasure_map.cli.hunt_cli import atlas_view, hunt_diff, hunt_pattern
from treasure_map.cli.init_cli import init


@click.group()
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


main.add_command(analyze)
main.add_command(init)
main.add_command(hunt_diff)
main.add_command(hunt_pattern)
main.add_command(atlas_view)

if __name__ == "__main__":
    main()
