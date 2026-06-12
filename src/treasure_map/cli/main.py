# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import logging

import click

from treasure_map.cli.analyze_cli import analyze
from treasure_map.cli.init_cli import init


@click.group()
@click.option("--debug", is_flag=True, default=False, help="Enable debug logging.")
def main(debug: bool) -> None:
    """Treasure Map — IoT firmware exploit-path discovery."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


main.add_command(analyze)
main.add_command(init)

if __name__ == "__main__":
    main()
