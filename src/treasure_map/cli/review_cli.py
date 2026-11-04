# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""``tmap review``: a run pair's review, cut into work units (lib/query/review_units).

``tmap review report <run_pair>`` prints the terminal summary — its first line the
coverage_statement — or writes the whole report (every unit, every member) as markdown or HTML.
Read-only.
"""

from __future__ import annotations

from pathlib import Path

import click

from treasure_map.cli.interrupts import InterruptGroup


@click.group(
    name="review",
    cls=InterruptGroup,
    short_help="A run pair's diff review cut into work units: what is read, what is not",
)
def review() -> None:
    """A run pair's diff review: the must-read set, the units it is handed out in, and how far
    the judgements have come (the same reading as start_diff_review(run_pair=...))."""


@review.command(name="report")
@click.argument("run_pair")
@click.option(
    "--k",
    "k",
    default=None,
    type=click.IntRange(0, None),
    help="How many first entries of each diff are must-read (default 4).",
)
@click.option("--md", "as_md", is_flag=True, help="Write the whole report as markdown.")
@click.option("--html", "as_html", is_flag=True, help="Write the whole report as one HTML page.")
@click.option(
    "-o",
    "--output",
    default=None,
    type=click.Path(dir_okay=False, writable=True),
    help="The file --md / --html writes (required with either).",
)
@click.option(
    "--atlas",
    "atlas_db",
    default=None,
    help="Atlas DB path (default: the last run's atlas, else the configured atlas.db).",
)
def report(
    run_pair: str,
    k: int | None,
    as_md: bool,
    as_html: bool,
    output: str | None,
    atlas_db: str | None,
) -> None:
    """Print RUN_PAIR's ({run_a}::{run_b}) review summary, or write the whole report."""
    from treasure_map.cli.mcp_cli import _resolve_mcp_target
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.query import file_diff as fd
    from treasure_map.lib.query import review_report as rr
    from treasure_map.lib.query import review_units as ru
    from treasure_map.version import installed_commit

    if as_md and as_html:
        raise click.UsageError("pass one of --md / --html")
    if (as_md or as_html) and output is None:
        raise click.UsageError("--md / --html write a file: pass -o <file>")
    if output is not None and not (as_md or as_html):
        raise click.UsageError("-o names the file --md / --html writes: pass one of them")
    atlas, _ = _resolve_mcp_target(atlas_db, None)
    if not Path(atlas).is_file():
        raise click.ClickException(f"no atlas at {atlas}: pass --atlas <path to atlas.db>")
    conn = open_atlas(Path(atlas))
    try:
        runs = fd.split_run_pair(conn, run_pair)
        if runs is None:
            raise click.ClickException(
                f"run pair {run_pair!r} does not name two runs of this atlas ({{run_a}}::{{run_b}}"
                ", see tmap runs)"
            )
        run_a, run_b = runs
        staleness = ru.pair_staleness(conn, run_a, run_b)
        commit = installed_commit()
        reading = ru.review_pair(
            conn,
            run_a,
            run_b,
            k=ru.DEFAULT_K if k is None else k,
            pair_staleness=staleness,
            server_commit=commit,
        )
    finally:
        conn.close()
    header: dict[str, object] = {"atlas": atlas}
    if staleness.get("source_stale"):
        header["stale"] = (
            f"{staleness['source_stale_reason']}: a run was produced by other code than is "
            "installed; its judgements read needs_recheck until it is re-scanned"
        )
    if as_md or as_html:
        assert output is not None
        text = (
            rr.markdown(reading, header=header) if as_md else rr.html_page(reading, header=header)
        )
        Path(output).write_text(text, encoding="utf-8")
        click.echo(reading.report["coverage_statement"])
        click.echo(f"wrote {output}")
        return
    click.echo(rr.terminal(reading, header=header))


SKILL_DIRNAME = "tmap-diff-review"


def skill_text() -> str:
    """The diff-review skill shipped with tmap (markdown with its frontmatter)."""
    from importlib.resources import files

    return files("treasure_map.skills").joinpath("diff-review.md").read_text(encoding="utf-8")


@review.command(name="skill")
@click.option(
    "--install",
    "install_dir",
    default=None,
    type=click.Path(file_okay=False),
    help=(
        "A skills directory to write it into, as <dir>/" + SKILL_DIRNAME + "/SKILL.md "
        "(an existing file there is replaced)."
    ),
)
def skill(install_dir: str | None) -> None:
    """Print the agent skill for reviewing a run pair unit by unit, or write it into a skills
    directory."""
    text = skill_text()
    if install_dir is None:
        click.echo(text, nl=False)
        return
    dest = Path(install_dir) / SKILL_DIRNAME / "SKILL.md"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
    click.echo(f"wrote {dest}")
