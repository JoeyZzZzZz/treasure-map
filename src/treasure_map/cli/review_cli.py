# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""``tmap review``: a run pair's review, cut into work units (lib/query/review_units).

``tmap review report <run_pair>`` prints the terminal summary — its first line the
coverage_statement — or writes the whole report (every unit, every member) as markdown or HTML.
Read-only.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any

import click

from treasure_map.cli.interrupts import InterruptGroup


class _ReviewGroup(InterruptGroup):
    """``tmap review <run_pair> --agent ...`` is the batch driver (``run``); every other first
    word names a subcommand."""

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        if args and not args[0].startswith("-") and args[0] not in self.commands:
            args = ["run", *args]
        return super().parse_args(ctx, args)


@click.group(
    name="review",
    cls=_ReviewGroup,
    short_help="A run pair's diff review cut into work units: what is read, what is not",
)
def review() -> None:
    """A run pair's diff review: the must-read set, the units it is handed out in, and how far
    the judgements have come (the same reading as start_diff_review(run_pair=...)).

    tmap review <run_pair> --agent <preset | template> runs the batch driver: one launch of your
    agent per unit, until none is left."""


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
    "--handoff",
    "as_handoff",
    is_flag=True,
    help="Write the standardized findings hand-off (one block per changed_real finding).",
)
@click.option(
    "-o",
    "--output",
    default=None,
    type=click.Path(dir_okay=False, writable=True),
    help="The file --md / --html / --handoff writes (required with any).",
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
    as_handoff: bool,
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

    file_flags = sum((as_md, as_html, as_handoff))
    if file_flags > 1:
        raise click.UsageError("pass one of --md / --html / --handoff")
    if file_flags and output is None:
        raise click.UsageError("--md / --html / --handoff write a file: pass -o <file>")
    if output is not None and not file_flags:
        raise click.UsageError(
            "-o names the file a format writes: pass one of --md / --html / --handoff"
        )
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
        if as_handoff:
            assert output is not None
            # The same staleness context and file-judgement reading the MCP get_diff_handoff
            # builds, so the file and the tool's pages are the same text (B-4(d)).
            stamp, file_staleness = rr.local_handoff_context(conn)
            findings = rr.handoff_findings(conn, run_pair, file_staleness=file_staleness)
            text = rr.handoff_header(run_pair, len(findings)) + "".join(
                rr.handoff_blocks(conn, run_pair, findings, stamp=stamp)
            )
            Path(output).write_text(text, encoding="utf-8")
            click.echo(f"wrote {output} ({len(findings)} findings)")
            return
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


SKILL_LOOP_MARKER = "{loop}"


def skill_text() -> str:
    """The diff-review skill shipped with tmap (markdown with its frontmatter): the template's
    frontmatter and rules around ``## The loop``, which is the server's own two workflow sentences
    (``DIFF_WORKFLOW`` and ``PAIR_WORKFLOW``) — quoted, never retyped, so the skill cannot drift
    from what the server says."""
    from importlib.resources import files

    from treasure_map.lib.query.diff_workflow import DIFF_WORKFLOW, PAIR_WORKFLOW

    template = files("treasure_map.skills").joinpath("diff-review.md").read_text(encoding="utf-8")
    if template.count(SKILL_LOOP_MARKER) != 1:
        raise RuntimeError(f"the skill template must hold {SKILL_LOOP_MARKER} exactly once")
    loop = f"## The loop\n\n{DIFF_WORKFLOW}\n\n{PAIR_WORKFLOW}"
    return template.replace(SKILL_LOOP_MARKER, loop)


@review.command(name="skill")
@click.option(
    "--install",
    "install_dir",
    default=None,
    type=click.Path(file_okay=False),
    help=(
        "A skills directory to write it into, as <dir>/" + SKILL_DIRNAME + "/SKILL.md "
        "(an earlier tmap's file there is replaced; any other file only with --force)."
    ),
)
@click.option(
    "--force", is_flag=True, help="With --install: replace a file there that is not tmap's."
)
def skill(install_dir: str | None, force: bool) -> None:
    """Print the agent skill for reviewing a run pair unit by unit, or write it into a skills
    directory."""
    text = skill_text()
    if install_dir is None:
        click.echo(text, nl=False)
        return
    from treasure_map.lib.errors import ConfigError
    from treasure_map.lib.setup import skills as sk
    from treasure_map.lib.setup.ledger import LEDGER_NAME, Ledger

    home = Path.home()
    try:
        ledger = Ledger.load(home / ".treasure-map" / "toolchain" / LEDGER_NAME)
    except ConfigError as exc:
        raise click.ClickException(str(exc)) from exc
    for line in sk.recover(ledger):
        click.echo(line)
    root = Path(install_dir)
    data = text.encode("utf-8")
    st = sk.classify(root, ledger, data)
    if st.state == "aligned":
        click.echo(f"{st.path} is already current")
        return
    if st.state in ("foreign", "invalid") and not force:
        raise click.ClickException(f"{st.path}: {st.detail}; not replaced (--force replaces it)")
    # Recorded only where tmap uninstall may take it away again.
    recorded = os.path.realpath(root) in {os.path.realpath(r) for r in sk.known_roots(home)}
    try:
        if recorded:
            sk.install(st.path, data, ledger)
        else:
            sk.write_plain(st.path, data)
    except OSError as exc:
        raise click.ClickException(f"could not write {st.path}: {exc}") from exc
    click.echo(f"wrote {st.path}" + ("" if recorded else " (not in tmap's install ledger)"))


# ── a person's judgements: judge (one) and the audit worksheet (many) ────────────────────────

# Environment variables an agent's shell is known to set. Seeing one, a write declared "human" is
# recorded as human-via-agent instead: best effort only — an agent that unsets them can still
# claim "human", so "human" means "typed and confirmed on an interactive terminal of this
# machine", never more.
AGENT_ENV_MARKERS = ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT")
_BY = ("human", "human-via-agent")


def _interactive() -> bool:
    import sys

    return sys.stdin.isatty() and sys.stdout.isatty()


def resolve_attribution(by: str) -> tuple[str, str | None]:
    """``(attributed_to, note)`` for a write declared ``by``. ``human`` needs an interactive
    terminal and a typed confirmation, and drops to ``human-via-agent`` (with a note) when an agent
    environment marker is set; ``human-via-agent`` is taken as it is."""
    import os

    if by == "human-via-agent":
        return by, None
    marker = next((m for m in AGENT_ENV_MARKERS if os.environ.get(m)), None)
    if marker is not None:
        return "human-via-agent", (
            f"{marker} is set: this looks like an agent's shell, so the judgement is recorded as "
            "human-via-agent"
        )
    if not _interactive():
        raise click.UsageError(
            "--by human needs an interactive terminal (a person typing): from a pipe or a script, "
            "record a person's judgement with --by human-via-agent"
        )
    typed = click.prompt('Type "human" to record this as your own judgement', default="")
    if typed.strip() != "human":
        raise click.ClickException("not confirmed: nothing was written")
    return "human", None


def _open(atlas_db: str | None, run_pair: str) -> tuple[sqlite3.Connection, str, str, str]:
    from treasure_map.cli.mcp_cli import _resolve_mcp_target
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.query import file_diff as fd

    atlas, _ = _resolve_mcp_target(atlas_db, None)
    if not Path(atlas).is_file():
        raise click.ClickException(f"no atlas at {atlas}: pass --atlas <path to atlas.db>")
    conn = open_atlas(Path(atlas))
    runs = fd.split_run_pair(conn, run_pair)
    if runs is None:
        conn.close()
        raise click.ClickException(f"run pair {run_pair!r} does not name two runs of this atlas")
    return conn, runs[0], runs[1], str(atlas)


def _scope(member: object, run_pair: str) -> dict[str, str]:
    """Where a member's judgement is written: its diff, or the run pair for a pair-level one."""
    kind = getattr(member, "kind", "")
    if kind == "entry":
        return {"diff_id": str(getattr(member, "stream", ""))}
    return {"run_pair": run_pair}


def _basis(
    checked: tuple[str, ...] | list[str] | None,
    why_unchanged: str | None,
    evidence: tuple[str, ...] | list[str] | None,
    change_kind: tuple[str, ...] | list[str] | None,
) -> dict[str, object] | None:
    out: dict[str, object] = {}
    if checked:
        out["checked"] = list(checked)
    if why_unchanged:
        out["why_unchanged"] = why_unchanged
    if evidence:
        out["evidence"] = list(evidence)
    if change_kind:
        out["change_kind"] = list(change_kind)
    return out or None


@review.command(name="judge")
@click.argument("unit_id")
@click.argument("run_pair")
@click.option(
    "--verdict",
    required=True,
    type=click.Choice(["changed_real", "no_real_change", "change_inconclusive"]),
)
@click.option(
    "--anchor", default=None, help="The member judged (needed when the unit has several)."
)
@click.option(
    "--rationale", default=None, help="Why (no_real_change defaults it to --why-unchanged)."
)
@click.option("--checked", multiple=True, help="no_real_change: an anchor or fact read (repeat).")
@click.option("--why-unchanged", default=None, help="no_real_change: why nothing real changed.")
@click.option("--evidence", multiple=True, help="changed_real: an anchor or fact it rests on.")
@click.option("--change-kind", multiple=True, help="changed_real: what the change does (repeat).")
@click.option("--by", "by", type=click.Choice(_BY), default="human", show_default=True)
@click.option(
    "--k", "k", default=None, type=click.IntRange(0, None), help="The k the unit came with."
)
@click.option("--atlas", "atlas_db", default=None, help="Atlas DB path.")
def judge(
    unit_id: str,
    run_pair: str,
    verdict: str,
    anchor: str | None,
    rationale: str | None,
    checked: tuple[str, ...],
    why_unchanged: str | None,
    evidence: tuple[str, ...],
    change_kind: tuple[str, ...],
    by: str,
    k: int | None,
    atlas_db: str | None,
) -> None:
    """Record a person's judgement on one member of UNIT_ID (a unit of RUN_PAIR, from the report or
    start_diff_review). It goes through the same checks as any judgement and becomes the current
    one — over an agent's, which stays in the history; on an audit unit too."""
    from treasure_map.lib import overlay
    from treasure_map.lib.errors import ConfigError
    from treasure_map.lib.query import review_units as ru

    attribution, note = resolve_attribution(by)
    conn, run_a, run_b, _atlas = _open(atlas_db, run_pair)
    try:
        reading = ru.review_pair(
            conn,
            run_a,
            run_b,
            k=ru.DEFAULT_K if k is None else k,
            pair_staleness=ru.pair_staleness(conn, run_a, run_b),
            server_commit=None,
        )
        unit = reading.unit(unit_id)
        if unit is None:
            raise click.ClickException(
                f"no unit {unit_id!r} in {run_pair} now (tmap review report)"
            )
        members = [m for m in unit.members if anchor is None or m.anchor_ref == anchor]
        if len(members) != 1:
            names = ", ".join(m.anchor_ref for m in unit.members[:5])
            raise click.UsageError(f"pass --anchor: the unit holds {len(unit.members)} ({names})")
        member = members[0]
        if verdict == "no_real_change" and not rationale:
            rationale = why_unchanged
        try:
            res = overlay.annotate_diff(
                conn,
                anchor_ref=member.anchor_ref,
                verdict=verdict,
                rationale=rationale or "",
                attributed_to=attribution,
                verdict_basis=_basis(checked, why_unchanged, evidence, change_kind),
                ctx=overlay.WriteContext(
                    channel="judge", unit_id=unit_id, read_basis={"basis": "human", "via": by}
                ),
                diff_id=_scope(member, run_pair).get("diff_id"),
                run_pair=_scope(member, run_pair).get("run_pair"),
            )
        except ConfigError as exc:
            raise click.ClickException(f"refused, nothing written: {exc}") from exc
    finally:
        conn.close()
    if note:
        click.echo(note)
    click.echo(f"{res.action}: {member.anchor_ref} = {verdict} ({attribution})")


@review.command(name="audit")
@click.argument("run_pair")
@click.option(
    "--emit",
    "emit_to",
    default=None,
    type=click.Path(dir_okay=False),
    help="Write the audit worksheet (the disagreements to settle, and open audits when blind "
    "auditing is enabled) here.",
)
@click.option(
    "--apply",
    "apply_from",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help="Write back the judgements filled in a worksheet.",
)
@click.option("--by", "by", type=click.Choice(_BY), default="human", show_default=True)
@click.option("--atlas", "atlas_db", default=None, help="Atlas DB path.")
def audit(
    run_pair: str, emit_to: str | None, apply_from: str | None, by: str, atlas_db: str | None
) -> None:
    """The pair's audit worksheet: --emit writes the disagreements a person settles (and, when
    blind auditing is enabled, the judgements owed a second reading); fill in verdict / rationale /
    checked / why_unchanged / evidence / change_kind for the ones you judge, then --apply it. Each
    filled item goes through the same checks as any judgement: one that fails is reported and not
    written."""
    import json

    from treasure_map.lib import overlay
    from treasure_map.lib.errors import ConfigError
    from treasure_map.lib.query import review_units as ru

    if (emit_to is None) == (apply_from is None):
        raise click.UsageError("pass one of --emit <file> / --apply <file>")
    attribution = note = None
    if apply_from is not None:
        attribution, note = resolve_attribution(by)
    conn, run_a, run_b, _atlas = _open(atlas_db, run_pair)
    try:
        reading = ru.review_pair(
            conn,
            run_a,
            run_b,
            pair_staleness=ru.pair_staleness(conn, run_a, run_b),
            server_commit=None,
        )
        if emit_to is not None:
            Path(emit_to).write_text(
                json.dumps(worksheet(conn, reading, run_pair), indent=2) + "\n", encoding="utf-8"
            )
            click.echo(f"wrote {emit_to}")
            return
        assert apply_from is not None and attribution is not None
        sheet = json.loads(Path(apply_from).read_text(encoding="utf-8"))
        written, refused, skipped = 0, [], 0
        for i, item in enumerate(sheet.get("items") or []):
            if not isinstance(item, dict) or not item.get("verdict"):
                skipped += 1
                continue
            verdict = str(item["verdict"])
            rationale = item.get("rationale") or (
                item.get("why_unchanged") if verdict == "no_real_change" else None
            )
            try:
                overlay.annotate_diff(
                    conn,
                    anchor_ref=str(item.get("anchor_ref")),
                    verdict=verdict,
                    rationale=str(rationale or ""),
                    attributed_to=attribution,
                    verdict_basis=_basis(
                        item.get("checked"),
                        item.get("why_unchanged"),
                        item.get("evidence"),
                        item.get("change_kind"),
                    ),
                    ctx=overlay.WriteContext(
                        channel="worksheet",
                        unit_id=item.get("unit_id"),
                        read_basis={"basis": "human", "via": by},
                    ),
                    diff_id=(item.get("scope") or {}).get("diff_id"),
                    run_pair=(item.get("scope") or {}).get("run_pair"),
                )
                written += 1
            except (ConfigError, TypeError) as exc:
                refused.append((i, str(item.get("anchor_ref")), str(exc)))
    finally:
        conn.close()
    if note:
        click.echo(note)
    click.echo(f"written {written}, refused {len(refused)}, left blank {skipped}")
    for i, anchor, why in refused:
        click.echo(f"  refused item {i} ({anchor}): {why}")


def worksheet(conn: sqlite3.Connection, reading: Any, run_pair: str) -> dict[str, object]:
    """The worksheet of a pair: one item per open audit and per disagreement, with where it is
    written and the fields to fill in."""
    from treasure_map.lib.query import review_units as ru

    assert isinstance(reading, ru.PairReview)
    current = {
        r[0]: {"verdict": r[1], "rationale": r[2], "attributed_to": r[3]}
        for r in conn.execute(
            "SELECT anchor_ref, verdict, rationale, attributed_to FROM overlay "
            "WHERE anchor_kind = 'diff_subject' AND run_id = ?",
            (run_pair,),
        )
    }
    members = {m.anchor_ref: m for u in reading.units for m in u.members}
    blank: dict[str, object] = {
        "verdict": None,
        "rationale": "",
        "checked": [],
        "why_unchanged": "",
        "evidence": [],
        "change_kind": [],
    }
    items: list[dict[str, object]] = []
    for a in reading.audits.open:
        # An audit is a BLIND second reading (spec six.7): the auditor must NOT see the verdict
        # under audit, or they are anchored by it (and their write becomes current and closes the
        # audit). So an audit item carries no ``current`` — unlike a disagreement below, which is
        # settled precisely by seeing the conflicting conclusions. Nor does it name the audit's
        # sources: a source IS the verdict under audit.
        items.append(
            {
                "unit_id": a.unit.unit_id,
                "anchor_ref": a.member.anchor_ref,
                "scope": _scope(a.member, run_pair),
                "why": ["audit"],
                **blank,
            }
        )
    for d in reading.audits.disagreements:
        m = members.get(str(d["anchor_ref"]))
        items.append(
            {
                "unit_id": None,
                "anchor_ref": d["anchor_ref"],
                "scope": _scope(m, run_pair) if m is not None else {"run_pair": run_pair},
                "why": ["disagreement", d["why"]],
                "current": current.get(str(d["anchor_ref"])),
                "other": {k: v for k, v in d.items() if k not in ("anchor_ref", "why")},
                **blank,
            }
        )
    return {
        "run_pair": run_pair,
        "fill_in": (
            "verdict = changed_real | no_real_change | change_inconclusive; no_real_change needs "
            "checked (an anchor read) and why_unchanged; leave verdict null to skip an item"
        ),
        "items": items,
    }


@review.command(name="run")
@click.argument("run_pair")
@click.option(
    "--agent",
    "agent",
    required=True,
    help=(
        "A preset (claude-code; experimental: codex, cursor) or a command template holding "
        "{prompt} (also {mcp_config}, {workdir}, {atlas}, {unit_id}, {run_pair}). A template or "
        "an experimental preset runs only after its probe passes."
    ),
)
@click.option("--probe", "probe_only", is_flag=True, help="Only check the agent's tool set.")
@click.option("--max-units", default=None, type=click.IntRange(1, None), help="Stop after N units.")
@click.option("--max-minutes", default=None, type=float, help="Stop after M minutes.")
@click.option(
    "--timeout",
    default=None,
    type=click.IntRange(30, None),
    help="Seconds one launch may take (default 900).",
)
@click.option(
    "--retries",
    default=None,
    type=click.IntRange(0, 5),
    help="Retries of a unit that did not judge every member (default 2).",
)
@click.option("--worker", default=None, type=click.IntRange(0, None), help="This shard's index.")
@click.option("--workers", default=None, type=click.IntRange(1, None), help="How many shards.")
@click.option(
    "--k",
    "k",
    default=None,
    type=click.IntRange(0, None),
    help="How many first entries of each diff are must-read (default 4).",
)
@click.option(
    "--handoff",
    "handoff_out",
    default=None,
    type=click.Path(dir_okay=False, writable=True),
    help="After the review is done, launch one agent to write the findings hand-off here "
    "(claude-code only this version).",
)
@click.option("--atlas", "atlas_db", default=None, help="Atlas DB path.")
def run(
    run_pair: str,
    agent: str,
    probe_only: bool,
    max_units: int | None,
    max_minutes: float | None,
    timeout: int | None,
    retries: int | None,
    worker: int | None,
    workers: int | None,
    k: int | None,
    handoff_out: str | None,
    atlas_db: str | None,
) -> None:
    """Review RUN_PAIR unit by unit, one launch of your agent per unit: tmap runs the loop and
    calls no model itself. A unit counts only when the overlay's history holds a judgement naming
    it for every member. Ends when no unit is left, or at a limit."""
    import tempfile

    from treasure_map.lib import review_driver as rd
    from treasure_map.lib.query import review_units as ru

    if (worker is None) != (workers is None):
        raise click.UsageError("--worker and --workers go together")
    if worker is not None and workers is not None and worker >= workers:
        raise click.UsageError(f"--worker must be below --workers ({workers})")
    try:
        preset = rd.preset_or_template(agent)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    if handoff_out is not None and preset.name not in rd.HANDOFF_PRESETS:
        # Fail before driving — B-5: an experimental preset's result is read differently and is not
        # supported this version, so the hand-off is refused, never attempted and silently empty.
        raise click.UsageError(
            f"--handoff can only write from the claude-code preset this version; {preset.name!r} "
            "is experimental and prints its result another way"
        )
    conn, run_a, run_b, atlas = _open(atlas_db, run_pair)
    staleness = ru.pair_staleness(conn, run_a, run_b)
    conn.close()
    if staleness.get("source_stale"):
        raise click.ClickException(
            f"{staleness['source_stale_reason']}: a run of the pair was produced by other code "
            "than is installed — the MCP server refuses it; re-scan it first (tmap rescan)"
        )
    workdir = Path(tempfile.mkdtemp(prefix="tmap-review-"))
    deadline = timeout or rd.DEFAULT_TIMEOUT
    click.echo(f"probing {preset.name} ({preset.note or 'preset'}) …")
    pr = rd.probe(preset, atlas_path=Path(atlas), workdir=workdir, timeout=min(deadline, 300))
    click.echo(
        f"probe: tmap reached {pr.tmap_reached}, built-in tools blocked {pr.builtin_blocked} — "
        f"{pr.why}"
    )
    if not pr.ok:
        raise click.ClickException("the probe failed: no unit is handed to this agent")
    if probe_only:
        return
    result = rd.drive(
        Path(atlas),
        run_a,
        run_b,
        preset,
        workdir=workdir,
        k=ru.DEFAULT_K if k is None else k,
        worker=worker,
        workers=workers,
        max_units=max_units,
        max_minutes=max_minutes,
        timeout=deadline,
        retries=rd.DEFAULT_RETRIES if retries is None else retries,
        pair_staleness=staleness,
        echo=click.echo,
    )
    click.echo(
        f"units tried {result.units_tried}, done {result.units_done}, failed "
        f"{len(result.failed)} — {result.stopped}"
    )
    for f in result.failed:
        click.echo(f"  failed {f['unit_id']} ({f['kind']}): {f['written']}/{f['members']} written")
    if result.statement:
        click.echo(result.statement)
    if handoff_out is not None:
        if result.stopped != "no unit left" or result.failed:
            click.echo(
                f"hand-off skipped: the review is not done ({result.stopped}); re-run without a "
                "limit, then write the hand-off"
            )
        else:
            click.echo(f"writing the findings hand-off with {preset.name} …")
            ho = rd.run_handoff(
                preset,
                atlas_path=Path(atlas),
                run_pair=run_pair,
                workdir=workdir,
                out_file=Path(handoff_out),
                timeout=deadline,
            )
            if ho["ok"]:
                gap = ho.get("nothing_written") or 0
                click.echo(
                    f"wrote {ho['out_file']} ({ho['bytes']} bytes, {ho.get('findings')} findings"
                    + (f"; the agent wrote nothing for {gap} of them)" if gap else ")")
                )
            else:
                click.echo(f"hand-off failed: {ho['error']}")
    if result.failed:
        raise SystemExit(3)
