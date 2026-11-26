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
from treasure_map.lib.query import diff_skill, scan_skill


class _ReviewGroup(InterruptGroup):
    """``tmap review <run_pair> --agent ...`` is the batch driver (``run``); every other first
    word names a subcommand."""

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        if args and not args[0].startswith("-") and args[0] not in self.commands:
            args = ["run", *args]
        return super().parse_args(ctx, args)


def _write_handoff_with_analysis(
    conn: sqlite3.Connection, run_pair: str, paths: tuple[str, ...], output: Path
) -> None:
    """``report --handoff --analysis <file> ...``: the driver's document (compose_handoff) with
    each file's texts under the blocks it names, every changed_real finding a block — one no file
    names, or names with both texts empty, says the agent wrote nothing for it, and is listed
    after the line saying what was written. A file that cannot be read whole, an anchor named
    twice (in one file or across them) or one the hand-off does not hold writes nothing (an
    existing ``output`` is left as it is)."""
    from treasure_map.lib import review_driver as rd
    from treasure_map.lib.query import review_report as rr

    sources: list[tuple[str, dict[str, dict[str, str]]]] = []
    for path in paths:
        try:
            text = Path(path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise click.ClickException(
                f"{path}: the file could not be read as utf-8 text ({exc}); nothing was written"
            ) from exc
        texts, err = rd.parse_handoff_analysis(text, source="the file")
        if texts is None:
            raise click.ClickException(f"{path}: {err}; nothing was written")
        sources.append((path, texts))
    composed = rd.compose_handoff(conn, run_pair, sources)
    if isinstance(composed, rd.HandoffRefusal):
        if composed.kind == "twice":
            raise click.ClickException(
                f"{composed.source} names {composed.anchors[0][:200]!r} a second time (in this "
                "file or an earlier one); nothing was written"
            )
        raise click.ClickException(
            "\n".join(
                [
                    f"{composed.source} names {len(composed.anchors)} anchor(s) the hand-off does "
                    "not hold; nothing was written:",
                    *(f"  {rr.handoff_anchor_text(key)}" for key in composed.anchors),
                ]
            )
        )
    output.write_text(composed.document, encoding="utf-8")
    missing = composed.nothing_written
    counts = f"{composed.findings} findings" + (
        f"; the agent wrote nothing for {len(missing)} of them" if missing else ""
    )
    click.echo(
        f"wrote {output} ({counts})"
        + (
            ""
            if composed.must_read_complete
            else " — PARTIAL: must_read_complete is false, not the official hand-off"
        )
    )
    if missing:
        click.echo("the agent wrote nothing for:")
        for anchor in missing:
            click.echo(f"  {rr.handoff_anchor_text(anchor)}")


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
    "--analysis",
    "analysis_files",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False),
    help=(
        "A file of an agent's texts per finding "
        '({"findings": [{"anchor_ref", "hypotheses", "device_checks"}]}), written under each '
        "block; repeat for several files. Only with --handoff."
    ),
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
    analysis_files: tuple[str, ...],
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

    if analysis_files and not as_handoff:
        raise click.UsageError("--analysis goes with --handoff")
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
        if as_handoff and analysis_files:
            assert output is not None
            _write_handoff_with_analysis(conn, run_pair, analysis_files, Path(output))
            return
        if as_handoff:
            assert output is not None
            # The same staleness context and file-judgement reading the MCP get_diff_handoff
            # builds, so the file and the tool's pages are the same text.
            stamp, file_staleness = rr.local_handoff_context(conn)
            findings = rr.handoff_findings(conn, run_pair, file_staleness=file_staleness)
            open_items = rr.handoff_open_items(conn, run_pair, file_staleness=file_staleness)
            # Not gated: before the must-read set is done the file is written all the same, its
            # header saying it is a PARTIAL hand-off (the MCP tool serves none then).
            hrep = rr.handoff_report(conn, run_pair, file_staleness=file_staleness)
            text = (
                rr.handoff_header(run_pair, len(findings), hrep, open_items=len(open_items))
                + "".join(rr.handoff_blocks(conn, run_pair, findings, stamp=stamp))
                + "".join(rr.handoff_open_blocks(conn, run_pair, open_items))
            )
            Path(output).write_text(text, encoding="utf-8")
            click.echo(
                f"wrote {output} ({len(findings)} findings, {len(open_items)} open items)"
                + (
                    ""
                    if hrep["must_read_complete"]
                    else " — PARTIAL: must_read_complete is false, not the official hand-off"
                )
            )
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
            navigation=as_md or as_html,
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


@review.command(name="skill")
@click.option(
    "--install",
    "install_dir",
    default=None,
    type=click.Path(file_okay=False),
    help=(
        "A skills directory to write the skills into, as <dir>/"
        + diff_skill.SKILL_DIRNAME
        + "/SKILL.md and <dir>/"
        + scan_skill.SKILL_DIRNAME
        + "/SKILL.md (one of them with --diff or --scan), recorded so tmap init keeps them "
        "current and tmap uninstall removes them (an earlier tmap's file there is replaced; any "
        "other file only with --force)."
    ),
)
@click.option(
    "--force", is_flag=True, help="With --install: replace a file there that is not tmap's."
)
@click.option(
    "--scan",
    "as_scan",
    is_flag=True,
    help="The SCAN review skill (one firmware's candidate map): print it, or install it alone.",
)
@click.option(
    "--diff",
    "as_diff",
    is_flag=True,
    help="The DIFF review skill (the default to print): with --install, install it alone.",
)
def skill(install_dir: str | None, force: bool, as_scan: bool, as_diff: bool) -> None:
    """Print the agent skill for reviewing a run pair unit by unit (--scan: the one-firmware scan
    profile's skill instead), or write the skills into a skills directory — both, unless --diff or
    --scan names one."""
    if as_scan and as_diff:
        raise click.UsageError("--scan and --diff name one skill each; give at most one")
    if install_dir is None:
        click.echo(scan_skill.skill_text() if as_scan else diff_skill.skill_text(), nl=False)
        return
    from treasure_map.lib.errors import ConfigError
    from treasure_map.lib.setup import skills as sk
    from treasure_map.lib.setup.ledger import LEDGER_NAME, Ledger

    chosen = (sk.SCAN,) if as_scan else (sk.DIFF,) if as_diff else sk.SHIPPED

    home = Path.home()
    try:
        ledger = Ledger.load(home / ".treasure-map" / "toolchain" / LEDGER_NAME)
    except ConfigError as exc:
        raise click.ClickException(str(exc)) from exc
    for line in sk.recover(ledger):
        click.echo(line)
    # absolute, not resolved: the ledger names the file from any working directory, and a
    # directory reached through a link stays the one the earlier install recorded
    root = Path(install_dir).expanduser().absolute()
    known = [r for _n, r in sk.managed_roots(home, os.environ, ledger)]
    refused: list[str] = []
    # each skill on its own: one tmap will not write is said so, and the other is still written
    for chosen_skill in chosen:
        data = sk.shipped_bytes(chosen_skill)
        st = sk.classify(root, chosen_skill, ledger, data, known=known)
        if st.state == "aligned":
            click.echo(f"{st.path} is already current")
            continue
        if st.state == "foreign" and not force:
            refused.append(f"{st.path}: {st.detail}; not replaced — {sk.next_step(st)}")
            continue
        if st.state == "invalid" and not force:
            refused.append(f"{st.path}: {st.detail}; not replaced (--force replaces it)")
            continue
        # Recorded wherever it goes: tmap init keeps tmap's copy there current, tmap uninstall
        # takes it back.
        try:
            sk.install(
                st.path,
                data,
                ledger,
                claude_config_dir=sk.claude_config_dir_of(root, home, os.environ),
            )
        except OSError as exc:
            refused.append(f"could not write {st.path}: {exc}")
            continue
        click.echo(f"wrote {st.path}")
    if refused:
        raise click.ClickException("\n".join(refused))


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


def _handoff_held(
    result: Any, atlas: str, run_a: str, run_b: str, k: int | None, staleness: dict[str, Any]
) -> str | None:
    """Why the driver writes no hand-off, or None: the drive stopped at a limit, a unit failed, or
    the must-read set is not done at the default k (the official hand-off's bar, the same the MCP
    get_diff_handoff holds) — read again at the default k when this drive worked at another."""
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.query import review_units as ru

    if not result.finished:
        return (
            f"the review is not done ({result.stopped}); re-run without a limit, then write the "
            "hand-off"
        )
    if result.failed:
        return f"{len(result.failed)} unit(s) failed; the review is not done"
    kk = ru.DEFAULT_K if k is None else k
    if result.offer is not None and result.offer["must_read_complete"] and kk == ru.DEFAULT_K:
        return None
    conn = open_atlas(Path(atlas))
    try:
        rep = ru.review_pair(
            conn, run_a, run_b, k=ru.DEFAULT_K, pair_staleness=staleness, server_commit=None
        ).report
    finally:
        conn.close()
    if rep["must_read_complete"]:
        return None
    mr, nr = rep["must_read"], rep["not_reachable"]
    return (
        f"must_read_complete false at the default k={ru.DEFAULT_K} (must-read left "
        f"{mr['members'] - mr['members_disposed']}, withheld diffs {len(nr['withheld_diffs'])}, "
        f"failed diffs {len(nr['failed_diffs'])}, judged unread {rep['judged_unread']['count']}, "
        f"reduce owed {rep['reduce']['owed']}); tmap review report --handoff writes a partial one "
        "for a person"
    )


@review.command(name="run")
@click.argument("run_pair")
@click.option(
    "--agent",
    "agent",
    required=True,
    help=(
        "A preset (claude-code; experimental: codex, cursor) or a command template holding "
        "{prompt} (also {mcp_config}, {workdir}, {atlas}, {unit_id}, {run_pair}). {workdir} is a "
        "temporary directory removed when the command exits — a template that writes anything "
        "worth keeping must put it elsewhere. A template or an experimental preset runs only "
        "after its probe passes."
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
    "--until",
    "until",
    default="must_read",
    show_default=True,
    type=click.Choice(["must_read", "complete"]),
    help="must_read: hand out the must-read units only, then stop and say how much of the second "
    "tier is unread; complete: the second tier too, after them.",
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
    until: str,
    handoff_out: str | None,
    atlas_db: str | None,
) -> None:
    """Review RUN_PAIR unit by unit, one launch of your agent per unit: tmap runs the loop and
    calls no model itself. A unit counts only when the overlay's history holds a judgement naming
    it for every member. Ends when no unit is left, or at a limit. By default only the must-read
    units are handed out (--until must_read); --until complete hands out the second tier too."""
    import shutil
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
        # Fail before driving: an experimental preset's result is read differently and is not
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
    try:
        deadline = timeout or rd.DEFAULT_TIMEOUT
        click.echo(f"probing {preset.name} ({preset.note or 'preset'}) …")
        pr = rd.probe(
            preset,
            atlas_path=Path(atlas),
            workdir=workdir,
            timeout=min(deadline, 300),
            handoff=handoff_out is not None,
        )
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
            until=until,
        )
        click.echo(
            f"units tried {result.units_tried}, done {result.units_done}, failed "
            f"{len(result.failed)} — {result.stopped}"
        )
        for f in result.failed:
            click.echo(
                f"  failed {f['unit_id']} ({f['kind']}): {f['written']}/{f['members']} written"
            )
        if result.statement:
            click.echo(result.statement)
        if result.offer is not None:
            second = result.offer["second_tier"]
            click.echo(
                f"second tier: {second['members']} member(s) in {second['units']} unit(s) not "
                f"judged (by bucket {second['by_bucket']}, {second['due_recheck']} due a re-check)"
                + (" — read them with --until complete" if result.offer["continue_with"] else "")
                + f"; must_read_complete {result.offer['must_read_complete']}, complete "
                f"{result.offer['complete']}"
            )
        if handoff_out is not None:
            held = _handoff_held(result, atlas, run_a, run_b, k, staleness)
            if held is not None:
                click.echo(f"hand-off skipped: {held}")
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
                        f"wrote {ho['out_file']} ({ho['bytes']} bytes, "
                        f"{ho.get('findings')} findings"
                        + (f"; the agent wrote nothing for {gap} of them)" if gap else ")")
                    )
                else:
                    click.echo(f"hand-off failed: {ho['error']}")
        if result.failed:
            raise SystemExit(3)
    finally:
        # Every exit leaves nothing behind: the probe-only return, a failed probe, an
        # interrupt, and the SystemExit a failed unit raises. The directory holds the
        # generated mcp.json and the probe's marker file, nothing a later run reads.
        shutil.rmtree(workdir, ignore_errors=True)


# ── the scan profile ────────────────────────────────────────────────────────────────────────────
# A second profile under the SAME command, because it answers the same question of a different
# scope: which of these must be read, how far has the reading come, and what is still unread. It is
# not a new command — `tmap review scan` — and it reuses the batch driver, the sharding and the
# unit primitives; what it does not reuse is anything shaped like a run pair (see
# lib/query/scan_review for which is which).


def _open_run(atlas_db: str | None, run_id: str) -> tuple[sqlite3.Connection, str]:
    """Open the atlas and check it holds ``run_id``."""
    from treasure_map.cli.mcp_cli import _resolve_mcp_target
    from treasure_map.lib.atlas.connection import open_atlas

    atlas, _ = _resolve_mcp_target(atlas_db, None)
    if not Path(atlas).is_file():
        raise click.ClickException(f"no atlas at {atlas}: pass --atlas <path to atlas.db>")
    conn = open_atlas(Path(atlas))
    row = conn.execute("SELECT 1 FROM instance WHERE source_run_id = ? LIMIT 1", (run_id,))
    if row.fetchone() is None:
        conn.close()
        raise click.ClickException(
            f"run {run_id!r} has no candidate in this atlas (tmap list-runs for the run ids)"
        )
    return conn, str(atlas)


@review.command(name="scan")
@click.argument("run_id")
@click.option(
    "--agent",
    "agent",
    default=None,
    help=(
        "Run the batch driver with this agent instead of printing the declaration: a preset "
        "(claude-code; experimental: codex, cursor) or a command template holding {prompt} (also "
        "{mcp_config}, {workdir}, {atlas}, {unit_id}, {run_pair} — the run id, for a scan). "
        "{workdir} is a temporary directory removed when the command exits."
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
    help="Retries of a unit that did not judge every candidate (default 2).",
)
@click.option("--worker", default=None, type=click.IntRange(0, None), help="This shard's index.")
@click.option("--workers", default=None, type=click.IntRange(1, None), help="How many shards.")
@click.option(
    "--until",
    "until",
    default="must_read",
    show_default=True,
    type=click.Choice(["must_read", "complete"]),
    help="must_read: hand out tier 1 only, then stop and say how much of the second tier is "
    "unread; complete: the second tier too, after it.",
)
@click.option("--atlas", "atlas_db", default=None, help="Atlas DB path.")
def scan(
    run_id: str,
    agent: str | None,
    probe_only: bool,
    max_units: int | None,
    max_minutes: float | None,
    timeout: int | None,
    retries: int | None,
    worker: int | None,
    workers: int | None,
    until: str,
    atlas_db: str | None,
) -> None:
    """One firmware scan's review: the four bands, the two tiers, the units they are handed out
    in, and what is still unread.

    Without --agent this prints the coverage declaration and nothing else (read-only). With it,
    tmap runs the batch driver: one launch of your agent per unit, until none is left — the same
    loop, retry policy and sharding as a run pair's review. Reading a candidate means calling
    explain_candidate on it; a verdict written before that reads needs_recheck.
    """
    import shutil
    import tempfile

    from treasure_map.lib import review_driver as rd
    from treasure_map.lib.query import scan_review as sr

    if (worker is None) != (workers is None):
        raise click.UsageError("--worker and --workers go together")
    if worker is not None and workers is not None and worker >= workers:
        raise click.UsageError(f"--worker must be below --workers ({workers})")
    conn, atlas = _open_run(atlas_db, run_id)
    try:
        if agent is None:
            review = sr.review_run(conn, run_id)
            dec = sr.declaration(
                review,
                worker=worker,
                workers=workers,
                drive_with=f"tmap review scan {run_id} --agent <preset | template>",
            )
            click.echo(sr.declaration_text(dec))
            return
    finally:
        conn.close()
    try:
        preset = rd.preset_or_template(agent)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    workdir = Path(tempfile.mkdtemp(prefix="tmap-scan-"))
    try:
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
        result = rd.scan_drive(
            Path(atlas),
            run_id,
            preset,
            workdir=workdir,
            worker=worker,
            workers=workers,
            max_units=max_units,
            max_minutes=max_minutes,
            timeout=deadline,
            retries=rd.DEFAULT_RETRIES if retries is None else retries,
            echo=click.echo,
            until=until,
        )
        click.echo(
            f"units tried {result.units_tried}, done {result.units_done}, failed "
            f"{len(result.failed)} — {result.stopped}"
        )
        for f in result.failed:
            click.echo(
                f"  failed {f['unit_id']} ({f['kind']}): {f['written']}/{f['members']} written"
            )
        if result.statement:
            click.echo(result.statement)
        if result.offer is not None:
            click.echo(sr.declaration_text(result.offer))
        if result.failed:
            raise SystemExit(3)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
