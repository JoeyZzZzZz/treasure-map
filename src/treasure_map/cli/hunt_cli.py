# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""CLI wrappers for the analyzers (A1 diff-driven, A2 pattern-driven) and atlas views.

Thin Click wrappers only — all logic lives in lib/hunt/ and lib/query/. A small set of
top-level commands; not a file-per-analyzer.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

if TYPE_CHECKING:
    from treasure_map.lib.atlas.models import RunRow
    from treasure_map.lib.query import CandidateExplanation, TriageCandidate

logger = logging.getLogger(__name__)


def _complete_workspace(ctx: click.Context, param: click.Parameter, incomplete: str) -> list[Any]:
    """Shell completion for ``scan -w``: existing workspace names under the configured base.

    A convenience for re-scanning an existing workspace without a typo; a brand-new name is still
    accepted (completion suggests, never restricts). Best-effort and side-effect-free — any failure
    yields no suggestions rather than an error (a completion helper must never crash the shell)."""
    from click.shell_completion import CompletionItem

    try:
        from treasure_map.lib.config.config import load_config
        from treasure_map.lib.workspace.resolver import list_workspace_names

        names = list_workspace_names(load_config(None).workspace_dir)
    except Exception:
        return []
    return [CompletionItem(n) for n in names if n.startswith(incomplete)]


def _complete_run_id(ctx: click.Context, param: click.Parameter, incomplete: str) -> list[Any]:
    """Shell completion for a run-id argument: the run names already recorded in the atlas.

    Honors a ``--atlas`` value already parsed into the context (so completion targets the same atlas
    the command will use), else the configured atlas. Opens the atlas READ-ONLY (no create/migrate
    side effects) and lists list_runs' run_ids. Absent atlas or any error -> no suggestions, never a
    crash. This is the ONE run-id completer (the former ``_complete_run_ids`` duplicate was merged
    in, keeping this read-only open over its migrating one so a tab-press never mutates it)."""
    import sqlite3

    from click.shell_completion import CompletionItem

    try:
        from treasure_map.lib.config.config import load_config
        from treasure_map.lib.query import list_runs

        override = ctx.params.get("atlas_path") if ctx is not None else None
        atlas = Path(override) if override else load_config(None).atlas.db_path
        if not atlas.exists():
            return []
        conn = sqlite3.connect(f"file:{atlas}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            ids = [r.run_id for r in list_runs(conn) if r.run_id]
        finally:
            conn.close()
    except Exception:
        return []
    return [CompletionItem(i) for i in ids if i.startswith(incomplete)]


def _echo_legal_notice(*, as_json: bool = False) -> None:
    """Print the intended-use / legal reminder to stderr (skipped under --json).

    stderr keeps stdout clean; skipping it under --json keeps machine output free of any
    framing. Substance lives in lib.notice so this wrapper carries no banned vocabulary into
    the scanned CLI module."""
    if as_json:
        return
    from treasure_map.lib.notice import LEGAL_NOTICE

    click.echo(LEGAL_NOTICE, err=True)
    click.echo("", err=True)


def _echo_single_diff(summary: Any, resolved_atlas: Path) -> None:
    """Print one binary's diff result (the --binary or single-binary path)."""
    for w in summary.warnings:
        click.echo(f"warning: {w}", err=True)
    click.echo(f"Atlas: {resolved_atlas}")
    click.echo(f"  diff_id       : {summary.diff_id}")
    click.echo(f"  binary        : {summary.binary}")
    click.echo(f"  matched_pairs : {summary.matched_pairs}")
    click.echo(f"  version_skew  : {summary.version_skew}")
    click.echo(
        "  delta         : "
        f"layer_changed={summary.delta_layer_changed}, "
        f"layer_unchanged={summary.delta_layer_unchanged}, "
        f"delta_undetermined={summary.delta_undetermined}"
    )
    click.echo(
        "Read the deltas: get_diff_deltas / get_diff_meta / get_function_alignment / "
        "get_diff_capabilities"
    )


def _echo_full_diff(fsum: Any, resolved_atlas: Path) -> None:
    """Print a full diff's roll-up: what was diffed vs skipped, and per-binary success/failure."""
    plan = fsum.plan
    click.echo(f"Atlas: {resolved_atlas}")
    if fsum.cancelled:
        click.echo(f"Cancelled — {len(plan.changed)} changed binaries not diffed.")
        return
    if not plan.changed:
        click.echo("No changed binaries between the two runs (nothing to diff).")
    ok = [o for o in fsum.outcomes if o.error is None]
    failed = [o for o in fsum.outcomes if o.error is not None]
    click.echo(
        f"  binaries      : {len(plan.changed)} changed (diffed), {len(plan.unchanged)} unchanged "
        f"(skipped), only-in-A {len(plan.only_in_a)}, only-in-B {len(plan.only_in_b)}"
    )
    click.echo(f"  diffed        : {len(ok)} ok, {len(failed)} failed")
    for o in failed:
        click.echo(f"    - {o.binary}: {o.error}")
    if plan.changed:
        click.echo("Read the deltas: list_diffs, then get_diff_deltas / get_diff_meta")


@click.command(
    "diff", short_help="Compare two firmware runs (all changed binaries, or one with --binary)"
)
@click.argument("run_a_id", shell_complete=_complete_run_id)
@click.argument("run_b_id", shell_complete=_complete_run_id)
@click.option(
    "--binary",
    "binary_name",
    default=None,
    help="Diff only this ONE binary (short name). Omitted (the default) diffs EVERY binary whose "
    "content changed between the two runs — the cross-binary view is tmap diff's unique value; a "
    "single binary you can already do in Ghidra.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Run even when the two runs used different tmap/Ghidra versions -- every delta will then "
    "be version_skew undetermined (the result stays honestly degraded).",
)
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to config.yaml (overrides ~/.treasure-map/config.yaml).",
)
@click.option(
    "--atlas",
    "atlas_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Atlas DB path (defaults to the configured atlas.db_path).",
)
def hunt_diff(
    run_a_id: str,
    run_b_id: str,
    binary_name: str | None,
    force: bool,
    config: Path | None,
    atlas_path: Path | None,
) -> None:
    """Diff two runs through the map-model pipeline, in a single command.

    RUN_A_ID / RUN_B_ID are run ids (a run id is scan's --run-id, default = the -w workspace name),
    NOT paths; tab-completion lists this atlas's runs. By default diffs every binary that changed
    between the two runs (serially, with progress); ``--binary NAME`` focuses one. Drives the
    external aligner end-to-end (BinExport -> BinDiff, you never touch an intermediate file), then
    writes alignment facts and tri-state dimension deltas to the atlas. A delta is a PROJECTION of
    existing annotations, never a change/defect verdict -- read it with the get_diff_* MCP tools
    (list_diffs to browse, then get_diff_deltas) and judge it yourself.
    """
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.config.config import load_config
    from treasure_map.lib.diff.driver import (
        _FULL_DIFF_CONFIRM_THRESHOLD,
        run_full_diff,
        run_version_diff,
    )
    from treasure_map.lib.errors import TreasureMapError

    cfg = load_config(config)
    resolved_atlas = atlas_path if atlas_path is not None else cfg.atlas.db_path

    def _confirm(n: int) -> bool:
        if n <= _FULL_DIFF_CONFIRM_THRESHOLD:
            return True
        mins = max(1, round(n * 20 / 60))
        return click.confirm(
            f"Will diff {n} changed binaries (~{mins} min, serial); --binary <name> does just one. "
            "Continue?",
            default=False,
        )

    def _on_outcome(i: int, total: int, outcome: Any) -> None:
        if outcome.error is not None:
            click.echo(f"  [{i}/{total}] {outcome.binary}: FAILED — {outcome.error}")
        else:
            s = outcome.summary
            click.echo(
                f"  [{i}/{total}] {outcome.binary}: {s.delta_layer_changed} changed / "
                f"{s.delta_layer_unchanged} unchanged / {s.delta_undetermined} undetermined"
            )

    atlas = open_atlas(Path(resolved_atlas))
    try:
        if binary_name is not None:
            single = run_version_diff(
                atlas, run_a_id, run_b_id, binary_name, config=cfg, force=force
            )
            full = None
        else:
            single = None
            full = run_full_diff(
                atlas,
                run_a_id,
                run_b_id,
                config=cfg,
                force=force,
                confirm=_confirm,
                on_outcome=_on_outcome,
            )
    except TreasureMapError as exc:
        raise click.ClickException(f"{type(exc).__name__}: {exc}") from exc
    finally:
        atlas.close()

    if single is not None:
        _echo_single_diff(single, resolved_atlas)
    else:
        _echo_full_diff(full, resolved_atlas)


@click.command("hunt", short_help="Match suspicious call-chains only (scan's 2nd stage)")
@click.argument("db", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--run-id", required=True, help="Neutral per-run id (the device_spread unit).")
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to config.yaml (overrides ~/.treasure-map/config.yaml).",
)
@click.option(
    "--atlas",
    "atlas_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Atlas DB path (defaults to the configured atlas.db_path).",
)
def hunt_pattern(
    db: Path,
    run_id: str,
    config: Path | None,
    atlas_path: Path | None,
) -> None:
    """Scan one analysis.db for call-sequence shape candidates and write atlas instances.

    Hermetic (no LLM / no key needed). OSS is excluded at scan time. Writes graded leads at
    provenance L0/L1 only; every instance is a candidate/lead, not a confirmed result.
    """
    from treasure_map.lib.config.config import load_config
    from treasure_map.lib.hunt import run_analyzer2
    from treasure_map.lib.last_run import write_last_run

    cfg = load_config(config)
    resolved_atlas = atlas_path if atlas_path is not None else cfg.atlas.db_path
    stats = run_analyzer2(db, resolved_atlas, source_run_id=run_id)
    # Record this as the last run so `tmap mcp` can serve it without explicit paths.
    write_last_run(db, resolved_atlas, run_id)

    click.echo(f"Atlas: {resolved_atlas}")
    click.echo(f"  Functions scanned : {stats.scanned}")
    click.echo(f"  Shape candidates  : {stats.matches}")
    click.echo(f"  Instances written : {stats.instances_written}")
    click.echo(f"  OSS binaries excluded : {stats.oss_excluded}")
    click.echo(
        "  By reachability   : "
        f"confirmed={stats.by_status.get('confirmed', 0)}, "
        f"blocked={stats.by_status.get('blocked', 0)}, "
        f"unknown={stats.by_status.get('unknown', 0)}"
    )
    if stats.data_gap_skipped:
        # Honesty flag: the candidate set is incomplete — these matches had no decompilable body.
        click.echo(
            f"  Data-gap skipped  : {stats.data_gap_skipped} "
            "(shape matches with no decompilable body — candidate set is INCOMPLETE)"
        )
    if stats.fmt_wrapper_unknown_source_demoted:
        # Not a recall flag: these candidates are IN the set, just ranked below a controllable
        # source. Shown so the reader knows how much of the fmt axis rests on an unknown.
        click.echo(
            f"  fmt-wrapper demote: {stats.fmt_wrapper_unknown_source_demoted} "
            "(fmt wrapper candidates KEPT but ranked low — forwarded source unknown)"
        )
    if stats.nvram_flows_written:
        click.echo(f"  nvram key-flow    : {stats.nvram_flows_written} ops flattened")
    if stats.nvram_wrapper_edges:
        click.echo(
            f"  nvram wrapper edge: {stats.nvram_wrapper_edges} indirect key edges (via wrappers)"
        )
    if stats.nvram_defaults_written:
        click.echo(
            f"  router_defaults   : {stats.nvram_defaults_written} web-settable default keys"
        )
    if stats.web_form_fields_written:
        click.echo(
            f"  web form fields   : {stats.web_form_fields_written} editable front-end fields"
        )
    click.echo(
        "Note: every instance is a candidate/lead, not a confirmed result. With one firmware "
        "device_spread stays ~1 — cross-device spread needs more devices (future)."
    )


_DEFAULT_TOP = 20


def _effective_top(top_n: int | None, *, show_all: bool, sink: str | None) -> int | None:
    """Resolve the row cap. --all (or --sink, which surfaces one sink in full) lifts the cap;
    an explicit --top wins; otherwise the default 20 keeps the list scannable."""
    if show_all:
        return None
    if top_n is not None:
        return top_n
    if sink is not None:
        return None
    return _DEFAULT_TOP


def _parse_dim_filters(specs: tuple[str, ...]) -> list[tuple[str, str]]:
    """Parse repeated --filter ``dim=value`` options into (dim, value) pairs; malformed skipped."""
    out: list[tuple[str, str]] = []
    for spec in specs:
        d, sep, v = spec.partition("=")
        if sep and d.strip() and v.strip():
            out.append((d.strip(), v.strip()))
    return out


def _lens_label(
    base: str,
    *,
    view: str | None,
    sort_by: str | None,
    dim_filters: list[tuple[str, str]],
    impact_order: str | None,
) -> str:
    """The current-lens label: the base default plus any active view / spine / filter / order so a
    reader always sees exactly which lens produced this ordering."""
    parts: list[str] = []
    if view:
        parts.append(f"view={view}")
    if sort_by:
        parts.append(f"spine={sort_by}")
    if dim_filters:
        parts.append("filter=" + ",".join(f"{d}={v}" for d, v in dim_filters))
    if impact_order:
        parts.append(f"impact-order={impact_order}")
    return base if not parts else f"{base}  [{' ; '.join(parts)}]"


# Display a dimension's value compactly: the concrete reading, or a bare '?' when unknown so a
# not-established layer never reads as a value. Shared by the list row and the JSON row.
def _dv(c: TriageCandidate, name: str, *, unknown_as: str = "?") -> str:
    d = c.dim(name)
    return unknown_as if d.state == "unknown" else d.value


class _OnlyRefused(click.ClickException):
    """An ``--only`` prune refused on a non-reducible dimension. Exits 2 (not the generic 1) so
    automation / an agent can distinguish a refusal from success (0) and other failures (1)."""

    exit_code = 2


def _render_triage(
    candidates: list[TriageCandidate],
    *,
    run_label: str,
    lens_label: str,
    caveats: tuple[str, ...],
    top_n: int | None,
    status: str | None,
    sink: str | None,
    include_gated: bool,
    as_json: bool,
    corpus_size: int | None = None,
    filter_note: str | None = None,
) -> None:
    """Render the candidate map under the current lens. Shared by `tmap triage` and `tmap scan`.

    ``corpus_size`` is the full corpus count (the invariant total); when an ``--only`` sweep has
    reduced the displayed view below it, the header shows ``corpus N · sweep shows M``. Absent (or
    equal to the shown count), the header reads ``N candidates`` as before. ``filter_note`` is the
    circle-and-weight ``--filter`` line (match count while the corpus stays whole).

    candidates arrives already projected into the active lens (apply_view sorted+filtered it). The
    row number # is the position in THAT lens order, so #N is safe to pass to --explain (which
    resolves it under the same lens). There is no score column — each row shows its dimension
    layers' three-state. top_n is None for an untruncated (full) view."""
    import json

    from treasure_map.lib.query import impact_tier as _impact_tier
    from treasure_map.lib.query import shown_statuses as _shown_statuses
    from treasure_map.lib.query import sink_matches as _sink_matches

    tier_name = {3: "hi", 2: "med", 1: "lo", 0: "?"}

    counts = {"reachable": 0, "to-verify": 0, "gated": 0}
    for c in candidates:
        counts[c.review_status] = counts.get(c.review_status, 0) + 1

    # Rank over the lens-ordered list, before the status/sink visibility fold + truncation.
    ranked = list(enumerate(candidates, 1))  # [(rank, candidate), ...]
    visible_statuses = _shown_statuses(status, include_gated=include_gated, sink=sink)
    visible = [
        (r, c)
        for r, c in ranked
        if c.review_status in visible_statuses and (sink is None or _sink_matches(c, sink))
    ][:top_n]

    if as_json:
        click.echo(
            json.dumps(
                [
                    {
                        "rank": r,
                        "function": c.function,
                        "sink_class": c.sink_class,
                        "sink_anchor": c.sink_anchor,
                        "nvram_source_key": c.nvram_source_key,
                        "dimensions": [
                            {
                                "name": d.name,
                                "state": d.state,
                                "value": d.value,
                                "source": d.source,
                                "note": d.note,
                            }
                            for d in c.dimensions
                        ],
                        "review_status": c.review_status,
                        "reachability_status": c.reachability_status,
                        "source_class": c.source_class,
                        "blocking_mechanism": c.blocking_mechanism,
                        "exposure_shape": c.exposure_shape,
                        "origin": c.origin,
                        "source_run_id": c.source_run_id,
                        "evidence_ref": c.evidence_ref,
                        "binary_path": c.binary_path,
                    }
                    for r, c in visible
                ],
                indent=2,
            )
        )
        return

    counts_str = (
        f"{counts['reachable']} reachable, {counts['to-verify']} to-verify, {counts['gated']} gated"
    )
    if corpus_size is not None and corpus_size != len(candidates):
        # --only prune: the corpus stays whole, the sweep is a reduced VIEW (its own honest header,
        # never the "never reduce" footer's promise).
        click.echo(
            f"triage: {run_label}   (corpus {corpus_size} · sweep shows {len(candidates)} "
            f"(pruned view): {counts_str})"
        )
    else:
        click.echo(f"triage: {run_label}   ({len(candidates)} candidates: {counts_str})")
    click.echo(f"  lens: {lens_label}")
    if filter_note is not None:
        click.echo(f"  {filter_note}")
    if sink is not None:
        click.echo(f"  filter: sink = {sink}   ({len(visible)} shown, all statuses)")
    elif top_n is not None and len(candidates) > top_n:
        click.echo(f"  showing top {top_n} of {len(candidates)} — use --all or --sink to see more")
    click.echo(
        "  #   sink(impact)   ctrl        reach   filter  writer      function (evidence_ref)"
    )
    for r, c in visible:
        sink_tag = f"{c.sink_class}/{tier_name.get(_impact_tier(c.sink_class), '?')}"
        click.echo(
            f"  {r:<3} {sink_tag:<14} {_dv(c, 'controllability'):<11} "
            f"{_dv(c, 'reachability'):<7} {_dv(c, 'filtering'):<7} {_dv(c, 'writer'):<11} "
            f"{c.function or '?'} ({c.evidence_ref or '?'})"
        )
        # Where to open it: the binary's full path, read straight from the atlas so a candidate
        # stays locatable even if its analysis.db is gone.
        loc = f"        in: {c.binary_path or '?'}"
        if c.nvram_source_key:
            loc += f"   nvram_source_key={c.nvram_source_key}"
        # the orthogonal source=param signal (A2 external_input) — surfaced here so the human list
        # carries it too, not only the MCP compact row / explain (contract C6 guardrail 2).
        if c.dim("source").value == "param":
            loc += "   source=param"
        click.echo(loc)
    if "gated" not in visible_statuses and counts["gated"]:
        click.echo(f"\n  (gated: {counts['gated']} hidden; --include-gated to show)")
    click.echo("\ncaveats (this map is honest but low-resolution — do not read it as complete):")
    for cav in caveats:
        click.echo(f"  - {cav}")
    click.echo(
        "\nNote: candidates are leads for manual review, arranged by the current lens (switch it "
        "with --sort-by / --view / --filter) — NOT confirmed results, and the list is re-ranked, "
        "never reduced."
    )


# Glyph = certainty bucket: ✓ proven (a positive proof) · ~ soft (likely / structural: a lead, NOT
# a proof) · ✗ excluded (ruled out) · ? unknown (not established). ``likely`` and ``structural`` map
# to the SAME ~ so a reader never mistakes an optimistic/structural lead for the ✓ of a proof.
_STATE_GLYPH = {"proven": "✓", "likely": "~", "structural": "~", "excluded": "✗", "unknown": "?"}


def _render_explain(ex: CandidateExplanation, *, as_json: bool) -> None:
    """Render one candidate's dimension layers, honest caveats, bounds, and verify checklist.

    Presents each layer's three-state (state / value / source / note) — no score. It does not
    declare the candidate real and prints no triggering input. Shared shape for human and --json."""
    import json

    c = ex.candidate
    if as_json:
        click.echo(
            json.dumps(
                {
                    "evidence_ref": c.evidence_ref,
                    "function": c.function,
                    "review_status": c.review_status,
                    "reachability_status": c.reachability_status,
                    "lens_label": ex.lens_label,
                    "caveats": list(ex.caveats),
                    "controllability": ex.controllability,
                    "sink_impact": ex.sink_impact,
                    # honest state:value siblings — a bare "free" alone loses the likely state
                    "controllability_labeled": ex.controllability_labeled,
                    "sink_impact_labeled": ex.sink_impact_labeled,
                    "dimensions": [
                        {
                            "name": d.name,
                            "state": d.state,
                            "value": d.value,
                            "source": d.source,
                            "note": d.note,
                        }
                        for d in ex.dimensions
                    ],
                    "structure": {
                        "source_class": c.source_class,
                        "source_kind": c.source_kind,
                        "sink_class": c.sink_class,
                        "sink_anchor": c.sink_anchor,
                        "nvram_source_key": c.nvram_source_key,
                        "call_sequence_shape": ex.call_sequence_shape,
                        "blocking_mechanism": c.blocking_mechanism,
                        "exposure_shape": c.exposure_shape,
                        "origin": c.origin,
                        "binary_path": c.binary_path,
                    },
                    "sink_arg_provenance_summary": list(ex.sink_arg_provenance_summary),
                    "claims_does": list(ex.claims_does),
                    "claims_does_not": list(ex.claims_does_not),
                    "verify": list(ex.verify_steps),
                },
                indent=2,
            )
        )
        return

    click.echo(
        f"explain: {c.evidence_ref}   function {c.function or '?'}   "
        f"sink_class={c.sink_class} ({c.sink_anchor or '?'})"
    )
    click.echo(f"\nlens: {ex.lens_label}")
    click.echo("\ndimension layers (state / value / source):")
    for d in ex.dimensions:
        glyph = _STATE_GLYPH.get(d.state, "?")
        click.echo(f"  {glyph} {d.name:<18} = {d.value:<16} [{d.source}]")
        if d.note:
            click.echo(f"      {d.note}")

    click.echo("\nstructure:")
    click.echo(f"  source_class = {c.source_class}")
    click.echo(f"  source_kind  = {c.source_kind}")
    if c.nvram_source_key:
        click.echo(f"  nvram_key    = {c.nvram_source_key}")
    click.echo(f"  sink         = {c.sink_anchor or '?'} ({c.sink_class})")
    click.echo(f"  shape        = {ex.call_sequence_shape or '?'}")
    click.echo(f"  function     = {c.function or '?'}")
    click.echo(f"  binary       = {c.binary_path or '?'}   (open this in the decompiler)")

    click.echo("\nin-function dataflow & filter:")
    click.echo(f"  {_reachability_inline(c.reachability_status)}")
    click.echo(f"  filter: {c.blocking_mechanism or 'none identified'}")
    if c.exposure_shape:
        # A danger SHAPE (e.g. bare_sink), not a mitigation — shown on its own line so it is never
        # read as a filter that blocks the value.
        click.echo(f"  exposure shape: {c.exposure_shape} (danger form, not a mitigation)")

    if ex.sink_arg_provenance_summary:
        click.echo("\nsink-arg provenance (def-use; get_sink_provenance for full detail):")
        for sp in ex.sink_arg_provenance_summary:
            extra = ""
            if sp.get("nearest_dominating_writer"):
                extra = f"   nearest_dominating_writer={sp['nearest_dominating_writer']}"
            elif sp.get("writer_count") is not None:
                extra = f"   writers={sp['writer_count']}"
            mark = "" if sp.get("resolved") else "   [unresolved — a boundary, not 'safe']"
            click.echo(
                f"  [{sp.get('sink_idx')}] {sp.get('sink') or '?'}@{sp.get('sink_addr') or '?'} "
                f"kind={sp.get('kind')}{extra}{mark}"
            )

    click.echo("\ncaveats (honest but low-resolution — do not read the map as complete):")
    for cav in ex.caveats:
        click.echo(f"  - {cav}")

    click.echo("\nwhat this view does / does NOT claim:")
    for line in ex.claims_does:
        click.echo(f"  DOES: {line}")
    for line in ex.claims_does_not:
        click.echo(f"  DOES NOT: {line}")

    click.echo("\nverify (manual — anchors point back to the source function):")
    for i, step in enumerate(ex.verify_steps, 1):
        click.echo(f"  {i}. {step}")

    click.echo(
        "\nNote: this presents the candidate's dimension layers and where to verify it — it does "
        "NOT confirm a real issue and prints no triggering input."
    )


def _reachability_inline(status: str) -> str:
    if status == "confirmed":
        return (
            "a source->sink flow was seen within ONE function (L1 at most) — not caller-confirmed, "
            "not cross-function"
        )
    if status == "blocked":
        return "a filter/guard was identified on the in-function path"
    return "not shown reachable within the function (a lead to verify)"


def _run_lineage_line(r: RunRow) -> str:
    """One human line of a run's lineage (M8a/M8c): id + status + scan date + build + counts.

    A run with no lineage row (a pre-existing scan) is shown but flagged — never hidden."""
    if not r.resolved:
        return f"{r.run_id}   [no lineage row — pre-existing scan; re-scan to record it]"
    parts = [r.run_id, r.scan_status or "unknown"]
    if r.scanned_at:
        parts.append(f"scanned {str(r.scanned_at).split(' ')[0]}")
    if r.build_hash:
        parts.append(f"build {r.build_hash}")
    if r.binaries is not None or r.functions is not None:
        parts.append(f"{r.binaries or 0} bins / {r.functions or 0} fns")
    return "   ".join(parts)


def _echo_run_lineage(atlas_path: Path, selected_run: str | None) -> None:
    """Print the run's scan lineage at the top of a CLI view (M8c) — the stale-scan guard.

    When scoped to one run, print its lineage line so its build/date/status is in front of the
    reader (a stale scan is otherwise silent); unscoped, print the run count + how to scope.
    Best-effort: any read failure is silent (a lineage banner never breaks the command)."""
    try:
        from treasure_map.lib.atlas.connection import open_atlas
        from treasure_map.lib.query import get_run as run_get_run
        from treasure_map.lib.query import list_runs as run_list_runs

        conn = open_atlas(atlas_path)
        try:
            if selected_run is not None:
                r = run_get_run(conn, selected_run)
                if r is not None:
                    click.echo(f"run: {_run_lineage_line(r)}")
                    return
            n = len(run_list_runs(conn))
        finally:
            conn.close()
    except Exception:
        return
    click.echo(f"atlas: {n} run(s) — `tmap runs` for lineage, --run <id> to scope")


@click.command("runs", short_help="List scanned firmware runs")
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to config.yaml (overrides ~/.treasure-map/config.yaml).",
)
@click.option(
    "--atlas",
    "atlas_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Atlas DB path (defaults to the configured atlas.db_path).",
)
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit structured JSON.")
def runs(config: Path | None, atlas_path: Path | None, as_json: bool) -> None:
    """List every firmware run (scan) in the atlas with its lineage.

    Each run shows its scan_status (in_progress / complete / partial / failed / unknown), build
    hash (the extraction pass_version — a differing build for the same firmware means a STALE
    scan), scan date, and binary/function counts. Use a run id here as ``--run`` for ``tmap
    triage`` or as run_id for the MCP fact tools. A run with no lineage row (a pre-existing scan) is
    shown but flagged, never hidden."""
    import json
    from dataclasses import asdict

    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.config.config import load_config
    from treasure_map.lib.query import list_runs as run_list_runs

    cfg = load_config(config)
    resolved_atlas = atlas_path if atlas_path is not None else cfg.atlas.db_path
    conn = open_atlas(resolved_atlas)
    try:
        run_rows = run_list_runs(conn)
    finally:
        conn.close()
    if as_json:
        click.echo(json.dumps([asdict(r) for r in run_rows], indent=2, default=str))
        return
    if not run_rows:
        click.echo("no runs in this atlas yet — run `tmap scan <firmware>` first.")
        return
    click.echo(f"{len(run_rows)} run(s) in {resolved_atlas}:")
    for r in run_rows:
        click.echo(f"  {_run_lineage_line(r)}")


@click.command("triage", short_help="Rank & show candidates only (scan's 3rd stage)")
@click.argument("run_id", required=False, default=None, shell_complete=_complete_run_id)
@click.option(
    "--run",
    "run_opt",
    default=None,
    help="Restrict to one run id (overrides RUN_ID).",
    shell_complete=_complete_run_id,
)
@click.option(
    "--top", "top_n", type=int, default=None, help="Show at most N candidates (default 20)."
)
@click.option(
    "--all", "show_all", is_flag=True, default=False, help="Show every candidate (no cap)."
)
@click.option(
    "--sink",
    default=None,
    help="Show only candidates for this sink — by callee (system/popen/execl/strcpy/…) or class "
    "(cmd/copy/format). Shows all statuses and is NOT capped, so a recalled-but-low-scored sink "
    "(e.g. system) is never hidden by the default top-N.",
)
@click.option(
    "--status",
    type=click.Choice(["to-verify", "reachable", "gated", "all"]),
    default=None,
    help="Show only this review status. Default shows to-verify + reachable (gated folded).",
)
@click.option(
    "--include-gated",
    is_flag=True,
    default=False,
    help="Also show gated candidates (folded by default — they are likely dormant/false).",
)
@click.option(
    "--sort-by",
    "sort_by",
    type=click.Choice(["impact", "controllability", "reachability", "sink_impact", "by-sink"]),
    default=None,
    help="Pivot axis (the spine). Default: impact. The demotion iron law rides under every spine, "
    "so a '?' is never buried by switching the lens.",
)
@click.option(
    "--view",
    "view",
    type=click.Choice(["default", "by-sink", "nvram-source", "reachable-first", "reachable-only"]),
    default=None,
    help="A preset lens for a hunting goal: default (balanced start) | by-sink (sweep one sink "
    "class, e.g. all system()) | nvram-source (hunt nvram-mediated bugs — the router-bug hotspot) "
    "| reachable-first (FLOATS candidates with a direct rootfs entry reference to the top — a "
    "MECHANISTIC reference, NOT call-graph reachability, an incomplete slice; corpus whole). "
    "reachable-only is a deprecated alias for reachable-first.",
)
@click.option(
    "--filter",
    "dim_filter_specs",
    multiple=True,
    help="Circle-and-weight a dimension: dim=value (controllability=free / sink_impact=cmd / "
    "source=nvram / reachability=entry:web / writer=located). Matches FLOAT to the first screen; "
    "the corpus is never reduced (every candidate stays listed). Repeatable (AND).",
)
@click.option(
    "--only",
    "only_specs",
    multiple=True,
    help="SWEEP mode — prune the view to dim=value (e.g. sink_class=cmd). Reduces the shown set, "
    "but the corpus total stays whole in the header. Accepted only on a ground-truth dimension "
    "(sink_class/sink_impact); refused on an optimistic one (controllability/source/...) — use "
    "--filter there. Repeatable; combinable with --filter (sweep, then float within it).",
)
@click.option(
    "--impact-order",
    "impact_order",
    default=None,
    help="Override the impact tiers, e.g. 'cmd=fmt_string,copy,log' (comma = descending tier, "
    "'=' co-ranks). Overridable judgement.",
)
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit structured JSON.")
@click.option(
    "--explain",
    "explain_ref",
    default=None,
    help="Explain ONE candidate by its # (rank, under the current lens) or evidence_ref: the "
    "dimension layers, honest caveats, and a manual-verify checklist. Ignores --top/--status.",
)
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to config.yaml (overrides ~/.treasure-map/config.yaml).",
)
@click.option(
    "--atlas",
    "atlas_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Atlas DB path (defaults to the configured atlas.db_path).",
)
def triage(
    run_id: str | None,
    run_opt: str | None,
    top_n: int | None,
    show_all: bool,
    sink: str | None,
    status: str | None,
    include_gated: bool,
    sort_by: str | None,
    view: str | None,
    dim_filter_specs: tuple[str, ...],
    only_specs: tuple[str, ...],
    impact_order: str | None,
    as_json: bool,
    explain_ref: str | None,
    config: Path | None,
    atlas_path: Path | None,
) -> None:
    """Map atlas candidates across honest dimension layers, ordered by a switchable lens.

    Read-only: nothing is written back to the atlas and no field is altered. There is NO score —
    each row shows its dimension layers' three-state, ordered by the current lens (default: spine
    on sink-impact, band by impact x controllability, only PROVEN-safe sinks demoted; a '?' never
    sinks). Switch the lens with --sort-by / --view / --filter / --impact-order — the list is
    re-ranked, NEVER reduced. The # is the row's position under the current lens; --explain <#|ref>
    resolves it under the SAME lens. Each row carries its evidence_ref plus the binary path to open
    in the decompiler. The list caps at 20 by default; --all shows everything and --sink <x> shows
    every candidate for one sink (uncapped). Candidates are leads, NOT confirmed results.
    """
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.config.config import load_config
    from treasure_map.lib.query import (
        DEFAULT_LENS_LABEL,
        PHASE1_CAVEATS,
        canonical_view,
        explain_candidate,
        filter_match_count,
        only_refusal,
    )
    from treasure_map.lib.query import apply_view as run_apply_view
    from treasure_map.lib.query import parse_impact_order as run_parse_impact_order
    from treasure_map.lib.query import triage as run_triage

    _echo_legal_notice(as_json=as_json)
    selected_run = run_opt if run_opt is not None else run_id
    cfg = load_config(config)
    resolved_atlas = atlas_path if atlas_path is not None else cfg.atlas.db_path
    # ★ M8c: print the current run's scan lineage (build / date / status) at the top — a stale scan
    # is otherwise silent, and this is exactly where a reader forgets an old build was scanned.
    if not as_json:
        _echo_run_lineage(resolved_atlas, selected_run)

    dim_filters = _parse_dim_filters(dim_filter_specs)
    only_filters = _parse_dim_filters(only_specs)
    overrides = run_parse_impact_order(impact_order) if impact_order else None
    # A deprecated alias (reachable-only) resolves to its canonical name everywhere the lens is
    # named, so the header nudges the reader onto the current spelling instead of echoing the old.
    view = canonical_view(view)
    lens_label = _lens_label(
        DEFAULT_LENS_LABEL,
        view=view,
        sort_by=sort_by,
        dim_filters=dim_filters,
        impact_order=impact_order,
    )

    def _lensed(cands: list[TriageCandidate]) -> list[TriageCandidate]:
        """Project the full candidate list into the current lens (sort + --filter float + --only
        sweep). The SAME projection feeds the rendered list and the --explain N index, so #N is
        consistent."""
        return run_apply_view(
            cands,
            view=view,
            sort_by=sort_by,
            dim_filters=dim_filters,
            only_filters=only_filters,
            impact_overrides=overrides or None,
        )

    explanation: CandidateExplanation | None = None
    error: str | None = None
    refusal: str | None = None
    corpus_size = 0
    conn = open_atlas(resolved_atlas)
    try:
        if explain_ref is not None and not explain_ref.isdigit():
            explanation = explain_candidate(conn, explain_ref)
        else:
            full = run_triage(conn, run_id=selected_run)
            # --only prune is refused on a dimension that is not a proven ground truth on THIS
            # corpus (would silently hide unknown/null candidates) — same refusal for CLI and MCP.
            refusal = only_refusal(only_filters, full)
            if refusal is None:
                corpus_size = len(full)
                candidates = _lensed(full)
                if explain_ref is not None:  # --explain N: resolve N under the SAME lens order
                    n = int(explain_ref)
                    if 1 <= n <= len(candidates):
                        ref = candidates[n - 1].evidence_ref
                        explanation = explain_candidate(conn, ref) if ref else None
                    else:
                        run_hint = selected_run if selected_run is not None else "<run>"
                        error = (
                            f"rank {n} out of range; {len(candidates)} candidates — "
                            f"run `tmap triage {run_hint}` to list"
                        )
    finally:
        conn.close()

    if refusal is not None:
        # exit 2 (distinct from a generic error's 1) so automation/an agent can tell an --only
        # refusal apart from success (0) and from other failures (1).
        raise _OnlyRefused(refusal)
    if error is not None:
        raise click.ClickException(error)

    if explain_ref is not None:
        if explanation is None:
            run_hint = explain_ref.split("#", 1)[0] if "#" in explain_ref else "<run>"
            raise click.ClickException(
                f"no candidate with evidence_ref {explain_ref}; "
                f"run `tmap triage {run_hint}` to list refs"
            )
        _render_explain(explanation, as_json=as_json)
        return

    # --filter is a circle-and-weight lens, not a reducer: report how many candidates match (within
    # the sweep, if --only is also active) while the corpus total stays whole.
    filter_note = None
    if dim_filters:
        spec = ",".join(f"{d}={v}" for d, v in dim_filters)
        n_match = filter_match_count(candidates, dim_filters)
        if only_filters:
            filter_note = f"--filter {spec} → {n_match} floated within sweep"
        else:
            filter_note = (
                f"--filter {spec} → {n_match} match of {len(candidates)} "
                "(circle-and-weight lens: matches float to the top, corpus NOT reduced)"
            )

    _render_triage(
        candidates,
        run_label=selected_run if selected_run is not None else "all runs",
        lens_label=lens_label,
        caveats=PHASE1_CAVEATS,
        top_n=_effective_top(top_n, show_all=show_all, sink=sink),
        status=status,
        sink=sink,
        include_gated=include_gated,
        as_json=as_json,
        corpus_size=corpus_size,
        filter_note=filter_note,
    )


@click.command("atlas-view", short_help="Query the atlas database")
@click.argument("view", type=click.Choice(["dormant", "density", "twins", "ledger"]))
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to config.yaml (overrides ~/.treasure-map/config.yaml).",
)
@click.option(
    "--atlas",
    "atlas_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Atlas DB path (defaults to the configured atlas.db_path).",
)
def atlas_view(view: str, config: Path | None, atlas_path: Path | None) -> None:
    """Print a neutral atlas aggregation view. Every row is a lead/candidate, not a result."""
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.config.config import load_config
    from treasure_map.lib.query import density, dormant, ledger, twins

    cfg = load_config(config)
    resolved_atlas = atlas_path if atlas_path is not None else cfg.atlas.db_path
    conn = open_atlas(resolved_atlas)
    try:
        if view == "dormant":
            rows = dormant(conn)
            click.echo(f"dormant candidates (blocked, L0/L1): {len(rows)}")
            for r in rows:
                click.echo(
                    f"  instance {r['instance_id']} pattern {r['pattern_id']} "
                    f"| {r['reachability_status']} {r['provenance_level']} "
                    f"| mechanism: {r['blocking_mechanism']}"
                )
        elif view == "density":
            drows = density(conn)
            click.echo(f"density (count per run / sink_class / fingerprint): {len(drows)}")
            for d in drows:
                click.echo(
                    f"  run={d.source_run_id} sink_class={d.sink_class} "
                    f"fp={d.structural_fingerprint} count={d.instance_count}"
                )
        elif view == "twins":
            trows = twins(conn)
            click.echo(f"twins (same shape, mixed reachability status): {len(trows)}")
            for t in trows:
                click.echo(
                    f"  fp={t.structural_fingerprint} sink_class={t.sink_class} "
                    f"blocked={t.blocked_count} non_blocked={t.non_blocked_count}"
                )
        else:  # ledger
            lrows = ledger(conn)
            click.echo(f"pattern ledger (device_spread vs pattern_breadth): {len(lrows)} patterns")
            for lr in lrows:
                click.echo(
                    f"  pattern {lr.pattern_id} sink_class={lr.sink_class} "
                    f"fp={lr.structural_fingerprint} "
                    f"device_spread={lr.device_spread} pattern_breadth={lr.pattern_breadth} "
                    f"algo={lr.fine_fp_algo_version}"
                )
    finally:
        conn.close()
    click.echo("Note: rows are leads/candidates, not findings; interpretation is out of scope.")


@click.command("scan", short_help="Scan firmware for suspicious sinks")
@click.argument("fs_root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--workspace",
    "-w",
    type=str,
    default=None,
    help="Workspace NAME, managed under your base. Omitted: auto name. Same name -> same dir.",
    shell_complete=_complete_workspace,
)
@click.option(
    "--run-id",
    "run_id",
    default=None,
    help="Neutral per-run id written to the atlas. Defaults to the workspace name.",
)
@click.option(
    "--top", "top_n", type=int, default=None, help="Show at most N candidates (default 20)."
)
@click.option(
    "--all", "show_all", is_flag=True, default=False, help="Show every candidate (no cap)."
)
@click.option(
    "--sink",
    default=None,
    help="Show only candidates for this sink — by callee (system/popen/…) or class (cmd/copy/"
    "format); uncapped, all statuses.",
)
@click.option(
    "--status",
    type=click.Choice(["to-verify", "reachable", "gated", "all"]),
    default=None,
    help="Show only this review status. Default shows to-verify + reachable (gated folded).",
)
@click.option(
    "--include-gated",
    is_flag=True,
    default=False,
    help="Also show gated candidates (folded by default — they are likely dormant/false).",
)
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit triage list as JSON.")
@click.option(
    "--skip-non-binary",
    is_flag=True,
    default=False,
    help="Skip the non-binary file analysis stage entirely.",
)
@click.option(
    "--skip-ingester",
    "skip_ingesters",
    multiple=True,
    help="Skip a specific ingester by kind (e.g. shell_script). Repeatable.",
)
@click.option(
    "--reanalyze",
    is_flag=False,
    flag_value="__all__",
    default=None,
    help="Force re-analysis, ignoring the Ghidra cache. Bare --reanalyze redoes ALL binaries. "
    "--reanalyze <name|path> scopes the run to ONLY that binary, ignoring every other binary's "
    "staleness — after editing the Ghidra extraction pass, '--reanalyze rc' re-runs just rc (the "
    "fast iteration path); a plain run with no flag re-runs every binary the edited pass "
    "invalidated (the full-update path).",
)
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to config.yaml (overrides ~/.treasure-map/config.yaml).",
)
@click.option(
    "--atlas",
    "atlas_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Atlas DB path (defaults to the configured atlas.db_path).",
)
def scan(
    fs_root: Path,
    workspace: str | None,
    run_id: str | None,
    top_n: int | None,
    show_all: bool,
    sink: str | None,
    status: str | None,
    include_gated: bool,
    as_json: bool,
    skip_non_binary: bool,
    skip_ingesters: tuple[str, ...],
    reanalyze: str | None,
    config: Path | None,
    atlas_path: Path | None,
) -> None:
    """Run the whole main path on one extracted firmware: analyze -> hunt -> triage.

    Ends by printing the same ranked, evidence_ref-anchored triage list as `tmap triage`. The
    three sub-commands stay independent for re-running a single step; this is the one-shot path.
    Slow stage is analyze (one Ghidra JVM per binary) — progress is shown per stage.
    """
    import asyncio

    from treasure_map.cli.analyze_cli import _warn_incomplete
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.config.config import load_config
    from treasure_map.lib.errors import GhidraNotFoundError, TreasureMapError
    from treasure_map.lib.hunt import run_analyzer2
    from treasure_map.lib.query import DEFAULT_LENS_LABEL, PHASE1_CAVEATS
    from treasure_map.lib.query import triage as run_triage
    from treasure_map.lib.workspace.resolver import resolve_workspace
    from treasure_map.lib.workspace.workspace import Workspace

    _echo_legal_notice(as_json=as_json)
    cfg = load_config(config)
    try:
        resolved = resolve_workspace(workspace, workspace_dir=cfg.workspace_dir, fs_root=fs_root)
    except TreasureMapError as exc:
        raise click.ClickException(str(exc)) from exc
    ws_path = resolved.path

    # ★ Store an ABSOLUTE firmware root so a later `tmap diff` can locate the binaries from ANY cwd
    # (binaries.path and firmware_path both derive from this one fs_root). The window is tight and
    # bounded on BOTH sides: resolve AFTER resolve_workspace (auto-naming without -w uses the raw
    # fs_root.name — resolving '.' first would rename the workspace and silently re-scan from
    # scratch) but BEFORE run_analyze (the traversal that writes binaries.path runs there, well
    # before firmware_path is recorded — resolving only near firmware_path would leave binaries.path
    # relative, exactly the half that blocks diff). One resolve here keeps both paths consistent
    # (mirrors analyzer2's resolve of analysis_db_path).
    fs_root = fs_root.resolve()

    effective_run_id = run_id if run_id is not None else ws_path.name
    resolved_atlas = atlas_path if atlas_path is not None else cfg.atlas.db_path

    def _progress(step: str, meta: dict[str, Any]) -> None:
        click.echo(f"  [{step}] {meta}")

    click.echo(
        f"note: re-running run-id '{effective_run_id}' refreshes its atlas entries "
        "(replace-by-run); keep one run-id per device+firmware version"
    )

    # [1/3] analyze — reuse the analyze command's resolve_workspace + Workspace + asyncio.run path.
    click.echo("\n[1/3] analyzing firmware (Ghidra) …")
    from treasure_map.lib.analyze.pipeline import run_analyze

    try:
        with Workspace(ws_path, progress_callback=_progress) as ws:
            result = asyncio.run(
                run_analyze(
                    fs_root,
                    ws,
                    cfg,
                    _progress,
                    skip_non_binary=skip_non_binary,
                    skip_ingesters=frozenset(skip_ingesters),
                    reanalyze=reanalyze,
                )
            )
    except KeyboardInterrupt:
        click.echo("\nAborted by user — all Ghidra processes terminated.", err=True)
        raise SystemExit(130) from None
    except GhidraNotFoundError as exc:
        raise click.ClickException(str(exc)) from exc
    except TreasureMapError as exc:
        raise click.ClickException(f"{type(exc).__name__}: {exc}") from exc
    click.echo(
        f"      → analysis.db: {result.binary_count} binaries, "
        f"{result.functions_ingested} functions"
    )
    _warn_incomplete(result.incomplete_binaries)

    # [2/3] hunt call-sequence shapes -> atlas.
    click.echo(f"\n[2/3] hunting call-sequence shapes → atlas (run-id={effective_run_id}) …")
    try:
        h = run_analyzer2(
            result.db_path,
            resolved_atlas,
            source_run_id=effective_run_id,
            firmware_path=str(fs_root),
        )
    except TreasureMapError as exc:
        raise click.ClickException(f"{type(exc).__name__}: {exc}") from exc
    click.echo(
        f"      → {h.instances_written} candidates written "
        f"(confirmed={h.by_status.get('confirmed', 0)}, "
        f"blocked={h.by_status.get('blocked', 0)}, "
        f"unknown={h.by_status.get('unknown', 0)})"
    )
    if h.data_gap_skipped:
        # Honesty flag: matches whose body Ghidra could not decompile were dropped — candidate
        # set is incomplete for this run (a real sink can hide in an un-decompilable function).
        click.echo(
            f"      → {h.data_gap_skipped} shape matches skipped (data gap: no decompilable "
            "body) — candidate set INCOMPLETE"
        )
    if h.fmt_wrapper_unknown_source_demoted:
        # Not a recall flag: kept in the set, only ranked lower (a '?' is never removed).
        click.echo(
            f"      → {h.fmt_wrapper_unknown_source_demoted} fmt-wrapper candidates KEPT but "
            "ranked low (forwarded source unknown)"
        )
    if h.nvram_flows_written:
        click.echo(f"      → {h.nvram_flows_written} nvram key-flow ops flattened → atlas")
    if h.nvram_wrapper_edges:
        click.echo(
            f"      → {h.nvram_wrapper_edges} nvram wrapper-indirect key edges recovered (A2)"
        )
    if h.nvram_defaults_written:
        click.echo(f"      → {h.nvram_defaults_written} router_defaults web-settable keys → atlas")
    if h.web_form_fields_written:
        click.echo(f"      → {h.web_form_fields_written} editable web form fields → atlas")
    # Record this as the last run so `tmap mcp` (no args) serves this firmware's analysis.db.
    from treasure_map.lib.last_run import write_last_run

    write_last_run(result.db_path, resolved_atlas, effective_run_id)

    # [3/3] triage — the readable, ranked candidate list (same renderer as `tmap triage`).
    click.echo("\n[3/3] triage — ranked candidates for manual review:\n")
    conn = open_atlas(resolved_atlas)
    try:
        candidates = run_triage(conn, run_id=effective_run_id)
    finally:
        conn.close()
    _render_triage(
        candidates,
        run_label=effective_run_id,
        lens_label=DEFAULT_LENS_LABEL,
        caveats=PHASE1_CAVEATS,
        top_n=_effective_top(top_n, show_all=show_all, sink=sink),
        status=status,
        sink=sink,
        include_gated=include_gated,
        as_json=as_json,
    )
