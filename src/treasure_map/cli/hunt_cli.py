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
    from treasure_map.lib.diff.matcher import _DiffRouter
    from treasure_map.lib.llm.types import LLMResponse
    from treasure_map.lib.query import CandidateExplanation, TriageCandidate

logger = logging.getLogger(__name__)


class _StaticOnlyRouter:
    """Router stand-in for ``--max-assist 0`` (pure static alignment).

    With max_assist 0 the matcher runs exact + hash passes only (it never reaches the bounded
    M-tier assist) and the differ skips the L-tier change description, so the diff makes no LLM
    call and needs no API key. This object fills the diff primitive's router slot; reaching it
    would be a logic error, hence the raise."""

    async def call(
        self, task: str, input_text: str, prompt: str, prompt_version: str
    ) -> LLMResponse:
        raise RuntimeError(
            "--max-assist 0 runs pure static alignment and must not invoke the LLM router"
        )


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


@click.command("diff", short_help="Diff two analysis.db builds; grade reachability.")
@click.argument("db_a", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("db_b", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--axis",
    type=click.Choice(["version", "mod", "sibling"]),
    default="version",
    help="Neutral comparison axis recorded as scope_origin (no vendor/version identity).",
)
@click.option("--run-id-a", required=True, help="Neutral run id for the baseline (db_a).")
@click.option("--run-id-b", required=True, help="Neutral run id for the comparison (db_b).")
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
@click.option(
    "--max-assist",
    "max_assist",
    type=int,
    default=None,
    help="Ceiling on M-tier function-match-assist calls for the stripped/renamed residue "
    "(degrade-and-flag above it; default 200). 0 = PURE STATIC alignment (exact + hash only): "
    "no LLM call, no API key needed; the residue degrades to added/removed and is reported.",
)
def hunt_diff(
    db_a: Path,
    db_b: Path,
    axis: str,
    run_id_a: str,
    run_id_b: str,
    config: Path | None,
    atlas_path: Path | None,
    max_assist: int | None,
) -> None:
    """Diff two analysis databases, grade reachability, and write neutral atlas instances.

    The LLM is only a fallback for the residue the two deterministic passes (exact symbol, then
    pseudocode hash) cannot align — it is NOT a hard gate. Symbol-complete builds align fully
    statically: run with --max-assist 0 to skip the LLM entirely (no API key needed). Writes
    graded leads at provenance L0/L1 only; public_finding is expected to be EMPTY in M2.
    """
    from treasure_map.lib.config.config import load_config
    from treasure_map.lib.diff.differ import DEFAULT_MAX_ASSIST
    from treasure_map.lib.errors import TreasureMapError
    from treasure_map.lib.hunt import run_diff_analyzer

    cfg = load_config(config)
    resolved_atlas = atlas_path if atlas_path is not None else cfg.atlas.db_path
    ledger_path = resolved_atlas.parent / "cost_ledger.json"
    effective_max_assist = DEFAULT_MAX_ASSIST if max_assist is None else max_assist

    router: _DiffRouter
    try:
        if effective_max_assist <= 0:
            # Pure static alignment: exact + hash only. No LLM call is made (the matcher never
            # reaches the assist budget and the differ skips the L-tier description), so no key
            # is required; the unmatched residue becomes added/removed and is reported.
            router = _StaticOnlyRouter()
        else:
            from treasure_map.lib.llm.factory import build_router
            from treasure_map.lib.llm.types import Tier

            if cfg.llm is None:
                raise click.ClickException(
                    f"--max-assist {effective_max_assist} needs an M-tier key "
                    "(function_match_assist for the stripped/renamed residue); "
                    "or run with --max-assist 0 for pure static alignment (no key)."
                )
            router = build_router(cfg.llm, ledger_path, tiers=[Tier.M])

        stats = run_diff_analyzer(
            db_a,
            db_b,
            axis,  # type: ignore[arg-type]  # Click constrains to the Axis literals
            resolved_atlas,
            router,
            run_id_a=run_id_a,
            run_id_b=run_id_b,
            max_assist=effective_max_assist,
        )
    except TreasureMapError as exc:
        raise click.ClickException(f"{type(exc).__name__}: {exc}") from exc

    click.echo(f"Atlas: {resolved_atlas}")
    click.echo(f"  Change leads      : {stats.leads}")
    click.echo(
        "  Of which          : "
        f"changed={stats.changed} (graded), "
        f"unverifiable={stats.changed_unverifiable} (one side had no body), "
        f"skipped_no_body={stats.skipped_no_body} (neither side had a body)"
    )
    click.echo(f"  Instances written : {stats.instances_written}")
    click.echo(
        "  By reachability   : "
        f"confirmed={stats.by_status.get('confirmed', 0)}, "
        f"blocked={stats.by_status.get('blocked', 0)}, "
        f"unknown={stats.by_status.get('unknown', 0)}"
    )
    click.echo(f"  public_finding    : {stats.public_findings}")
    click.echo(
        "Note: public_finding is expected to be empty in M2 — A1 writes L0/L1 only "
        "(no external anchor), so a confirmed result at L2 or above cannot arise here."
    )


@click.command("hunt", short_help="Find call-sequence shape candidates in a build.")
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
    if stats.fmt_wrapper_unknown_source_skipped:
        # Honesty flag: the fmt axis was intentionally narrowed (uncontrollable forwarded source).
        click.echo(
            f"  fmt-wrapper trim  : {stats.fmt_wrapper_unknown_source_skipped} "
            "(fmt wrapper candidates dropped — unknown/uncontrollable source; fmt recall NARROWED)"
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
) -> None:
    """Render the candidate map under the current lens. Shared by `tmap triage` and `tmap scan`.

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

    click.echo(
        f"triage: {run_label}   ({len(candidates)} candidates: "
        f"{counts['reachable']} reachable, {counts['to-verify']} to-verify, "
        f"{counts['gated']} gated)"
    )
    click.echo(f"  lens: {lens_label}")
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


_STATE_GLYPH = {"proven": "✓", "excluded": "✗", "unknown": "?"}


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


@click.command("triage", short_help="Rank to-verify candidates for manual reverse-engineering.")
@click.argument("run_id", required=False, default=None)
@click.option("--run", "run_opt", default=None, help="Restrict to one run id (overrides RUN_ID).")
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
    type=click.Choice(["default", "by-sink", "nvram-source", "reachable-only"]),
    default=None,
    help="A preset lens for a hunting goal: default (balanced start) | by-sink (sweep one sink "
    "class, e.g. all system()) | nvram-source (hunt nvram-mediated bugs — the router-bug hotspot) "
    "| reachable-only (prune to web-asset-linked candidates — NOTE string-level asp association, "
    "NOT call-graph reachability, so it drops reachability-'?' candidates that may still reach).",
)
@click.option(
    "--filter",
    "dim_filter_specs",
    multiple=True,
    help="Filter by a dimension: dim=value (controllability=free / sink_impact=cmd / source=nvram "
    "/ reachability=found / writer=located). Repeatable.",
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
    from treasure_map.lib.query import DEFAULT_LENS_LABEL, PHASE1_CAVEATS, explain_candidate
    from treasure_map.lib.query import apply_view as run_apply_view
    from treasure_map.lib.query import parse_impact_order as run_parse_impact_order
    from treasure_map.lib.query import triage as run_triage

    _echo_legal_notice(as_json=as_json)
    selected_run = run_opt if run_opt is not None else run_id
    cfg = load_config(config)
    resolved_atlas = atlas_path if atlas_path is not None else cfg.atlas.db_path

    dim_filters = _parse_dim_filters(dim_filter_specs)
    overrides = run_parse_impact_order(impact_order) if impact_order else None
    lens_label = _lens_label(
        DEFAULT_LENS_LABEL,
        view=view,
        sort_by=sort_by,
        dim_filters=dim_filters,
        impact_order=impact_order,
    )

    def _lensed(cands: list[TriageCandidate]) -> list[TriageCandidate]:
        """Project the full candidate list into the current lens (sort + dimension filters). The
        SAME projection feeds the rendered list and the --explain N index, so #N is consistent."""
        return run_apply_view(
            cands,
            view=view,
            sort_by=sort_by,
            dim_filters=dim_filters,
            impact_overrides=overrides or None,
        )

    explanation: CandidateExplanation | None = None
    error: str | None = None
    conn = open_atlas(resolved_atlas)
    try:
        if explain_ref is not None:
            if explain_ref.isdigit():
                # --explain N: resolve the Nth candidate in the SAME lens order the rendered # uses,
                # then reuse the evidence_ref path. No new explain logic.
                cands = _lensed(run_triage(conn, run_id=selected_run))
                n = int(explain_ref)
                if 1 <= n <= len(cands):
                    ref = cands[n - 1].evidence_ref
                    explanation = explain_candidate(conn, ref) if ref else None
                else:
                    run_hint = selected_run if selected_run is not None else "<run>"
                    error = (
                        f"rank {n} out of range; {len(cands)} candidates — "
                        f"run `tmap triage {run_hint}` to list"
                    )
            else:
                explanation = explain_candidate(conn, explain_ref)
        else:
            candidates = _lensed(run_triage(conn, run_id=selected_run))
    finally:
        conn.close()

    if explain_ref is not None:
        if error is not None:
            raise click.ClickException(error)
        if explanation is None:
            run_hint = explain_ref.split("#", 1)[0] if "#" in explain_ref else "<run>"
            raise click.ClickException(
                f"no candidate with evidence_ref {explain_ref}; "
                f"run `tmap triage {run_hint}` to list refs"
            )
        _render_explain(explanation, as_json=as_json)
        return

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
    )


@click.command("atlas-view", short_help="Neutral cross-firmware atlas aggregation views.")
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


@click.command("scan", short_help="One command: analyze -> hunt -> triage, ending in a list.")
@click.argument("fs_root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--workspace",
    "-w",
    type=str,
    default=None,
    help="Workspace as a NAME (managed under your base) or a PATH (verbatim). Omitted: auto name.",
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
    if h.fmt_wrapper_unknown_source_skipped:
        # Honesty flag: the fmt axis was intentionally narrowed (uncontrollable forwarded source).
        click.echo(
            f"      → {h.fmt_wrapper_unknown_source_skipped} fmt-wrapper candidates dropped "
            "(unknown/uncontrollable source) — fmt recall NARROWED"
        )
    if h.nvram_flows_written:
        click.echo(f"      → {h.nvram_flows_written} nvram key-flow ops flattened → atlas")
    if h.nvram_wrapper_edges:
        click.echo(
            f"      → {h.nvram_wrapper_edges} nvram wrapper-indirect key edges recovered (A2)"
        )
    if h.nvram_defaults_written:
        click.echo(f"      → {h.nvram_defaults_written} router_defaults web-settable keys → atlas")
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
