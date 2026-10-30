# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""CLI wrapper for the analyze capability.

Thin Click wrapper only — all logic lives in lib/analyze/pipeline.py.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import click

from treasure_map.cli.interrupts import interrupt_exit_code

logger = logging.getLogger(__name__)


def _shown(names: list[str]) -> str:
    return ", ".join(names[:20]) + (" …" if len(names) > 20 else "")


def _warn_incomplete(incomplete: list[str], no_functions: list[str] | None = None) -> None:
    """Warn (on stderr) when binaries produced no functions — analysis is incomplete, NOT clean.

    ★ Red-line (degrade must be visible): a binary Ghidra failed on holds 0 functions, so it looks
    'clean' to every downstream reader. Naming it here — and pointing at --reanalyze — stops a
    failed analysis from being mistaken for 'nothing to find'.

    Of the four analysis states only ``ok`` and ``ok_empty`` are clean. ``no_functions`` (the
    extraction finished on a binary that has code, and recovered no function) is incomplete too,
    but re-running the same pass gives the same answer, so those are named on a line of their own
    that says what WOULD change it instead of advising a retry."""
    no_functions = no_functions or []
    if not incomplete:
        return
    click.echo(
        f"\n⚠ {len(incomplete)} binaries produced no functions "
        f"(analysis incomplete, NOT clean): {_shown(incomplete)}\n"
        "  rerun with --reanalyze (or --reanalyze <name>) to retry them.",
        err=True,
    )
    if no_functions:
        click.echo(
            f"  {len(no_functions)} binaries have executable code but Ghidra recovered no function "
            "from it — re-running with the same pass does not change this; after a Ghidra or "
            "architecture-detection change, --reanalyze <name> retries it: "
            f"{_shown(no_functions)}",
            err=True,
        )


def _warn_kept_earlier(kept: list[dict[str, Any]]) -> None:
    """Name (on stderr) the binaries that still hold an EARLIER pass's extraction because this
    pass failed on them — their candidates come from that earlier extraction."""
    if not kept:
        return
    shown = ", ".join(f"{k['binary']} ({k.get('reason') or 'unknown'})" for k in kept[:20])
    if len(kept) > 20:
        shown += ", …"
    click.echo(
        f"⚠ {len(kept)} binaries kept their earlier extraction because this pass failed on them: "
        f"{shown} — their candidates read extraction_current=false.",
        err=True,
    )


def _warn_reanalyze_pending(pending: int, reanalyze: str | None) -> None:
    """Point at an unfinished bare --reanalyze that this run did not continue."""
    if pending <= 0 or reanalyze == "__all__":
        return
    click.echo(
        f"⚠ an interrupted --reanalyze left {pending} binaries not yet re-extracted; run the "
        "same command with --reanalyze to finish it.",
        err=True,
    )


def report_extraction_state(result: Any, reanalyze: str | None) -> None:
    """The stderr warnings both `tmap analyze` and `tmap scan` print after the extraction."""
    _warn_incomplete(result.incomplete_binaries, result.no_functions_binaries)
    _warn_kept_earlier(result.kept_earlier_binaries)
    _warn_reanalyze_pending(result.reanalyze_pending, reanalyze)
    _report_exports(
        getattr(result, "exports_by_status", {}), getattr(result, "extension_note", None)
    )


# binexport_status values a diff can read (lib/binexport_archive.USABLE_STATUSES).
_DIFFABLE = ("ok", "degraded")


def _report_exports(by_status: dict[str, int], note: str | None) -> None:
    """What this run's BinExport exports came to, and — said on stderr — how many of its binaries
    cannot be diffed and why: a scan without an export is still a scan, and its binaries only show
    up as blind spots when someone diffs them."""
    if not by_status:
        return
    parts = ", ".join(f"{n} {status}" for status, n in sorted(by_status.items()))
    click.echo(f"      → exports (for tmap diff): {parts}")
    no_diff = sum(n for status, n in by_status.items() if status not in _DIFFABLE)
    if note:
        click.echo(f"  ⚠ BinExport: {note}", err=True)
    if no_diff:
        click.echo(
            f"  ⚠ {no_diff} binaries have no usable export and cannot be diffed until they are "
            "re-scanned"
            + (
                " with the BinExport extension installed (tmap init)"
                if by_status.get("extension_missing")
                else ""
            ),
            err=True,
        )


def _report_timeout_skips(skipped: list[dict[str, Any]]) -> None:
    """Name the binaries no Ghidra time was spent on this scan, and why.

    ★ Red-line (a skip must be visible): these are binaries that timed out and were NOT re-run
    because this scan would hand them the same budget, which a timeout has already answered. The
    scan therefore finishes faster while covering less, and the only thing that makes those two
    tellable apart is saying so. Silence here reads as "it went fast", which is the wrong half.

    Printed alongside the incomplete warning, not instead of it: they are still incomplete, and a
    reader who sees only this line should still learn that from the other.

    The knob named is the configured base timeout, deliberately, and not the ceiling. The budget is
    ``min(ceiling, 2 * size-scaled base)``, so the ceiling only binds for binaries big enough for
    the doubled budget to reach it — over ~30MB at the default base. For the 14MB binary that
    prompted this, the budget is 846s against an 1800s ceiling: raising the ceiling moves nothing
    and the advice would send someone to change a number that cannot help them."""
    if not skipped:
        return
    click.echo(
        f"\n  skipped {len(skipped)} binary/ies that timed out at the current budget "
        "(same content, same extractor — a re-run reproduces the timeout):"
    )
    for entry in skipped[:20]:
        size = entry.get("size_bytes") or 0
        budget = entry.get("budget_seconds")
        budget_txt = f"{budget}s budget" if budget is not None else "budget unrecorded"
        click.echo(
            f"    - {entry['binary']} ({size / 1024 / 1024:.1f}MB, timed out at {budget_txt}) — "
            "still listed incomplete; raise ghidra.headless_timeout_seconds or --force-retry "
            "to re-attempt"
        )
    if len(skipped) > 20:
        click.echo(f"    … and {len(skipped) - 20} more")


_ANALYZE_EPILOG = """\
Examples:

\b
  tmap analyze ./_fw.extracted -w router_v1          # managed name -> <base>/router_v1
  tmap analyze ./_fw.extracted                       # auto name (re-run resumes)

-w takes a NAME under workspace_dir. To keep workspaces on a large or scratch
disk, point workspace_dir there in config.yaml and keep using -w <name>.

Re-running with the same -w resumes: binaries whose extraction finished are
kept and only the rest run (a binary cut off mid-decompile starts that binary
over).

Iterating on the Ghidra extraction pass (ExportFunctions):

\b
  # after editing the pass, validate on ONE binary (fast — ~that binary only):
  tmap analyze ./_fw.extracted -w router_v1 --reanalyze rc
  # validated? full update — the edited pass re-runs every binary automatically:
  tmap analyze ./_fw.extracted -w router_v1

Editing the pass changes its content hash (pass_version), so a plain re-run
re-extracts every binary with no manual file/db deletion; --reanalyze <name>
scopes that to just the binary you are validating.
"""


@click.command(
    "analyze",
    short_help="Decompile & extract facts only (scan's 1st stage)",
    epilog=_ANALYZE_EPILOG,
)
@click.argument("fs_root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--workspace",
    "-w",
    type=str,
    default=None,
    help=(
        "Workspace NAME, managed under your workspace base (e.g. -w router_v1). Omitted: a "
        "deterministic auto name derived from the firmware dir. Re-run with the same name to "
        "resume — the same name always maps to the same directory."
    ),
)
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to config.yaml (overrides ~/.treasure-map/config.yaml).",
)
@click.option(
    "--reanalyze",
    is_flag=False,
    flag_value="__all__",
    default=None,
    help="Force re-analysis, ignoring the Ghidra cache. Bare --reanalyze redoes ALL binaries. "
    "--reanalyze <name|path> scopes the run to ONLY that binary, ignoring every other binary's "
    "staleness. Use it to iterate on the Ghidra extraction pass: after editing ExportFunctions, "
    "'--reanalyze rc' re-runs just rc (~one binary) instead of the whole firmware. A plain run "
    "with no flag re-runs every binary the edited pass invalidated (the full-update path). Also "
    "the escape hatch for a single binary stuck in a bad cached state.",
)
@click.option(
    "--force-retry",
    is_flag=True,
    default=False,
    help="Also re-attempt binaries that timed out at a budget this scan would repeat, which are "
    "skipped by default (a timeout is deterministic — the same budget reproduces it). Use after "
    "raising the timeout, or on a machine with more to spare.",
)
def analyze(
    fs_root: Path,
    workspace: str | None,
    config: Path | None,
    reanalyze: str | None,
    force_retry: bool,
) -> None:
    """Analyze an extracted firmware filesystem root.

    Produces an analysis.db in the workspace directory. -w/--workspace takes a workspace NAME,
    managed under your workspace base; omitted, a deterministic auto name is derived from the
    firmware dir. Re-running with the same -w re-extracts only the binaries that changed (the
    same name always maps to the same directory).
    """
    from treasure_map.lib.analyze.pipeline import run_analyze
    from treasure_map.lib.config.config import load_config
    from treasure_map.lib.errors import GhidraNotFoundError, TreasureMapError
    from treasure_map.lib.workspace.resolver import resolve_workspace
    from treasure_map.lib.workspace.workspace import Workspace

    cfg = load_config(config)

    try:
        resolved = resolve_workspace(workspace, workspace_dir=cfg.workspace_dir, fs_root=fs_root)
    except TreasureMapError as exc:
        raise click.ClickException(str(exc)) from exc
    ws_path = resolved.path
    # Absolute from here on, as `tmap scan` does it (and for the same reason: binaries.path is
    # written from this root, and a relative one breaks `tmap diff` from another directory). After
    # resolve_workspace, which names an automatic workspace after the root as it was typed.
    fs_root = fs_root.resolve()

    def _progress(step: str, meta: dict[str, Any]) -> None:
        click.echo(f"  [{step}] {meta}")

    if resolved.kind == "auto":
        click.echo(f"Workspace: '{ws_path.name}'  (auto) → {ws_path}")
    else:
        click.echo(f"Workspace: '{workspace}' → {ws_path}")

    try:
        with Workspace(ws_path) as ws:
            # A plain call, not asyncio.run: the analysis has no await points, and asyncio's own
            # SIGINT handling turned the first Ctrl-C into a cancel that waited for the whole run.
            result = run_analyze(
                fs_root,
                ws,
                cfg,
                _progress,
                reanalyze=reanalyze,
                force_retry=force_retry,
            )
    except KeyboardInterrupt:
        click.echo(
            "\nAborted — all Ghidra processes terminated. Finished binaries are kept; re-run the "
            "same command to continue.",
            err=True,
        )
        raise SystemExit(interrupt_exit_code()) from None
    except GhidraNotFoundError as exc:
        raise click.ClickException(str(exc)) from exc
    except TreasureMapError as exc:
        raise click.ClickException(f"{type(exc).__name__}: {exc}") from exc

    # Record the produced analysis.db as the last run so `tmap mcp` can serve it without explicit
    # paths. analyze writes no atlas instances itself, so the run id is the workspace name (the
    # default a later `hunt`/`scan` would use); a subsequent hunt with an explicit --run-id updates
    # the pointer.
    from treasure_map.lib.last_run import write_last_run

    write_last_run(result.db_path, cfg.atlas.db_path, ws_path.name)

    click.echo(f"\nDone in {result.elapsed:.1f}s")
    click.echo(f"  Binaries : {result.binary_count}")
    click.echo(f"  Dirty    : {result.dirty_count}")
    nf = result.ghidra_no_functions
    click.echo(
        f"  Ghidra OK: {result.ghidra_ok}" + (f" (of which {nf} no_functions)" if nf else "")
    )
    click.echo(f"  Failed   : {result.ghidra_failed}")
    click.echo(f"  Skipped  : {result.ghidra_skipped} (cache hit)")
    click.echo(f"  Functions ingested: {result.functions_ingested}")
    click.echo(f"  Imports   ingested: {result.imports_ingested}")
    click.echo(f"  Exports   ingested: {result.exports_ingested}")
    click.echo(f"  Strings   ingested: {result.strings_ingested}")
    click.echo(f"  Xrefs (L0 callees×exports): {result.layer0_xrefs}")
    click.echo(f"  Xrefs (L1 import×export):   {result.layer1_xrefs}")
    click.echo(f"  Xrefs (L2 dt_needed):       {result.layer2_xrefs}")
    click.echo(f"  Xrefs (L3 string_ipc):      {result.layer3_xrefs}")
    click.echo(f"  Strings classified: {result.strings_classified}")
    click.echo(f"  Total xrefs: {result.total_xrefs}")
    click.echo(f"  Non-binary files: {result.non_binary_files_ingested}")
    click.echo(f"  Script calls: {result.script_calls_ingested}")
    click.echo(f"  Config entries: {result.config_entries_ingested}")
    click.echo(f"  Credentials: {result.credentials_ingested}")
    click.echo(f"  Web endpoints: {result.web_endpoints_ingested}")
    click.echo(f"  Symlinks recorded: {result.symlinks_recorded}")
    click.echo(f"  DB       : {result.db_path}")
    _report_timeout_skips(result.timeout_skipped)
    report_extraction_state(result, reanalyze)
