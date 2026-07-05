# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""CLI wrapper for the analyze capability.

Thin Click wrapper only — all logic lives in lib/analyze/pipeline.py.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

import click

logger = logging.getLogger(__name__)


def _warn_incomplete(incomplete: list[str]) -> None:
    """Warn (on stderr) when binaries produced no functions — analysis is incomplete, NOT clean.

    ★ Red-line (degrade must be visible): a binary Ghidra failed on holds 0 functions, so it looks
    'clean' to every downstream reader. Naming it here — and pointing at --reanalyze — stops a
    failed analysis from being mistaken for 'nothing to find'."""
    if not incomplete:
        return
    shown = ", ".join(incomplete[:20]) + (" …" if len(incomplete) > 20 else "")
    click.echo(
        f"\n⚠ {len(incomplete)} binaries produced no functions "
        f"(analysis incomplete, NOT clean): {shown}\n"
        "  rerun with --reanalyze (or --reanalyze <name>) to retry them.",
        err=True,
    )


_ANALYZE_EPILOG = """\
Examples:

\b
  tmap analyze ./_fw.extracted -w router_v1          # managed name -> <base>/router_v1
  tmap analyze ./_fw.extracted -w /mnt/scratch/fw1   # literal path (large/scratch disk)
  tmap analyze ./_fw.extracted                       # auto name (re-run resumes)

Re-running with the same -w (same name or path) resumes from the last checkpoint.

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
    short_help="Analyze an extracted firmware filesystem.",
    epilog=_ANALYZE_EPILOG,
)
@click.argument("fs_root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--workspace",
    "-w",
    type=str,
    default=None,
    help=(
        "Workspace as a NAME (managed under your workspace base, e.g. -w router_v1) or a "
        "PATH (used verbatim if it has a '/', '~', leading '.', or is absolute, e.g. "
        "-w /mnt/scratch/fw1). Omitted: a deterministic auto name under the base. Re-run "
        "with the same value to resume."
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
    "staleness. Use it to iterate on the Ghidra extraction pass: after editing ExportFunctions, "
    "'--reanalyze rc' re-runs just rc (~one binary) instead of the whole firmware. A plain run "
    "with no flag re-runs every binary the edited pass invalidated (the full-update path). Also "
    "the escape hatch for a single binary stuck in a bad cached state.",
)
def analyze(
    fs_root: Path,
    workspace: str | None,
    config: Path | None,
    skip_non_binary: bool,
    skip_ingesters: tuple[str, ...],
    reanalyze: str | None,
) -> None:
    """Analyze an extracted firmware filesystem root.

    Produces an analysis.db in the workspace directory. -w/--workspace takes a NAME
    (managed under your workspace base) or a PATH (used verbatim); omitted, a deterministic
    auto name is derived from the firmware dir. Resume-safe: re-running with the same -w
    skips completed steps.
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

    def _progress(step: str, meta: dict[str, Any]) -> None:
        click.echo(f"  [{step}] {meta}")

    if resolved.kind == "path":
        click.echo(f"Workspace: {ws_path}  (explicit path)")
    elif resolved.kind == "auto":
        click.echo(f"Workspace: '{ws_path.name}'  (auto) → {ws_path}")
    else:
        click.echo(f"Workspace: '{workspace}' → {ws_path}")

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

    # Record the produced analysis.db as the last run so `tmap mcp` can serve it without explicit
    # paths. analyze writes no atlas instances itself, so the run id is the workspace name (the
    # default a later `hunt`/`scan` would use); a subsequent hunt with an explicit --run-id updates
    # the pointer.
    from treasure_map.lib.last_run import write_last_run

    write_last_run(result.db_path, cfg.atlas.db_path, ws_path.name)

    click.echo(f"\nDone in {result.elapsed:.1f}s")
    click.echo(f"  Binaries : {result.binary_count}")
    click.echo(f"  Dirty    : {result.dirty_count}")
    click.echo(f"  Ghidra OK: {result.ghidra_ok}")
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
    click.echo(f"  DB       : {result.db_path}")
    _warn_incomplete(result.incomplete_binaries)
