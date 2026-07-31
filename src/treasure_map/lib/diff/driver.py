# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""One-command version diff — preflight, drive the external aligner, project the map.

``run_version_diff`` is the whole ``tmap diff`` pipeline behind a single call, mirroring how
``scan`` drives Ghidra internally so the user never touches an intermediate ``.BinExport`` /
``.BinDiff``:

    preflight (cheap, fail-fast)  ->  BinExport x2  ->  BinDiff CLI  ->  .BinDiff (temp)
      ->  layer0 parse (alignment facts)  ->  layer2 delta (dimension projection)

Preflight runs the five cheap checks BEFORE any heavy work so a missing run / missing analysis.db /
version skew / unlocatable binary / missing toolchain fails FAST with an actionable message instead
of crashing deep inside an IO/subprocess call. It reuses layer0's run-resolution and version
helpers (one source of truth) and NEVER judges — it only gates and drives; the map projection is
layer2's job.

BOUNDARY — the external-tool orchestration (Ghidra headless + the BinExport plugin + the BinDiff
CLI) is real-machine engineering that CANNOT run in CI (no Ghidra / BinExport / BinDiff here). The
preflight is fully unit-tested; the export/diff subprocess steps are exercised by the owner's
end-to-end smoke on a pinned toolchain (Ghidra 11.4.3 + BinDiff 8 + the prebuilt BinExport). Their
command lines are isolated in ``_run_binexport`` / ``_run_bindiff`` so a toolchain revision touches
only those two functions.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from treasure_map.lib.diff.layer0 import (
    _binary_name,
    _confirmed_same_version,
    _resolve_run,
    _version_skew,
    run_layer0_parse,
)
from treasure_map.lib.diff.layer2 import run_layer2_delta
from treasure_map.lib.errors import ConfigError, GhidraNotFoundError, TreasureMapError

if TYPE_CHECKING:
    from treasure_map.lib.atlas.models import RunRow
    from treasure_map.lib.config.config import Config

# tmap's OWN headless BinExport script. Kept OUT of lib/analyze/ghidra on purpose:
# compute_pass_version hashes EVERY *.java in that dir, so a file added there would change the
# extraction pass_version and re-extract every binary of every firmware on the next scan. This dir
# is not on that hash path.
_SCRIPT_DIR = Path(__file__).parent / "ghidra"
_BINEXPORT_SCRIPT = "ExportBinExport.java"


class DiffToolchainError(TreasureMapError):
    """The external diff toolchain (Ghidra + BinExport plugin + BinDiff CLI) is not available, or a
    toolchain step failed. Distinct from ConfigError (a data/run problem) so the CLI can point at
    the toolchain install rather than the atlas."""


@dataclass(frozen=True)
class PreflightResult:
    """The resolved inputs a diff run needs, plus the honest version-skew state. Produced only when
    all HARD checks pass; ``warnings`` carries the soft (force-overridden) version-skew note."""

    run_a: RunRow
    run_b: RunRow
    binary_a: str  # short name, as recorded in each analysis.db
    binary_b: str
    so_a: Path  # the located, existing .so file for side A
    so_b: Path
    version_skew: bool
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class DiffSummary:
    """What ``run_version_diff`` reports: identity + the top-line counts the CLI prints."""

    diff_id: str
    binary: str
    matched_pairs: int
    version_skew: bool
    delta_layer_changed: int
    delta_layer_unchanged: int
    delta_undetermined: int
    warnings: tuple[str, ...]


# ── binary .so location (finding-1 fail-fast) ────────────────────────────────────────


def _locate_binary_so(run: RunRow, binary_name: str) -> Path | None:
    """The on-disk ``.so`` file for ``binary_name`` in this run, or None if it cannot be located.

    BinExport needs the REAL binary file (a Ghidra plugin exports from it), not the analysis.db.
    ``binaries.path`` is recorded relative and its shape varies across runs (the scan-side
    absolute-path fix is a separate ticket), so this tries several roots and returns the first that
    EXISTS: an absolute recorded path, the path joined under the run's firmware root, that root plus
    the bare file name, and finally the recorded path relative to the CWD. None here is an honest
    'cannot locate' that preflight turns into a hard block -- never a guessed path fed to export."""
    if not run.analysis_db_path:
        return None
    con = sqlite3.connect(f"file:{run.analysis_db_path}?mode=ro", uri=True)
    try:
        row = con.execute(
            "SELECT path FROM binaries WHERE name = ? OR sha256 = ?", (binary_name, binary_name)
        ).fetchone()
    finally:
        con.close()
    if row is None or not row[0]:
        return None
    raw = Path(row[0])
    candidates: list[Path] = []
    if raw.is_absolute():
        candidates.append(raw)
    if run.firmware_path:
        fw = Path(run.firmware_path)
        candidates.append(fw / raw)
        candidates.append(fw / raw.name)
    candidates.append(raw)  # relative to the CWD
    for c in candidates:
        if c.is_file():
            return c
    return None


# ── toolchain discovery (finding-4 fail-fast) ────────────────────────────────────────


def _find_bindiff() -> Path | None:
    """The ``bindiff`` CLI on PATH, or None. A concrete, verifiable signal for preflight check 5."""
    found = shutil.which("bindiff")
    return Path(found) if found else None


def _binexport_present(headless: Path) -> bool:
    """Best-effort: is the BinExport Ghidra extension installed for the discovered Ghidra?

    ``analyzeHeadless`` lives at ``<ghidra_home>/support/analyzeHeadless``, so the home is its
    parent's parent; the extension unpacks under ``<home>/Ghidra/Extensions/BinExport`` or the
    user's ``~/.ghidra/.ghidra_*/Extensions/BinExport``. Detection is heuristic (a nonstandard
    install location is not seen), so the caller treats a False as 'not confirmed present' and says
    so -- it never silently proceeds as if it were there."""
    home = headless.parent.parent
    roots = [home / "Ghidra" / "Extensions"]
    user_ghidra = Path(os.path.expanduser("~")) / ".ghidra"
    if user_ghidra.is_dir():
        roots.extend(p / "Extensions" for p in user_ghidra.glob(".ghidra_*"))
    return any((root / "BinExport").exists() for root in roots if root.is_dir())


def _check_toolchain(config: Config) -> None:
    """HARD check 5: Ghidra headless + the BinExport plugin + the ``bindiff`` CLI must all be
    available. Raises DiffToolchainError listing exactly what is missing and pointing at the
    toolchain install, so a missing tool fails fast here instead of deep inside a subprocess."""
    from treasure_map.lib.analyze.ghidra_runner import find_headless

    missing: list[str] = []
    headless: Path | None = None
    try:
        headless = find_headless(config.ghidra)
    except GhidraNotFoundError:
        missing.append("Ghidra analyzeHeadless (set ghidra.local.home or $GHIDRA_HOME)")
    if headless is not None and not _binexport_present(headless):
        missing.append("the BinExport Ghidra extension (install the prebuilt BinExport for 11.4.3)")
    # tmap's OWN export script is a runtime .java asset — a wheel that dropped the package-data glob
    # would ship without it, so verify it here (a packaging problem, not a missing 3rd-party tool).
    if not (_SCRIPT_DIR / _BINEXPORT_SCRIPT).is_file():
        missing.append(
            f"tmap's own {_BINEXPORT_SCRIPT} (expected at {_SCRIPT_DIR}) — a packaging problem, "
            "not a missing third-party tool: reinstall tmap"
        )
    if _find_bindiff() is None:
        missing.append("the 'bindiff' CLI on PATH (install BinDiff 8)")
    if missing:
        joined = "\n".join(f"  - {m}" for m in missing)
        raise DiffToolchainError(
            "the version-diff toolchain is not available. Missing:\n"
            f"{joined}\n\nInstall the diff toolchain (Ghidra 11.4.3 + BinDiff 8 + the prebuilt "
            "BinExport) and retry."
        )


# ── preflight (five cheap checks, fail-fast, no judgement) ────────────────────────────


def preflight(
    atlas: sqlite3.Connection,
    run_a_id: str,
    run_b_id: str,
    binary_name: str,
    *,
    config: Config,
    force: bool,
) -> PreflightResult:
    """Run the five entry checks BEFORE any heavy work. Order matters: each check fails fast at its
    own gate so a later, more expensive check is never reached on already-broken input.

    1. both runs resolved (reuse ``_resolve_run``) — hard block.
    2. each analysis.db actually EXISTS on this machine — hard block.
    3. version consistency (``_confirmed_same_version`` via ``_version_skew``) — WARN + require
       ``--force`` (the sole soft check: the skew mark keeps the result honest, so an informed "I
       know the versions differ but want to look" stays allowed).
    4. the target binary's ``.so`` is locatable + exists — hard block (finding 1).
    5. the toolchain is available — hard block (finding 4).
    """
    run_a = _resolve_run(atlas, run_a_id, "a")  # check 1
    run_b = _resolve_run(atlas, run_b_id, "b")
    _check_db_on_disk(run_a, run_a_id)  # check 2
    _check_db_on_disk(run_b, run_b_id)

    warnings: list[str] = []
    skew = _version_skew(run_a, run_b)  # check 3
    if skew:
        note = (
            "the two runs were produced by different tmap/Ghidra versions (or a version was not "
            "recorded), so EVERY delta will be version_skew undetermined -- the diff cannot tell a "
            "real change from a detector-version change. Re-scan both with the same toolchain, or "
            "pass --force to run anyway (the result stays honestly degraded)."
        )
        if not force:
            raise ConfigError(note)
        warnings.append(note)
    # confirm-same is only used to phrase the note precisely; the gate itself is _version_skew.
    _ = _confirmed_same_version(run_a.ghidra_version, run_b.ghidra_version)

    so_a = _locate_binary_so(run_a, binary_name)  # check 4
    if so_a is None:
        raise ConfigError(_so_not_found_msg(run_a_id, binary_name, run_a))
    so_b = _locate_binary_so(run_b, binary_name)
    if so_b is None:
        raise ConfigError(_so_not_found_msg(run_b_id, binary_name, run_b))

    _check_toolchain(config)  # check 5

    bin_a = _binary_name(run_a.analysis_db_path, binary_name)  # type: ignore[arg-type]
    bin_b = _binary_name(run_b.analysis_db_path, binary_name)  # type: ignore[arg-type]
    assert bin_a is not None and bin_b is not None  # check 4 already resolved the row
    return PreflightResult(
        run_a=run_a,
        run_b=run_b,
        binary_a=bin_a,
        binary_b=bin_b,
        so_a=so_a,
        so_b=so_b,
        version_skew=skew,
        warnings=tuple(warnings),
    )


def _check_db_on_disk(run: RunRow, run_id: str) -> None:
    """HARD check 2: the run records an analysis.db path (check 1) AND that file is on THIS machine.
    A path recorded on another host that scanned it is not enough to diff here."""
    path = run.analysis_db_path
    if not path or not Path(path).exists():
        raise ConfigError(
            f"run '{run_id}': its analysis.db is not present on this machine "
            f"(recorded path: {path}). It may have been scanned elsewhere -- run `tmap scan` "
            "for it here before diffing."
        )


def _so_not_found_msg(run_id: str, binary_name: str, run: RunRow) -> str:
    recorded = "unknown"
    if run.analysis_db_path and Path(run.analysis_db_path).exists():
        con = sqlite3.connect(f"file:{run.analysis_db_path}?mode=ro", uri=True)
        try:
            row = con.execute(
                "SELECT path FROM binaries WHERE name = ? OR sha256 = ?", (binary_name, binary_name)
            ).fetchone()
        finally:
            con.close()
        recorded = (
            (row[0] if row and row[0] else "not in this run's binaries")
            if row
            else ("not in this run's binaries")
        )
    return (
        f"run '{run_id}': the .so file for binary '{binary_name}' cannot be located on this "
        f"machine (recorded path: {recorded}). BinExport needs the real binary file. Confirm the "
        "firmware is present here, or re-scan so an absolute path is recorded."
    )


# ── external toolchain orchestration (REAL-MACHINE; not exercised in CI) ──────────────


def _tail(raw: bytes | None, n: int) -> str:
    return raw.decode("utf-8", "replace")[-n:] if raw else ""


def _diag(
    cmd: list[str], proc: subprocess.CompletedProcess[bytes], log_path: Path | None = None
) -> str:
    """A readable failure report for a Ghidra/BinDiff subprocess.

    ★ Ghidra's and BinDiff's REAL diagnostics go to stdout and the ``-log`` file; stderr carries
    only the JVM banner. Reporting stderr alone (the original trap) makes a failure unreadable —
    this investigation's cost was almost entirely 'only the stderr banner was shown'. So this always
    includes the full argv, the stdout tail, the stderr tail, and the -log tail when there."""
    parts = [f"argv: {' '.join(cmd)}"]
    out = _tail(proc.stdout, 1600)
    err = _tail(proc.stderr, 800)
    if out:
        parts.append(f"stdout(tail):\n{out}")
    if err:
        parts.append(f"stderr(tail):\n{err}")
    if log_path is not None and log_path.is_file():
        log = log_path.read_text(errors="replace")[-1600:]
        if log:
            parts.append(f"log(tail):\n{log}")
    return "\n".join(parts)


def _run_binexport(so_path: Path, config: Config, out_dir: Path, side: str, timeout_s: int) -> Path:
    """Export one ``.so`` to a ``.BinExport`` via Ghidra headless + tmap's own export script.

    REAL-MACHINE PATH — requires Ghidra 11.4.3 + the BinExport extension (for its classes); not
    runnable in CI. Uses tmap's own non-interactive ``ExportBinExport.java`` (NOT the extension's
    interactive ``BinExport.java``, which ignores the output-path argument and lets analyzeHeadless
    exit 0 with no file). The argv here is the one adjustment point if the export entry changes."""
    from treasure_map.lib.analyze.ghidra_runner import find_headless

    headless = find_headless(config.ghidra)
    export_path = out_dir / f"{side}.BinExport"
    log_path = out_dir / f"{side}.ghidra.log"
    with tempfile.TemporaryDirectory(prefix="tm_binexport_proj_") as proj:
        cmd = [
            str(headless),
            proj,
            "Proj",
            "-import",
            str(so_path),
            "-postScript",
            _BINEXPORT_SCRIPT,
            str(export_path),
            "-scriptPath",
            str(_SCRIPT_DIR),
            "-deleteProject",
            "-log",
            str(log_path),
            "-analysisTimeoutPerFile",
            str(timeout_s),
        ]
        env = {**os.environ, "JAVA_TOOL_OPTIONS": "-Xmx4096m"}
        try:
            proc = subprocess.run(  # noqa: S603 -- fixed argv, no shell
                cmd, env=env, capture_output=True, timeout=timeout_s + 120
            )
        except subprocess.TimeoutExpired as exc:
            raise DiffToolchainError(
                f"BinExport timed out for side {side} ({so_path.name})"
            ) from exc
    if proc.returncode != 0:
        raise DiffToolchainError(
            f"BinExport subprocess failed (side {side}, {so_path.name}, rc={proc.returncode})\n"
            + _diag(cmd, proc, log_path)
        )
    if not export_path.exists():
        raise DiffToolchainError(
            f"BinExport produced no file for side {side} ({so_path.name}) although the process "
            "exited 0 — the postScript did not run to completion (analyzeHeadless returns 0 even "
            f"when a postScript aborts). Expected: {export_path}\n" + _diag(cmd, proc, log_path)
        )
    return export_path


def _run_bindiff(export_a: Path, export_b: Path, out_dir: Path, timeout_s: int) -> Path:
    """Diff two ``.BinExport`` files into a ``.BinDiff`` via the BinDiff CLI.

    REAL-MACHINE PATH — requires the ``bindiff`` CLI (BinDiff 8); not runnable in CI. The command
    line is the adjustment point if the CLI's flags change across versions."""
    bindiff = _find_bindiff()
    if bindiff is None:
        raise DiffToolchainError("the 'bindiff' CLI is not on PATH (install BinDiff 8)")
    cmd = [
        str(bindiff),
        "--primary",
        str(export_a),
        "--secondary",
        str(export_b),
        "--output_dir",
        str(out_dir),
    ]
    try:
        proc = subprocess.run(  # noqa: S603 -- fixed argv, no shell
            cmd, capture_output=True, timeout=timeout_s
        )
    except subprocess.TimeoutExpired as exc:
        raise DiffToolchainError("BinDiff timed out") from exc
    if proc.returncode != 0:
        raise DiffToolchainError(f"BinDiff failed (rc={proc.returncode})\n" + _diag(cmd, proc))
    produced = sorted(out_dir.glob("*.BinDiff"))
    if not produced:
        raise DiffToolchainError(
            "BinDiff exited 0 but produced no .BinDiff output\n" + _diag(cmd, proc)
        )
    return produced[0]


# ── the whole pipeline ───────────────────────────────────────────────────────────────


def run_version_diff(
    atlas: sqlite3.Connection,
    run_a_id: str,
    run_b_id: str,
    binary_name: str,
    *,
    config: Config,
    force: bool = False,
    diff_id: str | None = None,
) -> DiffSummary:
    """Preflight, drive BinExport+BinDiff, and project the map for ONE binary between two runs.

    Single binary by design — a whole-firmware loop is orders of magnitude more expensive, so the
    caller diffs one ``--binary`` at a time. ``binary_a == binary_b == binary_name``. The alignment
    is produced by the external differ (never self-built), then layer0/layer2 only project it."""
    pf = preflight(atlas, run_a_id, run_b_id, binary_name, config=config, force=force)
    did = diff_id or f"{run_a_id}::{run_b_id}"
    timeout_s = config.ghidra.headless_timeout_seconds

    with tempfile.TemporaryDirectory(prefix="tm_diff_") as td:
        tdp = Path(td)
        export_a = _run_binexport(pf.so_a, config, tdp, "a", timeout_s)
        export_b = _run_binexport(pf.so_b, config, tdp, "b", timeout_s)
        bindiff_path = _run_bindiff(export_a, export_b, tdp, timeout_s)
        l0 = run_layer0_parse(
            atlas,
            bindiff_path=bindiff_path,
            run_a_id=run_a_id,
            run_b_id=run_b_id,
            binary_a=binary_name,
            binary_b=binary_name,
            diff_id=did,
            commit=False,
        )
        run_layer2_delta(atlas, diff_id=did, run_a_id=run_a_id, run_b_id=run_b_id, commit=True)

    counts = _delta_counts(atlas, did)
    return DiffSummary(
        diff_id=did,
        binary=binary_name,
        matched_pairs=l0.matched_pairs,
        version_skew=pf.version_skew,
        delta_layer_changed=counts.get("layer_changed", 0),
        delta_layer_unchanged=counts.get("layer_unchanged", 0),
        delta_undetermined=counts.get("delta_undetermined", 0),
        warnings=pf.warnings,
    )


def _delta_counts(atlas: sqlite3.Connection, diff_id: str) -> dict[str, int]:
    """The tri-state delta distribution for one diff, read back from what layer2 wrote."""
    rows = atlas.execute(
        "SELECT delta_kind, COUNT(*) FROM dimension_delta WHERE diff_id = ? GROUP BY delta_kind",
        (diff_id,),
    ).fetchall()
    return {r[0]: r[1] for r in rows}
