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

import logging
import os
import shutil
import sqlite3
import subprocess
import tempfile
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from treasure_map.lib.atlas.models import DiffMetaRow
from treasure_map.lib.atlas.writer import add_diff_meta, delete_diff
from treasure_map.lib.diff.layer0 import (
    _binary_name,
    _binary_sha256,
    _confirmed_same_version,
    _next_attempts,
    _resolve_run,
    _version_skew,
    make_diff_id,
    run_layer0_parse,
)
from treasure_map.lib.diff.layer2 import run_layer2_delta
from treasure_map.lib.errors import ConfigError, GhidraNotFoundError, TreasureMapError
from treasure_map.lib.machine import clamp_parallelism_to_memory

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from treasure_map.lib.atlas.models import RunRow
    from treasure_map.lib.config.config import Config

# tmap's OWN headless BinExport script. Kept OUT of lib/analyze/ghidra on purpose:
# compute_pass_version hashes EVERY *.java in that dir, so a file added there would change the
# extraction pass_version and re-extract every binary of every firmware on the next scan. This dir
# is not on that hash path.
_SCRIPT_DIR = Path(__file__).parent / "ghidra"
_BINEXPORT_SCRIPT = "ExportBinExport.java"

# BinExport JVM heap for a diff. Deliberately a conservative fixed ceiling, NOT the per-binary
# adaptive_heap_mb ladder scan uses: RSS (~950MB measured) is not the -Xmx a peak analysis needs,
# and the export path here (ExportBinExport.java) differs from scan's (ExportFunctions.java), so its
# peak-heap demand is unmeasured. Downsizing to the ladder (max(size_a,size_b)) is a pending
# optimization — it awaits a measured peak-heap / OOM point on the largest diffed binary; until then
# 4096 stays (slower under parallelism, but never an OOM mid-sweep).
_DIFF_BINEXPORT_HEAP_MB = 4096


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


# Above this many changed binaries, a full diff asks for confirmation (serial diffs are ~20s each,
# so a large sweep can run for many minutes — never start that silently).
_FULL_DIFF_CONFIRM_THRESHOLD = 20

# How many times a full diff attempts a failing binary AT THE SAME CONTENT before treating it as a
# suspected hard boundary (a deterministic toolchain failure, e.g. BinDiff cannot rebuild the flow
# graph) and skipping it on later runs unless --force-retry. A transient failure (a Ghidra crash
# while printing stats) usually clears within one or two retries; a hard boundary never does, so
# retrying it every full diff is pure waste. Reset to zero when the binary's content changes (see
# _next_attempts): a recompiled binary may diff fine, so the past verdict is void.
_DIFF_RETRY_LIMIT = 3


def _classify_failure_reason(exc: BaseException) -> str:
    """Bucket a toolchain failure so a consumer can tell a likely-transient failure from a hard
    boundary. Matches the DETERMINISTIC message text the toolchain steps raise (``_run_binexport`` /
    ``_run_bindiff``); anything unrecognized is 'other'. Order matters -- timeout is checked before
    the generic step failure so a timed-out export is not miscounted as a crash."""
    msg = str(exc).lower()
    if "timed out" in msg or "timeout" in msg:
        return "timeout"
    if "produced no file" in msg or "produced no .bindiff" in msg:
        return "binexport_no_file"
    if "basic block" in msg or "flowgraph" in msg or "flow graph" in msg:
        return "bindiff_flowgraph"
    if "binexport" in msg:
        return "binexport_ghidra_crash"
    return "other"


def _record_diff_failure(
    atlas: sqlite3.Connection,
    *,
    diff_id: str,
    run_a_id: str,
    run_b_id: str,
    binary_short: str,
    exc: BaseException,
) -> tuple[int, str]:
    """Persist ONE binary's diff FAILURE as a self-contained atomic transaction; return
    (attempts, reason).

    diff's write model differs from scan's (add_diff_meta is a pure INSERT keyed on a PRIMARY KEY
    diff_id, and one diff spans an uncommitted layer-0 INSERT + a layer-2 commit), so "also write a
    failed row" cannot be a bare INSERT: a layer-2 failure would leave layer-0's uncommitted row to
    conflict, and a retry would hit the prior failed row's PK. The safe order is:

        rollback  -> discard any uncommitted layer-0 residue (no ok=1 row leaks through)
        next_attempts (read the prior row BEFORE deleting it)
        delete_diff(commit=False)  -> clear a prior committed failed row (else the INSERT conflicts)
        add_diff_meta(failed row, commit=False)  -> now the INSERT cannot conflict
        commit  -> the failed row lands as its own atomic transaction

    So every binary's diff is atomic: a failure never leaves a half-written or ok=1 row, and a
    second failure of the same binary is a clean replace, never a crash (the retry path must not
    crash on its own PK). The failed row carries NO coverage counts (there is no usable output),
    only the honest status + why + attempt count + the content it ran on."""
    atlas.rollback()  # ① drop layer-0's uncommitted diff_meta/alignment residue, if any
    sha_a, sha_b = _current_shas(atlas, run_a_id, run_b_id, binary_short)
    attempts = _next_attempts(atlas, diff_id, sha_a, sha_b)  # read prior BEFORE delete
    reason = _classify_failure_reason(exc)
    delete_diff(atlas, diff_id, commit=False)  # ② clear any prior failed row -> no PK conflict
    add_diff_meta(
        atlas,
        DiffMetaRow(
            diff_id=diff_id,
            run_a_id=run_a_id,
            run_b_id=run_b_id,
            binary_a=binary_short,
            binary_b=binary_short,
            diff_ok=0,
            diff_status="failed",
            diff_status_reason=reason,
            diff_attempts=attempts,
            sha256_a=sha_a,
            sha256_b=sha_b,
        ),
        commit=False,  # ③ INSERT now cannot conflict (prior row deleted, residue rolled back)
    )
    atlas.commit()  # ④ the failed row is its own atomic transaction
    return attempts, reason


def _current_shas(
    atlas: sqlite3.Connection, run_a_id: str, run_b_id: str, binary: str
) -> tuple[str | None, str | None]:
    """Best-effort (sha256_a, sha256_b) for one binary across two runs, for the failure path.

    Runs inside an except handler, so it must never raise: an unresolvable run or unreadable
    analysis.db yields (None, None) rather than masking the original failure. A None sha means the
    attempts counter cannot confirm same-content and resets to 1 (see _next_attempts) -- honest,
    since we cannot prove it is the same content that failed before."""
    try:
        run_a = _resolve_run(atlas, run_a_id, "a")
        run_b = _resolve_run(atlas, run_b_id, "b")
        sha_a = _binary_sha256(run_a.analysis_db_path, binary) if run_a.analysis_db_path else None
        sha_b = _binary_sha256(run_b.analysis_db_path, binary) if run_b.analysis_db_path else None
    except (ConfigError, sqlite3.Error):
        return None, None
    return sha_a, sha_b


@dataclass(frozen=True)
class FullDiffPlan:
    """Which binaries a full diff will (and won't) diff, decided from the two runs' inventories AND
    the per-binary diff status already recorded in the atlas.

    ``changed`` is the whole set present in both runs whose sha256 differs; it is PARTITIONED into
    four disjoint sub-sets by recorded status, so a full diff is incremental (skip already-ok) and
    self-healing (retry failed) instead of redoing everything:
      * ``to_diff``     -- never diffed, or content changed since the last diff (attempts reset).
      * ``retry``       -- failed before, under the retry cap -> diffed again (transient self-heal).
      * ``already_ok``  -- diff_ok=1 and both sides' sha256 unchanged -> skipped (redoing = waste).
      * ``hard_failed`` -- failed at the retry cap, same content -> skipped unless --force-retry
                           (a suspected hard boundary; still VISIBLE, never a silent drop)."""

    changed: tuple[str, ...]  # present in BOTH runs, sha256 differs (to_diff+retry+already_ok+hard)
    unchanged: tuple[str, ...]  # present in both, same sha256 -> skipped (diffing them is waste)
    only_in_a: tuple[str, ...]  # present only in run A -> cannot function-diff (no counterpart)
    only_in_b: tuple[str, ...]
    to_diff: tuple[str, ...] = ()  # never diffed, or content changed -> diff (attempts start fresh)
    retry: tuple[str, ...] = ()  # failed, attempts < cap -> retry (transient self-heal)
    already_ok: tuple[str, ...] = ()  # diff_ok=1, sha unchanged -> skip (incremental)
    hard_failed: tuple[str, ...] = ()  # failed at cap, sha unchanged -> skip unless --force-retry

    def binaries_to_run(self, *, force_retry: bool = False) -> tuple[str, ...]:
        """The binaries this full diff will actually diff: the never-done/changed set plus the
        under-cap retries, and -- only when ``force_retry`` -- the suspected hard boundaries too."""
        picked = list(self.to_diff) + list(self.retry)
        if force_retry:
            picked += list(self.hard_failed)
        return tuple(sorted(set(picked)))


@dataclass(frozen=True)
class BinaryDiffOutcome:
    """One binary's result within a full diff. ``summary`` is None exactly when it failed.

    ``attempts`` / ``reason`` are read back from the recorded diff_meta row (None when nothing was
    recorded, e.g. a preflight failure before the diff_id existed). ``was_failed_before`` marks a
    binary that entered this run as a retry (diff_ok=0), so a now-successful one is ``recovered`` --
    the visible evidence a transient failure self-healed."""

    binary: str
    summary: DiffSummary | None
    error: str | None
    attempts: int | None = None
    reason: str | None = None
    was_failed_before: bool = False
    recovered: bool = False


@dataclass(frozen=True)
class FullDiffSummary:
    """What a full diff reports: the plan, each binary's outcome, whether the user cancelled, and
    the retry cap in force (so a reader can label a failed binary 'will retry' vs 'hard')."""

    plan: FullDiffPlan
    outcomes: tuple[BinaryDiffOutcome, ...]
    cancelled: bool
    retry_limit: int = _DIFF_RETRY_LIMIT


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
        env = {**os.environ, "JAVA_TOOL_OPTIONS": f"-Xmx{_DIFF_BINEXPORT_HEAP_MB}m"}
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


# ── the whole pipeline: preflight (atlas) -> compute (zero-atlas) -> persist (atlas) ───
#
# The three phases are split so a full diff can run the CPU-heavy middle phase in parallel while the
# atlas-touching ends stay serial on the main thread. The atlas connection is check_same_thread=True
# (a worker touching it raises), and its writes must be serialized anyway (rollback-journal SQLite),
# so ONLY compute runs off the main thread — and compute takes Paths, never the atlas or a run id.


@dataclass(frozen=True)
class DiffArtifacts:
    """The external-toolchain output of one binary's compute phase — files on disk, no atlas state.
    Carried from a (possibly parallel) compute worker to the serial persist phase."""

    binexport_a: Path
    binexport_b: Path
    bindiff_path: Path


def compute_diff(so_a: Path, so_b: Path, td: Path, config: Config) -> DiffArtifacts:
    """The CPU-heavy middle phase for ONE binary: BinExport x2 + BinDiff, into ``td``. ZERO atlas.

    ★ Takes only Paths + config — NO atlas connection and NO run id — so it is safe to run in a
    worker thread (the atlas is check_same_thread and must be written serially; this function never
    touches it). Raises DiffToolchainError on any toolchain step failure; the caller records that
    against the atlas in the serial phase. The caller owns ``td`` (creates and removes it)."""
    timeout_s = config.ghidra.headless_timeout_seconds
    export_a = _run_binexport(so_a, config, td, "a", timeout_s)
    export_b = _run_binexport(so_b, config, td, "b", timeout_s)
    bindiff_path = _run_bindiff(export_a, export_b, td, timeout_s)
    return DiffArtifacts(binexport_a=export_a, binexport_b=export_b, bindiff_path=bindiff_path)


def _persist_success(
    atlas: sqlite3.Connection,
    *,
    diff_id: str,
    run_a_id: str,
    run_b_id: str,
    binary_name: str,
    binary_short: str,
    bindiff_path: Path,
    version_skew: bool,
    warnings: tuple[str, ...],
) -> DiffSummary:
    """The serial persist phase for a SUCCESSFUL compute: parse the .BinDiff into the atlas (layer0)
    and project the deltas (layer2), as ONE atomic write. A layer-2 failure is recorded as an atomic
    blind-spot row (rollback -> no dirty ok=1 residue) and re-raised — the exact retry-status logic,
    unchanged, just moved out of the fused pipeline so it runs on the main thread after compute."""
    try:
        l0 = run_layer0_parse(
            atlas,
            bindiff_path=bindiff_path,
            run_a_id=run_a_id,
            run_b_id=run_b_id,
            binary_a=binary_name,
            binary_b=binary_name,
            diff_id=diff_id,
            commit=False,
        )
        run_layer2_delta(atlas, diff_id=diff_id, run_a_id=run_a_id, run_b_id=run_b_id, commit=True)
    except TreasureMapError as exc:
        _record_diff_failure(
            atlas,
            diff_id=diff_id,
            run_a_id=run_a_id,
            run_b_id=run_b_id,
            binary_short=binary_short,
            exc=exc,
        )
        raise

    counts = _delta_counts(atlas, diff_id)
    return DiffSummary(
        diff_id=diff_id,
        binary=binary_name,
        matched_pairs=l0.matched_pairs,
        version_skew=version_skew,
        delta_layer_changed=counts.get("layer_changed", 0),
        delta_layer_unchanged=counts.get("layer_unchanged", 0),
        delta_undetermined=counts.get("delta_undetermined", 0),
        warnings=warnings,
    )


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
    is produced by the external differ (never self-built), then layer0/layer2 only project it.

    Structured as the three phases (preflight -> compute -> persist); the ``td`` is owned here (not
    a ``with`` block) so the same compute/persist split powers the parallel full diff. Any toolchain
    or parse failure is recorded as an honest, atomic blind-spot row (diff_ok=0 + why + attempts)
    then re-raised so the caller still sees the error."""
    pf = preflight(atlas, run_a_id, run_b_id, binary_name, config=config, force=force)
    # pf.binary_a is the normalized short name (preflight resolved it, asserted non-None). Include
    # it in the diff_id so this binary's diff does not overwrite another binary's under the same
    # run-pair (make_diff_id / delete_diff then scope to this one binary).
    did = diff_id or make_diff_id(run_a_id, run_b_id, pf.binary_a)

    td = Path(tempfile.mkdtemp(prefix="tm_diff_"))
    try:
        try:
            artifacts = compute_diff(pf.so_a, pf.so_b, td, config)
        except TreasureMapError as exc:
            _record_diff_failure(
                atlas,
                diff_id=did,
                run_a_id=run_a_id,
                run_b_id=run_b_id,
                binary_short=pf.binary_a,
                exc=exc,
            )
            raise
        return _persist_success(
            atlas,
            diff_id=did,
            run_a_id=run_a_id,
            run_b_id=run_b_id,
            binary_name=binary_name,
            binary_short=pf.binary_a,
            bindiff_path=artifacts.bindiff_path,
            version_skew=pf.version_skew,
            warnings=pf.warnings,
        )
    finally:
        shutil.rmtree(td, ignore_errors=True)


def _delta_counts(atlas: sqlite3.Connection, diff_id: str) -> dict[str, int]:
    """The tri-state delta distribution for one diff, read back from what layer2 wrote."""
    rows = atlas.execute(
        "SELECT delta_kind, COUNT(*) FROM dimension_delta WHERE diff_id = ? GROUP BY delta_kind",
        (diff_id,),
    ).fetchall()
    return {r[0]: r[1] for r in rows}


# ── full (default) diff: every CHANGED binary between two runs ────────────────────────


def _read_binaries(analysis_db_path: str) -> dict[str, str]:
    """``{binary short name -> sha256}`` for one run's analysis.db. Rows are already sha-deduped at
    scan; if a basename still repeats (two files, same name, different content) the last row wins —
    a rare collision, acceptable for deciding which binaries changed."""
    con = sqlite3.connect(f"file:{analysis_db_path}?mode=ro", uri=True)
    try:
        rows = con.execute(
            "SELECT name, sha256 FROM binaries WHERE name IS NOT NULL AND sha256 IS NOT NULL"
        ).fetchall()
    finally:
        con.close()
    return {r[0]: r[1] for r in rows}


@dataclass(frozen=True)
class _DiffStatusRecord:
    """One binary's recorded diff status for a run-pair, read from diff_meta for classification."""

    diff_ok: int
    diff_attempts: int
    sha256_a: str | None
    sha256_b: str | None


def _read_diff_status_map(
    atlas: sqlite3.Connection, run_a_id: str, run_b_id: str
) -> dict[str, _DiffStatusRecord]:
    """``{binary short name -> _DiffStatusRecord}`` for every recorded diff of this run-pair.

    Keyed on ``binary_a`` (the normalized short name plan_full_diff also uses). A pre-feature row
    with a NULL binary_a cannot be mapped to a binary, so it is skipped -> that binary reads as
    'never diffed' and is re-diffed, which backfills the new columns (honest, not a silent skip)."""
    rows = atlas.execute(
        "SELECT binary_a, diff_ok, diff_attempts, sha256_a, sha256_b FROM diff_meta "
        "WHERE run_a_id = ? AND run_b_id = ? AND binary_a IS NOT NULL",
        (run_a_id, run_b_id),
    ).fetchall()
    return {
        r[0]: _DiffStatusRecord(
            diff_ok=r[1] or 0, diff_attempts=r[2] or 0, sha256_a=r[3], sha256_b=r[4]
        )
        for r in rows
    }


def plan_full_diff(
    atlas: sqlite3.Connection,
    run_a_id: str,
    run_b_id: str,
    *,
    retry_limit: int = _DIFF_RETRY_LIMIT,
) -> FullDiffPlan:
    """Decide which binaries a full diff should diff: those present in BOTH runs whose content
    (sha256) differs, PARTITIONED by their recorded diff status so the sweep is incremental +
    self-healing. Unchanged binaries are skipped (diffing identical content is pure waste); a binary
    present on only one side has no counterpart to align, so it is listed, never diffed.

    Classification of each changed binary (see FullDiffPlan for the buckets):
      * no recorded diff, or recorded content (sha256) differs from now -> ``to_diff``
        (the content-changed case also VOIDS a past hard-boundary verdict: attempts reset).
      * diff_ok=1 and both sha256 unchanged -> ``already_ok`` (skip).
      * diff_ok=0, same content, attempts < ``retry_limit`` -> ``retry``.
      * diff_ok=0, same content, attempts >= ``retry_limit`` -> ``hard_failed`` (skip w/o force)."""
    run_a = _resolve_run(atlas, run_a_id, "a")
    run_b = _resolve_run(atlas, run_b_id, "b")
    assert run_a.analysis_db_path is not None and run_b.analysis_db_path is not None
    a = _read_binaries(run_a.analysis_db_path)
    b = _read_binaries(run_b.analysis_db_path)
    both = a.keys() & b.keys()
    changed = sorted(n for n in both if a[n] != b[n])
    unchanged = sorted(n for n in both if a[n] == b[n])
    status = _read_diff_status_map(atlas, run_a_id, run_b_id)

    to_diff: list[str] = []
    retry: list[str] = []
    already_ok: list[str] = []
    hard_failed: list[str] = []
    for n in changed:
        rec = status.get(n)
        if rec is None:
            to_diff.append(n)  # never diffed
        elif rec.diff_ok == 1 and rec.sha256_a == a[n] and rec.sha256_b == b[n]:
            already_ok.append(n)  # succeeded, content unchanged -> skip
        elif rec.sha256_a != a[n] or rec.sha256_b != b[n]:
            to_diff.append(n)  # content changed (or unrecorded sha) -> re-diff, attempts reset
        elif rec.diff_attempts < retry_limit:
            retry.append(n)  # failed, same content, under cap -> retry
        else:
            hard_failed.append(n)  # failed at cap, same content -> skip unless --force-retry

    return FullDiffPlan(
        changed=tuple(changed),
        unchanged=tuple(unchanged),
        only_in_a=tuple(sorted(a.keys() - b.keys())),
        only_in_b=tuple(sorted(b.keys() - a.keys())),
        to_diff=tuple(to_diff),
        retry=tuple(retry),
        already_ok=tuple(already_ok),
        hard_failed=tuple(hard_failed),
    )


def _read_recorded_status(atlas: sqlite3.Connection, diff_id: str) -> tuple[int | None, str | None]:
    """(diff_attempts, diff_status_reason) for one recorded diff, or (None, None) if none. Read back
    after a binary runs so the outcome carries the attempt count + failure bucket for reporting."""
    row = atlas.execute(
        "SELECT diff_attempts, diff_status_reason FROM diff_meta WHERE diff_id = ?", (diff_id,)
    ).fetchone()
    if row is None:
        return None, None
    return row[0], row[1]


@dataclass(frozen=True)
class _ResolvedDiff:
    """One binary resolved by the serial pre-phase, carrying only what compute (Paths) + persist
    (short name, skew, diff_id) need — deliberately NO atlas handle, so it crosses into a worker."""

    binary: str  # the name the plan iterated (a short name) -> layer0 binary_a/binary_b
    binary_short: str  # normalized short name (pf.binary_a) -> diff_meta + diff_id
    so_a: Path
    so_b: Path
    version_skew: bool
    warnings: tuple[str, ...]
    diff_id: str
    size_bytes: int  # max(so_a, so_b) on-disk size -> disk-headroom estimate
    prior_failed: bool  # entered this run as a retry (diff_ok=0) -> a success is a recovery


def _persist_outcome(
    atlas: sqlite3.Connection,
    rd: _ResolvedDiff,
    run_a_id: str,
    run_b_id: str,
    *,
    artifacts: DiffArtifacts | None,
    compute_exc: BaseException | None,
) -> BinaryDiffOutcome:
    """The serial persist step for ONE binary's compute result -> its outcome. Main thread only.

    Success -> layer0/layer2 write (an atomic transaction) + a recovered flag if it entered failed.
    Compute failure OR a persist (layer-2) failure -> the retry-status atomic blind-spot write
    (rollback -> delete -> insert -> commit), so every binary is its own independent transaction
    even under parallel compute — one binary's failure never corrupts another's row."""
    if compute_exc is not None:
        _record_diff_failure(
            atlas,
            diff_id=rd.diff_id,
            run_a_id=run_a_id,
            run_b_id=run_b_id,
            binary_short=rd.binary_short,
            exc=compute_exc,
        )
        attempts, reason = _read_recorded_status(atlas, rd.diff_id)
        return BinaryDiffOutcome(
            rd.binary,
            None,
            f"{type(compute_exc).__name__}: {compute_exc}",
            attempts=attempts,
            reason=reason,
            was_failed_before=rd.prior_failed,
        )
    assert artifacts is not None  # compute_exc is None -> artifacts present (mutually exclusive)
    try:
        summary = _persist_success(
            atlas,
            diff_id=rd.diff_id,
            run_a_id=run_a_id,
            run_b_id=run_b_id,
            binary_name=rd.binary,
            binary_short=rd.binary_short,
            bindiff_path=artifacts.bindiff_path,
            version_skew=rd.version_skew,
            warnings=rd.warnings,
        )
    except TreasureMapError as exc:
        # _persist_success already recorded the failed row atomically; belt-and-braces rollback so
        # no stray uncommitted state rides the next binary's commit.
        atlas.rollback()
        attempts, reason = _read_recorded_status(atlas, rd.diff_id)
        return BinaryDiffOutcome(
            rd.binary,
            None,
            f"{type(exc).__name__}: {exc}",
            attempts=attempts,
            reason=reason,
            was_failed_before=rd.prior_failed,
        )
    attempts, _ = _read_recorded_status(atlas, summary.diff_id)
    return BinaryDiffOutcome(
        rd.binary,
        summary,
        None,
        attempts=attempts,
        was_failed_before=rd.prior_failed,
        recovered=rd.prior_failed,  # entered failed, now succeeded -> self-healed
    )


def _effective_diff_workers(configured: int, resolved: list[_ResolvedDiff]) -> int:
    """Clamp the configured pool size DOWN to what current memory AND disk allow for this run.

    Memory: the config value is a stable MemTotal derivation; if free RAM is low right now, running
    that many BinExport JVMs would OOM (see clamp_parallelism_to_memory). Disk: N concurrent
    computes each write ~2x the binary (two .BinExport + a .BinDiff) into a temp dir; if free disk
    cannot hold ``workers`` of the largest such set, reduce (the interleaved persist keeps only
    ~workers sets on disk at once). Both clamps only lower the count, log it, never go below 1."""
    workers, note = clamp_parallelism_to_memory(max(1, configured))
    if note:
        logger.warning("diff: %s", note)
    try:
        free = shutil.disk_usage(tempfile.gettempdir()).free
        biggest = max((rd.size_bytes for rd in resolved), default=0)
        if biggest > 0:
            per_slot = biggest * 2  # 2 exports + a .BinDiff, conservatively <= 2x the binary
            disk_cap = max(1, int(free * 0.8) // per_slot)
            if disk_cap < workers:
                logger.warning(
                    "diff: low disk: parallelism %d->%d this run (~%dMB free)",
                    workers,
                    disk_cap,
                    free // (1024 * 1024),
                )
                workers = disk_cap
    except OSError:
        pass
    return max(1, workers)


def run_full_diff(
    atlas: sqlite3.Connection,
    run_a_id: str,
    run_b_id: str,
    *,
    config: Config,
    force: bool = False,
    force_retry: bool = False,
    retry_limit: int = _DIFF_RETRY_LIMIT,
    confirm: Callable[[int], bool] = lambda _n: True,
    on_outcome: Callable[[int, int, BinaryDiffOutcome], None] = lambda _i, _n, _o: None,
) -> FullDiffSummary:
    """Diff every CHANGED binary that NEEDS diffing: parallel compute, serial write.

    Incremental + self-healing: already-ok binaries whose content is unchanged are skipped, and
    previously-failed ones are retried (up to ``retry_limit`` at the same content; ``force_retry``
    also re-attempts suspected hard boundaries) -- see plan_full_diff.

    THREE PHASES: (1) a serial pre-phase resolves each binary (preflight reads the atlas + each
    analysis.db, so it cannot run off the main thread); (2) the CPU-heavy compute (BinExport x2 +
    BinDiff, zero atlas) runs in a thread pool sized to ``max_parallel_jvms``, clamped down for THIS
    run by current memory/disk; (3) as each compute completes, the main thread persists it SERIALLY
    (layer0/layer2 or the atomic failure write) — SQLite is written by one thread only, so no WAL /
    multi-connection complexity, and each binary stays its own independent atomic transaction.

    The run-pair-global preconditions (version skew, toolchain) are checked ONCE up front so a
    global problem fails fast; a PER-binary failure is recorded as an atomic blind-spot row and the
    sweep CONTINUES. ``confirm(n)`` gates a large sweep; ``on_outcome`` reports each binary as it
    finishes (in completion order, not submission order)."""
    plan = plan_full_diff(atlas, run_a_id, run_b_id, retry_limit=retry_limit)
    to_run = plan.binaries_to_run(force_retry=force_retry)
    if not to_run:
        # nothing NEEDS diffing: no changed binaries, or all already-ok / suspected-hard (skipped).
        return FullDiffSummary(plan, (), cancelled=False, retry_limit=retry_limit)
    # run-pair-global preflight, once (same for every binary):
    run_a = _resolve_run(atlas, run_a_id, "a")
    run_b = _resolve_run(atlas, run_b_id, "b")
    if _version_skew(run_a, run_b) and not force:
        raise ConfigError(
            "the two runs were produced by different tmap/Ghidra versions (or a version was not "
            "recorded), so every delta would be version_skew undetermined. Re-scan both with the "
            "same toolchain, or pass --force to diff anyway (the result stays honestly degraded)."
        )
    _check_toolchain(config)
    if not confirm(len(to_run)):
        return FullDiffSummary(plan, (), cancelled=True, retry_limit=retry_limit)

    was_failed_before = set(plan.retry) | set(plan.hard_failed)
    total = len(to_run)
    outcomes: list[BinaryDiffOutcome] = []
    done = 0

    # ── Phase 1 (serial, main thread): resolve each binary. preflight reads the atlas + the db,
    #    so it MUST stay on the main thread; a binary whose preflight fails (e.g. its .so cannot be
    #    located) never enters the pool — it is surfaced as a failure outcome right here. ──
    resolved: list[_ResolvedDiff] = []
    for binary in to_run:
        try:
            pf = preflight(atlas, run_a_id, run_b_id, binary, config=config, force=force)
        except TreasureMapError as exc:
            done += 1
            oc = BinaryDiffOutcome(
                binary,
                None,
                f"{type(exc).__name__}: {exc}",
                was_failed_before=binary in was_failed_before,
            )
            outcomes.append(oc)
            on_outcome(done, total, oc)
            continue
        try:
            size_bytes = max(pf.so_a.stat().st_size, pf.so_b.stat().st_size)
        except OSError:
            size_bytes = 0
        resolved.append(
            _ResolvedDiff(
                binary=binary,
                binary_short=pf.binary_a,
                so_a=pf.so_a,
                so_b=pf.so_b,
                version_skew=pf.version_skew,
                warnings=pf.warnings,
                diff_id=make_diff_id(run_a_id, run_b_id, pf.binary_a),
                size_bytes=size_bytes,
                prior_failed=binary in was_failed_before,
            )
        )

    # ── Phase 2 (parallel compute) + Phase 3 (serial persist as each completes) ──
    if resolved:
        workers = _effective_diff_workers(config.ghidra.max_parallel_jvms, resolved)
        tds = {rd.diff_id: Path(tempfile.mkdtemp(prefix="tm_diff_")) for rd in resolved}
        by_id = {rd.diff_id: rd for rd in resolved}
        pool = ThreadPoolExecutor(max_workers=workers)
        try:
            fut_to_id = {
                pool.submit(compute_diff, rd.so_a, rd.so_b, tds[rd.diff_id], config): rd.diff_id
                for rd in resolved
            }
            for fut in as_completed(fut_to_id):
                rd = by_id[fut_to_id[fut]]
                try:
                    artifacts: DiffArtifacts | None = fut.result()
                    compute_exc: BaseException | None = None
                except Exception as exc:  # toolchain error OR unexpected worker crash
                    artifacts, compute_exc = None, exc
                try:
                    oc = _persist_outcome(
                        atlas,
                        rd,
                        run_a_id,
                        run_b_id,
                        artifacts=artifacts,
                        compute_exc=compute_exc,
                    )
                finally:
                    # consume-and-clean: the orchestrator owns each temp dir (compute produced into
                    # it, persist read from it) so nothing leaks and disk stays bounded to ~workers.
                    shutil.rmtree(tds[rd.diff_id], ignore_errors=True)
                outcomes.append(oc)
                done += 1
                on_outcome(done, total, oc)
        finally:
            pool.shutdown(wait=True)
            for td in tds.values():
                shutil.rmtree(td, ignore_errors=True)

    return FullDiffSummary(plan, tuple(outcomes), cancelled=False, retry_limit=retry_limit)
