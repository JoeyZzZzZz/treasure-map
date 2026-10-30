# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Ghidra headless analysis runner.

Path discovery order: config.local.home → GHIDRA_HOME env → PATH.
Single-binary wrapper: GhidraRunner.run_ghidra().  Parallel dispatch: run_all().
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import signal
import struct
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path
from typing import Any

from treasure_map.lib.analyze.elf_inventory import ElfRecord, has_substantial_text
from treasure_map.lib.analyze.stub_resolve import (
    resolve_stubs,
    serialize_stub_table,
    stub_table_marker,
)
from treasure_map.lib.config.config import GhidraConfig
from treasure_map.lib.errors import GhidraNotFoundError

# The export stamp is its own axis, never part of the scan stamp: imported from a standard-library
# module the scan stamp's closure does not enter (rescan_version.CLOSURE_EXCLUDED).
from treasure_map.lib.export_stamp import (
    EXPORT_SCRIPT,
    EXPORT_SCRIPT_DIR,
    ScanExtension,
    link_into_home,
)
from treasure_map.lib.machine import clamp_parallelism_to_memory
from treasure_map.lib.pattern.extractor_names import validate_registry
from treasure_map.version import UNKNOWN_VERSION

logger = logging.getLogger(__name__)

# --- live Ghidra process-group registry (for deterministic teardown on abort) ---
# Each subprocess is started with start_new_session=True, so its pid == its pgid
# (session/group leader). We track live pgids so an interrupt handler can killpg
# the whole tree (analyzeHeadless wrapper + java + children) — terminal SIGINT does
# NOT reach them because they are in their own session.
_active_pgids: set[int] = set()
# Re-entrant: a launch holds it across the shutdown check, Popen AND _register_pgid.
_active_lock = threading.RLock()
# Set (under _active_lock) when a run is being torn down. A worker checks it under the SAME lock it
# registers its process group with, so at an interrupt every worker is either already registered
# (and terminate_all kills it) or sees the flag and never starts a JVM. Without that, a worker
# caught between its checks and Popen started a fresh JVM after the teardown, and the pool's
# shutdown then waited on it.
_shutting_down = False


def begin_shutdown() -> None:
    """Refuse every Ghidra launch from now on in this process (until the next run_all)."""
    global _shutting_down
    with _active_lock:
        _shutting_down = True


def _reset_shutdown() -> None:
    global _shutting_down
    with _active_lock:
        _shutting_down = False


def _register_pgid(pgid: int) -> None:
    with _active_lock:
        _active_pgids.add(pgid)


def _unregister_pgid(pgid: int) -> None:
    with _active_lock:
        _active_pgids.discard(pgid)


def _killpg_quiet(pgid: int, sig: int) -> None:
    try:
        os.killpg(pgid, sig)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def terminate_all(grace: float = 2.0) -> None:
    """Tear down every live Ghidra process group: SIGTERM, brief grace, then SIGKILL.

    Called on interrupt/abort so no orphan JVM survives. Idempotent and safe to
    call when nothing is running (no-op, no sleep).
    """
    with _active_lock:
        pgids = list(_active_pgids)
    if not pgids:
        return
    for pgid in pgids:
        _killpg_quiet(pgid, signal.SIGTERM)
    time.sleep(grace)
    for pgid in pgids:
        _killpg_quiet(pgid, signal.SIGKILL)
        _unregister_pgid(pgid)


ProgressCallback = Callable[[str, dict[str, Any]], None]
# Called once per record with its FINAL extraction result (see GhidraRunner.run_all).
FinalCallback = Callable[[ElfRecord, "GhidraResult"], None]
# Called at most once per record, after a phase-2 re-run of a binary whose extraction phase 1 had
# already finalized but whose export failed (see GhidraRunner.run_all).
ExportCallback = Callable[[ElfRecord, "GhidraResult"], None]

_SCRIPT_DIR = Path(__file__).parent / "ghidra"
_GHIDRA_RELEASES_URL = "https://github.com/NationalSecurityAgency/ghidra/releases"


# The Python extraction steps whose output is written into the per-binary ``functions`` cache
# during the dirty-record loop — the same cache the .java pass feeds. They belong in the pass
# fingerprint for the SAME reason the .java does: editing them changes what a re-scan would store,
# so a same-content re-scan must re-extract rather than skip. Declared EXPLICITLY, not derived from
# an import closure: ``ghidra_ingest`` imports ``elf_inventory`` for the ``ElfRecord`` TYPE and (two
# hops on) reaches ``symlinks``, which runs on every scan (wipe-and-rebuild) — pulling those in via
# import transitivity would make an edit to an unrelated wipe-and-rebuild step trigger a full,
# hours-long Ghidra re-extraction. The criterion is "its output is written into the functions cache
# inside the dirty loop", and ``test_pass_version.py`` locks this set against that criterion
# mechanically, so a future extraction step cannot be added and silently left out. The lock also
# covers the whole of each of these three modules' treasure_map reads: they read only one another
# (outside type annotations), so the fingerprint — which hashes exactly this set plus the .java and
# .tsv — is closed, and a read of an undeclared module fails the lock.
_PIPELINE_PY_MODULES: tuple[str, ...] = ("elf_exports.py", "ghidra_ingest.py", "stub_resolve.py")


def pass_version_source_files(script_dir: Path) -> list[Path]:
    """Every file whose content the pass fingerprint depends on: the .java scripts, the name
    registry they read at run time (the .tsv beside them), and the declared Python extraction
    modules (which live in the analyze dir, ``script_dir``'s parent).

    Sorted deterministically — .java by path, then .tsv by path, then the declared Python modules
    by name — so the same content always hashes the same, independent of import order or
    ``sys.modules`` state. A per-binary stub table is NOT here: it is written to the output
    directory, never beside the scripts, so it cannot enter this glob."""
    analyze_dir = script_dir.parent
    try:
        java = sorted(script_dir.glob("*.java"))
    except OSError:
        java = []
    try:
        tsv = sorted(script_dir.glob("*.tsv"))
    except OSError:
        tsv = []
    py = [analyze_dir / name for name in sorted(_PIPELINE_PY_MODULES)]
    return java + tsv + py


def compute_pass_version(script_dir: Path) -> str:
    """Content hash of the per-binary extraction PIPELINE — the .java Ghidra pass AND the declared
    Python load/relabel steps (``ghidra_ingest`` + ``stub_resolve`` + ``elf_exports``) that write
    the functions cache.

    This is a cache-key dimension: the per-binary output depends on the pipeline logic as much as on
    the binary bytes, so editing ANY step that changes what gets stored — the Java extraction OR the
    Python relabel — must invalidate the cache and re-extract automatically (no manual JSON/db
    deletion). It was ONCE only the .java; a Python relabel step (stub_resolve) then changed the
    stored callees while the fingerprint ignored it, so a same-content re-scan skipped every binary
    and the new extraction never ran — a false-negative fix deployed as a false negative. Hence the
    fingerprint now spans the whole pipeline. A missing/unreadable file is skipped so a scan still
    runs (treating everything as needing a first extraction) rather than crashing.

    ★ It hashes the extraction CODE, not the version of the tools the code calls. The Ghidra
    version is deliberately NOT in it: an upgraded decompiler is caught on an axis of its own —
    every binary another Ghidra extracted is re-extracted by a plain scan (db_ingest's toolchain
    check), and a run another Ghidra produced is refused until then (run_staleness' toolchain
    axis). pyelftools (which stub_resolve parses ELF with) is not in it either, and an upgrade of
    it still needs a manual --reanalyze. The BinExport export scripts the session also runs are
    kept out on purpose: they change no extracted fact, and are hashed into the export hash
    (lib/export_stamp) instead."""
    h = hashlib.sha256()
    for p in pass_version_source_files(script_dir):
        try:
            body = p.read_bytes()
        except OSError:
            continue
        h.update(p.name.encode("utf-8"))
        h.update(b"\0")
        h.update(body)
    return h.hexdigest()[:16]


@lru_cache(maxsize=1)
def current_pass_version() -> str:
    """The extraction fingerprint of the pipeline THIS install would run, for staleness reads.

    The same value ``GhidraRunner.pass_version()`` stamps onto a binary it extracts, computed
    without constructing a runner — a reader comparing a stored run against the current code needs
    the number, not a Ghidra installation. Cached: the source files cannot change under a running
    process in any way this value should follow mid-session.
    """
    return compute_pass_version(_SCRIPT_DIR)


def detect_ghidra_version(headless: Path) -> str:
    """The Ghidra version behind an ``analyzeHeadless`` path, or ``UNKNOWN_VERSION``.

    Reads ``application.version`` out of ``<ghidra_home>/Ghidra/application.properties``, the
    installation's own version declaration (``analyzeHeadless`` lives at
    ``<ghidra_home>/support/analyzeHeadless``, so the home is its parent's parent).

    Honesty red-line: a failure to detect returns the EXPLICIT ``UNKNOWN_VERSION`` string, never
    None and never a guess. A recorded "unknown" is read downstream as "cannot confirm this run's
    decompiler version", which is conservative; a None would let a version comparison short-circuit
    into a silent "same version"."""
    props = headless.parent.parent / "Ghidra" / "application.properties"
    try:
        text = props.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return UNKNOWN_VERSION
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() == "application.version":
            return value.strip() or UNKNOWN_VERSION
    return UNKNOWN_VERSION


@dataclass
class GhidraResult:
    binary: Path
    output_file: Path | None  # None = analysis failed
    success: bool
    elapsed: float
    retried: bool = False
    log_path: Path | None = None
    stderr_tail: str | None = None  # last 500 chars of stderr for debugging
    # ★ Red-line (degrade must be visible): the four-state analysis outcome, so a partial/empty run
    # is never frozen as "clean". "ok" = functions produced; "ok_empty" = a legitimately code-free
    # object (no substantial .text) with 0 functions (do not re-churn); "no_functions" = the
    # extraction ran to the end with its markers right, the binary HAS executable code, and Ghidra
    # recovered no function from it — a finished extraction, NOT a clean one (it is still listed
    # incomplete), recorded so the same pass does not re-run it for the same answer; "failed" = no
    # usable output (timed out, malformed, missing, another run's file). ``success`` is True for
    # ok / ok_empty / no_functions.
    analysis_status: str = "failed"
    function_count: int = 0  # functions in the output JSON (0 for ok_empty / no_functions / failed)
    # WHY a failed run failed, so a consumer distinguishes a recoverable timeout (re-scan may finish
    # it) from a structural failure. None on success. One of: 'timeout' / 'import_failed' /
    # 'no_output' / 'incomplete' / 'stale_output' (a JSON another pass or binary wrote). Recorded
    # onto binaries.ghidra_status_reason for the incomplete surfacing -- degrade must be visible AND
    # explicable, not just a flat 'failed'.
    reason: str | None = None
    # The wall-clock budget (seconds) the attempt behind THIS result actually ran under — recorded,
    # not re-derived, because "re-scan may finish it" is only true if the next scan hands it MORE
    # time. Measured rather than computed so a run that never reached the isolated retry (its phase
    # crashed) records the smaller budget it really got, and next scan re-runs it. None when the
    # result did not come from an attempt (a crash placeholder).
    timeout_budget: int | None = None
    # Size of the Ghidra log before THIS attempt started. ``-log`` appends, so every earlier run's
    # lines are still in the file; the timeout and import-failure checks read only what this attempt
    # wrote, from here on.
    log_offset: int = 0
    # ── the BinExport export written in the same session (lib/binexport_archive) ──
    # ok / degraded / failed:<why> / scan_failed:<why> / extension_missing; None when the result did
    # not come from an attempt that could export (a crash placeholder, an interrupted attempt).
    export_status: str | None = None
    # The export and its report when export_status is ok / degraded (in the output directory, not
    # yet archived); None otherwise.
    export_file: Path | None = None
    export_report_file: Path | None = None
    # The export's parsed report (ok / degraded only).
    export_report: dict[str, Any] | None = None
    # The export budget this attempt ran under (seconds past the analysis budget); None when the
    # attempt did not export.
    export_budget: int | None = None
    # True on a result handed to ``on_export`` that carries only an export outcome: the extraction
    # phase 1 finalized stands, and only the export status is to be updated.
    export_only: bool = False


# ★ A binary that cannot finish within this even on an isolated retry is a genuine hang, not a
# needs-more-time case — the dynamic timeout never runs a single binary unbounded.
_TIMEOUT_CEILING_SECONDS = 1800  # 30 min


def adaptive_heap_mb(size_bytes: int) -> tuple[int, int]:
    """(xmx_mb, xms_mb) for a Ghidra headless JVM, scaled by the binary's size — the per-binary heap
    ladder, NOT a machine-wide single value.

    A per-binary ladder is why a 500KB library runs in 512MB while a 60MB one gets 2048MB: a single
    machine-wide heap would either starve the big binary or waste memory on the small one (and cut
    how many can run in parallel). ``diff``'s BinExport does not use it (it keeps its own fixed
    heap). xms is 1/8 of xmx (min 64MB), matching the JVM's usual init/max ratio.
    """
    size_mb = size_bytes / 1024 / 1024
    xmx = 512 if size_mb < 1 else 768 if size_mb < 10 else 1536 if size_mb < 50 else 2048
    xms = max(64, xmx // 8)
    return xmx, xms


def _scaled_timeout(size_bytes: int, base: int) -> int:
    """The size-scaled, ceiling-capped budget for a binary of ``size_bytes``. Pure — no filesystem.

    Split out from ``_dynamic_timeout`` so the phase-2 budget below and the dirty check that
    re-derives it share ONE formula. Two copies would agree until either was adjusted, and then a
    binary would be compared against a budget nobody was going to give it."""
    size_mb = size_bytes / 1024 / 1024
    scaled = base if size_mb < 10 else int(base * (size_mb / 10))
    return min(_TIMEOUT_CEILING_SECONDS, max(base, scaled))


def _dynamic_timeout(binary: Path, base: int) -> int:
    """A per-binary analysis timeout scaled by file size, replacing the flat one-size-fits-all.

    A small binary uses ``base``; a large one (whose analysis+export budget genuinely needs more)
    gets proportionally more time, capped at the ceiling. This is why a 28M library no longer times
    out under a budget sized for a 200K one — and why a truly hung binary still cannot run forever.
    """
    try:
        size_bytes = binary.stat().st_size
    except OSError:
        return base
    return _scaled_timeout(size_bytes, base)


def retry_budget_seconds(binary: Path, base: int) -> int | None:
    """The budget a binary's LAST attempt gets: the serial isolated retry's doubled, capped one.

    THE number to compare a timed-out binary against, and the reason it is a function rather than an
    expression at the two call sites. ``run_all`` spends it in phase 2, and the dirty check asks
    with it whether a re-run would hand the binary MORE time than it had when it failed. A timeout
    is deterministic: at the same budget the same binary times out again, so re-running it is a
    guaranteed-identical result bought at half an hour of wall clock. Only a bigger budget makes the
    attempt a different one.

    ★ Phase 2's budget, deliberately, not phase 1's. A binary that fails in the parallel phase is
    re-run serially at ``2 * _dynamic_timeout`` (capped), so THAT is the budget it finally failed
    under. Comparing against phase 1's would also break the self-heal in the direction that costs
    most: ``_dynamic_timeout`` is ``min(ceiling, scaled)`` and for most binaries ``scaled`` is well
    under the ceiling, so raising the ceiling would not move it and a binary that should now get
    more time would go on being skipped. ``min(ceiling, 2 * scaled)`` does move with the ceiling
    exactly when the doubled budget is what the ceiling was clipping.

    None when the file cannot be measured. A budget that cannot be computed must not be compared:
    the caller re-runs rather than deciding on a number it does not have.
    """
    try:
        size_bytes = binary.stat().st_size
    except OSError:
        return None
    return min(_TIMEOUT_CEILING_SECONDS, _scaled_timeout(size_bytes, base) * 2)


def find_headless(config: GhidraConfig) -> Path:
    """Discover analyzeHeadless in priority order.

    1. config.local.home / support / analyzeHeadless
    2. $GHIDRA_HOME / support / analyzeHeadless
    3. shutil.which("analyzeHeadless")
    4. raise GhidraNotFoundError with actionable message
    """
    searched: list[str] = []

    if config.local.home is not None:
        candidate = config.local.home / "support" / "analyzeHeadless"
        searched.append(str(candidate))
        if candidate.exists():
            return candidate

    ghidra_home_env = os.environ.get("GHIDRA_HOME")
    if ghidra_home_env:
        candidate = Path(ghidra_home_env) / "support" / "analyzeHeadless"
        searched.append(str(candidate))
        if candidate.exists():
            return candidate

    found = shutil.which("analyzeHeadless")
    if found:
        return Path(found)
    searched.append("analyzeHeadless (PATH)")

    locations = "\n".join(f"  - {s}" for s in searched)
    raise GhidraNotFoundError(
        f"analyzeHeadless not found.\nSearched:\n{locations}\n\n"
        f"Install Ghidra: {_GHIDRA_RELEASES_URL}\n"
        "Then configure ghidra.local.home in ~/.treasure-map/config.yaml:\n"
        "  ghidra:\n    local:\n      home: /path/to/ghidra_11.x_PUBLIC"
    )


def _patch_elf_for_ghidra(src: Path) -> tuple[Path, Path] | None:
    """Create a patched ELF copy with sections that trigger Ghidra 11.1.2's
    StringIndexOutOfBoundsException neutralised (sh_type → SHT_NULL).

    Affected: SHT_NOTE sections whose name is "GNU" (3-4 bytes), and
    SHT_ARM_ATTRIBUTES sections.  Both are safe to nullify for decompilation.

    Returns (patched_file, tmpdir) where patched_file has the SAME NAME as src
    so Ghidra's currentProgram.getName() matches what the caller expects.
    Caller must shutil.rmtree(tmpdir) after use.
    Returns None if no patch is needed or if patching fails.
    """
    try:
        data = bytearray(src.read_bytes())
    except OSError:
        return None

    if data[:4] != b"\x7fELF" or len(data) < 64:
        return None

    ei_class = data[4]
    fmt = "<" if data[5] == 1 else ">"

    if ei_class == 1:  # ELF32
        e_shoff: int = struct.unpack_from(fmt + "I", data, 32)[0]
        e_shentsize: int = struct.unpack_from(fmt + "H", data, 46)[0]
        e_shnum: int = struct.unpack_from(fmt + "H", data, 48)[0]
        sh_off_off, sh_sz_off, sh_off_fmt = 16, 20, fmt + "I"
        min_entsize = 40
    elif ei_class == 2:  # ELF64
        e_shoff = struct.unpack_from(fmt + "Q", data, 40)[0]
        e_shentsize = struct.unpack_from(fmt + "H", data, 58)[0]
        e_shnum = struct.unpack_from(fmt + "H", data, 60)[0]
        sh_off_off, sh_sz_off, sh_off_fmt = 24, 32, fmt + "Q"
        min_entsize = 64
    else:
        return None

    if e_shoff == 0 or e_shentsize < min_entsize:
        return None

    sht_note = 7
    sht_arm_attributes = 0x70000003

    patched = False
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if off + e_shentsize > len(data):
            break

        sh_type: int = struct.unpack_from(fmt + "I", data, off + 4)[0]
        neutralise = False

        if sh_type == sht_arm_attributes:
            neutralise = True
        elif sh_type == sht_note:
            sec_off: int = struct.unpack_from(sh_off_fmt, data, off + sh_off_off)[0]
            sec_size: int = struct.unpack_from(sh_off_fmt, data, off + sh_sz_off)[0]
            if sec_size >= 12 and 0 < sec_off <= len(data) - sec_size:
                namesz: int = struct.unpack_from(fmt + "I", data, sec_off)[0]
                if namesz in (3, 4) and data[sec_off + 12 : sec_off + 15] == b"GNU":
                    neutralise = True

        if neutralise:
            struct.pack_into(fmt + "I", data, off + 4, 0)
            struct.pack_into(sh_off_fmt, data, off + sh_off_off, 0)
            struct.pack_into(sh_off_fmt, data, off + sh_sz_off, 0)
            patched = True

    if not patched:
        return None

    tmpdir = Path(tempfile.mkdtemp(prefix="tm_elfpatch_"))
    try:
        patched_file = tmpdir / src.name  # same name → Ghidra uses correct program name
        patched_file.write_bytes(bytes(data))
        return patched_file, tmpdir
    except Exception:
        shutil.rmtree(tmpdir, ignore_errors=True)
        return None


def _probe_function_count(
    output_file: Path,
) -> tuple[int | None, str | None, str | None, str | None]:
    """(function count, ``pass_version`` marker, ``sha8`` marker, ``stub_marker``) of a Ghidra
    output JSON.

    The count is None when the file is missing/unparseable — a hard failure (no usable output); 0
    is a valid parsed-but-empty result the caller judges against the ELF's code presence. The two
    markers are what the extractor wrote about itself (which extraction pass, which binary), None
    when absent; they are what lets a caller tell THIS run's output from a file an earlier run left
    at the same path. The stub marker says which stub table the extractor actually read (see
    ``stub_resolve.stub_table_marker``). The output files are modest, so a full parse is fine."""
    try:
        with output_file.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None, None, None, None
    if not isinstance(data, dict):
        return None, None, None, None
    funcs = data.get("functions")
    marker_pass = data.get("pass_version")
    marker_sha8 = data.get("sha8")
    marker_stub = data.get("stub_marker")
    return (
        len(funcs) if isinstance(funcs, list) else None,
        marker_pass if isinstance(marker_pass, str) else None,
        marker_sha8 if isinstance(marker_sha8, str) else None,
        marker_stub if isinstance(marker_stub, str) else None,
    )


def _markers_mismatch(
    marker_pass: str | None,
    marker_sha8: str | None,
    expected_pass: str | None,
    expected_sha8: str | None,
    marker_stub: str | None = None,
    expected_stub: str | None = None,
) -> bool:
    """True when an output's self-description disagrees with what this run expects. An expected
    value of None means "do not check that marker"; a missing/empty marker never matches.

    The stub marker is a content hash of the stub table the extractor loaded, so a JVM that read
    another binary's table (or none, when one was meant) is caught here even though its pass and
    binary markers are right."""
    if expected_pass is not None and (not marker_pass or marker_pass != expected_pass):
        return True
    if expected_sha8 is not None and (not marker_sha8 or marker_sha8 != expected_sha8):
        return True
    return expected_stub is not None and (not marker_stub or marker_stub != expected_stub)


def _classify_analysis(
    output_file: Path,
    binary: Path,
    expected_pass: str | None = None,
    expected_sha8: str | None = None,
    expected_stub: str | None = None,
) -> tuple[str, int]:
    """Classify a finished run into (analysis_status, function_count) — one of four states.

    ★ Red-line: ``ok`` requires a NON-EMPTY functions array, not merely a >200-byte file. A
    code-free object (no substantial .text) with 0 functions is ``ok_empty`` (legitimate; do not
    re-churn). A binary WITH code whose extraction parsed and carries all three markers right but
    holds 0 functions is ``no_functions``: the extraction finished and Ghidra found nothing it could
    call a function, which the same pass will find again — so it is recorded as done for this pass,
    and it is NOT clean (every incomplete surfacing still lists it). Everything else is ``failed``:
    a missing or unparseable file, or one whose markers say another run wrote it. A timeout never
    reaches here; the caller decides it from this attempt's log first.

    ★ Freshness: the output directory outlives a scan, so the file at ``output_file`` may be one an
    EARLIER run wrote — a run that timed out never replaces it. When ``expected_pass`` /
    ``expected_sha8`` are given, the file's own markers must equal them (a missing or empty marker
    is a mismatch), else ``failed``: counting another run's functions as this run's success is how a
    stale extraction got stamped current and was never re-extracted. Callers that run Ghidra pass
    both; the checks are skipped only when neither is given."""
    if not output_file.exists():
        return "failed", 0
    count, marker_pass, marker_sha8, marker_stub = _probe_function_count(output_file)
    if count is None:
        return "failed", 0
    if _markers_mismatch(
        marker_pass, marker_sha8, expected_pass, expected_sha8, marker_stub, expected_stub
    ):
        return "failed", 0
    if count > 0:
        return "ok", count
    return ("no_functions", 0) if has_substantial_text(binary) else ("ok_empty", 0)


# The decompile-retry budget of a session that does not export (its wall clock has no E share).
_DECOMPILE_RETRY_NO_EXPORT_S = 30

# The scripts a scan runs after Ghidra's analysis, in this order: create the functions the analysis
# left out, extract, then (when the BinExport extension is available) export.
PROMOTE_SCRIPT = "PromoteUndefined.java"
EXTRACT_SCRIPT = "ExportFunctions.java"


def export_paths(output_dir: Path, binary: Path, sha8: str) -> tuple[Path, Path]:
    """(export, report) a scan's export of ``binary`` is written to, in the output directory."""
    stem = f"{binary.name}_{sha8}"
    return output_dir / f"{stem}.BinExport", output_dir / f"{stem}.export_report.json"


def _build_cmd(
    headless: Path,
    binary: Path,
    arch: str,
    proj_dir: Path,
    output_dir: Path,
    script_dir: Path,
    sha8: str,
    timeout_s: int,
    export: tuple[Path, Path] | None = None,
) -> list[str]:
    """Build the analyzeHeadless invocation command list. With ``export`` (the export and report
    paths) the session also writes the BinExport export, after the extraction."""
    log_path = output_dir / f"{binary.name}_{sha8}.log"
    post = ["-postScript", PROMOTE_SCRIPT, "-postScript", EXTRACT_SCRIPT]
    script_path = str(script_dir)
    if export is not None:
        post += ["-postScript", EXPORT_SCRIPT, str(export[0]), str(export[1]), "scan"]
        # Ghidra takes several script directories separated by ';'. The export scripts stay beside
        # the diff code and out of the extraction pass's fingerprint (lib/export_stamp).
        script_path = f"{script_dir};{EXPORT_SCRIPT_DIR}"
    return [
        str(headless),
        str(proj_dir),
        "Proj",
        "-processor",
        arch,
        *post,
        "-scriptPath",
        script_path,
        "-deleteProject",
        "-log",
        str(log_path),
        "-analysisTimeoutPerFile",
        str(timeout_s),
        "-import",
        str(binary),
    ]


# The analysis states a finished extraction is recorded under (see GhidraResult.analysis_status).
_SUCCESS_STATUSES: tuple[str, ...] = ("ok", "ok_empty", "no_functions")

# GhidraResult.reason of an attempt the run's own teardown cut off: not a failure of the binary.
_INTERRUPTED = "interrupted"

# returncode of a process that could not be started at all (the launcher missing, not executable):
# never a timeout — a timeout settles a budget and is skipped at that budget on the next scan.
LAUNCH_FAILED_RC = -2

# What analyzeHeadless logs when -analysisTimeoutPerFile stops the analysis. It still runs the
# post-script and exits 0, so the JSON on disk is a HALF analysis that reads exactly like a whole
# one. (The diff driver reads the same line for its export: lib/diff/driver.py.)
_ANALYSIS_TIMED_OUT = re.compile(rb"REPORT: Analysis timed out at \d+ seconds")


def _log_size(log_path: Path) -> int:
    """The log's size now (0 when there is none yet): where the next attempt's lines will start."""
    try:
        return log_path.stat().st_size
    except OSError:
        return 0


def _log_since(log_path: Path, offset: int) -> bytes:
    """What was written to ``log_path`` from byte ``offset`` on — this attempt's part of a log that
    ``-log`` appends to. A file now SMALLER than the offset was rolled over (Ghidra starts a fresh
    log past its size limit), so the whole of it is this attempt's and it is read whole."""
    with log_path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        if f.tell() < offset:
            offset = 0
        f.seek(offset)
        return f.read()


def _analysis_timed_out(log_path: Path, offset: int = 0) -> bool:
    """Whether THIS attempt's part of the log (from ``offset`` on) reports the analysis timeout. An
    earlier run's timeout line, still in the appended log, says nothing about this one."""
    try:
        return bool(_ANALYSIS_TIMED_OUT.search(_log_since(log_path, offset)))
    except OSError:
        return False


# A Java exception class name and its message, as Ghidra logs a script that threw.
_EXCEPTION_LINE = re.compile(
    rb"((?:[a-z][\w$]*\.)+[A-Z][\w$]*(?:Exception|Error))(?::\s*([^\r\n]*))?"
)


def _export_failure_reason(log_path: Path, offset: int) -> str:
    """Why this attempt's export left no file: the first exception the log shows from the export
    script on (its class and the first part of its message), else ``no_file``."""
    try:
        text = _log_since(log_path, offset)
    except OSError:
        return "no_file"
    start = text.find(EXPORT_SCRIPT.encode())
    match = _EXCEPTION_LINE.search(text, start if start >= 0 else 0)
    if match is None:
        return "no_file"
    name = match.group(1).decode(errors="replace").rsplit(".", 1)[-1]
    msg = (match.group(2) or b"").decode(errors="replace").strip()
    reason = f"{name}: {msg}" if msg else name
    return reason[:160]


def _read_export(export_file: Path, report_file: Path) -> tuple[str, dict[str, Any] | None]:
    """(status, report) of an export the session wrote: ok, degraded (some operand written in its
    default form), or failed when the files are missing or the report is not what the export script
    writes."""
    if not export_file.is_file() or export_file.stat().st_size == 0 or not report_file.is_file():
        return "failed:no_file", None
    try:
        report = json.loads(report_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "failed:report_unreadable", None
    if not isinstance(report, dict):
        return "failed:report_unreadable", None
    degraded = report.get("operand_markup_degraded")
    n = degraded.get("instructions") if isinstance(degraded, dict) else None
    if isinstance(n, bool) or not isinstance(n, int):
        return "failed:report_unreadable", None
    return ("degraded" if n > 0 else "ok"), report


def _run_subprocess(
    cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
) -> tuple[int, str]:
    """Spawn cmd in a new session/process group; kill the whole group on timeout
    or interrupt.

    Returns (returncode, stderr_tail). returncode -1 = timeout; LAUNCH_FAILED_RC = the process
    could not be started (the text says why).
    analyzeHeadless is a shell wrapper that spawns Java without exec, so the whole
    process group must be killed to avoid orphan JVMs. The pgid is registered so a
    top-level interrupt can tear every live group down (terminal SIGINT never
    reaches them — they are in their own session).
    """
    proc: subprocess.Popen[bytes] | None = None
    pgid: int | None = None
    try:
        with _active_lock:
            if _shutting_down:
                return LAUNCH_FAILED_RC, "not started: the run is being interrupted"
            # A working directory of our own: analyzeHeadless resolves a bare script name against
            # the directory it is started from first, so a same-named file there would be run.
            proc = subprocess.Popen(
                cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                cwd=cwd,
            )
            pgid = proc.pid  # session leader: pgid == pid
            _register_pgid(pgid)
        try:
            _, stderr_bytes = proc.communicate(timeout=timeout)
            snippet = stderr_bytes.decode(errors="replace")[-500:]
            return proc.returncode, snippet
        except subprocess.TimeoutExpired:
            _killpg_quiet(pgid, signal.SIGKILL)
            proc.communicate()
            return -1, "timeout"
    except BaseException as exc:
        # BaseException covers KeyboardInterrupt (NOT an Exception): never leak a
        # live JVM group. Kill the group, reap, then decide whether to swallow.
        if pgid is not None:
            _killpg_quiet(pgid, signal.SIGKILL)
        if proc is not None:
            try:
                proc.communicate(timeout=5)
            except Exception:
                pass
        if isinstance(exc, Exception):
            return LAUNCH_FAILED_RC, str(exc)  # could not start: not a timeout
        raise  # KeyboardInterrupt / SystemExit propagate
    finally:
        if pgid is not None:
            _unregister_pgid(pgid)


class GhidraRunner:
    """Manages Ghidra headless analysis for one or many ELF binaries."""

    def __init__(
        self,
        config: GhidraConfig,
        *,
        script_dir: Path | None = None,
        headless: Path | None = None,
        extension: ScanExtension | None = None,
    ) -> None:
        self._config = config
        self._script_dir = script_dir or _SCRIPT_DIR
        self._headless = headless  # None = lazy-discovered on first use
        # The BinExport copy this scan loads, decided once before any JVM (lib/export_stamp).
        # None, or one with no ext_dir, = no export: binaries are recorded extension_missing.
        self._extension = extension

    def set_extension(self, extension: ScanExtension | None) -> None:
        """The BinExport copy the scan's JVMs load (None = none: no export is attempted)."""
        self._extension = extension

    def _exporting(self) -> bool:
        return self._extension is not None and self._extension.ext_dir is not None

    def get_headless(self) -> Path:
        """Return cached headless path, discovering it on first call."""
        if self._headless is None:
            self._headless = find_headless(self._config)
        return self._headless

    def pass_version(self) -> str:
        """Content hash of the extraction pass this runner will execute (its script dir's .java)."""
        return compute_pass_version(self._script_dir)

    def ghidra_version(self) -> str:
        """Version of the Ghidra installation this runner will invoke (``UNKNOWN_VERSION`` when it
        cannot be read). Stamped onto every binary this run analyzes, so a later cross-version diff
        can tell "the decompiler changed" apart from "the firmware changed"."""
        return detect_ghidra_version(self.get_headless())

    def run_ghidra(
        self,
        binary: Path,
        output_dir: Path,
        timeout: int,
        arch: str,
        sha8: str = "",
        retry: bool = True,
    ) -> GhidraResult:
        """Run analyzeHeadless on a single binary with at most one retry.

        - 'Import failed'  -> patch the problematic ELF sections (Ghidra 11.1.2
          StringIndexOutOfBoundsException on GNU notes / ARM attributes) and re-run the patched
          copy. This deterministic recovery ALWAYS runs (it is cheap and not CPU-bound).
        - any other failure (chiefly a per-file timeout on a large binary) -> re-run the ORIGINAL
          binary with a doubled budget (capped at the ceiling), ONLY when ``retry`` is True.

        ★ ``retry`` gates the TIMEOUT retry so ``run_all`` can defer it: phase 1 runs every binary
        once IN PARALLEL (retry=False), phase 2 re-runs the failures SERIALLY as ONE more attempt
        at an already-doubled budget (also retry=False), so a big binary retries with the CPU to
        itself instead of competing in the pool. A still-failing
        retry returns success=False with an explicit ``reason`` — never a fabricated 'ok'.
        """
        headless = self.get_headless()
        output_dir.mkdir(parents=True, exist_ok=True)
        if not sha8:
            sha8 = binary.name[:8]

        r1 = self._run_once(binary, output_dir, arch, sha8, timeout, headless)
        if r1.success:
            return r1
        if r1.reason == _INTERRUPTED:
            # Cut off by the run's teardown: not a failure of this binary, so no retry and no
            # warning. It is not recorded either; the next scan starts it over.
            logger.debug("ghidra: %s interrupted", binary.name)
            return r1

        import_failed = False
        if r1.log_path is not None and r1.log_path.exists():
            try:
                # This attempt's lines only: an "Import failed" an earlier run left in the appended
                # log would send a timeout down the patch-and-retry path.
                import_failed = b"Import failed" in _log_since(r1.log_path, r1.log_offset)
            except OSError:
                pass

        retry_timeout = min(_TIMEOUT_CEILING_SECONDS, timeout * 2)
        did_retry = False
        total_elapsed = r1.elapsed
        last = r1
        if import_failed:
            # deterministic recovery, always attempted (patch the ELF, re-run the patched copy)
            patch_result = _patch_elf_for_ghidra(binary)
            if patch_result is not None:
                patched_file, tmpdir = patch_result
                try:
                    r2 = self._run_once(
                        patched_file, output_dir, arch, sha8, retry_timeout, headless
                    )
                    did_retry = True
                    total_elapsed += r2.elapsed
                    last = r2
                    if r2.reason == _INTERRUPTED:
                        logger.debug("ghidra: %s interrupted", binary.name)
                        r2.binary = binary
                        return r2
                    if r2.success:
                        r2.binary = binary
                        r2.elapsed = total_elapsed
                        r2.retried = True
                        return r2
                finally:
                    shutil.rmtree(tmpdir, ignore_errors=True)
        elif retry:
            # the CPU-contending timeout retry — deferred to run_all's serial phase 2 (retry=False
            # in phase 1) so a big binary does not retry while competing for cores in the pool.
            r2 = self._run_once(binary, output_dir, arch, sha8, retry_timeout, headless)
            did_retry = True
            total_elapsed += r2.elapsed
            last = r2
            if r2.reason == _INTERRUPTED:
                logger.debug("ghidra: %s interrupted", binary.name)
                return r2
            if r2.success:
                r2.elapsed = total_elapsed
                r2.retried = True
                return r2

        failed_reason = "import_failed" if import_failed else last.reason
        export_status = f"scan_failed:{failed_reason or 'unknown'}"
        # Said where a person sees it: the reason, the end of Ghidra's stderr and its log.
        logger.warning(
            "ghidra: %s failed (%s)%s%s",
            binary.name,
            failed_reason or "unknown",
            f"; log: {r1.log_path}" if r1.log_path is not None else "",
            f"; stderr: {r1.stderr_tail.strip()[-300:]}" if r1.stderr_tail else "",
        )
        return GhidraResult(
            binary=binary,
            output_file=None,
            success=False,
            elapsed=total_elapsed,
            retried=did_retry,
            log_path=r1.log_path,
            stderr_tail=r1.stderr_tail,
            reason=failed_reason,
            # The budget of the attempt that actually failed last — ``last`` is the retry when one
            # ran, ``r1`` when none did. Taking r1's would under-report the time this binary was
            # given and make the next scan skip it on a budget it never had.
            timeout_budget=last.timeout_budget,
            log_offset=r1.log_offset,
            export_status=export_status,
        )

    def _run_once(
        self,
        binary: Path,
        output_dir: Path,
        arch: str,
        sha8: str,
        timeout: int,
        headless: Path,
    ) -> GhidraResult:
        t0 = time.monotonic()
        proj_dir: Path | None = None
        ghidra_home_dir: Path | None = None
        # ONE try from the first mkdtemp to the end of the JVM: an interrupt anywhere in between
        # (stub resolution, the table write) must not leave the two directories behind.
        try:
            proj_dir = Path(tempfile.mkdtemp(prefix="tm_ghidra_proj_"))
            ghidra_home_dir = Path(tempfile.mkdtemp(prefix="tm_ghidra_home_"))

            exporting = self._exporting()
            exp = export_paths(output_dir, binary, sha8) if exporting else None
            cmd = _build_cmd(
                headless, binary, arch, proj_dir, output_dir, self._script_dir, sha8, timeout, exp
            )
            expected_out = output_dir / f"{binary.name}_{sha8}_ghidra.json"
            stub_table = output_dir / f"{binary.name}_{sha8}.stubs.tsv"
            # A file left at the target path by an earlier run must never be read as this run's
            # output: clear it (and its in-flight .tmp, and an earlier run's stub table and export)
            # before starting, so the only files present afterwards are ones THIS run wrote. The
            # markers checked below catch every other way a foreign file appears.
            leftovers = [expected_out, stub_table, *export_paths(output_dir, binary, sha8)]
            for leftover in [*leftovers, *(f.with_name(f.name + ".tmp") for f in leftovers)]:
                leftover.unlink(missing_ok=True)
            expected_pass = self.pass_version()
            # This binary's lazy-binding stubs, resolved from ELF structure and handed to the
            # extractor so a call it renders as FUN_<stub-addr> is recognised as the import it
            # reaches. None (not a readable MIPS ELF with dynamic symbols) hands nothing in, and the
            # extractor must then report "none" — an empty table and no table are different
            # answers.
            resolution = resolve_stubs(binary)
            expected_stub = stub_table_marker(None if resolution is None else resolution.names)
            if resolution is not None:
                output_dir.mkdir(parents=True, exist_ok=True)
                stub_table.write_text(serialize_stub_table(resolution.names), encoding="utf-8")

            # Where this attempt's lines will start in the appended log (see GhidraResult).
            log_offset = _log_size(output_dir / f"{binary.name}_{sha8}.log")
            heap_mb, xms_mb = adaptive_heap_mb(binary.stat().st_size)
            env: dict[str, str] = {
                **dict(os.environ),
                "OUTPUT_DIR": str(output_dir),
                "SHA8": sha8,
                # echoed back into the JSON by the extractor, so the output proves which pass
                # wrote it
                "PASS_VERSION": expected_pass,
                "JAVA_TOOL_OPTIONS": (
                    f"-Xmx{heap_mb}m -Xms{xms_mb}m -Duser.home={ghidra_home_dir}"
                ),
            }
            # Never inherit a table from the parent environment: this binary's table, or none.
            env.pop("TMAP_STUB_NAMES", None)
            # Every Ghidra setting stays inside the temporary user home: with XDG_CONFIG_HOME
            # inherited, Ghidra would write its settings into the user's real configuration tree.
            env.pop("XDG_CONFIG_HOME", None)
            if resolution is not None:
                env["TMAP_STUB_NAMES"] = str(stub_table)
            if exporting and self._extension is not None:
                # A copy in the user settings directory is not seen under this JVM's temporary
                # user home: link it there (lib/export_stamp.link_into_home).
                link_into_home(self._extension, headless.resolve().parent.parent, ghidra_home_dir)

            # The export has a budget of its own, as long as the analysis's: sharing the analysis's
            # wall clock pushed binaries that analyse close to their limit over it at the export.
            export_budget = timeout if exporting else None
            wall = timeout + 60 + (export_budget or 0)
            # The one budget the extraction's decompile retries share (ExportFunctions): half the
            # analysis budget when the session exports (its wall clock carries E besides), a little
            # when it does not (its wall clock is T + 60).
            env["TMAP_DECOMPILE_RETRY_BUDGET_S"] = str(
                timeout // 2 if exporting else _DECOMPILE_RETRY_NO_EXPORT_S
            )
            rc, stderr_raw = _run_subprocess(cmd, env, wall, cwd=proj_dir)
        finally:
            for d in (proj_dir, ghidra_home_dir):
                if d is not None:
                    shutil.rmtree(d, ignore_errors=True)

        elapsed = time.monotonic() - t0
        log_path = output_dir / f"{binary.name}_{sha8}.log"

        # ★ Read under the lock the teardown sets it with, whatever the return code: a JVM killed by
        # an interrupt exits with a signal code (or never started), and classifying that would
        # record a failure of a binary that was only cut off — the next scan would then skip a
        # "timed out" one or retry an "import failed" one for no reason.
        with _active_lock:
            interrupted = _shutting_down
        if interrupted:
            return GhidraResult(
                binary=binary,
                output_file=None,
                success=False,
                elapsed=elapsed,
                log_path=log_path if log_path.exists() else None,
                stderr_tail=stderr_raw if stderr_raw else None,
                reason=_INTERRUPTED,
                timeout_budget=None,
                log_offset=log_offset,
            )

        reason: str | None = None
        budget: int | None = timeout
        export_status: str | None = None
        export_report: dict[str, Any] | None = None
        timed_out = log_path.exists() and _analysis_timed_out(log_path, log_offset)
        if rc == -1:
            # Killed at the wall-clock budget. The analysis timing out decides it first: then
            # whatever was written describes a half analysis. Otherwise the extraction may have
            # finished before the kill (it writes its JSON by an atomic move, and every earlier file
            # was cleared above), so its JSON decides — with its markers, as always. A finished
            # extraction is this run's success, and only the export (cut off) is lost.
            if timed_out:
                analysis_status, function_count = "failed", 0
            else:
                analysis_status, function_count = _classify_analysis(
                    expected_out, binary, expected_pass, sha8, expected_stub
                )
            if analysis_status in _SUCCESS_STATUSES:
                export_status = "failed:timeout" if exporting else "extension_missing"
            else:
                analysis_status, function_count = "failed", 0
                reason = "timeout"
        elif rc == LAUNCH_FAILED_RC:
            # Ghidra never ran. No budget was spent, so none is recorded: the next scan tries
            # again instead of skipping this binary as one that "would only time out again".
            analysis_status, function_count = "failed", 0
            reason, budget, export_budget = "launch_failed", None, None
        elif timed_out:
            # Ghidra stopped its own analysis at -analysisTimeoutPerFile and exported what it had:
            # a timeout at this budget, whatever the JSON says.
            analysis_status, function_count = "failed", 0
            reason = "timeout"
        else:
            analysis_status, function_count = _classify_analysis(
                expected_out, binary, expected_pass, sha8, expected_stub
            )
            if analysis_status not in _SUCCESS_STATUSES:
                # failure reason by cause (import_failed is decided by run_ghidra from the log)
                if not expected_out.exists():
                    reason = "no_output"  # ran but produced no JSON
                else:
                    count, marker_pass, marker_sha8, marker_stub = _probe_function_count(
                        expected_out
                    )
                    if count is not None and _markers_mismatch(
                        marker_pass, marker_sha8, expected_pass, sha8, marker_stub, expected_stub
                    ):
                        reason = "stale_output"  # a JSON is there, but another pass/binary wrote it
                    else:
                        reason = "incomplete"  # malformed (parsed, but no functions array)
            elif exp is not None:
                export_status, export_report = _read_export(*exp)
                if export_status == "failed:no_file":
                    export_status = f"failed:{_export_failure_reason(log_path, log_offset)}"
            else:
                export_status = "extension_missing"
        success = analysis_status in _SUCCESS_STATUSES
        if not success and reason is not None:
            # The export of a session whose extraction failed is never kept, whatever was written.
            export_status = f"scan_failed:{reason}"
        usable = export_status in ("ok", "degraded") and exp is not None
        return GhidraResult(
            binary=binary,
            output_file=expected_out if success else None,
            success=success,
            elapsed=elapsed,
            analysis_status=analysis_status,
            function_count=function_count,
            log_path=log_path if log_path.exists() else None,
            stderr_tail=stderr_raw if stderr_raw else None,
            reason=reason,
            timeout_budget=budget,
            log_offset=log_offset,
            export_status=export_status,
            export_file=exp[0] if usable and exp is not None else None,
            export_report_file=exp[1] if usable and exp is not None else None,
            export_report=export_report if usable else None,
            export_budget=export_budget,
        )

    def run_all(
        self,
        records: list[ElfRecord],
        output_dir: Path,
        progress_callback: ProgressCallback | None = None,
        *,
        on_final: FinalCallback | None = None,
        on_export: ExportCallback | None = None,
    ) -> list[GhidraResult]:
        """Two-phase Ghidra dispatch.

        ★ Phase 1: run every binary ONCE in parallel (pool = config.max_parallel_jvms), each at a
        size-scaled timeout, with the timeout retry DEFERRED (retry=False).
        ★ Phase 2: re-run phase-1 failures SERIALLY at a doubled budget — a big binary that timed
        because the pool was CPU-saturated now retries with the whole machine to itself. This is the
        real fix (a per-call 'longer timeout' flag would not help: the retry would still compete in
        the pool). A phase-2 failure stays a failure with its ``reason`` (surfaced downstream).

        ``on_final(record, result)`` is called on the calling thread as soon as a record's
        EXTRACTION is final — a phase-1 success, or whatever phase 2 settles for a phase-1 failure —
        so a caller can store each binary the moment it is done instead of after the whole batch.
        On a normal return it has been called exactly once per record. When this raises (an
        interrupt, or a callback itself failing), only the records that had already reached their
        final result were passed to it.

        ★ The export is settled in two steps. A phase-1 success whose export FAILED (cut off at its
        budget, or any other failure) is finalized for its extraction at once, and re-run once more
        in phase 2 at the doubled budget, like a failure. ``on_export(record, result)`` then
        reports that re-run, at most once per record: a result with ``export_only=False`` is a
        whole new session (extraction AND usable export) to store in place of phase 1's; one with
        ``export_only=True`` carries only the export outcome to record, phase 1's extraction
        standing (the re-run's export failed again, or its extraction did — then its export is
        dropped with it, and phase 1's export outcome and budget stand). The returned list holds
        each record's latest result.

        Discovers analyzeHeadless once before spawning threads so GhidraNotFoundError is raised
        immediately rather than N times.
        """
        self.get_headless()  # fail-fast: raise GhidraNotFoundError before any thread work
        # Same for the name registry every extractor JVM reads: a malformed file stops the scan
        # here, once and loudly, instead of failing every binary one JVM at a time.
        validate_registry(self._script_dir / "extractor_names.tsv")
        output_dir.mkdir(parents=True, exist_ok=True)
        _reset_shutdown()  # a previous run's interrupt must not refuse this run's launches
        base = self._config.headless_timeout_seconds
        n = len(records)
        by_idx: dict[int, GhidraResult] = {}

        # Runtime memory guard: the configured pool size is a stable MemTotal derivation, but if
        # the machine is actually short on free memory right now, running that many JVMs would OOM/
        # swap. Clamp DOWN to what MemAvailable allows for THIS run only (config is untouched).
        workers, clamp_note = clamp_parallelism_to_memory(self._config.max_parallel_jvms)
        if clamp_note:
            logger.warning("ghidra: %s", clamp_note)
        pool = ThreadPoolExecutor(max_workers=workers)
        try:
            future_to_idx = {
                pool.submit(
                    self.run_ghidra,
                    rec.path,
                    output_dir,
                    _dynamic_timeout(rec.path, base),
                    rec.arch,
                    rec.sha256[:8],
                    False,  # phase 1: defer the timeout retry to the serial phase 2
                ): i
                for i, rec in enumerate(records)
            }
            try:
                for done, fut in enumerate(as_completed(future_to_idx), 1):
                    i = future_to_idx[fut]
                    rec = records[i]
                    try:
                        result = fut.result()
                    except Exception as exc:
                        logger.error("Ghidra crashed for %s: %s", rec.name, exc)
                        result = GhidraResult(
                            binary=rec.path, output_file=None, success=False, elapsed=0.0
                        )
                    by_idx[i] = result
                    # A success is final here; a failure is settled by phase 2, which reports it.
                    if result.success and on_final is not None:
                        on_final(rec, result)
                    if progress_callback is not None:
                        progress_callback(
                            "ghidra",
                            {"done": done, "total": n, "name": rec.name, "ok": result.success},
                        )
                    status = "ok" if result.success else "fail"
                    logger.info("[%d/%d] %s %s (%.0fs)", done, n, rec.name, status, result.elapsed)
            except BaseException as exc:
                # Not only an interrupt: ``on_final`` (or the progress callback) failing must tear
                # the pool down the same way, or the JVMs still running outlive the exception.
                logger.warning(
                    "%s — terminating %d live Ghidra process group(s)",
                    "interrupted" if isinstance(exc, KeyboardInterrupt) else "aborted",
                    len(_active_pgids),
                )
                # Refuse new launches FIRST, then drop the queue, then kill what is running: a
                # worker between its checks and Popen now sees the flag instead of starting a JVM
                # after the teardown.
                begin_shutdown()
                for f in future_to_idx:
                    f.cancel()
                terminate_all()
                raise
        finally:
            # On the interrupt path the JVMs are already dead, so each worker's
            # communicate() returns immediately and shutdown(wait=True) does not hang;
            # cancel_futures drops the not-yet-started ones (Python 3.9+).
            terminate_all()
            pool.shutdown(wait=True, cancel_futures=True)

        # Phase 2: serial isolated retry of the failures, at a doubled (ceiling-capped) budget — and
        # of the binaries whose extraction finished but whose export did not. Those get the larger
        # budget too: one cut off at its export would be cut off again at the same budget on every
        # later scan, never reaching the larger one.
        export_retry = {
            i
            for i in range(n)
            if by_idx[i].success and (by_idx[i].export_status or "").startswith("failed:")
        }
        failed = [i for i in range(n) if not by_idx[i].success or i in export_retry]
        if failed:
            logger.info(
                "ghidra: retrying %d failed binary/ies serially (isolated CPU)", len(failed)
            )
            try:
                for k, i in enumerate(failed, 1):
                    rec = records[i]
                    budget = retry_budget_seconds(rec.path, base)
                    if budget is None:
                        # Unmeasurable file: the same fallback the scaling has always used (an
                        # unscaled base, doubled and capped), so behaviour here is unchanged.
                        budget = min(_TIMEOUT_CEILING_SECONDS, base * 2)
                    retry_timeout = budget
                    try:
                        r = self.run_ghidra(
                            rec.path, output_dir, retry_timeout, rec.arch, rec.sha256[:8], False
                        )
                    except Exception as exc:
                        logger.error("Ghidra retry crashed for %s: %s", rec.name, exc)
                        # Phase 1's result stands as the final one. Reported outside the try
                        # above, so a failure of the callback is never taken for a crashed retry.
                        # (An export re-run's binary was finalized in phase 1 already.)
                        if on_final is not None and i not in export_retry:
                            on_final(rec, by_idx[i])
                        continue
                    r.retried = True
                    if i in export_retry:
                        if r.reason == _INTERRUPTED:
                            continue  # phase 1's extraction and export outcome stand
                        settled = self._settle_export(by_idx[i], r)
                        by_idx[i] = settled
                        if on_export is not None:
                            on_export(rec, settled)
                    else:
                        by_idx[i] = r
                        if on_final is not None:
                            on_final(rec, r)
                    if progress_callback is not None:
                        progress_callback(
                            "ghidra_retry",
                            {"done": k, "total": len(failed), "name": rec.name, "ok": r.success},
                        )
                    logger.info(
                        "retry [%d/%d] %s %s (%.0fs)",
                        k,
                        len(failed),
                        rec.name,
                        "ok" if r.success else "fail",
                        r.elapsed,
                    )
            except BaseException as exc:
                logger.warning(
                    "%s during serial retry — terminating live process group(s)",
                    "interrupted" if isinstance(exc, KeyboardInterrupt) else "aborted",
                )
                begin_shutdown()
                terminate_all()
                raise

        return [by_idx[i] for i in range(n)]

    @staticmethod
    def _settle_export(first: GhidraResult, rerun: GhidraResult) -> GhidraResult:
        """What a phase-2 re-run of an export settles for a binary phase 1 extracted: the whole
        re-run when it extracted AND exported; otherwise only an export outcome — the re-run's
        failed export, or, when the re-run's extraction failed, phase 1's export outcome and budget
        (the re-run's export is dropped with its extraction: an export is only kept with the
        extraction of its own session)."""
        if rerun.success and rerun.export_status in ("ok", "degraded"):
            return rerun
        if rerun.success:
            return replace(
                first,
                export_status=rerun.export_status,
                export_budget=rerun.export_budget,
                export_file=None,
                export_report_file=None,
                export_report=None,
                retried=True,
                export_only=True,
            )
        return replace(first, retried=True, export_only=True)
