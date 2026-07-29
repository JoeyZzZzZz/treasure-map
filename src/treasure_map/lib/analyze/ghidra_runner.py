# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Ghidra headless analysis runner.

Path discovery order: config.local.home → GHIDRA_HOME env → PATH.
Single-binary wrapper: GhidraRunner.run_ghidra().  Parallel dispatch: run_all().
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import signal
import struct
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from treasure_map.lib.analyze.elf_inventory import ElfRecord, has_substantial_text
from treasure_map.lib.config.config import GhidraConfig
from treasure_map.lib.errors import GhidraNotFoundError
from treasure_map.version import UNKNOWN_VERSION

logger = logging.getLogger(__name__)

# --- live Ghidra process-group registry (for deterministic teardown on abort) ---
# Each subprocess is started with start_new_session=True, so its pid == its pgid
# (session/group leader). We track live pgids so an interrupt handler can killpg
# the whole tree (analyzeHeadless wrapper + java + children) — terminal SIGINT does
# NOT reach them because they are in their own session.
_active_pgids: set[int] = set()
_active_lock = threading.Lock()


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

_SCRIPT_DIR = Path(__file__).parent / "ghidra"
_GHIDRA_RELEASES_URL = "https://github.com/NationalSecurityAgency/ghidra/releases"


def compute_pass_version(script_dir: Path) -> str:
    """Content hash of the Ghidra extraction pass — every .java in the script dir (ExportFunctions
    plus any sibling).

    This is a cache-key dimension: the per-binary Ghidra output depends on the pass logic as much as
    on the binary bytes, so editing the pass must invalidate the cache and re-extract automatically
    (no manual JSON/db deletion). A missing/unreadable script dir yields a stable sentinel so a scan
    still runs (and treats everything as needing a first extraction) rather than crashing."""
    h = hashlib.sha256()
    try:
        scripts = sorted(script_dir.glob("*.java"))
    except OSError:
        scripts = []
    for p in scripts:
        try:
            body = p.read_bytes()
        except OSError:
            continue
        h.update(p.name.encode("utf-8"))
        h.update(b"\0")
        h.update(body)
    return h.hexdigest()[:16]


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
    # ★ Red-line (degrade must be visible): the tri-state analysis outcome, so a partial/empty run
    # is never frozen as "clean". "ok" = functions produced; "ok_empty" = a legitimately code-free
    # object (no substantial .text) with 0 functions (do not re-churn); "failed" = no usable output
    # OR code present but 0 functions decompiled. ``success`` is True for ok / ok_empty only.
    analysis_status: str = "failed"
    function_count: int = 0  # functions in the output JSON (0 for ok_empty / failed)
    # WHY a failed run failed, so a consumer distinguishes a recoverable timeout (re-scan may finish
    # it) from a structural failure. None on success. One of: 'timeout' / 'import_failed' /
    # 'no_output' / 'incomplete'. Recorded onto binaries.ghidra_status_reason for the incomplete
    # surfacing -- degrade must be visible AND explicable, not just a flat 'failed'.
    reason: str | None = None


# ★ A binary that cannot finish within this even on an isolated retry is a genuine hang, not a
# needs-more-time case — the dynamic timeout never runs a single binary unbounded.
_TIMEOUT_CEILING_SECONDS = 1800  # 30 min


def _dynamic_timeout(binary: Path, base: int) -> int:
    """A per-binary analysis timeout scaled by file size, replacing the flat one-size-fits-all.

    A small binary uses ``base``; a large one (whose analysis+export budget genuinely needs more)
    gets proportionally more time, capped at the ceiling. This is why a 28M library no longer times
    out under a budget sized for a 200K one — and why a truly hung binary still cannot run forever.
    """
    try:
        size_mb = binary.stat().st_size / 1024 / 1024
    except OSError:
        return base
    scaled = base if size_mb < 10 else int(base * (size_mb / 10))
    return min(_TIMEOUT_CEILING_SECONDS, max(base, scaled))


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


def _probe_function_count(output_file: Path) -> int | None:
    """Number of functions in a Ghidra output JSON, or None when it is missing/unparseable.

    None signals a hard failure (no usable output); 0 is a valid parsed-but-empty result the caller
    judges against the ELF's code presence. The output files are modest, so a full parse is fine."""
    try:
        with output_file.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    funcs = data.get("functions") if isinstance(data, dict) else None
    return len(funcs) if isinstance(funcs, list) else None


def _classify_analysis(output_file: Path, binary: Path) -> tuple[str, int]:
    """Classify a finished run into (analysis_status, function_count).

    ★ Red-line: success requires a NON-EMPTY functions array, not merely a >200-byte file — a
    truncated/partial run can leave a well-formed-but-empty shell (``{"functions": []}``), and
    counting that as success froze the binary as analyzed so it never re-ran. A code-free object
    (no substantial .text) with 0 functions is ``ok_empty`` (legitimate; do not re-churn); a binary
    with code but 0 functions is ``failed`` (not clean)."""
    count = _probe_function_count(output_file) if output_file.exists() else None
    if count is None:
        return "failed", 0
    if count > 0:
        return "ok", count
    return ("failed", 0) if has_substantial_text(binary) else ("ok_empty", 0)


def _build_cmd(
    headless: Path,
    binary: Path,
    arch: str,
    proj_dir: Path,
    output_dir: Path,
    script_dir: Path,
    sha8: str,
    timeout_s: int,
) -> list[str]:
    """Build the analyzeHeadless invocation command list."""
    log_path = output_dir / f"{binary.name}_{sha8}.log"
    return [
        str(headless),
        str(proj_dir),
        "Proj",
        "-processor",
        arch,
        "-postScript",
        "ExportFunctions.java",
        "-scriptPath",
        str(script_dir),
        "-deleteProject",
        "-log",
        str(log_path),
        "-analysisTimeoutPerFile",
        str(timeout_s),
        "-import",
        str(binary),
    ]


def _run_subprocess(cmd: list[str], env: dict[str, str], timeout: int) -> tuple[int, str]:
    """Spawn cmd in a new session/process group; kill the whole group on timeout
    or interrupt.

    Returns (returncode, stderr_tail). returncode -1 = timeout or launch error.
    analyzeHeadless is a shell wrapper that spawns Java without exec, so the whole
    process group must be killed to avoid orphan JVMs. The pgid is registered so a
    top-level interrupt can tear every live group down (terminal SIGINT never
    reaches them — they are in their own session).
    """
    proc: subprocess.Popen[bytes] | None = None
    pgid: int | None = None
    try:
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
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
            return -1, str(exc)  # ordinary launch error: behave as before
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
    ) -> None:
        self._config = config
        self._script_dir = script_dir or _SCRIPT_DIR
        self._headless = headless  # None = lazy-discovered on first use

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
        once IN PARALLEL (retry=False), phase 2 re-runs the failures SERIALLY (retry=True) so a big
        binary retries with the CPU to itself instead of competing in the pool. A still-failing
        retry returns success=False with an explicit ``reason`` — never a fabricated 'ok'.
        """
        headless = self.get_headless()
        output_dir.mkdir(parents=True, exist_ok=True)
        if not sha8:
            sha8 = binary.name[:8]

        r1 = self._run_once(binary, output_dir, arch, sha8, timeout, headless)
        if r1.success:
            return r1

        import_failed = False
        if r1.log_path is not None and r1.log_path.exists():
            try:
                import_failed = "Import failed" in r1.log_path.read_text(errors="replace")
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
            if r2.success:
                r2.elapsed = total_elapsed
                r2.retried = True
                return r2

        return GhidraResult(
            binary=binary,
            output_file=None,
            success=False,
            elapsed=total_elapsed,
            retried=did_retry,
            log_path=r1.log_path,
            stderr_tail=r1.stderr_tail,
            reason="import_failed" if import_failed else last.reason,
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
        proj_dir = Path(tempfile.mkdtemp(prefix="tm_ghidra_proj_"))
        ghidra_home_dir = Path(tempfile.mkdtemp(prefix="tm_ghidra_home_"))

        cmd = _build_cmd(
            headless, binary, arch, proj_dir, output_dir, self._script_dir, sha8, timeout
        )

        size_mb = binary.stat().st_size / 1024 / 1024
        heap_mb = 512 if size_mb < 1 else 768 if size_mb < 10 else 1536 if size_mb < 50 else 2048
        xms_mb = max(64, heap_mb // 8)
        env: dict[str, str] = {
            **dict(os.environ),
            "OUTPUT_DIR": str(output_dir),
            "SHA8": sha8,
            "JAVA_TOOL_OPTIONS": f"-Xmx{heap_mb}m -Xms{xms_mb}m -Duser.home={ghidra_home_dir}",
        }

        rc = 0
        stderr_raw = ""
        try:
            rc, stderr_raw = _run_subprocess(cmd, env, timeout + 60)
        finally:
            shutil.rmtree(proj_dir, ignore_errors=True)
            shutil.rmtree(ghidra_home_dir, ignore_errors=True)

        elapsed = time.monotonic() - t0
        expected_out = output_dir / f"{binary.name}_{sha8}_ghidra.json"
        log_path = output_dir / f"{binary.name}_{sha8}.log"

        analysis_status, function_count = _classify_analysis(expected_out, binary)
        success = analysis_status in ("ok", "ok_empty")
        # reason for a failure, by cause (import_failed is decided by run_ghidra from the log)
        reason: str | None = None
        if not success:
            if rc == -1:
                reason = "timeout"  # subprocess killed at the wall-clock budget
            elif not expected_out.exists():
                reason = "no_output"  # ran but produced no JSON
            else:
                reason = "incomplete"  # JSON present but unusable (malformed / 0 functions on code)
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
        )

    def run_all(
        self,
        records: list[ElfRecord],
        output_dir: Path,
        progress_callback: ProgressCallback | None = None,
    ) -> list[GhidraResult]:
        """Two-phase Ghidra dispatch.

        ★ Phase 1: run every binary ONCE in parallel (pool = config.max_parallel_jvms), each at a
        size-scaled timeout, with the timeout retry DEFERRED (retry=False).
        ★ Phase 2: re-run phase-1 failures SERIALLY at a doubled budget — a big binary that timed
        because the pool was CPU-saturated now retries with the whole machine to itself. This is the
        real fix (a per-call 'longer timeout' flag would not help: the retry would still compete in
        the pool). A phase-2 failure stays a failure with its ``reason`` (surfaced downstream).

        Discovers analyzeHeadless once before spawning threads so GhidraNotFoundError is raised
        immediately rather than N times.
        """
        self.get_headless()  # fail-fast: raise GhidraNotFoundError before any thread work
        output_dir.mkdir(parents=True, exist_ok=True)
        base = self._config.headless_timeout_seconds
        n = len(records)
        by_idx: dict[int, GhidraResult] = {}

        pool = ThreadPoolExecutor(max_workers=self._config.max_parallel_jvms)
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
                    if progress_callback is not None:
                        progress_callback(
                            "ghidra",
                            {"done": done, "total": n, "name": rec.name, "ok": result.success},
                        )
                    status = "ok" if result.success else "fail"
                    logger.info("[%d/%d] %s %s (%.0fs)", done, n, rec.name, status, result.elapsed)
            except KeyboardInterrupt:
                logger.warning(
                    "interrupted — terminating %d live Ghidra process group(s)",
                    len(_active_pgids),
                )
                terminate_all()
                for f in future_to_idx:
                    f.cancel()
                raise
        finally:
            # On the interrupt path the JVMs are already dead, so each worker's
            # communicate() returns immediately and shutdown(wait=True) does not hang;
            # cancel_futures drops the not-yet-started ones (Python 3.9+).
            terminate_all()
            pool.shutdown(wait=True, cancel_futures=True)

        # Phase 2: serial isolated retry of the failures, at a doubled (ceiling-capped) budget.
        failed = [i for i in range(n) if not by_idx[i].success]
        if failed:
            logger.info(
                "ghidra: retrying %d failed binary/ies serially (isolated CPU)", len(failed)
            )
            try:
                for k, i in enumerate(failed, 1):
                    rec = records[i]
                    retry_timeout = min(
                        _TIMEOUT_CEILING_SECONDS, _dynamic_timeout(rec.path, base) * 2
                    )
                    try:
                        r = self.run_ghidra(
                            rec.path, output_dir, retry_timeout, rec.arch, rec.sha256[:8], False
                        )
                    except Exception as exc:
                        logger.error("Ghidra retry crashed for %s: %s", rec.name, exc)
                        continue
                    r.retried = True
                    by_idx[i] = r
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
            except KeyboardInterrupt:
                logger.warning(
                    "interrupted during serial retry — terminating live process group(s)"
                )
                terminate_all()
                raise

        return [by_idx[i] for i in range(n)]
