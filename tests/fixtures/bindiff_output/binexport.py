# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A standalone BinExport run — what the committed fixture beside this file is rebuilt from.

NOT part of the shipped package and not a step of any pipeline: a scan exports each binary inside
its own Ghidra session and archives the result, and a diff reads that archive, so nothing in
``treasure_map`` exports a binary on its own any more. What is kept here is the one-off export
``make_fixture.sh`` needs, and the same path a maintainer uses by hand to reproduce a toolchain
failure. It lives with the fixture so the shipped diff driver holds only code a diff runs.

REAL-MACHINE PATH — requires Ghidra 11.4.3 + the BinExport extension; it cannot run in CI. The
tests around it drive it with the subprocess layer faked, which is what keeps its failure mapping
(timeout / crash / no file) readable without the toolchain. It runs through the driver's own
``_run_killable``, so a timed-out or interrupted export takes its whole process group — never an
orphaned JVM — exactly as a BinDiff run does.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from treasure_map.lib.diff import driver
from treasure_map.lib.diff import toolchain as _toolchain
from treasure_map.lib.diff.driver import (
    FAIL_BINEXPORT_CRASH,
    FAIL_BINEXPORT_NO_FILE,
    FAIL_TIMEOUT,
    DiffToolchainError,
)
from treasure_map.lib.diff.export_report import report_path
from treasure_map.lib.export_stamp import EXPORT_SCRIPT, EXPORT_SCRIPT_DIR

if TYPE_CHECKING:
    from treasure_map.lib.config.config import Config

# BinExport JVM heap for a standalone export. A conservative fixed ceiling, not the per-binary
# adaptive_heap_mb ladder a scan uses: its peak-heap demand is unmeasured, and 4096 never runs out
# of memory mid-export.
_DIFF_BINEXPORT_HEAP_MB = 4096


def _binexport_present(headless: Path) -> bool:
    """Is exactly one BinExport extension loaded by the discovered Ghidra?

    ``analyzeHeadless`` lives at ``<ghidra_home>/support/analyzeHeadless``, so the home is the
    resolved file's parent's parent. Where Ghidra loads the extension from is answered by the same
    locator the toolchain stamp reads (lib.diff.toolchain): the install's own Extensions directory
    and the user settings directory. Two loaded copies, or a settings directory that cannot be
    determined, both read as 'not confirmed present', so a caller reports it missing rather than
    silently proceeding; ``tmap doctor`` shows where it looked."""
    home = headless.resolve().parent.parent
    dirs = _toolchain.binexport_dirs(home)
    return dirs is not None and len(dirs) == 1


def _run_binexport(so_path: Path, config: Config, out_dir: Path, side: str, timeout_s: int) -> Path:
    """Export one ``.so`` to a ``.BinExport`` via Ghidra headless + tmap's own export script.

    REAL-MACHINE PATH — requires Ghidra 11.4.3 + the BinExport extension (for its classes); not
    runnable in CI. Uses tmap's own non-interactive ``ExportBinExport.java`` (NOT the extension's
    interactive ``BinExport.java``, which ignores the output-path argument and lets analyzeHeadless
    exit 0 with no file). The argv here is the one adjustment point if the export entry changes."""
    from treasure_map.lib.analyze.elf_inventory import detect_arch
    from treasure_map.lib.analyze.ghidra_runner import find_headless

    headless = find_headless(config.ghidra)
    export_path = out_dir / f"{side}.BinExport"
    log_path = out_dir / f"{side}.ghidra.log"
    # The language the scan imports the binary under, named here too: left to Ghidra's own guess,
    # a MIPS binary could be read in another variant than the scan's, and its export with it.
    arch = detect_arch(so_path)
    # An architecture detect_arch does not support comes back as an ``UNKNOWN_…`` label, which is
    # no Ghidra language: Ghidra is left to its own guess rather than handed a name it rejects.
    processor = ["-processor", arch] if arch and not arch.startswith("UNKNOWN_") else []
    with tempfile.TemporaryDirectory(prefix="tm_binexport_proj_") as proj:
        cmd = [
            str(headless),
            proj,
            "Proj",
            *processor,
            "-import",
            str(so_path),
            "-postScript",
            EXPORT_SCRIPT,
            str(export_path),
            str(report_path(export_path)),
            "-scriptPath",
            str(EXPORT_SCRIPT_DIR),
            "-deleteProject",
            "-log",
            str(log_path),
            "-analysisTimeoutPerFile",
            str(timeout_s),
        ]
        env = {**os.environ, "JAVA_TOOL_OPTIONS": f"-Xmx{_DIFF_BINEXPORT_HEAP_MB}m"}
        try:
            # Started from the project directory: analyzeHeadless resolves a bare script name
            # against the directory it starts in first, so a same-named file there would run.
            proc = driver._run_killable(cmd, env, timeout_s + 120, cwd=proj)
        except subprocess.TimeoutExpired as exc:
            raise DiffToolchainError(
                f"BinExport timed out for side {side} ({so_path.name})", kind=FAIL_TIMEOUT
            ) from exc
    if proc.returncode != 0:
        raise DiffToolchainError(
            f"BinExport subprocess failed (side {side}, {so_path.name}, rc={proc.returncode})\n"
            + driver._diag(cmd, proc, log_path),
            kind=FAIL_BINEXPORT_CRASH,
        )
    if _analysis_timed_out(proc, log_path):
        # Checked before the files: an export written after the analysis stopped is complete as a
        # file and still describes a half-analysed program, and when no export was written the
        # timeout says more about why.
        raise DiffToolchainError(
            f"Ghidra's analysis of side {side} ({so_path.name}) ran past -analysisTimeoutPerFile "
            f"({timeout_s}s): the export would describe a program it did not finish analysing\n"
            + driver._diag(cmd, proc, log_path),
            kind=FAIL_TIMEOUT,
        )
    if not export_path.exists() or not report_path(export_path).is_file():
        raise DiffToolchainError(
            f"BinExport produced no file for side {side} ({so_path.name}) although the process "
            "exited 0 — the postScript did not run to completion (analyzeHeadless returns 0 even "
            f"when a postScript aborts). Expected: {export_path} and its report\n"
            + driver._diag(cmd, proc, log_path),
            kind=FAIL_BINEXPORT_NO_FILE,
        )
    return export_path


# The line analyzeHeadless reports when -analysisTimeoutPerFile stops the analysis. It then still
# runs the post-script and exits 0, so this line is the only sign. Ghidra's own wording only: a
# library or flag with "timeout" in its name must not match.
_ANALYSIS_TIMED_OUT = re.compile(rb"REPORT: Analysis timed out at \d+ seconds")


def _analysis_timed_out(proc: subprocess.CompletedProcess[bytes], log_path: Path) -> bool:
    """Whether Ghidra reported its analysis timed out, on stdout or in its -log file. Both are
    read: the console always has it, but either can be missing (a log that was never written, an
    output that was not captured), and one missing must not pass the check silently."""
    if _ANALYSIS_TIMED_OUT.search(proc.stdout or b""):
        return True
    try:
        return bool(_ANALYSIS_TIMED_OUT.search(log_path.read_bytes()))
    except OSError:
        return False
