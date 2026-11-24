# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Make a toolchain this suite needs but cannot find an error, not a silent skip.

Every Ghidra-backed test here is guarded by a ``skipif`` on the toolchain it needs — right for a
developer's machine, where a run without the decompiler should still check what it can. In CI it
is the opposite: this is the one job that runs the real decompiler and compiles the Java the wheel
ships, and release.yml publishes on "CI passed". With ``analyzeHeadless`` missing from PATH, or a
BinExport a scan would not load, every one of those tests skipped and the job was green.

So CI sets ``TMAP_REQUIRE_GHIDRA=1`` and the session refuses to start without the toolchain,
naming what is missing. Nothing local changes: unset, the skips stand (scripts/ci-local.sh leaves
it unset and reports how many were skipped).
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

REQUIRE_ENV = "TMAP_REQUIRE_GHIDRA"


def missing_toolchain() -> list[str]:
    """What this suite needs and this machine does not have, each as a line. The BinExport check
    asks the same question a scan asks (``export_stamp.scan_extension``), not whether some file is
    on disk: an extension present but not one the scan's JVM would load skips the export tests
    just as surely as none at all."""
    out: list[str] = []
    headless = shutil.which("analyzeHeadless")
    if headless is None:
        out.append("analyzeHeadless is not on PATH (Ghidra's support/ directory)")
    else:
        from treasure_map.lib.export_stamp import scan_extension

        if scan_extension(Path(headless).resolve().parents[1]).ext_dir is None:
            out.append("no BinExport extension a scan of this Ghidra would load")
    for tool in ("javac", "java"):
        if shutil.which(tool) is None:
            out.append(f"{tool} is not on PATH (a JDK compiles the shipped Ghidra scripts)")
    return out


def pytest_sessionstart(session: pytest.Session) -> None:
    if os.environ.get(REQUIRE_ENV) != "1":
        return
    gaps = missing_toolchain()
    if gaps:
        pytest.exit(
            f"{REQUIRE_ENV}=1, so a skipped toolchain is a failure, not a pass:\n  "
            + "\n  ".join(gaps),
            returncode=1,
        )
