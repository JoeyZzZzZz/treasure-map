# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The stored architecture moves with an extraction attempt, on its success and on its failure.

ingest_elfs no longer writes the detected architecture up front (an interrupt before the attempt
would make the old extraction look current); the attempt's own stamp records the architecture it ran
under, so a scan after it compares against what was actually extracted.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import patch

from tests.unit.lib.test_pipeline import _NAMES, _e2e_cfg, _firmware, _ghidra
from tests.unit.lib.test_scan_export import _Sessions, _with_extension
from treasure_map.lib.analyze.ghidra_runner import GhidraRunner
from treasure_map.lib.analyze.pipeline import run_analyze
from treasure_map.lib.workspace import Workspace

_OLD = "x86:LE:64:default"
_NEW = "x86:LE:64:other"


def _arch_by_name(db: Path) -> dict[str, tuple[str, int | None, int | None]]:
    conn = sqlite3.connect(db)
    try:
        return {
            r[0]: (r[1], r[2], r[3])
            for r in conn.execute("SELECT name, arch, bits, ghidra_ok FROM binaries")
        }
    finally:
        conn.close()


def test_both_attempt_stamps_record_the_architecture_they_ran_under(tmp_path: Path) -> None:
    """A firmware scanned under one architecture, then again after detection moved for every
    binary: the binaries extracted again carry the new architecture (success stamp), and so does the
    one whose re-extraction failed (failure stamp) — so the next scan does not re-run it as moved.

    MUTATION (verified RED, 1 failed): drop arch/bits from the success stamp in
    ghidra_ingest -> the extracted binaries keep the old one. Drop them from the pipeline's
    failure stamp -> the failed binary keeps the old one."""
    fs = _firmware(tmp_path)
    home = _ghidra(tmp_path)
    _with_extension(home)
    failing = _NAMES[0]
    plan = {n: ["ok", "ok"] for n in _NAMES}
    plan[failing] = ["ok", "scan_failed", "scan_failed"]  # phase 1 and its phase-2 retry
    sessions = _Sessions(plan)
    db = tmp_path / "ws" / "analysis.db"
    with patch.object(GhidraRunner, "_run_session", lambda self, *a, **k: sessions(self, *a, **k)):
        for arch in (_OLD, _NEW):
            with (
                patch("treasure_map.lib.analyze.elf_inventory.detect_arch", lambda p, a=arch: a),
                Workspace(db.parent) as ws,
            ):
                run_analyze(fs, ws, _e2e_cfg(home))
    got = _arch_by_name(db)
    assert set(got) == set(_NAMES)
    assert got[failing] == (_NEW, 64, 0)
    assert all(got[n] == (_NEW, 64, 1) for n in _NAMES if n != failing), got
