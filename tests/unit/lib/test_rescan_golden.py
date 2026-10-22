# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The rescan fixture: it reaches the real scan and hunt, and its digest is deterministic.

``scripts/rescan_same_stamp_check.py`` runs the fixture harness (``tests/fixtures/rescan_golden/
harness.py``) on the current tree and on a base tree whose two code stamps are equal, and fails
when the digests differ: equal stamps must mean equal output, and an output change the stamps did
not see is something outside the hash. That comparison only means something when

  * the fixture actually exercises both sides (a run that stores nothing digests the same under
    any code) — the floor below, read straight from the databases the run left; and
  * the digest is a property of the code alone, not of where the run happened or how Python
    seeded its hashes — the determinism check below: two runs, hash seeds 1 and 2, different
    directories, equal digests.

The harness runs as a subprocess with ``src`` of THIS tree first on PYTHONPATH and a throwaway
HOME (it also resets HOME itself before importing the package), so nothing here can reach the
real ``~/.treasure-map``.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[3]
HARNESS = REPO / "tests" / "fixtures" / "rescan_golden" / "harness.py"


def _run_harness(base: Path, seed: int) -> tuple[Path, dict[str, Any]]:
    work = base / "work"
    out = base / "digest.json"
    env = {k: v for k, v in os.environ.items() if not k.startswith("TM_")}
    env.update(
        HOME=str(base / "home"),
        PYTHONHASHSEED=str(seed),
        PYTHONPATH=str(REPO / "src"),
        PYTHONDONTWRITEBYTECODE="1",
    )
    proc = subprocess.run(
        [
            sys.executable,
            str(HARNESS),
            "--work",
            str(work),
            "--out",
            str(out),
            "--expect-package",
            str(REPO / "src" / "treasure_map"),
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    assert proc.returncode == 0, f"harness failed (rc={proc.returncode}):\n{proc.stderr}"
    return work, json.loads(out.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def two_runs(tmp_path_factory: pytest.TempPathFactory) -> list[tuple[Path, dict[str, Any]]]:
    return [
        _run_harness(tmp_path_factory.mktemp("rescan_seed1"), 1),
        _run_harness(tmp_path_factory.mktemp("rescan_seed2"), 2),
    ]


def test_the_fixture_reaches_the_scan_and_the_hunt(
    two_runs: list[tuple[Path, dict[str, Any]]],
) -> None:
    """The floor: candidates of more than one sink class, cross-binary references, the symlink
    inventory and more than one kind of non-binary file all came out of the run.

    MUTATION (verified RED, 1 failed): stamp ``data["sha8"] = "00000000"`` in the harness's
    stand-in ``run_all`` -> the ingest skips each JSON as another binary's output, no function is
    stored, and ``instances >= 3`` fails with 0 written. (The determinism test stays green there:
    two empty runs digest alike, which is exactly why this floor exists.)"""
    work, _digest = two_runs[0]
    db = sqlite3.connect(work / "ws" / "analysis.db")
    atlas = sqlite3.connect(work / "atlas.db")
    try:
        instances = atlas.execute("SELECT COUNT(*) FROM instance").fetchone()[0]
        sink_classes = {
            r[0]
            for r in atlas.execute(
                "SELECT DISTINCT p.sink_class FROM instance i JOIN pattern p USING (pattern_id)"
            )
        }
        xrefs = db.execute("SELECT COUNT(*) FROM xrefs").fetchone()[0]
        symlinks = db.execute("SELECT COUNT(*) FROM fs_symlinks").fetchone()[0]
        kinds = {r[0] for r in db.execute("SELECT DISTINCT kind FROM non_binary_files")}
    finally:
        db.close()
        atlas.close()
    assert instances >= 3, f"only {instances} instance(s) written"
    assert len(sink_classes) >= 2, f"instances span only {sorted(sink_classes)}"
    assert xrefs > 0, "no cross-binary reference was built"
    assert symlinks > 0, "the symlink inventory is empty"
    assert len(kinds) >= 2, f"non-binary files of only {sorted(kinds)}"


def test_the_digest_is_a_property_of_the_code_alone(
    two_runs: list[tuple[Path, dict[str, Any]]],
) -> None:
    """Same code, different directory and hash seed -> the same digest, table by table.

    MUTATION (verified RED, 1 failed): drop ``("atlas", "run", "hunt_input_fingerprint")`` from
    the harness's EXCLUDED_COLUMNS -> the run row carries a hash over each run's own absolute
    paths, ``atlas/run`` differs between the two runs, and the digests differ.
    MUTATION (verified RED, 1 failed): make ``_normalise`` leave the work directory in place
    (``value = value``) -> ``analysis/binaries``, ``atlas/instance``, ``atlas/run`` and two more
    tables differ."""
    (_w1, first), (_w2, second) = two_runs
    differing = sorted(
        name
        for name in set(first["tables"]) | set(second["tables"])
        if first["tables"].get(name) != second["tables"].get(name)
    )
    assert first["digest"] == second["digest"], f"tables that differ: {differing}"
    assert differing == []
