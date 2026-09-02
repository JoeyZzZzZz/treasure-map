# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""`tmap rescan` selection, and the honesty rules about what it cannot do.

The command's whole job is to answer "which of my runs were produced by an older tmap, and what
happens to them". The rules pinned here are about the SECOND half of that: a run it cannot act on
must still be named. A refresh list that quietly omits the runs it failed to consider reads exactly
like a list on which everything was fine.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from treasure_map.cli.hunt_cli import _rescan_reason, rescan
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import RunRow
from treasure_map.version import UNKNOWN_VERSION

COMMIT = "c" * 40
OTHER = "d" * 40


def _run(**over: object) -> RunRow:
    base: dict[str, object] = {
        "run_id": "r1",
        "firmware_path": "/fw",
        "hunt_commit": COMMIT,
        "scan_status": "complete",
    }
    base.update(over)
    return RunRow(**base)  # type: ignore[arg-type]


def test_a_run_hunted_by_this_commit_is_left_alone() -> None:
    assert _rescan_reason(_run(), commit=COMMIT) is None


@pytest.mark.parametrize(
    ("run", "commit"),
    [
        (_run(hunt_commit=OTHER), COMMIT),
        (_run(hunt_commit=None), COMMIT),
        (_run(hunt_commit=UNKNOWN_VERSION), COMMIT),
        (_run(scan_status="in_progress"), COMMIT),
        (_run(scan_status="failed"), COMMIT),
        (_run(), UNKNOWN_VERSION),
    ],
)
def test_anything_not_shown_current_is_offered_for_rescan(run: RunRow, commit: str) -> None:
    """Rescan uses the SKIP's bar, not the refusal's: offer the work whenever sameness is unproven.

    That is the right direction here because the user asked for a refresh and can see the list
    before anything runs — over-offering costs a line of output, under-offering silently leaves a
    stale run in place while reporting success.

    MUTATION: make ``_rescan_reason`` return None for a NULL or 'unknown' stamp -> RED.
    """
    reason = _rescan_reason(run, commit=commit)
    assert reason, "an out-of-date run must come with the reason it is out of date"


def _atlas_with(tmp_path: Path, rows: list[dict[str, object]]) -> Path:
    db = tmp_path / "atlas.db"
    conn = open_atlas(db)
    for r in rows:
        cols = ", ".join(r)
        conn.execute(
            f"INSERT INTO run ({cols}) VALUES ({', '.join('?' * len(r))})", tuple(r.values())
        )
    conn.commit()
    conn.close()
    return db


def test_runs_that_cannot_be_rescanned_are_named_never_dropped(tmp_path: Path) -> None:
    """★ THE HONESTY RULE OF THIS COMMAND.

    A run with no recorded firmware root, and one whose root has been deleted, are both out of date
    and both un-refreshable. Skipping them silently would leave the operator believing a rescan
    covered everything it listed. They are reported in their own section, by name, with which of
    the two situations applies — the two need different fixes.

    MUTATION: drop the ``unrunnable`` reporting branch, or fold those runs into ``current`` -> RED.
    """
    db = _atlas_with(
        tmp_path,
        [
            {"run_id": "no_root", "scan_status": "complete", "firmware_path": None},
            {
                "run_id": "gone",
                "scan_status": "complete",
                "firmware_path": str(tmp_path / "deleted"),
            },
        ],
    )
    out = CliRunner().invoke(rescan, ["--atlas", str(db), "--dry-run"])
    assert out.exit_code == 0, out.output
    assert "CANNOT rescan (2)" in out.output
    assert "no_root: no firmware root recorded" in out.output
    assert f"gone: firmware root is gone: {tmp_path / 'deleted'}" in out.output
    assert "nothing to rescan" in out.output


def test_a_present_firmware_root_is_listed_as_rescannable(tmp_path: Path) -> None:
    fw = tmp_path / "fw"
    fw.mkdir()
    db = _atlas_with(
        tmp_path, [{"run_id": "live", "scan_status": "complete", "firmware_path": str(fw)}]
    )
    out = CliRunner().invoke(rescan, ["--atlas", str(db), "--dry-run"])
    assert out.exit_code == 0, out.output
    assert "to rescan (1)" in out.output
    assert "live:" in out.output
    assert "--dry-run: nothing was run." in out.output


def test_naming_an_unknown_run_is_an_error_not_an_empty_success(tmp_path: Path) -> None:
    """Asking to rescan a run that is not there must not report "nothing to rescan" — that reads
    as "you are already up to date" when in fact the request was never understood.
    """
    db = _atlas_with(tmp_path, [{"run_id": "a", "scan_status": "complete"}])
    out = CliRunner().invoke(rescan, ["--atlas", str(db), "--dry-run", "typo"])
    assert out.exit_code != 0
    assert "no such run" in out.output
