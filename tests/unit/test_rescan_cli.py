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

import click
import pytest
from click.testing import CliRunner

from treasure_map.cli import hunt_cli
from treasure_map.cli.hunt_cli import _rescan_reason, rescan
from treasure_map.lib.analyze.ghidra_runner import current_pass_version
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import RunRow
from treasure_map.version import UNKNOWN_VERSION

COMMIT = "c" * 40
OTHER = "d" * 40
BUILD = "beefbeefbeefbeef"
OTHER_BUILD = "facefeedfacefeed"


def _run(**over: object) -> RunRow:
    base: dict[str, object] = {
        "run_id": "r1",
        "firmware_path": "/fw",
        "hunt_commit": COMMIT,
        "hunt_instances": 5,
        "build_hash": BUILD,
        "scan_status": "complete",
    }
    base.update(over)
    return RunRow(**base)  # type: ignore[arg-type]


def _reason(
    run: RunRow, *, commit: str = COMMIT, build: str | None = BUILD, live: int = 5
) -> tuple[str, str] | None:
    return _rescan_reason(run, current_build=build, commit=commit, live_instances=live)


def test_a_run_hunted_by_this_commit_is_left_alone() -> None:
    assert _reason(_run()) is None


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
    result = _reason(run, commit=commit)
    assert result, "an out-of-date run must come with the reason it is out of date"
    axis, why = result
    assert axis in ("extraction", "hunt") and why


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


def test_a_changed_extraction_is_reported_on_its_own_axis() -> None:
    """★ WHICH input moved decides how long the fix takes, so the answer has to say which.

    A changed extraction hash means the analysis.db itself would come out differently: every binary
    is decompiled again. A changed hunt stamp means the stored facts are graded again and no
    decompiler runs at all. Reporting both as "out of date" left the reader to find out which by
    starting it.

    MUTATION: return a bare reason string again (single axis) -> RED. Drop the ``current_build``
    comparison -> RED. Measured RED at 1 failed each.
    """
    assert _reason(_run(), build=OTHER_BUILD) == (
        "extraction",
        f"extracted by {BUILD[:12]}, running {OTHER_BUILD[:12]}",
    )
    axis, _why = _reason(_run(hunt_commit=OTHER)) or ("", "")
    assert axis == "hunt"


@pytest.mark.parametrize(
    ("build", "current"),
    [(None, BUILD), (BUILD, None)],
)
def test_an_uncomparable_extraction_is_not_claimed_for_the_expensive_axis(
    build: str | None, current: str | None
) -> None:
    """Only two present-and-different hashes prove the extraction moved. A missing one on either
    side is unknown, and unknown must not be dressed up as a decompile-sized job.

    MUTATION: drop either ``and`` guard from the extraction branch -> RED.
    """
    result = _reason(_run(build_hash=build), build=current)
    assert result is None or result[0] == "hunt"


def test_both_inputs_changed_lands_on_the_extraction_axis_only() -> None:
    """Re-extracting re-hunts as a matter of course, so listing such a run as a fast re-hunt would
    promise seconds of work and then start a decompiler."""
    assert _reason(_run(hunt_commit=OTHER), build=OTHER_BUILD)[0] == "extraction"  # type: ignore[index]


def test_the_row_count_is_part_of_the_rescan_answer_too() -> None:
    """The same rule the skip gate applies: a stamp whose count no longer matches the table is
    describing a result that is not there any more.

    MUTATION: drop the ``hunt_instances`` branches from ``_rescan_reason`` -> RED.
    """
    assert _reason(_run(), live=4) == (
        "hunt",
        "stored candidate rows changed since the hunt (4 now, 5 then)",
    )
    assert _reason(_run(hunt_instances=None)) == (
        "hunt",
        "hunted before the instance count was recorded",
    )


def test_the_two_tiers_are_reported_separately_with_what_they_cost(tmp_path: Path) -> None:
    """The command's report, end to end: two runs, two tiers, each labelled with its cost, and the
    slower one carrying how many binaries would be decompiled.

    MUTATION: print one flat "to rescan" list again -> RED.
    """
    fw = tmp_path / "fw"
    fw.mkdir()
    db = _atlas_with(
        tmp_path,
        [
            {
                "run_id": "old_extract",
                "scan_status": "complete",
                "firmware_path": str(fw),
                "build_hash": OTHER_BUILD,
                "binaries": 484,
            },
            {
                "run_id": "old_hunt",
                "scan_status": "complete",
                "firmware_path": str(fw),
                "hunt_commit": None,
            },
        ],
    )
    out = CliRunner().invoke(rescan, ["--atlas", str(db), "--dry-run"])
    assert out.exit_code == 0, out.output
    assert "needs re-extraction (1)" in out.output
    assert "decompiler runs over every binary again" in out.output
    assert "old_extract:" in out.output and "[484 binaries]" in out.output
    assert "needs re-hunt (1)" in out.output
    assert "the decompiler does not run" in out.output
    assert "old_hunt:" in out.output


# --------------------------------------------------------------- what rescan actually DOES


def _two_runnable(tmp_path: Path) -> Path:
    fw = tmp_path / "fw"
    fw.mkdir()
    return _atlas_with(
        tmp_path,
        [
            {"run_id": "one", "scan_status": "complete", "firmware_path": str(fw)},
            {"run_id": "two", "scan_status": "complete", "firmware_path": str(fw)},
        ],
    )


def test_rescan_invokes_scan_per_runnable_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The half that had no test at all: the arguments rescan stuffs into another command.

    Every existing case here stopped at --dry-run or at the selection function, so the part most
    likely to break — a kwarg renamed on ``scan``, a flag passed with the wrong sense — was covered
    by nothing. The stub mirrors the real parameter names ON PURPOSE and takes no ``**kwargs``:
    that is what makes a signature change show up here as a failure instead of being swallowed.

    MUTATION: pass ``rehunt=True`` unconditionally, or drop ``top_n=0`` -> RED.
    """
    db = _two_runnable(tmp_path)
    calls: list[dict[str, object]] = []

    def _fake_scan(
        fs_root: Path,
        run_id: str | None,
        atlas_path: Path | None,
        config: Path | None,
        rehunt: bool,
        top_n: int | None,
    ) -> None:
        calls.append({"fs_root": fs_root, "run_id": run_id, "rehunt": rehunt, "top_n": top_n})

    monkeypatch.setattr(hunt_cli, "scan", _fake_scan)
    out = CliRunner().invoke(rescan, ["--atlas", str(db)])
    assert out.exit_code == 0, out.output
    assert [c["run_id"] for c in calls] == ["one", "two"]
    assert all(c["fs_root"] == tmp_path / "fw" for c in calls)
    # rehunt mirrors --force (absent here); the candidate list is a separate command, so a
    # multi-run refresh does not bury its own summary under six triage tables.
    assert all(c["rehunt"] is False and c["top_n"] == 0 for c in calls)
    assert "rescanned 2/2" in out.output


def test_one_failing_firmware_does_not_abandon_the_rest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A half-done refresh that stops silently is worse than one that says what broke.

    MUTATION: let the ``click.ClickException`` propagate instead of collecting it -> RED (the
    second run is never attempted and the exit code is non-zero). Measured RED at 1 failed.
    """
    db = _two_runnable(tmp_path)
    seen: list[str | None] = []

    def _fake_scan(
        fs_root: Path,
        run_id: str | None,
        atlas_path: Path | None,
        config: Path | None,
        rehunt: bool,
        top_n: int | None,
    ) -> None:
        seen.append(run_id)
        if run_id == "one":
            raise click.ClickException("ghidra exploded")

    monkeypatch.setattr(hunt_cli, "scan", _fake_scan)
    out = CliRunner().invoke(rescan, ["--atlas", str(db)])
    assert out.exit_code == 0, out.output
    assert seen == ["one", "two"], "a failure must not abandon the runs after it"
    assert "rescanned 1/2" in out.output
    assert "one: ghidra exploded" in out.output


def test_force_rescans_a_run_that_is_confirmed_current(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--force asks for the work on a run nothing else would offer, and ``rehunt`` travels with it.

    Without ``rehunt``, the forced scan would reach the hunt, find the stamp current and skip the
    very thing that was forced.

    ★ The run is made GENUINELY current here — matching commit, matching extraction hash, and a
    stored count equal to the (zero) live rows — because a run that is out of date anyway would be
    rescanned with or without --force, and the assertion would pass without the flag doing
    anything.

    MUTATION: drop the ``if force`` block that moves current runs into todo -> RED
    ("nothing to rescan").
    """
    fw = tmp_path / "fw"
    fw.mkdir()
    monkeypatch.setattr(hunt_cli, "installed_commit", lambda: COMMIT)
    db = _atlas_with(
        tmp_path,
        [
            {
                "run_id": "fresh",
                "scan_status": "complete",
                "firmware_path": str(fw),
                "hunt_commit": COMMIT,
                "hunt_instances": 0,
                "build_hash": current_pass_version(),
            }
        ],
    )
    assert (
        CliRunner().invoke(rescan, ["--atlas", str(db), "--dry-run"]).output.count("up to date (1)")
        == 1
    ), "the fixture must be confirmed current, or --force is not what moved it"
    calls: list[bool] = []

    def _fake_scan(
        fs_root: Path,
        run_id: str | None,
        atlas_path: Path | None,
        config: Path | None,
        rehunt: bool,
        top_n: int | None,
    ) -> None:
        calls.append(rehunt)

    monkeypatch.setattr(hunt_cli, "scan", _fake_scan)
    out = CliRunner().invoke(rescan, ["--atlas", str(db), "--force"])
    assert out.exit_code == 0, out.output
    assert calls == [True]
