# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""`tmap rescan` selection, and the honesty rules about what it cannot do.

The command's whole job is to answer "which of my runs were produced by an older tmap, and what
happens to them". The rules pinned here are about the SECOND half of that: a run it cannot act on
must still be named. A refresh list that quietly omits the runs it failed to consider reads exactly
like a list on which everything was fine.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from treasure_map.cli import hunt_cli
from treasure_map.cli.hunt_cli import _recorded_workspace_name, _rescan_reason, rescan
from treasure_map.lib.analyze.ghidra_runner import current_pass_version
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import RunRow
from treasure_map.lib.storage.connection import open_db
from treasure_map.lib.workspace.resolver import resolve_workspace
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
    assert axis in ("incomplete", "extraction", "hunt") and why


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
    # The hunt tier states BOTH halves: no decompiler on a cache hit, and the rebuild that happens
    # anyway. "no decompile" alone was the half that made a rebuilt inventory read as nothing.
    assert "no decompile on cache hit" in out.output
    assert "rebuilt" in out.output and "hunted again" in out.output
    assert "old_hunt:" in out.output


# --------------------------------------------------------------- what rescan actually DOES


def _workspace(ws_dir: Path, name: str) -> Path:
    """A managed workspace holding an analysis.db, and the recorded path that points at it."""
    ws = ws_dir / name
    ws.mkdir(parents=True)
    db = ws / "analysis.db"
    db.touch()
    return db


def _two_runnable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Two runs on the EXTRACTION axis, each recorded in its own managed workspace.

    The axis matters: extraction is the tier that still goes through ``scan``, which is what these
    cases are about. A hunt-tier run is re-graded in place and never reaches ``scan`` at all.
    """
    fw = tmp_path / "fw"
    fw.mkdir()
    ws_dir = tmp_path / "workspaces"
    monkeypatch.setenv("TM_WORKSPACE_DIR", str(ws_dir))
    return _atlas_with(
        tmp_path,
        [
            {
                "run_id": "one",
                "scan_status": "complete",
                "firmware_path": str(fw),
                "build_hash": OTHER_BUILD,
                "analysis_db_path": str(_workspace(ws_dir, "ws_one")),
            },
            {
                "run_id": "two",
                "scan_status": "complete",
                "firmware_path": str(fw),
                "build_hash": OTHER_BUILD,
                "analysis_db_path": str(_workspace(ws_dir, "ws_two")),
            },
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

    ``workspace`` is the load-bearing one (INV-1/INV-2): each run is re-scanned into the workspace
    it is RECORDED in, so the two runs get two DIFFERENT names. Passing None (what this command used
    to do) makes ``scan`` derive an auto name from the firmware root — and both runs here share one
    firmware root, so the old behaviour collapses them onto one name, which is what the set-level
    assertion catches.

    MUTATION: pass ``rehunt=True`` unconditionally, drop ``top_n=0``, or drop ``workspace=`` -> RED.
    Measured: dropping ``workspace=`` -> 1 failed.
    """
    db = _two_runnable(tmp_path, monkeypatch)
    calls: list[dict[str, object]] = []

    def _fake_scan(
        fs_root: Path,
        workspace: str | None,
        run_id: str | None,
        atlas_path: Path | None,
        config: Path | None,
        rehunt: bool,
        top_n: int | None,
    ) -> None:
        calls.append(
            {
                "fs_root": fs_root,
                "workspace": workspace,
                "run_id": run_id,
                "rehunt": rehunt,
                "top_n": top_n,
            }
        )

    monkeypatch.setattr(hunt_cli, "scan", _fake_scan)
    out = CliRunner().invoke(rescan, ["--atlas", str(db)])
    assert out.exit_code == 0, out.output
    assert [c["run_id"] for c in calls] == ["one", "two"]
    assert all(c["fs_root"] == tmp_path / "fw" for c in calls)
    # The recorded workspace, per run — not one auto name shared by both (same firmware root).
    assert [c["workspace"] for c in calls] == ["ws_one", "ws_two"]
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
    db = _two_runnable(tmp_path, monkeypatch)
    seen: list[str | None] = []

    def _fake_scan(
        fs_root: Path,
        workspace: str | None,
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

    Without ``rehunt``, the forced re-grade would find the stamp current and skip the very thing
    that was forced.

    ★ The run is made GENUINELY current here — matching commit, matching extraction hash, and a
    stored count equal to the (zero) live rows — because a run that is out of date anyway would be
    rescanned with or without --force, and the assertion would pass without the flag doing
    anything.

    A forced run lands on the HUNT axis (its extraction is current) and goes through ``scan`` like
    every other tier, into the workspace it is recorded in. ``rehunt`` has to travel that far: the
    scan reaches the hunt, finds the stamp current, and skips unless told otherwise.

    MUTATION: drop the ``if force`` block that moves current runs into todo -> RED
    ("nothing to rescan"). Pass ``rehunt=False`` to the scan -> RED.
    """
    fw = tmp_path / "fw"
    fw.mkdir()
    ws_dir = tmp_path / "workspaces"
    monkeypatch.setenv("TM_WORKSPACE_DIR", str(ws_dir))
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
                "analysis_db_path": str(_workspace(ws_dir, "fresh_ws")),
            }
        ],
    )
    assert (
        CliRunner().invoke(rescan, ["--atlas", str(db), "--dry-run"]).output.count("up to date (1)")
        == 1
    ), "the fixture must be confirmed current, or --force is not what moved it"
    scanned: list[tuple[str | None, str | None, bool]] = []

    def _fake_scan(
        fs_root: Path,
        workspace: str | None,
        run_id: str | None,
        atlas_path: Path | None,
        config: Path | None,
        rehunt: bool,
        top_n: int | None,
    ) -> None:
        scanned.append((run_id, workspace, rehunt))

    monkeypatch.setattr(hunt_cli, "scan", _fake_scan)
    out = CliRunner().invoke(rescan, ["--atlas", str(db), "--force"])
    assert out.exit_code == 0, out.output
    assert scanned == [("fresh", "fresh_ws", True)]


def test_rescan_lists_an_unfinished_run_in_its_own_tier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The tier has to reach the rescan report too, and it needs its own fixture to be seen:
    the runs that motivated it have no firmware root, so they are split off into CANNOT rescan
    before any tier is printed. A run with a root and an unfinished scan is what exercises it.

    MUTATION: leave the tier out of the axis map, or out of the render loop -> RED. The two fail
    differently and both quietly: without the axis the run is counted by "to rescan (N)" and
    matches no tier below it, so the header says N over a list of N-1.
    """
    monkeypatch.setattr(hunt_cli, "installed_commit", lambda: COMMIT)
    fw = tmp_path / "fw"
    fw.mkdir()
    db = _atlas_with(
        tmp_path,
        [
            {
                "run_id": "stopped",
                "scan_status": "in_progress",
                "firmware_path": str(fw),
                "binaries": 7,
                "build_hash": current_pass_version(),
            }
        ],
    )
    out = CliRunner().invoke(rescan, ["--atlas", str(db), "--dry-run"])
    assert out.exit_code == 0, out.output
    assert "to rescan (1):" in out.output
    assert "needs a full re-scan (1)" in out.output
    assert "the decompiler runs" in out.output
    assert "stopped:" in out.output and "[7 binaries]" in out.output
    # the count and the listing agree — a run with no axis would be counted and never printed
    listed = [ln for ln in out.output.splitlines() if ln.strip().startswith("stopped:")]
    assert len(listed) == 1, out.output


# ---------------------------------------------------------------------------------------------
# Refreshing a run IN PLACE: the run_id is the identity, and the atlas already records where that
# run's analysis.db lives. Deriving a workspace from the firmware root instead is what made a
# "fast re-hunt" decompile a whole firmware into a second directory and orphan the first.
# ---------------------------------------------------------------------------------------------

_BODY = (
    "void handle(char *param_1){ char cmd[128]; recv(0,param_1,64,0); "
    'snprintf(cmd,128,"/bin/sh -c %s",param_1); system(cmd); }'
)


def _seeded_analysis_db(db: Path) -> Path:
    """A tiny analysis.db that yields candidates, stamped with the CURRENT extraction pass.

    Stamped current ON PURPOSE: a matching ``build_hash`` is what puts the run on the hunt axis,
    and the hunt axis is the one whose whole claim is that no decompiler runs. ``last_seen_at`` is
    required — current_binaries selects on MAX(last_seen_at) and NULL never equals NULL, so without
    it the view is empty and the hunt has nothing to read.
    """
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, last_seen_at, pass_version) "
        "VALUES (1, 'webd', 'usr/sbin/webd', ?, '2026-01-01 00:00:00', ?)",
        ("a" * 64, current_pass_version()),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, pseudocode, pseudocode_hash, callees)"
        " VALUES (1, 1, 'handle', '0x1000', ?, 'h_handle', ?)",
        (_BODY, json.dumps(["recv", "snprintf", "system"])),
    )
    conn.commit()
    conn.close()
    return db


def _run_row(atlas: Path, run_id: str) -> dict[str, object]:
    conn = open_atlas(atlas)
    try:
        row = conn.execute("SELECT * FROM run WHERE run_id = ?", (run_id,)).fetchone()
        return dict(row)
    finally:
        conn.close()


def _instance_refs(atlas: Path, run_id: str) -> list[str]:
    conn = open_atlas(atlas)
    try:
        return [
            str(r[0])
            for r in conn.execute(
                "SELECT evidence_ref FROM instance WHERE source_run_id = ?", (run_id,)
            ).fetchall()
        ]
    finally:
        conn.close()


def _stale_xref_sentinel(db: Path) -> None:
    """A row in the xrefs table that only a rebuild can remove.

    ``build_xrefs`` opens with DELETE FROM xrefs / xref_folded_symbols / xref_unresolved_sonames and
    re-derives all three, so this row surviving a refresh means the rebuild did not happen. It is
    the observable for the half of a re-hunt that no fingerprint covers.
    """
    conn = open_db(db)
    try:
        conn.execute(
            "INSERT INTO xrefs (id, caller_binary_id, callee_binary_id, xref_type, confidence) "
            "VALUES (4242, 1, 1, 'stale_sentinel', 1.0)"
        )
        conn.commit()
    finally:
        conn.close()


def _has_sentinel(db: Path) -> bool:
    conn = open_db(db)
    try:
        return bool(
            conn.execute("SELECT 1 FROM xrefs WHERE xref_type = 'stale_sentinel'").fetchone()
        )
    finally:
        conn.close()


def test_a_custom_named_run_is_rescanned_in_place_rebuilding_without_the_decompiler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ THE REGRESSION, end to end on a real atlas, a real analysis.db and the REAL analyze stage.

    The shape that was bitten: a run scanned under a CUSTOM workspace name, whose extraction is
    current. Rescan handed ``scan`` only the firmware root, so it derived the auto name
    ``analyze_<root>_<hash8>`` — a different directory from the one this run is recorded in. That
    database is empty, so every binary reads as dirty, the decompiler runs over the whole firmware,
    and the run is re-pointed at the new directory with the original left behind as an orphan.

    What replaced it is NOT a path that skips the scan. ``build_hash`` proves the per-binary
    extraction can be re-used and nothing more: the ELF inventory, the symlinks, the cross-binary
    xrefs and the non-binary facts are in no fingerprint at all, so a refresh that jumped straight
    to the grading would keep whatever stale version of them was on disk. The scan runs, and its own
    dirty check is what keeps the decompiler out of it.

    Five things are pinned, and they fail independently:
      - the analyze stage IS entered (the rebuild actually happens);
      - Ghidra's ``run_all`` is NOT (0 dirty — what makes a re-hunt cheap);
      - a stale xrefs row is gone afterwards (the rebuild reached the parts no stamp covers);
      - ``analysis_db_path`` still names the same file, and ``workspace_dir`` gained no directory;
      - ``firmware_path`` survives — a run with no recorded root is what rescan reports as
        un-refreshable next time.

    MUTATION (the original bug, restored): drop ``workspace=`` so the auto name is derived -> RED.
    MUTATION: re-grade in place instead of scanning -> RED (the sentinel survives).
    MUTATION: make the fixture dirty (clear pass_version on the seeded binary) -> Ghidra runs,
    so this goes RED.
    """
    from treasure_map.lib.analyze import pipeline
    from treasure_map.lib.analyze.ghidra_runner import GhidraRunner

    fw = tmp_path / "cpio-root"
    fw.mkdir()
    ws_dir = tmp_path / "workspaces"
    monkeypatch.setenv("TM_WORKSPACE_DIR", str(ws_dir))
    (ws_dir / "my_device").mkdir(parents=True)
    db_file = _seeded_analysis_db(ws_dir / "my_device" / "analysis.db").resolve()
    _stale_xref_sentinel(db_file)
    assert _has_sentinel(db_file), "the fixture must start with the stale row it claims to remove"
    monkeypatch.setattr(hunt_cli, "installed_commit", lambda: COMMIT)
    atlas = _atlas_with(
        tmp_path,
        [
            {
                # ★ The run_id deliberately differs from the workspace name. They coincide on a run
                # scanned as `-w my_device` (the run_id defaults to it), and a fixture where they
                # match cannot tell the RECORDED workspace apart from one derived as
                # workspaces/<run_id> — a convention the run table's docstring says does not exist.
                "run_id": "device_run",
                "scan_status": "complete",
                "firmware_path": str(fw),
                "analysis_db_path": str(db_file),
                "build_hash": current_pass_version(),
                "hunt_commit": OTHER,
                "hunt_instances": 0,
            }
        ],
    )
    # The auto name this firmware root would produce is NOT the recorded one — without that the
    # fixture could not tell a reused workspace from a derived one.
    auto = resolve_workspace(None, workspace_dir=ws_dir, fs_root=fw).path.name
    assert auto != "my_device", "the fixture must let a derived name differ from the recorded one"

    # Ghidra is not installed in a test environment, and run_analyze fails fast on that before it
    # does any work. Only the DISCOVERY is faked; the pipeline itself is the real one, so what the
    # assertions below observe is the real rebuild.
    monkeypatch.setattr(GhidraRunner, "get_headless", lambda self: Path("/nonexistent/headless"))
    monkeypatch.setattr(GhidraRunner, "ghidra_version", lambda self: "unknown")
    decompiled: list[object] = []
    monkeypatch.setattr(
        GhidraRunner,
        "run_all",
        lambda self, *a, **k: decompiled.append(a) or [],  # type: ignore[func-returns-value]
    )
    analyzed: list[object] = []
    real_run_analyze = pipeline.run_analyze

    async def _spy_run_analyze(*a: object, **k: object) -> object:
        analyzed.append(a)
        return await real_run_analyze(*a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(pipeline, "run_analyze", _spy_run_analyze)

    before = sorted(p.name for p in ws_dir.iterdir())
    out = CliRunner().invoke(rescan, ["--atlas", str(atlas)])
    assert out.exit_code == 0, out.output
    assert analyzed, "the analyze stage must run — the rebuild is not optional"
    assert decompiled == [], "a current extraction means 0 dirty, so Ghidra must never start"
    assert not _has_sentinel(db_file), "the stale xrefs row must be rebuilt away"
    row = _run_row(atlas, "device_run")
    assert row["analysis_db_path"] == str(db_file), "the run must not be re-pointed"
    assert row["firmware_path"] == str(fw), "a refresh must not cost the run its firmware root"
    assert sorted(p.name for p in ws_dir.iterdir()) == before == ["my_device"]


def test_an_auto_named_run_is_re_scanned_into_the_very_same_auto_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The runs the old behaviour happened to get right must stay right.

    A run whose recorded workspace IS the auto name was never mis-routed: derived and recorded
    agreed. Reusing the recorded one has to land on that same directory, or an untouched case would
    start re-decompiling — so the name handed to ``scan`` is compared against the name the auto
    derivation itself produces, rather than against a string copied into the test.

    MUTATION: return ``Path(analysis_db_path).name`` from ``_recorded_workspace_name`` -> RED.
    """
    fw = tmp_path / "squashfs-root"
    fw.mkdir()
    ws_dir = tmp_path / "workspaces"
    monkeypatch.setenv("TM_WORKSPACE_DIR", str(ws_dir))
    auto = resolve_workspace(None, workspace_dir=ws_dir, fs_root=fw).path.name
    db_file = _workspace(ws_dir, auto)
    atlas = _atlas_with(
        tmp_path,
        [
            {
                "run_id": "auto_run",
                "scan_status": "complete",
                "firmware_path": str(fw),
                "analysis_db_path": str(db_file),
                # extraction axis, so the run goes through `scan` and the name is observable there
                "build_hash": OTHER_BUILD,
            }
        ],
    )
    seen: list[str | None] = []

    def _fake_scan(
        fs_root: Path,
        workspace: str | None,
        run_id: str | None,
        atlas_path: Path | None,
        config: Path | None,
        rehunt: bool,
        top_n: int | None,
    ) -> None:
        seen.append(workspace)

    monkeypatch.setattr(hunt_cli, "scan", _fake_scan)
    out = CliRunner().invoke(rescan, ["--atlas", str(atlas)])
    assert out.exit_code == 0, out.output
    assert seen == [auto]


def test_the_reused_workspace_is_the_directory_not_the_database_file() -> None:
    """★ ``analysis_db_path`` names the FILE; the workspace is its parent.

    ``Path(...).name`` is "analysis.db" for every run alike, and ``resolve_workspace`` accepts it as
    a perfectly valid NAME — so that mistake does not raise. It silently resolves every run into one
    shared ``workspaces/analysis.db`` directory that holds no extraction at all, which is the
    original bug with an extra collision on top.

    Asserted as a SET over two runs: a per-run equality could be satisfied by a constant, while a
    set of size 1 is exactly what the file-name mistake produces.

    MUTATION: use ``.name`` instead of ``.parent.name`` -> RED ({"analysis.db"}, size 1).
    """
    base = Path("/base/workspaces")
    names = {
        _recorded_workspace_name(
            _run(analysis_db_path=f"/base/workspaces/{n}/analysis.db"), workspace_dir=base
        )
        for n in ("my_device", "analyze_cpio-root_1dfa6bd2")
    }
    assert names == {"my_device", "analyze_cpio-root_1dfa6bd2"}


def test_a_run_with_no_recorded_database_has_nothing_to_reuse() -> None:
    """None, not an invented name: there is no workspace on record to go back to."""
    assert (
        _recorded_workspace_name(_run(analysis_db_path=None), workspace_dir=Path("/base")) is None
    )


def test_a_workspace_outside_the_configured_base_is_refused_not_guessed() -> None:
    """``-w`` re-resolves a NAME against workspace_dir, so a name from elsewhere designates a
    DIFFERENT directory — possibly another run's, when the names collide. Merging two firmware into
    one analysis.db is a worse outcome than a named failure.

    MUTATION: drop the base check and return ``ws.name`` regardless -> RED (no exception raised).
    """
    with pytest.raises(click.ClickException) as exc:
        _recorded_workspace_name(
            _run(analysis_db_path="/elsewhere/my_device/analysis.db"),
            workspace_dir=Path("/base/workspaces"),
        )
    assert "not under" in str(exc.value) and "/elsewhere/my_device" in str(exc.value)


def _unusable(kind: str, ws_dir: Path) -> tuple[str, str]:
    """One of the four REBUILDABLE unusable states, as (recorded path, workspace name).

    All four mean the same thing to a refresh — there is no extraction on disk to find current — and
    all four are repaired the same way, by letting ``scan`` rebuild the database where the run
    already lives. They are enumerated rather than collapsed because ``build_hash`` cannot see any
    of them: it is stamped per binary INSIDE the database, so a run whose database has since been
    truncated still compares as current against the running pass and still lands on the hunt tier.
    """
    ws = ws_dir / f"ws_{kind}"
    ws.mkdir(parents=True)
    db = ws / "analysis.db"
    if kind == "missing":
        pass  # the workspace exists, the database does not
    elif kind == "zero_byte":
        db.touch()
    elif kind == "no_table":
        # A real SQLite database with no tmap schema in it at all.
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE unrelated (x INTEGER)")
        conn.commit()
        conn.close()
    elif kind == "no_binaries":
        # The full schema, and not one binary extracted into it.
        open_db(db).close()
    else:  # pragma: no cover - guards a typo in the parametrize list
        raise AssertionError(f"unknown fixture kind {kind!r}")
    return str(db), ws.name


@pytest.mark.parametrize(
    ("kind", "says"),
    [
        ("missing", "recorded analysis.db is gone"),
        ("zero_byte", "recorded analysis.db is empty (0 bytes)"),
        ("no_table", "recorded analysis.db holds no binaries table"),
        ("no_binaries", "recorded analysis.db holds no extracted binaries"),
    ],
)
def test_a_hunt_tier_run_with_no_stored_facts_is_announced_before_it_decompiles(
    kind: str, says: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ M-A3. The tier said "no decompile on cache hit"; with no extraction on disk, there is no
    cache to hit and ``scan`` will decompile the whole firmware.

    Rebuilding is the right repair — an empty or missing database SHOULD be rebuilt, and into the
    workspace the run already occupies. It is the silence that is wrong: a reader who was told a
    re-hunt needs no decompiler, and then waits through a full Ghidra run, was misled by the report
    rather than merely delayed.

    Four states, because only the first one used to be detected. A 0-byte file, a database with no
    tmap schema, and a full schema holding zero binaries all reach ``scan`` looking exactly like a
    healthy re-hunt, and each of them decompiles everything.

    ★ Each state is pinned to the SENTENCE IT PRODUCES, not merely to the warning appearing. A
    0-byte file, asked for a row count, answers "no such table" exactly like a schema-less one — so
    a test that only checked "something was warned about" stayed green with the size check deleted
    (measured: 80 passed). The states differ to the person diagnosing them, so the report has to
    tell them apart, and the assertion has to require that.

    MUTATION: drop the echoed warning -> RED on all four. MUTATION: drop the 0-byte branch -> RED
    on that case (it reports itself as schema-less instead). MUTATION: use ``open_db`` for the check
    -> RED (it CREATES the schema in a 0-byte file, so that state reports itself as merely
    empty-of-binaries and the evidence of what was wrong is destroyed by the check).
    """
    fw = tmp_path / "fw"
    fw.mkdir()
    ws_dir = tmp_path / "workspaces"
    monkeypatch.setenv("TM_WORKSPACE_DIR", str(ws_dir))
    monkeypatch.setattr(hunt_cli, "installed_commit", lambda: COMMIT)
    recorded, ws_name = _unusable(kind, ws_dir)
    atlas = _atlas_with(
        tmp_path,
        [
            {
                "run_id": "no_facts",
                "scan_status": "complete",
                "firmware_path": str(fw),
                "analysis_db_path": recorded,
                "build_hash": current_pass_version(),
                "hunt_commit": OTHER,
                "hunt_instances": 0,
            }
        ],
    )
    seen: list[str | None] = []

    def _fake_scan(
        fs_root: Path,
        workspace: str | None,
        run_id: str | None,
        atlas_path: Path | None,
        config: Path | None,
        rehunt: bool,
        top_n: int | None,
    ) -> None:
        seen.append(workspace)

    monkeypatch.setattr(hunt_cli, "scan", _fake_scan)
    out = CliRunner().invoke(rescan, ["--atlas", str(atlas)])
    assert out.exit_code == 0, out.output
    assert says in out.output, out.output
    assert "the decompiler runs" in out.output, out.output
    assert seen == [ws_name], "the rebuild belongs in the workspace the run already occupies"


def test_a_run_that_recorded_no_database_is_announced_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same honesty with nothing recorded at all — and no workspace to name, so ``scan`` is left
    to derive one. The only case where deriving is right: there is no recorded workspace to re-use.

    MUTATION: return a name instead of None from ``_recorded_workspace_name`` -> RED.
    """
    fw = tmp_path / "fw"
    fw.mkdir()
    monkeypatch.setenv("TM_WORKSPACE_DIR", str(tmp_path / "workspaces"))
    monkeypatch.setattr(hunt_cli, "installed_commit", lambda: COMMIT)
    atlas = _atlas_with(
        tmp_path,
        [
            {
                "run_id": "no_db",
                "scan_status": "complete",
                "firmware_path": str(fw),
                "build_hash": current_pass_version(),
                "hunt_commit": OTHER,
                "hunt_instances": 0,
            }
        ],
    )
    seen: list[str | None] = []

    def _fake_scan(
        fs_root: Path,
        workspace: str | None,
        run_id: str | None,
        atlas_path: Path | None,
        config: Path | None,
        rehunt: bool,
        top_n: int | None,
    ) -> None:
        seen.append(workspace)

    monkeypatch.setattr(hunt_cli, "scan", _fake_scan)
    out = CliRunner().invoke(rescan, ["--atlas", str(atlas)])
    assert out.exit_code == 0, out.output
    assert "this run recorded no analysis.db" in out.output
    assert "the decompiler runs" in out.output
    assert seen == [None]


@pytest.mark.parametrize("kind", ["garbage_bytes", "directory"])
def test_a_file_that_is_not_a_database_fails_one_run_and_is_left_untouched(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ M-A5. The fifth state, and the only one that must NOT be rebuilt over.

    Bytes that are not a database may still be the only copy of an extraction that took hours —
    a half-written file, a wrong path, a damaged disk. ``scan`` would replace them. So this run is
    named as FAILED and its file is not touched, leaving the decision with the person who can tell
    what those bytes are.

    And it must not take the refresh down with it. ``sqlite3.DatabaseError`` is not a
    ``TreasureMapError``, so ``scan`` never converts it, and the loop's handler only catches
    ``ClickException``: unhandled, ONE bad file ends the whole run and every firmware queued behind
    it is silently never attempted. The bad run is FIRST here, because the whole claim is about what
    happens after it.

    ★ TWO shapes, because they raise DIFFERENT exception classes and only one of them reaches the
    "no such table" guard. Garbage bytes raise ``sqlite3.DatabaseError`` ("file is not a database"),
    which is NOT an ``OperationalError`` and so never enters that branch at all — with only that
    case here, deleting the guard changed nothing and the suite stayed green (measured: 80 passed).
    A directory in the database's place raises ``OperationalError`` ("disk I/O error"), which does
    enter it and must be re-raised rather than reported as rebuildable.

    MUTATION: accept every OperationalError as rebuildable (drop the "no such table" guard) -> RED
    on the directory case. MUTATION: drop the loop's ``except sqlite3.DatabaseError`` -> RED on
    both (the good run is never reached and the command exits non-zero).
    """
    fw = tmp_path / "fw"
    fw.mkdir()
    ws_dir = tmp_path / "workspaces"
    monkeypatch.setenv("TM_WORKSPACE_DIR", str(ws_dir))
    monkeypatch.setattr(hunt_cli, "installed_commit", lambda: COMMIT)
    (ws_dir / "junk_ws").mkdir(parents=True)
    junk = ws_dir / "junk_ws" / "analysis.db"
    payload = b"\x00\xffthis is not a database at all" * 40
    if kind == "garbage_bytes":
        junk.write_bytes(payload)
    else:
        junk.mkdir()  # a directory where the database should be
    (ws_dir / "good_ws").mkdir(parents=True)
    good = _seeded_analysis_db(ws_dir / "good_ws" / "analysis.db")
    atlas = _atlas_with(
        tmp_path,
        [
            {
                "run_id": "a_junk",
                "scan_status": "complete",
                "firmware_path": str(fw),
                "analysis_db_path": str(junk),
                "build_hash": current_pass_version(),
                "hunt_commit": OTHER,
                "hunt_instances": 0,
            },
            {
                "run_id": "b_good",
                "scan_status": "complete",
                "firmware_path": str(fw),
                "analysis_db_path": str(good.resolve()),
                "build_hash": current_pass_version(),
                "hunt_commit": OTHER,
                "hunt_instances": 0,
            },
        ],
    )
    seen: list[str | None] = []

    def _fake_scan(
        fs_root: Path,
        workspace: str | None,
        run_id: str | None,
        atlas_path: Path | None,
        config: Path | None,
        rehunt: bool,
        top_n: int | None,
    ) -> None:
        seen.append(run_id)

    monkeypatch.setattr(hunt_cli, "scan", _fake_scan)
    out = CliRunner().invoke(rescan, ["--atlas", str(atlas)])
    assert out.exit_code == 0, out.output
    assert "rescanned 1/2" in out.output
    assert "a_junk: recorded analysis.db is not a readable database" in out.output
    assert seen == ["b_good"], "the unreadable path must not be scanned over"
    if kind == "garbage_bytes":
        assert junk.read_bytes() == payload, "those bytes may be the only copy of an extraction"
    else:
        assert junk.is_dir() and not any(junk.iterdir()), "nothing may be written into it"
