# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The hunt-skip decision, the commit stamp that backs it, and the staleness reads built on it.

★ THE FOUNDATION IS MEASURED, NOT ASSUMED. Skipping a hunt is only defensible because the hunt
produces the same content rows twice from the same analysis.db and the same code. That property
was established by EXECUTION on three real firmware before the skip was enabled — 3163, 4187 and
4812 instances, each digesting identically across two consecutive hunts of the same database.
Those runs cannot live in this file (they need multi-hundred-MB analysis databases and minutes of
CPU), so what is pinned here is everything downstream of that measurement: that the decision only
skips on a CONFIRMED match, that the stamp is written only after the instances it describes, and
that the staleness reads use the opposite bar from the skip.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import RunRow
from treasure_map.lib.atlas.writer import begin_run, finish_run
from treasure_map.lib.hunt.analyzer2 import hunt_currency
from treasure_map.lib.query import get_run, run_staleness
from treasure_map.lib.storage.connection import open_db
from treasure_map.version import UNKNOWN_VERSION

COMMIT = "a" * 40
OTHER = "b" * 40
BUILD = "8beedde56942dbb1"


def _row(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "scan_status": "complete",
        "hunt_commit": COMMIT,
        "build_hash": BUILD,
    }
    base.update(over)
    return base


# --------------------------------------------------------------------------- currency decision


def test_same_commit_and_same_extraction_is_current() -> None:
    """The one case that skips: both inputs to the hunt are demonstrably the ones already used."""
    c = hunt_currency(_row(), build_hash=BUILD, commit=COMMIT)
    assert c.current is True
    assert COMMIT[:12] in c.reason


@pytest.mark.parametrize(
    ("row", "build", "commit", "why"),
    [
        (None, BUILD, COMMIT, "no run row at all"),
        (_row(scan_status="in_progress"), BUILD, COMMIT, "previous hunt crashed mid-write"),
        (_row(scan_status="failed"), BUILD, COMMIT, "previous hunt failed"),
        (_row(scan_status="partial"), BUILD, COMMIT, "previous hunt only partial"),
        (_row(hunt_commit=None), BUILD, COMMIT, "hunted before the stamp existed"),
        (_row(hunt_commit=""), BUILD, COMMIT, "empty stamp"),
        (_row(hunt_commit=UNKNOWN_VERSION), BUILD, COMMIT, "hunting install had no commit"),
        (_row(), BUILD, OTHER, "a different tmap is running now"),
        (_row(), BUILD, UNKNOWN_VERSION, "the running install has no commit to compare"),
        (_row(), None, COMMIT, "this analysis.db records no extraction hash"),
        (_row(build_hash=None), BUILD, COMMIT, "the run recorded no extraction hash"),
        (_row(build_hash="0000"), BUILD, COMMIT, "the extraction changed"),
    ],
)
def test_every_unconfirmed_case_re_hunts(
    row: dict[str, object] | None, build: str | None, commit: str, why: str
) -> None:
    """★ The load-bearing direction: anything short of a proven match does the work again.

    Each row here is a way of failing to CONFIRM that the stored result came from this code and
    this extraction. None of them is a proven mismatch — several are simply missing information —
    and all of them must still re-hunt, because a wrongly-skipped hunt leaves stale candidates
    that are indistinguishable from fresh ones while a wrongly-repeated hunt only costs time.

    MUTATION (proves this has teeth): loosen any single branch in ``hunt_currency`` — e.g. drop
    the ``scan_status`` check, or accept a NULL ``hunt_commit`` as matching, or compare only the
    commit and not the build hash — and the corresponding row here goes RED.
    """
    c = hunt_currency(row, build_hash=build, commit=commit)
    assert c.current is False, why
    assert c.reason, "a decision must always say why, in both directions"


def test_unknown_running_commit_never_skips_even_against_an_unknown_stamp() -> None:
    """Two unknowns must not compare equal into a skip.

    ``UNKNOWN_VERSION`` is a sentinel meaning "not recorded", so a stored 'unknown' and a running
    'unknown' are two absences, not two matching commits. A plain ``==`` on the stamps alone would
    read them as a match and skip the hunt for every editable install in existence.

    MUTATION: delete the ``commit == UNKNOWN_VERSION`` early return in ``hunt_currency`` — this
    test goes RED while every other case above still passes, which is what makes it worth its own
    test rather than another parametrize row.
    """
    c = hunt_currency(_row(hunt_commit=UNKNOWN_VERSION), build_hash=BUILD, commit=UNKNOWN_VERSION)
    assert c.current is False


# --------------------------------------------------------------------------- the stamp itself


def _atlas(tmp_path: Path) -> sqlite3.Connection:
    return open_atlas(tmp_path / "atlas.db")


def test_stamp_records_the_commit_that_wrote_the_instances(tmp_path: Path) -> None:
    conn = _atlas(tmp_path)
    begin_run(conn, "r1", analysis_db_path="/x/analysis.db", build_hash=BUILD)
    finish_run(conn, "r1", hunt_commit=COMMIT)
    assert conn.execute("SELECT hunt_commit FROM run WHERE run_id='r1'").fetchone()[0] == COMMIT


def test_begin_run_clears_the_stamp_so_a_crash_leaves_no_claim(tmp_path: Path) -> None:
    """★ The stamp says "this commit produced the rows in the table", so it must not survive the
    moment those rows are dropped.

    begin_run runs immediately before the delete-and-rewrite transaction. If it left the previous
    stamp in place and the write then crashed, the row would read: complete-looking stamp, whatever
    instances the crash happened to leave. The scan_status guard catches that case too, but a stamp
    that describes rows which no longer exist is wrong on its own terms.

    MUTATION: remove ``hunt_commit = NULL`` from begin_run's upsert -> RED.
    """
    conn = _atlas(tmp_path)
    begin_run(conn, "r1", build_hash=BUILD)
    finish_run(conn, "r1", hunt_commit=COMMIT)
    begin_run(conn, "r1", build_hash=BUILD)  # a second hunt starts
    assert conn.execute("SELECT hunt_commit FROM run WHERE run_id='r1'").fetchone()[0] is None


def test_finish_run_without_a_commit_leaves_an_existing_stamp_alone(tmp_path: Path) -> None:
    """A caller that does not know the commit has no grounds to erase one already established.

    MUTATION: drop the COALESCE from finish_run's UPDATE (write the parameter straight) -> RED.
    """
    conn = _atlas(tmp_path)
    conn.execute("INSERT INTO run (run_id, hunt_commit) VALUES ('r1', ?)", (COMMIT,))
    finish_run(conn, "r1")
    assert conn.execute("SELECT hunt_commit FROM run WHERE run_id='r1'").fetchone()[0] == COMMIT


def test_an_atlas_predating_the_column_gains_it_and_keeps_its_rows(tmp_path: Path) -> None:
    """The migration is additive: an existing run survives it, carrying NULL (i.e. re-hunt)."""
    db = tmp_path / "atlas.db"
    conn = open_atlas(db)
    conn.close()
    old = sqlite3.connect(db)
    old.execute("ALTER TABLE run DROP COLUMN hunt_commit")
    old.execute("INSERT INTO run (run_id, scan_status) VALUES ('old', 'complete')")
    old.commit()
    old.close()

    conn = open_atlas(db)
    row = conn.execute("SELECT run_id, hunt_commit FROM run").fetchone()
    assert row["run_id"] == "old"
    assert row["hunt_commit"] is None
    assert (
        hunt_currency(
            dict(row) | {"scan_status": "complete", "build_hash": BUILD},
            build_hash=BUILD,
            commit=COMMIT,
        ).current
        is False
    )


def test_hunt_commit_reaches_the_run_query_layer(tmp_path: Path) -> None:
    """The stamp is readable through the same lineage view `tmap runs` and the MCP tools use.

    MUTATION: remove "hunt_commit" from ``_RUN_COLUMNS`` or its line from ``_row_to_runrow`` -> RED
    (a KeyError, or a RunRow whose stamp is silently always None).
    """
    conn = _atlas(tmp_path)
    begin_run(conn, "r1", analysis_db_path="/x/a.db", build_hash=BUILD)
    finish_run(conn, "r1", hunt_commit=COMMIT)
    run = get_run(conn, "r1")
    assert run is not None and run.hunt_commit == COMMIT


# --------------------------------------------------------------------------- staleness reads


def _run(**over: object) -> RunRow:
    base: dict[str, object] = {
        "run_id": "r1",
        "analysis_db_path": "/x/a.db",
        "firmware_path": "/fw/root",
        "build_hash": BUILD,
        "hunt_commit": COMMIT,
        "scan_status": "complete",
    }
    base.update(over)
    return RunRow(**base)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("run", "build", "commit", "axis"),
    [
        (_run(build_hash="deadbeef"), BUILD, COMMIT, "extraction"),
        (_run(hunt_commit=OTHER), BUILD, COMMIT, "hunt"),
    ],
)
def test_a_proven_mismatch_is_stale(run: RunRow, build: str, commit: str, axis: str) -> None:
    s = run_staleness(run, build_hash=build, commit=commit)
    assert s.stale is True
    assert s.axis == axis
    assert s.remedy


@pytest.mark.parametrize(
    ("run", "build", "commit", "why"),
    [
        (_run(hunt_commit=None), BUILD, COMMIT, "no stamp is not a mismatch"),
        (_run(hunt_commit=UNKNOWN_VERSION), BUILD, COMMIT, "an unrecorded commit is not a commit"),
        (_run(), BUILD, UNKNOWN_VERSION, "an editable install must not mute every run"),
        (_run(build_hash=None), BUILD, COMMIT, "a run with no hash cannot be shown to differ"),
        (_run(), None, COMMIT, "no current hash to compare against"),
        (_run(build_hash="mixed:3"), BUILD, COMMIT, "a count is not a hash — not comparable"),
    ],
)
def test_unconfirmable_is_never_stale(
    run: RunRow, build: str | None, commit: str, why: str
) -> None:
    """★ THE OPPOSITE BAR FROM THE SKIP, AND THE POINT OF SPLITTING THE TWO FUNCTIONS.

    ``hunt_currency`` treats "cannot tell" as re-do the work; ``run_staleness`` treats it as do not
    refuse. Collapsing them into one predicate would force one of two failures: a skip that fires
    on unconfirmed sameness (stale candidates served as fresh), or a refusal that fires on every
    unstamped run and every editable install (a tool that answers nothing, which in practice means
    a gate someone turns off). Each row is a case where the honest reading is "no information".

    MUTATION: make ``run_staleness`` return stale whenever the stamps merely fail to match — every
    row here goes RED while the proven-mismatch test above still passes.
    """
    s = run_staleness(run, build_hash=build, commit=commit)
    assert s.stale is False, why
    assert s.detail, "a not-stale reading must still say what could not be compared"


def test_remedy_names_a_runnable_command_only_when_the_firmware_is_recorded() -> None:
    """A run with no firmware root cannot be told to `tmap rescan` — that command would fail.

    MUTATION: make ``_remedy_for`` always emit the rescan command -> RED. The wrong remedy is worse
    than a vague one: it sends the reader to a command that cannot work and looks like their fault.
    """
    have = run_staleness(_run(hunt_commit=OTHER), build_hash=BUILD, commit=COMMIT)
    assert "tmap rescan r1" in have.remedy
    lost = run_staleness(
        _run(hunt_commit=OTHER, firmware_path=None), build_hash=BUILD, commit=COMMIT
    )
    assert "tmap rescan r1" not in lost.remedy
    assert "no firmware root" in lost.remedy


# --------------------------------------------------------------------------- the commit reader


def test_installed_commit_is_a_string_and_never_asks_git(monkeypatch: pytest.MonkeyPatch) -> None:
    """★ HARD RULE: an unreadable install record yields the sentinel, never a git query.

    ``git rev-parse HEAD`` would answer confidently in a checkout that has nothing to do with the
    installed artifact — uncommitted edits, a different branch, or a directory the user merely
    happens to be standing in. The sentinel is the honest answer and the conservative one: it
    re-hunts, and it never refuses a read.

    ★ MAKING THE RECORD UNREADABLE IS THE WHOLE TEST. A first version of this poisoned subprocess
    and called the function — and stayed GREEN against a mutant that shelled out, because in a
    normal checkout the install record READS FINE and the fallback branch never ran. The failure
    has to be forced for the poison to be standing anywhere the mutant would step.

    MUTATION: add a subprocess fallback to ``installed_commit`` -> RED, both on the poison and on
    the sentinel assertion.
    """
    import subprocess

    from treasure_map import version as tm_version

    def _poisoned(*a: object, **k: object) -> None:
        raise AssertionError("installed_commit must never shell out")

    for name in ("run", "check_output", "Popen", "call", "check_call"):
        monkeypatch.setattr(subprocess, name, _poisoned)

    def _no_record(_name: str) -> object:
        raise ModuleNotFoundError("no install record here")

    monkeypatch.setattr(tm_version, "distribution", _no_record)
    assert tm_version.installed_commit() == UNKNOWN_VERSION


def test_a_malformed_install_record_reads_as_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every failure shape of the install record lands on the sentinel, not an exception.

    A read that raises here would take down every hunt and every fact tool, which is a far worse
    outcome than not knowing the commit.
    """
    from treasure_map import version as tm_version

    class _Dist:
        def __init__(self, payload: str | None) -> None:
            self._p = payload

        def read_text(self, _name: str) -> str | None:
            return self._p

    for payload in [
        None,
        "",
        "not json",
        "[]",
        '{"url":"file:///x"}',
        '{"vcs_info":{}}',
        '{"vcs_info":{"commit_id":""}}',
        '{"vcs_info":{"commit_id":5}}',
    ]:
        monkeypatch.setattr(tm_version, "distribution", lambda _n, p=payload: _Dist(p))
        assert tm_version.installed_commit() == UNKNOWN_VERSION, payload

    monkeypatch.setattr(
        tm_version, "distribution", lambda _n: _Dist('{"vcs_info":{"commit_id":"abc"}}')
    )
    assert tm_version.installed_commit() == "abc"


# --------------------------------------------------------------------------- end to end


_BODY = (
    "void handle(char* param_1){ char buf[64]; recv(fd,buf,64); char cmd[128]; "
    'snprintf(cmd,128,"/bin/sh -c %s",param_1); system(cmd); }'
)


def _seeded(tmp_path: Path, pass_version: str = "pv_x") -> Path:
    """A tiny analysis.db that yields exactly one candidate, with a uniform pipeline stamp.

    Built here rather than borrowed from the analyzer2 suite: what these tests assert is that a
    hunt's OUTPUT survives untouched, so the input has to stay pinned to this file. A shared
    fixture that later grew a second function would quietly change what "unchanged" means.
    ``last_seen_at`` is required — current_binaries selects on MAX(last_seen_at), and NULL never
    equals NULL, so without it the view is empty and the lineage carries no build hash at all.
    """
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, last_seen_at, pass_version) "
        "VALUES (1, 'webd', 'usr/sbin/webd', ?, '2026-01-01 00:00:00', ?)",
        ("a" * 64, pass_version),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, pseudocode, pseudocode_hash, callees)"
        " VALUES (1, 1, 'handle', '0x1000', ?, 'h_handle', ?)",
        (_BODY, json.dumps(["recv", "snprintf", "system"])),
    )
    conn.commit()
    conn.close()
    return db


def _instances(atlas: Path) -> list[tuple[object, ...]]:
    conn = open_atlas(atlas)
    try:
        return conn.execute(
            "SELECT instance_id, evidence_ref, reachability_status FROM instance ORDER BY 1"
        ).fetchall()
    finally:
        conn.close()


def test_a_second_hunt_by_the_same_commit_skips_and_touches_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ THE FEATURE, end to end — and the assertion that matters is what did NOT happen.

    The second call must not merely return quickly: it must leave the stored rows byte-for-byte
    where they were, including their instance_ids. A skip implemented after the delete would
    return just as fast and would have destroyed the run's candidates.

    MUTATION: move the skip gate below ``delete_run_instances`` -> RED (rows vanish). Remove the
    gate entirely -> RED (instance_ids change, because a re-hunt reinserts).
    """
    from treasure_map.lib.hunt import analyzer2 as a2

    monkeypatch.setattr(a2, "installed_commit", lambda: COMMIT)
    db, atlas = _seeded(tmp_path), tmp_path / "atlas.db"

    first = a2.run_analyzer2(db, atlas, source_run_id="r", firmware_path="/fw")
    assert first.skipped is False
    assert first.instances_written == 1
    before = _instances(atlas)
    assert before, "the fixture must actually write something, or the skip proves nothing"

    second = a2.run_analyzer2(db, atlas, source_run_id="r", firmware_path="/fw")
    assert second.skipped is True
    assert second.instances_written == 0
    assert _instances(atlas) == before


def test_rehunt_overrides_the_skip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from treasure_map.lib.hunt import analyzer2 as a2

    monkeypatch.setattr(a2, "installed_commit", lambda: COMMIT)
    db, atlas = _seeded(tmp_path), tmp_path / "atlas.db"
    a2.run_analyzer2(db, atlas, source_run_id="r")
    again = a2.run_analyzer2(db, atlas, source_run_id="r", rehunt=True)
    assert again.skipped is False
    assert again.instances_written == 1


@pytest.mark.parametrize("axis", ["commit", "extraction"])
def test_either_input_changing_defeats_the_skip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, axis: str
) -> None:
    """Both halves of the currency rule are load-bearing on a real hunt, not just in the unit test.

    MUTATION: drop the build_hash comparison from ``hunt_currency`` -> the 'extraction' case goes
    RED (an edited extraction pass would be silently ignored, which is the exact failure mode that
    made pass_version span the whole pipeline in the first place). Drop the commit comparison ->
    the 'commit' case goes RED.
    """
    from treasure_map.lib.hunt import analyzer2 as a2

    monkeypatch.setattr(a2, "installed_commit", lambda: COMMIT)
    db, atlas = _seeded(tmp_path), tmp_path / "atlas.db"
    a2.run_analyzer2(db, atlas, source_run_id="r")
    assert a2.run_analyzer2(db, atlas, source_run_id="r").skipped is True

    if axis == "commit":
        monkeypatch.setattr(a2, "installed_commit", lambda: OTHER)
    else:
        stamp = sqlite3.connect(db)
        stamp.execute("UPDATE binaries SET pass_version = 'pv_edited'")
        stamp.commit()
        stamp.close()
    assert a2.run_analyzer2(db, atlas, source_run_id="r").skipped is False


def test_a_completed_hunt_always_leaves_the_stamp_current(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The invariant every later skip and every staleness read rests on.

    After any hunt that finished — whether it did the work or skipped it — the run's stamp equals
    the running commit. If a completed hunt could leave a stale or absent stamp, the next run would
    re-hunt forever (harmless but pointless) or, worse, a staleness read would report a run as
    produced by code that did not produce it.
    """
    from treasure_map.lib.hunt import analyzer2 as a2

    monkeypatch.setattr(a2, "installed_commit", lambda: COMMIT)
    db, atlas = _seeded(tmp_path), tmp_path / "atlas.db"
    for _ in range(2):  # the working pass, then the skipping one
        a2.run_analyzer2(db, atlas, source_run_id="r")
        conn = open_atlas(atlas)
        try:
            assert get_run(conn, "r").hunt_commit == COMMIT  # type: ignore[union-attr]
        finally:
            conn.close()


def test_an_unknown_install_commit_never_skips_a_real_hunt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The developer case, and the one most likely to be got wrong silently.

    An editable install records no commit. Every hunt from it must do the work — which is exactly
    what makes the skip safe to ship: the environment where the code is changing fastest is the one
    where the skip never fires. If this regressed, a developer would edit the hunt, re-run it, and
    be shown the previous version's candidates.
    """
    from treasure_map.lib.hunt import analyzer2 as a2

    monkeypatch.setattr(a2, "installed_commit", lambda: UNKNOWN_VERSION)
    db, atlas = _seeded(tmp_path), tmp_path / "atlas.db"
    a2.run_analyzer2(db, atlas, source_run_id="r")
    assert a2.run_analyzer2(db, atlas, source_run_id="r").skipped is False
