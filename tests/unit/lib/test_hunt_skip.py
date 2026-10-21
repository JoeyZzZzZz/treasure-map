# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The hunt-skip decision, the commit stamp that backs it, and the staleness reads built on it.

★ THE FOUNDATION IS MEASURED, NOT ASSUMED. Skipping a hunt is only defensible because the hunt
produces the same content rows twice from the same analysis.db and the same code. That property
was established by EXECUTION on real firmware before the skip was enabled — each run digesting
identically across two consecutive hunts of the same database.
Those runs cannot live in this file (they need multi-hundred-MB analysis databases and minutes of
CPU), so what is pinned here is everything downstream of that measurement: that the decision only
skips on a CONFIRMED match, that the stamp is written only after the instances it describes, and
that the staleness reads use the opposite bar from the skip.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import RunRow
from treasure_map.lib.atlas.writer import begin_run, finish_run
from treasure_map.lib.hunt.analyzer2 import hunt_currency
from treasure_map.lib.query import get_run, run_staleness
from treasure_map.lib.rescan_version import CodeStamp
from treasure_map.lib.storage.connection import open_db
from treasure_map.version import UNKNOWN_VERSION

COMMIT = "a" * 40
OTHER = "b" * 40
BUILD = "8beedde56942dbb1"
FP = "f" * 32  # the hunt input fingerprint
HCODE = "src-a1a1a1a1a1a1a1a1"  # the running hunt code stamp
OTHER_HCODE = "src-b2b2b2b2b2b2b2b2"


def _scan(
    *, code: str = "src-c3c3c3c3c3c3c3c3", pyelftools: str = "0.33", threshold: int = 25000
) -> str:
    """A canonical-JSON scan stamp, so a test can vary one leaf at a time (code / deps / config)."""
    return json.dumps(
        {
            "code": code,
            "deps": {"pyelftools": pyelftools},
            "config": {"xref_fold_edge_threshold": threshold},
        },
        sort_keys=True,
        separators=(",", ":"),
    )


SCAN = _scan()
CURRENT = CodeStamp(hunt=HCODE, scan=SCAN)  # the running code stamp staleness compares against


def _row(**over: object) -> dict[str, object]:
    """A stored run row in the shape ``_stored_run_row`` returns — INCLUDING the live row count.

    Mirrors the real reader deliberately rather than accepting whatever keys a test happens to
    pass: when the currency rule grows an input, every case here has to be re-stated in terms of
    it, which is how a test notices that the decision now rests on something it never set."""
    base: dict[str, object] = {
        "scan_status": "complete",
        "hunt_commit": COMMIT,
        "hunt_code_version": HCODE,
        "scan_stamp": SCAN,
        "build_hash": BUILD,
        "hunt_instances": 3,
        "live_instances": 3,
        "hunt_input_fingerprint": FP,
    }
    base.update(over)
    return base


# --------------------------------------------------------------------------- currency decision


def test_same_code_and_same_analysis_db_is_current() -> None:
    """The one case that skips: both inputs to the hunt are demonstrably the ones already used."""
    c = hunt_currency(
        _row(), build_hash=BUILD, hunt_code=HCODE, db_scan_stamp=SCAN, input_fingerprint=FP
    )
    assert c.current is True
    assert HCODE in c.reason


@pytest.mark.parametrize(
    ("row", "build", "hunt_code", "db_stamp", "why"),
    [
        (None, BUILD, HCODE, SCAN, "no run row at all"),
        (_row(scan_status="in_progress"), BUILD, HCODE, SCAN, "previous hunt crashed mid-write"),
        (_row(scan_status="failed"), BUILD, HCODE, SCAN, "previous hunt failed"),
        (_row(scan_status="partial"), BUILD, HCODE, SCAN, "previous hunt only partial"),
        (_row(hunt_code_version=None), BUILD, HCODE, SCAN, "hunted before the code stamp existed"),
        (_row(hunt_code_version=OTHER_HCODE), BUILD, HCODE, SCAN, "a different hunt code"),
        (_row(), BUILD, HCODE, None, "this analysis.db records no scan stamp"),
        # Both the stored and the live scan stamp absent: the no-scan-stamp branch is what catches
        # this. Without it the `stored != db` check reads None != None as equal and the run would be
        # wrongly skipped — the row the audit's G06 mutation (dropping that branch) slips through.
        (_row(scan_stamp=None), BUILD, HCODE, None, "neither run nor db records a scan stamp"),
        (_row(scan_stamp=_scan(code="src-pipeOTHER")), BUILD, HCODE, SCAN, "analysis.db rebuilt"),
        (_row(), None, HCODE, SCAN, "no current extraction hash to compare"),
        (_row(build_hash=None), BUILD, HCODE, SCAN, "the run recorded no extraction hash"),
        (_row(build_hash="0000"), BUILD, HCODE, SCAN, "the extraction changed"),
        (_row(hunt_input_fingerprint="0" * 32), BUILD, HCODE, SCAN, "another firmware was read"),
    ],
)
def test_every_unconfirmed_case_re_hunts(
    row: dict[str, object] | None, build: str | None, hunt_code: str, db_stamp: str | None, why: str
) -> None:
    """★ The load-bearing direction: anything short of a proven match does the work again.

    Each row here is a way of failing to CONFIRM that the stored result came from this hunt code and
    this analysis.db. None of them is a proven mismatch — several are simply missing information —
    and all of them must still re-hunt, because a wrongly-skipped hunt leaves stale candidates
    that are indistinguishable from fresh ones while a wrongly-repeated hunt only costs time.

    MUTATION (proves this has teeth): loosen any single branch in ``hunt_currency`` — e.g. drop
    the ``scan_status`` check, or accept a NULL ``hunt_code_version`` as matching, or compare only
    the code and not the build hash — and the corresponding row here goes RED.
    """
    c = hunt_currency(
        row, build_hash=build, hunt_code=hunt_code, db_scan_stamp=db_stamp, input_fingerprint=FP
    )
    assert c.current is False, why
    assert c.reason, "a decision must always say why, in both directions"


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


def test_begin_run_without_a_firmware_root_leaves_the_recorded_one_alone(tmp_path: Path) -> None:
    """★ A caller passing no firmware root does not KNOW one; it is not reporting that the run
    has none.

    `tmap hunt` is exactly that caller: it re-hunts an analysis.db and is never told which firmware
    produced it, so it reaches begin_run with firmware_path=None. Assigned straight from
    ``excluded``, that NULLed the column on every hunt of an already-scanned run — and an absent
    firmware root is the SOLE condition on which `tmap rescan` reports a run as un-refreshable. A
    refresh would have spent the run's ability to ever be refreshed again.

    The neighbouring columns stay unconditional on purpose: each describes THIS extraction, where
    None is a scan that genuinely has nothing to record. Only the firmware root is a fact about the
    run that outlives any single hunt, so only it is COALESCEd.

    MUTATION: write ``firmware_path = excluded.firmware_path`` again -> RED. Measured: 1 failed.
    """
    conn = _atlas(tmp_path)
    begin_run(conn, "r1", analysis_db_path="/x/a.db", firmware_path="/fw/root", build_hash=BUILD)
    begin_run(conn, "r1", analysis_db_path="/x/a.db", build_hash=BUILD)  # a hunt, no root known
    assert (
        conn.execute("SELECT firmware_path FROM run WHERE run_id='r1'").fetchone()[0] == "/fw/root"
    )
    # ...and a caller that DOES know a new location still moves it (COALESCE must not freeze it).
    begin_run(conn, "r1", analysis_db_path="/x/a.db", firmware_path="/fw/moved", build_hash=BUILD)
    assert (
        conn.execute("SELECT firmware_path FROM run WHERE run_id='r1'").fetchone()[0] == "/fw/moved"
    )


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
            hunt_code=HCODE,
            db_scan_stamp=SCAN,
            input_fingerprint=FP,
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
        "hunt_code_version": HCODE,
        "scan_stamp": SCAN,
        "scan_status": "complete",
    }
    base.update(over)
    return RunRow(**base)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("run", "build", "commit", "axis"),
    [
        # extraction axis (build_hash), unchanged
        (_run(build_hash="deadbeef"), BUILD, COMMIT, "extraction"),
        # hunt code stamp differs
        (_run(hunt_code_version=OTHER_HCODE), BUILD, COMMIT, "hunt"),
        # scan stamp differs — one proven case per leaf (code / deps / config)
        (_run(scan_stamp=_scan(code="src-pipeX")), BUILD, COMMIT, "hunt"),
        (_run(scan_stamp=_scan(pyelftools="0.34")), BUILD, COMMIT, "hunt"),
        (_run(scan_stamp=_scan(threshold=10000)), BUILD, COMMIT, "hunt"),
        # an OLD run (no code stamp) still falls back to the commit rule
        (_run(hunt_code_version=None, scan_stamp=None, hunt_commit=OTHER), BUILD, COMMIT, "hunt"),
        # an editable install (unknown commit) is still refused when the code stamp PROVES a change
        (_run(hunt_code_version=OTHER_HCODE), BUILD, UNKNOWN_VERSION, "hunt"),
    ],
)
def test_a_proven_mismatch_is_stale(run: RunRow, build: str, commit: str, axis: str) -> None:
    s = run_staleness(run, build_hash=build, current=CURRENT, commit=commit)
    assert s.stale is True
    assert s.axis == axis
    assert s.remedy


@pytest.mark.parametrize(
    ("run", "build", "commit", "why", "detail_has"),
    [
        (
            _run(hunt_code_version=None, scan_stamp=None, hunt_commit=None),
            BUILD,
            COMMIT,
            "old run, no stamp",
            None,
        ),
        (
            _run(hunt_code_version=None, scan_stamp=None, hunt_commit=UNKNOWN_VERSION),
            BUILD,
            COMMIT,
            "an unrecorded commit is not a commit",
            None,
        ),
        (
            _run(hunt_code_version=None, scan_stamp=None),
            BUILD,
            UNKNOWN_VERSION,
            "an editable install on an old run must not mute it",
            None,
        ),
        (
            _run(build_hash=None),
            BUILD,
            COMMIT,
            "a run with no hash cannot be shown to differ",
            None,
        ),
        (_run(), None, COMMIT, "no current hash to compare against", None),
        (_run(build_hash="mixed:3"), BUILD, COMMIT, "a count is not a hash — not comparable", None),
        # new-stamp run whose scan stamp cannot be compared is a caveat, never a refusal — and it
        # must SAY the scan stamp is what could not be compared, never fall through to "all match".
        (
            _run(scan_stamp=None),
            BUILD,
            COMMIT,
            "a new run with no scan stamp is unconfirmable",
            "scan stamp (",
        ),
        (
            _run(scan_stamp=_scan(pyelftools=UNKNOWN_VERSION)),
            BUILD,
            COMMIT,
            "an unknown dep leaf is unconfirmable",
            "scan stamp (",
        ),
    ],
)
def test_unconfirmable_is_never_stale(
    run: RunRow, build: str | None, commit: str, why: str, detail_has: str | None
) -> None:
    """★ THE OPPOSITE BAR FROM THE SKIP, AND THE POINT OF SPLITTING THE TWO FUNCTIONS.

    ``hunt_currency`` treats "cannot tell" as re-do the work; ``run_staleness`` treats it as do not
    refuse. Collapsing them into one predicate would force one of two failures: a skip that fires
    on unconfirmed sameness (stale candidates served as fresh), or a refusal that fires on every
    unstamped run and every editable install (a tool that answers nothing, which in practice means
    a gate someone turns off). Each row is a case where the honest reading is "no information".

    MUTATION: make ``run_staleness`` return stale whenever the stamps merely fail to match — every
    row here goes RED while the proven-mismatch test above still passes.

    MUTATION (``detail_has``): make ``run_staleness`` drop the "scan stamp (…)" caveat for a
    new-stamp run whose scan stamp cannot be compared, so it reads "all match" instead — the two
    rows that carry ``detail_has`` go RED. Asserting only that ``detail`` is non-empty does not
    catch it, because the wrong "all match" string is non-empty too; a run reported current when
    nothing was comparable is the one that serves a stale answer as fresh.
    """
    s = run_staleness(run, build_hash=build, current=CURRENT, commit=commit)
    assert s.stale is False, why
    assert s.detail, "a not-stale reading must still say what could not be compared"
    if detail_has is not None:
        assert detail_has in s.detail, why
        assert s.remedy, why


def test_remedy_names_a_runnable_command_only_when_the_firmware_is_recorded() -> None:
    """A run with no firmware root cannot be told to `tmap rescan` — that command would fail.

    MUTATION: make ``_remedy_for`` always emit the rescan command -> RED. The wrong remedy is worse
    than a vague one: it sends the reader to a command that cannot work and looks like their fault.
    """
    have = run_staleness(
        _run(hunt_code_version=OTHER_HCODE), build_hash=BUILD, current=CURRENT, commit=COMMIT
    )
    assert "tmap rescan r1" in have.remedy
    lost = run_staleness(
        _run(hunt_code_version=OTHER_HCODE, firmware_path=None),
        build_hash=BUILD,
        current=CURRENT,
        commit=COMMIT,
    )
    assert "tmap rescan r1" not in lost.remedy
    assert "no firmware root" in lost.remedy


def test_a_run_with_no_firmware_is_told_its_facts_are_still_readable() -> None:
    """★ "You cannot refresh this" is not the same as "there is nothing you can do".

    A refused run whose firmware root is gone still has its analysis.db on disk, and the CLI reads
    that file directly — annotating the extraction mismatch instead of declining, because a person
    naming the file has chosen it on purpose. Naming that route turns a dead end into a next step;
    getting the firmware back can take a while, and the facts are readable in the meantime.

    MUTATION: drop the analysis-db branch from ``_remedy_for`` -> RED.
    """
    reachable = run_staleness(
        _run(
            hunt_code_version=OTHER_HCODE, firmware_path=None, analysis_db_path="/ws/r1/analysis.db"
        ),
        build_hash=BUILD,
        current=CURRENT,
        commit=COMMIT,
    )
    assert "tmap fact <subcommand> --analysis-db /ws/r1/analysis.db" in reachable.remedy
    assert "tmap scan <firmware-root> --run-id r1" in reachable.remedy


def test_the_analysis_db_route_is_not_offered_when_there_is_no_path_to_offer() -> None:
    """★ The command needs an argument. A run with neither a firmware root nor a recorded
    analysis.db would otherwise be handed ``--analysis-db None`` — a remedy that cannot be typed,
    which is worse than the honest "re-scan when you have the firmware".

    MUTATION: emit the analysis-db line unconditionally -> RED.
    """
    nothing = run_staleness(
        _run(hunt_code_version=OTHER_HCODE, firmware_path=None, analysis_db_path=None),
        build_hash=BUILD,
        current=CURRENT,
        commit=COMMIT,
    )
    assert "--analysis-db" not in nothing.remedy
    assert "tmap scan <firmware-root> --run-id r1" in nothing.remedy


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

    def _only_current(payload: str | None) -> object:
        # One distribution installed, under the current name; the old name is absent. (A fake
        # answering for both names would read as two installs, which is unknown on its own.)
        def _distribution(name: str) -> _Dist:
            if name != "tmap-agents":
                raise ModuleNotFoundError(name)
            return _Dist(payload)

        return _distribution

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
        monkeypatch.setattr(tm_version, "distribution", _only_current(payload))
        assert tm_version.installed_commit() == UNKNOWN_VERSION, payload

    monkeypatch.setattr(
        tm_version, "distribution", _only_current('{"vcs_info":{"commit_id":"abc"}}')
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
    # The scan stamp the hunt copies onto the run row and later compares against: without it the
    # analysis.db records no stamp and every hunt re-runs (the conservative direction).
    conn.execute("INSERT INTO scan_stamp (id, stamp) VALUES (1, ?)", (SCAN,))
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
    assert first.instances_written == 2  # cmd + the snprintf's own write candidate
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
    assert again.instances_written == 2  # cmd + the snprintf's own write candidate


def test_the_hunt_code_stamp_is_grabbed_once_so_the_skip_and_the_write_agree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``run_analyzer2`` reads the hunt code stamp ONCE at the start; the currency decision and the
    stamp ``finish_run`` records are the same value, so what is skipped and what is written cannot
    disagree.

    MUTATION: re-read ``rescan_version.hunt_code_version()`` at the finish_run site instead of
    reusing the one taken at the start -> the stand-in's second value "B" would be written while the
    skip judged against "A", and ``call_count`` would be 2.
    """
    from treasure_map.lib.hunt import analyzer2 as a2

    monkeypatch.setattr(a2, "installed_commit", lambda: COMMIT)
    stand_in = MagicMock(side_effect=["A", "B", "C"])
    monkeypatch.setattr(a2.rescan_version, "hunt_code_version", stand_in)
    db, atlas = _seeded(tmp_path), tmp_path / "atlas.db"

    a2.run_analyzer2(db, atlas, source_run_id="r", firmware_path="/fw")

    assert stand_in.call_count == 1
    conn = open_atlas(atlas)
    try:
        written = conn.execute("SELECT hunt_code_version FROM run WHERE run_id='r'").fetchone()[0]
    finally:
        conn.close()
    assert written == "A", "finish_run must record the stamp taken at the start, not a re-read"


def test_an_unreadable_input_fingerprint_never_skips() -> None:
    c = hunt_currency(
        _row(), build_hash=BUILD, hunt_code=HCODE, db_scan_stamp=SCAN, input_fingerprint=None
    )
    assert c.current is False


@pytest.mark.parametrize(
    "axis", ["hunt_code", "scan_stamp", "extraction", "firmware", "non_binary", "symlink"]
)
def test_either_input_changing_defeats_the_skip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, axis: str
) -> None:
    """Both halves of the currency rule are load-bearing on a real hunt, not just in the unit test.

    MUTATION: drop the build_hash comparison from ``hunt_currency`` -> the 'extraction' case goes
    RED (an edited extraction pass would be silently ignored, which is the exact failure mode that
    made pass_version span the whole pipeline in the first place). Drop the hunt-code comparison ->
    the 'hunt_code' case goes RED. Drop the scan-stamp comparison -> the 'scan_stamp' case goes RED
    (a rebuilt analysis.db kept the old candidates). Drop the input fingerprint -> the 'firmware'
    case goes RED: changed firmware kept the old candidates.

    The last two cases change one row's content and no table's row count, so the per-table counts
    in the fingerprint cannot see them. MUTATION (each measured RED, ``skipped`` stays True): drop
    the non_binary_files query from ``hunt_input_fingerprint`` -> the 'non_binary' case; drop the
    fs_symlinks query -> the 'symlink' case.
    """
    from treasure_map.lib.hunt import analyzer2 as a2

    monkeypatch.setattr(a2, "installed_commit", lambda: COMMIT)
    db, atlas = _seeded(tmp_path), tmp_path / "atlas.db"
    files = sqlite3.connect(db)
    files.execute(
        "INSERT INTO non_binary_files (kind, name, path, sha256) "
        "VALUES ('shell_script', 'rcS', 'etc/init.d/rcS', ?)",
        ("c" * 64,),
    )
    files.execute(
        "INSERT INTO fs_symlinks (link_path, link_name, target_raw, target_name, resolved) "
        "VALUES ('bin/sh', 'sh', 'busybox', 'busybox', 1)"
    )
    files.commit()
    files.close()
    a2.run_analyzer2(db, atlas, source_run_id="r")
    assert a2.run_analyzer2(db, atlas, source_run_id="r").skipped is True

    if axis == "hunt_code":
        # The hunt code changed since this run was hunted (patched on the module the hunt reads
        # it through, per the rescan_version call convention).
        monkeypatch.setattr(a2.rescan_version, "hunt_code_version", lambda: OTHER_HCODE)
    elif axis == "scan_stamp":
        # The analysis.db was rebuilt: its scan stamp no longer matches the copy on the run row.
        stamp = sqlite3.connect(db)
        stamp.execute("UPDATE scan_stamp SET stamp = ? WHERE id = 1", (_scan(code="src-rebuilt"),))
        stamp.commit()
        stamp.close()
    elif axis == "extraction":
        stamp = sqlite3.connect(db)
        stamp.execute("UPDATE binaries SET pass_version = 'pv_edited'")
        stamp.commit()
        stamp.close()
    elif axis == "firmware":
        # Same tmap, same extraction code, another firmware: a binary's content changed. The
        # extraction hash cannot see this — it names the code, not the image.
        stamp = sqlite3.connect(db)
        stamp.execute("UPDATE binaries SET sha256 = 'e' || substr(sha256, 2)")
        stamp.commit()
        stamp.close()
    elif axis == "non_binary":
        # Only an init script's content changed: same file, same path, every binary unchanged.
        stamp = sqlite3.connect(db)
        stamp.execute("UPDATE non_binary_files SET sha256 = ?", ("d" * 64,))
        stamp.commit()
        stamp.close()
    else:
        # Only one link's target changed: bin/sh now names another program.
        stamp = sqlite3.connect(db)
        stamp.execute("UPDATE fs_symlinks SET target_raw = 'bash', target_name = 'bash'")
        stamp.commit()
        stamp.close()
    assert a2.run_analyzer2(db, atlas, source_run_id="r").skipped is False


def test_a_completed_hunt_always_leaves_the_stamp_current(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The invariant every later skip and every staleness read rests on.

    After any hunt that finished — whether it did the work or skipped it — the run's code stamp
    equals the running hunt code. If a completed hunt could leave a stale or absent stamp, the next
    run would re-hunt forever (harmless but pointless) or, worse, a staleness read would report a
    run as produced by code that did not produce it.
    """
    from treasure_map.lib.hunt import analyzer2 as a2

    db, atlas = _seeded(tmp_path), tmp_path / "atlas.db"
    for _ in range(2):  # the working pass, then the skipping one
        a2.run_analyzer2(db, atlas, source_run_id="r")
        conn = open_atlas(atlas)
        try:
            assert (
                get_run(conn, "r").hunt_code_version  # type: ignore[union-attr]
                == a2.rescan_version.hunt_code_version()
            )
        finally:
            conn.close()


def test_an_editable_install_skips_when_the_code_stamp_matches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The developer case — and the one whose BEHAVIOUR this change flips.

    An editable install records no commit, so the old commit-based skip never fired there: every
    hunt redid the work. The code stamp is recorded even for an editable checkout, so now a second
    hunt of the SAME code over the SAME analysis.db skips, just as a release install does. Editing
    the hunt still defeats it (the stamp changes), which is what keeps the developer safe.

    MUTATION: make ``hunt_currency`` consult ``commit`` again -> RED (the unknown commit would
    force a re-hunt and this would never skip).
    """
    from treasure_map.lib.hunt import analyzer2 as a2

    monkeypatch.setattr(a2, "installed_commit", lambda: UNKNOWN_VERSION)
    db, atlas = _seeded(tmp_path), tmp_path / "atlas.db"
    a2.run_analyzer2(db, atlas, source_run_id="r")
    assert a2.run_analyzer2(db, atlas, source_run_id="r").skipped is True


# ------------------------------------------------------- the stamp must describe rows that exist


def _seeded_no_candidates(tmp_path: Path) -> Path:
    """An analysis.db that yields ZERO candidates — a legitimate, complete result.

    Load-bearing for the over-correction guard below: the difference between "the rows this hunt
    wrote are gone" and "this hunt wrote no rows" cannot be read off the table, only off the
    recorded count."""
    db = tmp_path / "empty.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, last_seen_at, pass_version) "
        "VALUES (1, 'quiet', 'usr/sbin/quiet', ?, '2026-01-01 00:00:00', 'pv_x')",
        ("b" * 64,),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, pseudocode, pseudocode_hash, callees)"
        " VALUES (1, 1, 'quiet', '0x2000', 'void quiet(void){ return; }', 'h_quiet', ?)",
        (json.dumps([]),),
    )
    conn.execute("INSERT INTO scan_stamp (id, stamp) VALUES (1, ?)", (SCAN,))
    conn.commit()
    conn.close()
    return db


def _run_column(atlas: Path, run_id: str, column: str) -> object:
    conn = open_atlas(atlas)
    try:
        row = conn.execute(
            f"SELECT {column} FROM run WHERE run_id = ?",  # noqa: S608 -- fixed literal names
            (run_id,),
        ).fetchone()
        return None if row is None else row[0]
    finally:
        conn.close()


def test_the_stamp_records_how_many_rows_the_hunt_wrote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The count is written beside the commit, by the same call, after the same transaction."""
    from treasure_map.lib.hunt import analyzer2 as a2

    monkeypatch.setattr(a2, "installed_commit", lambda: COMMIT)
    db, atlas = _seeded(tmp_path), tmp_path / "atlas.db"
    stats = a2.run_analyzer2(db, atlas, source_run_id="r")
    assert stats.instances_written == 2  # cmd + the snprintf's own write candidate
    assert _run_column(atlas, "r", "hunt_instances") == 2


def test_rows_deleted_out_from_under_the_stamp_defeat_the_skip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ THE HOLE THIS CLOSES — a stamp vouching for rows that are not there any more.

    Delete a run's instances by any route that is not this module (a manual DELETE, a half-restored
    atlas copy, another caller of delete_run_instances) and the stamp keeps saying "this commit
    produced this run's candidates". Before the count was compared, the next hunt read that stamp,
    skipped, and reported "already hunted by this tmap" over an empty table. The skip must fail
    here, and the rows must come back.

    MUTATION: remove the ``stored_rows != live_rows`` branch from ``hunt_currency`` -> RED
    (skipped is True and the table stays empty). Measured RED at 1 failed.

    ★ Why the 861ef07 mutation set missed it: its end-to-end assertion was "a skip leaves the rows
    unchanged", which holds just as well when both sides are zero. No mutation deleted data, so
    nothing ever produced the state in which the stamp is wrong.
    """
    from treasure_map.lib.hunt import analyzer2 as a2

    monkeypatch.setattr(a2, "installed_commit", lambda: COMMIT)
    db, atlas = _seeded(tmp_path), tmp_path / "atlas.db"
    a2.run_analyzer2(db, atlas, source_run_id="r")
    assert len(_instances(atlas)) == 2

    conn = open_atlas(atlas)
    conn.execute("DELETE FROM instance WHERE source_run_id = 'r'")
    conn.commit()
    conn.close()

    again = a2.run_analyzer2(db, atlas, source_run_id="r")
    assert again.skipped is False
    assert "stored candidate rows changed" in (again.hunt_currency or "")
    assert len(_instances(atlas)) == 2, "the re-hunt must restore what was deleted"


def test_extra_rows_under_the_stamp_also_defeat_the_skip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The comparison is a COUNT, so it catches a table that grew as well as one that shrank.

    This is the case an existence probe cannot see at all: the rows are still there, there are
    simply not the rows this hunt wrote. Pinned separately because a fix that only asked "is the
    table empty" would pass the deletion test above and fail here.

    MUTATION: replace the count comparison with ``if live_rows == 0`` -> RED.
    """
    from treasure_map.lib.hunt import analyzer2 as a2

    monkeypatch.setattr(a2, "installed_commit", lambda: COMMIT)
    db, atlas = _seeded(tmp_path), tmp_path / "atlas.db"
    a2.run_analyzer2(db, atlas, source_run_id="r")

    conn = open_atlas(atlas)
    conn.execute(
        "INSERT INTO instance (pattern_id, pseudocode_hash, sink_anchor, source_run_id, "
        "evidence_ref) SELECT pattern_id, 'h_extra', 'FUN_extra', 'r', 'r#extra' FROM instance "
        "WHERE source_run_id = 'r' LIMIT 1"
    )
    conn.commit()
    conn.close()

    again = a2.run_analyzer2(db, atlas, source_run_id="r")
    assert again.skipped is False
    assert "stored candidate rows changed" in (again.hunt_currency or "")


def test_a_run_stamped_before_the_count_existed_re_hunts_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A NULL count cannot be compared, so it re-hunts — the same direction every other unknown
    takes. Every run in an existing atlas is in this state exactly once after this ships.

    MUTATION: treat a NULL ``hunt_instances`` as matching -> RED.
    """
    from treasure_map.lib.hunt import analyzer2 as a2

    monkeypatch.setattr(a2, "installed_commit", lambda: COMMIT)
    db, atlas = _seeded(tmp_path), tmp_path / "atlas.db"
    a2.run_analyzer2(db, atlas, source_run_id="r")

    conn = open_atlas(atlas)
    conn.execute("UPDATE run SET hunt_instances = NULL WHERE run_id = 'r'")
    conn.commit()
    conn.close()

    again = a2.run_analyzer2(db, atlas, source_run_id="r")
    assert again.skipped is False
    assert "before the instance count was recorded" in (again.hunt_currency or "")
    assert _run_column(atlas, "r", "hunt_instances") == 2  # refilled by the re-hunt


def test_a_run_that_legitimately_found_nothing_still_skips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ THE OVER-CORRECTION GUARD — the only test that tells the right fix from the naive one.

    Zero candidates is a real, complete result: this analysis.db has no sink shape in it. An
    implementation that checked whether the run HAS rows (``SELECT 1 … LIMIT 1``) would find none,
    conclude the stamp was orphaned, and re-hunt this run on every single scan forever — trading
    one silent wrong answer for a permanent one. Comparing counts makes zero a value like any
    other.

    MUTATION: change the check to an existence probe -> RED (skipped is False). Measured RED at
    1 failed.
    """
    from treasure_map.lib.hunt import analyzer2 as a2

    monkeypatch.setattr(a2, "installed_commit", lambda: COMMIT)
    db, atlas = _seeded_no_candidates(tmp_path), tmp_path / "atlas.db"
    first = a2.run_analyzer2(db, atlas, source_run_id="quiet")
    assert first.instances_written == 0, "this fixture must produce no candidates, or it proves it"
    assert _run_column(atlas, "quiet", "hunt_instances") == 0  # zero is STORED, not left NULL

    second = a2.run_analyzer2(db, atlas, source_run_id="quiet")
    assert second.skipped is True


def test_begin_run_clears_the_count_with_the_stamp(tmp_path: Path) -> None:
    """The count describes the rows begin_run is about to delete, so it expires at the same moment
    the stamp does. Leaving it behind would let a crashed hunt's row count vouch for a table that
    was emptied and never refilled.

    MUTATION: drop ``hunt_instances = NULL`` from begin_run's upsert -> RED.
    """
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    begin_run(conn, "r", analysis_db_path="/ws/a.db")
    finish_run(conn, "r", hunt_commit=COMMIT, hunt_instances=7)
    assert conn.execute("SELECT hunt_instances FROM run WHERE run_id='r'").fetchone()[0] == 7
    begin_run(conn, "r", analysis_db_path="/ws/a.db")
    assert conn.execute("SELECT hunt_instances FROM run WHERE run_id='r'").fetchone()[0] is None
    conn.close()


def test_finish_run_without_a_count_leaves_an_existing_one_alone(tmp_path: Path) -> None:
    """COALESCE, same as the commit stamp: not knowing is not grounds to erase what is known."""
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    begin_run(conn, "r", analysis_db_path="/ws/a.db")
    finish_run(conn, "r", hunt_commit=COMMIT, hunt_instances=4)
    finish_run(conn, "r", scan_status="partial")
    assert conn.execute("SELECT hunt_instances FROM run WHERE run_id='r'").fetchone()[0] == 4
    conn.close()


def test_an_atlas_predating_the_count_column_gains_it_and_keeps_its_rows(tmp_path: Path) -> None:
    """The additive migration, on a run table built without the column.

    MUTATION: drop the hunt_instances ALTER from _migrate -> RED (OperationalError on the SELECT).
    """
    atlas = tmp_path / "old.db"
    raw = sqlite3.connect(atlas)
    raw.executescript(
        "CREATE TABLE run (run_id TEXT PRIMARY KEY, scan_status TEXT NOT NULL DEFAULT "
        "'in_progress', scanned_at DATETIME, updated_at DATETIME);"
        "INSERT INTO run (run_id, scan_status) VALUES ('legacy', 'complete');"
    )
    raw.commit()
    raw.close()

    conn = open_atlas(atlas)
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(run)").fetchall()}
        assert "hunt_instances" in cols
        row = conn.execute(
            "SELECT scan_status, hunt_instances FROM run WHERE run_id=?", ("legacy",)
        ).fetchone()
        # the row survived the migration; the count is honestly NULL, not 0
        assert tuple(row) == ("complete", None)
    finally:
        conn.close()
    open_atlas(atlas).close()  # idempotent


# --------------------------------------------------------- a skip still records where things are


def test_a_skipped_hunt_records_the_new_locations_and_nothing_else(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The skip returns before begin_run, so the lineage would otherwise freeze at the last hunt.

    Move the firmware, re-scan, and the run keeps pointing at a directory that is no longer there;
    everything that later re-reads the run (a rescan, the remedy line a refusal prints) is then
    aimed at the wrong place. The relocation is written, and ONLY the relocation: the stamp, the
    status, the counts and the extraction hash describe the hunt that actually ran, which this
    call did not.

    MUTATION: remove the ``refresh_run_lineage`` call from the skip branch -> RED (firmware_path
    stays at the old root). Call ``begin_run`` there instead -> RED (the stamp is cleared and the
    status is knocked back to in_progress). Measured RED at 1 failed each.
    """
    import shutil

    from treasure_map.lib.hunt import analyzer2 as a2

    monkeypatch.setattr(a2, "installed_commit", lambda: COMMIT)
    db, atlas = _seeded(tmp_path), tmp_path / "atlas.db"
    a2.run_analyzer2(db, atlas, source_run_id="r", firmware_path="/fw/OLD")
    before = {
        col: _run_column(atlas, "r", col)
        for col in ("scan_status", "hunt_commit", "hunt_instances", "build_hash", "scanned_at")
    }

    moved = tmp_path / "moved" / "analysis.db"
    moved.parent.mkdir()
    shutil.copy(db, moved)
    stats = a2.run_analyzer2(moved, atlas, source_run_id="r", firmware_path="/fw/NEW")

    assert stats.skipped is True
    assert _run_column(atlas, "r", "firmware_path") == "/fw/NEW"
    assert _run_column(atlas, "r", "analysis_db_path") == str(moved.resolve())
    for col, was in before.items():
        assert _run_column(atlas, "r", col) == was, f"a skip must not rewrite {col}"


def test_relocation_never_invents_a_run(tmp_path: Path) -> None:
    """UPDATE only. A run with no row has no lineage to relocate, and inserting one here would
    manufacture a scan that never happened."""
    from treasure_map.lib.atlas.writer import refresh_run_lineage

    conn = open_atlas(tmp_path / "atlas.db")
    try:
        assert refresh_run_lineage(conn, "ghost", analysis_db_path="/x", firmware_path="/y") == 0
        assert conn.execute("SELECT COUNT(*) FROM run").fetchone()[0] == 0
    finally:
        conn.close()


def test_an_atlas_without_the_fingerprint_column_gains_it_and_re_hunts(tmp_path: Path) -> None:
    """MUTATION: drop the hunt_input_fingerprint migration -> the old atlas never gains the column
    (the stamp write fails) -> RED."""
    db = tmp_path / "atlas.db"
    conn = open_atlas(db)
    conn.close()
    old = sqlite3.connect(db)
    old.execute("ALTER TABLE run DROP COLUMN hunt_input_fingerprint")
    old.execute("INSERT INTO run (run_id, scan_status) VALUES ('old', 'complete')")
    old.commit()
    old.close()
    conn = open_atlas(db)
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(run)")}
        assert "hunt_input_fingerprint" in cols
        finish_run(conn, "old", hunt_commit=COMMIT, hunt_input_fingerprint=FP)
        stored = conn.execute(
            "SELECT hunt_input_fingerprint FROM run WHERE run_id = 'old'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert stored == FP


# ------------------------------------------------- the code-content stamps (hunt_code / scan_stamp)


def test_finish_run_writes_the_code_stamps_and_begin_run_clears_them(tmp_path: Path) -> None:
    """finish_run records the hunt code and scan stamp; begin_run clears them with the other stamps
    the next hunt is about to replace.

    MUTATION: drop ``hunt_code_version``/``scan_stamp`` from finish_run's UPDATE -> RED (unstored).
    Drop ``hunt_code_version = NULL`` / ``scan_stamp = NULL`` from begin_run's upsert -> RED.
    """
    conn = open_atlas(tmp_path / "atlas.db")
    begin_run(conn, "r", analysis_db_path="/x/a.db", build_hash=BUILD)
    finish_run(conn, "r", hunt_commit=COMMIT, hunt_code_version=HCODE, scan_stamp=SCAN)
    row = conn.execute("SELECT hunt_code_version, scan_stamp FROM run WHERE run_id='r'").fetchone()
    assert (row[0], row[1]) == (HCODE, SCAN)
    begin_run(conn, "r", analysis_db_path="/x/a.db", build_hash=BUILD)  # a second hunt starts
    row = conn.execute("SELECT hunt_code_version, scan_stamp FROM run WHERE run_id='r'").fetchone()
    assert (row[0], row[1]) == (None, None)
    conn.close()


def test_finish_run_coalesces_the_code_stamps(tmp_path: Path) -> None:
    """A finish_run that does not know the stamps leaves the established ones alone (COALESCE)."""
    conn = open_atlas(tmp_path / "atlas.db")
    begin_run(conn, "r", analysis_db_path="/x/a.db")
    finish_run(conn, "r", hunt_code_version=HCODE, scan_stamp=SCAN)
    finish_run(conn, "r", scan_status="partial")
    row = conn.execute("SELECT hunt_code_version, scan_stamp FROM run WHERE run_id='r'").fetchone()
    assert (row[0], row[1]) == (HCODE, SCAN)
    conn.close()


def test_an_atlas_without_the_code_stamp_columns_gains_them(tmp_path: Path) -> None:
    """The additive migration brings the two columns onto an older atlas, NULL (i.e. fall back to
    the commit) on the runs that predate them.

    MUTATION: drop either ALTER from the atlas migration -> RED (the column never appears)."""
    db = tmp_path / "atlas.db"
    open_atlas(db).close()
    old = sqlite3.connect(db)
    old.execute("ALTER TABLE run DROP COLUMN hunt_code_version")
    old.execute("ALTER TABLE run DROP COLUMN scan_stamp")
    old.execute("INSERT INTO run (run_id, scan_status) VALUES ('old', 'complete')")
    old.commit()
    old.close()
    conn = open_atlas(db)
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(run)")}
        assert {"hunt_code_version", "scan_stamp"} <= cols
        row = conn.execute(
            "SELECT hunt_code_version, scan_stamp FROM run WHERE run_id='old'"
        ).fetchone()
        assert (row[0], row[1]) == (None, None)
    finally:
        conn.close()
