# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""The per-binary diff STATUS model: failure persistence (honest blind spots), the ATOMIC failure
write (no PK crash on retry, no dirty ok=1 residue on a layer-2 failure), incremental skip of
already-ok binaries, self-healing retry of failed ones, a retry cap with a sha256-driven reset, and
the read-side surfacing (list_diffs status, list_diff_blindspots, the empty-deltas note).

Hermetic and synthetic: the external toolchain (Ghidra / BinExport / BinDiff) never runs. Tests that
need the real layer-0 parse monkeypatch only the two subprocess steps to hand back a crafted
``.BinDiff`` (a plain SQLite file); everything downstream is exercised for real. Each fix is paired
with a reverse-validation assertion (a naive alternative that would go red), per the spec.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import DiffMetaRow
from treasure_map.lib.atlas.writer import (
    add_diff_meta,
    begin_run,
)
from treasure_map.lib.diff import driver
from treasure_map.lib.diff.driver import _DIFF_RETRY_LIMIT, DiffToolchainError
from treasure_map.lib.diff.layer0 import make_diff_id
from treasure_map.lib.query import diff_align
from treasure_map.lib.storage.connection import open_db

# ── fixtures ─────────────────────────────────────────────────────────────────────────


def _cfg():  # type: ignore[no-untyped-def]
    from treasure_map.lib.config.config import Config

    return Config()


def _mk_bindiff(path: Path, file_hashes: tuple[str, str]) -> Path:
    """A tiny synthetic .BinDiff with one matched pair (0x1000<->0x1100) + a file table whose side
    hashes must equal the two runs' binary sha256s (layer-0's binary-identity guard checks this)."""
    con = sqlite3.connect(path)
    con.execute(
        "CREATE TABLE function (id INTEGER PRIMARY KEY, address1 BIGINT, name1 TEXT, "
        "address2 BIGINT, name2 TEXT, similarity DOUBLE, confidence DOUBLE, "
        "basicblocks INTEGER, edges INTEGER, instructions INTEGER)"
    )
    con.execute(
        "INSERT INTO function (address1,name1,address2,name2,similarity,confidence,"
        "basicblocks,edges,instructions) VALUES (?,?,?,?,?,?,?,?,?)",
        (0x1000, "keep", 0x1100, "keep", 0.98, 0.97, 3, 2, 20),
    )
    con.execute("CREATE TABLE file (id INT, filename TEXT, hash CHARACTER(40))")
    con.executemany(
        "INSERT INTO file (id, filename, hash) VALUES (?, ?, ?)",
        [(1, "before", file_hashes[0]), (2, "after", file_hashes[1])],
    )
    con.commit()
    con.close()
    return path


def _seed_pair(
    tmp_path: Path, a: dict[str, str], b: dict[str, str], *, with_funcs: bool = False
) -> Path:
    """Two runs (run_a / run_b), one analysis.db each, mapping {binary name -> sha256}. ``.so``
    files are created on disk so preflight's locate check passes. Same tool/Ghidra -> no skew."""
    funcs = (("0x1000", "keep", "int keep(){}", 64),) if with_funcs else ()
    da = tmp_path / "a.db"
    db = tmp_path / "b.db"
    ca = open_db(da)
    cb = open_db(db)
    for i, (name, sha) in enumerate(a.items(), start=1):
        so = tmp_path / f"a_{name}"
        so.write_bytes(b"\x7fELF")
        ca.execute(
            "INSERT INTO binaries (id, name, path, sha256) VALUES (?, ?, ?, ?)",
            (i, name, str(so), sha),
        )
        if with_funcs:
            for addr, fname, pc, size in funcs:
                ca.execute(
                    "INSERT INTO functions (binary_id, name, address, pseudocode, size_bytes) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (i, fname, addr, pc, size),
                )
    for i, (name, sha) in enumerate(b.items(), start=1):
        so = tmp_path / f"b_{name}"
        so.write_bytes(b"\x7fELF")
        cb.execute(
            "INSERT INTO binaries (id, name, path, sha256) VALUES (?, ?, ?, ?)",
            (i, name, str(so), sha),
        )
        if with_funcs:
            for addr, fname, pc, size in funcs:
                cb.execute(
                    "INSERT INTO functions (binary_id, name, address, pseudocode, size_bytes) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (i, fname, addr, pc, size),
                )
    ca.commit()
    ca.close()
    cb.commit()
    cb.close()
    atlas_path = tmp_path / "atlas.db"
    con = open_atlas(atlas_path)
    begin_run(con, "run_a", analysis_db_path=str(da), tool_version="0.0.1", ghidra_version="11.4.3")
    begin_run(con, "run_b", analysis_db_path=str(db), tool_version="0.0.1", ghidra_version="11.4.3")
    con.close()
    return atlas_path


def _seed_committed_status(
    con: sqlite3.Connection,
    binary: str,
    *,
    diff_ok: int,
    attempts: int,
    sha_a: str | None,
    sha_b: str | None,
    reason: str | None = None,
) -> str:
    """Commit one diff_meta row as if a prior full diff had produced it (the plan's input state)."""
    did = make_diff_id("run_a", "run_b", binary)
    add_diff_meta(
        con,
        DiffMetaRow(
            diff_id=did,
            run_a_id="run_a",
            run_b_id="run_b",
            binary_a=binary,
            binary_b=binary,
            diff_ok=diff_ok,
            diff_status="ok" if diff_ok else "failed",
            diff_status_reason=reason,
            diff_attempts=attempts,
            sha256_a=sha_a,
            sha256_b=sha_b,
        ),
        commit=True,
    )
    return did


# ── failure is persisted as an honest row (never silently dropped) ──────────────────────


def test_record_diff_failure_writes_honest_row(tmp_path: Path) -> None:
    # ★ a failed binary must WRITE a diff_meta row (diff_ok=0 + status='failed' + a non-empty
    # reason + the sha it ran on), not vanish. Reverse of the old behaviour where a failure only
    # printed to stdout and left no trace.
    atlas_path = _seed_pair(tmp_path, {"liba": "s1"}, {"liba": "s1b"})
    con = open_atlas(atlas_path)
    did = make_diff_id("run_a", "run_b", "liba")
    attempts, reason = driver._record_diff_failure(
        con,
        diff_id=did,
        run_a_id="run_a",
        run_b_id="run_b",
        binary_short="liba",
        exc=DiffToolchainError("BinDiff failed (rc=1) ... Could not find basic block 000E1920"),
    )
    row = con.execute(
        "SELECT diff_ok, diff_status, diff_status_reason, diff_attempts, sha256_a, sha256_b, "
        "binary_a FROM diff_meta WHERE diff_id=?",
        (did,),
    ).fetchone()
    con.close()
    assert row is not None  # ★ the failure is persisted, not dropped
    assert row[0] == 0  # diff_ok
    assert row[1] == "failed"
    assert row[2] == "bindiff_flowgraph"  # classified from the message
    assert row[3] == 1 and attempts == 1
    assert (row[4], row[5]) == ("s1", "s1b")  # the content it ran on, for the incremental gate
    assert row[6] == "liba"  # binary_a set so plan_full_diff can map it
    assert reason == "bindiff_flowgraph"


def test_failure_reason_buckets() -> None:
    # the classifier distinguishes a likely-transient crash from a hard boundary from a timeout.
    c = driver._classify_failure_reason
    assert c(DiffToolchainError("BinExport subprocess failed (side a, x.so, rc=1)")) == (
        "binexport_ghidra_crash"
    )
    assert c(DiffToolchainError("BinDiff failed (rc=1) Could not find basic block 000E1920")) == (
        "bindiff_flowgraph"
    )
    assert c(DiffToolchainError("BinExport produced no file for side b")) == "binexport_no_file"
    assert c(DiffToolchainError("BinExport timed out for side a")) == "timeout"
    assert c(DiffToolchainError("something unexpected")) == "other"


# ── the atomic sequence: a second failure of the same binary must not crash ─────────────


def test_record_diff_failure_retry_is_atomic_no_pk_crash(tmp_path: Path) -> None:
    # ★ BLOCKER defence. The same binary failing TWICE must not raise a PRIMARY KEY conflict, must
    # leave ONE diff_meta row, and must count diff_attempts=2 (the retry path cannot crash on its
    # own prior row). This is the direct test of the rollback->delete->insert atomic sequence.
    atlas_path = _seed_pair(tmp_path, {"liba": "s1"}, {"liba": "s1b"})
    con = open_atlas(atlas_path)
    did = make_diff_id("run_a", "run_b", "liba")
    exc = DiffToolchainError("BinExport subprocess failed (rc=1)")
    driver._record_diff_failure(
        con, diff_id=did, run_a_id="run_a", run_b_id="run_b", binary_short="liba", exc=exc
    )
    # a SECOND failure of the same binary — must NOT raise, must replace not duplicate:
    driver._record_diff_failure(
        con, diff_id=did, run_a_id="run_a", run_b_id="run_b", binary_short="liba", exc=exc
    )
    n = con.execute("SELECT COUNT(*) FROM diff_meta WHERE diff_id=?", (did,)).fetchone()[0]
    attempts = con.execute(
        "SELECT diff_attempts FROM diff_meta WHERE diff_id=?", (did,)
    ).fetchone()[0]
    con.close()
    assert n == 1  # one row, not two
    assert attempts == 2  # the counter advanced at the same content


def test_plain_add_diff_meta_twice_conflicts(tmp_path: Path) -> None:
    # ★ Reverse-validation proving the atomic sequence is load-bearing: the NAIVE "just INSERT a
    # failed row" approach (a bare add_diff_meta) DOES crash on the second write with an
    # IntegrityError — which is exactly why _record_diff_failure must rollback + delete first.
    atlas_path = _seed_pair(tmp_path, {"liba": "s1"}, {"liba": "s1b"})
    con = open_atlas(atlas_path)
    did = make_diff_id("run_a", "run_b", "liba")
    row = DiffMetaRow(diff_id=did, run_a_id="run_a", run_b_id="run_b", binary_a="liba")
    add_diff_meta(con, row, commit=True)
    with pytest.raises(sqlite3.IntegrityError):
        add_diff_meta(con, row, commit=True)  # same PK -> conflict
    con.close()


# ── a layer-2 failure leaves NO dirty ok=1 row (the rollback) ───────────────────────────


def test_run_version_diff_layer2_failure_no_dirty_ok1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ★ MAJOR defence. layer-0 succeeds (INSERTing an ok=1 diff_meta + alignment into the
    # UNCOMMITTED transaction); layer-2 then fails. The failure path must roll that back so NO ok=1
    # row and NO alignment residue survive, and the honest failed row is written with attempts=1
    # (not 2). If the rollback were removed, _next_attempts would read the doomed uncommitted ok=1
    # row and over-count to 2 — so diff_attempts==1 is the teeth.
    bd = _mk_bindiff(tmp_path / "x.BinDiff", ("s1", "s1b"))
    atlas_path = _seed_pair(tmp_path, {"lib.so": "s1"}, {"lib.so": "s1b"}, with_funcs=True)
    con = open_atlas(atlas_path)
    monkeypatch.setattr(driver, "_check_toolchain", lambda config: None)
    monkeypatch.setattr(
        driver, "_run_binexport", lambda so, cfg, out, side, t: out / f"{side}.BinExport"
    )
    monkeypatch.setattr(driver, "_run_bindiff", lambda ea, eb, out, t: bd)

    def _layer2_boom(*a, **k):  # type: ignore[no-untyped-def]
        raise DiffToolchainError("layer2 boom")

    monkeypatch.setattr(driver, "run_layer2_delta", _layer2_boom)

    with pytest.raises(DiffToolchainError):
        driver.run_version_diff(con, "run_a", "run_b", "lib.so", config=_cfg())

    did = make_diff_id("run_a", "run_b", "lib.so")
    row = con.execute(
        "SELECT diff_ok, diff_status, diff_attempts FROM diff_meta WHERE diff_id=?", (did,)
    ).fetchone()
    n_align = con.execute(
        "SELECT COUNT(*) FROM function_alignment WHERE diff_id=?", (did,)
    ).fetchone()[0]
    n_meta = con.execute("SELECT COUNT(*) FROM diff_meta WHERE diff_id=?", (did,)).fetchone()[0]
    con.close()
    assert (row[0], row[1]) == (0, "failed")  # no dirty ok=1 residue
    assert row[2] == 1  # ★ correct attempts (rollback discarded the uncommitted ok=1 row)
    assert n_align == 0  # the layer-0 alignment rows were rolled back
    assert n_meta == 1  # exactly one row


def test_run_version_diff_success_sets_diff_ok_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the mirror: a fully-successful diff records diff_ok=1 / status='ok' / attempts=1 + the shas.
    bd = _mk_bindiff(tmp_path / "x.BinDiff", ("s1", "s1b"))
    atlas_path = _seed_pair(tmp_path, {"lib.so": "s1"}, {"lib.so": "s1b"}, with_funcs=True)
    con = open_atlas(atlas_path)
    monkeypatch.setattr(driver, "_check_toolchain", lambda config: None)
    monkeypatch.setattr(
        driver, "_run_binexport", lambda so, cfg, out, side, t: out / f"{side}.BinExport"
    )
    monkeypatch.setattr(driver, "_run_bindiff", lambda ea, eb, out, t: bd)

    summary = driver.run_version_diff(con, "run_a", "run_b", "lib.so", config=_cfg())

    row = con.execute(
        "SELECT diff_ok, diff_status, diff_status_reason, diff_attempts, sha256_a, sha256_b "
        "FROM diff_meta WHERE diff_id=?",
        (summary.diff_id,),
    ).fetchone()
    con.close()
    assert (row[0], row[1], row[2]) == (1, "ok", None)
    assert row[3] == 1
    assert (row[4], row[5]) == ("s1", "s1b")


# ── attempts reset when the content (sha256) changes ────────────────────────────────────


def test_plan_attempts_reset_on_sha_change(tmp_path: Path) -> None:
    # ★ MAJOR defence. A binary marked hard (attempts at the cap) whose CONTENT then changes must be
    # re-diffed (attempts void), not permanently skipped as a known hard boundary. The current
    # analysis.db sha differs from the recorded one, so it belongs in to_diff.
    atlas_path = _seed_pair(tmp_path, {"liba": "new_a"}, {"liba": "new_b"})
    con = open_atlas(atlas_path)
    _seed_committed_status(
        con, "liba", diff_ok=0, attempts=_DIFF_RETRY_LIMIT, sha_a="old_a", sha_b="old_b"
    )
    plan = driver.plan_full_diff(con, "run_a", "run_b")
    con.close()
    assert "liba" in plan.to_diff  # content changed -> re-diff (attempts reset)
    assert "liba" not in plan.hard_failed  # ★ NOT frozen as a known hard boundary


def test_plan_hard_failed_when_content_unchanged(tmp_path: Path) -> None:
    # Reverse of the above: SAME content at the cap stays hard_failed (the reset must be sha-gated,
    # not unconditional). Recorded sha == current sha, attempts at the cap.
    atlas_path = _seed_pair(tmp_path, {"liba": "s1"}, {"liba": "s1b"})
    con = open_atlas(atlas_path)
    _seed_committed_status(
        con, "liba", diff_ok=0, attempts=_DIFF_RETRY_LIMIT, sha_a="s1", sha_b="s1b"
    )
    plan = driver.plan_full_diff(con, "run_a", "run_b")
    con.close()
    assert "liba" in plan.hard_failed
    assert "liba" not in plan.to_diff


# ── incremental: an already-ok binary with unchanged content is skipped ─────────────────


def test_plan_incremental_skip_already_ok(tmp_path: Path) -> None:
    atlas_path = _seed_pair(tmp_path, {"liba": "s1"}, {"liba": "s1b"})
    con = open_atlas(atlas_path)
    _seed_committed_status(con, "liba", diff_ok=1, attempts=1, sha_a="s1", sha_b="s1b")
    plan = driver.plan_full_diff(con, "run_a", "run_b")
    con.close()
    assert "liba" in plan.already_ok  # succeeded + unchanged -> skip
    assert plan.binaries_to_run() == ()  # nothing needs diffing


def test_plan_ok_but_content_changed_is_rediffed(tmp_path: Path) -> None:
    # an ok=1 binary whose content changed is NOT skipped — it must be re-diffed.
    atlas_path = _seed_pair(tmp_path, {"liba": "NEW"}, {"liba": "NEWB"})
    con = open_atlas(atlas_path)
    _seed_committed_status(con, "liba", diff_ok=1, attempts=1, sha_a="old", sha_b="oldb")
    plan = driver.plan_full_diff(con, "run_a", "run_b")
    con.close()
    assert "liba" in plan.to_diff
    assert "liba" not in plan.already_ok


# ── retry cap: below it retries, at it becomes a (skippable) suspected boundary ──────────


def test_plan_retry_cap(tmp_path: Path) -> None:
    atlas_path = _seed_pair(tmp_path, {"under": "s1", "at": "s2"}, {"under": "s1b", "at": "s2b"})
    con = open_atlas(atlas_path)
    _seed_committed_status(
        con, "under", diff_ok=0, attempts=_DIFF_RETRY_LIMIT - 1, sha_a="s1", sha_b="s1b"
    )
    _seed_committed_status(
        con, "at", diff_ok=0, attempts=_DIFF_RETRY_LIMIT, sha_a="s2", sha_b="s2b"
    )
    plan = driver.plan_full_diff(con, "run_a", "run_b")
    con.close()
    assert "under" in plan.retry and "under" not in plan.hard_failed  # below cap -> retry
    assert "at" in plan.hard_failed and "at" not in plan.retry  # at cap -> suspected hard
    # default run skips the suspected-hard one; --force-retry re-attempts it:
    assert set(plan.binaries_to_run()) == {"under"}
    assert set(plan.binaries_to_run(force_retry=True)) == {"under", "at"}


# ── incidental self-heal: a failed binary that succeeds on retry ────────────────────────


def test_run_full_diff_recovers_failed_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ★ a binary recorded as failed (ok=0, under the cap) is retried; when it now succeeds it ends
    # diff_ok=1 with ONE row (not a failed row + a success row), and the outcome is labelled
    # recovered. The whole flow with one committed prior-failure state + a succeeding retry.
    atlas_path = _seed_pair(tmp_path, {"liba": "s1"}, {"liba": "s1b"})
    con = open_atlas(atlas_path)
    _seed_committed_status(con, "liba", diff_ok=0, attempts=1, sha_a="s1", sha_b="s1b")
    # real preflight (the .so files exist via _seed_pair) with the toolchain check stubbed; compute
    # is the parallel middle (stubbed to succeed); persist writes the ok=1 row (stubbed, no real
    # .BinDiff). The orchestration (retry -> compute -> persist -> recovered) is real.
    monkeypatch.setattr(driver, "_check_toolchain", lambda config: None)
    monkeypatch.setattr(
        driver,
        "compute_diff",
        lambda so_a, so_b, td, config: driver.DiffArtifacts(so_a, so_b, td / "x.BinDiff"),
    )

    def _fake_persist(atlas, **kw):  # type: ignore[no-untyped-def]
        did = kw["diff_id"]
        driver.delete_diff(atlas, did, commit=False)
        add_diff_meta(
            atlas,
            DiffMetaRow(
                diff_id=did,
                run_a_id=kw["run_a_id"],
                run_b_id=kw["run_b_id"],
                binary_a=kw["binary_short"],
                binary_b=kw["binary_short"],
                diff_ok=1,
                diff_status="ok",
                diff_attempts=2,
                sha256_a="s1",
                sha256_b="s1b",
            ),
            commit=True,
        )
        return driver.DiffSummary(
            diff_id=did,
            binary=kw["binary_name"],
            matched_pairs=1,
            version_skew=kw["version_skew"],
            delta_layer_changed=0,
            delta_layer_unchanged=0,
            delta_undetermined=0,
            warnings=kw["warnings"],
        )

    monkeypatch.setattr(driver, "_persist_success", _fake_persist)
    fsum = driver.run_full_diff(con, "run_a", "run_b", config=_cfg())
    row = con.execute(
        "SELECT diff_ok, diff_status FROM diff_meta WHERE diff_id=?",
        (make_diff_id("run_a", "run_b", "liba"),),
    ).fetchone()
    n = con.execute(
        "SELECT COUNT(*) FROM diff_meta WHERE diff_id=?", (make_diff_id("run_a", "run_b", "liba"),)
    ).fetchone()[0]
    con.close()
    assert (row[0], row[1]) == (1, "ok")  # self-healed
    assert n == 1  # one row, not failure+success
    liba = next(o for o in fsum.outcomes if o.binary == "liba")
    assert liba.error is None and liba.recovered is True  # labelled recovered


# ── read side: blind spots are queryable and empty deltas point at them ─────────────────


def test_list_diff_blindspots_and_status_in_list_diffs(tmp_path: Path) -> None:
    atlas_path = _seed_pair(tmp_path, {"ok_bin": "o1", "bad": "b1"}, {"ok_bin": "o2", "bad": "b2"})
    con = open_atlas(atlas_path)
    _seed_committed_status(con, "ok_bin", diff_ok=1, attempts=1, sha_a="o1", sha_b="o2")
    _seed_committed_status(
        con,
        "bad",
        diff_ok=0,
        attempts=_DIFF_RETRY_LIMIT,
        sha_a="b1",
        sha_b="b2",
        reason="bindiff_flowgraph",
    )

    bs = diff_align.list_diff_blindspots(con, "run_a", "run_b")
    assert bs["count"] == 1  # only the failed binary
    entry = bs["blindspots"][0]
    assert entry["binary"] == "bad"
    assert entry["diff_status_reason"] == "bindiff_flowgraph"
    assert entry["suspected_hard"] == 1  # at the cap

    ld = diff_align.list_diffs(con, "run_a", "run_b")
    by_bin = {d["binary"]: d for d in ld["diffs"]}
    assert by_bin["ok_bin"]["diff_ok"] == 1
    assert by_bin["bad"]["diff_ok"] == 0 and by_bin["bad"]["diff_status"] == "failed"
    con.close()


def test_get_diff_deltas_empty_points_at_status_even_non_verbose(tmp_path: Path) -> None:
    # ★ an empty get_diff_deltas is the trap ('reads as no change'); the honesty note that
    # points at diff_ok / list_diff_blindspots must appear EVEN in the terse (non-verbose) mode.
    atlas_path = _seed_pair(tmp_path, {"bad": "b1"}, {"bad": "b2"})
    con = open_atlas(atlas_path)
    did = _seed_committed_status(
        con, "bad", diff_ok=0, attempts=1, sha_a="b1", sha_b="b2", reason="binexport_ghidra_crash"
    )
    res = diff_align.get_diff_deltas(con, did, verbose=False)
    con.close()
    assert res["deltas"] == []
    assert "note" in res  # not a bare empty payload
    note = res["note"].lower()
    assert "not 'no changes'" in note or "not 'no change'" in note
    assert "diff_ok" in note and "list_diff_blindspots" in note
