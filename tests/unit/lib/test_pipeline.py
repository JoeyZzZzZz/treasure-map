# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for lib/analyze/pipeline.py.

Ghidra is fully mocked — these tests never touch analyzeHeadless.
They verify fail-fast behaviour, dirty-set routing, and result fields.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from treasure_map.lib.analyze.elf_inventory import ElfRecord
from treasure_map.lib.analyze.ghidra_runner import GhidraResult
from treasure_map.lib.analyze.pipeline import AnalyzeResult, run_analyze
from treasure_map.lib.config.config import Config
from treasure_map.lib.errors import GhidraNotFoundError
from treasure_map.lib.workspace.workspace import Workspace

MODULE = "treasure_map.lib.analyze.pipeline"


# ── helpers ───────────────────────────────────────────────────────────────────


def _cfg() -> Config:
    return Config()


def _rec(name: str = "httpd", sha: str = "abc123def4567890") -> ElfRecord:
    return ElfRecord(
        path=Path(f"/fake/bin/{name}"),
        name=name,
        arch="ARM:LE:32:v7",
        elf_type="executable",
        sha256=sha,
        dt_needed=["libc.so.0"],
    )


def _ok_ghidra(rec: ElfRecord) -> GhidraResult:
    return GhidraResult(
        binary=rec.path, output_file=Path("/fake/out.json"), success=True, elapsed=1.0
    )


def _fail_ghidra(rec: ElfRecord) -> GhidraResult:
    return GhidraResult(binary=rec.path, output_file=None, success=False, elapsed=0.5)


def _mock_runner(run_all_return: list[GhidraResult] | None = None) -> MagicMock:
    runner = MagicMock()
    runner.get_headless.return_value = Path("/fake/headless")
    runner.run_all.return_value = run_all_return or []
    runner.pass_version.return_value = "testpass"  # real str: stamped into binaries.pass_version
    runner.ghidra_version.return_value = "11.4.3"  # real str: stamped into binaries.ghidra_version
    return runner


def _mock_ingest(dirty_shas: set[str]) -> MagicMock:
    """Return a mock ingest_elfs that reports the given shas as dirty."""
    sha_to_id = {sha: i + 1 for i, sha in enumerate(dirty_shas)}
    return MagicMock(return_value=(sha_to_id, dirty_shas))


# ── fail-fast ─────────────────────────────────────────────────────────────────


def test_fail_fast_before_any_disk_work(tmp_path: Path) -> None:
    """GhidraNotFoundError is raised before scan_filesystem is called."""
    runner = MagicMock()
    runner.get_headless.side_effect = GhidraNotFoundError("Ghidra not found")

    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem") as mock_scan:
            with Workspace(tmp_path / "ws") as ws:
                with pytest.raises(GhidraNotFoundError):
                    run_analyze(tmp_path / "fs", ws, _cfg())

            mock_scan.assert_not_called()


# ── dirty set routing ─────────────────────────────────────────────────────────


def test_dirty_set_empty_skips_ghidra(tmp_path: Path) -> None:
    """When ingest_elfs reports 0 dirty shas, runner.run_all is not called."""
    rec = _rec()
    runner = _mock_runner()

    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=[rec]):
            with patch(f"{MODULE}.ingest_elfs", _mock_ingest(set())):
                with Workspace(tmp_path / "ws") as ws:
                    result = run_analyze(tmp_path / "fs", ws, _cfg())

    runner.run_all.assert_not_called()
    assert result.binary_count == 1
    assert result.dirty_count == 0
    assert result.ghidra_skipped == 1
    assert result.ghidra_ok == 0


def test_dirty_set_partial_only_runs_dirty(tmp_path: Path) -> None:
    """With 2 records and 1 already done, run_all receives only the dirty one."""
    rec1 = _rec("httpd", "deadbeef")
    rec2 = _rec("dropbear", "cafebabe")
    records = [rec1, rec2]

    captured: list[list[ElfRecord]] = []

    runner = _mock_runner()
    runner.run_all.side_effect = lambda recs, *a, **kw: (
        captured.append(list(recs)) or [_ok_ghidra(r) for r in recs]
    )

    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=records):
            # Only rec2 is dirty (rec1 has ghidra_ok=1 in DB)
            with patch(f"{MODULE}.ingest_elfs", _mock_ingest({"cafebabe"})):
                with Workspace(tmp_path / "ws") as ws:
                    result = run_analyze(tmp_path / "fs", ws, _cfg())

    assert len(captured) == 1
    assert len(captured[0]) == 1
    assert captured[0][0].sha256 == "cafebabe"
    assert result.binary_count == 2
    assert result.dirty_count == 1
    assert result.ghidra_skipped == 1


# ── empty filesystem ──────────────────────────────────────────────────────────


def test_empty_fs_ghidra_skipped(tmp_path: Path) -> None:
    """Zero ELFs found → Ghidra step is not called."""
    runner = _mock_runner()
    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=[]):
            with Workspace(tmp_path / "ws") as ws:
                result = run_analyze(tmp_path / "fs", ws, _cfg())

    runner.run_all.assert_not_called()
    assert result.binary_count == 0
    assert result.dirty_count == 0
    assert result.ghidra_skipped == 0


# ── AnalyzeResult fields ──────────────────────────────────────────────────────


def test_analyze_result_fields(tmp_path: Path) -> None:
    """AnalyzeResult carries correct counts and db_path."""
    rec1 = _rec("httpd", "deadbeef")
    rec2 = _rec("dropbear", "cafebabe")
    records = [rec1, rec2]

    runner = _mock_runner([_ok_ghidra(rec1), _fail_ghidra(rec2)])
    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=records):
            # Both records are dirty
            with patch(f"{MODULE}.ingest_elfs", _mock_ingest({"deadbeef", "cafebabe"})):
                with Workspace(tmp_path / "ws") as ws:
                    result = run_analyze(tmp_path / "fs", ws, _cfg())

    assert isinstance(result, AnalyzeResult)
    assert result.binary_count == 2
    assert result.dirty_count == 2
    assert result.ghidra_ok == 1
    assert result.ghidra_failed == 1
    assert result.ghidra_skipped == 0
    assert result.functions_ingested == 0
    assert result.imports_ingested == 0
    assert result.exports_ingested == 0
    assert result.strings_ingested == 0
    assert result.layer0_xrefs == 0
    assert result.layer1_xrefs == 0
    assert result.layer2_xrefs == 0
    assert result.layer3_xrefs == 0
    assert result.strings_classified == 0
    assert result.total_xrefs == 0
    assert result.db_path == tmp_path / "ws" / "analysis.db"
    assert result.elapsed > 0


# ── progress callback ─────────────────────────────────────────────────────────


def test_progress_callback_passed_to_run_all(tmp_path: Path) -> None:
    """run_analyze forwards progress_callback to GhidraRunner.run_all."""
    rec = _rec()
    runner = _mock_runner([_ok_ghidra(rec)])

    def cb(s: str, m: dict[str, Any]) -> None:
        pass

    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=[rec]):
            with patch(f"{MODULE}.ingest_elfs", _mock_ingest({rec.sha256})):
                with Workspace(tmp_path / "ws") as ws:
                    run_analyze(tmp_path / "fs", ws, _cfg(), progress_callback=cb)

    _args, kwargs = runner.run_all.call_args
    assert kwargs.get("progress_callback") is cb or cb in _args


# ── what a failed attempt ran under, and what the report says about a skip ────────────


def test_a_failed_attempt_records_its_budget_and_its_extractor(tmp_path: Path) -> None:
    """The failure UPDATE stores the two facts the next scan's decision is made from.

    ``pass_version`` is deliberately NOT stamped on failure — it describes the OUTPUT a row
    produced, and a failure produced none. That is exactly why the attempt's own fingerprint needs
    its own column: without it the next scan cannot tell an edited extractor from an unedited one
    and could never skip anything at all.

    MUTATION (must go RED): drop either column from the failure UPDATE, or stamp pass_version on
    failure and read that instead (the output column then lies about a row with no output)."""
    from treasure_map.lib.storage.connection import open_db

    rec = _rec()
    failed = GhidraResult(
        binary=rec.path,
        output_file=None,
        success=False,
        elapsed=1.0,
        reason="timeout",
        timeout_budget=846,
    )
    runner = _mock_runner([failed])

    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=[rec]):
            with patch(f"{MODULE}.ingest_elfs", _mock_ingest({rec.sha256})):
                with Workspace(tmp_path / "ws") as ws:
                    # ingest_elfs is mocked here, so the row it would have inserted is seeded.
                    seed = open_db(ws.db_path)
                    seed.execute(
                        "INSERT INTO binaries (name, path, sha256, last_seen_at) "
                        "VALUES (?, ?, ?, '2026-01-01')",
                        (rec.name, str(rec.path), rec.sha256),
                    )
                    seed.commit()
                    seed.close()
                    result = run_analyze(tmp_path / "fs", ws, _cfg())

    conn = open_db(result.db_path)
    row = conn.execute(
        "SELECT ghidra_status_reason, timeout_budget, timeout_pass_version, pass_version "
        "FROM binaries WHERE sha256 = ?",
        (rec.sha256,),
    ).fetchone()
    conn.close()
    assert row["ghidra_status_reason"] == "timeout"
    assert row["timeout_budget"] == 846
    assert row["timeout_pass_version"] == "testpass"
    assert row["pass_version"] is None  # the output column stays empty — there was no output


def test_the_report_names_what_was_skipped_and_follows_the_decision(
    tmp_path: Path,
) -> None:
    """★ A skip must be visible: the scan gets faster and covers less, and only saying so tells
    those two apart.

    Derived from the dirty set rather than re-computed, so the report cannot describe a rule the
    code no longer follows: a timed-out binary in this scan that nothing will be spent on IS the
    skip, by definition.

    MUTATION (must go RED): report every timeout row instead of only the ones left out of the dirty
    set — a binary being re-attempted right now would be listed as skipped."""
    from treasure_map.lib.storage.connection import open_db

    skipped = _rec("big_daemon", "facefeed")
    retried = _rec("httpd", "cafebabe")

    # Both timed out before; this scan re-runs only httpd (as a bigger budget or a pass edit would).
    def _seed(db_path: Path) -> None:
        conn = open_db(db_path)
        for rec in (skipped, retried):
            conn.execute(
                "INSERT INTO binaries (name, path, sha256, size_bytes, ghidra_ok, ghidra_status, "
                "ghidra_status_reason, timeout_budget, timeout_pass_version, last_seen_at) "
                "VALUES (?, ?, ?, ?, 0, 'failed', 'timeout', 846, 'testpass', '2026-01-01')",
                (rec.name, str(rec.path), rec.sha256, 14789215),
            )
        conn.commit()
        conn.close()

    runner = _mock_runner([_fail_ghidra(retried)])
    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=[skipped, retried]):
            with patch(f"{MODULE}.ingest_elfs", _mock_ingest({retried.sha256})):
                with Workspace(tmp_path / "ws") as ws:
                    _seed(ws.db_path)
                    result = run_analyze(tmp_path / "fs", ws, _cfg())

    assert [e["binary"] for e in result.timeout_skipped] == ["big_daemon"]
    assert result.timeout_skipped[0]["budget_seconds"] == 846
    assert result.timeout_skipped[0]["size_bytes"] == 14789215


def test_force_retry_reaches_the_dirty_check(tmp_path: Path) -> None:
    """The escape hatch is plumbed, not just accepted at the CLI and dropped on the way down."""
    rec = _rec()
    runner = _mock_runner([_ok_ghidra(rec)])
    ingest = _mock_ingest({rec.sha256})

    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=[rec]):
            with patch(f"{MODULE}.ingest_elfs", ingest):
                with Workspace(tmp_path / "ws") as ws:
                    run_analyze(tmp_path / "fs", ws, _cfg(), force_retry=True)

    assert ingest.call_args.kwargs["force_retry"] is True
    assert ingest.call_args.kwargs["timeout_base"] == _cfg().ghidra.headless_timeout_seconds


# ── stale-output wiring: only this run's successes are ingested, against this run's pass ───────


def test_only_this_runs_successes_are_ingested_against_its_pass(tmp_path: Path) -> None:
    """The ingest receives ONLY the binaries whose Ghidra run succeeded in this scan, plus the
    scan's pass_version to check every JSON against. A failed binary's leftover JSON never reaches
    the ingest, so its rows stay those of its last good extraction.

    MUTATION (must go RED): pass ``dirty_records`` instead of the successes, or drop the
    ``pass_version=`` argument from the ingest_ghidra_output call."""
    ok = _rec("httpd", "deadbeef")
    bad = _rec("dropbear", "cafebabe")
    runner = _mock_runner([_ok_ghidra(ok), _fail_ghidra(bad)])
    ingest = MagicMock(return_value=MagicMock(binaries_processed=1))
    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=[ok, bad]):
            with patch(f"{MODULE}.ingest_elfs", _mock_ingest({"deadbeef", "cafebabe"})):
                with patch(f"{MODULE}.ingest_ghidra_output", ingest):
                    with Workspace(tmp_path / "ws") as ws:
                        # dirty order follows scan order; make it deterministic
                        run_analyze(tmp_path / "fs", ws, _cfg())
    args, kwargs = ingest.call_args
    passed = args[2] if len(args) > 2 else kwargs["dirty_records"]
    assert [r.sha256 for r in passed] == ["deadbeef"]
    assert kwargs.get("pass_version") == "testpass"


# ── the success stamp and the function rows are one transaction, seen from the scan ────────────


def test_an_ingest_that_dies_leaves_no_success_stamp(tmp_path: Path) -> None:
    """Ghidra succeeds for the binary, then the ingest dies after writing its function rows and
    before committing them. Neither the rows nor the success stamp (ghidra_ok=1 + pass_version)
    may survive the scan: a stamp without its functions is read by the next scan as a finished
    extraction and skipped forever.

    The stamp is written in the same transaction as the function rows, inside the ingest; this pins
    that from the pipeline, the side the stamp used to be written and committed on.

    MUTATION (verified RED): in run_analyze's result loop, also write the success stamp
    (``UPDATE binaries SET ghidra_ok=1, ghidra_status=?, pass_version=?, ghidra_version=?``) and
    ``conn.commit()`` before ingest_ghidra_output runs -> the stamp survives the failed ingest and
    the ``pass_version is None`` assertion fails."""
    from treasure_map.lib.analyze import ghidra_ingest
    from treasure_map.lib.analyze.stub_resolve import STUB_MARKER_NONE
    from treasure_map.lib.storage.connection import open_db

    rec = _rec("httpd", "facefeed" * 8)
    runner = _mock_runner([_ok_ghidra(rec)])
    real_ingest = ghidra_ingest._ingest_one_binary
    rows_written: list[int] = []

    def dies_after_writing(conn: Any, binary_id: int, *args: Any) -> None:
        real_ingest(conn, binary_id, *args)
        rows_written.append(
            conn.execute(
                "SELECT COUNT(*) FROM functions WHERE binary_id = ?", (binary_id,)
            ).fetchone()[0]
        )
        raise RuntimeError("the ingest died before its commit")

    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=[rec]):
            with patch(f"{MODULE}.ingest_elfs", _mock_ingest({rec.sha256})):
                with Workspace(tmp_path / "ws") as ws:
                    # ingest_elfs is mocked, so the row it would have inserted is seeded (id 1).
                    seed = open_db(ws.db_path)
                    seed.execute(
                        "INSERT INTO binaries (id, name, path, sha256, last_seen_at) "
                        "VALUES (1, ?, ?, ?, '2026-01-01')",
                        (rec.name, str(rec.path), rec.sha256),
                    )
                    seed.commit()
                    seed.close()
                    # the extractor's output for this scan's pass, as Ghidra would leave it
                    out = ws.path / "ghidra_output"
                    out.mkdir(parents=True, exist_ok=True)
                    (out / f"{rec.name}_{rec.sha256[:8]}_ghidra.json").write_text(
                        json.dumps(
                            {
                                "pass_version": "testpass",
                                "sha8": rec.sha256[:8],
                                "stub_marker": STUB_MARKER_NONE,
                                "functions": [
                                    {"name": "main", "address": "0x1000", "pseudocode": "int m(){}"}
                                ],
                                "imports": [],
                                "exports": [],
                                "strings": [],
                            }
                        )
                    )
                    with patch.object(ghidra_ingest, "_ingest_one_binary", dies_after_writing):
                        with pytest.raises(RuntimeError, match="died before its commit"):
                            run_analyze(tmp_path / "fs", ws, _cfg())

                    conn = open_db(ws.db_path)
                    row = conn.execute(
                        "SELECT ghidra_ok, pass_version FROM binaries WHERE id = 1"
                    ).fetchone()
                    funcs = conn.execute("SELECT COUNT(*) FROM functions").fetchone()[0]
                    conn.close()

    assert rows_written == [1]  # the ingest really wrote the function row before it died
    assert funcs == 0  # ...and it went with the failed transaction
    assert row["pass_version"] is None  # the stamp went with it: not marked extracted
    assert row["ghidra_ok"] == 0


# ── the scan stamp (lib/rescan_version), written once the scan finishes ─────────────────

import sqlite3  # noqa: E402

from treasure_map.lib import rescan_version  # noqa: E402


def _stamp(db_path: Path) -> str | None:
    conn = sqlite3.connect(db_path)
    try:
        return rescan_version.read_scan_stamp(conn)
    finally:
        conn.close()


def test_scan_stamp_is_written_on_a_clean_finish(tmp_path: Path) -> None:
    """A finished scan records what built the analysis.db: the canonical scan stamp for its config.

    MUTATION: drop the INSERT into scan_stamp at the end of run_analyze -> RED (no stamp)."""
    with patch(f"{MODULE}.GhidraRunner", return_value=_mock_runner()):
        with patch(f"{MODULE}.scan_filesystem", return_value=[]):
            with Workspace(tmp_path / "ws") as ws:
                run_analyze(tmp_path / "fs", ws, _cfg())
                db = ws.db_path
    assert _stamp(db) == rescan_version.scan_stamp_for(_cfg())


def test_the_config_threshold_rides_in_the_scan_stamp(tmp_path: Path) -> None:
    """A content-marked config value (the xref fold threshold) lands in the stamp, so a run scanned
    under one is stale to an install configured with another."""
    cfg = Config(xref_fold_edge_threshold=12_345)
    with patch(f"{MODULE}.GhidraRunner", return_value=_mock_runner()):
        with patch(f"{MODULE}.scan_filesystem", return_value=[]):
            with Workspace(tmp_path / "ws") as ws:
                run_analyze(tmp_path / "fs", ws, cfg)
                db = ws.db_path
    assert json.loads(_stamp(db))["config"]["xref_fold_edge_threshold"] == 12_345


def test_a_scan_that_raises_leaves_no_stamp_and_clears_any_prior_one(tmp_path: Path) -> None:
    """The stamp is cleared up front and written only at the very end, so a crash mid-scan leaves
    NO stamp — never a stale one describing a half-built analysis.db.

    MUTATION: move the DELETE to after the INSERT, or the INSERT before the work -> RED."""
    # first scan writes a stamp
    with patch(f"{MODULE}.GhidraRunner", return_value=_mock_runner()):
        with patch(f"{MODULE}.scan_filesystem", return_value=[]):
            with Workspace(tmp_path / "ws") as ws:
                run_analyze(tmp_path / "fs", ws, _cfg())
                db = ws.db_path
    assert _stamp(db) is not None
    # a second scan that raises after the clear must leave the table empty
    with patch(f"{MODULE}.GhidraRunner", return_value=_mock_runner()):
        with patch(f"{MODULE}.scan_filesystem", return_value=[]):
            with patch(f"{MODULE}.run_all_ingesters", side_effect=RuntimeError("boom")):
                with Workspace(tmp_path / "ws") as ws:
                    with pytest.raises(RuntimeError):
                        run_analyze(tmp_path / "fs", ws, _cfg())
    assert _stamp(db) is None


def test_the_scan_stamp_is_grabbed_at_the_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stamp written at the end is the one taken at the START — so a source edit mid-scan does
    not change what this run is recorded as, and it is computed once.

    MUTATION: compute the stamp at the write site instead of the start -> this would record "B"."""
    stand_in = MagicMock(side_effect=["A", "B"])
    monkeypatch.setattr(rescan_version, "scan_stamp_for", stand_in)
    with patch(f"{MODULE}.GhidraRunner", return_value=_mock_runner()):
        with patch(f"{MODULE}.scan_filesystem", return_value=[]):
            with Workspace(tmp_path / "ws") as ws:
                run_analyze(tmp_path / "fs", ws, _cfg())
                db = ws.db_path
    assert _stamp(db) == "A"
    assert stand_in.call_count == 1
