# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for lib/analyze/pipeline.py.

Ghidra is fully mocked — these tests never touch analyzeHeadless.
They verify fail-fast behaviour, dirty-set routing, and result fields.
"""

from __future__ import annotations

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
        protections={"nx": True, "pie": False, "canary": False, "relro": "none", "fortify": False},
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


async def test_fail_fast_before_any_disk_work(tmp_path: Path) -> None:
    """GhidraNotFoundError is raised before scan_filesystem is called."""
    runner = MagicMock()
    runner.get_headless.side_effect = GhidraNotFoundError("Ghidra not found")

    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem") as mock_scan:
            with Workspace(tmp_path / "ws") as ws:
                with pytest.raises(GhidraNotFoundError):
                    await run_analyze(tmp_path / "fs", ws, _cfg())

            mock_scan.assert_not_called()


# ── dirty set routing ─────────────────────────────────────────────────────────


async def test_dirty_set_empty_skips_ghidra(tmp_path: Path) -> None:
    """When ingest_elfs reports 0 dirty shas, runner.run_all is not called."""
    rec = _rec()
    runner = _mock_runner()

    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=[rec]):
            with patch(f"{MODULE}.ingest_elfs", _mock_ingest(set())):
                with Workspace(tmp_path / "ws") as ws:
                    result = await run_analyze(tmp_path / "fs", ws, _cfg())

    runner.run_all.assert_not_called()
    assert result.binary_count == 1
    assert result.dirty_count == 0
    assert result.ghidra_skipped == 1
    assert result.ghidra_ok == 0


async def test_dirty_set_partial_only_runs_dirty(tmp_path: Path) -> None:
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
                    result = await run_analyze(tmp_path / "fs", ws, _cfg())

    assert len(captured) == 1
    assert len(captured[0]) == 1
    assert captured[0][0].sha256 == "cafebabe"
    assert result.binary_count == 2
    assert result.dirty_count == 1
    assert result.ghidra_skipped == 1


# ── empty filesystem ──────────────────────────────────────────────────────────


async def test_empty_fs_ghidra_skipped(tmp_path: Path) -> None:
    """Zero ELFs found → Ghidra step is not called."""
    runner = _mock_runner()
    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=[]):
            with Workspace(tmp_path / "ws") as ws:
                result = await run_analyze(tmp_path / "fs", ws, _cfg())

    runner.run_all.assert_not_called()
    assert result.binary_count == 0
    assert result.dirty_count == 0
    assert result.ghidra_skipped == 0


# ── AnalyzeResult fields ──────────────────────────────────────────────────────


async def test_analyze_result_fields(tmp_path: Path) -> None:
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
                    result = await run_analyze(tmp_path / "fs", ws, _cfg())

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


async def test_progress_callback_passed_to_run_all(tmp_path: Path) -> None:
    """run_analyze forwards progress_callback to GhidraRunner.run_all."""
    rec = _rec()
    runner = _mock_runner([_ok_ghidra(rec)])

    def cb(s: str, m: dict[str, Any]) -> None:
        pass

    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=[rec]):
            with patch(f"{MODULE}.ingest_elfs", _mock_ingest({rec.sha256})):
                with Workspace(tmp_path / "ws") as ws:
                    await run_analyze(tmp_path / "fs", ws, _cfg(), progress_callback=cb)

    _args, kwargs = runner.run_all.call_args
    assert kwargs.get("progress_callback") is cb or cb in _args


# ── what a failed attempt ran under, and what the report says about a skip ────────────


async def test_a_failed_attempt_records_its_budget_and_its_extractor(tmp_path: Path) -> None:
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
                    result = await run_analyze(tmp_path / "fs", ws, _cfg())

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


async def test_the_report_names_what_was_skipped_and_follows_the_decision(
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
                    result = await run_analyze(tmp_path / "fs", ws, _cfg())

    assert [e["binary"] for e in result.timeout_skipped] == ["big_daemon"]
    assert result.timeout_skipped[0]["budget_seconds"] == 846
    assert result.timeout_skipped[0]["size_bytes"] == 14789215


async def test_force_retry_reaches_the_dirty_check(tmp_path: Path) -> None:
    """The escape hatch is plumbed, not just accepted at the CLI and dropped on the way down."""
    rec = _rec()
    runner = _mock_runner([_ok_ghidra(rec)])
    ingest = _mock_ingest({rec.sha256})

    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=[rec]):
            with patch(f"{MODULE}.ingest_elfs", ingest):
                with Workspace(tmp_path / "ws") as ws:
                    await run_analyze(tmp_path / "fs", ws, _cfg(), force_retry=True)

    assert ingest.call_args.kwargs["force_retry"] is True
    assert ingest.call_args.kwargs["timeout_base"] == _cfg().ghidra.headless_timeout_seconds


# ── stale-output wiring: only this run's successes are ingested, against this run's pass ───────


async def test_only_this_runs_successes_are_ingested_against_its_pass(tmp_path: Path) -> None:
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
                        await run_analyze(tmp_path / "fs", ws, _cfg())
    args, kwargs = ingest.call_args
    passed = args[2] if len(args) > 2 else kwargs["dirty_records"]
    assert [r.sha256 for r in passed] == ["deadbeef"]
    assert kwargs.get("pass_version") == "testpass"
