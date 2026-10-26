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


# ── an interrupted scan keeps every binary it finished (S2), end to end ───────────────────────
#
# The real run_analyze, the real GhidraRunner.run_all (its pool, its two phases, its teardown),
# the real ingest; only the per-binary Ghidra run is a stand-in that writes the output the extractor
# would. The firmware is the fixture ELF, copied as six binaries of different content.

from treasure_map.lib.analyze import ghidra_ingest, ghidra_runner  # noqa: E402
from treasure_map.lib.analyze.ghidra_runner import GhidraRunner  # noqa: E402
from treasure_map.lib.analyze.stub_resolve import resolve_stubs, stub_table_marker  # noqa: E402
from treasure_map.lib.config.config import GhidraConfig, GhidraLocalConfig  # noqa: E402
from treasure_map.lib.storage.connection import open_db  # noqa: E402

_FIXTURE_ELF = Path(__file__).resolve().parents[2] / "fixtures" / "elfs" / "exe_x86_64"
_NAMES = [f"svc_{c}" for c in "abcdef"]


@pytest.fixture(autouse=True)
def _no_teardown_left_behind():  # type: ignore[no-untyped-def]
    """An interrupted run_all leaves the module's teardown flag set; the next test starts clean."""
    yield
    ghidra_runner._reset_shutdown()


def _firmware(root: Path) -> Path:
    fs = root / "fs"
    (fs / "bin").mkdir(parents=True)
    body = _FIXTURE_ELF.read_bytes()
    for i, name in enumerate(_NAMES):
        (fs / "bin" / name).write_bytes(body + b"\0" * (i + 1))  # same code, different content
    return fs


def _ghidra(root: Path, version: str = "11.0") -> Path:
    """A Ghidra install to be found (never run): the launcher and the version declaration."""
    home = root / "ghidra"
    (home / "support").mkdir(parents=True, exist_ok=True)
    (home / "support" / "analyzeHeadless").write_text("#!/bin/sh\nexit 1\n")
    (home / "Ghidra").mkdir(exist_ok=True)
    (home / "Ghidra" / "application.properties").write_text(f"application.version={version}\n")
    return home


def _e2e_cfg(home: Path) -> Config:
    return Config(ghidra=GhidraConfig(max_parallel_jvms=1, local=GhidraLocalConfig(home=home)))


class _Decompiler:
    """Stands in for one Ghidra run of one binary: writes the output the extractor would (this
    pass's markers, two functions, one string) and reports it. ``outcomes`` names a binary's
    other fate: ``no_functions``, ``stale`` (an output with another pass's marker, which the ingest
    skips), or a failure reason."""

    def __init__(self, outcomes: dict[str, str] | None = None) -> None:
        self.outcomes = dict(outcomes or {})
        self.calls: list[str] = []

    def __call__(
        self,
        runner: GhidraRunner,
        binary: Path,
        output_dir: Path,
        timeout: int,
        arch: str,
        sha8: str = "",
        retry: bool = True,
    ) -> GhidraResult:
        self.calls.append(binary.name)
        outcome = self.outcomes.get(binary.name, "ok")
        if outcome not in ("ok", "no_functions", "stale"):
            budget = 1800 if outcome == "timeout" else 60
            return GhidraResult(
                binary=binary,
                output_file=None,
                success=False,
                elapsed=0.0,
                reason=outcome,
                timeout_budget=budget,
            )
        stubs = resolve_stubs(binary)
        n = 0 if outcome == "no_functions" else 2
        funcs = [
            {
                "name": f"{binary.name}_f{j}",
                "address": f"0010{j}000",
                "size": 64,
                "callees": ["system", f"helper_{j}"],
                "pseudocode": f'void {binary.name}_f{j}(void) {{ system("{j}"); }}',
            }
            for j in range(n)
        ]
        data = {
            "pass_version": "another-pass" if outcome == "stale" else runner.pass_version(),
            "sha8": sha8,
            "stub_marker": stub_table_marker(None if stubs is None else stubs.names),
            "functions": funcs,
            "imports": [],
            "exports": [],
            "strings": [{"value": f"{binary.name} banner", "address": "00200000"}],
        }
        out = output_dir / f"{binary.name}_{sha8}_ghidra.json"
        out.write_text(json.dumps(data))
        return GhidraResult(
            binary=binary,
            output_file=out,
            success=True,
            elapsed=0.0,
            analysis_status="no_functions" if outcome == "no_functions" else "ok",
            function_count=n,
        )


def _interrupt_at(k: int):  # type: ignore[no-untyped-def]
    """A progress callback that raises Ctrl-C at the k-th phase-1 Ghidra event."""
    seen = {"n": 0}

    def cb(step: str, meta: dict[str, Any]) -> None:
        if step == "ghidra":
            seen["n"] += 1
            if seen["n"] == k:
                raise KeyboardInterrupt

    return cb


def _scan_e2e(
    fs: Path,
    ws_dir: Path,
    cfg: Config,
    dec: _Decompiler,
    *,
    progress: Any = None,
    reanalyze: str | None = None,
    pass_version: str | None = None,
) -> AnalyzeResult:
    import contextlib

    with contextlib.ExitStack() as stack:
        stack.enter_context(
            patch.object(GhidraRunner, "run_ghidra", lambda self, *a, **k: dec(self, *a, **k))
        )
        if pass_version is not None:
            stack.enter_context(
                patch.object(GhidraRunner, "pass_version", lambda self: pass_version)
            )
        ws = stack.enter_context(Workspace(ws_dir))
        return run_analyze(fs, ws, cfg, progress, reanalyze=reanalyze)


def _state(db: Path) -> dict[str, dict[str, Any]]:
    """Per binary name: its stamp, its mark, and its function rows as (address, hash, callees)."""
    conn = open_db(db)
    try:
        out: dict[str, dict[str, Any]] = {}
        for b in conn.execute("SELECT * FROM binaries"):
            out[b["name"]] = {
                "sha256": b["sha256"],
                "ghidra_ok": b["ghidra_ok"],
                "ghidra_status": b["ghidra_status"],
                "reason": b["ghidra_status_reason"],
                "pass_version": b["pass_version"],
                "timeout_pass_version": b["timeout_pass_version"],
                "pending": b["reanalyze_pending"],
                "functions": sorted(
                    (f["address"], f["pseudocode_hash"], f["callees"])
                    for f in conn.execute(
                        "SELECT address, pseudocode_hash, callees FROM functions "
                        "WHERE binary_id = ?",
                        (b["id"],),
                    )
                ),
                "strings": conn.execute(
                    "SELECT COUNT(*) FROM strings WHERE binary_id = ?", (b["id"],)
                ).fetchone()[0],
            }
        return out
    finally:
        conn.close()


def _scan_stamp_rows(db: Path) -> int:
    conn = open_db(db)
    try:
        return int(conn.execute("SELECT COUNT(*) FROM scan_stamp").fetchone()[0])
    finally:
        conn.close()


def test_an_interrupted_scan_keeps_what_finished_and_the_rerun_does_only_the_rest(
    tmp_path: Path,
) -> None:
    """T-S4. Six binaries, one JVM, Ctrl-C at the third progress event. The three handed over are
    stored for good — stamped with this pass, functions in — the other three carry no stamp at all,
    and the scan stamp stays cleared. The same command again decompiles exactly those three, and
    ends with the same functions an uninterrupted scan stores.

    MUTATION (verified RED): run_all without ``on_final`` (store only after the batch) -> nothing
    survives the interrupt and the rerun is dirty for all six."""
    fs = _firmware(tmp_path)
    cfg = _e2e_cfg(_ghidra(tmp_path))
    pv = ghidra_runner.current_pass_version()

    first = _Decompiler()
    with pytest.raises(KeyboardInterrupt):
        _scan_e2e(fs, tmp_path / "ws", cfg, first, progress=_interrupt_at(3))
    db = tmp_path / "ws" / "analysis.db"
    st = _state(db)
    done = first.calls[:3]
    for name in _NAMES:
        if name in done:
            assert (st[name]["ghidra_ok"], st[name]["pass_version"]) == (1, pv)
            assert st[name]["functions"], name
        else:
            assert (st[name]["ghidra_ok"], st[name]["ghidra_status"]) == (0, None), name
            assert (st[name]["pass_version"], st[name]["timeout_pass_version"]) == (None, None)
            assert not st[name]["functions"], name
    assert _scan_stamp_rows(db) == 0

    second = _Decompiler()
    result = _scan_e2e(fs, tmp_path / "ws", cfg, second)
    assert result.dirty_count == 3
    assert sorted(second.calls) == sorted(set(_NAMES) - set(done))

    whole = _Decompiler()
    _scan_e2e(fs, tmp_path / "ws_whole", cfg, whole)
    resumed, straight = _state(db), _state(tmp_path / "ws_whole" / "analysis.db")
    assert {v["sha256"]: v["functions"] for v in resumed.values()} == {
        v["sha256"]: v["functions"] for v in straight.values()
    }


def test_a_store_that_dies_mid_scan_keeps_the_ones_before_it(tmp_path: Path) -> None:
    """T-S5. Three successes; the second one's ingest dies after writing its rows. The first is
    committed (rows and stamp), the second has neither, the error propagates, and the third —
    whose result arrived only after — was never stored.

    MUTATION (verified RED): commit each result only after the batch -> the first is lost too."""
    fs = _firmware(tmp_path)
    cfg = _e2e_cfg(_ghidra(tmp_path))
    real_ingest = ghidra_ingest._ingest_one_binary
    seen = {"n": 0}

    def dies_on_the_second(conn: Any, binary_id: int, *args: Any) -> None:
        real_ingest(conn, binary_id, *args)
        seen["n"] += 1
        if seen["n"] == 2:
            raise RuntimeError("the second store died before its commit")

    dec = _Decompiler()
    with patch.object(ghidra_ingest, "_ingest_one_binary", dies_on_the_second):
        with pytest.raises(RuntimeError, match="second store died"):
            _scan_e2e(fs, tmp_path / "ws", cfg, dec)
    st = _state(tmp_path / "ws" / "analysis.db")
    first, second, third = dec.calls[:3]
    assert st[first]["ghidra_ok"] == 1 and st[first]["functions"]
    assert st[second]["ghidra_ok"] == 0 and st[second]["pass_version"] is None
    assert not st[second]["functions"]
    assert st[third]["ghidra_ok"] == 0 and not st[third]["functions"]


def test_results_not_handed_over_are_stored_once_after_the_batch(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """T-S6. A runner that hands over only some results: the rest are stored after it returns, and
    no binary is ingested twice. A binary whose output the ingest skips is not counted as kept.

    MUTATION (verified RED): store every returned result again after the batch -> ingested twice.
    MUTATION (verified RED): count a skipped ingest as kept -> "3 of 3"."""
    a, b, c = _rec("svc_a", "aa" * 32), _rec("svc_b", "bb" * 32), _rec("svc_c", "cc" * 32)
    results = [_ok_ghidra(a), _ok_ghidra(b), _ok_ghidra(c)]
    runner = _mock_runner(results)

    def run_all(records: list[ElfRecord], out: Path, cb: Any, *, on_final: Any) -> list[Any]:
        on_final(records[0], results[0])
        return results

    runner.run_all.side_effect = run_all
    ingested: list[str] = []

    def fake_ingest(conn: Any, out: Path, recs: list[ElfRecord], *a: Any, **k: Any) -> Any:
        from treasure_map.lib.analyze.ghidra_ingest import IngestStats

        ingested.extend(r.sha256 for r in recs)
        return IngestStats(binaries_processed=0 if recs[0].name == "svc_c" else 1)

    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=[a, b, c]):
            with patch(f"{MODULE}.ingest_elfs", _mock_ingest({a.sha256, b.sha256, c.sha256})):
                with patch(f"{MODULE}.ingest_ghidra_output", fake_ingest):
                    with Workspace(tmp_path / "ws") as ws, caplog.at_level("INFO"):
                        run_analyze(tmp_path / "fs", ws, _cfg())
    assert sorted(ingested) == sorted([a.sha256, b.sha256, c.sha256])
    assert any("2 of 3 dirty binaries stored" in r.getMessage() for r in caplog.records)


def test_an_interrupted_result_handed_over_is_not_stored(tmp_path: Path) -> None:
    """T-I1 (the store). A result the teardown cut off is neither stamped nor counted: the binary
    is simply run again next time.

    MUTATION (verified RED): drop the ``interrupted`` early return -> a failure stamp is written."""
    rec = _rec("svc_a", "aa" * 32)
    cut = GhidraResult(
        binary=rec.path, output_file=None, success=False, elapsed=0.0, reason="interrupted"
    )
    runner = _mock_runner([cut])

    def run_all(records: list[ElfRecord], out: Path, cb: Any, *, on_final: Any) -> list[Any]:
        on_final(records[0], cut)
        return [cut]

    runner.run_all.side_effect = run_all
    with patch(f"{MODULE}.GhidraRunner", return_value=runner):
        with patch(f"{MODULE}.scan_filesystem", return_value=[rec]):
            with patch(f"{MODULE}.ingest_elfs", _mock_ingest({rec.sha256})):
                with Workspace(tmp_path / "ws") as ws:
                    seed = open_db(ws.db_path)
                    seed.execute(
                        "INSERT INTO binaries (name, path, sha256, last_seen_at) "
                        "VALUES (?, ?, ?, '2026-01-01')",
                        (rec.name, str(rec.path), rec.sha256),
                    )
                    seed.commit()
                    seed.close()
                    result = run_analyze(tmp_path / "fs", ws, _cfg())
    assert (result.ghidra_ok, result.ghidra_failed) == (0, 0)
    row = _state(tmp_path / "ws" / "analysis.db")["svc_a"]
    assert (row["ghidra_status"], row["reason"], row["timeout_pass_version"]) == (None, None, None)


def test_a_binary_this_pass_failed_on_is_named_as_keeping_its_earlier_extraction(
    tmp_path: Path,
) -> None:
    """T-M6. Extracted by an earlier pass, failed by this one: it keeps the earlier rows and the
    scan names it, with why and which pass those rows are from.

    MUTATION (verified RED): leave kept_earlier_binaries empty."""
    fs = _firmware(tmp_path)
    cfg = _e2e_cfg(_ghidra(tmp_path))
    _scan_e2e(fs, tmp_path / "ws", cfg, _Decompiler(), pass_version="earlier-pass")
    result = _scan_e2e(fs, tmp_path / "ws", cfg, _Decompiler({"svc_b": "incomplete"}))
    assert result.kept_earlier_binaries == [
        {"binary": "svc_b", "reason": "incomplete", "earlier_pass": "earlier-pass"}
    ]


def test_a_finished_extraction_with_no_function_is_recorded_and_not_rerun(tmp_path: Path) -> None:
    """T-N2. svc_b failed under this pass and still held an earlier pass's rows; now its
    extraction finishes with no function. It is stored through the success path — ghidra_ok=1,
    no_functions, this pass, its old rows replaced — so the run's build hash is one value again; it
    is still named incomplete, and named no_functions; the next scan of the same pass leaves it.

    MUTATION (verified RED): drop the self-heal's no_functions exemption -> the next scan re-runs
    it.
    MUTATION (verified RED): leave no_functions_binaries empty."""
    from treasure_map.lib.facts import analysis_run_counts

    fs = _firmware(tmp_path)
    cfg = _e2e_cfg(_ghidra(tmp_path))
    pv = ghidra_runner.current_pass_version()
    _scan_e2e(fs, tmp_path / "ws", cfg, _Decompiler(), pass_version="earlier-pass")
    _scan_e2e(fs, tmp_path / "ws", cfg, _Decompiler({"svc_b": "incomplete"}))
    db = tmp_path / "ws" / "analysis.db"
    assert _state(db)["svc_b"]["functions"]  # the earlier pass's rows, kept

    result = _scan_e2e(fs, tmp_path / "ws", cfg, _Decompiler({"svc_b": "no_functions"}))
    row = _state(db)["svc_b"]
    assert (row["ghidra_ok"], row["ghidra_status"], row["pass_version"]) == (1, "no_functions", pv)
    assert row["functions"] == [] and row["strings"] == 1  # this pass's rows, not the earlier ones
    conn = open_db(db)
    try:
        assert analysis_run_counts(conn)["build_hash"] == pv
    finally:
        conn.close()
    assert "svc_b" in result.incomplete_binaries
    assert result.no_functions_binaries == ["svc_b"]
    assert result.ghidra_no_functions == 1

    again = _Decompiler()
    assert _scan_e2e(fs, tmp_path / "ws", cfg, again).dirty_count == 0
    assert again.calls == []


def test_an_interrupted_full_reanalyze_is_continued_not_restarted(tmp_path: Path) -> None:
    """T-R1 / T-R2 / T-R3. A bare --reanalyze marks all six and is cut off after two: two marks
    cleared, four left. A plain scan in between re-extracts nothing, leaves the marks, and reports
    them. The next bare --reanalyze decompiles exactly the four, and clears them.

    MUTATION (verified RED): ignore the marks (always a new request) -> the continuation redoes six.
    MUTATION (verified RED): leave the mark set on a stored success -> the continuation redoes six.
    """
    fs = _firmware(tmp_path)
    cfg = _e2e_cfg(_ghidra(tmp_path))
    db = tmp_path / "ws" / "analysis.db"
    _scan_e2e(fs, tmp_path / "ws", cfg, _Decompiler())

    cut = _Decompiler()
    with pytest.raises(KeyboardInterrupt):
        _scan_e2e(fs, tmp_path / "ws", cfg, cut, progress=_interrupt_at(2), reanalyze="__all__")
    redone = set(cut.calls[:2])
    assert {n: v["pending"] for n, v in _state(db).items()} == {
        n: 0 if n in redone else 1 for n in _NAMES
    }

    plain = _Decompiler()
    mid = _scan_e2e(fs, tmp_path / "ws", cfg, plain)
    assert (mid.dirty_count, plain.calls, mid.reanalyze_pending) == (0, [], 4)

    cont = _Decompiler()
    res = _scan_e2e(fs, tmp_path / "ws", cfg, cont, reanalyze="__all__")
    assert res.dirty_count == 4
    assert sorted(cont.calls) == sorted(set(_NAMES) - redone)
    assert res.reanalyze_pending == 0
    assert all(v["pending"] == 0 for v in _state(db).values())


def test_a_final_failure_clears_its_mark_and_a_skipped_store_keeps_it(tmp_path: Path) -> None:
    """T-R5. Under a bare --reanalyze: svc_c fails for good -> its mark is cleared (the request
    was answered); svc_d's output is one the ingest skips -> nothing was stored, so its mark stays.

    MUTATION (verified RED): drop ``reanalyze_pending=0`` from the failure stamp.
    MUTATION (verified RED): clear the mark whether or not the ingest stored anything."""
    fs = _firmware(tmp_path)
    cfg = _e2e_cfg(_ghidra(tmp_path))
    _scan_e2e(fs, tmp_path / "ws", cfg, _Decompiler())
    res = _scan_e2e(
        fs,
        tmp_path / "ws",
        cfg,
        _Decompiler({"svc_c": "import_failed", "svc_d": "stale"}),
        reanalyze="__all__",
    )
    st = _state(tmp_path / "ws" / "analysis.db")
    assert st["svc_c"]["pending"] == 0 and st["svc_c"]["reason"] == "import_failed"
    assert st["svc_d"]["pending"] == 1
    assert res.reanalyze_pending == 1
