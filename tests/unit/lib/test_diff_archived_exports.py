# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A diff reads the exports its two sides' scans archived (Spec 2): it decompresses them and runs
only BinDiff, refuses a side with no usable export as a declared blind spot that a re-scan — not a
retry — fixes, and carries an operand written in its default form as an additional fact that
changes nothing it determines.

Zero real data: the worlds of test_diff_export_gaps / test_diff_currency (synthetic analysis.db,
hand-made .BinDiff), with real gzip archives where the archive itself is under test.
"""

from __future__ import annotations

import gzip
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.binexport_seed import stored_export
from tests.unit.lib.test_diff_currency import _did, _full, _plan, _two
from tests.unit.lib.test_diff_currency import _stub as _currency_stub
from tests.unit.lib.test_diff_export_gaps import (
    _DID,
    _alignment,
    _diff,
    _edges,
    _presence,
    _report,
    _stub,
    _world,
)
from treasure_map.lib.binexport_archive import StoredExport, archive_names
from treasure_map.lib.config.config import Config
from treasure_map.lib.diff import driver
from treasure_map.lib.diff.export_report import ExportReportError, parse_export_report
from treasure_map.lib.query import diff_align
from treasure_map.lib.query import patch_view as pv

# ── compute: two archives decompressed, BinDiff, nothing else ─────────────────────────────────


def _real_archive(dest: Path, sha: str, payload: bytes) -> StoredExport:
    dest.mkdir(parents=True, exist_ok=True)
    exp, rep = archive_names(sha, "pv")
    (dest / exp).write_bytes(gzip.compress(payload))
    (dest / rep).write_bytes(gzip.compress(json.dumps(_report()).encode()))
    return StoredExport("ok", {"archive": exp, "report_archive": rep}, dest)


def test_compute_decompresses_the_two_archives_and_runs_only_bindiff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The compute step hands BinDiff the two archived exports, decompressed, and reads their
    reports; it never starts an export of its own.

    MUTATION (verified RED): export the binary again instead of reading the archive -> RED."""
    a = _real_archive(tmp_path / "a", "a" * 64, b"export A")
    b = _real_archive(tmp_path / "b", "b" * 64, b"export B")
    seen: dict[str, bytes] = {}

    def no_export(*_a: Any, **_k: Any) -> Path:
        raise AssertionError("a diff must not export a binary itself")

    def bindiff(ea: Path, eb: Path, out: Path, timeout: int) -> Path:
        seen["a"], seen["b"] = ea.read_bytes(), eb.read_bytes()
        return out / "x.BinDiff"

    monkeypatch.setattr(driver, "_run_binexport", no_export)
    monkeypatch.setattr(driver, "_run_bindiff", bindiff)
    td = tmp_path / "td"
    td.mkdir()
    art = driver.compute_diff(a, b, td, Config())
    assert seen == {"a": b"export A", "b": b"export B"}
    assert art.report_a is not None and art.report_a.builder == "fallback"


def test_an_archive_that_does_not_decompress_fails_the_diff_by_its_own_reason(
    tmp_path: Path,
) -> None:
    a = _real_archive(tmp_path / "a", "a" * 64, b"export A")
    b = _real_archive(tmp_path / "b", "b" * 64, b"export B")
    exp = tmp_path / "b" / b.meta["archive"]  # type: ignore[index]
    exp.write_bytes(exp.read_bytes()[:10])
    td = tmp_path / "td"
    td.mkdir()
    with pytest.raises(driver.DiffToolchainError) as e:
        driver.compute_diff(a, b, td, Config())
    assert e.value.kind == driver.FAIL_BINEXPORT_ARCHIVE


# ── a side with no usable export: a blind spot a re-scan fixes ────────────────────────────────


def test_a_side_with_no_usable_export_is_a_blind_spot_outside_the_retry_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A full diff records the binary as binexport_missing:<status> — listed with the other blind
    spots — with no attempt counted: a re-scan fixes it, so every full diff tries it again (cheap:
    no toolchain runs) and it never becomes a suspected hard boundary.

    MUTATION (verified RED): count it like a toolchain failure -> it reaches the cap and is
    skipped -> RED."""
    w = _two(tmp_path)
    _currency_stub(monkeypatch, w)
    db = w.tmp / "b.db"
    conn = sqlite3.connect(db)
    conn.execute("UPDATE binaries SET binexport_status = 'failed:IllegalStateException: x'")
    conn.commit()
    conn.close()
    for _ in range(driver._DIFF_RETRY_LIMIT + 1):
        fs = _full(w)
        (oc,) = fs.outcomes
        assert (oc.reason, oc.attempts) == (
            "binexport_missing:failed:IllegalStateException: x",
            0,
        )
    assert _plan(w).hard_failed == ()
    spots = diff_align.list_diff_blindspots(w.atlas, "run_a", "run_b")["blindspots"]
    assert [s["diff_status_reason"] for s in spots] == [
        "binexport_missing:failed:IllegalStateException: x"
    ]


# ── the report: operand_markup_degraded read strictly ─────────────────────────────────────────


def _markup(n: int, addrs: list[int], functions: list[int]) -> str:
    rep = _report()
    rep["operand_markup_degraded"] = {
        "instructions": n,
        "instruction_addresses": addrs,
        "functions": functions,
    }
    return json.dumps(rep)


def test_the_markup_block_is_read_strictly() -> None:
    """Absent (a report from before it) is empty; present, the instruction count must match the
    list and a listed instruction must come with its function.

    MUTATION (verified RED): accept a count that disagrees with the list -> RED."""
    assert parse_export_report(json.dumps(_report())).operand_markup_degraded == frozenset()
    r = parse_export_report(_markup(2, [0x1004, 0x1008], [0x1000]))
    assert r.operand_markup_degraded == {"00001000"}
    with pytest.raises(ExportReportError, match="counts 3 instructions"):
        parse_export_report(_markup(3, [0x1004, 0x1008], [0x1000]))
    with pytest.raises(ExportReportError, match="no function"):
        parse_export_report(_markup(1, [0x1004], []))
    with pytest.raises(ExportReportError):
        bad = _report()
        bad["operand_markup_degraded"] = [1]
        parse_export_report(json.dumps(bad))


def test_a_degraded_operand_is_an_additional_fact_that_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ N-5: caller (side a) had an operand written in its default form. Its pair is marked
    operand_markup_incomplete_a and stays aligned with no export gap; the edge resting on it stays
    determined; the unmatched function gone (marked too) keeps its determined absence. The read
    surfaces say it: get_function_alignment always, a patch-view entry only when it is set.

    MUTATION (verified RED): route it through export_gap -> the pair reads undetermined -> RED;
    leave it off the row -> RED."""
    rep = json.loads(_markup(1, [0x1004], [0x1000, 0x3000]))
    w = _world(tmp_path, reports={"a": rep})
    _stub(monkeypatch, w)
    _diff(w)
    assert _alignment(w)["00001000"] == ("aligned", None, None)
    flags = dict(
        w.atlas.execute(
            "SELECT addr_a, operand_markup_incomplete_a FROM function_alignment WHERE diff_id = ?",
            (_DID,),
        ).fetchall()
    )
    assert flags == {"00001000": 1, "00002000": 0}
    assert _presence(w)[("a", "00003000")] == ("unmatched_analysis_complete", None)
    gone = w.atlas.execute(
        "SELECT operand_markup_incomplete FROM function_presence WHERE addr = '00003000'"
    ).fetchone()[0]
    assert gone == 1
    assert [k for _s, k, _r in _edges(w)] == ["layer_unchanged"]  # determined, no gap reason
    found = diff_align.align_by_a(w.atlas, _DID, "0x1000")
    assert found["pairs"][0]["operand_markup_incomplete_a"] == 1
    view = pv.get_diff_patch_view(w.atlas, _DID, limit=50)
    marked = [e for e in view["entries"] if e.get("operand_markup_incomplete")]
    assert all(e["operand_markup_incomplete"] in (["a"], ["b"], ["a", "b"]) for e in marked)


def test_the_diff_toolchain_is_read_from_the_two_archives(tmp_path: Path) -> None:
    """The Ghidra and BinExport behind a diff are its exports' (a diff runs neither); unknown on a
    side, or no BinDiff here, is "not checked"."""
    a = stored_export(tmp_path, "x", "a")
    b = stored_export(tmp_path, "x", "b")
    tc = driver.diff_toolchain(a, b, "BinDiff 8")
    assert tc is not None and (tc.ghidra, tc.bindiff) == ("11.4.3", "BinDiff 8")
    assert driver.diff_toolchain(a, b, None) is None
    b.meta["binexport"] = "11.4.3+lib:ffffffffffff"  # type: ignore[index]
    tc2 = driver.diff_toolchain(a, b, "BinDiff 8")
    assert tc2 is not None and "|" in tc2.binexport
    assert _did() == "run_a::run_b::liba"


def test_the_refusal_names_the_fix_that_works_for_its_status() -> None:
    """A side with no usable export is told what makes one: a rescan where a rescan re-makes it,
    more time for a timeout, the extension for extension_missing, and — for an export that failed
    the same way it would again — that a rescan does not, with the command that does.

    MUTATION (verified RED): answer "tmap rescan" for every status -> RED."""
    r = driver._export_remedy
    assert "tmap rescan r" in r("not_recorded", "r", "b")
    assert "tmap rescan r" in r("archive_missing", "r", "b")
    assert "tmap init" in r("extension_missing", "r", "b")
    assert "headless_timeout_seconds" in r("failed:timeout", "r", "b")
    det = r("failed:IllegalStateException: x", "r", "b")
    assert "--reanalyze b" in det and "tmap rescan" not in det
