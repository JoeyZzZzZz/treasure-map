# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""One Ghidra session per binary across the runs of a rescan (lib/analyze/extraction_share).

A binary several firmware versions hold byte for byte is decompiled once; every run that needs it
stores that one session's output — the same functions, the same export, under the same session
name. A binary needing another session under any part of the key runs its own; a session cut off
by the teardown is not handed on.
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import patch

from tests.unit.lib.test_pipeline import _NAMES, _e2e_cfg, _firmware, _ghidra, _state
from tests.unit.lib.test_scan_export import _exports, _Sessions, _with_extension
from treasure_map.lib.analyze import ghidra_runner
from treasure_map.lib.analyze.extraction_share import ExtractionShare
from treasure_map.lib.analyze.ghidra_runner import GhidraResult, GhidraRunner
from treasure_map.lib.analyze.pipeline import run_analyze, sharing_extractions
from treasure_map.lib.config.config import GhidraConfig
from treasure_map.lib.workspace import Workspace


class _Counted:
    """The sessions of a fake decompiler (test_scan_export._Sessions), each with a session id."""

    def __init__(self, sessions: _Sessions) -> None:
        self.sessions = sessions
        self.n = 0

    def __call__(self, runner: Any, *a: Any, **k: Any) -> GhidraResult:
        self.n += 1
        return dataclasses.replace(self.sessions(runner, *a, **k), session=uuid.uuid4().hex[:12])


def _scan_two(tmp_path: Path, *, share: bool) -> tuple[_Counted, list[Path]]:
    fs = _firmware(tmp_path)
    home = _ghidra(tmp_path)
    _with_extension(home)
    dec = _Counted(_Sessions({n: ["ok"] * 4 for n in _NAMES}))
    dbs = [tmp_path / f"ws{i}" / "analysis.db" for i in (1, 2)]
    with patch.object(GhidraRunner, "_run_session", lambda self, *a, **k: dec(self, *a, **k)):
        ctx = sharing_extractions() if share else None
        if ctx is not None:
            ctx.__enter__()
        try:
            for db in dbs:
                with Workspace(db.parent) as ws:
                    run_analyze(fs, ws, _e2e_cfg(home))
        finally:
            if ctx is not None:
                ctx.__exit__(None, None, None)
    return dec, dbs


def test_a_rescan_decompiles_a_shared_binary_once_and_every_holder_stores_the_same(
    tmp_path: Path,
) -> None:
    """★ Two runs holding the same six binaries, scanned within one sharing block: six sessions,
    not twelve. Both store the same functions, and archive the same export under the same session
    name; the JSON each run stored is byte-identical. Without sharing, each run decompiles all six.

    MUTATION (verified RED): never hand a kept session on -> twelve sessions -> RED; archive under a
    fresh name per write -> the names differ -> RED."""
    dec, (db1, db2) = _scan_two(tmp_path / "shared", share=True)
    assert dec.n == len(_NAMES)
    s1, s2 = _state(db1), _state(db2)
    assert {n: v["functions"] for n, v in s1.items()} == {n: v["functions"] for n, v in s2.items()}
    e1, e2 = _exports(db1), _exports(db2)
    assert {n: m["archive"] for n, (_s, m) in e1.items() if m} == {
        n: m["archive"] for n, (_s, m) in e2.items() if m
    }
    for name in _NAMES:
        j1 = list((db1.parent / "ghidra_output").glob(f"{name}_*_ghidra.json"))
        j2 = list((db2.parent / "ghidra_output").glob(f"{name}_*_ghidra.json"))
        assert len(j1) == len(j2) == 1 and j1[0].read_bytes() == j2[0].read_bytes()

    alone, _dbs = _scan_two(tmp_path / "alone", share=False)
    assert alone.n == 2 * len(_NAMES)


def _runner(tmp_path: Path, share: ExtractionShare) -> GhidraRunner:
    runner = GhidraRunner(GhidraConfig(), headless=tmp_path / "analyzeHeadless")
    runner.set_share(share)
    return runner


def test_another_key_runs_its_own_session_and_a_cut_off_one_is_not_handed_on(
    tmp_path: Path,
) -> None:
    """★ The same binary under another budget (or output limit) is another session; one the
    teardown cut off is not kept, so the next holder runs its own.

    MUTATION (verified RED): key on the binary alone -> the larger budget is handed the smaller
    one's outcome -> RED; keep an interrupted session -> RED."""
    binary = tmp_path / "svc"
    binary.write_bytes(b"\x7fELF" + b"\0" * 100)
    calls: list[tuple[int, bool]] = []
    reasons: list[str | None] = [None, None, ghidra_runner._INTERRUPTED, None]

    def session(
        self: Any,
        b: Path,
        out: Path,
        timeout: int,
        arch: str,
        sha8: str = "",
        retry: bool = True,
        large_payload: bool = False,
    ) -> GhidraResult:
        calls.append((timeout, large_payload))
        reason = reasons[len(calls) - 1]
        return GhidraResult(binary=b, output_file=None, success=False, elapsed=0.0, reason=reason)

    share = ExtractionShare(tmp_path / "share")
    with (
        patch.object(GhidraRunner, "pass_version", lambda self: "p1"),
        patch.object(GhidraRunner, "ghidra_version", lambda self: "11.4.3"),
        patch.object(GhidraRunner, "_run_session", session),
    ):
        r1, r2 = _runner(tmp_path, share), _runner(tmp_path, share)
        r1.run_ghidra(binary, tmp_path / "o1", 60, "x", "deadbeef", retry=False)
        r2.run_ghidra(binary, tmp_path / "o2", 60, "x", "deadbeef", retry=False)  # handed on
        r2.run_ghidra(binary, tmp_path / "o2", 120, "x", "deadbeef", retry=False)  # another budget
        r1.run_ghidra(binary, tmp_path / "o1", 60, "x", "deadbeef", retry=False, large_payload=True)
        r2.run_ghidra(binary, tmp_path / "o2", 60, "x", "deadbeef", retry=False, large_payload=True)
    # the 3rd session was cut off (not kept), so the large-payload one ran for both holders
    assert calls == [(60, False), (120, False), (60, True), (60, True)]
    assert share.handed == 1


def test_a_handed_outcome_is_the_holders_own_copy(tmp_path: Path) -> None:
    """The files handed on are copies written into the holder's output directory, under the names
    its own session would have written, and the result names the holder's binary — never the first
    run's files, which its pipeline moves away once stored.

    MUTATION (verified RED): hand the first run's paths over -> RED."""
    first = tmp_path / "o1"
    first.mkdir()
    out = first / "svc_deadbeef_ghidra.json"
    out.write_text(json.dumps({"functions": []}))
    share = ExtractionShare(tmp_path / "share")
    key = ("sha", "svc")
    share.put(
        key, GhidraResult(binary=tmp_path / "a" / "svc", output_file=out, success=True, elapsed=1.0)
    )
    out.unlink()  # the first run's pipeline stored and removed it
    got = share.get(key, tmp_path / "b" / "svc", tmp_path / "o2")
    assert got is not None
    assert got.binary == tmp_path / "b" / "svc"
    assert got.output_file == tmp_path / "o2" / "svc_deadbeef_ghidra.json"
    assert json.loads(got.output_file.read_text()) == {"functions": []}


def test_phase_one_hands_the_largest_binaries_to_the_pool_first() -> None:
    """The pool starts the longest sessions first, so they do not trail alone at its end; equal
    sizes keep their order.

    MUTATION (verified RED): submit in inventory order -> RED."""
    from treasure_map.lib.analyze.elf_inventory import ElfRecord

    recs = [
        ElfRecord(path=Path(n), name=n, arch="x", elf_type="executable", sha256=n * 64, size=sz)
        for n, sz in (("a", 10), ("b", 300), ("c", 10), ("d", 2000))
    ]
    order = [rec.name for _i, rec in ghidra_runner.phase_one_order(recs)]
    assert order == ["d", "b", "a", "c"]
