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

import pytest

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


def test_setting_the_extension_keeps_the_share(tmp_path: Path) -> None:
    """The share is the runner's own setting, apart from the extension: setting the extension after
    the share leaves the share in place (the order the caller sets them in does not matter).

    MUTATION (verified RED): reset the share in set_extension -> RED."""
    share = ExtractionShare(tmp_path / "share")
    runner = GhidraRunner(GhidraConfig(), headless=tmp_path / "analyzeHeadless")
    runner.set_share(share)
    runner.set_extension(None)
    assert runner._share is share


def test_the_phase_two_decision_is_made_once_per_shared_session(tmp_path: Path) -> None:
    """★ Two runs of one rescan hold the same binary; its phase-1 session leaves a large decompile
    unfinished. Run A's database already records an isolated re-run (decompile_settled), run B's
    does not. The first holder's decision binds the second, so both end with the same session.

    MUTATION (verified RED, 1 failed): decide per run (ignore share.rerun_decision) -> run B
    re-runs and ends with another session."""
    from treasure_map.lib.analyze.elf_inventory import ElfRecord

    def fake_session(
        self: Any, binary: Path, output_dir: Path, timeout: int, arch: str,
        sha8: str = "", retry: bool = True, large_payload: bool = False,
    ) -> GhidraResult:  # fmt: skip
        left = 0 if large_payload else 1
        return GhidraResult(
            binary=binary, output_file=None, success=True, elapsed=1.0, analysis_status="ok",
            function_count=10, decompile_timeouts=left, decompile_large_timeouts=left,
            decompile_payload_exceeded=0, timeout_budget=timeout,
            export_status="extension_missing", session=uuid.uuid4().hex[:12],
        )  # fmt: skip

    binary = tmp_path / "fw" / "svc"
    binary.parent.mkdir()
    binary.write_bytes(b"\x7fELF" + b"\0" * 4096)
    rec = ElfRecord(
        path=binary, name="svc", arch="x", elf_type="executable", sha256="ab" * 32, size=4100
    )
    share = ExtractionShare(tmp_path / "share")
    out: dict[str, GhidraResult] = {}
    with (
        patch.object(GhidraRunner, "pass_version", lambda self: "p1"),
        patch.object(GhidraRunner, "ghidra_version", lambda self: "11.4.3"),
        patch.object(GhidraRunner, "get_headless", lambda self: tmp_path / "analyzeHeadless"),
        patch.object(GhidraRunner, "_run_session", fake_session),
        patch.object(ghidra_runner, "validate_registry", lambda p: None),
        patch.object(ghidra_runner, "sweep_orphans", lambda: None),
    ):
        for run, settled in (("runA", {rec.sha256}), ("runB", set())):
            runner = GhidraRunner(GhidraConfig(max_parallel_jvms=1))
            runner.set_share(share)
            (res,) = runner.run_all([rec], tmp_path / run / "out", decompile_settled=settled)
            out[run] = res
    assert out["runA"].session == out["runB"].session


def _counting_session(calls: list[tuple[str, int, bool]]) -> Any:
    def session(
        self: Any, b: Path, out: Path, timeout: int, arch: str,
        sha8: str = "", retry: bool = True, large_payload: bool = False,
    ) -> GhidraResult:  # fmt: skip
        calls.append((b.name, timeout, large_payload))
        return GhidraResult(
            binary=b, output_file=None, success=True, elapsed=0.0, analysis_status="ok",
            function_count=1, session=uuid.uuid4().hex[:12],
        )  # fmt: skip

    return session


@pytest.mark.parametrize("differs", ["arch", "pass_version", "extension", "environment", "content"])
def test_a_session_under_another_key_field_is_not_handed_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, differs: str
) -> None:
    """★ Two holders, one key field apart (the other's architecture, extraction pass, BinExport
    copy, inherited JVM environment, or another binary's bytes under the same name): two sessions,
    nothing handed. The same key in every field hands the first session on (the control).

    MUTATION (verified RED): drop ``arch`` / ``pass_version`` / ``extension`` / ``environment``
    from the key -> that case is handed the other's session -> RED; key on the name alone (drop the
    content digest) -> the "content" case -> RED."""
    from treasure_map.lib.export_stamp import ScanExtension

    def ext(stamp: str) -> ScanExtension:
        return ScanExtension(ext_dir=tmp_path / "ext", stamp=stamp, link_from=None, note=None)

    first_bin, second_bin = tmp_path / "a" / "svc", tmp_path / "b" / "svc"
    for p, body in ((first_bin, b"one"), (second_bin, b"two" if differs == "content" else b"one")):
        p.parent.mkdir()
        p.write_bytes(b"\x7fELF" + body * 64)
    calls: list[tuple[str, int, bool]] = []
    share = ExtractionShare(tmp_path / "share")
    passes = iter(["p1", "p2" if differs == "pass_version" else "p1"])
    monkeypatch.setenv("LANG", "C")
    with (
        patch.object(GhidraRunner, "ghidra_version", lambda self: "11.4.3"),
        patch.object(GhidraRunner, "_run_session", _counting_session(calls)),
    ):
        for n, binary in enumerate((first_bin, second_bin)):
            runner = _runner(tmp_path, share)
            pv = next(passes)
            monkeypatch.setattr(runner, "pass_version", lambda pv=pv: pv)
            runner.set_extension(ext("e2" if differs == "extension" and n else "e1"))
            if differs == "environment" and n:
                monkeypatch.setenv("LANG", "C.UTF-8")
            arch = "AARCH64:LE:64:v8A" if differs == "arch" and n else "ARM:LE:32:v7"
            runner.run_ghidra(binary, tmp_path / f"o{n}", 60, arch, "deadbeef", retry=False)
    assert len(calls) == 2 and share.handed == 0

    # the control: every field the same -> the second holder is handed the first session
    calls.clear()
    control = ExtractionShare(tmp_path / "share2")
    monkeypatch.setenv("LANG", "C")
    with (
        patch.object(GhidraRunner, "pass_version", lambda self: "p1"),
        patch.object(GhidraRunner, "ghidra_version", lambda self: "11.4.3"),
        patch.object(GhidraRunner, "_run_session", _counting_session(calls)),
    ):
        for n in (0, 1):
            runner = _runner(tmp_path, control)
            runner.set_extension(ext("e1"))
            runner.run_ghidra(first_bin, tmp_path / f"c{n}", 60, "ARM:LE:32:v7", "deadbeef",
                              retry=False)  # fmt: skip
    assert len(calls) == 1 and control.handed == 1


def test_phase_two_sessions_are_shared_too(tmp_path: Path) -> None:
    """★ Two runs hold one binary whose phase-1 session leaves a large decompile unfinished and
    neither run's database says it was re-run before: the phase-2 re-run is one session too, handed
    to the second holder like phase 1's — two sessions in all, both holders ending on the same one.

    MUTATION (verified RED, 1 failed): run phase 2 through ``_run_session`` directly instead of
    ``run_ghidra`` -> a third session."""
    from treasure_map.lib.analyze.elf_inventory import ElfRecord

    calls: list[tuple[str, int, bool]] = []

    def session(
        self: Any, b: Path, out: Path, timeout: int, arch: str,
        sha8: str = "", retry: bool = True, large_payload: bool = False,
    ) -> GhidraResult:  # fmt: skip
        calls.append((b.name, timeout, large_payload))
        left = 0 if large_payload else 1
        return GhidraResult(
            binary=b, output_file=None, success=True, elapsed=1.0, analysis_status="ok",
            function_count=10, decompile_timeouts=left, decompile_large_timeouts=left,
            decompile_payload_exceeded=0, timeout_budget=timeout,
            export_status="extension_missing", session=uuid.uuid4().hex[:12],
        )  # fmt: skip

    binary = tmp_path / "fw" / "svc"
    binary.parent.mkdir()
    binary.write_bytes(b"\x7fELF" + b"\0" * 4096)
    rec = ElfRecord(
        path=binary, name="svc", arch="x", elf_type="executable", sha256="ab" * 32, size=4100
    )
    share = ExtractionShare(tmp_path / "share")
    finals = []
    with (
        patch.object(GhidraRunner, "pass_version", lambda self: "p1"),
        patch.object(GhidraRunner, "ghidra_version", lambda self: "11.4.3"),
        patch.object(GhidraRunner, "get_headless", lambda self: tmp_path / "analyzeHeadless"),
        patch.object(GhidraRunner, "_run_session", session),
        patch.object(ghidra_runner, "validate_registry", lambda p: None),
        patch.object(ghidra_runner, "sweep_orphans", lambda: None),
    ):
        for run in ("runA", "runB"):
            runner = GhidraRunner(GhidraConfig(max_parallel_jvms=1))
            runner.set_share(share)
            (res,) = runner.run_all([rec], tmp_path / run / "out", decompile_settled=set())
            finals.append(res.session)
    assert [c[2] for c in calls] == [False, True]  # phase 1, then the one phase-2 re-run
    assert share.handed == 2
    assert finals[0] == finals[1]


def test_a_share_that_cannot_keep_a_session_costs_sharing_not_the_extraction(
    tmp_path: Path,
) -> None:
    """★ The share's directory is full (every copy into it fails): each binary is still extracted
    and stored as a success — the session is simply not kept — instead of being recorded as a
    crashed, function-less extraction.

    MUTATION (verified RED, 1 failed): let the OSError from ``share.put`` propagate in run_ghidra
    -> every binary is stored as failed."""
    import errno
    import shutil as real_shutil

    from treasure_map.lib.analyze import extraction_share

    fs = _firmware(tmp_path)
    home = _ghidra(tmp_path)
    _with_extension(home)
    dec = _Counted(_Sessions({n: ["ok"] * 4 for n in _NAMES}))
    real_copy = real_shutil.copyfile

    def full(src: Any, dst: Any, *a: Any, **k: Any) -> Any:
        if "tm_share_" in str(dst):
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_copy(src, dst, *a, **k)

    db = tmp_path / "ws" / "analysis.db"
    with (
        patch.object(GhidraRunner, "_run_session", lambda self, *a, **k: dec(self, *a, **k)),
        patch.object(extraction_share.shutil, "copyfile", full),
        sharing_extractions(),
        Workspace(db.parent) as ws,
    ):
        run_analyze(fs, ws, _e2e_cfg(home))
    state = _state(db)
    assert set(state) == set(_NAMES)
    assert all(v["ghidra_ok"] == 1 and v["functions"] for v in state.values()), state
