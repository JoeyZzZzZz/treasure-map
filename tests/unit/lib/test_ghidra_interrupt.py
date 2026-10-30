# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Behavioral tests for Ghidra subprocess-group teardown on interrupt/timeout.

Uses real child process groups (sleep) — no Ghidra needed. Proves terminate_all
kills a registered group, that an empty registry is an instant no-op, that a
timed-out subprocess leaves no live group, and that an interrupt mid-flight kills
the group and re-raises KeyboardInterrupt without leaking a JVM.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

from treasure_map.lib.analyze import ghidra_runner
from treasure_map.lib.analyze.elf_inventory import ElfRecord
from treasure_map.lib.analyze.ghidra_runner import (
    _active_pgids,
    _register_pgid,
    _run_subprocess,
    terminate_all,
)
from treasure_map.lib.config.config import GhidraConfig


def _group_alive(pgid: int) -> bool:
    """True if the process group still exists (signal 0 probes without killing)."""
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def test_terminate_all_kills_registered_group() -> None:
    proc = subprocess.Popen(["sleep", "600"], start_new_session=True)
    pgid = proc.pid
    _register_pgid(pgid)
    try:
        assert _group_alive(pgid)
        terminate_all(grace=0.2)
        assert proc.wait(timeout=5) != 0  # killed by signal -> non-zero
        assert pgid not in _active_pgids  # registry cleared
        assert not _group_alive(pgid)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


def test_terminate_all_empty_registry_is_instant_noop() -> None:
    assert not _active_pgids  # nothing registered
    t0 = time.monotonic()
    terminate_all(grace=2.0)
    assert time.monotonic() - t0 < 0.05  # never hit the grace sleep


def test_run_subprocess_timeout_kills_group() -> None:
    captured: dict[str, int] = {}
    real_register = ghidra_runner._register_pgid

    def _spy(pgid: int) -> None:
        captured["pgid"] = pgid
        real_register(pgid)

    ghidra_runner._register_pgid = _spy  # type: ignore[assignment]
    try:
        rc, tail = _run_subprocess(["sleep", "30"], dict(os.environ), timeout=1)
    finally:
        ghidra_runner._register_pgid = real_register  # type: ignore[assignment]

    assert rc == -1
    assert tail == "timeout"
    pgid = captured["pgid"]
    assert not _group_alive(pgid)  # the sleep group is gone after return
    assert pgid not in _active_pgids  # finally-unregistered


def test_run_subprocess_interrupt_kills_group_and_reraises(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, int] = {}
    real_register = ghidra_runner._register_pgid

    def _spy(pgid: int) -> None:
        captured["pgid"] = pgid
        real_register(pgid)

    monkeypatch.setattr(ghidra_runner, "_register_pgid", _spy)

    real_communicate = subprocess.Popen.communicate
    calls = {"n": 0}

    def _fake_communicate(self: subprocess.Popen, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        # First call (the blocking wait) raises KeyboardInterrupt; the teardown
        # reap call (second) is allowed through so the child is actually reaped.
        calls["n"] += 1
        if calls["n"] == 1:
            raise KeyboardInterrupt
        return real_communicate(self, *args, **kwargs)

    monkeypatch.setattr(subprocess.Popen, "communicate", _fake_communicate)

    with pytest.raises(KeyboardInterrupt):
        _run_subprocess(["sleep", "30"], dict(os.environ), timeout=30)

    pgid = captured["pgid"]
    assert not _group_alive(pgid)  # group killed on the interrupt path
    assert pgid not in _active_pgids  # finally-unregistered, no leak


def test_no_jvm_starts_once_a_teardown_has_begun() -> None:
    """A worker caught between its checks and Popen at the moment of an interrupt used to start a
    fresh JVM after terminate_all had run, and the pool's shutdown then waited on it.

    MUTATION: drop the _shutting_down check in _run_subprocess -> RED (the child is started and
    runs to completion)."""
    ghidra_runner.begin_shutdown()
    try:
        t0 = time.monotonic()
        rc, text = _run_subprocess(["sleep", "3"], dict(os.environ), 30)
        elapsed = time.monotonic() - t0
    finally:
        ghidra_runner._reset_shutdown()
    assert rc == ghidra_runner.LAUNCH_FAILED_RC
    assert "interrupted" in text
    assert elapsed < 1.0
    assert not _active_pgids


def test_a_new_run_clears_the_previous_runs_teardown(tmp_path: Path) -> None:
    """The flag is per run: a scan after an interrupted one in the same process must start JVMs.

    MUTATION: drop the _reset_shutdown() call at the top of run_all -> RED."""
    ghidra_runner.begin_shutdown()
    runner = ghidra_runner.GhidraRunner(GhidraConfig())
    seen: list[bool] = []

    def _probe(*_a: object, **_k: object) -> ghidra_runner.GhidraResult:
        seen.append(ghidra_runner._shutting_down)
        return ghidra_runner.GhidraResult(
            binary=Path("x"), output_file=None, success=True, elapsed=0.0
        )

    runner.get_headless = lambda: Path("/bin/true")  # type: ignore[method-assign]
    runner.run_ghidra = _probe  # type: ignore[method-assign]
    import treasure_map.lib.analyze.ghidra_runner as gr

    real_validate = gr.validate_registry
    gr.validate_registry = lambda _p: None  # type: ignore[assignment]
    try:
        rec = ElfRecord(
            path=tmp_path / "b",
            name="b",
            arch="x86:LE:64:default",
            elf_type="executable",
            sha256="a" * 64,
            dt_needed=[],
            size=1,
        )
        runner.run_all([rec], tmp_path / "out")
    finally:
        gr.validate_registry = real_validate
        ghidra_runner._reset_shutdown()
    assert seen == [False]


# ── an attempt the teardown cut off is not a failure of the binary (S8) ────────────────────────


@pytest.mark.parametrize("rc", [0, ghidra_runner.LAUNCH_FAILED_RC])
def test_an_attempt_cut_off_by_the_teardown_reads_interrupted_not_failed(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, rc: int
) -> None:
    """T-I1. The teardown begins while the attempt is out (the JVM then exits, or never starts):
    whatever the return code, the result is ``interrupted`` — not classified, not retried, not
    warned about — so it is never recorded as a timeout or an import failure of the binary.

    MUTATION (verified RED): drop the post-subprocess shutdown check -> classified (no_output),
    retried, and warned about."""
    from unittest.mock import patch

    binary = tmp_path / "svc_a"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
    calls = {"n": 0}

    def fake_sub(
        cmd: list[str], env: dict[str, str], timeout: int, cwd: Path | None = None
    ) -> tuple[int, str]:
        calls["n"] += 1
        ghidra_runner.begin_shutdown()
        return rc, "" if rc == 0 else "not started"

    runner = ghidra_runner.GhidraRunner(GhidraConfig(), headless=tmp_path / "hl")
    try:
        with (
            caplog.at_level("DEBUG"),
            patch.object(ghidra_runner, "_run_subprocess", fake_sub),
        ):
            r = runner.run_ghidra(binary, tmp_path / "out", 60, "x86:LE:64:default", "aabb1122")
    finally:
        ghidra_runner._reset_shutdown()
    assert (r.success, r.reason, r.timeout_budget) == (False, "interrupted", None)
    assert calls["n"] == 1  # no retry of any kind
    assert not [rec for rec in caplog.records if rec.levelname == "WARNING"]
