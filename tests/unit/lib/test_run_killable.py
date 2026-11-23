# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A timed-out or interrupted toolchain subprocess takes its whole process group — the orphaned-tool
leak — and it does so AT ONCE, not by waiting the orphan out.

The live path is BinDiff: a diff reads the exports the scans archived and runs only the ``bindiff``
CLI, so the group kill is driven here through ``_run_bindiff`` itself (with a fake ``bindiff`` on
PATH that backgrounds a child and waits for it, the launcher->tool shape). The standalone export
the fixture builder keeps goes through the same wrapper; its argv is checked at the end.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from treasure_map.lib.diff import driver
from treasure_map.lib.diff.driver import _kill_running_groups, _run_killable


@pytest.fixture(autouse=True)
def _fresh_sweep_state() -> Iterator[None]:
    """Each test starts and ends with no interrupted sweep recorded in this process."""
    driver._SWEEP_CANCELLED.clear()
    yield
    driver._SWEEP_CANCELLED.clear()


def _sleeper(marker: str) -> list[str]:
    """A shell that backgrounds a 60s child and waits for it: the launcher->tool shape."""
    return ["sh", "-c", f'python3 -c "import time; time.sleep(60)  # {marker}" & wait']


def _fake_bindiff(tmp_path: Path, marker: str, seconds: int = 60) -> Path:
    """A ``bindiff`` that backgrounds a long child and waits for it, as the real launcher does.

    Only a GROUP kill ends the child: reaping the script itself leaves the grandchild running."""
    path = tmp_path / "bin" / "bindiff"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f'#!/bin/sh\npython3 -c "import time; time.sleep({seconds})  # {marker}" &\nwait\n'
    )
    path.chmod(0o755)
    return path


def _reap(marker: str) -> list[str]:
    """Find, kill and return any surviving sleeper PIDs for ``marker`` (never leave a real leak)."""
    out = subprocess.run(["pgrep", "-f", marker], capture_output=True, text=True)  # noqa: S603,S607
    pids = [p for p in out.stdout.split() if p]
    for p in pids:
        try:
            os.kill(int(p), signal.SIGKILL)
        except (OSError, ValueError):
            pass
    return pids


def test_a_bindiff_timeout_kills_the_whole_group_at_once_not_just_the_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real BinDiff step, run out of time: a launcher that backgrounds the tool and waits for
    it (what ``bindiff`` is) outlives ``subprocess.run``'s own timeout as an orphan; the group kill
    ends the whole group, and ends it at once rather than letting communicate() block until the
    orphan exits on its own.

    The child sleeps 60s; the group kill must end this in a couple of seconds. The elapsed bound is
    what gives the test teeth: a version that dropped the killpg but kept communicate() would stay
    GREEN because, by the time communicate() returned (~60s later), the orphan had finished and
    pgrep found nothing. Here that version blows the time bound instead.

    MUTATIONS (each must go RED):
      * ``_run_bindiff`` back to ``subprocess.run(..., timeout=)`` -> the child survives -> the
        pgrep assertion fails.
      * drop the killpg in _run_killable and only re-raise -> communicate() waits ~60s -> the
        elapsed bound fails.
      * drop ``start_new_session=True`` -> killpg targets a non-group-leader -> child survives."""
    marker = "tmap_test_sleeper_rk1"
    monkeypatch.setattr(driver, "_find_bindiff", lambda: _fake_bindiff(tmp_path, marker))
    start = time.monotonic()
    with pytest.raises(driver.DiffToolchainError) as ei:
        driver._run_bindiff(tmp_path / "a.BinExport", tmp_path / "b.BinExport", tmp_path, 1)
    elapsed = time.monotonic() - start
    assert ei.value.kind == driver.FAIL_TIMEOUT  # the timeout still maps to its own bucket
    time.sleep(0.5)  # let SIGKILL propagate before we look
    leaked = _reap(marker)
    assert leaked == [], f"orphaned child survived the group kill: {leaked}"
    assert elapsed < 15, f"took {elapsed:.1f}s -> the orphan was waited on, not killed at once"


def test_run_killable_registers_its_group_only_while_running() -> None:
    """The running subprocess's group is in the registry during the call and gone after it, so an
    interrupt on another thread can reap it and a finished one is never signalled by mistake.

    MUTATION (RED): drop the ``_unregister_pgid`` in the finally -> the set keeps the dead group."""
    before = set(driver._RUNNING_PGIDS)
    cp = _run_killable(["true"], dict(os.environ), 30)
    assert cp.returncode == 0
    assert set(driver._RUNNING_PGIDS) == before  # registered during the run, removed after it


def test_kill_running_groups_reaps_a_registered_group() -> None:
    """``_kill_running_groups`` SIGKILLs every registered group — the main-thread path that takes
    the in-flight tools down when a full sweep is interrupted, without waiting each one out.

    MUTATION (RED): make ``_kill_running_groups`` a no-op (or ``os.kill`` instead of ``os.killpg``)
    -> the detached child outlives the call -> the time-bounded pgrep assertion fails."""
    marker = "tmap_test_sleeper_rk2"
    # A child in its OWN session (as _run_killable starts them), backgrounded under a shell that
    # exits immediately, so ONLY a group-level kill — not reaping its parent — can stop it.
    proc = subprocess.Popen(  # noqa: S603
        ["sh", "-c", f'python3 -c "import time; time.sleep(60)  # {marker}" & disown; exit 0'],
        start_new_session=True,
    )
    pgid = proc.pid
    driver._register_pgid(pgid)
    try:
        time.sleep(0.3)  # let the child spawn
        start = time.monotonic()
        _kill_running_groups()
        time.sleep(0.5)
        elapsed = time.monotonic() - start
        leaked = _reap(marker)
        assert leaked == [], f"registered group was not reaped: {leaked}"
        assert elapsed < 15
    finally:
        driver._unregister_pgid(pgid)
        _reap(marker)
        try:
            os.killpg(pgid, signal.SIGKILL)
        except OSError:
            pass


def test_an_interrupt_during_the_bindiff_kills_the_whole_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ctrl-C (or a SIGTERM/SIGHUP the CLI turns into one) arriving while BinDiff runs must take
    the whole group down before it propagates, not just leave the tool's process group running.
    The interrupt is delivered to this (the calling) thread mid-communicate, as a real one is.

    MUTATIONS (each must go RED): ``_run_bindiff`` back to ``subprocess.run`` -> the child survives
    the interrupt; catch only TimeoutExpired in _run_killable -> the KeyboardInterrupt passes
    straight through and the child survives -> the pgrep assertion fails."""
    marker = "tmap_test_sleeper_rk3"
    monkeypatch.setattr(driver, "_find_bindiff", lambda: _fake_bindiff(tmp_path, marker))

    def _interrupt(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGALRM, _interrupt)
    try:
        signal.setitimer(signal.ITIMER_REAL, 0.5)
        start = time.monotonic()
        with pytest.raises(KeyboardInterrupt):
            driver._run_bindiff(tmp_path / "a.BinExport", tmp_path / "b.BinExport", tmp_path, 60)
        elapsed = time.monotonic() - start
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    time.sleep(0.5)
    leaked = _reap(marker)
    assert leaked == [], f"the interrupted tool's group survived: {leaked}"
    assert elapsed < 15


def test_a_running_step_is_registered_and_a_sweep_kill_reaps_it() -> None:
    """End to end with the real pieces: while _run_killable runs on a worker thread its group is in
    the registry, and the real _kill_running_groups (what an interrupted sweep calls on the main
    thread) ends it at once, so the worker returns in seconds rather than at the child's 60s.

    MUTATION: drop the ``_register_pgid`` call -> the registry stays empty while the step runs
    -> the "registered while running" assertion fails (RED).
    MUTATION: drop ``_SWEEP_CANCELLED.set()`` in ``_kill_running_groups`` -> the kill no longer
    latches the cancel flag, so the post-kill ``_run_killable`` starts a subprocess instead of
    refusing -> the ``_SweepCancelledError`` assertion fails (RED)."""
    marker = "tmap_test_sleeper_rk4"
    before = set(driver._RUNNING_PGIDS)
    done: dict[str, object] = {}

    def _worker() -> None:
        try:
            done["result"] = _run_killable(_sleeper(marker), dict(os.environ), 60)
        except BaseException as exc:  # noqa: BLE001 -- recorded for the assertion below
            done["error"] = exc

    th = threading.Thread(target=_worker, daemon=True)
    th.start()
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not (set(driver._RUNNING_PGIDS) - before):
            time.sleep(0.05)
        registered = set(driver._RUNNING_PGIDS) - before
        assert registered, "the running step's group was not in the registry"
        start = time.monotonic()
        _kill_running_groups()
        th.join(timeout=15)
        assert not th.is_alive(), "the worker was still waiting on its subprocess after the kill"
        assert time.monotonic() - start < 15
        time.sleep(0.3)
        assert _reap(marker) == []
        assert set(driver._RUNNING_PGIDS) == before  # and it unregistered on the way out
        # the same kill latched the cancel flag: a worker that had NOT yet reached its Popen now
        # refuses to start one (the start-after-kill guard), so an interrupted sweep spawns no new
        # tool after the kill. ``["true"]`` would otherwise run and return cleanly.
        with pytest.raises(driver._SweepCancelledError):
            _run_killable(["true"], dict(os.environ), 30)
    finally:
        _reap(marker)


def test_an_interrupted_sweep_starts_no_new_step(monkeypatch: pytest.MonkeyPatch) -> None:
    """Once the sweep was interrupted, a worker that had not yet started its subprocess (the next
    binary's BinDiff) must not start one: a tool started after the kill would keep the shutdown
    waiting.

    MUTATION: drop the check before Popen -> the subprocess is started -> RED."""
    started: list[list[str]] = []
    real_popen = subprocess.Popen

    def _recording_popen(cmd, *a, **kw):  # type: ignore[no-untyped-def]
        started.append(list(cmd))
        return real_popen(cmd, *a, **kw)

    monkeypatch.setattr(driver.subprocess, "Popen", _recording_popen)
    driver._SWEEP_CANCELLED.set()
    with pytest.raises(driver._SweepCancelledError):
        _run_killable(["true"], dict(os.environ), 30)
    assert started == [], "a subprocess was started after the sweep was interrupted"


def test_a_kill_that_lands_as_the_step_starts_still_reaps_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The kill can run between the pre-start check and the registration, so it never sees the new
    group. The check right after registering catches that: the subprocess is stopped at once.

    MUTATION: drop the check after ``_register_pgid`` -> the subprocess runs until its own 20s
    timeout and stops with TimeoutExpired instead -> the "stopped as cancelled" assertion fails
    (RED)."""
    marker = "tmap_test_sleeper_rk5"
    real_register = driver._register_pgid

    def _register_then_kill(pgid: int) -> None:
        real_register(pgid)
        driver._SWEEP_CANCELLED.set()  # the sweep's kill ran just before this group registered

    monkeypatch.setattr(driver, "_register_pgid", _register_then_kill)
    start = time.monotonic()
    stopped_by: BaseException | None = None
    try:
        _run_killable(_sleeper(marker), dict(os.environ), 20)
    except BaseException as exc:  # noqa: BLE001 -- the kind of stop is what is asserted
        stopped_by = exc
    elapsed = time.monotonic() - start
    time.sleep(0.3)
    leaked = _reap(marker)
    assert isinstance(stopped_by, driver._SweepCancelledError), (
        f"the subprocess was not stopped as cancelled (got {stopped_by!r} after {elapsed:.1f}s)"
    )
    assert leaked == [], f"the subprocess started during the kill survived: {leaked}"
    assert elapsed < 15


def test_the_standalone_export_names_its_language_and_starts_in_its_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The standalone BinExport run (the fixture builder's, not a diff's) imports the binary
    under the language the scan detects (-processor), and starts from its own project directory, so
    a same-named script in the current directory is never run.

    MUTATION (verified RED): leave -processor out -> RED; start in the current directory -> RED."""
    import subprocess

    from tests.fixtures.layer0.binexport import _run_binexport
    from treasure_map.lib.config.config import Config
    from treasure_map.lib.diff.driver import DiffToolchainError

    seen: dict[str, object] = {}

    def fake(cmd: list[str], env: dict[str, str], timeout: int, cwd: object = None) -> object:
        seen.update(cmd=cmd, cwd=cwd)
        return subprocess.CompletedProcess(cmd, 1, b"", b"")

    monkeypatch.setattr(driver, "_run_killable", fake)
    monkeypatch.setattr(
        "treasure_map.lib.analyze.ghidra_runner.find_headless",
        lambda cfg: Path("/g/analyzeHeadless"),
    )
    elf = Path(__file__).resolve().parents[2] / "fixtures" / "elfs" / "exe_x86_64"
    with pytest.raises(DiffToolchainError):
        _run_binexport(elf, Config(), tmp_path, "a", 60)
    cmd = seen["cmd"]
    assert isinstance(cmd, list)
    assert cmd[cmd.index("-processor") + 1] == "x86:LE:64:default"
    assert seen["cwd"] == cmd[1]  # the project directory


def test_an_architecture_ghidra_has_no_language_for_is_not_passed_as_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An ELF machine detect_arch does not support comes back as ``UNKNOWN_…``: that is no Ghidra
    language, so no ``-processor`` is passed (Ghidra guesses) rather than one it rejects.

    MUTATION (verified RED, 1 failed): pass any detected arch as -processor again."""
    import subprocess

    from tests.fixtures.layer0.binexport import _run_binexport
    from treasure_map.lib.config.config import Config
    from treasure_map.lib.diff.driver import DiffToolchainError

    seen: dict[str, object] = {}

    def fake(cmd: list[str], env: dict[str, str], timeout: int, cwd: object = None) -> object:
        seen.update(cmd=cmd)
        return subprocess.CompletedProcess(cmd, 1, b"", b"")

    monkeypatch.setattr(driver, "_run_killable", fake)
    monkeypatch.setattr(
        "treasure_map.lib.analyze.ghidra_runner.find_headless",
        lambda cfg: Path("/g/analyzeHeadless"),
    )
    monkeypatch.setattr(
        "treasure_map.lib.analyze.elf_inventory.detect_arch",
        lambda p: "UNKNOWN_EM_999:LE:32:default",
    )
    with pytest.raises(DiffToolchainError):
        _run_binexport(tmp_path / "lib.so", Config(), tmp_path, "a", 60)
    cmd = seen["cmd"]
    assert isinstance(cmd, list) and "-import" in cmd
    assert "-processor" not in cmd
