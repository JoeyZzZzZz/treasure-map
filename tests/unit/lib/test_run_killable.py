# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A timed-out or interrupted BinExport subprocess takes its whole process group — the orphaned-JVM
leak — and it does so AT ONCE, not by waiting the orphan out."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from collections.abc import Iterator

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
    """A shell that backgrounds a 60s child and waits for it: the wrapper->JVM shape."""
    return ["sh", "-c", f'python3 -c "import time; time.sleep(60)  # {marker}" & wait']


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


def test_a_timeout_kills_the_whole_group_at_once_not_just_the_wrapper() -> None:
    """A shell that backgrounds a long child and waits (the analyzeHeadless->JVM shape): run's own
    timeout reaps the shell and leaves the child; _run_killable kills the whole group, and does it
    at once rather than letting communicate() block until the orphan exits on its own.

    The child sleeps 60s; the group kill must end this in a couple of seconds. The elapsed bound is
    what gives the test teeth the old version lacked: a version that dropped the killpg but kept
    communicate() stayed GREEN because, by the time communicate() returned (~60s later), the orphan
    had finished and pgrep found nothing. Here that version blows the time bound instead.

    MUTATIONS (each must go RED):
      * ``subprocess.run(..., timeout=)`` or ``os.kill(proc.pid, ...)`` (only the wrapper) ->
        the child survives -> the pgrep assertion fails.
      * drop the killpg and only re-raise -> communicate() waits ~60s -> the elapsed bound fails.
      * drop ``start_new_session=True`` -> killpg targets a non-group-leader -> child survives."""
    marker = "tmap_test_sleeper_rk1"
    script = f'python3 -c "import time; time.sleep(60)  # {marker}" & wait'
    start = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        _run_killable(["sh", "-c", script], dict(os.environ), 1)
    elapsed = time.monotonic() - start
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
    the in-flight JVMs down when a full sweep is interrupted, without waiting each one out.

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


def test_an_interrupt_during_the_export_kills_the_whole_group() -> None:
    """Ctrl-C (or a SIGTERM/SIGHUP the CLI turns into one) arriving while the export runs must take
    the whole group down before it propagates, not just leave the export's process group running.
    The interrupt is delivered to this (the calling) thread mid-communicate, as a real one is.

    MUTATION: catch only TimeoutExpired in _run_killable -> the KeyboardInterrupt passes straight
    through, the child survives -> the pgrep assertion fails (RED)."""
    marker = "tmap_test_sleeper_rk3"

    def _interrupt(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGALRM, _interrupt)
    try:
        signal.setitimer(signal.ITIMER_REAL, 0.5)
        start = time.monotonic()
        with pytest.raises(KeyboardInterrupt):
            _run_killable(_sleeper(marker), dict(os.environ), 60)
        elapsed = time.monotonic() - start
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    time.sleep(0.5)
    leaked = _reap(marker)
    assert leaked == [], f"the interrupted export's group survived: {leaked}"
    assert elapsed < 15


def test_a_running_export_is_registered_and_a_sweep_kill_reaps_it() -> None:
    """End to end with the real pieces: while _run_killable runs on a worker thread its group is in
    the registry, and the real _kill_running_groups (what an interrupted sweep calls on the main
    thread) ends it at once, so the worker returns in seconds rather than at the child's 60s.

    MUTATION: drop the ``_register_pgid`` call -> the registry stays empty while the export runs
    -> the "registered while running" assertion fails (RED).
    MUTATION: drop ``_SWEEP_CANCELLED.set()`` in ``_kill_running_groups`` -> the kill no longer
    latches the cancel flag, so the post-kill ``_run_killable`` starts an export instead of
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
        assert registered, "the running export's group was not in the registry"
        start = time.monotonic()
        _kill_running_groups()
        th.join(timeout=15)
        assert not th.is_alive(), "the worker was still waiting on its export after the kill"
        assert time.monotonic() - start < 15
        time.sleep(0.3)
        assert _reap(marker) == []
        assert set(driver._RUNNING_PGIDS) == before  # and it unregistered on the way out
        # the same kill latched the cancel flag: a worker that had NOT yet reached its Popen now
        # refuses to start one (the start-after-kill guard), so an interrupted sweep spawns no new
        # JVM after the kill. ``["true"]`` would otherwise run and return cleanly.
        with pytest.raises(driver._SweepCancelledError):
            _run_killable(["true"], dict(os.environ), 30)
    finally:
        _reap(marker)


def test_an_interrupted_sweep_starts_no_new_export(monkeypatch: pytest.MonkeyPatch) -> None:
    """Once the sweep was interrupted, a worker that had not yet started its export (side b after
    side a) must not start one: a JVM started after the kill would keep the shutdown waiting.

    MUTATION: drop the check before Popen -> the export is started -> RED."""
    started: list[list[str]] = []
    real_popen = subprocess.Popen

    def _recording_popen(cmd, *a, **kw):  # type: ignore[no-untyped-def]
        started.append(list(cmd))
        return real_popen(cmd, *a, **kw)

    monkeypatch.setattr(driver.subprocess, "Popen", _recording_popen)
    driver._SWEEP_CANCELLED.set()
    with pytest.raises(driver._SweepCancelledError):
        _run_killable(["true"], dict(os.environ), 30)
    assert started == [], "an export was started after the sweep was interrupted"


def test_a_kill_that_lands_as_the_export_starts_still_reaps_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The kill can run between the pre-start check and the registration, so it never sees the new
    group. The check right after registering catches that: the export is stopped at once.

    MUTATION: drop the check after ``_register_pgid`` -> the export runs until its own 20s timeout
    and stops with TimeoutExpired instead -> the "stopped as cancelled" assertion fails (RED)."""
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
        f"the export was not stopped as cancelled (got {stopped_by!r} after {elapsed:.1f}s)"
    )
    assert leaked == [], f"the export started during the kill survived: {leaked}"
    assert elapsed < 15
