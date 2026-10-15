# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""SIGTERM / SIGHUP take the Ctrl-C cleanup path (cli.interrupts)."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from treasure_map.cli import interrupts
from treasure_map.cli.main import main

_SRC = Path(__file__).resolve().parents[2] / "src"
_MARK = "47.4321"  # a sleep length nothing else on the machine is running


def _survivors() -> list[int]:
    """Pids of any process still running the marked sleep."""
    out = []
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            argv = (proc / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        if argv[:2] == [b"sleep", _MARK.encode()]:
            out.append(int(proc.name))
    return out


@pytest.mark.skipif(not Path("/proc").is_dir(), reason="needs /proc to find the child")
def test_sigterm_kills_the_child_group_and_exits_143(tmp_path: Path) -> None:
    """A kill must not leave the child process group running.

    MUTATION: make install_termination_handlers a no-op -> RED (the parent dies on the default
    action with -15, and the sleep group it started is still alive)."""
    script = tmp_path / "drive.py"
    script.write_text(
        textwrap.dedent(
            f"""
            import os, sys
            sys.path.insert(0, {str(_SRC)!r})
            from treasure_map.cli.interrupts import install_termination_handlers
            from treasure_map.cli.interrupts import interrupt_exit_code
            from treasure_map.lib.analyze import ghidra_runner
            install_termination_handlers()
            print("ready", flush=True)
            try:
                ghidra_runner._run_subprocess(["sleep", {_MARK!r}], dict(os.environ), 120)
            except KeyboardInterrupt:
                ghidra_runner.terminate_all(grace=0.2)
                sys.exit(interrupt_exit_code())
            """
        )
    )
    proc = subprocess.Popen([sys.executable, str(script)], stdout=subprocess.PIPE, text=True)
    try:
        assert proc.stdout is not None and proc.stdout.readline().strip() == "ready"
        deadline = time.monotonic() + 10
        while not _survivors() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert _survivors(), "the child never started, so the test would prove nothing"
        proc.send_signal(signal.SIGTERM)
        rc = proc.wait(timeout=20)
    finally:
        if proc.poll() is None:
            proc.kill()
    deadline = time.monotonic() + 5
    while _survivors() and time.monotonic() < deadline:
        time.sleep(0.05)
    leftovers = _survivors()
    for pid in leftovers:  # never leave one behind, even when the assertion fails
        os.kill(pid, signal.SIGKILL)
    assert rc == 128 + signal.SIGTERM
    assert leftovers == []


def test_the_cli_installs_the_handlers_and_the_server_gives_them_back() -> None:
    """MUTATION: drop the install call from main() -> RED."""
    before = signal.getsignal(signal.SIGTERM)
    before_hup = signal.getsignal(signal.SIGHUP) if hasattr(signal, "SIGHUP") else None
    try:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        result = CliRunner().invoke(main, ["doctor", "--help"])
        assert result.exit_code == 0, result.output
        assert signal.getsignal(signal.SIGTERM) is interrupts._to_interrupt
        interrupts.restore_default_termination()
        assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL
    finally:
        signal.signal(signal.SIGTERM, before)
        if before_hup is not None:
            signal.signal(signal.SIGHUP, before_hup)


def test_interrupt_exits_are_recognised() -> None:
    assert interrupts.is_interrupt_exit(130)
    assert interrupts.is_interrupt_exit(143)
    assert not interrupts.is_interrupt_exit(1)
    assert not interrupts.is_interrupt_exit(0)
