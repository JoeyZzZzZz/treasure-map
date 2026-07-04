# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Command final-form tests: shortened names + hidden back-compat aliases, and `tmap mcp`
path resolution (last-run pointer, friendly errors, stderr launch hint)."""

from __future__ import annotations

from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from treasure_map.cli import mcp_cli
from treasure_map.cli.main import main

# ── A1: shortened names listed; old names resolve but hidden ────────────────────────────


def test_short_names_registered_old_names_hidden() -> None:
    registered = set(main.commands)
    assert {"hunt", "diff", "mcp"} <= registered
    # old names are NOT registered as their own commands (resolved via alias only)
    assert registered.isdisjoint({"hunt-pattern", "hunt-diff", "mcp-serve"})
    assert "hunt-pattern" not in CliRunner().invoke(main, ["--help"]).output


@pytest.mark.parametrize(
    ("old", "new"),
    [("hunt-pattern", "hunt"), ("hunt-diff", "diff"), ("mcp-serve", "mcp")],
)
def test_old_names_still_resolve(old: str, new: str) -> None:
    # the hidden alias resolves to the same command object (back-compat for scripts/notes)
    r_old = CliRunner().invoke(main, [old, "--help"])
    r_new = CliRunner().invoke(main, [new, "--help"])
    assert r_old.exit_code == 0 and r_new.exit_code == 0
    # identical help bodies (only the usage line differs, reflecting the invoked name)
    assert r_old.output.split("\n", 1)[1] == r_new.output.split("\n", 1)[1]


# ── A2: `tmap mcp` resolves paths from the last-run pointer; explicit wins ───────────────


def test_mcp_target_from_pointer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    adb, atlas = tmp_path / "analysis.db", tmp_path / "atlas.db"
    adb.touch()
    atlas.touch()
    ptr = tmp_path / "last_run.json"
    from treasure_map.lib import last_run

    last_run.write_last_run(adb, atlas, "run_z", path=ptr)
    monkeypatch.setattr(last_run, "_POINTER_PATH", ptr)
    a, x, run_id = mcp_cli._resolve_mcp_target(None, None)
    assert Path(a) == adb.resolve() and Path(x) == atlas.resolve()
    assert run_id == "run_z"  # bound because the resolved analysis.db matches the pointer


def test_mcp_explicit_paths_win(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from treasure_map.lib import last_run

    monkeypatch.setattr(last_run, "_POINTER_PATH", tmp_path / "absent.json")
    a, x, run_id = mcp_cli._resolve_mcp_target("/custom/a.db", "/custom/x.db")
    assert a == "/custom/a.db" and x == "/custom/x.db"
    assert run_id is None  # no pointer to bind a run from


def test_mcp_missing_pointer_is_friendly_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from treasure_map.lib import last_run

    monkeypatch.setattr(last_run, "_POINTER_PATH", tmp_path / "absent.json")
    with pytest.raises(click.ClickException) as exc:
        mcp_cli._resolve_mcp_target(None, None)
    assert "tmap scan" in str(exc.value)  # tells the user what to do, not a traceback


# ── A3: stderr launch hint (mcp is a core dep — no missing-extra path to test) ───────────


def test_mcp_stderr_launch_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        mcp_cli, "_resolve_mcp_target", lambda a, x: ("/abs/a.db", "/abs/x.db", None)
    )

    class _FakeServer:
        def run(self) -> None:  # the client would drive JSON-RPC; here we just return
            return None

    import treasure_map.mcp_app as mcp_app

    monkeypatch.setattr(mcp_app, "build_server", lambda *a, **k: _FakeServer())
    r = CliRunner().invoke(main, ["mcp"])
    assert r.exit_code == 0
    assert "stdio" in r.stderr and "JSON-RPC on stdin" in r.stderr
    assert r.stdout == ""  # stdout stays clean for the protocol
