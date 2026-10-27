# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""``tmap update``: the newest tmap replaces this one in uv's tool environment, and a tmap that uv
does not manage is never touched."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from treasure_map.lib.setup import update as up
from treasure_map.lib.setup.discover import RunResult
from treasure_map.version import __version__

from . import fakes


def test_version_order() -> None:
    assert up.is_newer("0.2.0", "0.1.0")
    assert up.is_newer("0.10.0", "0.9.9")
    assert not up.is_newer("0.1.0", "0.1")
    assert up.is_newer("0.2.0", "0.2.0rc1") and not up.is_newer("0.2.0rc1", "0.2.0")


class _Uv:
    """A fake uv: a tool directory, a tool list, and a log of what was run."""

    def __init__(self, tools_dir: Path, listing: str, fail: str | None = None) -> None:
        self.tools_dir = tools_dir
        self.listing = listing
        self.fail = fail
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **_k: object) -> RunResult:
        self.calls.append(list(argv))
        sub = argv[1:3]
        if sub == ["tool", "dir"]:
            return RunResult(0, f"{self.tools_dir}\n", "")
        if sub == ["tool", "list"]:
            return RunResult(0, self.listing, "")
        if self.fail and self.fail in " ".join(argv):
            return RunResult(2, "", "resolution failed")
        return RunResult(0, "", "")


_LISTING = "tmap-agents v0.1.0\n- tmap\n"


def _plan(tmp_path: Path, uv: _Uv, prefix: Path, latest: str | None = "0.2.0") -> up.UpdatePlan:
    return up.plan_update(
        current="0.1.0",
        latest=latest,
        prefix=prefix,
        home=tmp_path,
        path_env="",
        which={"uv": "/x/uv"}.get,
        run=uv,
        tmap_command=None,
    )


def test_the_plan_installs_the_newest_and_touches_no_other_tool(tmp_path: Path) -> None:
    """Another uv tool — whatever its name — is not tmap's to remove.

    MUTATION: uninstall a tool by its name (the unrelated PyPI `treasure-map`) -> RED."""
    tools = tmp_path / "tools"
    (tools / "tmap-agents").mkdir(parents=True)
    uv = _Uv(tools, _LISTING + "treasure-map v0.1.3\n- dof\n")
    plan = _plan(tmp_path, uv, tools / "tmap-agents")
    assert plan.from_uv_tool and plan.newer
    assert not any("uninstall" in ln for ln in up.plan_lines(plan))
    assert plan.install_argv("0.2.0")[-1] == "tmap-agents==0.2.0"


def test_a_tmap_uv_does_not_manage_is_left_alone(tmp_path: Path) -> None:
    """★ An editable checkout or a pip install: no uv command at all.

    MUTATION: treat any install as uv's -> RED."""
    tools = tmp_path / "tools"
    (tools / "tmap-agents").mkdir(parents=True)
    plan = _plan(tmp_path, _Uv(tools, _LISTING), tmp_path / "venv")
    assert not plan.from_uv_tool and not plan.has_work
    assert any("not updated here" in ln for ln in up.plan_lines(plan))


def test_other_tmaps_on_path_are_named(tmp_path: Path) -> None:
    keep = fakes._exe(tmp_path / "uvbin" / "tmap")
    other = fakes._exe(tmp_path / "pipbin" / "tmap")
    link_dir = tmp_path / "linkbin"
    link_dir.mkdir()
    (link_dir / "tmap").symlink_to(keep)  # the same command reached twice is not "another"
    path = os.pathsep.join(str(d) for d in (keep.parent, other.parent, link_dir))
    assert up.other_tmaps(path, keep) == [other]


def _cli(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, uv: _Uv, args: list[str], latest: str | None
) -> tuple[str, int, list[list[str]]]:
    import sys

    from treasure_map.cli import update_cli
    from treasure_map.lib.setup import discover

    tools = uv.tools_dir
    monkeypatch.setattr(sys, "prefix", str(tools / "tmap-agents"))
    monkeypatch.setattr(up, "fetch_latest_version", lambda: latest if latest else _raise())
    host = fakes.make_host(Path.home(), which={"uv": "/x/uv"}, run=uv)
    monkeypatch.setattr(discover, "current_host", lambda _p: host)
    execs: list[list[str]] = []

    def fake_exec(_f: str, argv: list[str]) -> None:
        execs.append(list(argv))
        raise SystemExit(0)

    monkeypatch.setattr(os, "execvp", fake_exec)
    tmap = fakes._exe(tmp_path / "bin" / "tmap")
    monkeypatch.setattr("treasure_map.lib.setup.clients.tmap_executable", lambda: tmap)
    result = CliRunner().invoke(update_cli.update, args)
    return result.output, result.exit_code, execs


def _raise() -> str:
    raise OSError("offline")


def test_update_installs_the_newest_then_runs_the_new_init(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ One change — the tmap-agents install, whatever other uv tools exist (an unrelated PyPI
    `treasure-map` among them) — and the NEW program runs init.

    MUTATION: uninstall another tool by its name -> RED."""
    tools = tmp_path / "tools"
    (tools / "tmap-agents").mkdir(parents=True)
    uv = _Uv(tools, _LISTING + "treasure-map v0.1.3\n- dof\n")
    out, code, execs = _cli(monkeypatch, tmp_path, uv, ["--yes"], "0.2.0")
    changes = [c for c in uv.calls if c[1:3] in (["tool", "uninstall"], ["tool", "install"])]
    assert changes == [
        ["/x/uv", "tool", "install", "--force", "--python", "3.11", "tmap-agents==0.2.0"],
    ]
    assert execs and execs[0][-1] == "init" and code == 0


def test_check_changes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tools = tmp_path / "tools"
    (tools / "tmap-agents").mkdir(parents=True)
    uv = _Uv(tools, _LISTING)
    out, _code, execs = _cli(monkeypatch, tmp_path, uv, ["--check", "--yes"], "0.2.0")
    assert "tmap 0.2.0 (newer)" in out and execs == []
    assert all(c[1:3] in (["tool", "dir"], ["tool", "list"]) for c in uv.calls)


def test_check_without_an_answer_exits_non_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--check`` that could not learn the newest version has no answer to give.

    MUTATION: return before the unreachable-PyPI exit when --check is set -> RED (exit 0)."""
    tools = tmp_path / "tools"
    (tools / "tmap-agents").mkdir(parents=True)
    uv = _Uv(tools, _LISTING)
    out, code, execs = _cli(monkeypatch, tmp_path, uv, ["--check"], None)
    assert "could not reach PyPI" in out
    assert code == 1 and execs == []


def test_a_failed_install_puts_the_current_version_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION: drop the put-back -> a failed update leaves no tmap command -> RED."""
    tools = tmp_path / "tools"
    (tools / "tmap-agents").mkdir(parents=True)
    uv = _Uv(tools, _LISTING, fail="tmap-agents==0.2.0")
    out, code, execs = _cli(monkeypatch, tmp_path, uv, ["--yes"], "0.2.0")
    assert code == 1 and execs == [] and "put back" in out
    # the version running now — the one a failed update must leave installed
    assert uv.calls[-1][-1] == f"tmap-agents=={__version__}"


def test_up_to_date_and_nothing_old_means_nothing_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tools = tmp_path / "tools"
    (tools / "tmap-agents").mkdir(parents=True)
    uv = _Uv(tools, f"tmap-agents v{__version__}\n- tmap\n")
    out, code, execs = _cli(monkeypatch, tmp_path, uv, ["--yes"], __version__)
    assert "up to date" in out and code == 0 and execs == []


def test_the_help_says_what_update_does() -> None:
    """The help shown by `tmap --help` and `tmap update --help` describes the in-place install
    and the hand-over to init — not a removal of another tool, which update does not do.

    MUTATION: put back "and remove the old one" in the short help -> RED."""
    from treasure_map.cli.update_cli import update

    assert update.short_help == "Update tmap to the newest version, then run its init"
    text = CliRunner().invoke(update, ["--help"]).output
    assert "in place of this one" in text and "tmap init" in text
    assert "remove" not in (update.short_help or "") + text.replace("never removed", "")
