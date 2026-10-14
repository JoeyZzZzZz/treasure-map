# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Which commit the running tmap was built from — and when that cannot be trusted.

A wheel from the package index carries no ``direct_url.json``, so the release build bakes the
commit into ``treasure_map/_build_info.py``. Everywhere else (git, a local directory, a wheel
installed by path, an editable checkout) only the VCS record is trusted: a ``_build_info.py`` left
in such a tree may describe a different build."""

from __future__ import annotations

import sys
import types

import pytest

from treasure_map import version as tm_version
from treasure_map.version import UNKNOWN_VERSION

BAKED = "a" * 40
VCS = "b" * 40


class _Dist:
    def __init__(self, direct_url: str | None) -> None:
        self.direct_url = direct_url

    def read_text(self, name: str) -> str | None:
        return self.direct_url if name == "direct_url.json" else None


def _install(monkeypatch: pytest.MonkeyPatch, **dists: _Dist) -> None:
    def distribution(name: str) -> _Dist:
        if name not in dists:
            raise ModuleNotFoundError(name)
        return dists[name]

    monkeypatch.setattr(tm_version, "distribution", distribution)


@pytest.fixture()
def baked(monkeypatch: pytest.MonkeyPatch) -> None:
    module = types.ModuleType("treasure_map._build_info")
    module.COMMIT = BAKED  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "treasure_map._build_info", module)


def test_an_index_install_reads_the_baked_commit(
    monkeypatch: pytest.MonkeyPatch, baked: None
) -> None:
    _install(monkeypatch, **{"tmap-agents": _Dist(None)})
    assert tm_version.installed_commit() == BAKED


def test_a_direct_url_install_never_reads_the_baked_commit(
    monkeypatch: pytest.MonkeyPatch, baked: None
) -> None:
    """★ An editable checkout, or a wheel installed by path, with a leftover _build_info.py:
    unknown, not the leftover commit.

    MUTATION: fall back to the baked commit whenever the VCS record has none -> RED."""
    for record in (
        '{"url":"file:///src","dir_info":{"editable":true}}',
        '{"url":"file:///dist/tmap_agents-0.1.0-py3-none-any.whl","archive_info":{}}',
    ):
        _install(monkeypatch, **{"tmap-agents": _Dist(record)})
        assert tm_version.installed_commit() == UNKNOWN_VERSION, record


def test_a_vcs_install_reads_its_commit(monkeypatch: pytest.MonkeyPatch, baked: None) -> None:
    record = f'{{"url":"https://x/y.git","vcs_info":{{"vcs":"git","commit_id":"{VCS}"}}}}'
    _install(monkeypatch, **{"tmap-agents": _Dist(record)})
    assert tm_version.installed_commit() == VCS


def test_the_old_distribution_name_still_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    record = f'{{"url":"https://x/y.git","vcs_info":{{"vcs":"git","commit_id":"{VCS}"}}}}'
    _install(monkeypatch, **{"treasure-map": _Dist(record)})
    assert tm_version.installed_commit() == VCS


def test_both_names_installed_is_unknown(monkeypatch: pytest.MonkeyPatch, baked: None) -> None:
    """Two distributions in one environment: which one is running cannot be told.

    MUTATION: read the first one found -> RED."""
    record = f'{{"url":"https://x/y.git","vcs_info":{{"vcs":"git","commit_id":"{VCS}"}}}}'
    _install(monkeypatch, **{"tmap-agents": _Dist(record), "treasure-map": _Dist(record)})
    assert tm_version.installed_commit() == UNKNOWN_VERSION


def test_a_malformed_baked_commit_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    module = types.ModuleType("treasure_map._build_info")
    module.COMMIT = "not-a-commit"  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "treasure_map._build_info", module)
    _install(monkeypatch, **{"tmap-agents": _Dist(None)})
    assert tm_version.installed_commit() == UNKNOWN_VERSION


def test_tmap_version_flag() -> None:
    from click.testing import CliRunner

    from treasure_map.cli.main import main

    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"tmap {tm_version.__version__}"
