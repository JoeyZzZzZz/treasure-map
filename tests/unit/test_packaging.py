# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Regression guard: the wheel must ship the non-.py runtime assets.

A built wheel only carries files declared under [tool.setuptools.package-data]; without
them a pipx/pip install produces a tmap whose analyze (Ghidra headless export) and schema
creation fail at runtime, while editable installs hide the gap. These tests fail fast if
(a) an asset can no longer be resolved from the installed package, or (b) the package-data
declaration is dropped from pyproject.toml.
"""

from __future__ import annotations

import importlib.util
import tomllib
from importlib.resources import files
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_PYPROJECT = _ROOT / "pyproject.toml"


def _load_asset_list() -> tuple[tuple[str, str], ...]:
    """The ONE asset list (scripts/wheel_assets.py), also read by CI and the release."""
    spec = importlib.util.spec_from_file_location("wheel_assets", _ROOT / "scripts/wheel_assets.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.ASSETS  # type: ignore[no-any-return]


# (package, resource) pairs for every non-.py asset the runtime loads from disk. Under an editable
# install this resolves from the source tree; CI's package job checks the BUILT wheel installed
# into a fresh venv, which is the check an editable install cannot fake.
_ASSETS = _load_asset_list()


def test_runtime_assets_are_resolvable() -> None:
    # Resolves the same way an installed wheel exposes them; missing data files fail here.
    for package, resource in _ASSETS:
        path = files(package) / resource
        assert path.is_file(), f"{package}/{resource} not packaged"


def test_pyproject_declares_package_data() -> None:
    # Guards against someone deleting the package-data globs (which would silently strip the
    # assets from the next wheel without any test resolving them from the source tree).
    data = tomllib.loads(_PYPROJECT.read_text())
    package_data = data["tool"]["setuptools"]["package-data"]
    assert "*.java" in package_data["treasure_map.lib.analyze.ghidra"]
    assert "*.tsv" in package_data["treasure_map.lib.analyze.ghidra"]
    assert "*.java" in package_data["treasure_map.lib.diff.ghidra"]
    assert "*.sql" in package_data["treasure_map.lib.storage"]
    assert "*.json" in package_data["treasure_map.lib.setup"]
    assert "*.md" in package_data["treasure_map.skills"]


def test_one_command_and_one_version_source() -> None:
    """``tmap`` is the only command, under two names: the MCP registry publishes
    ``uvx tmap-agents mcp`` and uvx runs the command named after the package, so the distribution
    name is an ALIAS of the same callable. What this holds out is a second entry point with its
    OWN behaviour — ``treasure-map-mcp`` was one, it bound a relative atlas.db, and it is gone.
    The version is read from treasure_map/version.py, not written twice.

    MUTATION (verified RED): point the alias at another callable, or add a third name -> RED."""
    data = tomllib.loads(_PYPROJECT.read_text())
    project = data["project"]
    assert project["name"] == "tmap-agents"
    assert project["scripts"] == {
        "tmap": "treasure_map.cli.main:main",
        project["name"]: "treasure_map.cli.main:main",
    }
    assert len(set(project["scripts"].values())) == 1  # one callable, whatever it is called
    assert "version" not in project and "version" in project["dynamic"]
    attr = data["tool"]["setuptools"]["dynamic"]["version"]["attr"]
    assert attr == "treasure_map.version.__version__"
