# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Regression guard: the wheel must ship the non-.py runtime assets.

A built wheel only carries files declared under [tool.setuptools.package-data]; without
them a pipx/pip install produces a tmap whose analyze (Ghidra headless export) and schema
creation fail at runtime, while editable installs hide the gap. These tests fail fast if
(a) an asset can no longer be resolved from the installed package, or (b) the package-data
declaration is dropped from pyproject.toml.
"""

from __future__ import annotations

import tomllib
from importlib.resources import files
from pathlib import Path

_PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"

# (package, resource) pairs for every non-.py asset the runtime loads from disk.
_ASSETS = [
    ("treasure_map.lib.analyze.ghidra", "ExportFunctions.java"),
    ("treasure_map.lib.storage", "atlas_schema.sql"),
    ("treasure_map.lib.storage", "schema.sql"),
]


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
    assert "*.sql" in package_data["treasure_map.lib.storage"]
