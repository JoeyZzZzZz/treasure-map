# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""server.json agrees with the package it points at (scripts/check_server_json.py).

The MCP registry publishes metadata only: at publish time it fetches the named PyPI package and
reads an ``mcp-name:`` marker out of its description to prove ownership. That step runs AFTER PyPI
has the version, and a PyPI version cannot be re-used — so each of these disagreements has to be
caught before the tag, not at the last step of the release.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "check_server_json", ROOT / "scripts" / "check_server_json.py"
)
assert _SPEC is not None and _SPEC.loader is not None
_MOD = importlib.util.module_from_spec(_SPEC)
sys.modules["check_server_json"] = _MOD
_SPEC.loader.exec_module(_MOD)
problems: Callable[[Path], list[str]] = _MOD.problems


def _copy_repo_metadata(dst: Path) -> Path:
    """The four files the gate reads, copied out of the real repo so a test may edit one."""
    (dst / "src" / "treasure_map").mkdir(parents=True, exist_ok=True)
    readme = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "readme"
    ]
    for rel in ("server.json", "pyproject.toml", readme, "src/treasure_map/version.py"):
        shutil.copyfile(ROOT / rel, dst / rel)
    assert problems(dst) == [], "the copy itself must start consistent"
    return dst


def _edit_server_json(root: Path, change: Callable[[dict[str, Any]], None]) -> None:
    path = root / "server.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    change(doc)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def test_the_real_repo_agrees_with_itself() -> None:
    """The one that fails when a version is bumped in three files out of four.

    MUTATION (verified RED): set server.json's version to 0.0.1 -> two problems reported."""
    assert problems(ROOT) == []


@pytest.mark.parametrize("where", ["top-level", "package"])
def test_a_version_bumped_in_only_some_places_is_caught(tmp_path: Path, where: str) -> None:
    """__version__ is the authority: the release already refuses a tag that does not match it, and
    server.json carries the same number twice more.

    MUTATION (verified RED, 2 failed): drop either version comparison from the gate -> the
    mismatched file passes."""
    root = _copy_repo_metadata(tmp_path)
    if where == "top-level":
        _edit_server_json(root, lambda d: d.__setitem__("version", "9.9.9"))
    else:
        _edit_server_json(root, lambda d: d["packages"][0].__setitem__("version", "9.9.9"))
    found = problems(root)
    assert len(found) == 1 and "9.9.9" in found[0] and "__version__" in found[0], found


def test_a_readme_that_lost_the_marker_is_caught(tmp_path: Path) -> None:
    """Without the marker in the PyPI description the registry cannot prove we own the package, so
    the publish fails — after the version is already on PyPI.

    MUTATION (verified RED): drop the marker lookup from the gate -> a bare README passes."""
    root = _copy_repo_metadata(tmp_path)
    readme = root / "README.md"
    text = readme.read_text(encoding="utf-8")
    name = json.loads((root / "server.json").read_text(encoding="utf-8"))["name"]
    readme.write_text(text.replace(f"mcp-name: {name}", "a readme with no marker", 1), "utf-8")
    found = problems(root)
    assert len(found) == 1 and "mcp-name" in found[0], found


def test_a_marker_glued_to_the_next_character_is_caught(tmp_path: Path) -> None:
    """The registry needs a boundary after the name — a newline, whitespace, an HTML tag or the
    comment close. Glued to a sentence-ending period the name does not match, and the marker is
    there to be read, so "present" is not the same as "readable".

    MUTATION (verified RED): drop the boundary check -> the glued marker passes."""
    root = _copy_repo_metadata(tmp_path)
    readme = root / "README.md"
    name = json.loads((root / "server.json").read_text(encoding="utf-8"))["name"]
    text = readme.read_text(encoding="utf-8")
    readme.write_text(text.replace(f"mcp-name: {name} -->", f"mcp-name: {name}.", 1), "utf-8")
    found = problems(root)
    assert len(found) == 1 and "boundary" in found[0], found


def test_an_identifier_that_is_not_the_distribution_name_is_caught(tmp_path: Path) -> None:
    """The identifier is what the registry resolves on PyPI; the import package and the
    distribution differ here, so naming the wrong one is an easy mistake.

    A wrong identifier also loses the console script uvx would look for, so the gate reports both
    — it is exhaustive on purpose, the way the publisher's own validate is.

    MUTATION (verified RED): drop the identifier comparison -> only the entry-point problem is
    left, and the first assertion fails."""
    root = _copy_repo_metadata(tmp_path)
    _edit_server_json(root, lambda d: d["packages"][0].__setitem__("identifier", "treasure-map"))
    found = problems(root)
    assert any("distribution name" in f for f in found), found
    assert any("entry point" in f for f in found), found
    assert len(found) == 2, found


def test_a_uvx_hint_without_the_console_script_it_needs_is_caught(tmp_path: Path) -> None:
    """A client told ``runtimeHint: uvx`` runs ``uvx <identifier> mcp``, and uvx runs the command
    named after the package. Drop that entry point and every published call fails to start, with
    nothing here to say why.

    MUTATION (verified RED): drop the runtimeHint branch -> a pyproject with only `tmap` passes."""
    root = _copy_repo_metadata(tmp_path)
    pp = root / "pyproject.toml"
    name = json.loads((root / "server.json").read_text(encoding="utf-8"))["packages"][0][
        "identifier"
    ]
    text = pp.read_text(encoding="utf-8")
    assert f'{name} = "treasure_map.cli.main:main"\n' in text
    pp.write_text(text.replace(f'{name} = "treasure_map.cli.main:main"\n', "", 1), "utf-8")
    found = problems(root)
    assert len(found) == 1 and "entry point" in found[0], found
