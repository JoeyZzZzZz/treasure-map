# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The two release workflows run tmap code before anything is published; the parts of them that
can be checked off GitHub are checked here."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

_WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"
# a heredoc script line that imports tmap, and a `python -c '...'` one-liner that does (its
# interpreter captured)
_IMPORTS_TMAP = re.compile(r"^\s*(from|import)\s+treasure_map\b", re.MULTILINE)
_ONE_LINER = re.compile(r"([\w/.]*python3?) -c '[^']*\b(?:from|import)\s+treasure_map\b")


def test_the_binexport_export_smoke_finds_the_export_script() -> None:
    """The export smoke's own one-liner, run as written, prints the directory that holds the export
    script.

    MUTATION: take the directory from ``treasure_map.lib.diff.ghidra.__file__`` (a namespace
    package: None) -> the one-liner fails -> RED."""
    text = (_WORKFLOWS / "binexport.yml").read_text()
    match = re.search(r"""SCRIPTS="\$\(python -c '([^']+)'\)\"""", text)
    assert match is not None, "the export smoke no longer computes SCRIPTS with python -c"
    res = subprocess.run(  # noqa: S603 -- the workflow's fixed one-liner
        [sys.executable, "-c", match.group(1)], capture_output=True, text=True, timeout=60
    )
    assert res.returncode == 0, res.stderr
    assert (Path(res.stdout.strip()) / "ExportBinExport.java").is_file()


def _steps(name: str) -> list[dict[str, Any]]:
    doc = yaml.safe_load((_WORKFLOWS / name).read_text())
    return [s for job in doc["jobs"].values() for s in job["steps"]]


def test_the_release_imports_tmap_only_from_the_installed_venv() -> None:
    """The runner's Python has only pip and build; tmap's dependencies are in the venv the
    install step makes. So every step that imports tmap runs after that step, with the venv's
    Python, never from the checkout — and the lock check still runs before anything is published.

    MUTATION: check the lock with the runner's Python and PYTHONPATH=src before the install step
    (``import yaml`` fails there) -> RED. MUTATION: check it after the PyPI upload -> RED."""
    steps = _steps("release.yml")
    install = next(i for i, s in enumerate(steps) if "/tmp/v/bin/pip install" in s.get("run", ""))
    publish = next(i for i, s in enumerate(steps) if "pypi-publish" in s.get("uses", ""))
    importers = [i for i, s in enumerate(steps) if _IMPORTS_TMAP.search(s.get("run", ""))]
    assert importers, "no step imports tmap: the lock check is gone"
    for i in importers:
        run = steps[i]["run"]
        assert i > install, f"step {steps[i].get('name')!r} imports tmap before it is installed"
        assert "PYTHONPATH" not in (steps[i].get("env") or {})
        assert re.search(r"/tmp/v/bin/python -I -", run), steps[i].get("name")
    lock_check = next(i for i in importers if "placeholders(" in steps[i]["run"])
    assert lock_check < publish
    for i, s in enumerate(steps):
        for interpreter in _ONE_LINER.findall(s.get("run", "")):
            assert interpreter == "/tmp/v/bin/python" and i >= install, s.get("name")
