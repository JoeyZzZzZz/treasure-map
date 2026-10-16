# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The two release workflows run tmap code before anything is published; the parts of them that
can be checked off GitHub are checked here."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import zipfile
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
    return [s for job in doc["jobs"].values() for s in job.get("steps", [])]


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


def test_nothing_is_published_unless_the_whole_ci_passes() -> None:
    """A v* tag used to publish straight to PyPI whatever the tests said.

    MUTATION: drop ``needs: ci`` from the release job -> RED. MUTATION: drop ``workflow_call``
    from ci.yml (the release could no longer run it) -> RED. MUTATION: drop ``secrets: inherit``
    from the ci job -> RED (observed: 1 failed) — a reusable workflow gets no secrets by default,
    so the release-time neutrality check would silently fall back to the brand-free example."""
    release = yaml.safe_load((_WORKFLOWS / "release.yml").read_text())
    jobs = release["jobs"]
    assert jobs["ci"]["uses"] == "./.github/workflows/ci.yml"
    # The private watchlist is a repository secret; the reusable CI workflow only sees it when the
    # caller forwards it.
    assert jobs["ci"].get("secrets") == "inherit"
    assert jobs["release"].get("needs") in ("ci", ["ci"])
    ci = yaml.safe_load((_WORKFLOWS / "ci.yml").read_text())
    # PyYAML reads the bare key `on` as the boolean True.
    triggers = ci.get("on", ci.get(True))
    assert "workflow_call" in triggers
    for name in ("test", "lint", "typecheck", "integration", "package"):
        assert name in ci["jobs"], name


def test_every_third_party_action_is_pinned_to_a_commit() -> None:
    """A tag can be moved to other code; a 40-character commit cannot. The release job holds
    id-token: write, so what runs there must be exactly what was reviewed.

    MUTATION: write any action as @v4 -> RED."""
    pinned = re.compile(r"^[\w.-]+/[\w.-]+(?:/[\w.-]+)*@[0-9a-f]{40}$")
    for wf in sorted(_WORKFLOWS.glob("*.yml")):
        doc = yaml.safe_load(wf.read_text())
        for job in doc["jobs"].values():
            uses = [job["uses"]] if "uses" in job else []
            uses += [s["uses"] for s in job.get("steps", []) if "uses" in s]
            for ref in uses:
                if ref.startswith("./"):
                    continue  # this repository's own reusable workflow
                assert pinned.match(ref), f"{wf.name}: {ref} is not pinned to a commit"


def _clean_lock() -> dict[str, Any]:
    """A fully-resolved toolchain lock: schema 1, all components present, no placeholder values."""
    asset = {"url": "https://example.invalid/a.zip", "sha256": "0" * 64, "size": 7, "kind": "zip"}
    component = {"version": "1.0", "assets": {"linux-x86_64": asset}}
    return {
        "schema": 1,
        "components": {
            name: json.loads(json.dumps(component))
            for name in ("jdk", "ghidra", "binexport", "bindiff")
        },
    }


def test_the_release_lock_check_exits_nonzero_on_a_placeholder(tmp_path: Path) -> None:
    """The release step that guards the shipped lock must EXIT NON-ZERO (not merely print) when a
    placeholder is left, or a lock naming an unpublished artifact could ship. The step's own
    Python is run here over a wheel whose toolchain_lock.json still has a placeholder; a
    fully-resolved lock is the control, so the failure is the placeholder and not noise.

    MUTATION: change the step's ``sys.exit(...)`` to ``print(...)`` in release.yml -> it exits 0
    -> RED (observed: the placeholder run returns 0)."""
    run = next(s["run"] for s in _steps("release.yml") if "placeholders(" in s.get("run", ""))
    match = re.search(r"<<'PY'\n(.*?)\nPY\b", run, re.DOTALL)
    assert match is not None, "the lock check no longer uses a PY heredoc"
    code = match.group(1)

    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")

    def run_over(lock: dict[str, Any], tag: str) -> subprocess.CompletedProcess[str]:
        work = tmp_path / tag
        (work / "dist").mkdir(parents=True)
        with zipfile.ZipFile(work / "dist" / "pkg.whl", "w") as whl:
            whl.writestr("treasure_map/lib/setup/toolchain_lock.json", json.dumps(lock))
        return subprocess.run(  # noqa: S603 -- the workflow's own fixed heredoc
            [sys.executable, "-"],
            input=code,
            cwd=str(work),
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )

    with_placeholder = _clean_lock()
    with_placeholder["components"]["binexport"]["assets"]["linux-x86_64"]["url"] = "<unpublished>"
    bad = run_over(with_placeholder, "bad")
    assert bad.returncode != 0, f"must fail on a placeholder; out={bad.stdout!r} err={bad.stderr!r}"
    assert "placeholders" in (bad.stdout + bad.stderr)

    good = run_over(_clean_lock(), "good")
    assert good.returncode == 0, f"clean lock must pass; out={good.stdout!r} err={good.stderr!r}"
