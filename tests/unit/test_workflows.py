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


def test_ci_runs_the_rescan_stamp_backstop_on_a_checkout_holding_its_base() -> None:
    """CI compares the rescan fixture's output against HEAD~1 whenever the code stamps are equal;
    that needs the script to run and the checkout to hold HEAD~1 (the default clone is one commit
    deep, where the check could only error).

    MUTATION (verified RED, 1 failed): drop ``fetch-depth: 2`` from the rescan-stamps checkout ->
    RED."""
    ci = yaml.safe_load((_WORKFLOWS / "ci.yml").read_text())
    steps = ci["jobs"]["rescan-stamps"]["steps"]
    checkout = next(s for s in steps if s.get("uses", "").startswith("actions/checkout@"))
    depth = int((checkout.get("with") or {}).get("fetch-depth", 1))
    assert depth == 0 or depth >= 2, f"fetch-depth {depth} holds no HEAD~1"
    assert any("scripts/rescan_same_stamp_check.py" in s.get("run", "") for s in steps)


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


_ROOT = Path(__file__).resolve().parents[2]
_SECTION = _ROOT / "scripts" / "changelog_section.py"


def _changelog_section(version: str, changelog: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- this repository's own script
        [sys.executable, str(_SECTION), version, str(changelog)],
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_changelog_section_prints_one_version_body_and_refuses_a_missing_one(
    tmp_path: Path,
) -> None:
    """The release body is one version's section: heading left out, stopping at the next version
    or the link-reference block, never a neighbouring version whose number starts the same. A
    missing or empty section exits non-zero with nothing on stdout, so the release step stops.

    MUTATION: stop only at ``## [`` headings (not the link block) -> RED. MUTATION: match the
    heading as a bare prefix (``0.1.1`` finds ``0.1.10``) -> RED. MUTATION: return the empty
    section instead of raising -> RED."""
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        "# Changelog\n\nPreamble.\n\n"
        "## [0.1.10] - 2026-12-01\n\nTen.\n\n"
        "## [0.1.2] - 2026-11-01\n\n\n"
        "## [0.1.1] - 2026-10-26\n\nOne.\n\n### Fixed\n\n- a fix\n\n"
        "[0.1.10]: https://example.invalid/0.1.10\n"
        "[0.1.1]: https://example.invalid/0.1.1\n",
        encoding="utf-8",
    )
    one = _changelog_section("0.1.1", changelog)
    assert one.returncode == 0, one.stderr
    assert one.stdout == "One.\n\n### Fixed\n\n- a fix\n"
    ten = _changelog_section("0.1.10", changelog)
    assert ten.returncode == 0, ten.stderr
    assert ten.stdout == "Ten.\n"
    for version in ("0.1.2", "0.1", "9.9.9"):  # empty section; prefix only; absent
        res = _changelog_section(version, changelog)
        assert res.returncode != 0, version
        assert res.stdout == "", version
        assert f"[{version}]" in res.stderr, version


def test_the_current_version_has_a_release_body() -> None:
    """Bumping __version__ without its CHANGELOG section would fail the release mid-way; this
    fails it in CI first. The body is the section's text, not the heading or the next version.

    MUTATION: rename the current version's heading in CHANGELOG.md -> RED."""
    import runpy

    version = runpy.run_path(str(_ROOT / "src" / "treasure_map" / "version.py"))["__version__"]
    res = _changelog_section(version, _ROOT / "CHANGELOG.md")
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip()
    assert not re.search(r"^## ", res.stdout, re.MULTILINE)


def test_the_release_body_comes_from_the_changelog_before_anything_is_built() -> None:
    """The notes are taken in the first step (so a missing section stops the release before the
    build and the PyPI upload), and the draft gets them both when it is created and when a re-run
    finds it already there. Before this, the body was one fixed line, edited by hand afterwards.

    MUTATION: create the draft with ``--notes "..."`` -> RED. MUTATION: drop the ``gh release
    edit --notes-file`` from the re-run branch -> RED. MUTATION: take the notes after the
    PyPI upload -> RED."""
    steps = _steps("release.yml")
    take = re.compile(
        r'^\s*python scripts/changelog_section\.py "\$V" CHANGELOG\.md > "(?P<f>[^"]+)"$',
        re.MULTILINE,
    )
    taken = [(i, m.group("f")) for i, s in enumerate(steps) if (m := take.search(s.get("run", "")))]
    assert len(taken) == 1, taken
    at, notes = taken[0]
    build = next(i for i, s in enumerate(steps) if "python -m build" in s.get("run", ""))
    publish = next(i for i, s in enumerate(steps) if "pypi-publish" in s.get("uses", ""))
    assert at < build < publish
    assert "set -e" in steps[at]["run"]
    run = next(s["run"] for s in steps if "gh release create" in s.get("run", ""))
    rerun, _, create = run.partition("else")
    assert "gh release create" in create and "gh release upload" in rerun
    assert f'--notes-file "{notes}"' in create
    assert re.search(rf'gh release edit [^\n]*--notes-file "{re.escape(notes)}"', rerun)
    assert "--notes " not in run
