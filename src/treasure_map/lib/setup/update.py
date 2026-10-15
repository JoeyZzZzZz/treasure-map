# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""``tmap update``: install the newest tmap.

Only a tmap installed with ``uv tool install tmap-agents`` is updated in place — tmap cannot know
how else it was installed, so any other install is told how to update itself and left alone. The
update replaces the ``tmap-agents`` tool environment (``uv tool install --force``) and names every
other ``tmap`` on PATH that would shadow the new one. It then hands over to the NEW version's
``tmap init``, which checks the toolchain and agent entries that version expects.

The only network access is one request for the newest published version.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from treasure_map.lib.setup.discover import Runner

DIST = "tmap-agents"
PYPI_JSON = f"https://pypi.org/pypi/{DIST}/json"

_VERSION_RE = re.compile(r"^(\d+(?:\.\d+)*)(.*)$")


def version_key(version: str) -> tuple[tuple[int, ...], int, str]:
    """A sortable key: the release numbers, then a final release above any pre-release suffix
    (``0.2.0rc1`` < ``0.2.0``)."""
    m = _VERSION_RE.match(version.strip())
    if m is None:
        return ((), 0, version)
    numbers = tuple(int(x) for x in m.group(1).split("."))
    while len(numbers) > 1 and numbers[-1] == 0:
        numbers = numbers[:-1]
    suffix = m.group(2)
    return (numbers, 0 if suffix else 1, suffix)


def is_newer(candidate: str, current: str) -> bool:
    return version_key(candidate) > version_key(current)


def fetch_latest_version(timeout: float = 15.0) -> str:
    """The newest version of tmap-agents on PyPI (yanked and pre-releases are skipped)."""
    import urllib.request

    req = urllib.request.Request(PYPI_JSON, headers={"User-Agent": "tmap-update"})  # noqa: S310
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        data = json.loads(resp.read())
    releases = data.get("releases") or {}
    finals: list[str] = []
    for version, files in releases.items():
        m = _VERSION_RE.match(str(version))
        if m is None or m.group(2) or not files:
            continue  # unparsable, a pre-release, or nothing published
        if all(isinstance(f, dict) and f.get("yanked") for f in files):
            continue
        finals.append(str(version))
    if finals:
        return max(finals, key=version_key)
    return str(data["info"]["version"])


def find_uv(home: Path, which: Callable[[str], str | None]) -> str | None:
    uv = which("uv")
    if uv is not None:
        return uv
    for cand in (home / ".local" / "bin" / "uv", home / ".cargo" / "bin" / "uv"):
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return None


def uv_tool_dir(uv: str, run: Runner) -> Path | None:
    res = run([uv, "tool", "dir"])
    if res is None or res.returncode != 0 or not res.stdout.strip():
        return None
    return Path(res.stdout.strip().splitlines()[-1])


def runs_from_uv_tool(prefix: Path, uv: str, run: Runner) -> bool:
    """Is this tmap running from uv's ``tmap-agents`` tool environment?"""
    tools = uv_tool_dir(uv, run)
    return tools is not None and os.path.realpath(prefix) == os.path.realpath(tools / DIST)


def other_tmaps(path_env: str, keep: Path | None) -> list[Path]:
    """Every ``tmap`` on PATH other than ``keep`` (the uv tool's command)."""
    seen: set[str] = set()
    found: list[Path] = []
    keep_real = os.path.realpath(keep) if keep is not None else None
    for d in path_env.split(os.pathsep):
        if not d:
            continue
        p = Path(d) / "tmap"
        if not (p.is_file() and os.access(p, os.X_OK)):
            continue
        real = os.path.realpath(p)
        if real in seen or (keep is not None and (p == keep or real == keep_real)):
            continue
        seen.add(real)
        found.append(p)
    return found


@dataclass
class UpdatePlan:
    current: str
    latest: str | None
    uv: str | None
    from_uv_tool: bool
    shadowing: list[Path] = field(default_factory=list)
    reason: str = ""  # why tmap will not update itself (another kind of install)

    @property
    def newer(self) -> bool:
        return self.latest is not None and is_newer(self.latest, self.current)

    @property
    def has_work(self) -> bool:
        return self.from_uv_tool and self.newer

    def install_argv(self, version: str) -> list[str]:
        assert self.uv is not None
        return [self.uv, "tool", "install", "--force", "--python", "3.11", f"{DIST}=={version}"]


def plan_update(
    *,
    current: str,
    latest: str | None,
    prefix: Path,
    home: Path,
    path_env: str,
    which: Callable[[str], str | None],
    run: Runner,
    tmap_command: Path | None,
) -> UpdatePlan:
    uv = find_uv(home, which)
    if uv is None:
        return UpdatePlan(current, latest, None, False, reason="uv is not installed")
    from_uv = runs_from_uv_tool(prefix, uv, run)
    if not from_uv:
        return UpdatePlan(
            current,
            latest,
            uv,
            False,
            reason="this tmap was not installed with `uv tool install tmap-agents`",
        )
    return UpdatePlan(current, latest, uv, True, shadowing=other_tmaps(path_env, tmap_command))


def plan_lines(plan: UpdatePlan) -> list[str]:
    lines = [f"installed: tmap {plan.current}"]
    if plan.latest is None:
        lines.append("newest:    unknown (not read from PyPI)")
    else:
        state = "newer" if plan.newer else "already installed"
        lines.append(f"newest:    tmap {plan.latest} ({state})")
    if not plan.from_uv_tool:
        lines.append(f"not updated here: {plan.reason}")
        return lines
    if plan.newer and plan.latest is not None:
        lines.append(f"install: {' '.join(plan.install_argv(plan.latest)[1:])}")
        lines.append("then: tmap init (the new version checks its toolchain and agent entries)")
    for p in plan.shadowing:
        lines.append(f"another tmap on PATH, not managed by uv (remove it yourself): {p}")
    return lines


def manual_update_hint() -> str:
    """How to update a tmap that tmap does not manage."""
    direct = None
    try:
        from importlib.metadata import distribution

        direct = distribution(DIST).read_text("direct_url.json")
    except Exception:
        direct = None
    if direct and '"editable": true' in direct.replace("'", '"'):
        return "this is an editable checkout: `git pull` there, then run `tmap init`"
    return (
        "update it the way you installed it, or move to the managed install: "
        "`uv tool install --python 3.11 tmap-agents` (then remove the old one)"
    )


def run_steps(argvs: Sequence[list[str]], run: Runner) -> tuple[bool, str]:
    for argv in argvs:
        res = run(argv, timeout=900)
        if res is None or res.returncode != 0:
            tail = ((res.stderr or res.stdout) if res else "").strip().splitlines()
            return False, f"`{' '.join(argv[1:])}` failed: {tail[-1] if tail else 'did not run'}"
    return True, ""
