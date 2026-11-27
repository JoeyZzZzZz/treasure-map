# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The agent skills tmap ships are finished files in the package, where a skill catalogue that
reads the repository finds them: ``src/treasure_map/skills/<name>/SKILL.md``, the very bytes
``tmap init`` installs. A catalogue that searches the whole tree takes every ``SKILL.md`` it
meets, so the repository holds no other."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from treasure_map.lib.setup import skills as sk

_ROOT = Path(__file__).resolve().parents[2]
_SKILLS = _ROOT / "src" / "treasure_map" / "skills"


@pytest.mark.parametrize("skill", sk.SHIPPED, ids=lambda s: s.id)
def test_each_source_file_is_the_skill_tmap_installs(skill: sk.Shipped) -> None:
    """MUTATION (verified RED, 1 failed): serve the scan skill with a line added -> RED."""
    source = _SKILLS / skill.dirname / "SKILL.md"
    assert source.read_bytes() == sk.shipped_bytes(skill)


@pytest.mark.parametrize("skill", sk.SHIPPED, ids=lambda s: s.id)
def test_each_skill_carries_the_frontmatter_a_catalogue_reads(skill: sk.Shipped) -> None:
    """``name`` is the directory's name (lowercase letters, digits and hyphens, at most 64) and
    ``description`` one non-empty line of at most 1024 characters."""
    text = (_SKILLS / skill.dirname / "SKILL.md").read_text(encoding="utf-8")
    m = re.match(r"---\n(.*?)\n---\n", text, re.S)
    assert m, skill.dirname
    fields = dict(line.split(": ", 1) for line in m.group(1).splitlines())
    assert fields["name"] == skill.dirname
    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", fields["name"]) and len(fields["name"]) <= 64
    assert 0 < len(fields["description"]) <= 1024


def test_the_repository_holds_no_other_skill_file() -> None:
    """MUTATION (verified RED, 1 failed): add a second copy of a skill anywhere in the tree
    -> RED."""
    if shutil.which("git") is None or not (_ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    tracked = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    found = sorted(p for p in tracked if Path(p).name == "SKILL.md")
    assert found == sorted(f"src/treasure_map/skills/{s.dirname}/SKILL.md" for s in sk.SHIPPED)
