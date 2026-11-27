# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The skills under ``skills/`` at the repository root are the ones tmap installs, byte for byte.

They are generated copies (``scripts/sync_skills.py``) for a catalogue that reads a repository and
for uploading by hand; the source stays the package templates, which the wheel carries. A copy
that drifted would hand a reader one skill and ``tmap init`` another."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from types import ModuleType

import pytest

from treasure_map.lib.setup import skills as sk

_ROOT = Path(__file__).resolve().parents[2]
_SKILLS = _ROOT / "skills"
_SYNC = "python scripts/sync_skills.py"


def _sync_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("sync_skills", _ROOT / "scripts/sync_skills.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("skill", sk.SHIPPED, ids=lambda s: s.id)
def test_each_repo_copy_is_the_skill_tmap_installs(skill: sk.Shipped) -> None:
    """MUTATION (verified RED, 1 failed): append a line to either template -> RED."""
    copy = _SKILLS / skill.dirname / "SKILL.md"
    assert copy.is_file(), f"{copy.relative_to(_ROOT)} is missing; run {_SYNC}"
    assert copy.read_bytes() == sk.shipped_bytes(skill), (
        f"{copy.relative_to(_ROOT)} is not the shipped text; edit the template under "
        f"src/treasure_map/skills/ and run {_SYNC}"
    )


def test_the_skills_directory_holds_the_shipped_skills_and_nothing_else() -> None:
    """MUTATION (verified RED, 1 failed): drop SCAN from ``SHIPPED`` -> RED."""
    assert sorted(p.name for p in _SKILLS.iterdir()) == sorted(s.dirname for s in sk.SHIPPED)
    for skill in sk.SHIPPED:
        assert [p.name for p in (_SKILLS / skill.dirname).iterdir()] == ["SKILL.md"]


@pytest.mark.parametrize("skill", sk.SHIPPED, ids=lambda s: s.id)
def test_each_copy_carries_the_frontmatter_a_skill_catalogue_reads(skill: sk.Shipped) -> None:
    """A skill directory names the skill: the frontmatter ``name`` is that directory's name
    (lowercase letters, digits and hyphens, at most 64), and ``description`` is one non-empty
    line of at most 1024 characters."""
    text = (_SKILLS / skill.dirname / "SKILL.md").read_text(encoding="utf-8")
    m = re.match(r"---\n(.*?)\n---\n", text, re.S)
    assert m, skill.dirname
    fields = dict(line.split(": ", 1) for line in m.group(1).splitlines())
    assert fields["name"] == skill.dirname
    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", fields["name"]) and len(fields["name"]) <= 64
    assert 0 < len(fields["description"]) <= 1024


def test_the_sync_script_writes_a_stale_copy_and_leaves_a_stranger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION (verified RED, 1 failed): write only copies that are missing (not those that
    differ) -> RED."""
    sync = _sync_module()
    monkeypatch.setattr(sync, "ROOT", tmp_path / "skills")
    assert sync.main(["--check"]) == 1
    assert sync.main([]) == 0
    assert sync.main(["--check"]) == 0
    diff = tmp_path / "skills" / sk.DIFF.dirname / "SKILL.md"
    diff.write_bytes(diff.read_bytes() + b"edited\n")
    stranger = tmp_path / "skills" / "other-skill"
    stranger.mkdir()
    assert sync.main(["--check"]) == 1
    assert sync.main([]) == 1  # the stranger is reported, never removed
    assert diff.read_bytes() == sk.shipped_bytes(sk.DIFF)
    assert stranger.is_dir()
    assert sync.main(["--bogus"]) == 2


def test_git_keeps_the_copies_lf() -> None:
    """A CRLF checkout would make every copy differ from the shipped bytes."""
    lines = (_ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
    assert "/skills/** text eol=lf" in lines
