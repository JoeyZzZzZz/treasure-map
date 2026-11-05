# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The shipped diff-review skill: built in lib (the CLI only calls it), and every tmap command its
Rules name is one the real CLI accepts."""

from __future__ import annotations

import ast
import re
import shlex
from pathlib import Path

from click.testing import CliRunner

import treasure_map
from treasure_map.cli.main import main
from treasure_map.lib.query.diff_skill import skill_text

_LIB = Path(treasure_map.__file__).parent / "lib"


def _imported_modules(path: Path) -> set[str]:
    """Every module ``path`` imports, relative imports resolved against its package."""
    package = ".".join(path.relative_to(_LIB.parent.parent).with_suffix("").parts[:-1])
    out: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
        if isinstance(node, ast.Import):
            out |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package.split(".")[: len(package.split(".")) - (node.level - 1)]
                mod = ".".join([*base, *([node.module] if node.module else [])])
            else:
                mod = node.module or ""
            out.add(mod)
            out |= {f"{mod}.{a.name}" for a in node.names}
    return out


def test_lib_never_imports_the_cli_package() -> None:
    """★ E-m7: lib is below the CLI — nothing under ``treasure_map/lib`` imports
    ``treasure_map.cli`` (at module level or inside a function). The skill text lives in
    ``lib/query/diff_skill``; ``tmap review skill`` and the installer both call it there.

    MUTATION: import ``treasure_map.cli.review_cli`` again (as it once did) inside
    ``skills.shipped_bytes`` -> RED (names lib/setup/skills.py)."""
    files = sorted(_LIB.rglob("*.py"))
    assert len(files) > 50  # the walk really found the lib tree
    offenders = {
        str(p.relative_to(_LIB)): sorted(
            m
            for m in _imported_modules(p)
            if m == "treasure_map.cli" or m.startswith("treasure_map.cli.")
        )
        for p in files
    }
    assert {k: v for k, v in offenders.items() if v} == {}


def _rules_commands() -> list[str]:
    """Every ``tmap ...`` span in backticks in the skill's ``## Rules`` section."""
    text = skill_text()
    rules = text[text.index("## Rules") :]
    return [m for m in re.findall(r"`([^`]+)`", rules) if m.startswith("tmap ")]


def test_every_command_the_skill_rules_name_exists() -> None:
    """★ Each ``tmap ...`` command the skill's Rules give (``tmap review report <run_pair> --md
    -o review.md``, ``tmap review <run_pair> --agent claude-code``) is parsed by the real click
    command tree: placeholders filled, ``--help`` appended so nothing runs. A renamed command or
    option makes click fail the parse (exit 2) before help is shown.

    MUTATION: rename the report command's ``--md`` option to ``--markdown`` -> RED; rename the
    batch driver's ``--agent`` to ``--agent-cmd`` -> RED; rename ``tmap review`` to ``tmap
    reviews`` -> RED."""
    commands = _rules_commands()
    assert len(commands) >= 2, commands  # the section still names commands to check
    for cmd in commands:
        argv = [re.sub(r"<[^>]+>", "deadbeef::facefeed", a) for a in shlex.split(cmd)[1:]]
        res = CliRunner().invoke(main, [*argv, "--help"])
        assert res.exit_code == 0, (cmd, res.output)
        assert "Usage:" in res.output, (cmd, res.output)
