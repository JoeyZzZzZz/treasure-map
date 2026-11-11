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
    -o review.md``, ``tmap review run <run_pair> --agent claude-code``) is parsed by the real click
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


def test_the_rules_name_exactly_the_driver_and_the_report() -> None:
    """★ T-F2b: the Rules name two commands, the batch driver and the report (both checked by the
    test above against the real command tree).

    MUTATION (verified RED, 1 failed): write the driver's ``--agent`` as ``--agents`` -> the
    command test above RED (exit 2)."""
    assert _rules_commands() == [
        "tmap review run <run_pair> --agent claude-code",
        "tmap review report <run_pair> --md -o review.md",
    ]


def test_the_skill_says_a_pair_spans_sessions_and_how_one_hands_off() -> None:
    """★ T-F2a: the description no longer promises the whole pair in one go; the Rules name the
    batch driver (which probes the agent's tool set) before the loop's own rules, say where a
    session stops and what its hand-off quotes, and what a shard's counts are; the unit_id and the
    full-list rules are as they were.

    MUTATION (verified RED, 1 failed): put back the old description -> RED. MUTATION (verified
    RED, 1 failed): drop the shard sentence -> RED."""
    text = skill_text()
    head, rules = text[: text.index("## Rules")], text[text.index("## Rules") :]
    assert "until the server reports the must-read set complete" not in head
    assert "a whole run pair usually spans several sessions, or tmap's batch driver" in head
    assert rules.index("`tmap review run <run_pair>") < rules.index("An unjudged member is UNREAD")
    assert "it probes the agent's tool set first" in rules
    flat = " ".join(rules.split())
    assert "Stop only at a unit boundary" in flat
    assert "An early stop is a hand-off" in flat
    assert "name `progress.resume_with` as the call a fresh session continues with" in flat
    assert "Never call the review complete unless `must_read_complete` is true" in flat
    assert (
        "Working a shard (`progress.scope` is `shard`), the counts `progress.pair_wide` names are "
        "the whole pair's, not this shard's." in flat
    )
    assert (
        "- Name the unit you judge (`unit_id`). A judgment written before its subject was read "
        "reads\n  `needs_recheck` — not disposed — until you judge it again after reading it. A "
        "`no_real_change`\n  or `change_inconclusive` on a must-read subject needs it read whole "
        "(every candidate row; code\n  held back, read in full); a `changed_real` read in part "
        "still counts.\n" in rules
    )
    assert (
        "- The full unit list is not sent over MCP: `tmap review report <run_pair> --md -o "
        "review.md`\n  writes it for a person to read.\n" in rules
    )


def test_the_pair_workflow_still_closes_with_both_sides() -> None:
    """★ T-F2d: PAIR_WORKFLOW still ends with PAIR_SIDES (the module docstring says it closes it),
    the several-sessions sentence before it.

    MUTATION (verified RED, 1 failed): append the new sentence after PAIR_SIDES -> RED."""
    from treasure_map.lib.query import diff_workflow as dw

    assert dw.PAIR_WORKFLOW.endswith(dw.PAIR_SIDES)
    new = "A pair larger than one session is reviewed in several"
    assert new in dw.PAIR_WORKFLOW
    assert dw.PAIR_WORKFLOW.index(new) < dw.PAIR_WORKFLOW.index(dw.PAIR_SIDES)
