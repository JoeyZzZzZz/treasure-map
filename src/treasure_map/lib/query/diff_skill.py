# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The diff-review agent skill tmap ships: ``treasure_map/skills/tmap-diff-review/SKILL.md``, the
finished file an agent loads. ``tmap review skill`` prints it and ``tmap init`` writes it
(lib/setup/skills).

Its ``## The loop`` is the server's own two workflow sentences (``diff_workflow``'s
``DIFF_WORKFLOW`` and ``PAIR_WORKFLOW``), copied in verbatim so the skill says what the server
says; a unit test fails when the two differ."""

from __future__ import annotations

from importlib.resources import files

SKILL_DIRNAME = "tmap-diff-review"


def skill_text() -> str:
    """The diff-review skill shipped with tmap (markdown with its frontmatter)."""
    path = files("treasure_map.skills").joinpath(SKILL_DIRNAME, "SKILL.md")
    return path.read_text(encoding="utf-8")
