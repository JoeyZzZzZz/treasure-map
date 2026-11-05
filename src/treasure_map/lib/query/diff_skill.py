# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The diff-review agent skill tmap ships: the template in ``treasure_map/skills/diff-review.md``
with its ``## The loop`` filled from the server's own workflow sentences (``diff_workflow``).
``tmap review skill`` prints it and ``tmap init`` writes it (lib/setup/skills)."""

from __future__ import annotations

from importlib.resources import files

from treasure_map.lib.query.diff_workflow import DIFF_WORKFLOW, PAIR_WORKFLOW

SKILL_DIRNAME = "tmap-diff-review"
SKILL_LOOP_MARKER = "{loop}"


def skill_text() -> str:
    """The diff-review skill shipped with tmap (markdown with its frontmatter): the template's
    frontmatter and rules around ``## The loop``, which is the server's own two workflow sentences
    (``DIFF_WORKFLOW`` and ``PAIR_WORKFLOW``) — quoted, never retyped, so the skill cannot drift
    from what the server says."""
    template = files("treasure_map.skills").joinpath("diff-review.md").read_text(encoding="utf-8")
    if template.count(SKILL_LOOP_MARKER) != 1:
        raise RuntimeError(f"the skill template must hold {SKILL_LOOP_MARKER} exactly once")
    loop = f"## The loop\n\n{DIFF_WORKFLOW}\n\n{PAIR_WORKFLOW}"
    return template.replace(SKILL_LOOP_MARKER, loop)
