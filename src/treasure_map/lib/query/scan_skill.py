# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The scan-review agent skill tmap ships: ``treasure_map/skills/tmap-scan-review/SKILL.md``, the
finished file an agent loads, printed by ``tmap review skill --scan`` and written beside the
diff-review skill by ``tmap init`` and ``tmap review skill --install`` (lib/setup/skills).

Unlike the diff-review skill it quotes no server sentence: the scan profile has none to quote, and
its loop is four steps over one unit, written out in the file."""

from __future__ import annotations

from importlib.resources import files

SKILL_DIRNAME = "tmap-scan-review"


def skill_text() -> str:
    """The scan-review skill shipped with tmap (markdown with its frontmatter)."""
    path = files("treasure_map.skills").joinpath(SKILL_DIRNAME, "SKILL.md")
    return path.read_text(encoding="utf-8")
