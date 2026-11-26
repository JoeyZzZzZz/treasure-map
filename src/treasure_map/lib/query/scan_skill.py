# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The scan-review agent skill tmap ships: ``treasure_map/skills/scan-review.md``, printed by
``tmap review skill --scan`` and written beside the diff-review skill by ``tmap init`` and
``tmap review skill --install`` (lib/setup/skills).

Parallel to ``diff_skill`` and deliberately simpler: the diff skill quotes the server's own
workflow sentences into a ``{loop}`` marker so the two cannot drift, and the scan profile has no
such server-side sentence to quote — its loop is four steps over one unit, written out in the file.
"""

from __future__ import annotations

from importlib.resources import files

SKILL_DIRNAME = "tmap-scan-review"


def skill_text() -> str:
    """The scan-review skill shipped with tmap (markdown with its frontmatter)."""
    return files("treasure_map.skills").joinpath("scan-review.md").read_text(encoding="utf-8")
