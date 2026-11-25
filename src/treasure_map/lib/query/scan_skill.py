# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The scan-review agent skill tmap ships: ``treasure_map/skills/scan-review.md``, printed by
``tmap review skill --scan``.

Parallel to ``diff_skill`` and deliberately simpler: the diff skill quotes the server's own
workflow sentences into a ``{loop}`` marker so the two cannot drift, and the scan profile has no
such server-side sentence to quote — its loop is four steps over one unit, written out in the file.

★ NOT INSTALLED by ``tmap init`` / ``tmap review skill --install`` this version. The installer
carries ONE skill: ``lib/setup/skills`` reads ``diff_skill.SKILL_DIRNAME`` as a module constant in
its path builder, its ledger-entry validation, its help text and its uninstall check, and the
legacy-hash set that lets it replace an earlier tmap's file is the diff skill's history. Wiring a
second skill means giving each of those a skill identity and a ledger entry per skill; until that
is done, saying this file is installed would be the install ledger claiming a file it does not
keep current. Printing it is honest, and a person can save it where their agent reads skills.
"""

from __future__ import annotations

from importlib.resources import files

SKILL_DIRNAME = "tmap-scan-review"


def skill_text() -> str:
    """The scan-review skill shipped with tmap (markdown with its frontmatter)."""
    return files("treasure_map.skills").joinpath("scan-review.md").read_text(encoding="utf-8")
