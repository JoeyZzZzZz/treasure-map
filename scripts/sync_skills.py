# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Write the agent skills tmap ships to ``skills/<name>/SKILL.md`` at the repository root.

    python scripts/sync_skills.py           # rewrite every copy that differs
    python scripts/sync_skills.py --check   # exit 1, naming each copy that differs

The copies are for a skill directory or catalogue that reads a repository, and for uploading by
hand. They are generated, never edited: the text comes from the templates in
``src/treasure_map/skills/`` (the diff-review one with the server's own workflow sentences filled
in), byte for byte what ``tmap init`` and ``tmap review skill --install`` write. Edit a template,
then run this; tests/unit/test_repo_skills.py fails while a copy is stale.
"""

from __future__ import annotations

import sys
from pathlib import Path

from treasure_map.lib.setup import skills as sk

ROOT = Path(__file__).resolve().parents[1] / "skills"


def stale() -> list[Path]:
    """Every copy whose bytes are not the shipped skill's, and every directory under ``skills/``
    that names no shipped skill."""
    out = [
        ROOT / s.dirname / "SKILL.md"
        for s in sk.SHIPPED
        if not (ROOT / s.dirname / "SKILL.md").is_file()
        or (ROOT / s.dirname / "SKILL.md").read_bytes() != sk.shipped_bytes(s)
    ]
    if ROOT.is_dir():
        out += sorted(p for p in ROOT.iterdir() if p.name not in sk.BY_DIRNAME)
    return out


def main(argv: list[str]) -> int:
    if argv not in ([], ["--check"]):
        print(__doc__, file=sys.stderr)
        return 2
    bad = stale()
    if argv == ["--check"]:
        for p in bad:
            print(f"stale: {p.relative_to(ROOT.parent)}", file=sys.stderr)
        return 1 if bad else 0
    for s in sk.SHIPPED:
        path = ROOT / s.dirname / "SKILL.md"
        if path in bad:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(sk.shipped_bytes(s))
            print(f"wrote {path.relative_to(ROOT.parent)}")
    for p in bad:
        if p.parent == ROOT:
            print(f"not a shipped skill, left alone: {p.relative_to(ROOT.parent)}", file=sys.stderr)
    return 1 if any(p.parent == ROOT for p in bad) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
