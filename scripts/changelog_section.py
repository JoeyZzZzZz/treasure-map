# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Print one version's CHANGELOG.md section — the body of a GitHub release.

    python scripts/changelog_section.py 0.1.1 [CHANGELOG.md] > notes.md

The section is everything under the ``## [0.1.1]`` heading (the heading itself left out: the
release title already names the version) up to the next ``## `` heading or the link-reference
block of a Keep a Changelog file, with leading and trailing blank lines dropped. Exits non-zero,
printing nothing to stdout, when the file has no such heading or the section is empty, so a
release cannot go out with no notes. Standard library only: the release runner's Python has no
tmap dependencies.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_LINK_REFERENCE = re.compile(r"^\[[^\]]+\]:\s")


def section(text: str, version: str) -> str:
    """The body of ``version``'s section, or raise ValueError when it is missing or empty."""
    heading = re.compile(rf"^## \[{re.escape(version)}\](?:\s|$)")
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if heading.match(line)), None)
    if start is None:
        raise ValueError(f"no '## [{version}]' heading")
    body: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith("## ") or _LINK_REFERENCE.match(line):
            break
        body.append(line)
    out = "\n".join(body).strip("\n")
    if not out.strip():
        raise ValueError(f"the '## [{version}]' section is empty")
    return out + "\n"


def main(argv: list[str]) -> int:
    if len(argv) not in (1, 2):
        print(__doc__, file=sys.stderr)
        return 2
    path = Path(argv[1] if len(argv) == 2 else "CHANGELOG.md")
    try:
        notes = section(path.read_text(encoding="utf-8"), argv[0])
    except (OSError, ValueError) as exc:
        print(f"{path}: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(notes)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
