#!/usr/bin/env python3
# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Developer Certificate of Origin check for a pull request.

Every non-merge commit in BASE..HEAD must carry a ``Signed-off-by:`` trailer naming its author
exactly as git records it (``git commit -s`` writes it). Exit 0 when all do, 1 listing the ones
that do not, 2 when the range cannot be read — a range that cannot be checked never passes.

usage: check_dco.py BASE HEAD
"""

from __future__ import annotations

import subprocess
import sys


def _git(*args: str) -> str:
    return subprocess.run(  # noqa: S603 -- git with fixed arguments
        ["git", *args], check=True, capture_output=True, text=True
    ).stdout


def unsigned_commits(base: str, head: str) -> list[str]:
    """The commits in base..head (merges aside) whose author has not signed off."""
    out = []
    for sha in _git("rev-list", "--no-merges", f"{base}..{head}").split():
        author = _git("log", "-1", "--format=%an <%ae>", sha).strip()
        signers = _git(
            "log", "-1", "--format=%(trailers:key=Signed-off-by,valueonly,unfold)", sha
        ).splitlines()
        if author not in {s.strip() for s in signers}:
            out.append(f"{sha[:12]} {author}")
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: check_dco.py BASE HEAD", file=sys.stderr)
        return 2
    try:
        missing = unsigned_commits(argv[0], argv[1])
    except subprocess.CalledProcessError as exc:
        print(f"cannot read {argv[0]}..{argv[1]}: {exc.stderr.strip()}", file=sys.stderr)
        return 2
    if missing:
        print("commits without a Signed-off-by from their author (use `git commit -s`; see")
        print("CONTRIBUTING.md, Developer Certificate of Origin):")
        for line in missing:
            print(f"  {line}")
        return 1
    print("every commit is signed off by its author")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
