#!/usr/bin/env python3
# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Equal code stamps must mean equal output: check it against a base commit.

A stored run is treated as current while its two code stamps (``pipeline_code_version`` and
``hunt_code_version`` of ``lib/rescan_version``) equal the running code's. Those stamps hash the
source the scan and the hunt are built from; anything that changes what they write without
changing that source — code the closure walk does not reach, a file nobody declared as an asset —
leaves the stamps equal and old results wrongly current. No static guard can see that, so this
looks at the output instead:

  1. the stamps are computed for the base commit (checked out into a temporary ``git worktree``,
     always removed afterwards) and for the working tree, each in its own interpreter with that
     tree's ``src`` first on PYTHONPATH;
  2. if either stamp differs, there is nothing to check — the stamps already report the change —
     and the script says so and passes;
  3. if both are equal, the rescan fixture (``tests/fixtures/rescan_golden/harness.py``) is run
     once against each tree, on this machine in this environment, and the two digests must be
     equal. A difference means the output changed while the stamps did not.

The harness and the fixture always come from the working tree, so the two runs differ in the
package under test and nothing else. There is no committed golden digest to compare with: nothing
is ever re-recorded, and a machine-dependent digest cannot go stale in the repository.

WHICH BASE. ``--base`` (default ``HEAD~1``). On GitHub Actions a pull request is checked out as
the merge commit whose first parent is the base branch tip, so ``HEAD~1`` there is the pull
request's base and the comparison covers the whole pull request; on a push it is the commit
before the pushed tip, so a push of several commits compares its last commit only (each of them
went through a pull request or the local run, where this ran against its own parent). Either way
the checkout needs ``fetch-depth: 2``. Locally ``scripts/ci-local.sh`` uses ``HEAD~1`` too, which
compares the working tree, uncommitted edits included, against the commit before HEAD.

Exit status: 0 = equal digests, or a stamp moved (skip); 1 = the digests differ; 2 = the check
could not be made (no base, the fixture failed to run, the wrong package was imported).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

HARNESS_REL = Path("tests") / "fixtures" / "rescan_golden" / "harness.py"

_STAMPS_PROGRAM = """
import json, sys
from pathlib import Path
import treasure_map
try:
    from treasure_map.lib import rescan_version
except ImportError:
    rescan_version = None
out = {"package": str(Path(treasure_map.__file__).resolve().parent)}
if rescan_version is not None and hasattr(rescan_version, "hunt_code_version"):
    out["pipeline"] = rescan_version.pipeline_code_version()
    out["hunt"] = rescan_version.hunt_code_version()
json.dump(out, sys.stdout)
"""


class CheckError(RuntimeError):
    """The comparison could not be made."""


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise CheckError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def _env(tree: Path, home: Path) -> dict[str, str]:
    """The environment a tree's interpreter runs in: its ``src`` first, a throwaway home, no
    ``TM_*`` override from the caller's shell, a fixed hash seed, no bytecode written."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("TM_")}
    env.update(
        PYTHONPATH=str(tree / "src"),
        HOME=str(home),
        PYTHONHASHSEED="0",
        PYTHONDONTWRITEBYTECODE="1",
    )
    home.mkdir(parents=True, exist_ok=True)
    return env


def _expect_package(tree: Path, package: str) -> None:
    want = (tree / "src" / "treasure_map").resolve()
    if Path(package) != want:
        raise CheckError(
            f"imported treasure_map from {package}, expected {want}: PYTHONPATH did not win"
        )


def _stamps(tree: Path, scratch: Path) -> dict[str, str]:
    proc = subprocess.run(
        [sys.executable, "-c", _STAMPS_PROGRAM],
        env=_env(tree, scratch / "home-stamps"),
        cwd=scratch,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise CheckError(f"computing the code stamps of {tree} failed:\n{proc.stderr}")
    out: dict[str, str] = json.loads(proc.stdout)
    _expect_package(tree, out["package"])
    return out


def _run_fixture(harness: Path, tree: Path, scratch: Path, label: str) -> dict[str, Any]:
    work = scratch / f"run-{label}"
    out = scratch / f"digest-{label}.json"
    proc = subprocess.run(
        [
            sys.executable,
            str(harness),
            "--work",
            str(work),
            "--out",
            str(out),
            "--expect-package",
            str(tree / "src" / "treasure_map"),
        ],
        env=_env(tree, scratch / f"home-{label}"),
        cwd=scratch,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise CheckError(f"the fixture failed to run against the {label} tree:\n{proc.stderr}")
    result: dict[str, Any] = json.loads(out.read_text(encoding="utf-8"))
    return result


def _differing_tables(base: dict[str, Any], head: dict[str, Any]) -> list[str]:
    lines = []
    for name in sorted(set(base["tables"]) | set(head["tables"])):
        a, b = base["tables"].get(name), head["tables"].get(name)
        if a != b:
            rows_a = "absent" if a is None else f"{a['rows']} rows"
            rows_b = "absent" if b is None else f"{b['rows']} rows"
            lines.append(f"  {name}: base {rows_a}, working tree {rows_b}")
    return lines


def check(repo: Path, base_rev: str) -> int:
    harness = repo / HARNESS_REL
    if not harness.is_file():
        raise CheckError(f"no fixture harness at {harness}")
    try:
        base_sha = _git(repo, "rev-parse", "--verify", "--quiet", f"{base_rev}^{{commit}}")
    except CheckError:
        raise CheckError(
            f"{base_rev} is not a commit in this checkout (a shallow clone needs fetch-depth: 2)"
        ) from None
    short = base_sha[:12]
    scratch = Path(tempfile.mkdtemp(prefix="tmap-stamp-check-"))
    base_tree = scratch / "base"
    added = False
    try:
        _git(repo, "worktree", "add", "--detach", "--quiet", str(base_tree), base_sha)
        added = True

        head_stamps = _stamps(repo, scratch)
        base_stamps = _stamps(base_tree, scratch)
        if "hunt" not in base_stamps:
            print(f"rescan stamp check: SKIP: base {short} computes no code stamps")
            return 0
        moved = [
            f"{key} {base_stamps[key]} -> {head_stamps[key]}"
            for key in ("pipeline", "hunt")
            if base_stamps[key] != head_stamps[key]
        ]
        if moved:
            print(
                f"rescan stamp check: SKIP: the code stamps changed since {short} "
                f"({'; '.join(moved)}). Runs from before are reported stale by the stamps "
                "themselves, so there is no same-stamp output to compare."
            )
            return 0

        base_out = _run_fixture(harness, base_tree, scratch, "base")
        head_out = _run_fixture(harness, repo, scratch, "head")
        if base_out["digest"] == head_out["digest"]:
            print(
                f"rescan stamp check: OK: code stamps equal to {short}'s "
                f"(pipeline {head_stamps['pipeline']}, hunt {head_stamps['hunt']}) and the "
                f"fixture output is identical (digest {head_out['digest'][:16]})."
            )
            return 0
        differing = "\n".join(_differing_tables(base_out, head_out))
        print(
            "rescan stamp check: FAIL: output changed while the code stamps did not: "
            "something the hash cannot see changed the output.\n"
            f"  base {short} and the working tree both stamp pipeline "
            f"{head_stamps['pipeline']}, hunt {head_stamps['hunt']}, yet the fixture stored "
            f"different rows. Tables that differ:\n{differing}"
        )
        print(
            "  Find what changed the output outside the stamp closures (lib/rescan_version), and "
            "bring it inside them; old runs are being treated as current."
        )
        return 1
    finally:
        removed = not added
        if added:
            removed = (
                subprocess.run(
                    ["git", "-C", str(repo), "worktree", "remove", "--force", str(base_tree)],
                    capture_output=True,
                    check=False,
                ).returncode
                == 0
            )
        shutil.rmtree(scratch, ignore_errors=True)
        if not removed:
            # The directory is gone now; drop the registration git still holds for it.
            subprocess.run(
                ["git", "-C", str(repo), "worktree", "prune"], capture_output=True, check=False
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", default="HEAD~1", help="the commit to compare against")
    args = parser.parse_args(argv)
    repo = Path(__file__).resolve().parents[1]
    try:
        return check(repo, args.base)
    except CheckError as exc:
        print(f"rescan stamp check: ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
