#!/usr/bin/env python3
# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Run the five recall-integrity gates over real scan-and-hunt output.

``check_recall_integrity.py --self-test`` proves the gates tell a clean database from a seeded
violation — it checks the checker. This checks the product: the rescan fixture
(``tests/fixtures/rescan_golden/harness.py``) runs the real scan and the real hunt over the
committed ELFs, needs no decompiler and takes seconds, and the gates then read the atlas and the
analysis database it wrote. So every one of Gates A-E runs against output the shipped code
produced on every CI run, which is what a docstring-only invariant never got.

The fixture is assembled in a temporary directory and removed afterwards.

Usage: python scripts/gates_on_fixture.py [--keep DIR]
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
HARNESS = REPO / "tests" / "fixtures" / "rescan_golden" / "harness.py"
CHECKER = REPO / "scripts" / "check_recall_integrity.py"


def run(work: Path) -> int:
    out = work / "digest.json"
    fixture = subprocess.run(  # noqa: S603 -- our own harness, fixed argv
        [sys.executable, str(HARNESS), "--work", str(work / "run"), "--out", str(out)],
        capture_output=True,
        text=True,
        check=False,
    )
    if fixture.returncode != 0:
        print(
            "gates on fixture: the fixture did not run, so the gates read nothing:\n"
            + fixture.stdout
            + fixture.stderr,
            file=sys.stderr,
        )
        return 2
    result = json.loads(out.read_text(encoding="utf-8"))
    # flushed: the checker below writes to the same stdout from its own process, and an unflushed
    # line here lands after everything it printed.
    print(
        f"gates on fixture: scanned and hunted the fixture (digest {result['digest'][:16]})",
        flush=True,
    )
    gates = subprocess.run(  # noqa: S603 -- our own checker, fixed argv
        [
            sys.executable,
            str(CHECKER),
            "--atlas",
            result["atlas"],
            "--analysis",
            result["analysis"],
            "--run-id",
            result["run_id"],
            # Every gate has to find rows of its own here. The fixture is the one database whose
            # contents we choose, so "this gate judged nothing" is a hole in the fixture to fill,
            # not a pass to collect — and it is how Gates A and E came to read 0 rows unnoticed.
            "--require-population",
        ],
        check=False,
    )
    return gates.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--keep", type=Path, default=None, help="work in this directory and leave it behind"
    )
    args = parser.parse_args(argv)
    if args.keep is not None:
        args.keep.mkdir(parents=True, exist_ok=True)
        return run(args.keep)
    work = Path(tempfile.mkdtemp(prefix="tmap-gates-"))
    try:
        return run(work)
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
