# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Run the rescan fixture through the real scan and hunt, and digest everything they stored.

The dynamic backstop for the two code stamps of ``lib/rescan_version``. A stored run is treated as
current while both stamps match, which is only sound if equal stamps mean equal output. The static
guards check the hash's inputs; this checks its claim, by running the code and looking at what it
wrote. One copy, two callers, each running it as a program (never importing it):

  * ``tests/unit/lib/test_rescan_golden.py`` — the fixture really reaches the scan and the hunt,
    and the digest is the same for the same code wherever and with whatever hash seed it ran;
  * ``scripts/rescan_same_stamp_check.py`` — on two code trees whose stamps are equal, the
    digests are equal.

Which code runs is whatever ``treasure_map`` the interpreter imports, so a caller selects a tree by
putting its ``src`` first on ``PYTHONPATH`` and passes ``--expect-package`` to have that checked.
The harness and the fixture always come from the tree the caller lives in, so two runs differ in
the package under test and in nothing else. Every package name used here lives in a module inside
the two stamp closures (``lib.analyze.pipeline`` and the ``ghidra_runner`` / ``stub_resolve`` /
``workspace`` / ``config`` modules it reaches, and ``lib.hunt.analyzer2``), so the harness runs
unchanged against any tree whose stamps equal the current one's.

THE FIXTURE, assembled fresh under ``--work`` on every run:
  * a firmware root: the text files under ``rootfs/`` (a start-up shell script, a config file, a
    web page), the two ELFs of ``tests/fixtures/elfs`` copied in as ``bin/fixtured`` and
    ``lib/libfixture.so``, and one symlink, ``sbin/fixtured -> ../bin/fixtured``;
  * ``ghidra/<binary name>.json``: the extractor output for each ELF, written by hand. The ELFs'
    sources call no command, copy or format sink, so it could not be recorded from them; it is
    small, but has the shape the real extractor writes, and calls system / strcpy / sprintf.

THE RUN: ``pipeline.GhidraRunner`` is replaced by a stand-in whose ``run_all`` writes each binary's
hand-written JSON (stamped with this pass, the binary's sha8 and its stub marker, as the extractor
does) into the output directory, handing each result to ``on_final`` when the pipeline passes one;
then the real ``run_analyze`` and ``run_analyzer2`` run, into a
fresh workspace and a fresh atlas.

THE DIGEST covers every table of the analysis.db and every table of the atlas. The atlas is fresh
and the hunt writes one run into it, so each atlas table holds exactly that run's rows (checked:
a row whose run id is another's stops the harness), and the global ``pattern`` table is taken
whole, autoincrement ids included. Each table is reduced to its rows, values normalised (the work
directory, which holds every absolute path the run wrote, becomes ``<WORK>``) and sorted, then
hashed; ``EXCLUDED_COLUMNS`` below lists every column left out, and why.

Usage: python harness.py --work DIR --out FILE [--expect-package DIR]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shutil
import sqlite3
import sys
from pathlib import Path
from typing import Any

FIXTURE = Path(__file__).resolve().parent
ELFS = FIXTURE.parent / "elfs"

RUN_ID = "rescan-fixture"
# What the stand-in runner reports for the extraction pass and the decompiler that produced the
# JSON. Fixed strings: the real values are hashes and versions of a Ghidra this run never starts.
PASS_VERSION = "fixture-pass"
GHIDRA_VERSION = "fixture-ghidra"

# (database, table, column) -> why the column is left out of the digest. Written out in full, and
# kept honest from both sides: a column whose declared type or default reads as a timestamp that
# is NOT listed here stops the harness (it has to be classified first), and so does an entry that
# names a column the schema no longer has.
EXCLUDED_COLUMNS: dict[tuple[str, str, str], str] = {
    # timestamps: when the row was written, not what was found
    ("analysis", "binaries", "last_seen_at"): "timestamp",
    ("analysis", "binaries", "analyzed_at"): "timestamp",
    ("atlas", "pattern", "first_seen_at"): "timestamp",
    ("atlas", "pattern", "last_updated_at"): "timestamp",
    ("atlas", "instance", "created_at"): "timestamp",
    ("atlas", "run", "scanned_at"): "timestamp",
    ("atlas", "run", "updated_at"): "timestamp",
    ("atlas", "nvram_key_flow", "created_at"): "timestamp",
    ("atlas", "nvram_defaults", "created_at"): "timestamp",
    ("atlas", "web_form_fields", "created_at"): "timestamp",
    ("atlas", "string_keyed_edge", "created_at"): "timestamp",
    ("atlas", "exec_edge", "created_at"): "timestamp",
    ("atlas", "run_capability", "created_at"): "timestamp",
    ("atlas", "public_cve_pattern", "created_at"): "timestamp",
    ("atlas", "private_exploit", "created_at"): "timestamp",
    ("atlas", "diff_meta", "created_at"): "timestamp",
    ("atlas", "overlay", "created_at"): "timestamp",
    ("atlas", "overlay", "updated_at"): "timestamp",
    # the stamps themselves: they describe the code, which is what is being compared, not output
    ("analysis", "scan_stamp", "stamp"): "the scan stamp (pipeline code hash + deps + config)",
    ("atlas", "run", "scan_stamp"): "the scan stamp, copied onto the run row",
    ("atlas", "run", "hunt_code_version"): "the hunt code stamp",
    ("atlas", "run", "hunt_commit"): "the commit the install records, a stamp of the install",
    # a hash over absolute paths: it differs with the work directory and cannot be normalised
    # back; what it summarises (binaries, non-binary files, links, row counts) is digested directly
    ("atlas", "run", "hunt_input_fingerprint"): "a hash over the binaries' absolute paths",
}


class HarnessError(RuntimeError):
    """The fixture could not be run or digested as designed (not an output difference)."""


# ── the stand-in runner ──────────────────────────────────────────────────────────────


def _runner_class() -> type:
    """A ``GhidraRunner`` stand-in. Built after the package is importable from the chosen tree."""
    from treasure_map.lib.analyze.ghidra_runner import GhidraResult
    from treasure_map.lib.analyze.stub_resolve import resolve_stubs, stub_table_marker

    class FixtureRunner:
        """Hands the pipeline the hand-written extractor output instead of running Ghidra."""

        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def get_headless(self) -> Path:
            return Path("analyzeHeadless")

        def pass_version(self) -> str:
            return PASS_VERSION

        def ghidra_version(self) -> str:
            return GHIDRA_VERSION

        def run_all(
            self, records: list[Any], out_dir: Path, *_a: Any, on_final: Any = None, **_k: Any
        ) -> list[Any]:
            # ``on_final`` is handed each result as it is made, the way the real runner does, so
            # a pipeline that stores each binary as it arrives is digested through that path. A
            # pipeline that does not pass it is run exactly as before.
            results = []
            for rec in records:
                src = FIXTURE / "ghidra" / f"{rec.name}.json"
                if not src.is_file():
                    raise HarnessError(f"no hand-written extractor output for binary {rec.name!r}")
                data = json.loads(src.read_text(encoding="utf-8"))
                # The three markers the real extractor echoes and the ingest checks.
                stubs = resolve_stubs(rec.path)
                data["pass_version"] = PASS_VERSION
                data["sha8"] = rec.sha256[:8]
                data["stub_marker"] = stub_table_marker(None if stubs is None else stubs.names)
                out = out_dir / f"{rec.name}_{rec.sha256[:8]}_ghidra.json"
                out.write_text(json.dumps(data, indent=1), encoding="utf-8")
                result = GhidraResult(
                    binary=rec.path,
                    output_file=out,
                    success=True,
                    elapsed=0.0,
                    analysis_status="ok",
                    function_count=len(data.get("functions", [])),
                )
                results.append(result)
                if on_final is not None:
                    on_final(rec, result)
            return results

    return FixtureRunner


# ── the run ──────────────────────────────────────────────────────────────────────────


def build_firmware_root(dest: Path) -> None:
    """Assemble the fixture firmware root at ``dest`` (which must not exist)."""
    shutil.copytree(FIXTURE / "rootfs", dest)
    (dest / "bin").mkdir()
    shutil.copy(ELFS / "exe_x86_64", dest / "bin" / "fixtured")
    (dest / "lib").mkdir()
    shutil.copy(ELFS / "libfixture_x86_64.so", dest / "lib" / "libfixture.so")
    (dest / "sbin").mkdir()
    os.symlink("../bin/fixtured", dest / "sbin" / "fixtured")


def run_fixture(work: Path) -> tuple[Path, Path]:
    """Scan and hunt the fixture under ``work``; return (analysis.db, atlas.db)."""
    from unittest.mock import patch

    from treasure_map.lib.analyze import pipeline
    from treasure_map.lib.config.config import Config
    from treasure_map.lib.hunt.analyzer2 import run_analyzer2
    from treasure_map.lib.workspace.workspace import Workspace

    fs_root = work / "fs"
    build_firmware_root(fs_root)
    ws_dir = work / "ws"
    atlas = work / "atlas.db"
    with patch.object(pipeline, "GhidraRunner", _runner_class()):
        with Workspace(ws_dir) as ws:
            pipeline.run_analyze(fs_root, ws, Config())
            db = ws.db_path
    stats = run_analyzer2(db, atlas, source_run_id=RUN_ID, firmware_path=str(fs_root))
    if stats.skipped:
        raise HarnessError(f"the hunt skipped on a fresh atlas: {stats.hunt_currency}")
    return db, atlas


# ── the digest ───────────────────────────────────────────────────────────────────────


def _is_timestamp_column(decl_type: str, default: object) -> bool:
    t = (decl_type or "").upper()
    return "DATE" in t or "TIME" in t or "CURRENT_TIMESTAMP" in str(default or "").upper()


def _normalise(value: object, roots: list[tuple[str, str]]) -> object:
    if isinstance(value, bytes):
        return {"bytes": value.hex()}
    if isinstance(value, float):
        return {"float": repr(value)}
    if isinstance(value, str):
        for root, placeholder in roots:
            value = value.replace(root, placeholder)
    return value


def digest_database(
    path: Path, label: str, roots: list[tuple[str, str]], seen_exclusions: set[tuple[str, str, str]]
) -> dict[str, dict[str, Any]]:
    """``{table: {"rows": n, "sha256": hex}}`` for every table of one database."""
    out: dict[str, dict[str, Any]] = {}
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        tables = [
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY 1")
        ]
        for table in tables:
            info = conn.execute(f'PRAGMA table_info("{table}")').fetchall()
            kept: list[str] = []
            for _cid, name, decl_type, _notnull, default, _pk in info:
                key = (label, table, name)
                if key in EXCLUDED_COLUMNS:
                    seen_exclusions.add(key)
                    continue
                if _is_timestamp_column(decl_type, default):
                    raise HarnessError(
                        f"{label}.{table}.{name} looks like a timestamp ({decl_type}, default "
                        f"{default}) and is not classified: add it to EXCLUDED_COLUMNS"
                    )
                kept.append(name)
            if label == "atlas":
                for run_col in ("source_run_id", "run_id"):
                    if run_col in kept:
                        other = conn.execute(
                            f'SELECT COUNT(*) FROM "{table}" WHERE "{run_col}" IS NOT ?', (RUN_ID,)
                        ).fetchone()[0]
                        if other:
                            raise HarnessError(f"atlas.{table} holds {other} row(s) of another run")
            cols = ", ".join(f'"{c}"' for c in kept)
            rows = conn.execute(f'SELECT {cols} FROM "{table}"').fetchall() if kept else []
            lines = sorted(
                json.dumps([_normalise(v, roots) for v in row], sort_keys=True, ensure_ascii=False)
                for row in rows
            )
            h = hashlib.sha256(json.dumps(kept).encode("utf-8") + b"\n")
            for line in lines:
                h.update(line.encode("utf-8") + b"\n")
            out[table] = {"rows": len(rows), "sha256": h.hexdigest()}
    finally:
        conn.close()
    return out


def digest_run(work: Path, db: Path, atlas: Path) -> dict[str, Any]:
    # Every absolute path the run wrote is under the work directory; either spelling of it (as
    # given, and with symlinks resolved) becomes one placeholder, the longer one replaced first.
    spellings = sorted({str(work), str(work.resolve())}, key=len, reverse=True)
    roots = [(s, "<WORK>") for s in spellings]
    seen: set[tuple[str, str, str]] = set()
    tables: dict[str, dict[str, Any]] = {}
    for label, path in (("analysis", db), ("atlas", atlas)):
        for table, entry in digest_database(path, label, roots, seen).items():
            tables[f"{label}/{table}"] = entry
    stale = sorted(set(EXCLUDED_COLUMNS) - seen)
    if stale:
        raise HarnessError(f"EXCLUDED_COLUMNS names columns the schema no longer has: {stale}")
    whole = hashlib.sha256()
    for name in sorted(tables):
        whole.update(f"{name}={tables[name]['sha256']}\n".encode())
    return {"digest": whole.hexdigest(), "tables": tables}


# ── entry point ──────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--work", required=True, type=Path, help="a directory that does not exist")
    parser.add_argument("--out", required=True, type=Path, help="where to write the digest JSON")
    parser.add_argument(
        "--expect-package", type=Path, help="the treasure_map package directory that must load"
    )
    args = parser.parse_args(argv)

    work: Path = args.work.absolute()
    if work.exists():
        print(f"harness: --work {work} already exists", file=sys.stderr)
        return 2
    # Before anything imports the package: a throwaway home (some defaults resolve under it, one at
    # import time) and no TM_* override from the caller's shell.
    home = work / "home"
    (home / ".treasure-map").mkdir(parents=True)
    os.environ["HOME"] = str(home)
    for name in [n for n in os.environ if n.startswith("TM_")]:
        del os.environ[name]
    logging.basicConfig(level=logging.WARNING, format="harness: %(name)s: %(message)s")

    import treasure_map

    package = Path(treasure_map.__file__).resolve().parent
    if args.expect_package is not None and package != args.expect_package.resolve():
        print(
            f"harness: imported treasure_map from {package}, expected {args.expect_package} "
            "(PYTHONPATH must put the tree under test first)",
            file=sys.stderr,
        )
        return 2
    try:
        db, atlas = run_fixture(work)
        result = digest_run(work, db, atlas)
    except HarnessError as exc:
        print(f"harness: {exc}", file=sys.stderr)
        return 2
    result["package"] = str(package)
    args.out.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
