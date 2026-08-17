# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A diff is about two specific builds; the reader has to be told when those builds are gone.

Re-scan a source with different content and the alignment underneath still reads as current — the
addresses it matched belong to a file that no longer exists. Nothing corrects for that on its own,
so the check happens where the result is consumed.

★ The test is the GENERATION, never the clock. Re-scanning identical content is the ordinary case
and leaves every diff valid; judging by "which happened later" would brand a whole table stale on
any re-scan, which is the same failure — old data read as current — pointed the other way.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import DiffMetaRow, DimensionDeltaRow
from treasure_map.lib.atlas.writer import add_diff_meta, add_dimension_deltas, begin_run
from treasure_map.lib.query.diff_align import (
    STALE_CHANGED,
    STALE_GONE,
    STALE_NO_STAMP,
    STALE_UNKNOWN,
    get_diff_deltas,
    list_diff_blindspots,
    list_diffs,
)
from treasure_map.lib.storage.connection import open_db

_SHA_OLD = "a" * 64
_SHA_NEW = "b" * 64
_SHA_OTHER = "c" * 64


def _analysis(path: Path, binaries: list[tuple[str, str]]) -> Path:
    """An analysis.db whose current scan holds ``(name, sha256)`` — several rows may share a name,
    which is what a real firmware does (four such names in one measured run)."""
    conn = open_db(path)
    for i, (name, sha) in enumerate(binaries, start=1):
        conn.execute(
            "INSERT INTO binaries (id, name, path, sha256, ghidra_status, last_seen_at) "
            "VALUES (?, ?, ?, ?, 'ok', '2026-01-01')",
            (i, name, f"bin/{name}.{i}", sha),
        )
    conn.commit()
    conn.close()
    return path


def _atlas(
    tmp_path: Path,
    *,
    stored_sha: str | None = _SHA_OLD,
    current: list[tuple[str, str]] | None = None,
    diff_id: str | None = None,
    binary: str = "libfoo.so",
    register_run: bool = True,
    with_deltas: bool = True,
) -> Path:
    """One diff of ``binary`` between two runs, plus the analysis.db the A-side run resolves to."""
    analysis = _analysis(
        tmp_path / "analysis.db", current if current is not None else [(binary, _SHA_OLD)]
    )
    atlas_path = tmp_path / "atlas.db"
    conn = open_atlas(atlas_path)
    if register_run:
        begin_run(conn, "run_a", analysis_db_path=str(analysis))
        begin_run(conn, "run_b", analysis_db_path=str(analysis))
    did = diff_id or f"run_a::run_b::{binary}"
    add_diff_meta(
        conn,
        DiffMetaRow(
            diff_id=did,
            run_a_id="run_a",
            run_b_id="run_b",
            binary_a=binary,
            binary_b=binary,
            sha256_a=stored_sha,
            sha256_b=stored_sha,
            diff_ok=1,
            diff_status="ok",
            matched_pairs=10,
        ),
    )
    if with_deltas:
        add_dimension_deltas(
            conn,
            [
                DimensionDeltaRow(
                    diff_id=did,
                    dimension="controllability",
                    subject_kind="function",
                    subject_key=f"{binary}|00011000",
                    delta_kind="layer_changed",
                    binary=binary,
                )
            ],
        )
    conn.close()
    return atlas_path


def _only(result: dict[str, Any]) -> dict[str, Any]:
    assert result["count"] == 1, result
    return result["diffs"][0]


# ── the generation test itself ────────────────────────────────────────────────────────


def test_a_diff_of_files_that_are_still_there_is_not_stale(tmp_path: Path) -> None:
    # ★ The case that must NOT be flagged, and the one a timestamp rule gets wrong: the sources
    # were re-scanned, the content is identical, and every alignment still holds.
    conn = open_atlas(_atlas(tmp_path))
    try:
        row = _only(list_diffs(conn))
        assert row["source_stale"] is False
        assert row["source_stale_reason"] is None
    finally:
        conn.close()


def test_a_diff_whose_source_content_changed_is_stale(tmp_path: Path) -> None:
    # The scan still holds a binary by that name, but not the one that was diffed.
    #
    # MUTATION (verified RED, 1 failed): in diff_align._freshness return `(False, None)` whenever
    # the name is present, ignoring the hash -> a diff of a replaced file reads as current.
    conn = open_atlas(_atlas(tmp_path, current=[("libfoo.so", _SHA_NEW)]))
    try:
        row = _only(list_diffs(conn))
        assert row["source_stale"] is True
        assert row["source_stale_reason"] == STALE_CHANGED
    finally:
        conn.close()


def test_a_diff_whose_binary_left_the_scan_is_stale(tmp_path: Path) -> None:
    conn = open_atlas(_atlas(tmp_path, current=[("something_else", _SHA_NEW)]))
    try:
        row = _only(list_diffs(conn))
        assert (row["source_stale"], row["source_stale_reason"]) == (True, STALE_GONE)
    finally:
        conn.close()


def test_one_name_covering_several_files_is_judged_by_existence(tmp_path: Path) -> None:
    # ★ THE COIN-FLIP GUARD. A diff records a binary's SHORT NAME, and one name really can cover
    # several files in a scan — a real firmware has four such names in one run, one of which was
    # itself diffed. Reading "the" hash for a name would be a coin flip, and half the time it would
    # call an unchanged diff stale. The stored hash matching ANY hash under that name means the
    # file that was diffed is still there.
    #
    # MUTATION (verified RED, 1 failed): in diff_align._current_generation keep one hash per name —
    # `out[name] = {sha}` instead of `out.setdefault(name, set()).add(sha)` — and this flips to
    # stale whenever the other row is the one kept (here, always: the second write wins).
    conn = open_atlas(
        _atlas(tmp_path, current=[("libfoo.so", _SHA_OLD), ("libfoo.so", _SHA_OTHER)])
    )
    try:
        row = _only(list_diffs(conn))
        assert row["source_stale"] is False, "the diffed file is still present, unchanged"
    finally:
        conn.close()


def test_no_stamp_is_unverified_not_stale_and_not_clean(tmp_path: Path) -> None:
    # ★ A diff written before the content stamp existed cannot be checked either way. Reported as
    # its own answer: calling it stale would brand old-but-valid work, calling it fresh would be a
    # clean bill nobody earned. A real atlas holds exactly one such row.
    #
    # MUTATION (verified RED, 1 failed): in diff_align._freshness treat a missing stamp as changed
    # — `return True, STALE_CHANGED` — and an unverifiable diff is reported as definitely stale.
    conn = open_atlas(_atlas(tmp_path, stored_sha=None))
    try:
        row = _only(list_diffs(conn))
        assert row["source_stale"] is None
        assert row["source_stale_reason"] == STALE_NO_STAMP
    finally:
        conn.close()


def test_an_unreachable_source_is_unverified_not_stale(tmp_path: Path) -> None:
    # Same principle for a run whose analysis.db is gone or was never recorded: "we could not
    # check" and "we checked and it is fine" are different things to hand a reader.
    #
    # MUTATION (verified RED, 1 failed): in diff_align._current_generation return `{}` instead of
    # None when the path is missing -> every diff of that run reads as stale (binary absent).
    conn = open_atlas(_atlas(tmp_path, register_run=False))
    try:
        row = _only(list_diffs(conn))
        assert (row["source_stale"], row["source_stale_reason"]) == (None, STALE_UNKNOWN)
    finally:
        conn.close()


def test_staleness_does_not_overwrite_the_diff_status(tmp_path: Path) -> None:
    # ★ The two are orthogonal: a diff can have computed perfectly AND be about a file that has
    # since been replaced. Folding staleness into diff_status would lose one of them.
    #
    # MUTATION (verified RED, 1 failed): in diff_align.list_diffs overwrite the status —
    # `row["diff_status"] = "stale" if row["source_stale"] else row["diff_status"]` -> the fact
    # that the diff itself succeeded is gone.
    conn = open_atlas(_atlas(tmp_path, current=[("libfoo.so", _SHA_NEW)]))
    try:
        row = _only(list_diffs(conn))
        assert row["source_stale"] is True
        assert row["diff_status"] == "ok"
        assert row["diff_ok"] == 1
    finally:
        conn.close()


def test_the_deltas_carry_the_same_answer(tmp_path: Path) -> None:
    # The other consumption point. Attached to EVERY response, not just the verbose one: a reader
    # who trimmed the notes to save room is the one who would otherwise act on a diff of a build
    # that is gone.
    #
    # MUTATION (verified RED, 1 failed): in diff_align.get_diff_deltas attach source_stale only
    # under `if verbose:` -> the compact response serves deltas with nothing said about the ground
    # they rest on.
    atlas_path = _atlas(tmp_path, current=[("libfoo.so", _SHA_NEW)])
    conn = open_atlas(atlas_path)
    try:
        compact = get_diff_deltas(conn, "run_a::run_b::libfoo.so", verbose=False)
        assert compact["source_stale"] is True
        assert compact["source_stale_reason"] == STALE_CHANGED
        assert compact["page"]["count"] == 1  # the deltas are still served, with the flag on them
    finally:
        conn.close()


# ── the leftover run-pair row ─────────────────────────────────────────────────────────


def test_a_leftover_run_pair_row_is_not_served(tmp_path: Path) -> None:
    # ★ A diff aligns ONE binary and its id names it as a third segment. A row whose id is just the
    # two run ids predates that and describes nothing a reader can act on.
    #
    # MUTATION (verified RED, 1 failed): in diff_align.list_diffs drop the `_is_whole_run_row`
    # skip -> the leftover is served as though it were a binary's diff.
    atlas_path = tmp_path / "atlas.db"
    analysis = _analysis(tmp_path / "analysis.db", [("libfoo.so", _SHA_OLD)])
    conn = open_atlas(atlas_path)
    try:
        begin_run(conn, "run_a", analysis_db_path=str(analysis))
        begin_run(conn, "run_b", analysis_db_path=str(analysis))
        for did, binary in (("run_a::run_b", "openssl"), ("run_a::run_b::libfoo.so", "libfoo.so")):
            add_diff_meta(
                conn,
                DiffMetaRow(
                    diff_id=did,
                    run_a_id="run_a",
                    run_b_id="run_b",
                    binary_a=binary,
                    binary_b=binary,
                    sha256_a=_SHA_OLD,
                    sha256_b=_SHA_OLD,
                    diff_ok=0 if did == "run_a::run_b" else 1,
                ),
            )
        served = list_diffs(conn)
        assert [d["diff_id"] for d in served["diffs"]] == ["run_a::run_b::libfoo.so"]
        assert served["count"] == 1
    finally:
        conn.close()


def test_a_failed_per_binary_diff_stays_a_visible_blind_spot(tmp_path: Path) -> None:
    # ★ THE TRAP THE LEFTOVER FILTER MUST NOT FALL INTO. A failed per-binary diff also has
    # diff_ok=0. Filtering the leftover on that flag would take this one with it — hiding a binary
    # that could not be diffed behind the same silence as a row nobody meant to keep. The leftover
    # is identified by the SHAPE OF ITS ID instead.
    #
    # MUTATION (verified RED, 1 failed): in diff_align.list_diffs skip on the flag —
    # `if not row["diff_ok"]: continue` -> the failed binary disappears from the listing.
    atlas_path = tmp_path / "atlas.db"
    analysis = _analysis(tmp_path / "analysis.db", [("libxml2.so.2", _SHA_OLD)])
    conn = open_atlas(atlas_path)
    try:
        begin_run(conn, "run_a", analysis_db_path=str(analysis))
        begin_run(conn, "run_b", analysis_db_path=str(analysis))
        add_diff_meta(
            conn,
            DiffMetaRow(
                diff_id="run_a::run_b::libxml2.so.2",
                run_a_id="run_a",
                run_b_id="run_b",
                binary_a="libxml2.so.2",
                binary_b="libxml2.so.2",
                sha256_a=_SHA_OLD,
                sha256_b=_SHA_OLD,
                diff_ok=0,
                diff_status="failed",
                diff_status_reason="binexport_failed",
                diff_attempts=1,
            ),
        )
        served = list_diffs(conn)
        assert [d["diff_id"] for d in served["diffs"]] == ["run_a::run_b::libxml2.so.2"]
        assert served["diffs"][0]["diff_status"] == "failed"
        # and it is still the blind spot it was
        assert [b["binary"] for b in list_diff_blindspots(conn)["blindspots"]] == ["libxml2.so.2"]
    finally:
        conn.close()


def test_the_generation_of_each_run_is_read_once(tmp_path: Path) -> None:
    # A listing spans many diffs over few runs; resolving each run's analysis.db per row would
    # reopen the same database for every binary.
    atlas_path = tmp_path / "atlas.db"
    shas = [f"{i}{'d' * 63}" for i in range(5)]
    analysis = _analysis(tmp_path / "analysis.db", [(f"lib{i}.so", shas[i]) for i in range(5)])
    conn = open_atlas(atlas_path)
    try:
        begin_run(conn, "run_a", analysis_db_path=str(analysis))
        begin_run(conn, "run_b", analysis_db_path=str(analysis))
        for i in range(5):
            add_diff_meta(
                conn,
                DiffMetaRow(
                    diff_id=f"run_a::run_b::lib{i}.so",
                    run_a_id="run_a",
                    run_b_id="run_b",
                    binary_a=f"lib{i}.so",
                    binary_b=f"lib{i}.so",
                    sha256_a=shas[i],
                    sha256_b=shas[i],
                    diff_ok=1,
                ),
            )
        opened: list[str] = []
        real_connect = sqlite3.connect

        def counting_connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
            opened.append(str(args[0]))
            return real_connect(*args, **kwargs)

        sqlite3.connect = counting_connect  # type: ignore[assignment]
        try:
            served = list_diffs(conn)
        finally:
            sqlite3.connect = real_connect  # type: ignore[assignment]
        assert served["count"] == 5
        assert all(d["source_stale"] is False for d in served["diffs"])
        # two runs, two opens — not one per row
        assert len(opened) == 2, opened
    finally:
        conn.close()
