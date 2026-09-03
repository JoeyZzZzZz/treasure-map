# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The staleness gate: MCP REFUSES a proven-stale run, the CLI ANNOTATES an old extraction.

The two halves are deliberately different, and this file exists mostly to keep them different.
An agent routes by run_id and has no way to notice that the answer came out of a pipeline that no
longer exists, so a proven mismatch stops the read. A person naming an analysis.db on the command
line has usually chosen that file on purpose, so the same mismatch is stated and the fact printed.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from click.testing import CliRunner

from treasure_map import mcp_app
from treasure_map.cli.mcp_cli import fact as fact_group
from treasure_map.lib.analyze.ghidra_runner import current_pass_version
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.writer import begin_run, finish_run
from treasure_map.lib.storage.connection import open_db


def _mk_analysis(tmp_path: Path) -> Path:
    """A minimal analysis.db: one binary, one function with pseudocode to fetch."""
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    conn.execute(
        # ★ last_seen_at is LOAD-BEARING here, not decoration: current_binaries selects rows whose
        # last_seen_at equals the maximum, and NULL = NULL is never true, so a fixture that omits it
        # yields an EMPTY view. The staleness read would then find no version to compare and stay
        # silent — and the "says nothing when there is nothing to say" tests below would pass
        # without ever exercising a comparison.
        "INSERT INTO binaries (id, name, path, sha256, pass_version, last_seen_at) "
        "VALUES (1, 'webd', 'usr/sbin/webd', ?, ?, '2026-01-01T00:00:00')",
        ("a" * 64, current_pass_version()),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, size_bytes, pseudocode, callees) "
        "VALUES (1, 1, 'handle_req', '0x6b90', 64, 'void handle_req(){ do_fwd(buf); }', ?)",
        (json.dumps(["do_fwd"]),),
    )
    conn.commit()
    conn.close()
    return db


STALE_BUILD = "0000staleaaaa000"


def _atlas(tmp_path: Path, **lineage: object) -> Path:
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    begin_run(
        conn,
        "run_m",
        analysis_db_path=str((tmp_path / "analysis.db").resolve()),
        firmware_path=str(tmp_path / "fw"),
        **lineage,  # type: ignore[arg-type]
    )
    finish_run(conn, "run_m", binaries=1, functions=2)
    conn.close()
    return atlas


def test_a_proven_stale_extraction_refuses_the_read(tmp_path: Path) -> None:
    """★ The refusal, and why it is a refusal.

    The stored run says it was extracted by a pipeline this install does not have. Every fact the
    tools would return for it is what THAT pipeline recorded, served with the same shape and the
    same confidence as a current answer — an agent cannot tell them apart, and a caveat attached to
    a large result does not change what the agent then reasons from. So the read stops and hands
    back the command that fixes it.

    MUTATION: delete the ``if stale.stale`` block from ``_resolve_db`` -> RED.
    """
    _mk_analysis(tmp_path)
    tools = mcp_app.make_tools(_atlas(tmp_path, build_hash=STALE_BUILD))
    r = tools["get_pseudocode"]("handle_req", run_id="run_m")
    assert r["found"] is False
    assert r["stale_scan"]["axis"] == "extraction"
    assert STALE_BUILD in r["stale_scan"]["detail"]
    assert "tmap rescan run_m" in r["remedy"]


def test_the_remedy_matches_what_the_run_actually_recorded(tmp_path: Path) -> None:
    """A run with no firmware root gets the manual remedy, not a command that cannot run."""
    _mk_analysis(tmp_path)
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    begin_run(
        conn,
        "run_m",
        analysis_db_path=str((tmp_path / "analysis.db").resolve()),
        build_hash=STALE_BUILD,
    )
    finish_run(conn, "run_m")
    conn.close()
    r = mcp_app.make_tools(atlas)["get_pseudocode"]("handle_req", run_id="run_m")
    assert r["found"] is False
    assert "tmap rescan" not in r["remedy"]
    assert "tmap scan <firmware-root> --run-id run_m" in r["remedy"]


@pytest.mark.parametrize(
    ("lineage", "why"),
    [
        ({}, "a run with no recorded lineage at all"),
        ({"build_hash": None}, "no stored extraction hash"),
        ({"build_hash": "mixed:2"}, "a count, not a comparable hash"),
    ],
)
def test_an_unconfirmable_run_is_still_readable(
    tmp_path: Path, lineage: dict[str, object], why: str
) -> None:
    """★ THE GATE MUST NOT EAT THE ATLAS.

    Every run written before the stamp existed falls in here, as does every run scanned by an
    editable install. If "cannot confirm current" refused, this change would make an existing atlas
    unreadable on the day it lands and the only practical response would be to turn the gate off.
    Refusal is reserved for a mismatch that was actually demonstrated.

    MUTATION: change ``run_staleness`` to treat a missing or unmatched-by-absence value as stale ->
    RED here (and the refusal test above still passes, so the two directions are pinned apart).
    """
    _mk_analysis(tmp_path)
    tools = mcp_app.make_tools(_atlas(tmp_path, **lineage))
    r = tools["get_pseudocode"]("handle_req", run_id="run_m")
    assert r.get("found") is not False, why
    assert "stale_scan" not in r


def test_a_current_extraction_reads_normally(tmp_path: Path) -> None:
    _mk_analysis(tmp_path)
    tools = mcp_app.make_tools(_atlas(tmp_path, build_hash=current_pass_version()))
    r = tools["get_pseudocode"]("handle_req", run_id="run_m")
    assert "stale_scan" not in r


# --------------------------------------------------------------------------- the CLI half


def _set_pass_version(analysis: Path, value: str | None) -> None:
    conn = sqlite3.connect(analysis)
    conn.execute("UPDATE binaries SET pass_version = ?", (value,))
    conn.commit()
    conn.close()


def test_cli_fact_annotates_an_old_extraction_and_still_prints_the_fact(tmp_path: Path) -> None:
    """★ ANNOTATION, NEVER REFUSAL — the deliberate asymmetry with the MCP path above.

    Reading facts out of a previous extraction on purpose is a normal thing to do on the command
    line; it is often the whole reason the old analysis.db is still on disk. So the mismatch is
    stated in its own key and the fact is printed anyway.

    MUTATION: turn ``_stale_extract`` into an early return / error path -> RED (the payload
    disappears). Rename the key into the record's existing ``note`` -> RED (two independent honest
    statements would then overwrite each other).
    """
    analysis = _mk_analysis(tmp_path)
    _set_pass_version(analysis, STALE_BUILD)
    out = CliRunner().invoke(
        fact_group, ["pseudocode", "handle_req", "--analysis-db", str(analysis)]
    )
    assert out.exit_code == 0, out.output
    payload = json.loads(out.output)
    assert STALE_BUILD in payload["stale_extract_warning"]
    assert payload["found"] is True
    assert payload["pseudocode"]


def test_cli_fact_says_nothing_when_the_extraction_matches(tmp_path: Path) -> None:
    """No note when the comparison was made and came out equal — the only silent case.

    ★ The visible-row assertion is here because this test can pass for the WRONG reason. An
    analysis.db whose current_binaries view is empty also produces no note — silence proves nothing
    unless there was a row to compare. It cost a debugging round to notice, so it is asserted.
    """
    analysis = _mk_analysis(tmp_path)
    _set_pass_version(analysis, current_pass_version())
    conn = sqlite3.connect(analysis)
    assert conn.execute("SELECT COUNT(*) FROM current_binaries").fetchone()[0] == 1
    conn.close()
    out = CliRunner().invoke(
        fact_group, ["pseudocode", "handle_req", "--analysis-db", str(analysis)]
    )
    assert out.exit_code == 0, out.output
    assert "stale_extract_warning" not in json.loads(out.output)


def test_cli_fact_says_so_when_the_extraction_pass_was_never_recorded(tmp_path: Path) -> None:
    """★ An unrecorded pipeline version is UNKNOWN, and unknown gets said out loud.

    The check used to filter these rows out of its own query, so an analysis.db predating the
    versioning produced the same silence as one that matched. Silence here reads as "extracted by
    the pipeline you are running" — which is exactly the collapse of "cannot tell" into "same"
    that this note exists to prevent. The fact is still printed; only the silence is gone.

    MUTATION: put ``WHERE pass_version IS NOT NULL`` back on the query -> RED (no warning key).
    Measured RED at 1 failed.

    ★ The visible-row assertion is load-bearing for the same reason as above: with an empty
    current_binaries view there is no NULL to find and the branch never runs.
    """
    analysis = _mk_analysis(tmp_path)
    _set_pass_version(analysis, None)
    conn = sqlite3.connect(analysis)
    assert conn.execute("SELECT COUNT(*) FROM current_binaries").fetchone()[0] == 1
    conn.close()
    out = CliRunner().invoke(
        fact_group, ["pseudocode", "handle_req", "--analysis-db", str(analysis)]
    )
    assert out.exit_code == 0, out.output
    payload = json.loads(out.output)
    assert "extraction pass unknown" in payload["stale_extract_warning"]
    assert payload["found"] is True  # annotated, never refused
    assert payload["pseudocode"]


def test_cli_fact_tolerates_an_analysis_db_without_the_column(tmp_path: Path) -> None:
    """An analysis.db too old to have pass_version must still answer, not crash on the check.

    MUTATION: remove the OperationalError branch from ``_stale_extract`` -> RED.
    """
    analysis = _mk_analysis(tmp_path)
    conn = sqlite3.connect(analysis)
    conn.execute("ALTER TABLE binaries DROP COLUMN pass_version")
    conn.commit()
    conn.close()
    out = CliRunner().invoke(
        fact_group, ["pseudocode", "handle_req", "--analysis-db", str(analysis)]
    )
    assert out.exit_code == 0, out.output
    assert json.loads(out.output)["found"] is True
