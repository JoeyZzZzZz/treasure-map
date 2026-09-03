# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""WHICH entry points the staleness gate stands on, and what a blocked completeness check says.

The bar for refusing is decided elsewhere (only a PROVEN mismatch; see test_stale_scan_gate) and is
not re-litigated here. What this file pins is coverage: a gate that stops one tool and waves
another through is not a weaker gate, it is an open door beside a locked one, and the caller has no
way to know which they walked through. The first version of this feature was verified on
get_pseudocode — a tool that happened to route through the gate — while the entry the tool
instructions name FIRST, list_candidates, read the atlas directly and never met it. A run proven to
have been graded by code that no longer exists handed back candidates with no marking at all.

The second half is the same failure one layer down: when the completeness check cannot run, its
three lists come back empty, and empty is how a clean scan looks too.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from treasure_map import mcp_app
from treasure_map.lib.analyze.ghidra_runner import current_pass_version
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, begin_run, finish_run, upsert_pattern
from treasure_map.lib.storage.connection import open_db

STALE_BUILD = "0000staleaaaa000"


def _analysis(tmp_path: Path, name: str) -> Path:
    db = tmp_path / f"{name}.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, pass_version, last_seen_at) "
        "VALUES (1, 'webd', 'usr/sbin/webd', ?, ?, '2026-01-01T00:00:00')",
        ("a" * 64, current_pass_version()),
    )
    conn.execute(
        "INSERT INTO functions (id, binary_id, name, address, size_bytes, pseudocode, callees) "
        "VALUES (1, 1, 'handle_req', '0x6b90', 64, 'void handle_req(){ system(buf); }', ?)",
        (json.dumps(["system"]),),
    )
    conn.commit()
    conn.close()
    return db


def _candidates(conn: object, run_id: str, n: int) -> None:
    pid = upsert_pattern(
        conn,  # type: ignore[arg-type]
        source_class="external_input",
        sink_class="cmd",
        call_sequence_shape="s->cmd",
    )
    for i in range(n):
        add_instance(
            conn,  # type: ignore[arg-type]
            InstanceRow(
                pattern_id=pid,
                pseudocode_hash=f"h_{run_id}_{i}",
                source_anchor="handle_req",
                sink_anchor="system",
                binary_path="usr/sbin/webd",
                source_run_id=run_id,
                evidence_ref=f"{run_id}#handle_req_{i}",
                # The first of each run is 'blocked', so the dormant view (blocked + L0/L1) has
                # rows to exclude. Without one, the exclusion assertion below runs over an empty
                # list and passes without the exclusion having happened.
                reachability_status="blocked" if i == 0 else "unknown",
                provenance_level="L1",
            ),
        )


@pytest.fixture
def atlas(tmp_path: Path) -> Path:
    """Two runs with candidates: one PROVABLY stale, one whose extraction matches this install.

    ★ The stale side is built by setting ``build_hash`` to a value that cannot be the current
    pass_version. Without that, run_staleness answers not-stale for every run in the fixture and
    every assertion below passes without the gate ever being consulted — the vacuous-green shape
    this whole file exists to rule out. The control run is asserted SERVED for the same reason: it
    proves the refusals came from staleness and not from the fixture being broken.
    """
    a = tmp_path / "atlas.db"
    conn = open_atlas(a)
    for run_id, build in (("run_stale", STALE_BUILD), ("run_ok", current_pass_version())):
        begin_run(
            conn,
            run_id,
            analysis_db_path=str(_analysis(tmp_path, run_id).resolve()),
            firmware_path=str(tmp_path / "fw"),
            build_hash=build,
        )
        finish_run(conn, run_id, binaries=1, functions=1)
    _candidates(conn, "run_stale", 3)
    _candidates(conn, "run_ok", 2)
    conn.commit()
    conn.close()
    return a


def test_the_fixture_really_is_provably_stale(atlas: Path) -> None:
    """The anti-vacuity check, asserted before anything else reads it.

    Every refusal assertion in this file is satisfied by a fixture in which nothing is stale, so
    the fixture's staleness is itself a claim that has to be tested."""
    from treasure_map.lib.atlas.connection import open_atlas as _open
    from treasure_map.lib.query import get_run, run_staleness

    conn = _open(atlas)
    try:
        stale = run_staleness(
            get_run(conn, "run_stale"),  # type: ignore[arg-type]
            build_hash=current_pass_version(),
            commit="c" * 40,
        )
        assert stale.stale is True and stale.axis == "extraction"
        ok = run_staleness(
            get_run(conn, "run_ok"),  # type: ignore[arg-type]
            build_hash=current_pass_version(),
            commit="c" * 40,
        )
        assert ok.stale is False
    finally:
        conn.close()


def test_a_stale_run_is_refused_on_the_candidate_entry_points(atlas: Path) -> None:
    """★ THE GAP THIS CLOSES. The map and the ref-following tools are where an agent actually
    arrives; the fact tools are the second hop.

    MUTATION: remove the ``_refuse_stale_run`` call from list_candidates -> RED. Remove the
    ``_stale_refusal`` call from explain_candidate -> RED. Measured RED at 1 failed each.
    """
    tools = mcp_app.make_tools(atlas)

    listing = tools["list_candidates"](run_id="run_stale")
    assert listing["stale_scan"]["axis"] == "extraction"
    assert "tmap rescan run_stale" in listing["remedy"]
    assert "candidates" not in listing

    explained = tools["explain_candidate"]("run_stale#handle_req_0")
    assert explained["stale_scan"]["axis"] == "extraction"
    assert explained.get("found") is not True

    prov = tools["get_sink_provenance"]("run_stale#handle_req_0")
    assert prov["stale_scan"]["axis"] == "extraction"

    # the fact-tool path, unchanged — kept here so the two halves are compared side by side
    assert tools["get_pseudocode"]("handle_req", run_id="run_stale")["found"] is False


@pytest.mark.parametrize("tool", ["get_nvram_key_flow", "list_overlays", "launched_by"])
def test_a_stale_run_is_refused_on_the_run_scoped_readers(atlas: Path, tool: str) -> None:
    """Every reader that takes a run_id refuses the same run for the same reason.

    MUTATION: drop the gate from any one of them -> that parameter goes RED.
    """
    tools = mcp_app.make_tools(atlas)
    call = {
        "get_nvram_key_flow": lambda: tools[tool]("wan_proto", run_id="run_stale"),
        "list_overlays": lambda: tools[tool](run_id="run_stale"),
        "launched_by": lambda: tools[tool]("httpd", run_id="run_stale"),
    }[tool]
    assert call()["stale_scan"]["axis"] == "extraction"


def test_an_unprovable_mismatch_is_still_served(tmp_path: Path) -> None:
    """★ THE GATE MUST NOT EAT THE ATLAS — the counterweight to every refusal above.

    A run with no comparable extraction hash is not shown to be stale, and 'not shown to be stale'
    is the servable side. If widening the gate's coverage had also widened its bar, an atlas full
    of pre-stamp runs would go dark on the day this shipped.

    MUTATION: make _stale_refusal fire on an unconfirmable run -> RED.
    """
    a = tmp_path / "atlas.db"
    conn = open_atlas(a)
    begin_run(
        conn,
        "run_unknown",
        analysis_db_path=str(_analysis(tmp_path, "run_unknown").resolve()),
        firmware_path=str(tmp_path / "fw"),
    )
    finish_run(conn, "run_unknown", binaries=1, functions=1)
    _candidates(conn, "run_unknown", 2)
    conn.commit()
    conn.close()

    tools = mcp_app.make_tools(a)
    listing = tools["list_candidates"](run_id="run_unknown")
    assert "stale_scan" not in listing
    assert listing["corpus"] == 1  # 2 seeded, the blocked one is gated out of the default lens
    assert tools["explain_candidate"]("run_unknown#handle_req_0")["found"] is True


def test_an_all_runs_listing_drops_the_stale_rows_and_names_the_run(atlas: Path) -> None:
    """Unscoped, the map spans firmware, so a refusal would take the current runs down with the
    stale one. The stale run's rows leave the corpus instead — and are COUNTED where they left, so
    "this firmware produced nothing" and "this firmware was not served" stay different answers.

    MUTATION: move the exclusion after ``ranked`` is built (i.e. after ``corpus`` is taken) -> RED,
    because corpus then still counts rows that are not in the listing. Measured RED at 1 failed.
    """
    tools = mcp_app.make_tools(atlas)
    listing = tools["list_candidates"]()

    # run_ok seeds 2 rows and run_stale 3; the first of each is 'blocked', which the default lens
    # gates out. So 1 is served and 2 left — and both numbers are counted AFTER that gating, which
    # is what makes "corpus excludes 2" an arithmetic statement rather than a slogan.
    assert listing["corpus"] == 1, "only the servable run's candidates are in the denominator"
    refused = listing["stale_runs_refused"]
    assert [r["run_id"] for r in refused] == ["run_stale"]
    assert refused[0]["candidates_excluded"] == 2
    assert refused[0]["axis"] == "extraction"
    assert "tmap rescan run_stale" in refused[0]["remedy"]
    assert "excludes 2 candidates" in listing["corpus_note"]
    assert all(c["run"] != "run_stale" for c in listing["candidates"])


def test_the_excluded_count_is_measured_on_the_same_basis_as_corpus(atlas: Path) -> None:
    """★ ``corpus excludes N`` is arithmetic, so N has to be counted the way corpus is.

    This call's own filters narrow the corpus. Counting the refused rows BEFORE those filters would
    report rows that would not have been in the listing anyway — telling a caller who asked for one
    sink class that the corpus is missing candidates of every other class. Turning the gate off
    admits the blocked row on BOTH sides, so both numbers move together.

    MUTATION: count the refused rows where they are removed (before ``_narrow``) -> RED, because
    the excluded count then stays at 3 while corpus is 1.
    """
    tools = mcp_app.make_tools(atlas)
    default = tools["list_candidates"]()
    gated = tools["list_candidates"](include_gated=True)

    assert (default["corpus"], default["stale_runs_refused"][0]["candidates_excluded"]) == (1, 2)
    assert (gated["corpus"], gated["stale_runs_refused"][0]["candidates_excluded"]) == (2, 3)


def test_a_clean_atlas_reports_no_refusals_and_an_untouched_corpus(tmp_path: Path) -> None:
    """The regression on the other side: with nothing stale, the corpus is the whole corpus and
    the two new keys say so without inventing a placeholder entry.

    MUTATION: emit ``corpus_note`` unconditionally -> RED (a note about zero refused runs reads as
    if some had been).
    """
    a = tmp_path / "atlas.db"
    conn = open_atlas(a)
    begin_run(
        conn,
        "run_ok",
        analysis_db_path=str(_analysis(tmp_path, "run_ok").resolve()),
        build_hash=current_pass_version(),
    )
    finish_run(conn, "run_ok", binaries=1, functions=1)
    _candidates(conn, "run_ok", 4)
    conn.commit()
    conn.close()

    listing = mcp_app.make_tools(a)["list_candidates"]()
    assert listing["corpus"] == 3  # 4 seeded, one blocked
    assert listing["stale_runs_refused"] == []
    assert listing["corpus_note"] is None


@pytest.mark.parametrize("tool", ["dormant_candidates", "pattern_density"])
def test_the_cross_run_aggregates_drop_stale_rows_and_name_them(atlas: Path, tool: str) -> None:
    """These readers span firmware, so they annotate rather than refuse — but a row that leaves
    silently is a row that was never there, so the run is named with what it cost.

    MUTATION: drop the exclusion loop from either reader -> RED.
    """
    tools = mcp_app.make_tools(atlas)
    result = tools[tool]()
    refused = result["stale_runs_refused"]
    assert [r["run_id"] for r in refused] == ["run_stale"]
    # 1 blocked instance for dormant; all 3 of the run's instances for the density counts
    assert refused[0]["candidates_excluded"] == (1 if tool == "dormant_candidates" else 3)
    rows = result.get("dormant", result.get("density", []))
    assert rows, "the reader must return the SERVABLE run's rows, or the exclusion proves nothing"
    assert all((r.get("source_run_id") != "run_stale") for r in rows)


@pytest.mark.parametrize("tool", ["pattern_twins", "cross_firmware_patterns"])
def test_an_aggregate_that_cannot_drop_the_rows_says_so(atlas: Path, tool: str) -> None:
    """★ Null is not zero. These two count ACROSS runs and carry no run column, so a refused run's
    instances are still inside the numbers. Reporting ``candidates_excluded: 0`` would claim the
    run contributed nothing; null says its contribution could not be separated out, and the note
    says which numbers still include it.

    MUTATION: report 0 instead of None for these -> RED.
    """
    result = mcp_app.make_tools(atlas)[tool]()
    refused = result["stale_runs_refused"]
    assert [r["run_id"] for r in refused] == ["run_stale"]
    assert refused[0]["candidates_excluded"] is None
    assert "stale_runs_refused" in result["stale_runs_note"]


@pytest.mark.parametrize("side", ["a", "b"])
def test_a_diff_is_refused_when_either_side_is_stale(atlas: Path, side: str) -> None:
    """A diff is a claim about two scans, so it is only as current as the older of them.

    Reading a delta between a run graded by this code and one graded by code that no longer exists
    gives a difference whose cause cannot be told apart from the difference between the graders.
    The refusal names WHICH side, because the two need separate re-scans.

    MUTATION: check only run_a_id -> the 'b' parameter goes RED. Drop the gate from any one diff
    tool -> that tool's assertion goes RED.
    """
    conn = open_atlas(atlas)
    a_id, b_id = ("run_stale", "run_ok") if side == "a" else ("run_ok", "run_stale")
    conn.execute(
        "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id) VALUES (?, ?, ?)",
        ("d1", a_id, b_id),
    )
    conn.commit()
    conn.close()

    tools = mcp_app.make_tools(atlas)
    for call in (
        lambda: tools["get_diff_deltas"]("d1"),
        lambda: tools["get_diff_meta"]("d1"),
        lambda: tools["get_diff_capabilities"]("d1"),
        lambda: tools["get_function_alignment"]("d1", "0x1000"),
    ):
        result = call()
        assert result["stale_scan"]["axis"] == "extraction"
        assert result["stale_scan"]["diff_side"] == side


def test_a_diff_between_two_servable_runs_is_not_refused(atlas: Path) -> None:
    """The counterweight: both sides comparable, so the diff answers."""
    conn = open_atlas(atlas)
    conn.execute(
        "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id) VALUES ('d_ok', 'run_ok', 'run_ok')"
    )
    conn.commit()
    conn.close()
    assert "stale_scan" not in mcp_app.make_tools(atlas)["get_diff_meta"]("d_ok")


# ------------------------------------------------------------------ the completeness red-line


def test_a_blocked_completeness_check_is_visible_not_empty(tmp_path: Path) -> None:
    """★ Empty lists are how a CLEAN scan looks. They must never also be how a check that did not
    run looks.

    incomplete_binaries / partially_incomplete_binaries / folded_xref_symbols exist so that an
    absent candidate is not read as a clean binary. When the run has no recorded analysis.db there
    is nothing to read them from — and the answer used to be the same three empty lists, i.e. the
    strongest possible statement of cleanliness produced by not looking.

    MUTATION: return ``[], [], []`` from _incomplete_for_run's failure branches (dropping the
    fourth element) -> RED. Measured RED at 1 failed.
    """
    a = tmp_path / "atlas.db"
    conn = open_atlas(a)
    begin_run(conn, "no_db", build_hash=current_pass_version())
    finish_run(conn, "no_db")
    _candidates(conn, "no_db", 1)
    conn.commit()
    conn.close()

    listing = mcp_app.make_tools(a)["list_candidates"](run_id="no_db")
    block = listing["analysis_completeness"]
    assert block["unavailable"] is not None
    assert "no recorded analysis.db" in block["unavailable"]["error"]
    assert "UNAVAILABLE, not clean" in block["note"]
    assert listing["incomplete_binaries"] == []  # still empty — the note is what makes it honest


def test_a_completeness_check_that_ran_says_so(atlas: Path) -> None:
    """The other side: when it did run, ``unavailable`` is null and the note does not warn."""
    listing = mcp_app.make_tools(atlas)["list_candidates"](run_id="run_ok")
    block = listing["analysis_completeness"]
    assert block["unavailable"] is None
    assert "UNAVAILABLE" not in block["note"]


def test_an_unscoped_listing_does_not_claim_a_clean_completeness_check(atlas: Path) -> None:
    """Across every run there is no single scan to answer for, so the empty lists are neither a
    result nor a failure — and the note says which."""
    block = mcp_app.make_tools(atlas)["list_candidates"]()["analysis_completeness"]
    assert block["unavailable"] is None
    assert "pass run_id" in block["note"]
