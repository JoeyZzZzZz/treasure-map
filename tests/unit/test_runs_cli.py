# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""CLI ergonomics for runs: `tmap runs` lists the atlas's scans + lineage, `tmap triage` prints
the current run's lineage at the top (the stale-scan guard), and `--run` tab-completes run ids."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from treasure_map.cli import hunt_cli
from treasure_map.cli.hunt_cli import _complete_run_id, runs, triage
from treasure_map.lib import rescan_version
from treasure_map.lib.analyze.ghidra_runner import current_pass_version
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import add_instance, begin_run, finish_run, upsert_pattern
from treasure_map.lib.config.config import load_config
from treasure_map.version import UNKNOWN_VERSION


def _running_stamp() -> rescan_version.CodeStamp:
    """The code stamp the in-process ``runs`` / ``rescan`` command will compute (real installed
    code, same config it loads), so a test can stamp a run row to read as current."""
    return rescan_version.current_code_stamp(load_config(None))


def _atlas_with_runs(tmp_path: Path) -> Path:
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    # a fully-recorded run
    begin_run(conn, "rt_scanned", analysis_db_path="/ws/rt/analysis.db", build_hash="pv_a")
    finish_run(conn, "rt_scanned", binaries=12, functions=3400)
    # a pre-existing run: candidates only, no lineage row
    pid = upsert_pattern(
        conn, source_class="external_input", sink_class="cmd", call_sequence_shape="s->cmd"
    )
    add_instance(
        conn,
        InstanceRow(
            pattern_id=pid,
            pseudocode_hash="h1",
            sink_anchor="FUN_1",
            source_run_id="old_preexisting",
            evidence_ref="old_preexisting#fn1",
        ),
    )
    conn.close()
    return atlas


def test_runs_lists_lineage_and_flags_unresolved(tmp_path: Path) -> None:
    atlas = _atlas_with_runs(tmp_path)
    r = CliRunner().invoke(runs, ["--atlas", str(atlas)])
    assert r.exit_code == 0, r.output
    assert "rt_scanned" in r.output
    assert "complete" in r.output  # status shown
    assert "12 bins / 3400 fns" in r.output
    # the pre-existing (instance-only) run is VISIBLE but flagged, never hidden
    assert "old_preexisting" in r.output
    assert "no lineage row" in r.output


def test_runs_json_mode(tmp_path: Path) -> None:
    atlas = _atlas_with_runs(tmp_path)
    r = CliRunner().invoke(runs, ["--atlas", str(atlas), "--json"])
    assert r.exit_code == 0, r.output
    data = json.loads(r.output)
    by_id = {row["run_id"]: row for row in data}
    assert by_id["rt_scanned"]["scan_status"] == "complete"
    assert by_id["rt_scanned"]["resolved"] is True
    assert by_id["old_preexisting"]["resolved"] is False  # honestly unresolved


def test_runs_empty_atlas_is_friendly(tmp_path: Path) -> None:
    atlas = tmp_path / "atlas.db"
    open_atlas(atlas).close()
    r = CliRunner().invoke(runs, ["--atlas", str(atlas)])
    assert r.exit_code == 0
    assert "no runs" in r.output and "tmap scan" in r.output


def test_triage_prints_run_lineage_header(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # ★ The run's lineage rides the top of the triage view. A PROVEN stale run is refused before
    # it (see the stale-refusal tests), so this run is made current: the running pass is pv_a.
    monkeypatch.setattr(
        "treasure_map.lib.analyze.ghidra_runner.current_pass_version", lambda: "pv_a"
    )
    atlas = _atlas_with_runs(tmp_path)
    r = CliRunner().invoke(triage, ["--run", "rt_scanned", "--atlas", str(atlas)])
    assert r.exit_code == 0, r.output
    assert "run: rt_scanned" in r.output and "build pv_a" in r.output


def test_triage_without_a_run_is_refused_and_names_the_runs(tmp_path: Path) -> None:
    """A run is required: the whole-atlas triage materialised every run's candidates. The refusal
    names the runs to pick from, so it is a step forward, not a dead end.

    MUTATION: delete the ``selected_run is None`` refusal in triage -> RED (exit 0, a listing).
    """
    atlas = _atlas_with_runs(tmp_path)
    r = CliRunner().invoke(triage, ["--atlas", str(atlas)])
    assert r.exit_code != 0, r.output
    assert "needs a run" in r.output
    assert "rt_scanned" in r.output


def test_triage_with_a_misspelled_run_is_an_error_that_names_the_runs(tmp_path: Path) -> None:
    """``tmap triage --run <typo>`` must error and list the real runs, never exit 0 over an empty
    list (which reads as "this run has no candidates", so a typo looks like a clean scan).

    MUTATION: delete the run-existence check after _refuse_stale_triage_run in triage -> RED
    (exit 0, an empty listing for a run that does not exist)."""
    atlas = _atlas_with_runs(tmp_path)
    r = CliRunner().invoke(triage, ["--run", "nope", "--atlas", str(atlas)])
    assert r.exit_code != 0, r.output
    assert "no such run" in r.output
    assert "rt_scanned" in r.output


def test_run_id_completion_matches_prefix(tmp_path: Path) -> None:
    # ★ Tab-completion returns the atlas's run ids that start with the incomplete token; no
    # ambiguous short-prefix auto-match (the user SEES and picks).
    atlas = _atlas_with_runs(tmp_path)

    class _Ctx:
        params = {"atlas_path": atlas}

    out = _complete_run_id(_Ctx(), None, "rt_")  # type: ignore[arg-type]
    assert [c.value for c in out] == ["rt_scanned"]
    assert _complete_run_id(_Ctx(), None, "zzz") == []  # type: ignore[arg-type]


def _run_lines(output: str) -> list[str]:
    """The per-run lines of a listing: indented, and not one of the tier's ``→`` reason lines."""
    return [
        ln
        for ln in output.splitlines()
        if ln.startswith("  ") and not ln.strip().startswith("→") and ln.strip()
    ]


def test_the_human_listing_carries_no_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The listing answers what is here and whether it is current. The build hash, the hunt
    stamp and the row count answer neither: they are what a machine compares, they are in
    ``--json``, and on six lines they crowded out the list they were annotating.

    MUTATION: put the ``build`` / ``hunt`` / ``rows`` parts back into ``_run_lineage_line`` -> RED.
    Measured RED at 1 failed.
    """
    # A commit the stamps can differ FROM. Without it the editable install records none and every
    # run lands on the same "cannot be confirmed" reason, before the reason under test is reached.
    monkeypatch.setattr(hunt_cli, "installed_commit", lambda: "c" * 40)
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    begin_run(conn, "stamped", analysis_db_path="/ws/a.db", build_hash="pv_a")
    finish_run(conn, "stamped", binaries=3, functions=9, hunt_commit="f" * 40, hunt_instances=1683)
    begin_run(conn, "unstamped", analysis_db_path="/ws/b.db", build_hash="pv_a")
    finish_run(conn, "unstamped", binaries=1, functions=2)
    conn.close()

    out = CliRunner().invoke(runs, ["--atlas", str(atlas)])
    assert out.exit_code == 0, out.output
    # Checked on the RUN LINES, not the whole output: the tier label and the reason both
    # legitimately contain "re-hunt", so asserting over everything is a check nothing can satisfy.
    run_lines = _run_lines(out.output)
    assert run_lines, out.output
    for line in run_lines:
        for token in ("build ", "hunt ", "rows "):
            assert token not in line, (token, line)
    # what it DOES carry: the run, its state, and one line saying what to do about it
    assert "stamped" in out.output and "3 bins / 9 fns" in out.output
    assert "needs re-extraction (2):" in out.output  # build_hash 'pv_a' is not this pipeline
    assert "`tmap rescan`" in out.output


def test_the_one_run_banner_keeps_its_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The counterweight. The banner at the top of a candidate view exists so a STALE scan
    cannot be read in silence, and that view has no ``--json`` to fall back on — so the build hash
    stays there even though the listing dropped it. Two surfaces, two questions.

    MUTATION: point ``_echo_run_lineage`` at ``_run_lineage_line`` -> RED.
    """
    monkeypatch.setattr(
        "treasure_map.lib.analyze.ghidra_runner.current_pass_version", lambda: "pv_a"
    )
    atlas = _atlas_with_runs(tmp_path)
    out = CliRunner().invoke(triage, ["--run", "rt_scanned", "--atlas", str(atlas)])
    assert out.exit_code == 0, out.output
    assert "run: rt_scanned" in out.output and "build pv_a" in out.output


def test_the_reason_is_said_once_per_tier_not_once_per_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Six runs out of date for the same reason is ONE fact about the install. Repeated beside
    every line it buried the list; with a single reason the run ids are redundant too.

    MUTATION: make ``_reason_human`` return "" -> RED.
    """
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    for rid in ("a_run", "b_run"):
        begin_run(conn, rid, analysis_db_path=f"/ws/{rid}.db", build_hash=current_pass_version())
        # Both hunted by a DIFFERENT hunt code than is running — the same reason for both.
        finish_run(
            conn,
            rid,
            binaries=2,
            functions=3,
            hunt_instances=1,
            hunt_code_version="src-b2b2b2b2b2b2b2b2",
        )
    conn.close()

    out = CliRunner().invoke(runs, ["--atlas", str(atlas)])
    assert out.exit_code == 0, out.output
    arrows = [ln for ln in out.output.splitlines() if ln.strip().startswith("→")]
    assert len(arrows) == 1, out.output
    assert arrows[0].strip() == (
        "→ the hunt code changed since this run was hunted; re-hunt needs no decompile"
    )


def test_two_reasons_in_one_tier_are_listed_apart_with_their_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Grouping must not merge two situations into whichever sentence came first — each reason
    names the runs it is about.

    MUTATION: emit only the first reason, or drop the run ids when there are several groups -> RED.
    """
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    stamp = _running_stamp()
    # Both land in the SAME tier (hunt) for DIFFERENT reasons — which is the property under test.
    # graded_old: a different hunt code. uncounted: the running code and scan stamp, but no recorded
    # instance count (so the count branch is what fires, reached only past the code/scan branches).
    begin_run(conn, "graded_old", analysis_db_path="/ws/a.db", build_hash=current_pass_version())
    finish_run(
        conn,
        "graded_old",
        binaries=2,
        functions=3,
        hunt_instances=1,
        hunt_code_version="src-b2b2b2b2b2b2b2b2",
    )
    begin_run(conn, "uncounted", analysis_db_path="/ws/b.db", build_hash=current_pass_version())
    finish_run(
        conn,
        "uncounted",
        binaries=1,
        functions=1,
        hunt_code_version=stamp.hunt,
        scan_stamp=stamp.scan,
    )
    conn.close()

    out = CliRunner().invoke(runs, ["--atlas", str(atlas)])
    assert out.exit_code == 0, out.output
    arrows = [ln.strip() for ln in out.output.splitlines() if ln.strip().startswith("→")]
    assert len(arrows) == 2, out.output
    assert any(a.endswith(": graded_old") and "hunt code changed" in a for a in arrows)
    assert any(a.endswith(": uncounted") and "recorded what it ran" in a for a in arrows)


def test_an_unmapped_reason_passes_through_verbatim() -> None:
    """★ Rewriting only the reasons that were thought of is how a new one becomes invisible: the
    reader would see a familiar sentence describing a situation nobody had considered.

    MUTATION: return a catch-all sentence instead of the reason -> RED.
    """
    from treasure_map.cli.hunt_cli import _reason_human

    novel = "the moon was in the wrong phase"
    assert _reason_human("hunt", novel) == novel
    assert _reason_human("extraction", novel) == novel
    # and the mapped ones ARE rewritten, so the passthrough is not simply doing nothing
    assert "needs no decompile" in _reason_human("hunt", "hunted by hunt code src-a, running src-b")
    # the unconfirmable-scan-stamp reason is mapped too (its _REASON_HUMAN entry, audit G13)
    confirmed = _reason_human("hunt", "scan stamp cannot be confirmed: scan stamp")
    assert "cannot be confirmed" in confirmed and "rescan needs no decompile" in confirmed
    assert "decompiles 37 binaries" in _reason_human(
        "extraction", "extracted by abc, running def", binaries=37
    )


def test_runs_groups_by_which_input_moved(tmp_path: Path) -> None:
    """★ The same three tiers `tmap rescan` uses, from the same classifier — so the command that
    lists runs and the command that refreshes them cannot disagree about which are current.

    MUTATION: classify with ``run_staleness`` instead -> RED (it treats an unconfirmable run as
    current, so the un-stamped run would be reported up to date and never offered for refresh).
    """
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    begin_run(conn, "old_extract", analysis_db_path="/ws/a.db", build_hash="facefeedfacefeed")
    finish_run(conn, "old_extract", binaries=37, functions=9)
    begin_run(conn, "old_hunt", analysis_db_path="/ws/b.db", build_hash=current_pass_version())
    finish_run(conn, "old_hunt", binaries=2, functions=3)
    conn.close()

    out = CliRunner().invoke(runs, ["--atlas", str(atlas)])
    assert out.exit_code == 0, out.output
    assert "needs re-extraction (1)" in out.output
    assert "old_extract" in out.output
    assert "needs re-hunt (1)" in out.output
    assert "old_hunt" in out.output
    assert "tmap rescan" in out.output


def test_runs_json_carries_the_stamp_and_the_classification(tmp_path: Path) -> None:
    """A script gets the same answer without re-deriving it (and so cannot derive a different one).

    MUTATION: drop the ``staleness`` key from the JSON view -> RED.
    """
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    begin_run(conn, "r", analysis_db_path="/ws/a.db", build_hash="facefeedfacefeed")
    finish_run(conn, "r", hunt_commit="f" * 40, hunt_instances=12)
    conn.close()

    out = CliRunner().invoke(runs, ["--atlas", str(atlas), "--json"])
    assert out.exit_code == 0, out.output
    row = json.loads(out.output)[0]
    assert row["hunt_commit"] == "f" * 40
    assert row["hunt_instances"] == 12
    assert row["staleness"]["axis"] == "extraction"
    assert "facefeedface" in row["staleness"]["reason"]


# ── the fourth tier: a run that never finished needs a whole scan, not a fast re-hunt ──


def _unfinished_atlas(
    tmp_path: Path, *, firmware: str | None = None, fine_current: bool = True
) -> Path:
    """One run that stopped mid-scan and one that is up to date.

    ``fine_current`` stamps the finished run with the running code stamp so it reads as current;
    False leaves it an old run (no code stamp), which falls back to the commit and so lands in the
    hunt tier — used by the ordering test."""
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    begin_run(
        conn,
        "stopped",
        analysis_db_path="/ws/a.db",
        firmware_path=firmware,
        build_hash=current_pass_version(),
    )
    finish_run(conn, "stopped", scan_status="failed", binaries=7, functions=9)
    begin_run(conn, "fine", analysis_db_path="/ws/b.db", build_hash=current_pass_version())
    stamp = _running_stamp()
    finish_run(
        conn,
        "fine",
        binaries=1,
        functions=1,
        hunt_commit="c" * 40,
        hunt_instances=0,
        hunt_code_version=stamp.hunt if fine_current else None,
        scan_stamp=stamp.scan if fine_current else None,
    )
    conn.close()
    return atlas


def test_an_unfinished_run_is_its_own_tier_not_a_fast_re_hunt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A run that never finished was reported as "needs re-hunt / fast, no decompile".

    That is a promise about how long the fix takes, and it was wrong in the expensive direction:
    the run's analysis.db is incomplete or absent, so bringing it forward is a full scan with the
    decompiler in it. The reader was told seconds and got Ghidra.

    MUTATION: return ``("hunt", …)`` from the scan_status branch again -> RED.
    """
    monkeypatch.setattr(hunt_cli, "installed_commit", lambda: "c" * 40)
    out = CliRunner().invoke(runs, ["--atlas", str(_unfinished_atlas(tmp_path))])
    assert out.exit_code == 0, out.output
    assert "needs a full re-scan (1):" in out.output
    assert "needs re-hunt" not in out.output
    assert "up to date (1):" in out.output
    # the cost is stated where the tier is named, and it is the honest (pessimistic) one
    arrows = [ln.strip() for ln in out.output.splitlines() if ln.strip().startswith("→")]
    assert any("needs a full scan" in a and "did not finish" in a for a in arrows), arrows
    assert any("7 binaries" in a for a in arrows), arrows  # sized like the other decompiling tier


def test_a_run_with_no_lineage_row_is_in_the_same_tier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pre-existing scan this tmap never recorded is the same situation one step earlier: there
    is nothing to compare, and the fix is a whole scan.

    ★ What the ``not run.resolved`` half actually decides is the SENTENCE, not the tier. Such a run
    also carries ``scan_status='unknown'``, so the status half already puts it here — but the
    reason it would then give is "previous run did not finish", which is not what happened. It did
    not fail; it was never recorded. Asserted on the tier's ``→`` line, because the run's own line
    says "no lineage row" either way and an assertion over the whole output passes without the
    branch under test doing anything (it did, until this was tightened).

    MUTATION: drop the ``not run.resolved`` half -> RED (the tier reason becomes "did not finish").
    """
    monkeypatch.setattr(hunt_cli, "installed_commit", lambda: "c" * 40)
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    pid = upsert_pattern(
        conn, source_class="external_input", sink_class="cmd", call_sequence_shape="s->cmd"
    )
    add_instance(
        conn,
        InstanceRow(
            pattern_id=pid,
            pseudocode_hash="h1",
            sink_anchor="FUN_1",
            source_run_id="no_lineage",
            evidence_ref="no_lineage#fn1",
        ),
    )
    conn.close()

    out = CliRunner().invoke(runs, ["--atlas", str(atlas)])
    assert out.exit_code == 0, out.output
    assert "needs a full re-scan (1):" in out.output
    (arrow,) = [ln.strip() for ln in out.output.splitlines() if ln.strip().startswith("→")]
    assert "never recorded" in arrow, arrow
    assert "did not finish" not in arrow, arrow


def test_the_unfinished_tier_is_decided_before_the_unknown_commit_branch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ THE ORDER, and the only fixture that can see it.

    A run with no code stamp (every run before this feature) is caught by the "hunted before the
    code stamp existed" branch, which matches EVERY old run. Put the unfinished check behind it and
    this tier is empty exactly where it is most needed. Nothing else in the suite catches that: a
    fixture whose runs all carry a current code stamp never reaches the branch that would steal the
    run.

    ★ The build_hash matches the running pipeline on purpose too. With a stale one the extraction
    branch answers first, and the test would pass with the unfinished check anywhere after it.

    MUTATION: move the unfinished check below the code-stamp-missing branch -> RED.
    """
    monkeypatch.setattr(hunt_cli, "installed_commit", lambda: UNKNOWN_VERSION)
    # 'fine' kept as an OLD run (no code stamp), so it IS caught by the catch-all branch — the one
    # the unfinished check must be ordered ahead of.
    out = CliRunner().invoke(
        runs, ["--atlas", str(_unfinished_atlas(tmp_path, fine_current=False))]
    )
    assert out.exit_code == 0, out.output
    assert "needs a full re-scan (1):" in out.output
    assert "stopped" in out.output
    # the other run has no code stamp, so it lands in the hunt tier — which is what makes this a
    # real ordering test: the catch-all branch IS live here and did not take 'stopped'
    assert "needs re-hunt (1):" in out.output


def test_the_unfinished_tier_reaches_the_json_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A tier missing from the JSON view reports ``staleness: null`` — which a script reads as
    "confirmed current", the one thing these runs are not. The omission looks like nothing at all
    in the output, which is what makes it worth pinning.

    MUTATION: build ``axis_reason`` from the extraction and hunt tiers only -> RED.
    """
    monkeypatch.setattr(hunt_cli, "installed_commit", lambda: "c" * 40)
    out = CliRunner().invoke(runs, ["--atlas", str(_unfinished_atlas(tmp_path)), "--json"])
    assert out.exit_code == 0, out.output
    by_id = {r["run_id"]: r for r in json.loads(out.output)}
    assert by_id["stopped"]["staleness"]["axis"] == "incomplete"
    assert "did not finish" in by_id["stopped"]["staleness"]["reason"]
    assert by_id["fine"]["staleness"] is None  # the counterweight: current really is null


def test_the_closing_line_counts_the_unfinished_tier_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The closing line claims what `tmap rescan` can do about what was just listed. Check only
    some tiers for a firmware root and the runs in the others are quietly assumed refreshable —
    and the tier most likely to hold un-refreshable runs is the one for runs that never finished.

    MUTATION: build ``stale_runs`` from the extraction and hunt tiers only -> RED (the output
    promises `tmap rescan` refreshes them, when the only stale run has no firmware root at all).
    """
    monkeypatch.setattr(hunt_cli, "installed_commit", lambda: "c" * 40)
    out = CliRunner().invoke(runs, ["--atlas", str(_unfinished_atlas(tmp_path, firmware=None))])
    assert out.exit_code == 0, out.output
    assert "readable via `tmap fact pseudocode <func> --analysis-db" in out.output
    assert "`tmap rescan` refreshes them." not in out.output

    # and the counterweight: with the root present, the plain sentence is the true one
    fw = tmp_path / "fw"
    fw.mkdir()
    out2 = CliRunner().invoke(
        runs, ["--atlas", str(_unfinished_atlas(tmp_path / "b", firmware=str(fw)))]
    )
    assert out2.exit_code == 0, out2.output
    assert "`tmap rescan` refreshes them." in out2.output


def test_read_only_commands_never_create_the_atlas(tmp_path: Path) -> None:
    """MUTATION: open (and so create) the atlas before checking it exists -> RED."""
    from click.testing import CliRunner

    from treasure_map.cli.hunt_cli import atlas_view, runs, triage

    atlas = tmp_path / "none" / "atlas.db"
    for cmd, args in ((runs, []), (triage, []), (atlas_view, ["density"])):
        result = CliRunner().invoke(cmd, [*args, "--atlas", str(atlas)])
        assert result.exit_code == 1 and "no atlas yet" in result.output, result.output
        assert not atlas.exists()


def test_a_missing_analysis_db_is_a_message_not_a_traceback(tmp_path: Path) -> None:
    """MUTATION: open the path without checking it -> sqlite OperationalError -> RED."""
    from click.testing import CliRunner

    from treasure_map.cli.mcp_cli import fact

    result = CliRunner().invoke(fact, ["pseudocode", "main", "--analysis-db", str(tmp_path / "x")])
    assert isinstance(result.exception, SystemExit) and result.exit_code == 1
    assert "no analysis database at" in result.output
