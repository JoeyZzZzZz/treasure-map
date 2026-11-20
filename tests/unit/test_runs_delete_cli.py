# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""`tmap runs` now lists diffs beside scans, deletes runs / pairs / single diffs from the atlas, and
`tmap scan` / `tmap analyze` confirm before overwriting a scan of DIFFERENT firmware.

Deletion removes atlas records only: files are kept, and human annotations (overlay) are kept and
only counted. Everything is validated before anything is touched, and applied in one transaction."""

from __future__ import annotations

import fcntl
import json
import sqlite3
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from treasure_map.cli.analyze_cli import confirm_overwrite
from treasure_map.cli.hunt_cli import _render_diff_pairs, runs
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import DiffMetaRow, InstanceRow
from treasure_map.lib.atlas.writer import (
    add_diff_meta,
    add_instance,
    begin_run,
    finish_run,
    upsert_pattern,
)
from treasure_map.lib.errors import TreasureMapError
from treasure_map.lib.query.runs import run_recorded_elsewhere
from treasure_map.lib.run_delete import plan_delete
from treasure_map.lib.storage.connection import open_db
from treasure_map.lib.workspace.workspace import Workspace, workspace_holds_other_firmware

_LOCK = Workspace._LOCK_NAME


# ── fixtures ──────────────────────────────────────────────────────────────────


def _atlas(tmp: Path) -> Path:
    """Two finished runs (av, bv), two per-binary diffs av::bv (libok, libbad), one instance under
    av, and two overlay rows: a scan judgement on av and a diff judgement on av::bv."""
    atlas = tmp / "atlas.db"
    conn = open_atlas(atlas)
    for rid in ("av", "bv"):
        begin_run(
            conn,
            rid,
            analysis_db_path=f"/outside/{rid}/analysis.db",
            firmware_path=f"/fw/{rid}",
            build_hash="pv",
        )
        finish_run(conn, rid, binaries=5, functions=100)
    for binary, ok, reason in (("libok", 1, None), ("libbad", 0, "bindiff_flowgraph")):
        add_diff_meta(
            conn,
            DiffMetaRow(
                diff_id=f"av::bv::{binary}",
                run_a_id="av",
                run_b_id="bv",
                binary_a=binary,
                binary_b=binary,
                diff_ok=ok,
                diff_status="ok" if ok else "failed",
                diff_status_reason=reason,
                matched_pairs=10 if ok else None,
            ),
            commit=True,
        )
    pid = upsert_pattern(
        conn, source_class="external_input", sink_class="cmd", call_sequence_shape="s->cmd"
    )
    add_instance(
        conn,
        InstanceRow(
            pattern_id=pid,
            pseudocode_hash="h",
            sink_anchor="F",
            source_run_id="av",
            evidence_ref="av#F",
        ),
    )
    conn.execute(
        "INSERT INTO overlay (anchor_kind, anchor_ref, run_id, verdict, rationale) "
        "VALUES ('evidence_ref','av#F','av','safe','x')"
    )
    conn.execute(
        "INSERT INTO overlay (anchor_kind, anchor_ref, run_id, verdict, rationale) "
        "VALUES ('diff_subject','av::bv#candidate#k','av::bv','changed_real','y')"
    )
    conn.commit()
    conn.close()
    return atlas


def _counts(atlas: Path, table: str, where: str = "") -> int:
    conn = sqlite3.connect(atlas)
    try:
        return int(conn.execute(f"SELECT COUNT(*) FROM {table} {where}").fetchone()[0])  # noqa: S608
    finally:
        conn.close()


def _mk_analysis_db(path: Path, binary_paths: list[str]) -> Path:
    """An analysis.db whose current binaries are at ``binary_paths`` (as a scan records them)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = open_db(path)
    for i, bp in enumerate(binary_paths, start=1):
        conn.execute(
            "INSERT INTO binaries (id, name, path, sha256, last_seen_at) "
            "VALUES (?, ?, ?, ?, '2026-01-01 00:00:00')",
            (i, Path(bp).name, bp, f"{i:064d}"),
        )
    conn.commit()
    conn.close()
    return path


def _invoke(atlas: Path, args: list[str]):
    return CliRunner().invoke(runs, ["--atlas", str(atlas), *args])


# ── listing ───────────────────────────────────────────────────────────────────


def test_listing_shows_runs_and_diff_pairs(tmp_path: Path) -> None:
    atlas = _atlas(tmp_path)
    out = _invoke(atlas, [])
    assert out.exit_code == 0, out.output
    assert "av" in out.output and "bv" in out.output
    assert "diffs (1 pair(s)):" in out.output
    assert "av::bv" in out.output and "2 diffs" in out.output
    # a failed diff is never silent: its count and reason are on the pair's line (a blind spot
    # must never read as 'no change'); the binary itself is named under --diffs
    assert "FAILED 1 (bindiff_flowgraph)" in out.output
    assert "libbad" not in out.output
    assert "libbad" in _invoke(atlas, ["--diffs"]).output
    assert "--delete" in out.output  # the removal hint


def test_render_diff_pairs_hides_current_unless_diffs_flag() -> None:
    # Unit-level: a genuinely-current diff needs the full currency stamps, so drive the renderer
    # directly with the row shapes list_diff_pairs produces.
    pair = {
        "run_pair": "a::b",
        "last_diffed_at": "2026-01-01 00:00:00",
        "counts": {"total": 2, "current": 1, "stale": 0, "unverified": 0, "failed": 1},
        "diffs": [
            {"binary": "libok", "diff_ok": 1, "source_stale": False, "matched_pairs": 10},
            {
                "binary": "libbad",
                "diff_ok": 0,
                "source_stale": None,
                "diff_status_reason": "bindiff_failed",
            },
        ],
    }
    default = _render_diff_pairs([pair], show_all=False)
    (pair_line,) = [ln for ln in default if "a::b" in ln]  # exactly one line for the pair
    assert "current 1" in pair_line and "FAILED 1 (bindiff_failed)" in pair_line
    assert not any("libok" in ln or "libbad" in ln for ln in default)  # no per-binary lines
    assert "`tmap runs --diffs` lists each binary." in default
    every = "\n".join(_render_diff_pairs([pair], show_all=True))
    assert "libok" in every and "current 10 pairs" in every
    assert "libbad" in every and "FAILED   bindiff_failed" in every


def _stale_rows(reasons: list[str]) -> list[dict[str, object]]:
    return [
        {"binary": f"b{i}", "diff_ok": 1, "source_stale": True, "source_stale_reason": r}
        for i, r in enumerate(reasons)
    ]


def test_a_pair_stale_for_one_reason_is_one_line() -> None:
    # The reported case: every diff of a pair stale for the same reason. One line, the reason
    # once — not 32 lines repeating it.
    rows = _stale_rows(["diff_logic_changed"] * 32)
    pair = {
        "run_pair": "a::b",
        "last_diffed_at": "2026-11-06 00:00:00",
        "counts": {"total": 32, "current": 0, "stale": 32, "unverified": 0, "failed": 0},
        "diffs": rows,
    }
    lines = _render_diff_pairs([pair], show_all=False)
    body = [ln for ln in lines if ln.startswith("  ")]
    assert body == ["  a::b   32 diffs   stale 32 (diff_logic_changed)   last diffed 2026-11-06"]


def test_mixed_reasons_are_counted_most_frequent_first() -> None:
    # The more frequent reason sorts LATER alphabetically, so frequency order is what is checked.
    rows = _stale_rows(["diff_logic_changed"] * 2 + ["hunt_inputs_changed"] * 3)
    pair = {
        "run_pair": "a::b",
        "last_diffed_at": None,
        "counts": {"total": 5, "current": 0, "stale": 5, "unverified": 0, "failed": 0},
        "diffs": rows,
    }
    (line,) = [ln for ln in _render_diff_pairs([pair], show_all=False) if "a::b" in ln]
    assert "stale 5 (hunt_inputs_changed 3, diff_logic_changed 2)" in line


def test_a_failure_with_no_recorded_reason_says_so() -> None:
    # Never a guessed reason: a failed row without diff_status_reason is reported as unrecorded.
    pair = {
        "run_pair": "a::b",
        "last_diffed_at": None,
        "counts": {"total": 1, "current": 0, "stale": 0, "unverified": 0, "failed": 1},
        "diffs": [{"binary": "x", "diff_ok": 0, "source_stale": None}],
    }
    text = "\n".join(_render_diff_pairs([pair], show_all=True))
    assert "FAILED 1 (reason not recorded)" in text
    assert "bindiff_failed" not in text


def test_pair_names_are_aligned_in_one_column() -> None:
    def entry(name: str) -> dict[str, object]:
        return {
            "run_pair": name,
            "last_diffed_at": None,
            "counts": {"total": 1, "current": 1, "stale": 0, "unverified": 0, "failed": 0},
            "diffs": [{"binary": "x", "diff_ok": 1, "source_stale": False}],
        }

    lines = [
        ln
        for ln in _render_diff_pairs([entry("a::b"), entry("long_a::long_b")], show_all=False)
        if "diffs   " in ln
    ]
    assert len({ln.index("1 diffs") for ln in lines}) == 1  # the counts start in one column


def test_counts_sum_to_total(tmp_path: Path) -> None:
    out = _invoke(_atlas(tmp_path), ["--json"])
    (pair,) = json.loads(out.output)["diffs"]
    c = pair["counts"]
    assert c["current"] + c["stale"] + c["unverified"] + c["failed"] == c["total"] == 2


def test_json_is_object_with_runs_and_diffs(tmp_path: Path) -> None:
    data = json.loads(_invoke(_atlas(tmp_path), ["--json"]).output)
    assert set(data) == {"runs", "diffs"}
    assert len(data["runs"]) == 2
    assert data["diffs"][0]["run_pair"] == "av::bv"


def test_json_empty_atlas_is_still_the_object(tmp_path: Path) -> None:
    atlas = tmp_path / "atlas.db"
    open_atlas(atlas).close()
    data = json.loads(_invoke(atlas, ["--json"]).output)
    assert data == {"runs": [], "diffs": []}


def test_diffs_present_but_no_runs_does_not_early_return(tmp_path: Path) -> None:
    # Diffs whose runs have no `run` row and no instances: list_runs is empty, diffs are not.
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    add_diff_meta(
        conn,
        DiffMetaRow(diff_id="x::y::z", run_a_id="x", run_b_id="y", binary_a="z", diff_ok=1),
        commit=True,
    )
    conn.close()
    out = _invoke(atlas, [])
    assert out.exit_code == 0, out.output
    assert "no runs in this atlas yet" not in out.output
    assert "x::y" in out.output


# ── delete: diffs ─────────────────────────────────────────────────────────────

_DIFF_TABLES = (
    "function_alignment",
    "function_presence",
    "instruction_match",
    "diff_meta",
    "dimension_delta",
    "dimension_capability_state",
)


def test_delete_single_binary_diff_leaves_the_sibling(tmp_path: Path) -> None:
    atlas = _atlas(tmp_path)
    out = _invoke(atlas, ["--delete", "av::bv::libok", "--yes"])
    assert out.exit_code == 0, out.output
    for table in _DIFF_TABLES:
        assert _counts(atlas, table, "WHERE diff_id = 'av::bv::libok'") == 0, table
    # the other binary of the same pair is untouched
    assert _counts(atlas, "diff_meta", "WHERE diff_id = 'av::bv::libbad'") == 1


def test_delete_pair_clears_every_diff_including_the_whole_run_row_runs_kept(
    tmp_path: Path,
) -> None:
    atlas = _atlas(tmp_path)
    # add a leftover whole-run-pair row (diff_id == 'a::b')
    conn = open_atlas(atlas)
    add_diff_meta(conn, DiffMetaRow(diff_id="av::bv", run_a_id="av", run_b_id="bv"), commit=True)
    conn.close()
    out = _invoke(atlas, ["--delete", "av::bv", "--yes"])
    assert out.exit_code == 0, out.output
    assert _counts(atlas, "diff_meta", "WHERE run_a_id = 'av' AND run_b_id = 'bv'") == 0
    assert _counts(atlas, "run") == 2  # both runs kept


def test_reverse_pair_id_suggests_the_swap(tmp_path: Path) -> None:
    atlas = _atlas(tmp_path)
    out = _invoke(atlas, ["--delete", "bv::av", "--yes"])
    assert out.exit_code != 0
    assert "did you mean av::bv?" in out.output
    assert _counts(atlas, "diff_meta") == 2  # nothing removed


# ── delete: runs ──────────────────────────────────────────────────────────────


def test_delete_run_clears_its_row_per_run_tables_and_its_diffs(tmp_path: Path) -> None:
    atlas = _atlas(tmp_path)
    out = _invoke(atlas, ["--delete", "av", "--yes"])
    assert out.exit_code == 0, out.output
    assert _counts(atlas, "run", "WHERE run_id = 'av'") == 0
    assert _counts(atlas, "instance", "WHERE source_run_id = 'av'") == 0
    # every diff av is a side of is gone; the other run stays
    assert _counts(atlas, "diff_meta", "WHERE run_a_id = 'av' OR run_b_id = 'av'") == 0
    assert _counts(atlas, "run", "WHERE run_id = 'bv'") == 1


def test_delete_run_function_removes_the_runs_diffs_itself(tmp_path: Path) -> None:
    # delete_run is public (spec 3.1) and must take a run's diffs on its own, not only through the
    # orchestrator's separate diff pass — so this exercises it directly.
    from treasure_map.lib.atlas.writer import delete_run

    atlas = _atlas(tmp_path)
    conn = open_atlas(atlas)
    counts = delete_run(conn, "av")
    conn.close()
    assert counts["diffs"] == 2  # both av::bv diffs, removed by delete_run alone
    assert counts["instances"] == 1 and counts["run"] == 1
    assert _counts(atlas, "diff_meta", "WHERE run_a_id = 'av' OR run_b_id = 'av'") == 0
    assert _counts(atlas, "instance", "WHERE source_run_id = 'av'") == 0


def test_delete_run_recounts_shared_pattern_device_spread(tmp_path: Path) -> None:
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    for rid in ("av", "bv"):
        begin_run(conn, rid, analysis_db_path=f"/o/{rid}/analysis.db", build_hash="pv")
        finish_run(conn, rid)
    pid = upsert_pattern(
        conn, source_class="external_input", sink_class="cmd", call_sequence_shape="s->cmd"
    )
    for rid in ("av", "bv"):
        add_instance(
            conn,
            InstanceRow(
                pattern_id=pid,
                pseudocode_hash=f"h_{rid}",
                sink_anchor="F",
                source_run_id=rid,
                evidence_ref=f"{rid}#F",
            ),
        )
    conn.commit()
    conn.close()
    assert _invoke(atlas, ["--delete", "av", "--yes"]).exit_code == 0
    conn = sqlite3.connect(atlas)
    stored = conn.execute(
        "SELECT device_spread FROM pattern WHERE pattern_id = ?", (pid,)
    ).fetchone()[0]
    distinct = conn.execute(
        "SELECT COUNT(DISTINCT source_run_id) FROM instance WHERE pattern_id = ?", (pid,)
    ).fetchone()[0]
    conn.close()
    assert stored == distinct == 1  # only bv's instance remains; the pattern row is kept


def test_an_unresolved_instance_only_run_can_be_deleted(tmp_path: Path) -> None:
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    pid = upsert_pattern(
        conn, source_class="external_input", sink_class="cmd", call_sequence_shape="s->cmd"
    )
    add_instance(
        conn,
        InstanceRow(
            pattern_id=pid,
            pseudocode_hash="h",
            sink_anchor="F",
            source_run_id="ghost",
            evidence_ref="ghost#F",
        ),
    )
    conn.commit()
    conn.close()
    assert _invoke(atlas, ["--delete", "ghost", "--yes"]).exit_code == 0
    assert _counts(atlas, "instance", "WHERE source_run_id = 'ghost'") == 0


# ── delete: atomicity + ambiguity ─────────────────────────────────────────────


def test_one_bad_id_deletes_nothing(tmp_path: Path) -> None:
    atlas = _atlas(tmp_path)
    out = _invoke(atlas, ["--delete", "av", "--delete", "missing", "--yes"])
    assert out.exit_code != 0
    assert "unknown id 'missing'" in out.output
    assert _counts(atlas, "run", "WHERE run_id = 'av'") == 1  # av NOT deleted


def test_an_id_that_is_both_a_run_and_a_diff_is_ambiguous(tmp_path: Path) -> None:
    atlas = _atlas(tmp_path)
    # a run literally named 'av::bv', alongside the av/bv runs and their diffs
    conn = open_atlas(atlas)
    conn.execute("INSERT INTO run (run_id, scan_status) VALUES ('av::bv','complete')")
    conn.commit()
    conn.close()
    out = _invoke(atlas, ["--delete", "av::bv", "--yes"])
    assert out.exit_code != 0
    assert "ambiguous id 'av::bv'" in out.output
    assert _counts(atlas, "diff_meta") == 2  # nothing deleted
    assert _counts(atlas, "run", "WHERE run_id = 'av::bv'") == 1


# ── delete: scan-in-progress lock (R6) ────────────────────────────────────────


def _workspace_run_atlas(tmp_path: Path) -> tuple[Path, Path]:
    """An atlas with one run whose analysis.db is inside a tmap workspace under a base."""
    base = tmp_path / "workspaces"
    ws = base / "dev"
    _mk_analysis_db(ws / "analysis.db", [str(tmp_path / "fw" / "bin" / "busybox")])
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    begin_run(conn, "dev", analysis_db_path=str(ws / "analysis.db"), build_hash="pv")
    finish_run(conn, "dev")
    conn.close()
    return atlas, base


def test_a_scan_in_progress_blocks_the_delete(tmp_path: Path) -> None:
    atlas, base = _workspace_run_atlas(tmp_path)
    lock = base / "dev" / _LOCK
    lock.write_text("")  # a scan's lock file, left behind
    held = lock.open("r+")
    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)  # stand in for a running scan
    try:
        conn = open_atlas(atlas)
        with pytest.raises(TreasureMapError) as exc:
            plan_delete(conn, ["dev"], workspace_dir=base)
        conn.close()
        assert "in progress" in str(exc.value)
        assert (
            base / "dev"
        ).is_dir()  # the directory is never created or removed by a refused plan
    finally:
        fcntl.flock(held, fcntl.LOCK_UN)
        held.close()


def test_delete_never_creates_a_lock_file_outside_a_workspace(tmp_path: Path) -> None:
    # analysis.db sits outside the base and has no lock file: workspace_of is None, so no lock is
    # taken and none is created.
    outside = tmp_path / "outside"
    _mk_analysis_db(outside / "analysis.db", [str(tmp_path / "fw" / "x")])
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    begin_run(conn, "dev", analysis_db_path=str(outside / "analysis.db"), build_hash="pv")
    finish_run(conn, "dev")
    conn.close()
    conn = open_atlas(atlas)
    plan = plan_delete(conn, ["dev"], workspace_dir=tmp_path / "workspaces")
    plan.release()
    conn.close()
    assert not (outside / _LOCK).exists()


def test_planning_again_after_release_succeeds_lock_was_freed(tmp_path: Path) -> None:
    atlas, base = _workspace_run_atlas(tmp_path)
    (base / "dev" / _LOCK).write_text("")  # a leftover, unlocked lock file
    conn = open_atlas(atlas)
    plan = plan_delete(conn, ["dev"], workspace_dir=base)  # takes the lock
    plan.release()  # as the CLI does when the user answers No
    plan2 = plan_delete(conn, ["dev"], workspace_dir=base)  # must succeed now
    plan2.release()
    conn.close()


# ── delete: files kept, option rejected, annotations ──────────────────────────


def test_workspace_is_kept_and_reported_files_option_is_rejected(tmp_path: Path) -> None:
    atlas, base = _workspace_run_atlas(tmp_path)
    out = CliRunner().invoke(
        runs,
        ["--atlas", str(atlas), "--delete", "dev", "--yes"],
        env={"TM_WORKSPACE_DIR": str(base)},
    )
    assert out.exit_code == 0, out.output
    assert (base / "dev").is_dir()  # files are never removed
    assert "workspace kept" in out.output
    assert "other atlases may also record this workspace" in out.output
    # there is no --files escape hatch
    rejected = _invoke(atlas, ["--delete", "dev", "--files", "--yes"])
    assert rejected.exit_code != 0
    assert "no such option" in rejected.output.lower()


def test_delete_leaves_the_last_run_pointer_untouched(tmp_path: Path) -> None:
    from treasure_map.lib import last_run

    atlas = _atlas(tmp_path)
    last_run.write_last_run(Path("/outside/av/analysis.db"), atlas, "av")
    before = last_run.pointer_path().read_bytes()
    out = _invoke(atlas, ["--delete", "av", "--yes"])
    assert out.exit_code == 0, out.output
    assert last_run.pointer_path().read_bytes() == before  # delete neither reads nor writes it


def test_annotations_are_kept_and_counted_by_exact_match(tmp_path: Path) -> None:
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    begin_run(conn, "dev_1", analysis_db_path="/o/dev_1/analysis.db", build_hash="pv")
    finish_run(conn, "dev_1")
    # a scan judgement on dev_1, and a DECOY whose run id LIKE 'dev_1' would also match ('_' is a
    # LIKE wildcard) but which is a different run and must NOT be counted.
    for anchor, run_id in (("dev_1#F", "dev_1"), ("devX1#F", "devX1")):
        conn.execute(
            "INSERT INTO overlay (anchor_kind, anchor_ref, run_id, verdict, rationale) "
            "VALUES ('evidence_ref', ?, ?, 'safe', 'x')",
            (anchor, run_id),
        )
    conn.commit()
    conn.close()
    before = _counts(atlas, "overlay")
    out = _invoke(atlas, ["--delete", "dev_1", "--yes"])
    assert out.exit_code == 0, out.output
    assert "annotations kept: 1 " in out.output  # the decoy is excluded; exact match, not LIKE
    assert _counts(atlas, "overlay") == before  # nothing deleted from overlay


# ── delete: confirm prompt ────────────────────────────────────────────────────


def test_non_tty_without_yes_refuses_to_delete(tmp_path: Path) -> None:
    # CliRunner is non-interactive: there is no one to ask, so a delete without --yes is refused.
    atlas = _atlas(tmp_path)
    out = _invoke(atlas, ["--delete", "av"])
    assert out.exit_code != 0
    assert "pass --yes to delete without a prompt" in out.output
    assert _counts(atlas, "run", "WHERE run_id = 'av'") == 1


def test_declining_the_prompt_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    atlas = _atlas(tmp_path)
    monkeypatch.setattr("treasure_map.lib.setup.selector.can_use_tty", lambda: True)
    monkeypatch.setattr("click.confirm", lambda *a, **k: False)
    out = _invoke(atlas, ["--delete", "av"])
    assert out.exit_code == 0
    assert "Nothing changed." in out.output
    assert _counts(atlas, "run", "WHERE run_id = 'av'") == 1


def test_delete_json_requires_yes(tmp_path: Path) -> None:
    atlas = _atlas(tmp_path)
    out = _invoke(atlas, ["--delete", "av", "--json"])
    assert out.exit_code != 0
    assert "--yes" in out.output
    assert _counts(atlas, "run", "WHERE run_id = 'av'") == 1


# ── overwrite check: unit (S1 / S2 / confirm_overwrite) ───────────────────────


def test_run_recorded_elsewhere_fires_only_on_other_firmware(tmp_path: Path) -> None:
    atlas = _atlas(tmp_path)
    conn = open_atlas(atlas)
    # a run with no recorded firmware_path cannot say it is other firmware -> no prompt
    begin_run(conn, "no_fw", analysis_db_path="/o/analysis.db")
    finish_run(conn, "no_fw")
    try:
        same = run_recorded_elsewhere(conn, run_id="av", fs_root=Path("/fw/av"))
        other = run_recorded_elsewhere(conn, run_id="av", fs_root=Path("/fw/elsewhere"))
        missing = run_recorded_elsewhere(conn, run_id="nope", fs_root=Path("/fw/av"))
        blank = run_recorded_elsewhere(conn, run_id="no_fw", fs_root=Path("/fw/elsewhere"))
    finally:
        conn.close()
    assert same is None  # re-scanning the same firmware does not warn
    assert other is not None and other.firmware_path == "/fw/av"
    assert missing is None
    assert blank is None  # no firmware_path recorded -> cannot claim other firmware


def test_workspace_holds_other_firmware(tmp_path: Path) -> None:
    fw_a = tmp_path / "fwA"
    db = _mk_analysis_db(tmp_path / "ws" / "analysis.db", [str(fw_a / "bin" / "busybox")])
    assert workspace_holds_other_firmware(db, fw_a) is None  # same firmware
    other = workspace_holds_other_firmware(db, tmp_path / "fwB")
    assert other is not None and str(fw_a) in other
    assert workspace_holds_other_firmware(tmp_path / "nope" / "analysis.db", fw_a) is None


def test_workspace_holds_other_firmware_empty_db_is_silent(tmp_path: Path) -> None:
    db = _mk_analysis_db(tmp_path / "ws" / "analysis.db", [])
    assert workspace_holds_other_firmware(db, tmp_path / "fwB") is None


def test_confirm_overwrite_empty_hits_returns() -> None:
    confirm_overwrite([], assume_yes=False)  # no overwrite, nothing happens


def test_confirm_overwrite_yes_continues() -> None:
    confirm_overwrite(["workspace /w holds a scan of /fw/other"], assume_yes=True)


def test_confirm_overwrite_non_tty_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("treasure_map.lib.setup.selector.can_use_tty", lambda: False)
    with pytest.raises(click.ClickException) as exc:
        confirm_overwrite(["workspace /w holds a scan of /fw/other"], assume_yes=False)
    assert "--run-id / -w" in str(exc.value)  # scan variant
    with pytest.raises(click.ClickException) as exc2:
        confirm_overwrite(["x"], assume_yes=False, run_id_hint=False)
    assert "--run-id" not in str(exc2.value)  # analyze variant


def test_confirm_overwrite_interactive_no_exits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("treasure_map.lib.setup.selector.can_use_tty", lambda: True)
    monkeypatch.setattr("click.confirm", lambda *a, **k: False)
    with pytest.raises(SystemExit):
        confirm_overwrite(["x"], assume_yes=False)


# ── overwrite check: scan / analyze integration (before any Ghidra) ───────────


def _firmware(tmp_path: Path, name: str) -> Path:
    root = tmp_path / name
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "busybox").write_bytes(b"\x7fELF")
    return root


def test_scan_s1_refuses_when_run_id_recorded_other_firmware(tmp_path: Path) -> None:
    from treasure_map.cli.hunt_cli import scan

    fw_b = _firmware(tmp_path, "fwB")
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    begin_run(
        conn, "shared", analysis_db_path="/o/analysis.db", firmware_path=str(tmp_path / "fwA")
    )
    finish_run(conn, "shared")
    conn.close()
    out = CliRunner().invoke(scan, [str(fw_b), "--run-id", "shared", "--atlas", str(atlas)])
    assert out.exit_code == 1, out.output
    assert "overwrites an earlier scan of different firmware" in out.output
    # the overwrite check is read-only: the recorded firmware_path is untouched
    conn = open_atlas(atlas)
    assert conn.execute("SELECT firmware_path FROM run WHERE run_id='shared'").fetchone()[0] == str(
        tmp_path / "fwA"
    )
    conn.close()


def test_scan_no_s1_prompt_when_firmware_matches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The recorded firmware IS the one being scanned: run_recorded_elsewhere returns None, so the
    # scan proceeds (and here fails later for lack of Ghidra, never at the overwrite check).
    from treasure_map.cli.hunt_cli import scan

    fw = _firmware(tmp_path, "fw")
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    begin_run(conn, "same", analysis_db_path="/o/analysis.db", firmware_path=str(fw.resolve()))
    finish_run(conn, "same")
    conn.close()
    monkeypatch.setenv("TM_WORKSPACE_DIR", str(tmp_path / "ws"))
    out = CliRunner().invoke(scan, [str(fw), "--run-id", "same", "--atlas", str(atlas)])
    assert "overwrites an earlier scan" not in out.output


def test_scan_s2_refuses_when_workspace_holds_other_firmware(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from treasure_map.cli.hunt_cli import scan

    base = tmp_path / "workspaces"
    # a workspace 'dev' already holding a scan of fwA
    _mk_analysis_db(base / "dev" / "analysis.db", [str(tmp_path / "fwA" / "bin" / "busybox")])
    fw_b = _firmware(tmp_path, "fwB")
    monkeypatch.setenv("TM_WORKSPACE_DIR", str(base))
    out = CliRunner().invoke(scan, [str(fw_b), "-w", "dev", "--atlas", str(tmp_path / "atlas.db")])
    assert out.exit_code == 1, out.output
    assert "holds a scan of" in out.output


def test_analyze_s2_refuses_when_workspace_holds_other_firmware(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from treasure_map.cli.analyze_cli import analyze

    base = tmp_path / "workspaces"
    _mk_analysis_db(base / "dev" / "analysis.db", [str(tmp_path / "fwA" / "bin" / "busybox")])
    fw_b = _firmware(tmp_path, "fwB")
    monkeypatch.setenv("TM_WORKSPACE_DIR", str(base))
    out = CliRunner().invoke(analyze, [str(fw_b), "-w", "dev"])
    assert out.exit_code == 1, out.output
    assert "holds a scan of" in out.output
    assert "--run-id" not in out.output  # analyze's advice omits --run-id


def test_scan_does_not_prompt_s1_when_atlas_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No atlas yet: the S1 check is guarded by resolved_atlas.exists() and ro_connect opens read
    # only (mode=ro cannot create), so it neither prompts nor creates the atlas. The scan opens it
    # to WRITE its results is a separate act, outside the check.
    from treasure_map.cli.hunt_cli import scan

    fw = _firmware(tmp_path, "fw")
    monkeypatch.setenv("TM_WORKSPACE_DIR", str(tmp_path / "ws"))
    out = CliRunner().invoke(
        scan, [str(fw), "--run-id", "fresh", "--atlas", str(tmp_path / "atlas.db")]
    )
    assert "overwrites an earlier scan" not in out.output  # no false S1 on a fresh atlas
