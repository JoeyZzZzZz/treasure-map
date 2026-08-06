# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""The overlay annotation layer: two-layer separation, basis-staleness, and the honesty rules.

The load-bearing invariant is that the overlay NEVER touches the base map — the instance/pattern
tables read byte-identical whether the overlay is empty or full, and clearing it restores nothing
(there was nothing to restore). Basis staleness is checked at the SET level (all sibling
instances of a ref, keyed by the content-stable pattern_id), so a change to ANY sibling is caught,
same-content re-scan produces ZERO delta. Each fix is paired with a reverse-validation where useful.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest

from treasure_map.lib import overlay
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.atlas.writer import (
    add_instance,
    delete_run_instances,
    upsert_pattern,
)
from treasure_map.lib.errors import ConfigError

_REF = "run1#deadbeef:0x100"


def _seed(tmp_path: Path):  # type: ignore[no-untyped-def]
    """An atlas with one candidate (evidence_ref _REF): one pattern + one instance."""
    con = open_atlas(tmp_path / "atlas.db")
    pid = upsert_pattern(con, source_class="param", sink_class="system", call_sequence_shape="c")
    add_instance(
        con,
        InstanceRow(
            pattern_id=pid,
            source_run_id="run1",
            evidence_ref=_REF,
            pseudocode_hash="hash-A",
            reachability_status="unknown",
        ),
    )
    return con


def _dump_base(con: sqlite3.Connection) -> dict[str, list]:
    """A byte-level snapshot of the base-map tables, for the untouched invariant."""
    return {
        "pattern": con.execute("SELECT * FROM pattern ORDER BY pattern_id").fetchall(),
        "instance": con.execute("SELECT * FROM instance ORDER BY instance_id").fetchall(),
    }


# ── two-layer separation: the overlay never writes the base map ─────────────────────────


def test_overlay_source_only_writes_the_overlay_table() -> None:
    # ★ static guard: every INSERT/UPDATE/DELETE in overlay.py targets the `overlay` table; the base
    # map (instance/pattern) is only ever READ. A write to instance/pattern here would go red.
    src = (
        Path(__file__).resolve().parents[3] / "src" / "treasure_map" / "lib" / "overlay.py"
    ).read_text()
    writes = re.findall(r"(?:INSERT INTO|UPDATE|DELETE FROM)\s+(\w+)", src)
    assert writes, "expected to find the overlay writes"
    assert all(tbl == "overlay" for tbl in writes), (
        f"overlay.py writes a non-overlay table: {writes}"
    )
    assert "FROM instance" in src  # it DOES read the base map (for the basis snapshot)


def test_base_map_is_byte_identical_whether_overlay_empty_or_full(tmp_path: Path) -> None:
    # ★ the command invariant: annotating (and clearing) leaves instance/pattern untouched.
    con = _seed(tmp_path)
    before = _dump_base(con)
    overlay.upsert_overlay(con, evidence_ref=_REF, verdict="suspicious", rationale="dig here")
    overlay.upsert_overlay(
        con, evidence_ref=_REF, verdict="excluded", rationale="on reflection, noise"
    )
    assert _dump_base(con) == before  # base map unchanged with a full overlay
    overlay.clear_overlay(con)
    assert _dump_base(con) == before  # ...and after clearing it
    con.close()


# ── write: validation + blind-write honesty + last-write-wins ───────────────────────────


def test_upsert_rejects_bad_verdict_and_blank_rationale(tmp_path: Path) -> None:
    con = _seed(tmp_path)
    with pytest.raises(ConfigError, match="verdict must be one of"):
        overlay.upsert_overlay(con, evidence_ref=_REF, verdict="nope", rationale="x")
    with pytest.raises(ConfigError, match="rationale must be non-blank"):
        overlay.upsert_overlay(con, evidence_ref=_REF, verdict="to-review", rationale="   ")
    con.close()


def test_attribution_is_never_fabricated(tmp_path: Path) -> None:
    # ★ coarse attribution only: the writer rejects a fabricated identity, and the schema CHECK is
    # the backstop (a raw INSERT of an arbitrary attributor fails).
    con = _seed(tmp_path)
    with pytest.raises(ConfigError, match="never fabricated"):
        overlay.upsert_overlay(
            con, evidence_ref=_REF, verdict="safe", rationale="ok", attributed_to="alice"
        )
    with pytest.raises(sqlite3.IntegrityError):
        con.execute(
            "INSERT INTO overlay (anchor_ref, verdict, rationale, attributed_to) "
            "VALUES (?, 'safe', 'ok', 'alice')",
            (_REF,),
        )
    con.close()


def test_blind_write_on_unresolved_ref_is_recorded_with_basis_unresolved(tmp_path: Path) -> None:
    con = _seed(tmp_path)
    res = overlay.upsert_overlay(
        con, evidence_ref="ghost#0:0x0", verdict="to-review", rationale="note before scan"
    )
    assert res.action == "inserted"
    assert res.basis_resolved is False  # honest: nothing to snapshot
    assert overlay.list_overlays(con)["count"] == 1  # written anyway, not dropped
    con.close()


def test_last_write_wins_overwrites_in_place_with_echo(tmp_path: Path) -> None:
    con = _seed(tmp_path)
    overlay.upsert_overlay(con, evidence_ref=_REF, verdict="suspicious", rationale="first")
    res = overlay.upsert_overlay(con, evidence_ref=_REF, verdict="excluded", rationale="second")
    assert res.action == "updated"
    assert res.prior_attributed_to == "agent-via-mcp"  # echoes whom it overwrote
    assert res.prior_updated_at is not None
    rows = con.execute("SELECT verdict FROM overlay WHERE anchor_ref = ?", (_REF,)).fetchall()
    assert [r["verdict"] for r in rows] == ["excluded"]  # ONE row, the latest verdict
    con.close()


# ── basis staleness: facts only, set-level, NULL-honest ─────────────────────────────────


def test_basis_unchanged_when_nothing_moves(tmp_path: Path) -> None:
    con = _seed(tmp_path)
    overlay.upsert_overlay(con, evidence_ref=_REF, verdict="suspicious", rationale="watch")
    row = overlay.list_overlays(con)["overlays"][0]
    assert row["basis_state"] == "unchanged"
    con.close()


def test_basis_changed_when_a_dimension_moves(tmp_path: Path) -> None:
    # ★ tmap EMITS the fact (reachability moved unknown->confirmed) — it never judges the verdict
    # dead; that is the consumer's call.
    con = _seed(tmp_path)
    overlay.upsert_overlay(con, evidence_ref=_REF, verdict="suspicious", rationale="watch")
    con.execute("UPDATE instance SET reachability_status='confirmed' WHERE evidence_ref=?", (_REF,))
    con.commit()
    row = overlay.list_overlays(con)["overlays"][0]
    assert row["basis_state"] == "changed"
    moves = row["basis_delta"]["dimensions"]["moves"]
    assert moves and moves[0]["moved"]["reachability_status"] == ["unknown", "confirmed"]
    con.close()


def test_basis_changed_when_pseudocode_hash_moves(tmp_path: Path) -> None:
    con = _seed(tmp_path)
    overlay.upsert_overlay(con, evidence_ref=_REF, verdict="in-progress", rationale="reading")
    con.execute("UPDATE instance SET pseudocode_hash='hash-B' WHERE evidence_ref=?", (_REF,))
    con.commit()
    row = overlay.list_overlays(con)["overlays"][0]
    assert row["basis_state"] == "changed"
    assert row["basis_delta"]["pseudocode"] == "changed"  # the thing the agent actually read moved
    con.close()


def test_null_pseudocode_is_unverifiable_not_unchanged(tmp_path: Path) -> None:
    # ★ NULL-honest: no pseudocode hash to compare -> 'unverifiable', an explicit can't-say, NEVER a
    # silent 'unchanged' (which would falsely imply the annotation still stands).
    con = open_atlas(tmp_path / "atlas.db")
    pid = upsert_pattern(con, source_class="param", sink_class="system", call_sequence_shape="c")
    add_instance(
        con,
        InstanceRow(
            pattern_id=pid,
            source_run_id="run1",
            evidence_ref=_REF,
            pseudocode_hash=None,  # no pseudocode recorded
            source_anchor="a",  # satisfies the traceability CHECK without a hash
            reachability_status="unknown",
        ),
    )
    overlay.upsert_overlay(con, evidence_ref=_REF, verdict="suspicious", rationale="x")
    assert overlay.list_overlays(con)["overlays"][0]["basis_state"] == "unverifiable"
    con.close()


def test_basis_is_ref_level_set_catches_a_non_first_sibling(tmp_path: Path) -> None:
    # ★ an evidence_ref maps to MANY instances (different pattern_id); a change to a sibling that is
    # NOT the first row must still register — a LIMIT-1 snapshot would miss it (ref-level SET).
    con = open_atlas(tmp_path / "atlas.db")
    p1 = upsert_pattern(con, source_class="param", sink_class="system", call_sequence_shape="c1")
    p2 = upsert_pattern(con, source_class="param", sink_class="popen", call_sequence_shape="c2")
    for pid in (p1, p2):
        add_instance(
            con,
            InstanceRow(
                pattern_id=pid,
                source_run_id="run1",
                evidence_ref=_REF,
                pseudocode_hash="hash-A",
                reachability_status="unknown",
            ),
        )
    overlay.upsert_overlay(con, evidence_ref=_REF, verdict="suspicious", rationale="two siblings")
    # move ONLY the second sibling (higher pattern_id):
    con.execute(
        "UPDATE instance SET blocking_mechanism='length_check' "
        "WHERE evidence_ref=? AND pattern_id=?",
        (_REF, p2),
    )
    con.commit()
    row = overlay.list_overlays(con)["overlays"][0]
    assert row["basis_state"] == "changed"  # the non-first sibling's move was caught
    moved_pids = [m["pattern_id"] for m in row["basis_delta"]["dimensions"]["moves"]]
    assert moved_pids == [p2]
    con.close()


def test_same_content_rescan_produces_zero_basis_delta(tmp_path: Path) -> None:
    # ★ zero-change -> zero delta: a re-scan that deletes then re-inserts the SAME content must not
    # churn the basis. This pins the hidden dependency on pattern_id content-stability (patterns are
    # content-deduped on upsert + never deleted, so the re-inserted instance rejoins the same
    # pattern_id even though its instance_id is new).
    con = _seed(tmp_path)
    overlay.upsert_overlay(con, evidence_ref=_REF, verdict="suspicious", rationale="watch")
    delete_run_instances(con, "run1")  # the re-scan wipe
    add_instance(  # re-ingest identical content
        con,
        InstanceRow(
            pattern_id=upsert_pattern(
                con, source_class="param", sink_class="system", call_sequence_shape="c"
            ),
            source_run_id="run1",
            evidence_ref=_REF,
            pseudocode_hash="hash-A",
            reachability_status="unknown",
        ),
    )
    assert overlay.list_overlays(con)["overlays"][0]["basis_state"] == "unchanged"  # zero delta
    con.close()


def test_dangling_anchor_is_surfaced_not_dropped(tmp_path: Path) -> None:
    con = _seed(tmp_path)
    overlay.upsert_overlay(con, evidence_ref=_REF, verdict="suspicious", rationale="watch")
    delete_run_instances(con, "run1")  # the candidate is gone (re-scan removed it)
    lst = overlay.list_overlays(con)
    assert lst["count"] == 1  # the annotation is NOT dropped
    assert (
        lst["overlays"][0]["basis_state"] == "anchor_unresolved"
    )  # ...it is surfaced for re-check
    con.close()


# ── read: verdict filter + bias ─────────────────────────────────────────────────────────


def test_list_overlays_verdict_filter_and_bias(tmp_path: Path) -> None:
    con = _seed(tmp_path)
    add_instance(
        con,
        InstanceRow(
            pattern_id=upsert_pattern(
                con, source_class="p", sink_class="popen", call_sequence_shape="c2"
            ),
            source_run_id="run1",
            evidence_ref="run1#deadbeef:0x200",
            pseudocode_hash="hash-Z",
            reachability_status="unknown",
        ),
    )
    overlay.upsert_overlay(con, evidence_ref=_REF, verdict="suspicious", rationale="a")
    overlay.upsert_overlay(
        con, evidence_ref="run1#deadbeef:0x200", verdict="excluded", rationale="b"
    )
    only_susp = overlay.list_overlays(con, verdict="suspicious")
    assert only_susp["count"] == 1 and only_susp["overlays"][0]["verdict"] == "suspicious"
    assert only_susp["overlays"][0]["bias"] == 1  # suspicious floats
    excl = overlay.list_overlays(con, verdict="excluded")["overlays"][0]
    assert excl["bias"] == -1  # excluded sinks
    con.close()


# ── run_id: which firmware an annotation belongs to ────────────────────────────────────
#
# Reverse mutations — each applied once and observed RED (assertion failures, not errors), then
# restored. Re-run any to re-verify these guards bite:
#
# 1. no run filter. In `overlay.list_overlays` never append the `run_id = ?` condition. -> 2 failed,
#    incl. `test_run_id_filter_isolates_one_firmware`: the other firmware's annotation leaks in.
# 2. write path forgets the run. In `upsert_overlay` pass None instead of
#    `_run_id_from_ref(evidence_ref)`. -> 3 failed, incl. `test_new_annotation_records_its_run`:
#    the fresh row's run_id is NULL, so its own firmware's view no longer returns it.
# 3. no backfill. In `atlas.connection._migrate` skip the overlay backfill UPDATE. -> 1 failed:
#    `test_pre_existing_rows_are_backfilled` — a row written before the column existed stays NULL
#    and silently drops out of its own firmware's view.
# 4. OR instead of AND. In `list_overlays` join the conditions with " OR ". -> 1 failed:
#    `test_filters_and_together` — the other firmware's row comes back too.


_REF_A = "run_a#deadbeef:0x100"
_REF_B = "run_b#cafebabe:0x200"


def _seed_two_runs(tmp_path: Path) -> sqlite3.Connection:
    """One atlas holding candidates from TWO firmwares — the shared-atlas case run_id exists for.

    The refs carry their own run segment, because that is where run_id is derived FROM — the
    anchor, not the instance's source_run_id. Keeping them equal here would hide which one the
    column actually follows."""
    con = open_atlas(tmp_path / "atlas.db")
    for run, ref in ((_REF_A.split("#")[0], _REF_A), (_REF_B.split("#")[0], _REF_B)):
        pid = upsert_pattern(
            con, source_class="param", sink_class="system", call_sequence_shape=f"c-{run}"
        )
        add_instance(
            con,
            InstanceRow(
                pattern_id=pid,
                source_run_id=run,
                evidence_ref=ref,
                pseudocode_hash=f"hash-{run}",
                reachability_status="unknown",
            ),
        )
    return con


def test_run_id_filter_isolates_one_firmware(tmp_path: Path) -> None:
    # ★ The point of the column: a shared atlas accumulates every scan, so "my annotations" has to
    # mean "this firmware's annotations" or a multi-firmware audit reads back one mixed pile.
    con = _seed_two_runs(tmp_path)
    overlay.upsert_overlay(con, evidence_ref=_REF_A, verdict="suspicious", rationale="dig here")
    overlay.upsert_overlay(con, evidence_ref=_REF_B, verdict="excluded", rationale="benign")
    assert overlay.list_overlays(con)["count"] == 2  # unfiltered: both firmwares

    only_a = overlay.list_overlays(con, run_id="run_a")
    assert [o["anchor_ref"] for o in only_a["overlays"]] == [_REF_A]
    assert only_a["filter"]["run_id"] == "run_a"
    only_b = overlay.list_overlays(con, run_id="run_b")
    assert [o["anchor_ref"] for o in only_b["overlays"]] == [_REF_B]
    assert overlay.list_overlays(con, run_id="run_nope")["count"] == 0  # honest empty, not a guess


def test_new_annotation_records_its_run(tmp_path: Path) -> None:
    # A row written today must carry the run, or it is invisible to its own firmware's view.
    con = _seed_two_runs(tmp_path)
    overlay.upsert_overlay(con, evidence_ref=_REF_A, verdict="in-progress", rationale="reading it")
    stored = con.execute("SELECT run_id FROM overlay WHERE anchor_ref = ?", (_REF_A,)).fetchone()
    assert stored["run_id"] == "run_a"
    assert overlay.list_overlays(con, run_id="run_a")["count"] == 1
    # ... and the row surfaces its own run, so a mixed listing stays attributable
    assert overlay.list_overlays(con)["overlays"][0]["run_id"] == "run_a"


def test_pre_existing_rows_are_backfilled(tmp_path: Path) -> None:
    # ★ An annotation written before the column existed must not fall out of its firmware's view.
    # Simulated by clearing the value and re-opening, which is exactly what an old atlas looks like.
    db = tmp_path / "atlas.db"
    con = _seed_two_runs(tmp_path)
    overlay.upsert_overlay(con, evidence_ref=_REF_A, verdict="safe", rationale="checked")
    con.execute("UPDATE overlay SET run_id = NULL")  # the pre-column shape
    con.commit()
    con.close()

    con = open_atlas(db)  # re-open runs the migration
    try:
        stored = con.execute(
            "SELECT run_id FROM overlay WHERE anchor_ref = ?", (_REF_A,)
        ).fetchone()
        assert stored["run_id"] == "run_a"  # backfilled from the anchor
        assert overlay.list_overlays(con, run_id="run_a")["count"] == 1
    finally:
        con.close()


def test_filters_and_together(tmp_path: Path) -> None:
    con = _seed_two_runs(tmp_path)
    overlay.upsert_overlay(con, evidence_ref=_REF_A, verdict="suspicious", rationale="dig")
    overlay.upsert_overlay(con, evidence_ref=_REF_B, verdict="excluded", rationale="benign")
    both = overlay.list_overlays(con, run_id="run_a", verdict="suspicious")
    assert [o["anchor_ref"] for o in both["overlays"]] == [_REF_A]
    # the same verdict on the OTHER firmware is not this firmware's
    assert overlay.list_overlays(con, run_id="run_b", verdict="suspicious")["count"] == 0


def test_anchor_without_a_run_segment_stays_null(tmp_path: Path) -> None:
    # Derived, never invented: an anchor carrying no run segment is left NULL rather than guessed
    # at — and the write path and the migration backfill agree on that rule.
    assert overlay._run_id_from_ref("run_a#deadbeef:0x1@cmd") == "run_a"
    assert overlay._run_id_from_ref("#leading-hash") is None  # empty prefix is not a run
    assert overlay._run_id_from_ref("no-hash-at-all") is None
