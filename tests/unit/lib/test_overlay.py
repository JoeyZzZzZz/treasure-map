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
        overlay.upsert_overlay(con, evidence_ref=_REF, verdict="inconclusive", rationale="   ")
    con.close()


def test_attribution_is_never_fabricated(tmp_path: Path) -> None:
    # ★ coarse attribution only: the writer rejects a fabricated identity, and the schema CHECK is
    # the backstop (a raw INSERT of an arbitrary attributor fails).
    con = _seed(tmp_path)
    with pytest.raises(ConfigError, match="never fabricated"):
        overlay.upsert_overlay(
            con, evidence_ref=_REF, verdict="suspicious", rationale="ok", attributed_to="alice"
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
        con, evidence_ref="ghost#0:0x0", verdict="inconclusive", rationale="note before scan"
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
    overlay.upsert_overlay(con, evidence_ref=_REF, verdict="inconclusive", rationale="reading")
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
    overlay.upsert_overlay(con, evidence_ref=_REF_A, verdict="inconclusive", rationale="reading it")
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
    overlay.upsert_overlay(con, evidence_ref=_REF_A, verdict="suspicious", rationale="checked")
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


# ── the verdict vocabulary moved: retire one word, rename another, and stay readable ───
#
# Reverse mutations — each applied once and observed RED, then restored:
#
# 1. drop the tolerance: in `overlay.list_overlays` index `_VERDICT_BIAS[...]` again.
#    -> `test_list_overlays_tolerates_a_retired_verdict` fails with KeyError.
# 2. un-retire: put "in-progress" back in `_VERDICTS`.
#    -> `test_upsert_rejects_a_retired_verdict` fails — the write is accepted again.
# 3. skip the rename: remove the UPDATE from `atlas.connection._migrate`.
#    -> `test_migrate_renames_to_review_to_inconclusive` fails — the old word survives.
# 4. ignore the scope: in `clear_overlay` always run the unscoped DELETE.
#    -> `test_clear_overlay_scoped` fails — the untargeted rows are gone too.


def test_upsert_rejects_a_retired_verdict(tmp_path: Path) -> None:
    # A word removed from the vocabulary stops being writable — the write path is where validity
    # lives now that no database constraint pins it.
    con = _seed(tmp_path)
    with pytest.raises(ConfigError, match="verdict must be one of"):
        overlay.upsert_overlay(con, evidence_ref=_REF, verdict="in-progress", rationale="x")
    con.close()


def test_upsert_accepts_inconclusive(tmp_path: Path) -> None:
    con = _seed(tmp_path)
    res = overlay.upsert_overlay(
        con, evidence_ref=_REF, verdict="inconclusive", rationale="looked; nothing decisive"
    )
    assert res.action == "inserted"
    row = overlay.list_overlays(con)["overlays"][0]
    assert row["verdict"] == "inconclusive"
    assert row["bias"] == 0  # neutral: leaves the candidate where the base map put it
    con.close()


def test_list_overlays_tolerates_a_retired_verdict(tmp_path: Path) -> None:
    # ★ Old databases still hold words this build has retired. Reading one must not fail — a
    # vocabulary change cannot be allowed to make existing annotations unreadable.
    con = _seed(tmp_path)
    con.execute(
        "INSERT INTO overlay (anchor_ref, run_id, verdict, rationale) "
        "VALUES (?, 'run1', 'in-progress', 'written before the word was retired')",
        (_REF,),
    )
    con.commit()
    res = overlay.list_overlays(con)  # must not raise
    assert res["count"] == 1
    row = res["overlays"][0]
    assert row["verdict"] == "in-progress"  # surfaced as stored, never rewritten
    assert row["bias"] == 0  # unknown word -> neutral, so no view moves it on a guess
    con.close()


def test_migrate_renames_to_review_to_inconclusive(tmp_path: Path) -> None:
    # ★ The rename reaches rows written under the old name, and only those.
    db = tmp_path / "atlas.db"
    con = _seed(tmp_path)
    con.execute(
        "INSERT INTO overlay (anchor_ref, run_id, verdict, rationale) "
        "VALUES ('r#a:0x1@cmd', 'r', 'to-review', 'old name')"
    )
    con.execute(
        "INSERT INTO overlay (anchor_ref, run_id, verdict, rationale) "
        "VALUES ('r#a:0x2@cmd', 'r', 'suspicious', 'untouched')"
    )
    con.commit()
    con.close()

    con = open_atlas(db)  # the migration runs on open
    verdicts = dict(con.execute("SELECT anchor_ref, verdict FROM overlay"))
    assert verdicts["r#a:0x1@cmd"] == "inconclusive"
    assert verdicts["r#a:0x2@cmd"] == "suspicious"  # every other verdict left alone
    con.close()

    con = open_atlas(db)  # idempotent: nothing left to rename
    assert dict(con.execute("SELECT anchor_ref, verdict FROM overlay")) == verdicts
    con.close()


def test_clear_overlay_scoped(tmp_path: Path) -> None:
    # ★ Clearing one entry — or one firmware's — instead of starting over. Anything outside the
    # scope must survive; a scope that silently widened would delete work the consumer still wants.
    def _seed_rows(con: sqlite3.Connection) -> None:
        for ref in ("rC#s:0x1@cmd", "rC#s:0x2@cmd", "rD#s:0x1@cmd", "rE#s:0x1@cmd"):
            con.execute(
                "INSERT INTO overlay (anchor_ref, run_id, verdict, rationale) VALUES (?,?,?,?)",
                (ref, ref.split("#")[0], "suspicious", "seed"),
            )
        con.commit()

    def _refs(con: sqlite3.Connection) -> list[str]:
        return [r[0] for r in con.execute("SELECT anchor_ref FROM overlay ORDER BY anchor_ref")]

    con = _seed(tmp_path)
    _seed_rows(con)
    assert overlay.clear_overlay(con, evidence_ref="rC#s:0x1@cmd") == 1
    assert _refs(con) == ["rC#s:0x2@cmd", "rD#s:0x1@cmd", "rE#s:0x1@cmd"]

    assert overlay.clear_overlay(con, run_id="rC") == 1  # only what is left of that run
    assert _refs(con) == ["rD#s:0x1@cmd", "rE#s:0x1@cmd"]

    assert overlay.clear_overlay(con) == 2  # no scope: everything
    assert _refs(con) == []

    _seed_rows(con)
    with pytest.raises(ConfigError, match="at most one scope"):
        overlay.clear_overlay(con, run_id="rC", evidence_ref="rC#s:0x1@cmd")
    assert len(_refs(con)) == 4  # the refusal deleted nothing
    con.close()


# ── the two verdicts that owe an explanation: safe (required) and exploitable (soft) ───
#
# Reverse mutations — each applied once and observed RED, then restored:
#
# 1. drop the safe gate: return None instead of raising when a safe row has no basis.
#    -> `test_safe_requires_all_three_parts` fails — an unexplained 'safe' is accepted.
# 2. harden exploitable: raise when its basis is None.
#    -> `test_exploitable_basis_is_validated_but_not_required` fails on the no-basis case.
# 3. drop the chain probe: skip the _CHAIN_ANCHOR search.
#    -> the same test fails — a chain naming no code is accepted.
# 4. accept cross-kind: delete the trailing `if vb is not None: raise`.
#    -> `test_verdict_basis_is_refused_for_the_other_verdicts` fails.
# 5. move the column migration BEFORE the rebuild in `_migrate` (or drop its guard).
#    -> `test_verdict_basis_column_survives_an_old_atlas` fails — the rebuild's fixed ten-column
#    copy drops the new column on any atlas old enough to be rebuilt.

_SAFE_OK = {
    "block_source": "the topic string from the mqtt subscribe",
    "block_point": "check_topic_prefix, before the buffer is built",
    "block_why": "every caller of build_cmd goes through it, and it rejects anything with a shell "
    "metacharacter before the copy",
}
_EXPLOIT_OK = {
    "chain": "mqtt topic -> handler_parse_cmd -> build_cmd (0x4a12) -> system",
    "verification_gaps": [
        "needs a device on the same mesh segment",
        "unclear whether the daemon runs as root",
    ],
}


def _basis_of(con: sqlite3.Connection, ref: str) -> dict | None:
    raw = con.execute("SELECT verdict_basis FROM overlay WHERE anchor_ref = ?", (ref,)).fetchone()
    import json as _json

    return _json.loads(raw[0]) if raw and raw[0] else None


def test_safe_requires_all_three_parts(tmp_path: Path) -> None:
    # ★ 'safe' is the judgement that takes a candidate off the table, and a wrong one only comes
    # back if the CODE changes — never because the judgement was wrong. So it has to say what is
    # blocked, where, and why that holds everywhere.
    con = _seed(tmp_path)
    with pytest.raises(ConfigError, match="safe requires verdict_basis"):
        overlay.upsert_overlay(con, evidence_ref=_REF, verdict="safe", rationale="looks fine")
    for missing in _SAFE_OK:
        partial = {k: v for k, v in _SAFE_OK.items() if k != missing}
        with pytest.raises(ConfigError, match=f"safe.{missing}"):
            overlay.upsert_overlay(
                con, evidence_ref=_REF, verdict="safe", rationale="x", verdict_basis=partial
            )
    with pytest.raises(ConfigError, match="block_why"):  # present but blank is not present
        overlay.upsert_overlay(
            con,
            evidence_ref=_REF,
            verdict="safe",
            rationale="x",
            verdict_basis={**_SAFE_OK, "block_why": "   "},
        )
    assert overlay.list_overlays(con)["count"] == 0  # nothing was written by any refusal

    overlay.upsert_overlay(
        con, evidence_ref=_REF, verdict="safe", rationale="blocked", verdict_basis=_SAFE_OK
    )
    stored = _basis_of(con, _REF)
    assert stored is not None and stored["kind"] == "safe"
    assert stored["block_point"] == _SAFE_OK["block_point"]
    assert overlay.list_overlays(con)["overlays"][0]["verdict_basis"]["kind"] == "safe"
    con.close()


def test_exploitable_basis_is_validated_but_not_required(tmp_path: Path) -> None:
    # ★ Soft on purpose: the shape is still being learned from real cases, and requiring it before
    # it settles just produces filler. What IS given gets checked.
    con = _seed(tmp_path)
    overlay.upsert_overlay(
        con, evidence_ref=_REF, verdict="exploitable", rationale="chain looks complete"
    )
    assert _basis_of(con, _REF) is None  # accepted with nothing attached

    with pytest.raises(ConfigError, match="cite code"):  # a chain naming nothing in the binary
        overlay.upsert_overlay(
            con,
            evidence_ref=_REF,
            verdict="exploitable",
            rationale="x",
            verdict_basis={**_EXPLOIT_OK, "chain": "the input reaches a shell somewhere"},
        )
    with pytest.raises(ConfigError, match="verification_gaps"):  # one gap is not a list of gaps
        overlay.upsert_overlay(
            con,
            evidence_ref=_REF,
            verdict="exploitable",
            rationale="x",
            verdict_basis={**_EXPLOIT_OK, "verification_gaps": ["only one"]},
        )

    overlay.upsert_overlay(
        con,
        evidence_ref=_REF,
        verdict="exploitable",
        rationale="ready for hardware",
        verdict_basis={**_EXPLOIT_OK, "shared_prereq": "same mesh segment"},
    )
    stored = _basis_of(con, _REF)
    assert stored is not None and stored["kind"] == "exploitable"
    assert len(stored["verification_gaps"]) == 2
    assert stored["shared_prereq"] == "same mesh segment"
    con.close()


def test_verdict_basis_is_refused_for_the_other_verdicts(tmp_path: Path) -> None:
    # Storing a justification under a verdict nothing reads it for would quietly lose it — say so.
    con = _seed(tmp_path)
    for verdict in ("inconclusive", "suspicious", "excluded"):
        with pytest.raises(ConfigError, match="applies to safe / exploitable only"):
            overlay.upsert_overlay(
                con,
                evidence_ref=_REF,
                verdict=verdict,
                rationale="x",
                verdict_basis=_EXPLOIT_OK,
            )
    con.close()


def test_verdict_basis_column_survives_an_old_atlas(tmp_path: Path) -> None:
    # ★ The column is added AFTER the verdict-CHECK rebuild, which copies a fixed ten-column list.
    # Added before it, the rebuild would drop it again on exactly the databases that need migrating.
    db = tmp_path / "atlas.db"
    con = open_atlas(db)
    con.execute("DROP TABLE overlay")  # replace with the pre-change shape: CHECK, and no new column
    con.execute("""CREATE TABLE overlay (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        anchor_kind TEXT NOT NULL DEFAULT 'evidence_ref'
            CHECK (anchor_kind IN ('evidence_ref','diff_subject')),
        anchor_ref TEXT NOT NULL,
        run_id TEXT,
        verdict TEXT NOT NULL
            CHECK (verdict IN ('to-review','in-progress','suspicious','excluded','safe')),
        rationale TEXT NOT NULL,
        attributed_to TEXT
            CHECK (attributed_to IS NULL OR attributed_to IN ('agent','agent-via-mcp')),
        basis_state TEXT,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (anchor_kind, anchor_ref))""")
    con.execute(
        "INSERT INTO overlay (anchor_ref, run_id, verdict, rationale) "
        "VALUES ('old#a:0x1@cmd', 'old', 'suspicious', 'written before the column existed')"
    )
    con.commit()
    con.close()

    con = open_atlas(db)  # rebuild (CHECK removal) THEN the column add
    cols = {r[1] for r in con.execute("PRAGMA table_info(overlay)")}
    assert "verdict_basis" in cols, "the rebuild's fixed column list dropped the new column"
    row = con.execute("SELECT * FROM overlay").fetchone()
    assert row["verdict_basis"] is None  # nullable: an existing row simply has none
    assert row["rationale"] == "written before the column existed"  # and is otherwise intact
    con.close()

    con = open_atlas(db)  # idempotent: adding it twice would raise "duplicate column name"
    assert "verdict_basis" in {r[1] for r in con.execute("PRAGMA table_info(overlay)")}
    con.close()
