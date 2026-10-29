# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Judgements on a diff's function-level view (lib/query/diff_review, lib/query/diff_annotations,
and the diff side of lib/overlay.py).

Zero real data: runs, binaries, addresses and refs are synthetic. One atlas holds two diffs of one
run pair, of ``libx`` and ``liby``. The candidate rows each diff's view reads are set by the test
(``World.rows``, through the overlay computation the view falls back to), so every landing a row
can have is reachable without building the call-site facts that produce it in a real diff.
"""

from __future__ import annotations

import ast
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from treasure_map import mcp_app
from treasure_map.lib import overlay
from treasure_map.lib.analyze.ghidra_runner import current_pass_version
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.errors import ConfigError
from treasure_map.lib.query import coverage
from treasure_map.lib.query import diff_align as da
from treasure_map.lib.query import diff_annotations as dann
from treasure_map.lib.query import diff_review as dr
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query import sink_overlay as so
from treasure_map.lib.storage.connection import open_db
from treasure_map.version import UNKNOWN_VERSION


@pytest.fixture(autouse=True)
def _clear_view_caches() -> None:
    """Every World reuses one diff_id, run ids and build hash, so drop the view's process-wide
    caches (lib/query/patch_view) between tests to keep one test's reading out of the next."""
    pv._clear_view_caches()


PAIR = "runA::runB"
DX = "runA::runB::libx"
DY = "runA::runB::liby"
SHAS = {DX: ("a" * 64, "b" * 64), DY: ("c" * 64, "d" * 64)}


def _nrc(anchor: str, why: str = "same call, renamed wrapper") -> dict[str, Any]:
    """A valid no_real_change basis: the judged anchor (an entry's own anchor always resolves in
    the view) plus a plain-text note, and why_unchanged."""
    return {"checked": [anchor, "the matched call's target"], "why_unchanged": why}


def _ref(run: str, func: str, at: str = "0x10") -> str:
    """An evidence_ref in the real shape: {run}#{banchor}:{func}@{class}@{offset}."""
    return f"{run}#deadbeef:{func}@cmd@{at}"


def _row(
    a_ref: str | None,
    b_ref: str | None,
    *,
    presence: str = "presence_undetermined",
    reason: str | None = None,
    call: str | None = None,
    elsewhere: bool | None = None,
    conf: float | None = 0.97,
    cls: str = "cmd",
) -> so.SinkOverlayRow:
    callee = None
    if call == "present_different_callee":
        callee = {
            "matched_addr": "00000010",
            "callees": [{"name": "popen"}],
            "same_callee_candidate_elsewhere": elsewhere,
        }
    return so.SinkOverlayRow(
        diff_id=None,
        binary=None,
        sink_class=cls,
        a_ref=a_ref,
        b_ref=b_ref,
        key_granularity="callsite",
        presence=presence,
        presence_reason=reason,
        match_basis="instruction",
        counterpart_call=call,
        alignment_confidence=conf,
        counterpart_callee=callee,
    )


def a_row(func_a: str, *, elsewhere: bool | None = False) -> so.SinkOverlayRow:
    """The matched call now calls another callee (lands A when nothing holds the old one)."""
    return _row(
        _ref("runA", func_a),
        None,
        reason="present_different_callee",
        call="present_different_callee",
        elsewhere=elsewhere,
    )


class _Rehunted(dict[str, list[so.SinkOverlayRow]]):
    """``World.rows``: giving a diff new candidate rows is a re-hunt, and a re-hunt moves both
    runs' stamps — so a view computed from the old rows (the overlay recomputed in memory is
    cached under those stamps) is never served for the new ones, as on a real atlas."""

    def __init__(self, atlas: sqlite3.Connection, rows: dict[str, list[so.SinkOverlayRow]]) -> None:
        super().__init__(rows)
        self._atlas = atlas
        self._hunts = 0

    def __setitem__(self, key: str, value: list[so.SinkOverlayRow]) -> None:
        super().__setitem__(key, value)
        self._hunts += 1
        self._atlas.execute("UPDATE run SET updated_at = ?", (f"rehunt-{self._hunts}",))
        self._atlas.commit()


class World:
    """Two diffs of one run pair, with each run's analysis.db holding both binaries."""

    def __init__(self, tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.tmp = tmp
        self.path = tmp / "atlas.db"
        self.atlas = open_atlas(self.path)
        self.rows: dict[str, list[so.SinkOverlayRow]] = _Rehunted(self.atlas, {DX: [], DY: []})
        self.stale: dict[str, dict[str, Any]] = {}
        for side, run in (("a", "runA"), ("b", "runB")):
            db = tmp / f"analysis_{side}.db"
            conn = open_db(db)
            for diff_id, shas in SHAS.items():
                name = diff_id.rsplit("::", 1)[1]
                conn.execute(
                    "INSERT INTO binaries (name, sha256) VALUES (?, ?)",
                    (name, shas[0 if side == "a" else 1]),
                )
            conn.commit()
            conn.close()
            self.atlas.execute(
                "INSERT INTO run (run_id, hunt_commit, build_hash, hunt_instances, "
                "analysis_db_path) VALUES (?, 'facade', ?, 10, ?)",
                (run, current_pass_version(), str(db)),
            )
        for diff_id, (sha_a, sha_b) in SHAS.items():
            binary = diff_id.rsplit("::", 1)[1]
            self.atlas.execute(
                "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id, binary_a, binary_b, "
                "sha256_a, sha256_b, diff_ok, version_skew) "
                "VALUES (?, 'runA', 'runB', ?, ?, ?, ?, 1, 0)",
                (diff_id, binary, binary, sha_a, sha_b),
            )
        self.atlas.commit()
        world = self

        def rows_of(atlas: sqlite3.Connection, diff_id: str) -> so.SinkOverlayResult:
            rows = [
                so.SinkOverlayRow(**{**r.__dict__, "diff_id": diff_id, "binary": None})
                for r in world.rows.get(diff_id, [])
            ]
            cov = so.SinkOverlayCoverage(0, 0, 0, 0, 0, False)
            return so.SinkOverlayResult(rows, cov)

        def staleness(atlas: sqlite3.Connection, diff_id: str) -> dict[str, Any]:
            return {
                "source_stale": False,
                "source_stale_reason": None,
                "toolchain_checked": True,
                **world.stale.get(diff_id, {}),
            }

        def many(atlas: sqlite3.Connection, ids: Any) -> dict[str, dict[str, Any]]:
            return {d: staleness(atlas, d) for d in sorted(set(ids))}

        monkeypatch.setattr(pv, "compute_sink_overlay", rows_of)
        monkeypatch.setattr(pv, "diff_source_staleness", staleness)
        monkeypatch.setattr(da, "diffs_source_staleness", many)
        monkeypatch.setattr(mcp_app, "_installed_commit", lambda: UNKNOWN_VERSION)

    def pair(self, diff_id: str, a: str, b: str, conf: float = 0.97, sim: float = 0.8) -> None:
        state = "aligned" if conf >= 0.9 else "alignment_undetermined"
        self.atlas.execute(
            "INSERT INTO function_alignment (diff_id, addr_a, addr_b, alignment_confidence, "
            "similarity, alignment_state) VALUES (?, ?, ?, ?, ?, ?)",
            (diff_id, a, b, conf, sim, state),
        )
        self.atlas.commit()

    def unpaired(self, diff_id: str, side: str, addr: str, state: str) -> None:
        self.atlas.execute(
            "INSERT INTO function_presence (diff_id, side, addr, presence_state) "
            "VALUES (?, ?, ?, ?)",
            (diff_id, side, addr, state),
        )
        self.atlas.commit()

    def candidate(self, ref: str) -> None:
        """The candidate a promotion writes to, so its own basis resolves."""
        run = ref.split("#", 1)[0]
        pid = self.atlas.execute(
            "INSERT INTO pattern (source_class, sink_class, call_sequence_shape, "
            "structural_fingerprint, fingerprint_algo_version) "
            "VALUES ('external_input', 'cmd', 's->cmd', ?, 'v1')",
            (f"fp_{ref}",),
        ).lastrowid
        self.atlas.execute(
            "INSERT INTO instance (pattern_id, evidence_ref, source_run_id, pseudocode_hash) "
            "VALUES (?, ?, ?, 'h1')",
            (pid, ref, run),
        )
        self.atlas.commit()

    def view(self, diff_id: str = DX, **kw: Any) -> dict[str, Any]:
        return pv.get_diff_patch_view(self.atlas, diff_id, **kw)

    def entry(self, entry_id: str, diff_id: str = DX, **kw: Any) -> dict[str, Any]:
        return next(e for e in self.view(diff_id, **kw)["entries"] if e["entry_id"] == entry_id)

    def judge(self, diff_id: str, anchor: str, verdict: str, **kw: Any) -> overlay.UpsertResult:
        return overlay.annotate_diff(
            self.atlas,
            diff_id=diff_id,
            anchor_ref=anchor,
            verdict=verdict,
            rationale="looked at both sides",
            **kw,
        )


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> World:
    return World(tmp_path, monkeypatch)


def _pair_anchor(diff_id: str, a: str, b: str) -> str:
    return f"{PAIR}#function_pair#{diff_id.rsplit('::', 1)[1]}::{a}::{b}"


# ── the anchor names the binary ───────────────────────────────────────────────────────────────


def test_two_binaries_with_a_function_at_one_address_have_two_anchors(world: World) -> None:
    """★ A run pair's diffs are one per binary, and two binaries can hold a function at the same
    entry address. Without the binary in the anchor, judging one judges the other.

    MUTATION: drop ``{binary}::`` from ``pair_anchor`` -> RED (the second entry reads concluded)."""
    for diff_id in (DX, DY):
        world.pair(diff_id, "00001000", "00002000")
        world.rows[diff_id] = [a_row("00001000")]
    x = world.entry("pair:00001000:00002000", DX)
    y = world.entry("pair:00001000:00002000", DY)
    assert x["anchor_ref"] == f"{PAIR}#function_pair#libx::00001000::00002000"
    assert y["anchor_ref"] == f"{PAIR}#function_pair#liby::00001000::00002000"

    world.judge(DX, x["anchor_ref"], "changed_real")
    assert world.entry("pair:00001000:00002000", DX)["review_state"] == coverage.CONCLUDED
    assert world.entry("pair:00001000:00002000", DY)["review_state"] == coverage.UNSEEN


def test_the_anchors_are_spelled_as_documented(world: World) -> None:
    world.pair(DX, "00001000", "00002000")
    world.unpaired(DX, "b", "00003000", "unmatched_analysis_complete")
    world.rows[DX] = [a_row("00001000")]
    by_id = {e["entry_id"]: e["anchor_ref"] for e in world.view()["entries"]}
    assert by_id == {
        "pair:00001000:00002000": "runA::runB#function_pair#libx::00001000::00002000",
        "b:00003000": "runA::runB#function_presence#libx::b:00003000",
    }
    assert dr.split_anchor(by_id["b:00003000"], "runA", "runB") == (
        "function_presence",
        "libx::b:00003000",
    )
    assert dr.key_binary("function_pair", "lib::x::00001000::00002000") == "lib::x"


# ── promotion: where the row lands ────────────────────────────────────────────────────────────


def _promote(world: World, entry_id: str, ref: str, **kw: Any) -> overlay.PromoteResult:
    return overlay.promote(
        world.atlas,
        diff_id=kw.pop("diff_id", DX),
        entry_id=entry_id,
        row_ref=ref,
        verdict=kw.pop("verdict", "suspicious"),
        rationale="carried over from the diff",
        **kw,
    )


def test_an_a_row_is_promoted_though_its_presence_is_undetermined(world: World) -> None:
    """★ Every A row reads presence_undetermined — the overlay never claims a call was added or
    removed. Judging by presence would refuse every A row there is.

    MUTATION: refuse on ``presence == 'presence_undetermined'`` instead of reading the landing ->
    RED."""
    world.pair(DX, "00001000", "00002000")
    world.rows[DX] = [a_row("00001000")]
    ref = _ref("runA", "00001000")
    world.candidate(ref)
    view_row = world.entry("pair:00001000:00002000")["rows"][0]
    assert (view_row["landing"], view_row["presence"]) == ("A", "presence_undetermined")

    res = _promote(world, "pair:00001000:00002000", ref)
    assert res.written.action == "inserted"
    assert res.promoted_from == {
        "diff_id": DX,
        "anchor_ref": _pair_anchor(DX, "00001000", "00002000"),
        "landing": "A",
        "subclass": "matched_call_other_callee",
    }


@pytest.mark.parametrize(
    ("row", "landing", "subclass", "reason"),
    [
        (
            _row(_ref("runA", "00001000"), None, reason="instruction_unmatched"),
            "B",
            "instruction_unmatched",
            "instruction_unmatched",
        ),
        (a_row("00001000", elsewhere=True), "B", "rematch_suspected", "present_different_callee"),
        (
            _row(_ref("runA", "00001000"), None, reason="a_reason_from_later"),
            "B",
            "unmapped_reason:a_reason_from_later",
            "a_reason_from_later",
        ),
        (
            _row(_ref("runA", "00001000"), None, reason="alignment_low_confidence"),
            "R",
            "alignment_low_confidence",
            "alignment_low_confidence",
        ),
    ],
    ids=["instruction_unmatched", "elsewhere", "unmapped_reason", "r_row"],
)
def test_a_row_outside_the_allowed_landings_is_refused_with_its_facts(
    world: World, row: so.SinkOverlayRow, landing: str, subclass: str, reason: str
) -> None:
    """Refused with the row's landing, subclass and reason as the view states them, and nothing
    written.

    MUTATION: add ``B`` (or ``R``) to the allowed landings -> those parameters go RED."""
    world.pair(DX, "00001000", "00002000")
    world.rows[DX] = [row]
    with pytest.raises(dann.PromotionRefusedError) as exc:
        _promote(world, "pair:00001000:00002000", _ref("runA", "00001000"))
    assert exc.value.details == {
        "landing": landing,
        "subclass": subclass,
        "presence_reason": reason,
    }
    assert world.atlas.execute("SELECT COUNT(*) FROM overlay").fetchone()[0] == 0


def test_a_landing_nobody_named_is_refused(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    """★ The rule is an ALLOW list: a landing added later is refused until someone names it.

    MUTATION: refuse only ``landing in ('B', 'R', 'banner')`` -> RED (the new landing passes)."""
    world.pair(DX, "00001000", "00002000")
    world.rows[DX] = [_row(_ref("runA", "00001000"), None, reason="instruction_unmatched")]
    real = pv.row_landing
    monkeypatch.setattr(
        pv, "row_landing", lambda *a, **k: ("Q", "from_later") if a[1] else real(*a, **k)
    )
    with pytest.raises(dann.PromotionRefusedError) as exc:
        _promote(world, "pair:00001000:00002000", _ref("runA", "00001000"))
    assert exc.value.details["landing"] == "Q"


def test_a_persisted_row_is_promoted(world: World) -> None:
    """★ The origin records the carrying row's landing + subclass; a persisted row lands
    (persisted, None). 'persisted' is where the judgement was carried from, NOT proof the code is
    unchanged.

    MUTATION: drop landing/subclass from the origin in check_promotion -> RED."""
    world.pair(DX, "00001000", "00002000")
    ref_a, ref_b = _ref("runA", "00001000"), _ref("runB", "00002000")
    world.rows[DX] = [_row(ref_a, ref_b, presence="persisted", call="present_same_callee")]
    world.candidate(ref_b)
    entry = world.entry("pair:00001000:00002000")
    assert entry["rows"][0]["landing"] == "persisted"
    res = _promote(world, entry["entry_id"], ref_b)
    assert res.evidence_ref == ref_b
    assert (res.promoted_from.get("landing"), res.promoted_from.get("subclass")) == (
        "persisted",
        None,
    )


# ── promotion: is the counterpart determined ─────────────────────────────────────────────────


def test_an_undetermined_pair_is_refused_whatever_its_rows_say(world: World) -> None:
    """MUTATION: drop the alignment_state check -> RED (the persisted row of an undetermined pair
    is promoted)."""
    world.pair(DX, "00001000", "00002000", conf=0.4)
    ref_a, ref_b = _ref("runA", "00001000"), _ref("runB", "00002000")
    world.rows[DX] = [_row(ref_a, ref_b, presence="persisted", call="present_same_callee")]
    with pytest.raises(dann.PromotionRefusedError) as exc:
        _promote(world, "pair:00001000:00002000", ref_a)
    assert exc.value.details == {"alignment_state": "alignment_undetermined"}


@pytest.mark.parametrize("state", ["unmatched_analysis_incomplete", "inventory_mismatch"])
def test_a_function_whose_absence_is_not_established_is_refused(world: World, state: str) -> None:
    """The row itself lands P / unmatched_analysis_complete (its reason says so); the function's
    own presence record says otherwise, and that record decides.

    MUTATION: drop the presence_state check -> RED."""
    world.unpaired(DX, "a", "00005000", state)
    ref = _ref("runA", "00005000")
    world.rows[DX] = [_row(ref, None, reason="function_unmatched", conf=None)]
    assert world.entry("a:00005000")["rows"][0]["subclass"] == "unmatched_analysis_complete"
    with pytest.raises(dann.PromotionRefusedError) as exc:
        _promote(world, "a:00005000", ref)
    assert exc.value.details == {"presence_state": state}


def test_a_function_with_no_presence_record_lands_absent_and_is_refused(world: World) -> None:
    """A P row whose function was never analysed says nothing about the candidate.

    MUTATION: allow every P landing -> RED."""
    ref = _ref("runA", "00006000")
    world.rows[DX] = [_row(ref, None, reason="counterpart_not_analyzed", conf=None)]
    with pytest.raises(dann.PromotionRefusedError) as exc:
        _promote(world, "a:00006000", ref)
    details = exc.value.details
    assert (details.get("landing"), details.get("subclass")) == ("P", "absent")


def test_a_function_established_to_have_no_counterpart_is_promoted(world: World) -> None:
    """MUTATION: drop landing/subclass from the origin in check_promotion -> RED (the P row's
    landing + subclass are recorded with the judgement)."""
    world.unpaired(DX, "a", "00005000", "unmatched_analysis_complete")
    ref = _ref("runA", "00005000")
    world.rows[DX] = [_row(ref, None, reason="function_unmatched", conf=None)]
    world.candidate(ref)
    res = _promote(world, "a:00005000", ref)
    assert res.written.action == "inserted"
    assert (res.promoted_from.get("landing"), res.promoted_from.get("subclass")) == (
        "P",
        "unmatched_analysis_complete",
    )


# ── promotion: is the diff current, and is it one binary's ───────────────────────────────────


@pytest.mark.parametrize(("stale", "reason"), [(True, "extraction_changed"), (None, "unknown")])
def test_a_diff_that_is_not_current_is_refused_unless_allowed(
    world: World, stale: bool | None, reason: str
) -> None:
    """★ null is refused like true: a diff that could not be checked is not taken as current.

    MUTATION: refuse only ``source_stale is True`` -> the null case goes RED."""
    world.pair(DX, "00001000", "00002000")
    world.rows[DX] = [a_row("00001000")]
    ref = _ref("runA", "00001000")
    world.candidate(ref)
    world.stale[DX] = {"source_stale": stale, "source_stale_reason": reason}
    with pytest.raises(dann.PromotionRefusedError) as exc:
        _promote(world, "pair:00001000:00002000", ref)
    assert exc.value.details == {"source_stale": stale, "source_stale_reason": reason}

    res = _promote(world, "pair:00001000:00002000", ref, allow_stale_source=True)
    assert res.promoted_from.get("promoted_while_source_stale") == {
        "source_stale": stale,
        "source_stale_reason": reason,
    }


def test_a_fresh_atlas_has_the_origin_column(tmp_path: Path) -> None:
    """The schema file carries the column itself; the migration only adds it to older atlases."""
    conn = open_atlas(tmp_path / "fresh.db")
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(overlay)")}
        assert "promoted_from" in cols
    finally:
        conn.close()


def test_a_run_pair_is_refused_as_the_diff(world: World) -> None:
    world.atlas.execute(
        "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id, diff_ok) "
        "VALUES ('runA::runB', 'runA', 'runB', 1)"
    )
    for diff_id in ("runA::runB", "nope::x::y"):
        with pytest.raises(ConfigError, match="run pair|no diff"):
            _promote(world, "pair:00001000:00002000", "r", diff_id=diff_id)


def test_an_entry_anchor_of_another_binary_is_refused(world: World) -> None:
    world.pair(DX, "00001000", "00002000")
    world.rows[DX] = [a_row("00001000")]
    ref = _ref("runA", "00001000")
    world.candidate(ref)
    with pytest.raises(ConfigError, match="names binary 'liby'"):
        _promote(world, _pair_anchor(DY, "00001000", "00002000"), ref)
    # ... and the entry's own anchor is accepted in place of its entry_id
    assert _promote(world, _pair_anchor(DX, "00001000", "00002000"), ref).evidence_ref == ref


def test_a_row_ref_outside_the_entry_is_refused(world: World) -> None:
    """The candidate written to has to be one of the entry's own rows.

    MUTATION: drop the check -> RED (another function's candidate takes the entry's judgement)."""
    world.pair(DX, "00001000", "00002000")
    world.rows[DX] = [a_row("00001000")]
    other = _ref("runA", "00009000")
    world.candidate(other)
    with pytest.raises(dann.PromotionRefusedError) as exc:
        _promote(world, "pair:00001000:00002000", other)
    assert exc.value.details == {
        "entry_id": "pair:00001000:00002000",
        "row_refs": [_ref("runA", "00001000")],
    }


def test_exploitable_needs_its_basis_when_promoted(world: World) -> None:
    """Stricter than a plain candidate write, which records exploitable with no basis.

    MUTATION: drop the requirement from promote -> RED."""
    world.pair(DX, "00001000", "00002000")
    world.rows[DX] = [a_row("00001000")]
    ref = _ref("runA", "00001000")
    world.candidate(ref)
    with pytest.raises(ConfigError, match="requires verdict_basis"):
        _promote(world, "pair:00001000:00002000", ref, verdict="exploitable")
    overlay.upsert_overlay(world.atlas, evidence_ref=ref, verdict="exploitable", rationale="r")


# ── the origin travels with the candidate judgement ──────────────────────────────────────────


def _promoted_world(world: World) -> str:
    world.pair(DX, "00001000", "00002000")
    world.rows[DX] = [a_row("00001000")]
    ref = _ref("runA", "00001000")
    world.candidate(ref)
    _promote(world, "pair:00001000:00002000", ref)
    return ref


def test_the_origin_is_listed_and_a_plain_rewrite_drops_it(world: World) -> None:
    """MUTATION: leave ``promoted_from`` out of the UPDATE in ``_write_row`` -> RED (the
    re-annotated row keeps the old origin)."""
    ref = _promoted_world(world)
    (row,) = overlay.list_overlays(world.atlas)["overlays"]
    assert row["promoted_from"] == {
        "diff_id": DX,
        "anchor_ref": _pair_anchor(DX, "00001000", "00002000"),
        "landing": "A",
        "subclass": "matched_call_other_callee",
        "source_stale": False,
        "source_stale_reason": None,
    }
    assert row["basis_state"] == "unchanged"

    overlay.upsert_overlay(world.atlas, evidence_ref=ref, verdict="excluded", rationale="no")
    stored = world.atlas.execute("SELECT promoted_from FROM overlay").fetchone()[0]
    assert stored is None
    assert overlay.list_overlays(world.atlas)["overlays"][0]["promoted_from"] is None


def test_only_promote_passes_an_origin() -> None:
    """``promoted_from`` is set by promote and by nothing else, anywhere in the package.

    MUTATION: pass ``promoted_from=None`` from the MCP annotate tool -> RED."""
    src = Path(__file__).resolve().parents[3] / "src" / "treasure_map"
    callers = []
    for py in sorted(src.rglob("*.py")):
        tree = ast.parse(py.read_text())
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef):
                continue
            for node in ast.walk(fn):
                if isinstance(node, ast.Call) and any(
                    k.arg == "promoted_from" for k in node.keywords
                ):
                    # the bare name, so an import alias (``as _upsert_overlay``) is still seen
                    name = getattr(node.func, "id", getattr(node.func, "attr", ""))
                    callers.append((py.name, fn.name, name.lstrip("_")))
    assert ("overlay.py", "promote", "upsert_overlay") in callers
    assert {c for c in callers if c[2] == "upsert_overlay"} == {
        ("overlay.py", "promote", "upsert_overlay")
    }


@pytest.mark.parametrize("how", ["stale", "unchecked", "gone"])
def test_a_promoted_judgement_whose_diff_moved_reads_due_a_recheck(world: World, how: str) -> None:
    """★ THE COUPLING. The candidate's own snapshot cannot see the diff it was promoted from move,
    so its own basis still reads unchanged; the listing, the row marker and coverage must say it
    is due a re-check anyway.

    MUTATION: skip the source check in ``effective_basis_state`` -> RED on every parameter."""
    ref = _promoted_world(world)
    if how == "gone":
        world.atlas.execute("DELETE FROM diff_meta WHERE diff_id = ?", (DX,))
        reason = "source_diff_gone"
    else:
        reason = "diff_logic_changed" if how == "stale" else "unknown"
        world.stale[DX] = {
            "source_stale": True if how == "stale" else None,
            "source_stale_reason": reason,
        }
    (row,) = overlay.list_overlays(world.atlas)["overlays"]
    assert row["basis_delta"]["state"] == "unchanged"  # its own facts did not move
    assert row["basis_state"] == overlay.SOURCE_DIFF_STALE
    assert row["promoted_from"]["source_stale_reason"] == reason
    index = coverage.load_coverage_index(world.atlas)
    assert index.state_for(ref) == coverage.NEEDS_RECHECK
    marker = mcp_app._overlay_marker(row)
    assert "re_review" in marker
    assert (marker.get("promoted_from") or {}).get("source_stale_reason") == reason


def test_a_row_that_was_never_promoted_reads_as_before(world: World) -> None:
    ref = _ref("runA", "00009000")
    world.candidate(ref)
    overlay.upsert_overlay(world.atlas, evidence_ref=ref, verdict="suspicious", rationale="r")
    world.stale[DX] = {"source_stale": True, "source_stale_reason": "diff_logic_changed"}
    (row,) = overlay.list_overlays(world.atlas)["overlays"]
    assert (row["basis_state"], row["promoted_from"]) == ("unchanged", None)
    assert coverage.load_coverage_index(world.atlas).state_for(ref) == coverage.CONCLUDED


# ── the two vocabularies stay apart ──────────────────────────────────────────────────────────


def test_each_vocabulary_is_refused_on_the_other_anchor(world: World) -> None:
    world.pair(DX, "00001000", "00002000")
    world.rows[DX] = [a_row("00001000")]
    with pytest.raises(ConfigError, match="diff-entry verdict"):
        overlay.upsert_overlay(
            world.atlas,
            evidence_ref=_ref("runA", "00001000"),
            verdict="changed_real",
            rationale="r",
        )
    with pytest.raises(ConfigError, match="candidate verdict"):
        world.judge(DX, _pair_anchor(DX, "00001000", "00002000"), "suspicious")
    with pytest.raises(ConfigError, match="diff-entry verdict"):
        _promote(world, "pair:00001000:00002000", _ref("runA", "00001000"), verdict="changed_real")
    assert world.atlas.execute("SELECT COUNT(*) FROM overlay").fetchone()[0] == 0


# ── no_real_change owes its basis ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "basis",
    [
        None,
        {"checked": [], "why_unchanged": "x"},
        {"checked": ["a", "  "], "why_unchanged": "x"},
        {"checked": ["a", "b"], "why_unchanged": "  "},
    ],
)
def test_no_real_change_without_its_basis_is_refused(
    world: World, basis: dict[str, Any] | None
) -> None:
    world.pair(DX, "00001000", "00002000")
    world.rows[DX] = [a_row("00001000")]
    with pytest.raises(ConfigError, match="no_real_change"):
        world.judge(
            DX, _pair_anchor(DX, "00001000", "00002000"), "no_real_change", verdict_basis=basis
        )


def test_no_real_change_with_its_basis_is_stored(world: World) -> None:
    world.pair(DX, "00001000", "00002000")
    world.rows[DX] = [a_row("00001000")]
    world.judge(
        DX,
        _pair_anchor(DX, "00001000", "00002000"),
        "no_real_change",
        verdict_basis=_nrc(_pair_anchor(DX, "00001000", "00002000")),
    )
    stored = json.loads(world.atlas.execute("SELECT verdict_basis FROM overlay").fetchone()[0])
    assert stored["kind"] == "no_real_change" and len(stored["checked"]) == 2
    with pytest.raises(ConfigError, match="changed_real takes evidence only"):
        world.judge(
            DX,
            _pair_anchor(DX, "00001000", "00002000"),
            "changed_real",
            verdict_basis={"checked": ["x"]},
        )


# ── band: moves judged entries only inside the groups the base order forms ────────────────────


def _e(
    bucket: str,
    tier: int | str,
    addr: str,
    sim: float = 0.5,
    subclass: str = "instruction_unmatched",
) -> Any:
    pair = pv._Pair(addr, addr, None, None, 0.95, sim, "aligned", None, None)
    e = pv._Entry(pair=pair, unpaired=None, bucket=bucket)
    e.tier, e.subclass = tier, subclass
    e.rank = pv._rank(e)
    return e


def test_band_moves_an_entry_only_inside_its_group() -> None:
    """★ segment 2 interleaves R and B by tier, so there is no contiguous bucket band to sink
    into — a sunk entry may only fall to the end of the group whose first four components it
    shares. Here: a B of tier 3 marked no_real_change stays above every tier-2 entry and above
    every candidate-less entry, and sinks only below the other tier-3 B.

    MUTATION: put the band ahead of the tier in ``_default_key`` -> RED."""
    b3_sunk = _e("B", 3, "b3_sunk", sim=0.1)
    b3 = _e("B", 3, "b3", sim=0.9)
    r3 = _e("R", 3, "r3", sim=0.9)
    b2 = _e("B", 2, "b2", sim=0.0)
    c = _e("C", "no_sink", "c", sim=0.0)
    entries = [c, b2, b3, r3, b3_sunk]
    base = [e.entry_id for e in pv._sort(entries, None)]
    assert base == [r3.entry_id, b3_sunk.entry_id, b3.entry_id, b2.entry_id, c.entry_id]

    bands = {e.entry_id: dr.band_bias(coverage.UNSEEN, None) for e in entries}
    bands[b3_sunk.entry_id] = dr.band_bias(coverage.CONCLUDED, "no_real_change")
    banded = [e.entry_id for e in pv._sort(entries, None, bands)]
    assert banded == [r3.entry_id, b3.entry_id, b3_sunk.entry_id, b2.entry_id, c.entry_id]


def test_band_moves_an_entry_only_inside_its_subclass_rank() -> None:
    """★ Within segment 2 the B subclass rank sorts sink-presence-signal B (rank 0) ahead of the
    rest (rank 1) BEFORE the band. A rank-0 B marked no_real_change (the band that sinks furthest)
    stays above an unseen rank-1 B: the band orders only inside a subclass rank, never across it.

    MUTATION: put the band ahead of ``subclass_rank`` in ``_default_key`` -> RED."""
    hi = _e("B", 3, "hi", sim=0.9, subclass="sink_presence_signal_added")  # subclass_rank 0
    lo = _e("B", 3, "lo", sim=0.1)  # instruction_unmatched -> subclass_rank 2 (the catch-all)
    assert (hi.rank["subclass_rank"], lo.rank["subclass_rank"]) == (0, 2)
    entries = [lo, hi]
    assert [e.entry_id for e in pv._sort(entries, None)] == [hi.entry_id, lo.entry_id]

    bands = {
        hi.entry_id: dr.band_bias(coverage.CONCLUDED, "no_real_change"),  # 5: sinks furthest
        lo.entry_id: dr.band_bias(coverage.UNSEEN, None),  # 2
    }
    banded = [e.entry_id for e in pv._sort(entries, None, bands)]
    assert banded == [hi.entry_id, lo.entry_id]  # subclass_rank holds hi above lo despite the band


def _judged(state: str, verdict: str | None) -> dr.Item:
    return dr.Item("x", "", "B", "", 3, state, verdict, (0,))


def _with_delta(e: Any) -> Any:
    e.row_views = [{"landing": "persisted", "sink_arg_constant_delta": {"from": "1", "to": "2"}}]
    return e


def test_significance_floats_scoped_signals_and_never_sinks_what_must_stay_in_view() -> None:
    """★ The lens's tiers, from the entry's own facts. A scoped sink signal floats (and wins over
    sinking); a pseudocode-identical or C entry sinks — except an R entry, a guard
    (sink_present_no_visible_delta, labelled so) and anything judged changed_real, inconclusive or
    due a re-check / relabel, C included. A judged no_real_change may sink.

    MUTATION: let a held-up judgement sink (drop ``_held_up``) -> RED; sink an R entry -> RED;
    exempt nothing for the guard -> RED; check sinking before the scoped signals -> RED."""
    sig = pv.significance
    b = _e("B", 3, "b1")
    c = _e("C", "no_sink", "c1", subclass="no_sink_candidate")
    assert sig(_e("A", 3, "a1"), "identical", None) == (0, "matched_call_other_callee")
    assert sig(_with_delta(_e("B", 3, "d1")), "identical", None) == (0, "sink_arg_constant_delta")
    assert sig(b, "identical", None) == (2, "pseudocode_identical")
    assert sig(b, "differs", None) == (1, "similarity")
    assert sig(c, None, None) == (2, "no_sink_candidate")
    guard = _e("B", 3, "g1", subclass="sink_present_no_visible_delta")
    assert sig(guard, "identical", None) == (1, "recheckable_no_visible_delta")
    r = _e("R", 3, "r1", subclass="degenerate_block_source")
    assert sig(r, "identical", None) == (1, "undetermined_never_sunk")
    held = (
        (coverage.CONCLUDED, "changed_real"),
        (coverage.NEEDS_RECHECK, "no_real_change"),
        (coverage.NEEDS_RELABEL, "a_retired_word"),
        (coverage.OPEN, "change_inconclusive"),
    )
    for state, verdict in held:
        assert sig(b, "identical", _judged(state, verdict)) == (1, "judged_never_sunk")
        assert sig(c, None, _judged(state, verdict)) == (1, "judged_never_sunk")
    assert sig(b, "identical", _judged(coverage.CONCLUDED, "no_real_change"))[0] == 2


def test_the_significance_order_is_attention_then_band_then_similarity() -> None:
    """MUTATION: put similarity ahead of attention -> RED; leave the band out with band on ->
    RED."""
    sunk, hi, lo, top = (
        _e("B", 3, "s", sim=0.1),
        _e("B", 3, "h", sim=0.9),
        _e("B", 3, "l", sim=0.2),
        _e("B", 3, "t", sim=0.95),
    )
    att = {sunk.entry_id: 2, hi.entry_id: 1, lo.entry_id: 1, top.entry_id: 0}
    ents = [sunk, hi, lo, top]
    order = [e.entry_id for e in pv._sort(ents, "significance", None, att)]
    assert order == [top.entry_id, lo.entry_id, hi.entry_id, sunk.entry_id]
    bands = {
        lo.entry_id: dr.band_bias(coverage.CONCLUDED, "no_real_change"),
        hi.entry_id: dr.band_bias(coverage.NEEDS_RECHECK, "changed_real"),
    }
    order = [e.entry_id for e in pv._sort(ents, "significance", bands, att)]
    assert order == [top.entry_id, hi.entry_id, lo.entry_id, sunk.entry_id]


def test_band_orders_recheck_then_open_then_unseen() -> None:
    """MUTATION: rank OPEN after UNSEEN in ``band_bias`` -> RED."""
    ent = [_e("B", 2, n, sim=s) for n, s in (("u", 0.1), ("o", 0.5), ("k", 0.9), ("n", 0.2))]
    states = {
        ent[0].entry_id: (coverage.UNSEEN, None),
        ent[1].entry_id: (coverage.OPEN, "change_inconclusive"),
        ent[2].entry_id: (coverage.NEEDS_RECHECK, "no_real_change"),
        ent[3].entry_id: (coverage.CONCLUDED, "changed_real"),
    }
    bands = {k: dr.band_bias(*v) for k, v in states.items()}
    order = [e.entry_id for e in pv._sort(ent, None, bands)]
    assert order == [ent[2].entry_id, ent[1].entry_id, ent[0].entry_id, ent[3].entry_id]


def test_band_off_leaves_the_view_as_it_was(world: World) -> None:
    """With judgements present and band off, the view is the view with none, apart from the two
    judgement keys on each entry and the two judgement blocks on the envelope.

    MUTATION: apply the band whatever ``band`` says -> RED."""
    for a, b, sim in (("00001000", "00002000", 0.9), ("00003000", "00004000", 0.1)):
        world.pair(DX, a, b, sim=sim)
    world.rows[DX] = [a_row("00001000"), a_row("00003000")]
    before = world.view()
    world.judge(
        DX,
        _pair_anchor(DX, "00003000", "00004000"),
        "no_real_change",
        verdict_basis=_nrc(_pair_anchor(DX, "00003000", "00004000"), "x"),
    )
    after = world.view()

    def strip(v: dict[str, Any]) -> dict[str, Any]:
        out = {k: x for k, x in v.items() if k not in ("review_progress", "annotation")}
        out["entries"] = [
            {k: x for k, x in e.items() if k not in ("review_state", "anchor_ref")}
            for e in v["entries"]
        ]
        return out

    assert strip(after) == strip(before)
    banded = world.view(band=True)
    assert [e["entry_id"] for e in banded["entries"]] == [
        "pair:00001000:00002000",
        "pair:00003000:00004000",
    ]
    assert [e["entry_id"] for e in after["entries"]] == [
        "pair:00003000:00004000",
        "pair:00001000:00002000",
    ]
    assert banded["entries"][1]["rank_key"]["band_bias"] == 5
    assert "band_bias" not in after["entries"][0]["rank_key"]


# ── what a judgement rests on, and when it moves ─────────────────────────────────────────────


def test_a_judged_entry_whose_facts_moved_is_due_a_recheck_and_floats(world: World) -> None:
    """The other entry sorts first by similarity, so the float is the band's doing.

    MUTATION: compare nothing in ``judge`` (always unchanged) -> RED."""
    world.pair(DX, "00001000", "00002000", sim=0.1)
    world.pair(DX, "00003000", "00004000", sim=0.05)
    world.rows[DX] = [a_row("00001000"), a_row("00003000")]
    anchor = _pair_anchor(DX, "00001000", "00002000")
    world.judge(DX, anchor, "no_real_change", verdict_basis=_nrc(anchor, "x"))
    assert world.entry("pair:00001000:00002000")["review_state"] == coverage.CONCLUDED

    world.atlas.execute("UPDATE function_alignment SET similarity = 0.3 WHERE addr_a = '00001000'")
    entry = world.entry("pair:00001000:00002000")
    assert entry["review_state"] == coverage.NEEDS_RECHECK
    listed = overlay.list_overlays(world.atlas, anchor_kind="diff_subject")["overlays"][0]
    assert listed["basis_moved"] == {"similarity": [0.1, 0.3]}
    assert world.view()["entries"][0]["entry_id"] == "pair:00003000:00004000"
    banded = world.view(band=True)["entries"]
    assert banded[0]["entry_id"] == "pair:00001000:00002000"


def test_a_diff_that_is_not_current_puts_its_judgements_in_recheck(world: World) -> None:
    world.pair(DX, "00001000", "00002000")
    world.rows[DX] = [a_row("00001000")]
    world.judge(DX, _pair_anchor(DX, "00001000", "00002000"), "changed_real")
    world.stale[DX] = {"source_stale": None, "source_stale_reason": "unknown"}
    assert world.entry("pair:00001000:00002000")["review_state"] == coverage.NEEDS_RECHECK
    (row,) = overlay.list_overlays(world.atlas, anchor_kind="diff_subject")["overlays"]
    assert (row["review_state"], row["source_stale_reason"]) == (coverage.NEEDS_RECHECK, "unknown")


def test_a_repaired_pair_leaves_its_judgement_dangling(world: World) -> None:
    """BinDiff pairs the function with another one: the judged pair is no longer a subject."""
    world.pair(DX, "00001000", "00002000")
    world.rows[DX] = [a_row("00001000")]
    anchor = _pair_anchor(DX, "00001000", "00002000")
    world.judge(DX, anchor, "changed_real")
    world.atlas.execute("UPDATE function_alignment SET addr_b = '00002400'")
    view = world.view()
    assert view["review_progress"]["dangling_annotations"] == [anchor]
    assert view["entries"][0]["review_state"] == coverage.UNSEEN
    (row,) = overlay.list_overlays(world.atlas, anchor_kind="diff_subject")["overlays"]
    assert row["basis_state"] == dr.ANCHOR_UNRESOLVED


def test_a_rekeyed_candidate_moves_the_pair_and_strands_the_candidate_anchor(
    world: World,
) -> None:
    """A candidate re-key changes the refs under a pair: the pair's judgement holds its anchor
    and reads moved; a judgement anchored on the candidate row itself is left dangling (the
    re-key re-points candidate annotations only)."""
    world.pair(DX, "00001000", "00002000")
    world.rows[DX] = [a_row("00001000")]
    pair_anchor = _pair_anchor(DX, "00001000", "00002000")
    cand_anchor = dr.candidate_anchor(
        "runA", "runB", f"callsite|cmd|{_ref('runA', '00001000')}|(none)"
    )
    world.judge(DX, pair_anchor, "changed_real")
    world.judge(DX, cand_anchor, "change_inconclusive")
    world.rows[DX] = [_rekeyed()]
    rows = {
        r["anchor_ref"]: r
        for r in overlay.list_overlays(world.atlas, anchor_kind="diff_subject")["overlays"]
    }
    assert rows[pair_anchor]["review_state"] == coverage.NEEDS_RECHECK
    assert list(rows[pair_anchor]["basis_moved"]) == ["rows"]
    assert rows[cand_anchor]["basis_state"] == dr.ANCHOR_UNRESOLVED
    assert world.view()["review_progress"]["dangling_annotations"] == [cand_anchor]


def _rekeyed() -> so.SinkOverlayRow:
    return _row(
        _ref("runA", "00001000", at="0x14"),
        None,
        reason="present_different_callee",
        call="present_different_callee",
        elsewhere=False,
    )


def test_an_anchor_that_names_nothing_listed_is_refused(world: World) -> None:
    world.pair(DX, "00001000", "00002000", sim=1.0)  # identical, no candidate: not listed
    with pytest.raises(ConfigError, match="names nothing"):
        world.judge(DX, _pair_anchor(DX, "00001000", "00002000"), "changed_real")
    with pytest.raises(ConfigError, match="not an anchor of this diff's run pair"):
        world.judge(DX, "runC::runB#function_pair#libx::00001000::00002000", "changed_real")


# ── progress ─────────────────────────────────────────────────────────────────────────────────


def test_progress_counts_entries_by_bucket_in_the_view_order(world: World) -> None:
    world.pair(DX, "00001000", "00002000")
    world.pair(DX, "00003000", "00004000", sim=0.3)
    world.unpaired(DX, "b", "00005000", "unmatched_analysis_complete")
    world.rows[DX] = [a_row("00001000"), _row(_ref("runA", "00003000"), None, reason="x_later")]
    view = world.view()
    world.judge(DX, view["entries"][0]["anchor_ref"], "change_inconclusive")
    p = world.view()["review_progress"]
    assert (p["total"], p["looked_at"], p["not_looked_at"]) == (3, 1, 2)
    assert p["by_bucket"]["A"][coverage.OPEN] == 1
    assert p["by_bucket"]["B"][coverage.UNSEEN] == 1 and p["by_bucket"]["P"][coverage.UNSEEN] == 1
    assert [n["entry_id"] for n in p["next_page"]] == ["pair:00003000:00004000", "b:00005000"]
    assert p["complete"] is False and p["blind_spots"]["structural"]

    scoped = world.view(bucket="A")["review_progress"]
    assert (scoped["total"], scoped["complete"]) == (1, True)
    assert scoped["outside_this_scope"]["not_looked_at"] == 2


def test_a_withheld_diff_counts_nothing_and_cannot_be_judged(world: World) -> None:
    world.pair(DX, "00001000", "00002000")
    world.rows[DX] = [a_row("00001000")]
    world.atlas.execute("UPDATE diff_meta SET version_skew = 1 WHERE diff_id = ?", (DX,))
    view = world.view()
    p = view["review_progress"]
    assert p.get("withheld") is True and "diff_undetermined:version_skew" in p["banners"]
    assert "not_looked_at" not in p and "states" not in p and p["complete"] is False
    assert view["annotation"]["available"] is False
    with pytest.raises(ConfigError, match="undetermined as a whole"):
        world.judge(DX, _pair_anchor(DX, "00001000", "00002000"), "changed_real")


def test_a_judgement_already_on_a_now_withheld_diff_reads_diff_withheld(world: World) -> None:
    """A diff undetermined as a whole lists no entry, but a judgement already written on one is
    still read — and must read ``diff_withheld`` / needs_recheck, never ``unchanged`` (its facts
    cannot be checked while the diff is withheld) and never dangling (the subject is not gone, the
    diff is).

    MUTATION: in ``judge``, drop the ``withheld`` branch -> the judgement reads anchor_unresolved
    (basis_state goes RED) and is reported as dangling; let the view compute as if determined ->
    it reads unchanged / concluded (both review_state and basis_state go RED)."""
    world.pair(DX, "00001000", "00002000")
    world.rows[DX] = [a_row("00001000")]
    anchor = _pair_anchor(DX, "00001000", "00002000")
    world.judge(DX, anchor, "changed_real")
    settled = overlay.list_overlays(world.atlas, anchor_kind="diff_subject", run_id=PAIR)
    assert settled["overlays"][0]["basis_state"] == dr.UNCHANGED
    assert settled["overlays"][0]["review_state"] == coverage.CONCLUDED

    world.atlas.execute("UPDATE diff_meta SET version_skew = 1 WHERE diff_id = ?", (DX,))
    withheld = overlay.list_overlays(world.atlas, anchor_kind="diff_subject", run_id=PAIR)
    row = withheld["overlays"][0]
    assert row["basis_state"] == dr.DIFF_WITHHELD
    assert row["review_state"] == coverage.NEEDS_RECHECK
    assert withheld["review_progress"]["dangling_annotations"] == []


def test_a_run_pair_is_never_complete_while_a_binary_is_not_covered(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ Every listed entry judged is not the run pair read: a failed diff lists no entry, and a
    binary no diff covers has none either. Each of them alone keeps ``complete`` false.

    MUTATION: compute ``complete`` from the entry count alone -> RED on both parameters."""
    world.pair(DX, "00001000", "00002000")
    world.rows[DX] = [a_row("00001000")]
    monkeypatch.setattr(dann, "not_diffed_binaries", lambda *a, **k: {})
    world.atlas.execute("DELETE FROM diff_meta WHERE diff_id = ?", (DY,))
    world.judge(DX, _pair_anchor(DX, "00001000", "00002000"), "changed_real")
    clean = overlay.list_overlays(world.atlas, anchor_kind="diff_subject", run_id=PAIR)
    assert clean["review_progress"]["complete"] is True

    world.atlas.execute(
        "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id, binary_a, diff_ok, "
        "diff_status_reason) VALUES (?, 'runA', 'runB', 'liby', 0, 'bindiff_failed')",
        (DY,),
    )
    failed = overlay.list_overlays(world.atlas, anchor_kind="diff_subject", run_id=PAIR)
    progress = failed["review_progress"]
    assert progress["not_looked_at"] == 0 and progress["complete"] is False
    assert [d["diff_id"] for d in progress["blind_spots"]["failed_diffs"]] == [DY]
    assert progress["blind_spots"]["withheld_diffs"] == []

    world.atlas.execute("DELETE FROM diff_meta WHERE diff_id = ?", (DY,))
    monkeypatch.setattr(
        dann,
        "not_diffed_binaries",
        lambda *a, **k: {
            "b": {"binary_not_diffed": {"binaries": 1, "candidates": 2, "names": ["z"]}}
        },
    )
    undiffed = overlay.list_overlays(world.atlas, anchor_kind="diff_subject", run_id=PAIR)
    assert undiffed["review_progress"]["complete"] is False


def test_the_not_diffed_binaries_are_split_by_whether_they_are_blind_spots(world: World) -> None:
    """Read straight from the atlas, by content hash: a binary whose bytes are on BOTH sides was
    not diffed because there was nothing to diff (``identical_both_sides`` — no blind spot); one on
    this side only is ``binary_not_diffed``; one whose NAME matches a diffed binary but whose bytes
    do not is ``shadowed_by_name_collision``. (The diffs are of libx/liby.)

    MUTATION: drop the identical check in ``not_diffed_reason`` (call it binary_not_diffed) -> the
    libz rows go RED; drop the shadowed check -> the libx row goes RED."""
    insert = (
        # (evidence_ref, run, path, content_hash)
        (_ref("runA", "00007000"), "runA", "/fw/usr/lib/libz", "e" * 64),  # identical, both sides
        (_ref("runB", "00008000"), "runB", "/fw/usr/lib/libz", "e" * 64),  # identical, both sides
        (_ref("runA", "00009000"), "runA", "/fw/sbin/libq", "f" * 64),  # a-side only
        (_ref("runB", "0000a000"), "runB", "/fw/usr/lib/libx", "cafe" * 16),  # name libx diffed
    )
    for ref, run, path, sha in insert:
        world.atlas.execute(
            "INSERT INTO pattern (source_class, sink_class, call_sequence_shape, "
            "structural_fingerprint, fingerprint_algo_version) "
            "VALUES ('external_input', 'cmd', 's', ?, 'v1')",
            (f"fp_{ref}",),
        )
        world.atlas.execute(
            "INSERT INTO instance (pattern_id, evidence_ref, source_run_id, binary_path, "
            "binary_content_hash) VALUES (last_insert_rowid(), ?, ?, ?, ?)",
            (ref, run, path, sha),
        )
    world.atlas.commit()
    one = {"binaries": 1, "candidates": 1}
    assert da.not_diffed_binaries(world.atlas, "runA", "runB") == {
        "a": {
            "binary_not_diffed": {**one, "names": ["libq"]},
            "identical_both_sides": {**one, "names": ["libz"]},
        },
        "b": {
            "identical_both_sides": {**one, "names": ["libz"]},
            "shadowed_by_name_collision": {**one, "names": ["libx"]},
        },
    }


def _cand(world: World, ref: str, run: str, path: str, sha: str) -> None:
    world.atlas.execute(
        "INSERT INTO pattern (source_class, sink_class, call_sequence_shape, "
        "structural_fingerprint, fingerprint_algo_version) "
        "VALUES ('external_input', 'cmd', 's', ?, 'v1')",
        (f"fp_{ref}",),
    )
    world.atlas.execute(
        "INSERT INTO instance (pattern_id, evidence_ref, source_run_id, binary_path, "
        "binary_content_hash) VALUES (last_insert_rowid(), ?, ?, ?, ?)",
        (ref, run, path, sha),
    )
    world.atlas.commit()


def test_list_diffs_reads_the_same_split_and_an_identical_binary_never_blocks_coverage(
    world: World,
) -> None:
    """★ The run-pair coverage beside list_diffs uses the one shared classifier: a binary
    byte-identical in both runs is information (with the scan-map pointer), never a blind spot; a
    binary on one side only is, and keeps ``all_candidate_binaries_covered`` false.

    MUTATION: fold identical_both_sides into the blind-spot reasons -> RED."""
    _cand(world, _ref("runA", "00007000"), "runA", "/fw/usr/lib/libz", "e" * 64)
    _cand(world, _ref("runB", "00008000"), "runB", "/fw/usr/lib/libz", "e" * 64)
    _cand(world, _ref("runA", "00009000"), "runA", "/fw/sbin/libq", "f" * 64)
    cov = da.list_diffs(world.atlas, "runA", "runB")["coverage"]
    one = {"binaries": 1, "candidates": 1}
    assert cov["identical_binaries"] == {"a": one, "b": one}
    assert cov["not_diffed_binaries"] == {"a": {"binary_not_diffed": {**one, "names": ["libq"]}}}
    assert cov["all_candidate_binaries_covered"] is False
    assert "list_candidates(run_id='runB')" in cov["see"]
    world.atlas.execute("DELETE FROM instance WHERE binary_content_hash = ?", ("f" * 64,))
    world.atlas.commit()
    cov = da.list_diffs(world.atlas, "runA", "runB")["coverage"]
    assert cov["all_candidate_binaries_covered"] is True  # the identical binary alone never blocks
    assert cov["identical_binaries"] == {"a": one, "b": one}


def test_a_diffed_binary_holding_candidates_on_both_sides_is_covered(world: World) -> None:
    """★ A binary whose content WAS one side of a diff is covered, whatever else shares its name:
    its candidates are in no not-diffed reason and the pair reads covered.

    MUTATION: drop the "content is a diffed hash" skip in ``not_diffed_binaries`` -> libx's
    candidates fall to its diffed name and read shadowed_by_name_collision -> RED."""
    _cand(world, _ref("runA", "00001000"), "runA", "/fw/usr/lib/libx", SHAS[DX][0])
    _cand(world, _ref("runB", "00002000"), "runB", "/fw/usr/lib/libx", SHAS[DX][1])
    assert da.not_diffed_binaries(world.atlas, "runA", "runB") == {}
    cov = da.list_diffs(world.atlas, "runA", "runB")["coverage"]
    assert cov["not_diffed_binaries"] == {} and cov["identical_binaries"] == {}
    assert cov["all_candidate_binaries_covered"] is True


def test_identical_content_wins_over_a_same_named_diffed_binary(world: World) -> None:
    """A binary byte-identical on both sides needed no diff, even when another file of the same name
    was diffed: it is identical_both_sides, never read as shadowed by that name.

    MUTATION: test the name collision before the identical content in ``not_diffed_reason`` -> both
    sides read shadowed_by_name_collision -> RED."""
    _cand(world, _ref("runA", "00007000"), "runA", "/fw/opt/lib/libx", "e" * 64)
    _cand(world, _ref("runB", "00008000"), "runB", "/fw/opt/lib/libx", "e" * 64)
    same = {"identical_both_sides": {"binaries": 1, "candidates": 1, "names": ["libx"]}}
    assert da.not_diffed_binaries(world.atlas, "runA", "runB") == {"a": same, "b": same}
    cov = da.list_diffs(world.atlas, "runA", "runB")["coverage"]
    assert cov["not_diffed_binaries"] == {}
    assert cov["all_candidate_binaries_covered"] is True


def test_a_failed_diff_alone_keeps_the_pair_uncovered(world: World) -> None:
    """★ A diff that failed covers nothing, though it names its binary's content (a failure row
    records both sides' sha256, as the driver writes it): with no other blind spot, the failure
    alone keeps ``all_candidate_binaries_covered`` false, and is listed.

    MUTATION: compute the flag from the not-diffed binaries alone (ignore the failed diffs) ->
    RED."""
    world.atlas.execute(
        "UPDATE diff_meta SET diff_ok = 0, diff_status = 'failed', "
        "diff_status_reason = 'bindiff_failed' WHERE diff_id = ?",
        (DY,),
    )
    _cand(world, _ref("runA", "00003000"), "runA", "/fw/usr/lib/liby", SHAS[DY][0])
    _cand(world, _ref("runB", "00004000"), "runB", "/fw/usr/lib/liby", SHAS[DY][1])
    cov = da.list_diffs(world.atlas, "runA", "runB")["coverage"]
    assert cov["failed_diffs"] == [DY]
    assert cov["not_diffed_binaries"] == {}  # the failure's content is named: no blind spot
    assert cov["all_candidate_binaries_covered"] is False


def test_get_diff_meta_carries_the_views_function_split_and_a_failed_diff_has_none(
    world: World,
) -> None:
    """get_diff_meta's ``functions`` is function_states — the view's facts, not a second reading;
    a diff that did not run says so and gives no counts.

    MUTATION: compute get_diff_meta's split from similarity instead -> RED (it no longer equals
    the view's); print zeros for the failed diff -> RED."""
    world.pair(DX, "00001000", "00002000", sim=1.0)
    world.rows[DX] = [a_row("00001000")]
    meta = da.get_diff_meta(world.atlas, DX)
    assert meta["functions"] == pv.function_states(world.atlas, DX)
    assert meta["functions"]["aligned"] == 1
    world.atlas.execute("UPDATE diff_meta SET diff_ok = 0 WHERE diff_id = ?", (DX,))
    failed = da.get_diff_meta(world.atlas, DX)["functions"]
    assert failed["withheld"] is True and failed["blind_spot"] == "did_not_diff"
    assert "aligned" not in failed


def test_a_binary_identical_on_both_sides_does_not_keep_a_pair_incomplete(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A binary byte-identical on both sides needed no diff, so — unlike a genuine not-diffed
    binary — it must not keep ``complete`` false. It is reported apart, never as a blind spot.

    MUTATION: fold identical_both_sides into the blind-spot reasons -> RED (complete goes false)."""
    world.pair(DX, "00001000", "00002000")
    world.rows[DX] = [a_row("00001000")]
    world.atlas.execute("DELETE FROM diff_meta WHERE diff_id = ?", (DY,))
    world.judge(DX, _pair_anchor(DX, "00001000", "00002000"), "changed_real")
    monkeypatch.setattr(
        dann,
        "not_diffed_binaries",
        lambda *a, **k: {
            "a": {"identical_both_sides": {"binaries": 2, "candidates": 9, "names": ["x", "y"]}}
        },
    )
    progress = overlay.list_overlays(world.atlas, anchor_kind="diff_subject", run_id=PAIR)[
        "review_progress"
    ]
    assert progress["complete"] is True
    assert progress["blind_spots"]["not_diffed_binaries"] == {}
    assert progress["identical_not_diffed_binaries"] == {"a": {"binaries": 2, "candidates": 9}}


# ── discoverable without a single judgement ──────────────────────────────────────────────────


@pytest.mark.parametrize("band", [False, True])
def test_with_no_judgement_the_view_says_how_to_write_one(world: World, band: bool) -> None:
    """MUTATION: emit ``annotation`` / ``review_state`` only with band on -> the band=False
    parameter goes RED."""
    world.pair(DX, "00001000", "00002000")
    world.rows[DX] = [a_row("00001000")]
    view = world.view(band=band)
    (entry,) = view["entries"]
    assert entry.get("review_state") == coverage.UNSEEN
    block = view["annotation"]
    assert isinstance(block, dict) and block["available"] is True
    assert entry["anchor_ref"] in block["annotate_diff"] and f'"{DX}"' in block["annotate_diff"]
    assert block["by_bucket"]["A"] == {
        "seen": 0,
        "unseen": 1,
        "next": f'get_diff_patch_view(diff_id="{DX}", bucket="A")',
    }
    assert f'run_id="{PAIR}"' in block["review_with"]


# ── kept apart from the candidate layer ──────────────────────────────────────────────────────


def test_diff_judgements_stay_out_of_the_candidate_layer(world: World) -> None:
    world.pair(DX, "00001000", "00002000")
    world.rows[DX] = [a_row("00001000")]
    world.judge(DX, _pair_anchor(DX, "00001000", "00002000"), "changed_real")
    assert overlay.list_overlays(world.atlas)["count"] == 0
    assert coverage.load_coverage_index(world.atlas).by_ref == {}
    # no scope + clear_all: candidate (evidence_ref) annotations only, not the diff-entry kind
    assert overlay.clear_overlay(world.atlas, clear_all=True) == 0
    assert overlay.list_overlays(world.atlas, anchor_kind="diff_subject")["count"] == 1
    assert overlay.clear_overlay(world.atlas, anchor_kind="diff_subject", run_id=PAIR) == 1
    with pytest.raises(ConfigError, match="anchor_kind"):
        overlay.list_overlays(world.atlas, anchor_kind="made_up")


# ── the MCP face ─────────────────────────────────────────────────────────────────────────────


def test_the_tools_write_list_and_refuse_with_the_facts(world: World) -> None:
    world.pair(DX, "00001000", "00002000")
    world.rows[DX] = [a_row("00001000"), _row(_ref("runA", "00001000", "0x40"), None, reason="x")]
    ref = _ref("runA", "00001000")
    world.candidate(ref)
    tools = mcp_app.make_tools(world.path)
    view = tools["get_diff_patch_view"](DX)
    anchor = view["entries"][0]["anchor_ref"]
    r = tools["annotate_diff"](anchor, "no_real_change", "why", checked=[anchor], diff_id=DX)
    assert r["written"] is False and "why_unchanged" in r["error"]
    r = tools["annotate_diff"](
        anchor, "no_real_change", "why", checked=[anchor], why_unchanged="renamed", diff_id=DX
    )
    assert r["written"] is True and r["action"] == "inserted"

    refused = tools["promote"](
        DX, "pair:00001000:00002000", _ref("runA", "00001000", "0x40"), "suspicious", "r"
    )
    assert refused["written"] is False
    assert refused.get("refused", {}).get("landing") == "B"
    done = tools["promote"](DX, "pair:00001000:00002000", ref, "suspicious", "r")
    assert done["written"] is True and done["promoted_from"]["anchor_ref"] == anchor

    listed = tools["list_candidates"](run_id="runA", overlay=True)
    marker = next(c for c in listed["candidates"] if c["evidence_ref"] == ref)["overlay"]
    assert marker["promoted_from"]["diff_id"] == DX
    judged = tools["list_overlays"](anchor_kind="diff_subject", run_id=PAIR)
    assert judged["count"] == 1 and "review_progress" in judged
    assert tools["clear_overlay"](anchor_kind="diff_subject", anchor_ref=anchor)["cleared"] == 1


# ── annotate_diff_batch (T3): all-or-none, checked anchors, rationale, evidence, echo ──────────


def _batch_world(world: World, n: int, diff_id: str = DX) -> tuple[Any, list[str]]:
    """``n`` listed function_pair entries on ``diff_id``, and the tools + each entry's anchor_ref
    (built directly, so no view pagination hides one)."""
    for i in range(n):
        world.pair(diff_id, f"{0x1000 + i:08x}", f"{0x9000 + i:08x}")
    world.rows[diff_id] = [a_row(f"{0x1000 + i:08x}") for i in range(n)]
    anchors = [_pair_anchor(diff_id, f"{0x1000 + i:08x}", f"{0x9000 + i:08x}") for i in range(n)]
    return mcp_app.make_tools(world.path), anchors


def _overlay_rows(world: World) -> int:
    return world.atlas.execute(
        "SELECT COUNT(*) FROM overlay WHERE anchor_kind = 'diff_subject'"
    ).fetchone()[0]


def test_batch_writes_every_valid_entry_and_echoes_compactly(world: World) -> None:
    tools, anchors = _batch_world(world, 50)
    items = [
        {"anchor_ref": a, "verdict": "changed_real", "rationale": "it does X"} for a in anchors
    ]
    out = tools["annotate_diff_batch"](items, diff_id=DX)
    assert out["written"] is True and out["count"] == 50
    assert {r["index"] for r in out["results"]} == set(range(50))
    assert all(r["action"] == "inserted" for r in out["results"])
    assert _overlay_rows(world) == 50
    # each plain result is small (no verdict / id echoed back)
    assert all(len(json.dumps(r)) <= 160 for r in out["results"])
    assert len(json.dumps(out)) <= mcp_app._RESPONSE_BYTE_BUDGET


def test_batch_all_or_none_one_bad_item_writes_nothing(world: World) -> None:
    """K6: a single invalid item (a candidate verdict on a diff entry) makes the whole batch a
    no-op, and the failures are returned once.

    MUTATION (verified RED): write as each item validates (per-item commit) -> the valid ones
    persist and the batch is no longer all-or-none."""
    tools, anchors = _batch_world(world, 20)
    items = [{"anchor_ref": a, "verdict": "changed_real", "rationale": "x"} for a in anchors]
    items[7] = {
        "anchor_ref": anchors[7],
        "verdict": "suspicious",
        "rationale": "x",
    }  # candidate verdict
    out = tools["annotate_diff_batch"](items, diff_id=DX)
    assert out["written"] is False and out["count"] == 0
    assert any(7 in e["indexes"] for e in out["errors"])
    assert _overlay_rows(world) == 0


def test_batch_equals_per_entry_field_for_field(world: World) -> None:
    """K5: a row written by the batch is identical to one the single annotate_diff writes for the
    same anchor and inputs — verdict, rationale, attribution, basis_state, verdict_basis."""
    tools, anchors = _batch_world(world, 1)
    anchor = anchors[0]
    cols = "verdict, rationale, attributed_to, basis_state, verdict_basis, promoted_from, run_id"

    def row() -> tuple[Any, ...]:
        return world.atlas.execute(
            f"SELECT {cols} FROM overlay WHERE anchor_ref = ?",
            (anchor,),  # noqa: S608
        ).fetchone()

    tools["annotate_diff_batch"](
        [
            {
                "anchor_ref": anchor,
                "verdict": "no_real_change",
                "why_unchanged": "renamed only",
                "checked": [anchor, "a note"],
            }
        ],
        diff_id=DX,
    )
    batched = tuple(row())
    tools["clear_overlay"](anchor_kind="diff_subject", anchor_ref=anchor)
    tools["annotate_diff"](
        anchor,
        "no_real_change",
        None,
        checked=[anchor, "a note"],
        why_unchanged="renamed only",
        diff_id=DX,
    )
    assert tuple(row()) == batched


def test_batch_duplicate_anchor_refuses_the_whole_batch(world: World) -> None:
    """D-T3-2: the same anchor_ref twice -> integer indexes in one error, nothing written.

    MUTATION (verified RED): let the second write win instead of refusing -> a row is written."""
    tools, anchors = _batch_world(world, 3)
    items = [{"anchor_ref": a, "verdict": "changed_real", "rationale": "x"} for a in anchors]
    items.append({"anchor_ref": anchors[0], "verdict": "changed_real", "rationale": "y"})
    out = tools["annotate_diff_batch"](items, diff_id=DX)
    assert out["written"] is False
    dup = next(e for e in out["errors"] if sorted(e["indexes"]) == [0, 3])
    assert anchors[0] in dup["error"]
    assert _overlay_rows(world) == 0


def test_batch_rejects_over_two_hundred(world: World) -> None:
    tools, anchors = _batch_world(world, 1)
    item = {"anchor_ref": anchors[0], "verdict": "changed_real", "rationale": "x"}
    assert tools["annotate_diff_batch"]([item] * 201, diff_id=DX)["written"] is False
    assert tools["annotate_diff_batch"]([], diff_id=DX)["written"] is False


def test_batch_checked_needs_a_resolving_anchor_and_names_a_fake_one(world: World) -> None:
    """M-1: checked needs one anchor that resolves; a plain-text-only checked is refused with
    the rule, and an item that LOOKS like an anchor but names nothing is refused by position.

    MUTATION (verified RED): count plain text as a hit -> plain-text-only is wrongly accepted;
    pass a looks-like-but-unresolved anchor as plain text -> the fake one is wrongly accepted."""
    tools, anchors = _batch_world(world, 2)
    ok = {
        "anchor_ref": anchors[0],
        "verdict": "no_real_change",
        "why_unchanged": "w",
        "checked": [anchors[0], "a plain note"],
    }
    assert tools["annotate_diff_batch"]([ok], diff_id=DX)["written"] is True
    tools["clear_overlay"](anchor_kind="diff_subject", anchor_ref=anchors[0])

    plain = {
        "anchor_ref": anchors[0],
        "verdict": "no_real_change",
        "why_unchanged": "w",
        "checked": ["just a note", "another note"],
    }
    out = tools["annotate_diff_batch"]([plain], diff_id=DX)
    assert out["written"] is False
    assert "at least one anchor" in out["errors"][0]["error"]

    fake = _pair_anchor(DX, "deadbeef", "cafebabe")  # anchor-shaped, not in the view
    item = {
        "anchor_ref": anchors[0],
        "verdict": "no_real_change",
        "why_unchanged": "w",
        "checked": [anchors[0], fake],
    }
    out = tools["annotate_diff_batch"]([item], diff_id=DX)
    assert out["written"] is False
    assert (
        "looks like" in out["errors"][0]["error"] and "names nothing" in out["errors"][0]["error"]
    )
    assert _overlay_rows(world) == 0


def test_batch_rationale_is_optional_for_no_real_change(world: World) -> None:
    """K2: no_real_change with only why_unchanged writes, and rationale is that why_unchanged;
    changed_real with no rationale is refused."""
    tools, anchors = _batch_world(world, 2)
    out = tools["annotate_diff_batch"](
        [
            {
                "anchor_ref": anchors[0],
                "verdict": "no_real_change",
                "why_unchanged": "same call, renamed",
                "checked": [anchors[0]],
            }
        ],
        diff_id=DX,
    )
    assert out["written"] is True
    stored = world.atlas.execute(
        "SELECT rationale FROM overlay WHERE anchor_ref = ?", (anchors[0],)
    ).fetchone()[0]
    assert stored == "same call, renamed"
    out = tools["annotate_diff_batch"](
        [{"anchor_ref": anchors[1], "verdict": "changed_real"}], diff_id=DX
    )
    assert out["written"] is False and "rationale is required" in out["errors"][0]["error"]


def test_batch_changed_real_evidence_is_recorded_and_echoed(world: World) -> None:
    """changed_real may carry evidence (same anchor rule as checked); P-7: it may carry ONLY
    evidence, not checked / why_unchanged."""
    tools, anchors = _batch_world(world, 2)
    out = tools["annotate_diff_batch"](
        [
            {
                "anchor_ref": anchors[0],
                "verdict": "changed_real",
                "rationale": "adds a system call",
                "evidence": [anchors[0]],
            }
        ],
        diff_id=DX,
    )
    assert out["written"] is True
    stored = json.loads(
        world.atlas.execute(
            "SELECT verdict_basis FROM overlay WHERE anchor_ref = ?", (anchors[0],)
        ).fetchone()[0]
    )
    assert stored == {"kind": "changed_real", "evidence": [anchors[0]]}
    # K4: evidence does not move basis_state / review_state vs the same verdict without it
    without = _pair_anchor(DX, f"{0x1000 + 1:08x}", f"{0x9000 + 1:08x}")
    tools["annotate_diff_batch"](
        [{"anchor_ref": without, "verdict": "changed_real", "rationale": "adds a system call"}],
        diff_id=DX,
    )

    def basis_and_state(a: str) -> tuple[str, str]:
        row = overlay.list_overlays(world.atlas, anchor_kind="diff_subject")["overlays"]
        one = next(o for o in row if o["anchor_ref"] == a)
        return one["basis_state"], one["review_state"]

    assert basis_and_state(anchors[0]) == basis_and_state(without)
    bad = tools["annotate_diff_batch"](
        [
            {
                "anchor_ref": anchors[1],
                "verdict": "changed_real",
                "rationale": "x",
                "checked": [anchors[1]],
            }
        ],
        diff_id=DX,
    )
    assert bad["written"] is False and "evidence only" in bad["errors"][0]["error"]


_WORDS = {"removed", "added", "gone", "new", "bounded", "safe", "fix", "patch", "regression"}
_LABEL = re.compile(r"[a-z][a-z0-9_]*")


def _labels(value: Any, out: set[str]) -> set[str]:
    """Every key in ``value``, at any depth, and every string value shaped like a label."""
    if isinstance(value, dict):
        for k, v in value.items():
            out.add(str(k))
            _labels(v, out)
    elif isinstance(value, list):
        for v in value:
            _labels(v, out)
    elif isinstance(value, str) and _LABEL.fullmatch(value):
        out.add(value)
    return out


def test_no_batch_or_evidence_label_says_what_a_change_means(world: World) -> None:
    """Every key and label value the batch write returns — written, refused, a duplicate anchor —
    the single write's evidence echo, and the stored basis of each verdict are free of words that
    say what a change means.

    MUTATION (verified RED, 5 failed — this test and four that pin the action's value): name a
    batch result's action 'added' -> RED."""
    tools, anchors = _batch_world(world, 4)
    batch = tools["annotate_diff_batch"]
    wrote = batch(
        [
            {"anchor_ref": anchors[0], "verdict": "changed_real", "rationale": "x"},
            {
                "anchor_ref": anchors[1],
                "verdict": "changed_real",
                "rationale": "x",
                "evidence": [anchors[1]],
            },
            {"anchor_ref": anchors[2], "verdict": "no_real_change", **_nrc(anchors[2])},
        ],
        diff_id=DX,
    )
    assert wrote["written"] is True
    again = batch(
        [{"anchor_ref": anchors[0], "verdict": "changed_real", "rationale": "y"}], diff_id=DX
    )
    refused = batch(
        [
            {"anchor_ref": anchors[3], "verdict": "suspicious", "rationale": "x"},
            {"anchor_ref": anchors[3], "verdict": "changed_real", "rationale": "x"},
        ],
        diff_id=DX,
    )
    assert refused["written"] is False
    plain = batch([{"anchor_ref": anchors[3], "verdict": "changed_real"}], diff_id=DX)
    single = tools["annotate_diff"](
        anchors[3], "changed_real", "x", diff_id=DX, evidence=[anchors[3]]
    )
    assert "error" not in single, single
    labels: set[str] = set()
    for out in (wrote, again, refused, plain, single):
        _labels(out, labels)
    for (basis,) in world.atlas.execute(
        "SELECT verdict_basis FROM overlay WHERE anchor_kind = 'diff_subject' "
        "AND verdict_basis IS NOT NULL"
    ):
        _labels(json.loads(basis), labels)
    assert {"written", "results", "action", "inserted", "updated", "errors", "indexes"} <= labels
    assert {"evidence", "kind", "checked", "why_unchanged"} <= labels
    for label in labels:
        words = set(re.split(r"[^a-z0-9]+", label.lower()))
        assert not words & _WORDS, label


def test_batch_unknown_key_and_missing_fields_fail_that_item(world: World) -> None:
    """q-5 / P-4: an unknown key fails that item (named); a missing anchor_ref / verdict fails it.
    The framework rejects a non-dict item before the function runs (tested via call_tool elsewhere).

    MUTATION (verified RED): accept unknown keys silently -> the stray-key item is wrongly kept."""
    tools, anchors = _batch_world(world, 2)
    items = [
        {"anchor_ref": anchors[0], "verdict": "changed_real", "rationale": "x", "evidences": ["y"]},
        {"verdict": "changed_real", "rationale": "x"},
        {"anchor_ref": anchors[1], "rationale": "x"},
    ]
    out = tools["annotate_diff_batch"](items, diff_id=DX)
    assert out["written"] is False and _overlay_rows(world) == 0
    joined = json.dumps(out["errors"])
    assert (
        "evidences" in joined
        and "anchor_ref is required" in joined
        and "verdict is required" in joined
    )


def test_batch_failures_merge_by_message_within_budget(world: World) -> None:
    """P-3 + Q-1: 200 same-cause failures come back as one {error, indexes[200]} under budget —
    both a shared-text cause (plain-text checked) and a per-anchor one (the annotation anchor names
    nothing), the latter only after its own anchor is placeholdered before merging.

    MUTATION (verified RED): echo one error per item with its anchor_ref -> over budget; or do not
    placeholder the item's own anchor before merging -> the names-nothing case stays 200 apart."""
    tools, anchors = _batch_world(world, 200)
    plain = [
        {
            "anchor_ref": a,
            "verdict": "no_real_change",
            "why_unchanged": "w",
            "checked": ["a note", "b note"],
        }
        for a in anchors
    ]
    out = tools["annotate_diff_batch"](plain, diff_id=DX)
    assert (
        out["written"] is False
        and len(out["errors"]) == 1
        and len(out["errors"][0]["indexes"]) == 200
    )
    assert len(json.dumps(out)) <= mcp_app._RESPONSE_BYTE_BUDGET

    # W3: the annotation's own anchor names nothing in the view (each error embeds that anchor)
    missing = [
        {
            "anchor_ref": _pair_anchor(DX, f"{0xBEEF0 + i:08x}", f"{0xCAFE0 + i:08x}"),
            "verdict": "changed_real",
            "rationale": "x",
        }
        for i in range(200)
    ]
    out = tools["annotate_diff_batch"](missing, diff_id=DX)
    assert (
        out["written"] is False
        and len(out["errors"]) == 1
        and len(out["errors"][0]["indexes"]) == 200
    )
    assert len(json.dumps(out)) <= mcp_app._RESPONSE_BYTE_BUDGET


def test_checked_rule_is_one_shared_constant(world: World) -> None:
    """P-2 / q-3: the view's per-page hint, the write-time refusal, and the MCP docstring all carry
    the one CHECKED_RULE — no copy that could drift to the old "two or more" wording.

    MUTATION (verified RED): leave the annotation block's no_real_change_needs written as the old
    literal -> the ``endswith`` / no-"two or more" assertion fails."""
    tools, anchors = _batch_world(world, 1)
    block = world.view()["annotation"]["no_real_change_needs"]
    assert block.endswith(dr.CHECKED_RULE)
    assert "two or more" not in block
    assert "at least one anchor" in block

    built = dann._built(world.atlas, DX)
    meta = dann._binary_diff(world.atlas, DX)
    from treasure_map.lib.query.same_shape_siblings import _meta as _side_meta

    with pytest.raises(ConfigError) as exc:
        dann.require_checked_anchor(
            world.atlas, built, meta, _side_meta(world.atlas, DX), ["just a plain note"], "checked"
        )
    assert str(exc.value) == dr.CHECKED_RULE  # the same constant, not a paraphrase

    doc = " ".join(mcp_app.make_tools(world.path)["annotate_diff"].__doc__.split())
    assert " ".join(dr.CHECKED_RULE.split()) in doc  # copied verbatim into the docstring (q-3)


def test_batch_rejects_a_non_object_item_without_writing(world: World) -> None:
    """P-4: a non-object annotation item is rejected by the framework before the tool runs, so the
    all-or-none guarantee holds — nothing is written, and the tool body never executes."""
    import asyncio

    tools, anchors = _batch_world(world, 1)
    server = mcp_app.build_server(world.path)
    ok = {"anchor_ref": anchors[0], "verdict": "changed_real", "rationale": "x"}

    async def _call() -> Any:
        return await server.call_tool(
            "annotate_diff_batch", {"diff_id": DX, "annotations": [ok, 5]}
        )

    with pytest.raises(Exception):  # noqa: B017 -- FastMCP raises ToolError on a bad item type
        asyncio.run(_call())
    assert _overlay_rows(world) == 0

    # a JSON string of valid objects is parsed by the framework and written
    import json as _json

    res = asyncio.run(
        server.call_tool("annotate_diff_batch", {"diff_id": DX, "annotations": _json.dumps([ok])})
    )
    assert _overlay_rows(world) == 1, res


# ── checked: every anchor kind resolves on its own; a wrong-run anchor is refused ─────────────


def _checked_kinds() -> dict[str, tuple[str, str]]:
    """One item per anchor kind (the group_ref kind is in test_diff_group_freshness, which has a
    group), each naming something in ``_batch_world(world, 2)`` + one unpaired function, and the
    kind ``is_diff_anchor`` must read it as. None of them is the judged entry's own anchor."""
    return {
        "function_pair": (_pair_anchor(DX, "00001001", "00009001"), "function_pair"),
        "function_presence": (f"{PAIR}#function_presence#libx::b:0000f000", "function_presence"),
        "candidate": (
            dr.candidate_anchor("runA", "runB", f"callsite|cmd|{_ref('runA', '00001001')}|(none)"),
            "candidate",
        ),
        "entry_id": ("pair:00001001:00009001", "entry_id"),
        "row_ref": (_ref("runA", "00001001"), "row_ref"),
    }


@pytest.mark.parametrize("kind", sorted(_checked_kinds()))
def test_each_anchor_kind_alone_satisfies_checked(world: World, kind: str) -> None:
    """Every anchor kind the rule names counts on its own — no other anchor in ``checked``, only a
    plain note beside it (which does not count) — and is read as exactly that kind.

    MUTATIONS (verified RED, one per kind): an entry_id never resolves in ``is_diff_anchor``; a
    row_ref never resolves; a candidate anchor is not counted; a function_presence anchor is not
    counted -> that kind's item falls to the "looks like an anchor but names nothing" refusal."""
    tools, anchors = _batch_world(world, 2)
    world.unpaired(DX, "b", "0000f000", "unmatched_analysis_complete")
    item, expected = _checked_kinds()[kind]

    out = tools["annotate_diff_batch"](
        [
            {
                "anchor_ref": anchors[0],
                "verdict": "no_real_change",
                "why_unchanged": "w",
                "checked": [item, "a plain note"],
            }
        ],
        diff_id=DX,
    )
    assert out["written"] is True, out
    stored = json.loads(
        world.atlas.execute(
            "SELECT verdict_basis FROM overlay WHERE anchor_ref = ?", (anchors[0],)
        ).fetchone()[0]
    )
    assert stored["checked"] == [item, "a plain note"]

    built = dann._built(world.atlas, DX)
    meta = dann._binary_diff(world.atlas, DX)
    from treasure_map.lib.query.same_shape_siblings import _meta as _side_meta

    side_meta = _side_meta(world.atlas, DX)
    assert dann.is_diff_anchor(world.atlas, built, meta, side_meta, item) == expected


def test_checked_refuses_an_anchor_of_another_run_pair_by_position(world: World) -> None:
    """An anchor of ANOTHER run pair still looks like an anchor, so it must resolve here — it is
    refused and named by its position, not kept as a plain note (even beside one that resolves).

    MUTATION (verified RED): only treat this diff's own run pair as anchor-shaped -> the wrong-run
    anchor passes as plain text and the batch writes."""
    tools, anchors = _batch_world(world, 1)
    wrong_run = anchors[0].replace(f"{PAIR}#", "runX::runY#", 1)
    assert wrong_run != anchors[0]
    item = {
        "anchor_ref": anchors[0],
        "verdict": "no_real_change",
        "why_unchanged": "w",
        "checked": [anchors[0], "a plain note", wrong_run],
    }
    out = tools["annotate_diff_batch"]([item], diff_id=DX)
    assert out["written"] is False
    (err,) = out["errors"]
    assert err["indexes"] == [0]
    assert "checked[2]" in err["error"] and "anchor_ref anchor" in err["error"]
    assert "names nothing" in err["error"]
    single = tools["annotate_diff"](
        anchors[0], "no_real_change", checked=item["checked"], why_unchanged="w", diff_id=DX
    )
    assert single["written"] is False and "checked[2]" in single["error"]
    assert _overlay_rows(world) == 0


# ── evidence on the other verdicts; rationale on change_inconclusive; a candidate verdict ──────


@pytest.mark.parametrize("verdict", ["no_real_change", "change_inconclusive"])
def test_evidence_on_any_verdict_but_changed_real_is_refused(world: World, verdict: str) -> None:
    """``evidence`` belongs to changed_real only; on the other two verdicts it is refused with that
    message — never silently dropped while the rest of the item is written.

    MUTATION (verified RED): drop ``evidence`` from the basis of the other verdicts instead of
    refusing it -> no_real_change writes (evidence lost), change_inconclusive fails with another
    message."""
    tools, anchors = _batch_world(world, 1)
    item: dict[str, Any] = {
        "anchor_ref": anchors[0],
        "verdict": verdict,
        "rationale": "looked",
        "evidence": [anchors[0]],
    }
    if verdict == "no_real_change":
        item.update(checked=[anchors[0]], why_unchanged="w")
    out = tools["annotate_diff_batch"]([item], diff_id=DX)
    assert out["written"] is False, out
    assert out["errors"][0]["error"] == "evidence applies to changed_real only"
    single = tools["annotate_diff"](
        **{k: v for k, v in item.items() if k != "anchor_ref"}, anchor_ref=anchors[0], diff_id=DX
    )
    assert single["written"] is False and single["error"] == "evidence applies to changed_real only"
    assert _overlay_rows(world) == 0


def test_change_inconclusive_without_a_rationale_is_refused(world: World) -> None:
    """Only no_real_change may default its rationale (to why_unchanged); change_inconclusive owes
    one — its rationale is where the next step goes.

    MUTATION (verified RED): let change_inconclusive fall back to why_unchanged as no_real_change
    does -> the refusal no longer names the missing rationale."""
    tools, anchors = _batch_world(world, 1)
    out = tools["annotate_diff_batch"](
        [{"anchor_ref": anchors[0], "verdict": "change_inconclusive"}], diff_id=DX
    )
    assert out["written"] is False
    assert "rationale is required for change_inconclusive" in out["errors"][0]["error"]
    single = tools["annotate_diff"](anchors[0], "change_inconclusive", diff_id=DX)
    assert single["written"] is False
    assert "rationale is required for change_inconclusive" in single["error"]
    assert _overlay_rows(world) == 0


def test_a_candidate_verdict_without_a_rationale_names_the_right_tool(world: World) -> None:
    """A candidate verdict on a diff entry is refused for what it is (annotate / promote is the
    tool for it), even when the rationale is missing too — not with "rationale is required".

    MUTATION (verified RED): resolve the rationale before the verdict is known to be a diff verdict
    -> the refusal reads "rationale is required for suspicious"."""
    tools, anchors = _batch_world(world, 1)
    out = tools["annotate_diff_batch"](
        [{"anchor_ref": anchors[0], "verdict": "suspicious"}], diff_id=DX
    )
    assert out["written"] is False
    assert "candidate verdict" in out["errors"][0]["error"]
    single = tools["annotate_diff"](anchors[0], "suspicious", diff_id=DX)
    assert single["written"] is False and "candidate verdict" in single["error"]
    assert _overlay_rows(world) == 0


# ── field types: a wrong type fails that item, listed with the rest, never a raw exception ─────


@pytest.mark.parametrize("bad", [5, ["a", "b"], {"group_ref": "x"}])
def test_a_non_string_group_ref_fails_that_item(world: World, bad: Any) -> None:
    """A group_ref that is not a string fails that one item with a named error, listed beside the
    other items' errors — the batch neither raises nor writes.

    MUTATION (verified RED): drop the type check -> ``_parse_ref`` calls ``.partition`` on it and
    the tool raises AttributeError."""
    tools, anchors = _batch_world(world, 2)
    items = [
        {"anchor_ref": anchors[0], "verdict": "changed_real", "rationale": "x", "group_ref": bad},
        {"anchor_ref": anchors[1], "rationale": "x"},  # missing verdict
    ]
    out = tools["annotate_diff_batch"](items, diff_id=DX)
    assert out["written"] is False
    by_index = {i: e["error"] for e in out["errors"] for i in e["indexes"]}
    assert set(by_index) == {0, 1}
    assert "group_ref must be a string" in by_index[0]
    assert by_index[1] == "verdict is required"
    assert _overlay_rows(world) == 0


# ── all or none when a write itself fails (stage two) ─────────────────────────────────────────


@pytest.mark.parametrize("fail_at", [2, 4])
def test_a_write_failing_mid_batch_leaves_nothing_written(
    world: World, monkeypatch: pytest.MonkeyPatch, fail_at: int
) -> None:
    """Every item validated, then the k-th write raises: the batch reports it and NOTHING it wrote
    persists — the writes before k are rolled back, and a judgement it was overwriting is intact.

    MUTATIONS (verified RED): commit after each write -> the writes before k persist and the prior
    judgement is overwritten; open the batch's connection in autocommit mode -> the same."""
    tools, anchors = _batch_world(world, 5)
    before = tools["annotate_diff"](anchors[0], "changed_real", "before the batch", diff_id=DX)
    assert before["written"] is True
    real = overlay.write_prepared
    calls = {"n": 0}

    def flaky(atlas: sqlite3.Connection, p: overlay.PreparedDiffWrite) -> overlay.UpsertResult:
        calls["n"] += 1
        if calls["n"] == fail_at + 1:
            raise sqlite3.OperationalError("disk I/O error (injected)")
        return real(atlas, p)

    monkeypatch.setattr(overlay, "write_prepared", flaky)
    items = [
        {"anchor_ref": a, "verdict": "change_inconclusive", "rationale": "in the batch"}
        for a in anchors
    ]
    out = tools["annotate_diff_batch"](items, diff_id=DX)
    assert calls["n"] == fail_at + 1  # the injection fired, at the k-th write
    assert out["written"] is False and out["count"] == 0
    assert "nothing was written" in out["errors"][0]["error"]
    rows = world.atlas.execute(
        "SELECT anchor_ref, verdict, rationale FROM overlay WHERE anchor_kind = 'diff_subject'"
    ).fetchall()
    assert [tuple(r) for r in rows] == [(anchors[0], "changed_real", "before the batch")]
