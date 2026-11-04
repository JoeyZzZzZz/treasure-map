# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""R9: the read-face signals a diff judgement leans on are part of its facts (entry_facts) —
pair_evidence, counterpart_hint, the per-sink call-count delta, listed_as and the subclass — read
on the write and on the re-check alike; a snapshot is compared on the keys it holds; the
predicate version is no fact of a judgement.

Zero real data: the pair-evidence World of test_pair_evidence, and the World of test_diff_review
for bucket S."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib import test_diff_review as tdr
from tests.unit.lib.test_pair_evidence import (  # noqa: F401 — the autouse fixture
    CONFLICT,
    NEG,
    _evidence_world,
    _fresh,
)
from tests.unit.lib.test_patch_view import DIFF, _pair_id
from treasure_map.lib import overlay
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query import review_units as ru


def _anchor_of(atlas: Any, diff_id: str, entry_id: str) -> str:
    page = pv.get_diff_patch_view(atlas, diff_id, entry_id=entry_id)
    return str(page["entries"][0]["anchor_ref"])


def _states(atlas: Any, diff_id: str) -> dict[str, str]:
    built = pv.build_diff_view(atlas, diff_id)
    assert built is not None
    review = pv.ViewReview(atlas, built)
    return {a: j.state for a, j in review.judged.items()}


def test_a_change_in_one_entrys_pair_evidence_re_checks_its_judgement_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ Two R entries judged; the pair evidence of one of them reads otherwise now: only that
    judgement reads needs_recheck, the other stays as it was.

    MUTATION (verified RED): leave pair_evidence / counterpart_hint out of entry_facts -> the
    moved one reads concluded -> RED; do not attach the evidence on the write path -> the stored
    facts hold None and every judgement moves -> RED."""
    w = _evidence_world(tmp_path)
    anchors = {}
    for pair in (CONFLICT, NEG):
        anchor = _anchor_of(w.atlas, DIFF, _pair_id(*pair))
        overlay.annotate_diff(
            w.atlas, anchor_ref=anchor, verdict="changed_real", rationale="r", diff_id=DIFF
        )
        anchors[pair] = anchor
    pv._clear_view_caches()
    assert set(_states(w.atlas, DIFF).values()) == {"concluded"}
    real = pv._PairEvidence.of

    def moved(self: Any, p: Any) -> Any:
        evidence, hint = real(self, p)
        if (p.addr_a, p.addr_b) == CONFLICT:
            return {**evidence, "state": "negated"}, hint
        return evidence, hint

    monkeypatch.setattr(pv._PairEvidence, "of", moved)
    pv._clear_view_caches()
    states = _states(w.atlas, DIFF)
    assert states[anchors[CONFLICT]] == "needs_recheck"
    assert states[anchors[NEG]] == "concluded"


def test_an_s_entry_that_stops_differing_re_checks_its_judgement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ An aligned similarity-1 pair is listed as S while its pseudocode differs; judged there,
    then read identical (no longer listed): its judgement reads needs_recheck — the bucket alone
    (empty for S) would never show it.

    MUTATION (verified RED): leave listed_as out of entry_facts -> it reads concluded -> RED."""
    w = tdr.World(tmp_path, monkeypatch)
    w.pair(tdr.DX, "00001000", "00001000", sim=1.0)
    pair = ("00001000", "00001000")
    monkeypatch.setattr(pv, "_differs_of", lambda readings, built: frozenset({pair}))
    page = pv.get_diff_patch_view(w.atlas, tdr.DX)
    (entry,) = page["entries"]
    assert entry["bucket"] == "S"
    w.judge(tdr.DX, entry["anchor_ref"], "changed_real")
    pv._clear_view_caches()
    assert _states(w.atlas, tdr.DX)[entry["anchor_ref"]] == "concluded"
    monkeypatch.setattr(pv, "_differs_of", lambda readings, built: frozenset())
    pv._clear_view_caches()
    assert _states(w.atlas, tdr.DX)[entry["anchor_ref"]] == "needs_recheck"
    built = pv.build_diff_view(w.atlas, tdr.DX)
    assert built is not None
    moved = pv.ViewReview(w.atlas, built).judged[entry["anchor_ref"]].moved
    assert moved.get("listed_as") == ["S", None]


def test_a_snapshot_is_compared_on_its_own_keys_and_the_predicate_is_no_fact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A judgement stored before the new facts existed (its snapshot lacks them) still reads
    concluded; bumping the must-read predicate version moves no judgement.

    MUTATION (verified RED): compare every key of both snapshots -> the old one reads
    needs_recheck -> RED."""
    w = tdr.World(tmp_path, monkeypatch)
    w.pair(tdr.DX, "00001000", "00001000")
    w.rows[tdr.DX] = [tdr.a_row("00001000")]
    anchor = tdr._pair_anchor(tdr.DX, "00001000", "00001000")
    w.judge(tdr.DX, anchor, "changed_real")
    raw = w.atlas.execute("SELECT basis_state FROM overlay WHERE anchor_ref = ?", (anchor,))
    snap = json.loads(raw.fetchone()[0])
    for key in (
        "listed_as",
        "subclass",
        "pair_evidence",
        "counterpart_hint",
        "sink_callsite_delta",
    ):
        assert key in snap["facts"], key
        del snap["facts"][key]
    w.atlas.execute(
        "UPDATE overlay SET basis_state = ? WHERE anchor_ref = ?", (json.dumps(snap), anchor)
    )
    w.atlas.commit()
    pv._clear_view_caches()
    assert _states(w.atlas, tdr.DX)[anchor] == "concluded"
    monkeypatch.setattr(ru, "PREDICATE_VERSION", "v-next")
    pv._clear_view_caches()
    assert _states(w.atlas, tdr.DX)[anchor] == "concluded"
