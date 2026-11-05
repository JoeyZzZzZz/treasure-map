# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A formal anchor minted for an out-of-body call, read through the two surfaces that are not the
overlay's annotate: promoting a diff finding onto it, and the CLI's explain view.

Zero real data: the rows come from the real hunt (minting included) run on a synthetic bridged
database — Inl (entry 0x401000) and Late (entry 0x405000) both reach the call at 0x409020 outside
their bodies; Inl's row is minted the call's formal anchor, Late's stays the bare,
function-level claimant.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from tests.unit.lib.test_analyzer2 import _bridged, _make_db, _rows_for
from tests.unit.lib.test_diff_review import (  # noqa: F401 — the autouse cache fixture
    DX,
    World,
    _clear_view_caches,
    _promote,
    _row,
    world,
)
from treasure_map.cli.hunt_cli import triage as triage_cmd
from treasure_map.lib.errors import ConfigError
from treasure_map.lib.hunt.analyzer2 import run_analyzer2
from treasure_map.lib.query import sink_overlay as so

_RUN = "runA"


def _hunt(tmp: Path) -> tuple[Path, tuple[str, dict[str, object]], tuple[str, dict[str, object]]]:
    """The real hunt on the Inl/Late fixture as run ``runA``: its atlas, the minted row, the bare
    claimant's row (each ``(evidence_ref, flow_evidence)``)."""
    h = tmp / "hunt"
    h.mkdir()
    inl_pc = "void Inl(char *a,char *b,int n) {\n  memcpy(a,b,4);\n  memcpy(a,b,n);\n}\n"
    inl = _bridged(
        "Inl", 0x401000, inl_pc, ["memcpy"],
        body=(0x401000, 0x401100), addr_of={"memcpy": [0x409010, 0x409020]},
    )  # fmt: skip
    late = _bridged(
        "Late", 0x405000, "void Late(char *a,char *b) {\n  memcpy(a,b,8);\n}\n", ["memcpy"],
        body=(0x405000, 0x405100), addr_of={"memcpy": [0x409020]},
    )  # fmt: skip
    db = _make_db(h, [{"name": "httpd", "funcs": [inl, late]}])
    atlas = h / "atlas.db"
    run_analyzer2(db, atlas, source_run_id=_RUN)
    by_addr = {ev["callsite_addr"]: (ref, ev) for ref, ev in _rows_for(atlas, "Inl")}
    ((late_ref, late_ev),) = _rows_for(atlas, "Late")
    minted_ref, minted_ev = by_addr["0x409020"]
    # premises: the minted call has its own offset ref, the claimant left bare has none (what the
    # evidence says of each is what the tests below read through the surface they test)
    assert minted_ref.endswith("00401000@copy@0x008020"), minted_ref
    assert late_ref.endswith("00405000@copy"), late_ref
    return atlas, (minted_ref, minted_ev), (late_ref, late_ev)


def _put(w: World, ref: str, ev: dict[str, object]) -> None:
    """One candidate of run ``runA`` in the diff world's atlas, with the hunt's own evidence."""
    pid = w.atlas.execute(
        "INSERT INTO pattern (source_class, sink_class, call_sequence_shape, "
        "structural_fingerprint, fingerprint_algo_version) "
        "VALUES ('external_input', 'copy', 's->copy', ?, 'v1')",
        (f"fp_{ref}",),
    ).lastrowid
    w.atlas.execute(
        "INSERT INTO instance (pattern_id, evidence_ref, source_run_id, pseudocode_hash, "
        "flow_evidence) VALUES (?, ?, ?, 'h1', ?)",
        (pid, ref, _RUN, json.dumps(ev, sort_keys=True)),
    )
    w.atlas.commit()


def _a_row(ref: str) -> so.SinkOverlayRow:
    """A row that lands A: the matched call now calls another callee."""
    return _row(
        ref, None, reason="present_different_callee", call="present_different_callee",
        elsewhere=False, cls="copy",
    )  # fmt: skip


def test_promote_onto_a_minted_anchor_succeeds_and_a_bare_claimant_is_refused(
    world: World,  # noqa: F811 — the fixture
    tmp_path: Path,
) -> None:
    """H-5. promote(row_ref=<minted anchor>) passes the same degraded-anchor gate annotate does,
    with the flow_evidence the hunt really writes; the bare claimant of the same call is refused.

    MUTATION (verified RED, 1 failed): mint the ref without rewriting flow_evidence (the UPDATE
    sets evidence_ref only) -> the promote onto the minted anchor is refused as a degraded
    anchor."""
    _atlas, (minted_ref, minted_ev), (late_ref, late_ev) = _hunt(tmp_path)
    minted_ref = f"{_RUN}#" + minted_ref.split("#", 1)[1]
    late_ref = f"{_RUN}#" + late_ref.split("#", 1)[1]
    _put(world, minted_ref, minted_ev)
    _put(world, late_ref, late_ev)
    world.pair(DX, "00401000", "00402000")
    world.pair(DX, "00405000", "00406000")
    world.rows[DX] = [_a_row(minted_ref), _a_row(late_ref)]
    assert world.entry("pair:00401000:00402000")["rows"][0]["landing"] == "A"

    try:
        res = _promote(world, "pair:00401000:00402000", minted_ref)
    except ConfigError as exc:
        pytest.fail(f"the promote onto the minted anchor was refused: {exc}")
    assert res.written.action == "inserted"
    with pytest.raises(ConfigError, match="degraded anchor"):
        _promote(world, "pair:00405000:00406000", late_ref)


def _explain(atlas: Path, ref: str) -> str:
    result = CliRunner().invoke(triage_cmd, [_RUN, "--explain", ref, "--atlas", str(atlas)])
    assert result.exit_code == 0, result.output
    return result.output


def test_the_cli_explain_labels_a_minted_anchor_formal_and_a_bare_claimant_degraded(
    tmp_path: Path,
) -> None:
    """H-5. The CLI explain view names the anchor's standing: the minted anchor (callsite located,
    evidence still saying the call lies out of body) reads ``formal``, the bare claimant reads
    ``degraded``; each line carries its own note.

    MUTATION (verified RED, 1 failed): print the anchor line only under
    ``callsite_located is False`` (the label back to degraded-only) -> the minted anchor's line is
    gone."""
    atlas, (minted_ref, minted_ev), (late_ref, late_ev) = _hunt(tmp_path)
    assert minted_ev.get("callsite_located") is True  # premise: the hunt located the minted call
    assert late_ev.get("callsite_located") is False  # premise: the claimant stays function-level
    minted_out = _explain(atlas, minted_ref)
    assert "  anchor       = formal (out_of_body): " in minted_out, minted_out
    assert "formal anchor" in minted_out
    assert "= degraded (" not in minted_out
    late_out = _explain(atlas, late_ref)
    assert "  anchor       = degraded (out_of_body): " in late_out, late_out
    assert "= formal (" not in late_out
