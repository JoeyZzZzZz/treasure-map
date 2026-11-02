# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""D29: what each function's decompile came to is a recorded fact (ok / timeout / error /
skipped_micro, an error's message beside it in decompile_error), stored by the ingest, and read by
the diff view: a side whose decompile did not complete reads its sink candidate counts as unknown —
its candidates, which the hunt reads from the pseudocode, are missing, not 0 — and the entry names
that side.

Zero real data: a hand-written extractor output for the ingest, and test_patch_view's world.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.unit.lib.test_diff_read_signals import _cmd, _rows
from tests.unit.lib.test_patch_view import World, _overlay_row, _pair_id, _view
from treasure_map.lib.analyze.elf_inventory import ElfRecord
from treasure_map.lib.analyze.ghidra_ingest import ingest_ghidra_output
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.storage.connection import open_db

# ── the ingest stores the outcome ─────────────────────────────────────────────────────────────


def test_each_functions_decompile_outcome_is_stored(tmp_path: Path) -> None:
    """★ ok / timeout (retried) / error / skipped_micro are stored as written, and an error's
    message goes to decompile_error — the status stays one of four values a reader can group by.
    An export written before the split (``error:<why>`` in the status) is read as error + <why>.
    Anything else (an export predating the field, a value of another form) is NULL — not
    recorded, never guessed.

    MUTATION (verified RED): store the raw value whatever it is -> 'bogus' is stored -> RED; keep
    the old form's message in the status -> 'error:payload too large' is stored -> RED; drop the
    decompile_error column from the INSERT -> RED."""
    out = tmp_path / "out"
    out.mkdir()
    rec = ElfRecord(path=tmp_path / "x", name="x", arch="a", elf_type="executable", sha256="a" * 64)
    funcs = [
        {
            "name": n,
            "address": f"0x{i:x}000",
            "size": 64,
            "callees": [],
            "decompile_status": s,
            "decompile_retried": r,
        }
        for i, (n, s, r) in enumerate(
            [
                ("f_ok", "ok", False),
                ("f_to", "timeout", True),
                ("f_err", "error", False),
                ("f_legacy", "error:payload too large", False),
                ("f_micro", "skipped_micro", False),
                ("f_bogus", "bogus", False),
                ("f_old", None, None),
            ],
            start=1,
        )
    ]
    funcs[2]["decompile_error"] = "Exception while decompiling 00401000: boom"
    (out / f"x_{rec.sha256[:8]}_ghidra.json").write_text(
        json.dumps({"functions": funcs, "imports": [], "exports": [], "strings": []})
    )
    conn = open_db(tmp_path / "analysis.db")
    conn.execute("INSERT INTO binaries (id, name, sha256) VALUES (1, 'x', ?)", (rec.sha256,))
    ingest_ghidra_output(conn, out, [rec], {rec.sha256: 1})
    got = {
        r["name"]: (r["decompile_status"], r["decompile_error"], r["decompile_retried"])
        for r in conn.execute(
            "SELECT name, decompile_status, decompile_error, decompile_retried FROM functions"
        )
    }
    conn.close()
    assert got == {
        "f_ok": ("ok", None, 0),
        "f_to": ("timeout", None, 1),
        "f_err": ("error", "Exception while decompiling 00401000: boom", 0),
        "f_legacy": ("error", "payload too large", 0),
        "f_micro": ("skipped_micro", None, 0),
        "f_bogus": (None, None, 0),
        "f_old": (None, None, 0),
    }


# ── the diff view reads it ────────────────────────────────────────────────────────────────────


def _timed_out_world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str) -> World:
    """An aligned pair: A holds 4 system candidates; B's function's decompile came to ``status``,
    so the hunt found none there."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 0.8)
    w.fn("a", "00001000", ["system"])
    w.fn("b", "00002000", ["system"])
    w.adb["b"].execute("UPDATE functions SET decompile_status = ?", (status,))
    rows = []
    for i in range(4):
        ref = _cmd("a", "00001000", f"0x{0x10 + 4 * i:x}")
        w.inst("a", ref, "cmd", "system")
        rows.append(_overlay_row(ref, None, "callsite", "cmd"))
    w.commit()
    _rows(monkeypatch, rows)
    return w


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        ("timeout", "decompile_timeout"),
        ("error", "decompile_error"),
        # an analysis.db extracted before the message moved to decompile_error
        ("error:payload too large", "decompile_error"),
    ],
)
def test_a_side_whose_decompile_did_not_complete_counts_unknown_never_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str, reason: str
) -> None:
    """★ The B function's decompile timed out (or errored): its sink counts read unknown with that
    reason — not "4 -> 0", which would float the entry as a removed call — and the entry names the
    side (a fact and a blind spot).

    MUTATION (verified RED): leave the decompile outcome out of the counts -> a 4 -> 0 delta ->
    RED; drop the entry fact -> RED; read only the old ``error:<why>`` form as an error -> the
    ``error`` case floats 4 -> 0 -> RED."""
    w = _timed_out_world(tmp_path, monkeypatch, status)
    e = _view(w, sort_by="significance")["by_id"][_pair_id("00001000", "00002000")]
    counts = e["sink_candidate_counts"]
    assert counts["delta"] == []
    assert counts["unknown"] == [{"sink": "system", "side": "b", "reason": reason}]
    gap = reason.replace("decompile_", "")
    assert f"decompile_{gap}:b" in e["facts"]
    assert f"decompile_{gap}:b" in e["blind_spots"]
    assert e["significance"]["basis"] != "sink_candidate_counts"


def test_a_completed_or_micro_decompile_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ok and skipped_micro are not gaps: the counts are counted (here a 4 -> 0 delta) and no
    decompile fact is added."""
    for status in ("ok", "skipped_micro"):
        pv._clear_view_caches()
        w = _timed_out_world(tmp_path / status, monkeypatch, status)
        e = _view(w)["by_id"][_pair_id("00001000", "00002000")]
        assert e["sink_candidate_counts"]["delta"] == [{"sink": "system", "a": 4, "b": 0}]
        assert not [f for f in e["facts"] if f.startswith("decompile_")]


def test_a_gap_side_with_no_candidate_either_side_still_reads_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Neither function holds a candidate, and B's decompile timed out: the counts block is there,
    unknown for B — not absent, which reads as "no candidate either side".

    MUTATION (verified RED): return None whenever neither side holds a candidate -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 0.8)
    w.fn("a", "00001000", ["system"])
    w.fn("b", "00002000", ["system"])
    w.adb["b"].execute("UPDATE functions SET decompile_status = 'timeout'")
    w.commit()
    _rows(monkeypatch, [])
    e = _view(w)["by_id"][_pair_id("00001000", "00002000")]
    assert e["sink_candidate_counts"]["unknown"] == [
        {"sink": None, "side": "b", "reason": "decompile_timeout"}
    ]
