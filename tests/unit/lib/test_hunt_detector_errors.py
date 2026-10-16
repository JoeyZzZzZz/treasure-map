# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A detector that threw during extraction reaches triage as '?', end to end.

When an additive detector throws, the extractor stores the empty value it fell back to (the same
value a detector that found nothing stores) and names the detector in ``functions.detector_errors``.
These tests build an analysis.db in exactly that shape, run the real hunt into an atlas and read
the real triage: the function whose sink-provenance detector threw must read controllability '?',
while an identical function whose detector ran cleanly keeps its confident 'constant'. Both ways a
candidate is emitted are covered: a direct sink call and a call through a thin format wrapper.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.hunt import run_analyzer2
from treasure_map.lib.query import triage
from treasure_map.lib.query.triage import TriageCandidate
from treasure_map.lib.storage.connection import open_db

# What the extractor writes for a function on which the sink-provenance detector threw: the
# fallback empty provenance and the detector's name.
_CRASHED = {"sink_provenance": "[]", "detector_errors": '["sink_provenance"]'}
_CLEAN = {"sink_provenance": "[]", "detector_errors": "[]"}

# (name, entry address, pseudocode, callees, extraction outcome). Each errored function has a
# clean twin with the same body, so the stored detector list is the only difference between them.
_FUNCS: tuple[tuple[str, str, str, list[str], dict[str, str]], ...] = (
    ("log_msg", "0x1000", "void log_msg(char* param_1){ printf(param_1); }", ["printf"], _CLEAN),
    (
        "show_err",
        "0x2000",
        'void show_err(void){ log_msg("fixed text"); }',
        ["log_msg"],
        _CRASHED,
    ),
    ("show_ok", "0x3000", 'void show_ok(void){ log_msg("fixed text"); }', ["log_msg"], _CLEAN),
    ("reboot_err", "0x4000", 'void reboot_err(void){ system("reboot"); }', ["system"], _CRASHED),
    ("reboot_ok", "0x5000", 'void reboot_ok(void){ system("reboot"); }', ["system"], _CLEAN),
)


def _analysis_db(tmp_path: Path, *, with_column: bool = True) -> Path:
    """One binary holding ``_FUNCS``. ``with_column=False`` drops ``functions.detector_errors``,
    the shape of an analysis.db extracted before the list was recorded."""
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, ghidra_ok) VALUES (1, ?, ?, ?, 1)",
        ("netd", "/usr/sbin/netd", hashlib.sha256(b"netd").hexdigest()),
    )
    for fid, (name, addr, body, callees, outcome) in enumerate(_FUNCS, start=1):
        conn.execute(
            "INSERT INTO functions (id, binary_id, name, address, pseudocode, pseudocode_hash, "
            "callees, sink_provenance, detector_errors) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?)",
            (
                fid,
                name,
                addr,
                body,
                f"h_{name}",
                json.dumps(callees),
                outcome["sink_provenance"],
                outcome["detector_errors"],
            ),
        )
    if not with_column:
        conn.execute("ALTER TABLE functions DROP COLUMN detector_errors")
    conn.commit()
    conn.close()
    return db


def _hunt_and_triage(tmp_path: Path, db: Path) -> dict[str, TriageCandidate]:
    """Hunt ``db`` into a fresh atlas and triage it: the candidate per function name."""
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id="r")
    conn = open_atlas(atlas)
    try:
        return {c.function: c for c in triage(conn)}
    finally:
        conn.close()


def _flow_evidence(tmp_path: Path, function: str) -> dict[str, object]:
    conn = open_atlas(tmp_path / "atlas.db")
    try:
        rows = conn.execute(
            "SELECT flow_evidence FROM instance WHERE source_anchor = ?", (function,)
        ).fetchall()
    finally:
        conn.close()
    assert len(rows) == 1, f"{function}: expected one candidate, got {len(rows)}"
    data = json.loads(rows[0][0])
    assert isinstance(data, dict)
    return data


@pytest.mark.parametrize(
    ("errored", "clean", "ref_axis"),
    [("reboot_err", "reboot_ok", "@cmd#"), ("show_err", "show_ok", "@fmt_via_wrapper#")],
    ids=["direct_sink_call", "through_a_format_wrapper"],
)
def test_a_crashed_detector_reads_unknown_never_constant(
    tmp_path: Path, errored: str, clean: str, ref_axis: str
) -> None:
    """analysis.db with detector_errors set -> hunt -> triage: the errored function's
    controllability is '?', its clean twin's is a confident 'constant' (so the fallback empty
    provenance really would read as constant, and the carried list is what changes it).

    MUTATION (verified RED, each case on its own): drop the ``_detector_error_keys(...)`` merge for
    that emission path in run_analyzer2 (the ``evidence_keys.update`` for a direct sink call, the
    ``| _detector_error_keys(...)`` term for a wrapper candidate) -> the errored candidate carries
    no list, reads 'constant' like its twin, and the '?' assertion fails."""
    cands = _hunt_and_triage(tmp_path, _analysis_db(tmp_path))
    assert errored in cands and clean in cands
    assert ref_axis in cands[errored].evidence_ref and ref_axis in cands[clean].evidence_ref
    # the clean twin reads confident: the crash shape alone is what would have sunk the errored one
    assert cands[clean].dim("controllability").state == "proven"
    assert cands[clean].dim("controllability").value == "constant"
    # the errored function reads '?', never the confident constant its fallback empty would give
    ctrl = cands[errored].dim("controllability")
    assert (ctrl.state, ctrl.value) == ("unknown", "unknown")
    assert "errored" in ctrl.note
    # ...because its list was carried onto its candidate
    assert _flow_evidence(tmp_path, errored).get("detector_errors") == ["sink_provenance"]
    # a clean function carries no list at all
    assert "detector_errors" not in _flow_evidence(tmp_path, clean)


def test_an_analysis_db_without_the_column_still_hunts(tmp_path: Path) -> None:
    """An analysis.db extracted before detector_errors was recorded hunts as before: no error, and
    no key on any candidate (nothing was recorded, so nothing is claimed either way).

    MUTATION (verified RED): drop the ``except sqlite3.OperationalError`` fallback in
    _load_detector_errors -> the hunt raises "no such column" and the test fails on that."""
    db = _analysis_db(tmp_path, with_column=False)
    conn = sqlite3.connect(db)
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(functions)")}
    finally:
        conn.close()
    assert "detector_errors" not in cols  # the fixture really is the older shape
    try:
        cands = _hunt_and_triage(tmp_path, db)
    except sqlite3.OperationalError as exc:
        pytest.fail(f"an analysis.db without detector_errors must still hunt: {exc}")
    assert {"reboot_err", "reboot_ok", "show_err", "show_ok"} <= set(cands)
    for name in ("reboot_err", "reboot_ok", "show_err", "show_ok"):
        assert "detector_errors" not in _flow_evidence(tmp_path, name)
