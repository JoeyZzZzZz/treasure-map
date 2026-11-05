# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A decompile that failed has no text to compare, and never reads as "nothing changed".

An earlier extractor stored ``/* decompile_error: <message> */`` as the pseudocode of a function
whose decompile threw. Two sides that threw the same message then compared equal, so an aligned
pair read identical and left the review view: a function nobody could read, gone without a trace.
The extractor now stores no text there; every reader treats the old note as no text either, and an
empty text whose decompile is recorded as failed says so instead of reading as an empty function.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.unit.lib.test_d29_callsite import _pair, _scc
from tests.unit.lib.test_patch_view import DIFF, SHA_A, World
from treasure_map.lib import facts
from treasure_map.lib.diff.layer0 import _decompile_status
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query import sameness


@pytest.fixture
def current(monkeypatch: pytest.MonkeyPatch) -> None:
    """The diff reads as current (its stamps are not under test here)."""
    monkeypatch.setattr(
        pv,
        "diff_source_staleness",
        lambda atlas, diff_id: {
            "source_stale": False,
            "source_stale_reason": None,
            "toolchain_checked": True,
        },
    )


NOTE = "/* decompile_error: Low-level Error: Forced merge caused intersection */"


def test_the_placeholder_is_no_text_to_any_reader() -> None:
    """★ The shared test, and the two body classifiers built on it: the placeholder is no text, at a
    real size a failed decompile — never ``ok``.

    MUTATION (verified RED): read any non-empty text as text (no placeholder test) -> RED."""
    assert facts.has_text("int f(void) { return 0; }")
    assert not facts.has_text(NOTE)
    assert not facts.has_text("   " + NOTE)
    assert not facts.has_text("") and not facts.has_text(None)
    assert _decompile_status(NOTE, 200) == "failed"
    bodies = {"0x1000": {"pseudocode": NOTE, "size_bytes": 200}}
    assert sameness._body_status(bodies, "0x1000") != "ok"


def test_two_sides_that_threw_the_same_message_are_unavailable_never_identical(
    tmp_path: Path, current: None
) -> None:
    """★ The case itself: an aligned pair whose two sides hold the same placeholder reads
    UNAVAILABLE and is counted in function_states' unverified.unavailable — not identical, and not
    unchanged.

    MUTATION (verified RED): keep the placeholder as text when loading bodies AND in _body_status
    -> identical, unchanged -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 1.0)
    w.fn("a", "00001000", ["foo"], pseudocode=NOTE, size_bytes=200)
    w.fn("b", "00002000", ["foo"], pseudocode=NOTE, size_bytes=200)
    w.commit()
    nl = pv.get_diff_patch_view(w.atlas, DIFF)["not_listed"]
    assert nl["aligned_pseudocode_unavailable"]["count"] == 1
    assert nl["aligned_pseudocode_identical"]["count"] == 0
    states = pv.function_states(w.atlas, DIFF)
    assert states is not None
    assert states["unverified"]["unavailable"] == 1
    assert states["unchanged"] == 0


def test_a_failed_decompile_is_named_by_its_recorded_status_not_as_an_empty_one(
    tmp_path: Path, current: None
) -> None:
    """★ An empty text whose decompile is recorded as an error is ``decompile_failed`` — the cause
    the extraction recorded — not ``decompile_empty`` (a decompile that produced nothing), which
    the size alone would say.

    MUTATION (verified RED): classify an empty body by its size alone -> decompile_empty -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 1.0)
    w.fn("a", "00001000", ["foo"], pseudocode="", size_bytes=200)
    w.fn("b", "00002000", ["foo"], pseudocode="", size_bytes=200)
    for side in ("a", "b"):
        w.adb[side].execute("UPDATE functions SET decompile_status = 'error'")
    w.commit()
    bodies = sameness.read_function_bodies(str(tmp_path / "analysis_a.db"), SHA_A)
    assert bodies is not None
    [addr] = list(bodies)
    assert sameness._body_status(bodies, addr) == sameness.DECOMPILE_FAILED
    view = pv.get_diff_patch_view(w.atlas, DIFF)
    assert view["not_listed"]["aligned_pseudocode_unavailable"]["count"] == 1
    states = pv.function_states(w.atlas, DIFF)
    assert states is not None
    assert states["unavailable_by_cause"]["decompile_failed"] == 1
    assert states["unavailable_by_cause"]["decompile_empty"] == 0


def test_a_side_holding_the_placeholder_has_no_call_counts(tmp_path: Path, current: None) -> None:
    """The per-sink call counts are read off the text: a side holding the placeholder has none to
    read, so it is unknown (text_unavailable), never a count of 0.

    MUTATION (verified RED): read the placeholder as text in the side query -> a 4 -> 0 delta."""
    w = _pair(tmp_path, ["_eval"] * 4, [], b_pc=NOTE, b_sz=300, a_callees=["_eval"])
    scc = _scc(w)
    assert {"sink": "_eval", "side": "b", "reason": "text_unavailable"} in scc["unknown"]
    assert scc["delta"] == []


def test_get_pseudocode_carries_the_recorded_outcome_of_an_empty_text(tmp_path: Path) -> None:
    """★ A function with no text says why from what the extraction recorded: decompile_failed, the
    status and the error — never read as a function with nothing in it.

    MUTATION (verified RED): leave the recorded status out -> RED."""
    from treasure_map.lib.storage.connection import open_db

    conn = open_db(tmp_path / "a.db")
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, last_seen_at) "
        "VALUES (1, 'httpd', 'bin/httpd', ?, '2026-01-01T00:00:00')",
        ("a" * 64,),
    )
    conn.execute(
        "INSERT INTO functions (binary_id, name, address, pseudocode, size_bytes, "
        "decompile_status, decompile_error) VALUES (1, 'f', '0x1000', '', 400, 'error', "
        "'Low-level Error: Forced merge')"
    )
    conn.execute(
        "INSERT INTO functions (binary_id, name, address, pseudocode, size_bytes) "
        "VALUES (1, 'g', '0x2000', ?, 400)",
        (NOTE,),
    )
    conn.commit()
    got = facts.get_pseudocode(conn, func="f", binary="httpd")
    assert got["pseudocode_status"] == facts.PSEUDOCODE_DECOMPILE_FAILED
    assert got["decompile_status"] == "error"
    assert got["decompile_error"] == "Low-level Error: Forced merge"
    old = facts.get_pseudocode(conn, func="g", binary="httpd")
    assert "pseudocode_status" in old  # the placeholder is not text: its status is given
    conn.close()


def test_the_extractor_writes_no_placeholder_for_a_decompile_that_threw() -> None:
    """★ At the source: a decompile that threw stores an empty text (its status is the failure, its
    error message the reason), never a note in place of pseudocode.

    MUTATION (verified RED): write the note back -> RED."""
    src = (Path(facts.__file__).parent / "analyze" / "ghidra" / "ExportFunctions.java").read_text(
        encoding="utf-8"
    )
    assert '"/* decompile_error: "' not in src
    catch = src[src.index("} catch (Exception e) {\n            // No text") :][:400]
    assert 'pseudocode = "";' in catch and "decompileStatus = DECOMPILE_ERROR;" in catch
