# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The pair review's navigation reader (lib/query/review_navigation): its compact report blocks
carry data and one short note each (the report file renders the full wording), and its dispatch
grouping is cached per process under a key that holds everything the grouping reads.

Zero real data: a hand-built atlas with one diff, a static table and a strcmp gate per side; the
units are hand-made, so a test can change one input of the grouping and nothing else.
"""

from __future__ import annotations

import inspect
import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from treasure_map import mcp_app
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.query import dispatch_groups as dg
from treasure_map.lib.query import review_navigation as rn
from treasure_map.lib.query import upstream_version as uv

D1 = "runA::runB::app"
F1A, F1B = "00001000", "00001001"  # a static-table handler on each side
H1A, H1B = "00003000", "00003001"  # gated by the dispatch function D on each side
DA, DB = "00004000", "00004001"
UA, UB = "00005000", "00005001"  # named by no table or gate
TA, TB = "0x7000", "0x7100"


def _atlas(path: Path) -> sqlite3.Connection:
    atlas = open_atlas(path)
    for run in ("runA", "runB"):
        atlas.execute(
            "INSERT INTO run (run_id, hunt_commit, build_hash, hunt_instances) "
            "VALUES (?, 'c0', 'b0', 10)",
            (run,),
        )
    atlas.execute(
        "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id, binary_a, binary_b, binary_path_a, "
        "binary_path_b, sha256_a, sha256_b, diff_ok, version_skew) "
        "VALUES (?, 'runA', 'runB', 'app', 'app', '/p1/app', '/p1/app', ?, ?, 1, 0)",
        (D1, "a" * 64, "b" * 64),
    )
    for run, table, handler in (("runA", TA, F1A), ("runB", TB, F1B)):
        atlas.execute(
            "INSERT INTO string_keyed_edge (source_run_id, binary, binary_path, key, mechanism, "
            "callee_addr, callee_kind, table_addr, completeness_status) "
            "VALUES (?, 'app', '/p1/app', 'k1', 'static_string_table', ?, 'direct', ?, 'complete')",
            (run, handler, table),
        )
    for run, ffa, callee in (("runA", DA, H1A), ("runB", DB, H1B)):
        _gate(atlas, run, ffa, callee)
    atlas.execute(
        "INSERT INTO function_alignment (diff_id, addr_a, addr_b, alignment_confidence, "
        "similarity, alignment_state) VALUES (?, ?, ?, 0.97, 0.9, 'aligned')",
        (D1, DA, DB),
    )
    atlas.commit()
    return atlas


def _gate(atlas: sqlite3.Connection, run: str, ffa: str, callee: str, key: str = "k3") -> None:
    atlas.execute(
        "INSERT INTO string_keyed_edge (source_run_id, binary, binary_path, from_function, "
        "from_func_addr, key, mechanism, callee_addr, callee_kind, completeness_status) "
        "VALUES (?, 'app', '/p1/app', ?, ?, ?, 'strcmp_gate', ?, 'direct', 'complete')",
        (run, f"FUN_{ffa}", ffa, key, callee),
    )


def _unit(entry_id: str, kind: str = "entry") -> SimpleNamespace:
    member = SimpleNamespace(
        kind="entry", must_read=True, entry_id=entry_id, stream=D1, anchor_ref=f"anc:{entry_id}"
    )
    return SimpleNamespace(kind=kind, stream=D1, must_read=True, members=[member])


FACTS = SimpleNamespace(
    run_a="runA", run_b="runB", diffs=[SimpleNamespace(diff_id=D1, binary="app")]
)
UNITS = [_unit(f"pair:{a}:{b}") for a, b in ((F1A, F1B), (H1A, H1B), (UA, UB))]


def _read(atlas: sqlite3.Connection, units: list[Any] = UNITS) -> rn.PairNavigation:
    return rn.read(atlas, FACTS, units, lambda _u: False)


def _fresh(atlas: sqlite3.Connection, units: list[Any] = UNITS) -> dict[str, Any]:
    """The compact dispatch block computed with no cache."""
    return rn.dispatch_block(dg.from_review(atlas, FACTS, units))


# ── the compact blocks: data, one short note; the full wording in the report file ──────────────


def test_the_compact_blocks_carry_data_and_the_report_file_the_full_wording(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The two blocks ride in the answer that hands out the next unit, so they carry data and
    one short note each — none of the static wording that would take bytes from the unit's
    material. The report file (``--md`` / ``--html``) renders the full wording beside its tables,
    and start_diff_review's description states it.

    MUTATION (verified RED, 1 failed): keep ``mechanism_note`` in dispatch_block (drop its
    ``pop``) -> RED.
    MUTATION (verified RED, 1 failed): the markdown renders the block's ``note`` in place of the
    full mechanism wording -> RED.
    MUTATION (verified RED, 1 failed): upstream_block keeps upstream_groups' own note -> RED."""
    from treasure_map.lib.query import review_report as rr

    atlas = _atlas(tmp_path / "atlas.db")
    pair = {D1: {"library": "openssl", "a": {"version": "1.1.1k"}, "b": {"version": "1.1.1t"}}}
    monkeypatch.setattr(uv, "pair_upstream", lambda *_a: pair)
    nav = _read(atlas)
    block, ublock = nav.report["dispatch_groups"], nav.report["upstream_groups"]
    assert block.get("note") == rn.DISPATCH_NOTE and ublock.get("note") == rn.UPSTREAM_NOTE
    assert "mechanism_note" not in block, block
    assert "note" not in block["uncovered"] and "note" not in block["static_table_detector"]
    assert block["grouped_members"] == 2 and block["uncovered"]["count"] == 1, block
    assert ublock["groups_total"] == 1 and ublock["groups"][0]["library"] == "openssl", ublock
    shown = json.dumps(nav.report)
    for text in (*rn.DISPATCH_NOTES.values(), *rn.UPSTREAM_NOTES.values()):
        assert text not in shown, text
    assert "not a safety proof" in rn.UPSTREAM_NOTE

    review = SimpleNamespace(navigation=nav, report=nav.report)
    md = "\n".join(rr._navigation_md(review))  # type: ignore[arg-type]
    page = "\n".join(rr._navigation_html(review))  # type: ignore[arg-type]
    for text in (*rn.DISPATCH_NOTES.values(), *rn.UPSTREAM_NOTES.values()):
        assert text in md, text
        assert __import__("html").escape(text) in page, text

    doc = inspect.getdoc(mcp_app.make_tools(tmp_path / "atlas.db")["start_diff_review"]) or ""
    flat = " ".join(doc.split())
    for phrase in (
        "scanned_no_static_table_found",
        "supported_scope",
        "the strcmp-gate detector records no scan status",
        "= no rule or no string matched, on either side",
        "is not a safety proof",
        "never a reachability claim",
    ):
        assert phrase in flat, phrase


# ── the dispatch grouping, cached per process under everything it reads ────────────────────────


def _edge(atlas: sqlite3.Connection, _tmp: Path) -> sqlite3.Connection:
    _gate(atlas, "runA", DA, UA, key="k4")  # U is now gated too
    return atlas


def _status(atlas: sqlite3.Connection, _tmp: Path) -> sqlite3.Connection:
    atlas.execute(
        "INSERT INTO detector_scan_status (source_run_id, binary, binary_path, detector, scanned, "
        "supported_scope, unsupported_note, cap_hit, found_count) "
        "VALUES ('runA', 'app', '/p1/app', 'string_tables', 1, 'scope_x', NULL, 0, 1)"
    )
    return atlas


def _alignment(atlas: sqlite3.Connection, _tmp: Path) -> sqlite3.Connection:
    # A re-diff replaces the diff's pairings (delete, then insert with fresh ids), as the writer
    # does: the dispatch functions' pairing is now undetermined.
    atlas.execute("DELETE FROM function_alignment WHERE diff_id = ?", (D1,))
    atlas.execute(
        "INSERT INTO function_alignment (diff_id, addr_a, addr_b, alignment_confidence, "
        "similarity, alignment_state) VALUES (?, ?, ?, 0.4, 0.9, 'alignment_undetermined')",
        (D1, DA, DB),
    )
    return atlas


def _diff_row(atlas: sqlite3.Connection, _tmp: Path) -> sqlite3.Connection:
    atlas.execute("UPDATE diff_meta SET binary_path_b = '/p9/app' WHERE diff_id = ?", (D1,))
    return atlas


def _run_row(atlas: sqlite3.Connection, _tmp: Path) -> sqlite3.Connection:
    atlas.execute("UPDATE run SET build_hash = 'b1' WHERE run_id = 'runB'")
    return atlas


def _other_atlas(atlas: sqlite3.Connection, tmp: Path) -> sqlite3.Connection:
    # The same content in another file: a second atlas served by one process.
    other = open_atlas(tmp / "other.db")
    atlas.backup(other)
    return other


@pytest.mark.parametrize(
    ("change", "shows"),
    [
        (_edge, True),
        (_status, True),
        (_alignment, True),
        (_diff_row, True),
        (_run_row, False),
        (_other_atlas, False),
    ],
    ids=[
        "string_keyed_edge",
        "detector_scan_status",
        "function_alignment",
        "diff_meta",
        "run",
        "atlas_file",
    ],
)
def test_the_grouping_is_read_once_and_again_when_anything_it_reads_moves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: Any, shows: bool
) -> None:
    """★ A pair read again with nothing moved is grouped once (the cache answers); after any
    input of the grouping moves — a string-keyed edge, a detector status row, a function
    pairing, the pair's diff row, a run's row, another atlas file — it is grouped again, and the
    block is the one an uncached grouping gives (a change the grouping shows is shown).

    MUTATION (verified RED, 1 failed each): leave ``per_run`` (the edge stamp; the detector
    stamp), ``align``, ``diffs``, ``runs`` or ``_atlas_identity(atlas)`` out of _dispatch_key
    -> the matching case is answered stale -> RED.
    MUTATION (verified RED, 6 failed): no cache (always compute) -> the second read groups again
    -> RED."""
    calls: list[int] = []
    real = dg.from_review
    monkeypatch.setattr(dg, "from_review", lambda *a, **kw: calls.append(1) or real(*a, **kw))
    atlas = _atlas(tmp_path / "atlas.db")
    before = _read(atlas).report["dispatch_groups"]
    again = _read(atlas).report["dispatch_groups"]
    assert calls == [1] and again == before, (calls, again)
    atlas = change(atlas, tmp_path)
    after = _read(atlas).report["dispatch_groups"]
    assert calls == [1, 1], calls
    want = _fresh(atlas)
    assert after == want, (after, want)
    assert (after != before) is shows, (before, after)


def test_another_set_of_members_is_grouped_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The members the units hold are part of the key: units without one grouped member are
    grouped again and the block counts one fewer.

    MUTATION (verified RED, 1 failed): leave the members out of _dispatch_key -> the earlier
    grouping is answered -> RED."""
    calls: list[int] = []
    real = dg.from_review
    monkeypatch.setattr(dg, "from_review", lambda *a, **kw: calls.append(1) or real(*a, **kw))
    atlas = _atlas(tmp_path / "atlas.db")
    assert _read(atlas).report["dispatch_groups"]["grouped_members"] == 2
    fewer = [u for u in UNITS if u.members[0].entry_id != f"pair:{H1A}:{H1B}"]
    block = _read(atlas, fewer).report["dispatch_groups"]
    assert calls == [1, 1] and block["grouped_members"] == 1, (calls, block)
    assert block == _fresh(atlas, fewer)


def test_a_read_that_fails_is_never_cached_and_a_hit_is_a_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A sqlite error is ``unreadable`` in the block and is not remembered: the next read groups
    again. A cached block is handed out as a copy, so a caller changing it changes no later read.

    MUTATION (verified RED, 1 failed): hand out the cached block itself (no deepcopy) -> RED."""
    atlas = _atlas(tmp_path / "atlas.db")
    real = dg.from_review

    def broken(*_a: Any, **_kw: Any) -> Any:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(dg, "from_review", broken)
    assert "database is locked" in str(_read(atlas).report["dispatch_groups"].get("unreadable"))
    monkeypatch.setattr(dg, "from_review", real)
    first = _read(atlas).report["dispatch_groups"]
    assert "unreadable" not in first and first["grouped_members"] == 2, first
    first["grouped_members"] = 99
    assert _read(atlas).report["dispatch_groups"]["grouped_members"] == 2


def test_a_member_label_is_handed_out_as_a_copy(tmp_path: Path) -> None:
    """The member labels are shared with the process cache; ``member_dispatch`` hands each out as
    a copy, so the answer it is put into can change it without changing a later read.

    MUTATION (verified RED, 1 failed): return the cached label itself (no deepcopy) -> RED."""
    atlas = _atlas(tmp_path / "atlas.db")
    entry = f"pair:{F1A}:{F1B}"
    label = _read(atlas).member_dispatch(D1, entry)
    assert label, "the fixture's first entry must carry a dispatch label"
    before = json.dumps(label, sort_keys=True)
    label.append({"changed": True})
    label[0]["group_ref"] = "changed"
    assert json.dumps(_read(atlas).member_dispatch(D1, entry), sort_keys=True) == before
