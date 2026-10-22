# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The calls of the same shape as one sink call of a diff (lib/query/same_shape_siblings).

Zero real data: every run, binary, address and function name is synthetic. One atlas holds one diff
of ``libx`` between runA and runB, each run with its own analysis.db. Other binaries of the two runs
(never diffed) hold the calls ``binaries_not_diffed`` counts, and a third run holds a binary with
libx's own content, which no group may draw from.
"""

from __future__ import annotations

import dataclasses
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from treasure_map import mcp_app
from treasure_map.cli import mcp_cli
from treasure_map.lib.analyze.ghidra_runner import current_pass_version
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.query import diff_annotations as da
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query import same_shape_siblings as ss
from treasure_map.lib.query.sink_overlay import SinkOverlayRow, _subject_key
from treasure_map.lib.rescan_version import CodeStamp
from treasure_map.lib.storage.connection import open_db
from treasure_map.version import UNKNOWN_VERSION

# An old run (no code stamp) is read through the commit fallback, and this install's commit is
# UNKNOWN, so the diff is servable regardless of this value — it just has to be supplied.
_CURRENT = CodeStamp(hunt="src-a1a1a1a1a1a1a1a1", scan="{}")

SHA_A = "a" * 64
SHA_B = "b" * 64
DIFF = "runA::runB::libx"
BANCHOR = "deadbeef"
COMMIT = "facade"
FPV = "fpv-test"  # the fingerprint version the fixture's pattern rows record, not the code's
SRC = json.dumps({"size_kind": "source_len"})
CONST = json.dumps({"size_kind": "const"})


def _ref(run: str, func: str, cls: str, offset: str | None = None, banchor: str = BANCHOR) -> str:
    """An evidence_ref in the real shape: {run}#{banchor}:{func}@{class}[@{offset}]."""
    return f"{run}#{banchor}:{func}@{cls}" + (f"@{offset}" if offset is not None else "")


def _addr(func: str, offset: str) -> str:
    return f"{int(func, 16) + int(offset, 16):08x}"


class World:
    """One diff of ``libx`` between runA and runB, plus each run's analysis.db."""

    def __init__(self, tmp: Path, *, diff_ok: int = 1, version_skew: int = 0) -> None:
        self.tmp = tmp
        self.path = tmp / "atlas.db"
        self.atlas = open_atlas(self.path)
        self.atlas.execute("PRAGMA synchronous = OFF")
        self.build = current_pass_version()
        self.adb: dict[str, sqlite3.Connection] = {}
        for side, run, sha in (("a", "runA", SHA_A), ("b", "runB", SHA_B)):
            db = tmp / f"analysis_{side}.db"
            conn = open_db(db)
            conn.execute("PRAGMA synchronous = OFF")
            conn.execute("INSERT INTO binaries (name, sha256) VALUES ('libx', ?)", (sha,))
            conn.commit()
            self.adb[side] = conn
            self.atlas.execute(
                "INSERT INTO run (run_id, hunt_commit, build_hash, hunt_instances, "
                "analysis_db_path) VALUES (?, ?, ?, 10, ?)",
                (run, COMMIT, self.build, str(db)),
            )
        self.atlas.execute(
            "INSERT INTO run (run_id, hunt_commit, build_hash, hunt_instances) "
            "VALUES ('runC', ?, ?, 10)",
            (COMMIT, self.build),
        )
        self.atlas.execute(
            "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id, binary_a, binary_b, sha256_a, "
            "sha256_b, diff_ok, version_skew, callsite_facts_a, callsite_facts_b, "
            "callsite_facts_hash_a, callsite_facts_hash_b, stub_state_a, stub_state_b) "
            "VALUES (?, 'runA', 'runB', 'libx', 'libx', ?, ?, ?, ?, 'read', 'read', ?, ?, "
            "'not_applicable', 'not_applicable')",
            (DIFF, SHA_A, SHA_B, diff_ok, version_skew, self.build, self.build),
        )

    def pair(self, a: str, b: str, conf: float, sim: float) -> None:
        state = "aligned" if conf >= 0.9 else "alignment_undetermined"
        self.atlas.execute(
            "INSERT INTO function_alignment (diff_id, addr_a, addr_b, alignment_confidence, "
            "similarity, alignment_state) VALUES (?, ?, ?, ?, ?, ?)",
            (DIFF, a, b, conf, sim, state),
        )

    def fn(
        self, side: str, addr: str, callees: list[str], *, name: str | None = None, trunc: int = 0
    ) -> None:
        self.adb[side].execute(
            "INSERT INTO functions (binary_id, name, address, callees, callees_truncated, "
            "unresolved_external_calls) VALUES (1, ?, ?, ?, ?, '[]')",
            (name or f"fn_{addr}", addr, json.dumps(callees), trunc),
        )

    def im(self, a: str, b: str, func_a: str) -> None:
        self.atlas.execute(
            "INSERT INTO instruction_match (diff_id, func_addr_a, addr_a, addr_b) "
            "VALUES (?, ?, ?, ?)",
            (DIFF, func_a, a, b),
        )

    def inst(
        self,
        run: str,
        ref: str | None,
        sink_class: str,
        sink: str | None,
        flow: str | None = None,
        *,
        fp: str | None = "fp_copy",
        sha: str | None = None,
        path: str = "/fw/lib/libx",
    ) -> None:
        sha = sha or {"runA": SHA_A, "runB": SHA_B, "runC": SHA_A}[run]
        self.atlas.execute(
            "INSERT INTO instance (pattern_id, evidence_ref, source_run_id, binary_content_hash, "
            "binary_path, sink_anchor, flow_evidence) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (self._pattern(sink_class, fp), ref, run, sha, path, sink, flow),
        )

    def _pattern(self, sink_class: str, fp: str | None) -> int:
        row = self.atlas.execute(
            "SELECT pattern_id FROM pattern WHERE sink_class = ? AND call_sequence_shape = ?",
            (sink_class, f"shape_{fp}"),
        ).fetchone()
        if row is not None:
            return int(row[0])
        cur = self.atlas.execute(
            "INSERT INTO pattern (source_class, sink_class, call_sequence_shape, "
            "structural_fingerprint, fingerprint_algo_version) VALUES "
            "('external_input', ?, ?, ?, ?)",
            (sink_class, f"shape_{fp}", fp, FPV),
        )
        return int(cur.lastrowid or 0)

    def lined(
        self,
        fa: str,
        fb: str,
        sim: float,
        sink: str = "strcpy",
        flow: str = SRC,
        *,
        sink_class: str = "copy",
        fp: str = "fp_copy",
        offset: str = "0x10",
    ) -> str:
        """An aligned pair whose one call lines up across the diff (persisted); the A ref."""
        self.pair(fa, fb, 0.97, sim)
        ref_a = _ref("runA", fa, sink_class, offset)
        self.inst("runA", ref_a, sink_class, sink, flow, fp=fp)
        self.inst("runB", _ref("runB", fb, sink_class, offset), sink_class, sink, flow, fp=fp)
        self.im(_addr(fa, offset), _addr(fb, offset), fa)
        self.fn("a", fa, [sink])
        self.fn("b", fb, [sink])
        return ref_a

    def commit(self) -> None:
        for conn in (self.atlas, *self.adb.values()):
            conn.commit()


# The strcpy / source_len group on side A, one member per landing the view gives it.
LISTED = _ref("runA", "00001000", "copy", "0x10")  # changed pair, lined up: listed, persisted
UNLISTED = [_ref("runA", f, "copy", "0x10") for f in ("00003000", "00005000", "00007000")]
R_MEMBER = _ref("runA", "00009000", "copy", "0x10")  # an undetermined pair
P_MEMBER = _ref("runA", "0000b000", "copy", "0x10")  # a function with no record at all
CTX_MEMBER = _ref("runA", "0000c000", "copy", "0x30")  # sink name absent in the paired callees
GROUP_A = [LISTED, *UNLISTED, R_MEMBER, P_MEMBER, CTX_MEMBER]
MEMCPY = _ref("runA", "0000e000", "copy", "0x10")
STRCPY_CONST = _ref("runA", "00010000", "copy", "0x10")
SYSTEM_FREE = [_ref("runA", f, "cmd", "0x10") for f in ("00012000", "00014000")]
SYSTEM_SAFE = _ref("runA", "00016000", "cmd", "0x10")
WRAPPED = [_ref("runA", f, "cmd_via_wrapper", "0x20") for f in ("00018000", "0001a000", "0001e000")]
WRAPPED_OLD = _ref("runA", "00020000", "cmd_via_wrapper", "0x20")
WRAPPER_FN = _ref("runA", "00018000", "cmd_via_wrapper")
FALLBACK = _ref("runA", "0001c000", "copy")
DEGRADED = _ref("runA", "00022000", "copy")
B_LISTED = _ref("runB", "00002000", "copy", "0x10")


def _wflow(name: str, addr: str | None) -> str:
    wrapper: dict[str, Any] = {"name": name}
    if addr is not None:
        wrapper["addr"] = addr
    return json.dumps({"source_kind": "free_string", "flow_path": {"wrapper": wrapper}})


def _build(w: World) -> None:
    w.lined("00001000", "00002000", 0.8)
    for fa, fb in (("00003000", "00004000"), ("00005000", "00006000"), ("00007000", "00008000")):
        w.lined(fa, fb, 1.0)
    w.inst("runA", UNLISTED[0], "copy", "strcpy", SRC)  # the same call recorded twice: one member
    w.pair("00009000", "0000a000", 0.5, 0.4)
    w.inst("runA", R_MEMBER, "copy", "strcpy", SRC)
    w.inst("runA", P_MEMBER, "copy", "strcpy", SRC)
    w.pair("0000c000", "0000d000", 0.97, 0.7)
    w.inst("runA", CTX_MEMBER, "copy", "strcpy", SRC)
    w.fn("a", "0000c000", ["strcpy"])
    w.fn("b", "0000d000", ["memset"])
    # Same pattern and kind, another sink; same sink and pattern, another size kind.
    w.lined("0000e000", "0000f000", 1.0, "memcpy")
    w.lined("00010000", "00011000", 1.0, "strcpy", CONST)
    # cmd calls group by source kind; a size kind they carry is not theirs to group by.
    cmd = {"sink_class": "cmd", "fp": "fp_cmd"}
    w.lined(
        "00012000", "00013000", 1.0, "system", json.dumps({"source_kind": "free_string"}), **cmd
    )
    w.lined(
        "00014000",
        "00015000",
        1.0,
        "system",
        json.dumps({"source_kind": "free_string", "size_kind": "const"}),
        **cmd,
    )
    w.lined(
        "00016000", "00017000", 1.0, "system", json.dumps({"source_kind": "charset_safe"}), **cmd
    )
    # Calls to wrappers (members, their sink the one the wrapper forwards to): two through run_cmd,
    # one through log_cmd, one an older hunt recorded by name only.
    for (fa, fb), (name, addr) in zip(
        (("00018000", "00019000"), ("0001a000", "0001b000"), ("0001e000", "0001f000")),
        (("run_cmd", "0x00030000"), ("run_cmd", "0x00030000"), ("log_cmd", "0x00031000")),
        strict=True,
    ):
        w.pair(fa, fb, 0.97, 0.9)
        w.inst(
            "runA",
            _ref("runA", fa, "cmd_via_wrapper", "0x20"),
            "cmd",
            "system",
            _wflow(name, addr),
            fp="fp_wrap",
        )
    w.pair("00020000", "00021000", 0.97, 0.9)
    w.inst("runA", WRAPPED_OLD, "cmd", "system", _wflow("old_cmd", None), fp="fp_wrap")
    # Function-level candidates of the strcpy shape and of the wrapper shape: never members.
    w.inst("runA", WRAPPER_FN, "cmd", "system", _wflow("run_cmd", "0x00030000"), fp="fp_wrap")
    w.pair("0001c000", "0001d000", 0.97, 0.9)
    w.inst("runA", FALLBACK, "copy", "strcpy", SRC)
    w.pair("00022000", "00023000", 0.97, 0.9)
    degraded = json.dumps({"callsite_located": False, "size_kind": "source_len"})
    w.inst("runA", DEGRADED, "copy", "strcpy", degraded)
    w.inst("runA", DEGRADED, "copy", "strcpy", degraded)  # one ref, two rows: counted once
    # ... and the same degraded ref with a second shape no member has.
    w.inst(
        "runA",
        DEGRADED,
        "copy",
        "memcpy",
        json.dumps({"callsite_located": False, "size_kind": "const"}),
    )
    # Calls no shape can be given.
    w.inst("runA", "runA#fn12", "copy", "strcpy", SRC)
    w.inst("runA", _ref("runA", "00024000", "copy", "0x10"), "copy", "strcpy", SRC, fp=None)
    w.inst("runA", _ref("runA", "00026000", "copy", "0x10"), "copy", None, SRC)
    # A sink the hunt does not recall, named in a callee list of the binary.
    w.fn("a", "00030000", ["wcscpy"], name="run_cmd")
    # libx's content in another run: never drawn into a group of this diff.
    w.inst("runC", _ref("runC", "00003000", "copy", "0x10"), "copy", "strcpy", SRC)
    _not_diffed(w)
    w.commit()


def _not_diffed(w: World) -> None:
    """Other binaries of runA holding the strcpy / source_len shape, one per reason, plus calls of
    other kinds and granularities there that are not counted."""

    def call(run: str, func: str, sha: str, path: str, flow: str = SRC, off: str | None = "0x10"):
        ref = _ref(run, func, "copy", off, sha[:8])
        w.inst(run, ref, "copy", "strcpy", flow, sha=sha, path=path)

    call("runA", "00040000", "c" * 64, "/fw/alt/libx")  # a same-named binary was diffed
    call("runA", "00040000", "1" * 64, "/fw/opt/libx")  # ... and its content is on B too
    call("runB", "00040000", "1" * 64, "/fw/opt/libx")
    call("runA", "00040000", "d" * 64, "/fw/lib/libsame")  # the same content is on B
    call("runB", "00040000", "d" * 64, "/fw/lib/libsame")
    call("runA", "00040000", "e" * 64, "/fw/lib/libold")  # B holds the name, other content
    call("runB", "00040000", "f" * 64, "/fw/lib/libold")
    call("runA", "00040000", "9" * 64, "/fw/lib/libonly")  # this side only
    call("runA", "00050000", "9" * 64, "/fw/lib/libonly")
    call("runA", "00040000", "9" * 64, "/fw/lib2/libonly")  # the same content at a second path
    call("runA", "00060000", "9" * 64, "/fw/lib/libonly", CONST)  # another kind
    call("runA", "00070000", "9" * 64, "/fw/lib/libonly", SRC, None)  # function level


@pytest.fixture(autouse=True)
def _servable(monkeypatch: pytest.MonkeyPatch) -> None:
    """The MCP gate compares a run's hunt commit with the install's; this install's is unknown, and
    the CLI is made to read it the same way. The view's process-wide caches are dropped: every
    World reuses one diff_id."""
    monkeypatch.setattr(mcp_app, "_installed_commit", lambda: UNKNOWN_VERSION)
    monkeypatch.setattr(mcp_cli, "installed_commit", lambda: UNKNOWN_VERSION)
    pv._clear_view_caches()


@pytest.fixture
def current(monkeypatch: pytest.MonkeyPatch) -> None:
    """The diff reads as current (its stamps are not under test here)."""

    def fresh(atlas: Any, diff_id: str) -> dict[str, Any]:
        return {"source_stale": False, "source_stale_reason": None, "toolchain_checked": True}

    monkeypatch.setattr(pv, "diff_source_staleness", fresh)
    monkeypatch.setattr(ss, "diff_source_staleness", fresh)


@pytest.fixture
def world(tmp_path: Path, current: None) -> World:
    w = World(tmp_path)
    _build(w)
    return w


def _sib(w: World, **kw: Any) -> dict[str, Any]:
    return ss.same_shape_siblings(
        w.atlas,
        kw.pop("diff_id", DIFF),
        build_hash=w.build,
        current=_CURRENT,
        commit=UNKNOWN_VERSION,
        **kw,
    )


def _members(w: World, ref: str, limit: int = 7) -> list[dict[str, Any]]:
    """Every member of ``ref``'s group, every page walked."""
    out: list[dict[str, Any]] = []
    offset: int | None = 0
    while offset is not None:
        page = _sib(w, evidence_ref=ref, members_offset=offset, members_limit=limit)
        assert "error" not in page, page
        out += page["members"]
        offset = page["members_next_offset"]
    return out


def _group(w: World, ref: str, **kw: Any) -> dict[str, Any]:
    out = _sib(w, evidence_ref=ref, **kw)
    assert "error" not in out, out
    return out


# ── the shape ────────────────────────────────────────────────────────────────────────────────


def test_the_sink_name_is_part_of_the_shape(world: World) -> None:
    """T1: strcpy and memcpy calls of one pattern and one kind are two groups.

    MUTATION (verified RED): key the shape by fingerprint + kind only -> memcpy joins strcpy."""
    strcpy = _group(world, LISTED)
    assert strcpy["member_count"] == len(GROUP_A) == 7
    refs = {m["evidence_ref"] for m in _members(world, LISTED)}
    assert refs == set(GROUP_A)
    assert MEMCPY not in refs
    assert _group(world, MEMCPY)["member_count"] == 1


def test_a_copy_groups_by_its_length_kind_and_a_command_by_its_source_kind(world: World) -> None:
    """T2: one sink, one pattern: a copy whose length kind differs (const / source_len, neither
    recording a source kind) is another group; a command call groups by its source kind, and a
    length kind it happens to carry does not split it.

    MUTATION (verified RED): read source_kind for copy/format too -> const joins source_len.
    MUTATION (verified RED): read size_kind for every class -> the two free_string calls split."""
    assert _group(world, STRCPY_CONST)["member_count"] == 1
    assert _group(world, LISTED)["shape"]["kind"] == "source_len"
    free = _group(world, SYSTEM_FREE[0])
    assert free["member_count"] == 2
    assert {m["evidence_ref"] for m in _members(world, SYSTEM_FREE[0])} == set(SYSTEM_FREE)
    assert free["shape"]["kind"] == "free_string"
    assert _group(world, SYSTEM_SAFE)["member_count"] == 1


def test_a_call_recorded_twice_is_one_member(world: World) -> None:
    """T3: UNLISTED[0] has two instance rows (and so two rows in the view): one member, read once.

    MUTATION (verified RED): count members per instance row -> 8."""
    rows = world.atlas.execute(
        "SELECT COUNT(*) FROM instance WHERE evidence_ref = ?", (UNLISTED[0],)
    ).fetchone()[0]
    assert rows == 2
    g = _group(world, LISTED)
    assert g["member_count"] == 7
    assert g["by_landing"]["persisted"] == {"-": 4}
    assert [m["evidence_ref"] for m in _members(world, LISTED)].count(UNLISTED[0]) == 1


def test_a_group_is_one_run_and_one_side(world: World) -> None:
    """T3b: runC holds libx's own content with a strcpy call of the same shape: no group of this
    diff draws from it. A B-side call is grouped with B's calls, by runB and B's content.

    MUTATION (verified RED): drop the run from the enumeration -> runC's call joins (8).
    MUTATION (verified RED): always enumerate side a -> a B ref is not found among A's calls."""
    assert world.atlas.execute(
        "SELECT COUNT(*) FROM instance WHERE source_run_id = 'runC' AND binary_content_hash = ?",
        (SHA_A,),
    ).fetchone()[0]
    assert _group(world, LISTED)["member_count"] == 7
    b = _group(world, B_LISTED)
    assert (b["side"], b["member_count"]) == ("b", 4)
    assert all(m["evidence_ref"].startswith("runB#") for m in _members(world, B_LISTED))


# ── who is a member ──────────────────────────────────────────────────────────────────────────


def test_calls_to_a_wrapper_are_members_and_function_level_candidates_are_not(
    world: World,
) -> None:
    """T4: the wrapper_callsite calls form a group of their own (the wrapper's shape); a
    function-level candidate is in no group, and as an input it is not a member. The strcpy
    group counts its function-level siblings beside it, once per ref.

    MUTATION (verified RED): count function-level candidates as members -> FALLBACK / DEGRADED
    join the strcpy group (9). MUTATION (verified RED): leave wrapper_callsite out of the members
    -> a wrapper_callsite input is not a member."""
    wrapped = _group(world, WRAPPED[0])
    assert wrapped["member_count"] == 4
    assert wrapped["input"]["key_granularity"] == "wrapper_callsite"
    assert {m["evidence_ref"] for m in _members(world, WRAPPED[0])} == {*WRAPPED, WRAPPED_OLD}
    assert _group(world, LISTED)["member_count"] == 7
    for ref, gran in (
        (WRAPPER_FN, "wrapper"),
        (FALLBACK, "function_fallback"),
        (DEGRADED, "degraded_out_of_body"),
    ):
        out = _group(world, ref)
        assert out.get("not_a_member") is True, ref
        assert out["key_granularity"] == gran
        assert "member_count" not in out and "by_landing" not in out
    bounds = _group(world, LISTED)["sibling_set_bounds"]
    assert bounds["excluded_non_callsite"] == {
        "wrapper": 0,
        "function_fallback": 1,
        "degraded_out_of_body": 1,  # two instance rows, one ref
    }
    assert _group(world, WRAPPED[0])["sibling_set_bounds"]["excluded_non_callsite"] == {
        "wrapper": 1,
        "function_fallback": 0,
        "degraded_out_of_body": 0,
    }


def test_excluded_non_callsite_counts_by_sink_and_kind_not_sink_alone(world: World) -> None:
    """``excluded_non_callsite`` counts the function-level candidates of the GROUP's shape — its
    sink AND its kind. A function-level candidate with the same sink (strcpy) but another kind (a
    const length, not source_len) is a different shape and is not counted beside this group.

    MUTATION (audit M10): count by sink alone, dropping the kind test -> the const-kind fallback
    joins the source_len group's excluded count -> RED.
    """
    assert (
        _group(world, LISTED)["sibling_set_bounds"]["excluded_non_callsite"]["function_fallback"]
        == 1
    )
    # same sink (strcpy), different kind (const length, not source_len): a different shape.
    world.inst("runA", _ref("runA", "00032000", "copy"), "copy", "strcpy", CONST)
    world.commit()
    pv._clear_view_caches()
    excluded = _group(world, LISTED)["sibling_set_bounds"]["excluded_non_callsite"]
    assert excluded["function_fallback"] == 1, (
        "a same-sink, different-kind candidate is not counted"
    )


def test_the_calls_to_wrappers_are_counted_per_wrapper(world: World) -> None:
    """d-4: the wrapper is not part of the shape; its entry is on each member and counted on the
    group, by name when an older hunt recorded no address."""
    assert _group(world, WRAPPED[0])["by_wrapper"] == {
        "00030000": 2,
        "00031000": 1,
        "name:old_cmd": 1,
    }
    by_ref = {m["evidence_ref"]: m for m in _members(world, WRAPPED[0])}
    assert by_ref[WRAPPED[0]]["wrapper"] == {"name": "run_cmd", "entry": "00030000"}
    assert by_ref[WRAPPED_OLD]["wrapper"] == {"name": "old_cmd", "entry": None}
    assert "by_wrapper" not in _group(world, LISTED)


def test_a_function_level_input_gets_every_shape_it_has(world: World) -> None:
    """T11: the degraded ref has two shapes. strcpy / source_len has a group on this side; memcpy
    / const has none, and says so with a null group_ref and 0 members, never another group.

    MUTATION (verified RED): return only the first shape -> one key. MUTATION (verified RED): give
    a shape with no member the group_ref of its name -> a group_ref where there is no group."""
    out = _group(world, DEGRADED)
    strcpy = _group(world, LISTED)
    keys = {k["sink_anchor"]: k for k in out["f2_keys"]}
    assert set(keys) == {"strcpy", "memcpy"}
    assert keys["strcpy"]["group_ref"] == strcpy["group_ref"]
    assert keys["strcpy"]["member_count"] == 7
    assert keys["memcpy"]["group_ref"] is None
    assert keys["memcpy"]["member_count"] == 0
    assert out["f2_keys"] == sorted(out["f2_keys"], key=lambda k: k["f2_key"])
    page = _sib(world, evidence_ref=DEGRADED, members_offset=0)
    assert "error" in page and "members" not in page


# ── where each member landed ─────────────────────────────────────────────────────────────────


def test_each_member_lands_where_the_view_puts_its_row(world: World) -> None:
    """T5 / T6: listed persisted 1, not listed (aligned, similarity 1) 3, R 1, P 1 (``absent``,
    the view's own subclass), and B with the subclass only the entry's context gives
    (sink_name_absent_in_paired_callees). The P member has no pair, so it is in neither similarity
    count.

    MUTATION (verified RED): read every member's row from compute_sink_overlay + row_landing with
    no entry context -> the B member loses sink_name_absent_in_paired_callees.
    MUTATION (verified RED): count a member with no pair as below 1 -> 4.
    MUTATION (verified RED): leave not-listed members uncounted -> not_listed_sim1 0."""
    g = _group(world, LISTED)
    assert g["by_landing"] == {
        "B": {"sink_presence_signal:sink_name_absent_in_paired_callees": 1},
        "P": {"absent": 1},
        "R": {"alignment_low_confidence": 1},
        "persisted": {"-": 4},
    }
    assert g["not_listed_sim1"] == 3
    assert g["similarity_below_1"] == 3  # 0.8, 0.4, 0.7
    assert g["states_unreadable"] == {}
    by_ref = {m["evidence_ref"]: m for m in _members(world, LISTED)}
    assert by_ref[CTX_MEMBER]["subclass"] == (
        "sink_presence_signal:sink_name_absent_in_paired_callees"
    )
    assert by_ref[P_MEMBER]["similarity"] is None
    assert [by_ref[r]["listed"] for r in UNLISTED] == [False] * 3
    assert all(by_ref[r]["similarity"] == 1.0 for r in UNLISTED)


def test_similarity_below_one_counts_an_unrecorded_similarity(world: World) -> None:
    """``similarity_below_1`` counts members whose pair's similarity is below 1 OR unrecorded — a
    NULL similarity cannot be called identical, as the tool says ("below 1 or unrecorded"). The
    existing members cover only explicit < 1 values (0.8 / 0.4 / 0.7).

    MUTATION (audit M14): count only ``similarity < 1`` and drop the None case -> a member whose
    pair records no similarity is left out -> RED.
    """
    assert _group(world, LISTED)["similarity_below_1"] == 3
    fa, fb = "0003e000", "0003f000"
    world.pair(fa, fb, 0.97, None)  # aligned, similarity unrecorded (NULL)
    world.inst("runA", _ref("runA", fa, "copy", "0x10"), "copy", "strcpy", SRC)
    world.inst("runB", _ref("runB", fb, "copy", "0x10"), "copy", "strcpy", SRC)
    world.im(_addr(fa, "0x10"), _addr(fb, "0x10"), fa)
    world.fn("a", fa, ["strcpy"])
    world.fn("b", fb, ["strcpy"])
    world.commit()
    pv._clear_view_caches()
    assert _group(world, LISTED)["similarity_below_1"] == 4, "a NULL similarity counts too"


def test_no_state_word_is_made_up(world: World) -> None:
    """T5: the group object's keys are fixed, and every landing / subclass is one the view gives —
    ``absent`` only as the P subclass the view passes through, never as a state of its own.

    MUTATION (verified RED): add a ``changed`` / ``unchanged`` count -> the key set differs."""
    g = _group(world, LISTED)
    assert set(g) == {
        "diff_id",
        "side",
        "binary",
        "input",
        "group_ref",
        "shape",
        "member_count",
        "by_landing",
        "not_listed_sim1",
        "similarity_below_1",
        "states_unreadable",
        "sibling_set_bounds",
        "members_page_ref",
        "source_stale",
        "source_stale_reason",
        "note",
    }
    built = pv.build_diff_view(world.atlas, DIFF)
    assert built is not None
    landings = {(v["landing"], v["subclass"] or "-") for e in built.placed for v in e.row_views}
    assert {(k, s) for k, subs in g["by_landing"].items() for s in subs} <= landings
    words = re.findall(r"\w+", json.dumps([g, _members(world, LISTED)]))
    assert not {"changed", "unchanged", "removed", "added"} & set(words)


def test_a_diff_unreadable_as_a_whole_counts_every_member_unreadable(
    tmp_path: Path, current: None
) -> None:
    """T14: a failed diff, and a diff whose tools disagree, place nothing. Their members are
    counted under the view's banners — never as not listed, never in by_landing — and the input is
    still checked against the run's candidates, not against the (empty) view.

    MUTATION (verified RED): count a member with no row as not listed -> not_listed_sim1 7."""
    for kw, banner in (
        ({"diff_ok": 0}, "diff_undetermined:diff_failed"),
        ({"version_skew": 1}, "diff_undetermined:version_skew"),
    ):
        pv._clear_view_caches()
        path = tmp_path / banner.split(":")[1]
        path.mkdir()
        w = World(path, **kw)
        _build(w)
        g = _group(w, LISTED)
        assert g["states_unreadable"] == {banner: 7}
        assert (g["by_landing"], g["not_listed_sim1"], g["similarity_below_1"]) == ({}, 0, 0)
        assert g["sibling_set_bounds"]["undetermined_alignment_n"] == 0
        members = _members(w, LISTED)
        assert {m["landing"] for m in members} == {None}
        assert {m["listed"] for m in members} == {None}
        assert all(m["unreadable"] == [banner] for m in members)


# One member's state read straight from a view (``_states``). The view represents each instance row
# of the binary once, so a built view never holds a member with no row, nor one call's records in
# two entries; these views are the real one with a real entry left out, or one real row re-pointed
# at another call (that call recorded a second time). Every object is the real dataclass, changed
# by dataclasses.replace, so a renamed field breaks the test rather than leaving a stale stub.


def _view_and_calls(w: World) -> tuple[pv.BuiltDiff, dict[str, ss._Call]]:
    """The diff's real view and side A's real calls, by evidence_ref."""
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None and built.withheld is None
    return built, {c.ref: c for c in ss._calls(w.atlas, "runA", SHA_A) if c.ref}


def _placed(built: pv.BuiltDiff, ref: str) -> tuple[pv._Entry, SinkOverlayRow, dict[str, Any]]:
    """The one (entry, row, row view) the view places for side A's ``ref``."""
    hits = ss._row_index(built, "a", {ref}).get(ref, [])
    assert len(hits) == 1, (ref, hits)
    return hits[0]


def _with_rows(
    built: pv.BuiltDiff,
    entry: pv._Entry,
    rows: list[SinkOverlayRow],
    views: list[dict[str, Any]],
) -> pv.BuiltDiff:
    """``built`` with ``entry`` holding ``rows`` (read as ``views``); every other entry as built."""
    new = dataclasses.replace(entry, rows=rows, row_views=views)
    return dataclasses.replace(built, placed=[new if e is entry else e for e in built.placed])


def test_a_member_with_no_row_in_the_view_is_unreadable_no_row_in_view(world: World) -> None:
    """A member the view holds no row for reads ``no_row_in_view`` — not a landing, and not the
    other unreadable reason. The view is the real one without LISTED's entry; another member, still
    placed, reads its own row, so the index is not simply empty.

    MUTATION (verified RED, 1 failed): give every member with no single reading
    ``several_rows_in_view`` -> LISTED reads several_rows_in_view."""
    built, calls = _view_and_calls(world)
    entry, _row, _view = _placed(built, LISTED)
    without = dataclasses.replace(built, placed=[e for e in built.placed if e is not entry])
    states = ss._states(without, "a", [calls[LISTED], calls[UNLISTED[1]]])
    gone = states[LISTED]
    assert gone.unreadable == ["no_row_in_view"]
    assert (gone.entry, gone.row, gone.view) == (None, None, None)
    kept = states[UNLISTED[1]]
    assert kept.unreadable == []
    assert kept.view is _placed(built, UNLISTED[1])[2]


def test_a_member_whose_rows_sit_apart_or_land_apart_is_unreadable_several_rows(
    world: World,
) -> None:
    """A call recorded twice has a row per record. They read as one only when they sit in one entry
    AND land alike. Rows in two entries (landing alike or not), or landing differently in one
    entry, leave the member ``several_rows_in_view`` — never read as its first row. Each view is the
    real one with one real row (and its view) re-pointed at LISTED as its second record.

    MUTATION (verified RED, 1 failed): read a member with any row as its first row
    (``if hits:``) -> LISTED reads as its persisted row."""
    built, calls = _view_and_calls(world)
    listed_entry, listed_row, listed_view = _placed(built, LISTED)
    r_entry, r_row, r_view = _placed(built, R_MEMBER)
    u_entry, u_row, u_view = _placed(built, UNLISTED[1])
    assert len(r_entry.rows) == len(u_entry.rows) == 1
    assert len({listed_entry.entry_id, r_entry.entry_id, u_entry.entry_id}) == 3
    assert [v["landing"] for v in (listed_view, r_view, u_view)] == ["persisted", "R", "persisted"]

    def again(row: SinkOverlayRow, view: dict[str, Any]) -> tuple[SinkOverlayRow, dict[str, Any]]:
        return dataclasses.replace(row, a_ref=LISTED), {**view, "a_ref": LISTED}

    r2, r2_view = again(r_row, r_view)
    u2, u2_view = again(u_row, u_view)
    views = {
        "two entries, landing apart": _with_rows(built, r_entry, [r2], [r2_view]),
        "two entries, landing alike": _with_rows(built, u_entry, [u2], [u2_view]),
        "one entry, landing apart": _with_rows(
            built, listed_entry, [listed_row, r2], [listed_view, r2_view]
        ),
    }
    for name, view in views.items():
        assert len(ss._row_index(view, "a", {LISTED}).get(LISTED, [])) == 2, name
        st = ss._states(view, "a", [calls[LISTED]])[LISTED]
        assert st.unreadable == ["several_rows_in_view"], name
        assert (st.entry, st.row, st.view) == (None, None, None), name


def test_a_call_recorded_twice_in_one_entry_landing_alike_reads_as_one(world: World) -> None:
    """The counterweight, on the view as built: UNLISTED[0] has two instance rows, so two rows in
    one entry, landing alike. They read as one — its first row, readable.

    MUTATION (verified RED, 5 failed): read a member only when it has exactly one row
    (``len(hits) == 1``) -> UNLISTED[0] reads several_rows_in_view."""
    built, calls = _view_and_calls(world)
    hits = ss._row_index(built, "a", {UNLISTED[0]}).get(UNLISTED[0], [])
    assert len(hits) == 2
    assert len({e.entry_id for e, _r, _v in hits}) == 1
    assert len({(v["landing"], v["subclass"]) for _e, _r, v in hits}) == 1
    st = ss._states(built, "a", [calls[UNLISTED[0]]])[UNLISTED[0]]
    assert st.unreadable == []
    first_entry, first_row, first_view = hits[0]
    assert st.entry is first_entry and st.row is first_row and st.view is first_view


# ── what can make the group look smaller ─────────────────────────────────────────────────────


def test_the_bounds_are_each_counted(world: World) -> None:
    """T8: each of the bounds has its value. A binary whose content is on the other side too reads
    identical_both_sides even when a same-named binary was diffed (/fw/opt/libx) — the order
    list_diff_blindspots decides it in, so one binary gets one reason in both.

    MUTATION (verified RED, 1 failed): decide a diffed name before identical content ->
    /fw/opt/libx moves from identical to shadowed -> RED. MUTATION (verified RED): leave the other
    side's names out -> libold reads binary_not_diffed. MUTATION (verified RED): count binaries
    by path -> libonly, one content at two paths, counts 2. MUTATION (verified RED):
    undetermined_alignment_n not from by_landing.R -> 0."""
    bounds = _group(world, LISTED)["sibling_set_bounds"]
    assert bounds["recall_gaps"] == {"families": ["wide_char_string"], "state": "read"}
    assert bounds["undetermined_alignment_n"] == 1
    assert bounds["binaries_not_diffed"] == {
        "shadowed_by_name_collision": {"binaries": 1, "calls": 1},
        "identical_both_sides": {"binaries": 2, "calls": 2},
        "other_side_same_name_not_diffed": {"binaries": 1, "calls": 1},
        "binary_not_diffed": {"binaries": 1, "calls": 2},
    }
    assert bounds["unkeyed"] == {
        "no_function_address": 1,
        "no_structural_fingerprint": 1,
        "no_sink_name": 1,
    }


def test_recall_gaps_that_cannot_be_read_are_null_never_empty(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T8b: a cut-short list makes the reading partial (what was read is still named); a run with
    no analysis.db, or sources not shown current, make it unreadable — families null, which is
    not how a binary with no such call looks ([]).

    MUTATION (verified RED): return [] when the lists cannot be read -> families [] on an
    unreadable side."""
    world.fn("a", "00031000", ["vswprintf"], trunc=1)
    world.commit()
    gaps = _group(world, LISTED)["sibling_set_bounds"]["recall_gaps"]
    assert gaps == {"families": ["wide_char_string"], "state": "partial:1"}

    stale = {"source_stale": True, "source_stale_reason": "x", "toolchain_checked": True}
    monkeypatch.setattr(pv, "diff_source_staleness", lambda atlas, diff_id: stale)
    pv._clear_view_caches()
    gaps = _group(world, LISTED)["sibling_set_bounds"]["recall_gaps"]
    assert gaps == {"families": None, "state": "unreadable:source_stale"}

    monkeypatch.undo()
    monkeypatch.setattr(mcp_cli, "installed_commit", lambda: UNKNOWN_VERSION)
    monkeypatch.setattr(
        pv,
        "diff_source_staleness",
        lambda atlas, diff_id: {**stale, "source_stale": False, "source_stale_reason": None},
    )
    world.atlas.execute("UPDATE run SET analysis_db_path = NULL WHERE run_id = 'runA'")
    world.commit()
    pv._clear_view_caches()
    gaps = _group(world, LISTED)["sibling_set_bounds"]["recall_gaps"]
    assert gaps == {"families": None, "state": "unreadable:analysis_db_unavailable"}


def test_recall_gaps_are_three_state_on_truncation_callees_and_source_stale(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T8b's three-state edges: ``truncated`` NOT RECORDED (None, an old analysis.db) and a callee
    list that cannot be read (None) each make the reading partial, not read; ``source_stale``
    anything but False — None included — makes it unreadable. Asserting only the recorded / True
    forms would miss a check narrowed to truthiness.

    MUTATIONs (audit M01/M02/M03b): ``fn.truncated is not False`` -> ``fn.truncated`` (None reads as
    not truncated); drop the ``fn.callees is None`` guard; ``source_stale is not False`` ->
    ``source_stale`` (None reads as current) — each goes RED on the None case asserted here.
    """

    def gaps() -> dict[str, Any]:
        pv._clear_view_caches()
        return _group(world, LISTED)["sibling_set_bounds"]["recall_gaps"]

    assert gaps() == {"families": ["wide_char_string"], "state": "read"}

    # M01: truncation not recorded (NULL) is still partial — the list may have been cut.
    world.adb["a"].execute(
        "UPDATE functions SET callees_truncated = NULL WHERE address = '00030000'"
    )
    world.commit()
    assert gaps() == {"families": ["wide_char_string"], "state": "partial:1"}

    # M02: a callee list that cannot be read (NULL) is partial, and reads no family from it.
    world.adb["a"].execute(
        "UPDATE functions SET callees_truncated = 0, callees = NULL WHERE address = '00030000'"
    )
    world.commit()
    assert gaps() == {"families": [], "state": "partial:1"}

    # M03b: source_stale None (not False) is unreadable, exactly as True is.
    monkeypatch.setattr(
        pv,
        "diff_source_staleness",
        lambda atlas, diff_id: {
            "source_stale": None,
            "source_stale_reason": None,
            "toolchain_checked": True,
        },
    )
    assert gaps() == {"families": None, "state": "unreadable:source_stale"}


def test_a_binary_with_no_such_call_reads_an_empty_list(world: World) -> None:
    """The counterweight to T8b: read in full with no recall-gap sink -> [] and ``read``."""
    world.adb["a"].execute("DELETE FROM functions WHERE address = '00030000'")
    world.commit()
    gaps = _group(world, LISTED)["sibling_set_bounds"]["recall_gaps"]
    assert gaps == {"families": [], "state": "read"}


# ── the group's name ─────────────────────────────────────────────────────────────────────────


def test_group_ref_is_stable_and_names_its_side(world: World) -> None:
    """T-gr: ``{diff_id}#f2:{key}:{side}@{fingerprint version}/f2-v1``, the fingerprint version as
    the pattern rows record it; the same from every member and every call; the same shape on the
    two sides is two names.

    MUTATION (verified RED): leave the side out of group_ref -> A and B read the same.
    MUTATION (verified RED): take the code's fingerprint version -> not the rows' one."""
    a = _group(world, LISTED)["group_ref"]
    assert re.fullmatch(rf"{re.escape(DIFF)}#f2:[0-9a-f]{{16}}:a@{FPV}/f2-v1", a)
    assert {_group(world, r)["group_ref"] for r in GROUP_A} == {a}
    assert _group(world, LISTED)["group_ref"] == a
    b = _group(world, B_LISTED)["group_ref"]
    assert b != a
    assert b == a.replace(":a@", ":b@")


# ── the input ────────────────────────────────────────────────────────────────────────────────


def test_a_candidate_anchor_names_the_same_group(world: World) -> None:
    """A candidate anchor names its A ref when it has one, else its B ref."""
    built = pv.build_diff_view(world.atlas, DIFF)
    assert built is not None
    rows = {r.a_ref or r.b_ref: r for e in built.placed for r in e.rows}
    anchor = f"runA::runB#candidate#{_subject_key(rows[LISTED])}"
    by_anchor = _sib(world, candidate_anchor=anchor)
    by_ref = _group(world, LISTED)
    assert {**by_anchor, "members_page_ref": None} == {**by_ref, "members_page_ref": None}
    assert by_anchor["members_page_ref"]["candidate_anchor"] == anchor


@pytest.mark.parametrize(
    ("kw", "fragment"),
    [
        ({}, "exactly one of"),
        ({"evidence_ref": LISTED, "candidate_anchor": "x"}, "exactly one of"),
        ({"evidence_ref": ""}, "non-empty string"),
        ({"evidence_ref": LISTED, "members_offset": -1}, "members_offset"),
        ({"evidence_ref": LISTED, "members_offset": True}, "members_offset"),
        ({"evidence_ref": LISTED, "members_limit": 0}, "members_limit"),
        ({"evidence_ref": "runZ#deadbeef:00001000@copy@0x10"}, "not a ref of this diff's runs"),
        ({"evidence_ref": "runA#deadbeef:0000ffff@copy@0x10"}, "is not a candidate of 'libx'"),
        ({"candidate_anchor": "runX::runB#candidate#k"}, "not an anchor of this diff's run pair"),
        ({"candidate_anchor": "runA::runB#function_pair#libx::1::2"}, "is a function_pair"),
        ({"evidence_ref": "runA#fn12"}, "cannot be given a shape: no_function_address"),
        ({"evidence_ref": LISTED, "members_offset": 7}, "past the group's 7 members"),
        ({"diff_id": "runA::runB::nope", "evidence_ref": LISTED}, "no diff"),
    ],
)
def test_an_input_that_names_no_call_of_this_diff_is_refused(
    world: World, kw: dict[str, Any], fragment: str
) -> None:
    """r-3: a call is checked against the side's candidates, and every refusal says why."""
    out = _sib(world, **kw)
    assert fragment in out.get("error", ""), out


# ── the members page ─────────────────────────────────────────────────────────────────────────


def test_members_are_paged_in_a_fixed_order_never_by_landing(world: World) -> None:
    """T9: no member is in the group object; the pages, walked, hold every member once, in
    (function entry, call address, evidence_ref) order — which here is not landing order.

    MUTATION (verified RED): order the members by landing -> the walk is out of address order.
    MUTATION (verified RED): put the members in the group object -> the key set differs (T5)."""
    g = _group(world, LISTED)
    assert "members" not in g
    walked = _members(world, LISTED, limit=2)
    assert len(walked) == len({m["evidence_ref"] for m in walked}) == g["member_count"]
    keys = [(m["function_entry"], m["call_addr"], m["evidence_ref"]) for m in walked]
    assert keys == sorted(keys)
    landings = [m["landing"] for m in walked]
    assert landings != sorted(landings, key=str)
    first = _sib(world, evidence_ref=LISTED, members_offset=0, members_limit=2)
    assert first["members_order"] == ss.MEMBERS_ORDER
    assert first["members_next_offset"] == 2


def test_a_member_carries_the_handles_that_take_it(world: World) -> None:
    """T15: a member in a listed entry carries entry_id + row_ref (what promote takes) and its
    candidate anchor (what annotate_diff takes) — and both are taken; a member in a pair the view
    does not list carries neither, because neither tool takes it.

    MUTATION (verified RED): give a not-listed member its candidate anchor -> it carries one."""
    by_ref = {m["evidence_ref"]: m for m in _members(world, LISTED)}
    listed = by_ref[LISTED]
    assert (listed["entry_id"], listed["row_ref"]) == ("pair:00001000:00002000", LISTED)
    da.capture_diff_basis(world.atlas, DIFF, listed["candidate_anchor"])
    origin = da.check_promotion(
        world.atlas, diff_id=DIFF, entry_id=listed["entry_id"], row_ref=listed["row_ref"]
    )
    assert origin
    for ref in UNLISTED:
        m = by_ref[ref]
        assert not {"entry_id", "row_ref", "candidate_anchor"} & set(m), m
    built = pv.build_diff_view(world.atlas, DIFF)
    assert built is not None
    row = next(r for e in built.placed for r in e.rows if r.a_ref == UNLISTED[1])
    with pytest.raises(Exception, match="names nothing get_diff_patch_view lists"):
        da.capture_diff_basis(world.atlas, DIFF, f"runA::runB#candidate#{_subject_key(row)}")


def test_a_page_is_cut_to_the_byte_budget_with_its_paging_fields_measured_first() -> None:
    """T9: a members page as the MCP tool returns it is never over the budget, and is full when
    cut. The envelope is swept a byte at a step across a whole member's width, so the page's end
    lands at every byte below the budget; "full" is measured with the paging fields at the
    placeholders the fit measures with (members_truncated false, members_next_offset the wider of
    null and the total), since their final values are narrower.

    MUTATION (verified RED): fit the members without first setting members_next_offset /
    members_truncated to their widest -> a page over the budget."""
    budget = mcp_app._RESPONSE_BYTE_BUDGET
    member = {"evidence_ref": "r" * 300, "landing": "persisted"}
    width = len(json.dumps(member)) + 2
    for total in (999, 99_999):
        held_null = len(json.dumps(total)) <= len(json.dumps(None))
        seen: set[int] = set()
        for pad in range(width):
            result = {
                "diff_id": "d",
                "pad": "x" * (budget - 3 * width - 200 + pad),
                "member_count": total,
                "members_offset": 0,
                "members": [dict(member) for _ in range(5)],
                "members_next_offset": 5,
            }
            out = mcp_app._fit_members(result, 0)
            assert len(json.dumps(out)) <= budget, (total, pad)
            assert out["members_truncated"] is True
            assert out["members_next_offset"] == len(out["members"])
            held = {
                **out,
                "members_next_offset": None if held_null else total,
                "members_truncated": False,
            }
            assert len(json.dumps(held)) <= budget < len(json.dumps(held)) + width
            seen.add(len(json.dumps(held)))
        assert seen == set(range(budget - width + 1, budget + 1))


def test_a_large_group_is_walked_through_the_tool_within_the_budget(
    tmp_path: Path, current: None
) -> None:
    """T9 through the MCP tool: 400 members of one shape, every page within the budget, every
    member once, member_count the same on every page."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 0.8)
    w.fn("a", "00001000", ["strcpy"])
    w.fn("b", "00002000", ["strcpy"])
    for i in range(400):
        w.inst("runA", _ref("runA", "00001000", "copy", hex(16 + 8 * i)), "copy", "strcpy", SRC)
    w.commit()
    tool = mcp_app.make_tools(w.path)["same_shape_siblings"]
    ref = _ref("runA", "00001000", "copy", "0x10")
    assert len(json.dumps(tool(DIFF, evidence_ref=ref))) < 4000
    seen: list[str] = []
    offset: int | None = 0
    pages = 0
    while offset is not None:
        page = tool(DIFF, evidence_ref=ref, members_offset=offset)
        assert len(json.dumps(page)) <= mcp_app._RESPONSE_BYTE_BUDGET
        assert page["member_count"] == 400
        seen += [m["evidence_ref"] for m in page["members"]]
        offset = page["members_next_offset"]
        pages += 1
    assert pages > 1 and len(seen) == len(set(seen)) == 400


# ── the two ways in ──────────────────────────────────────────────────────────────────────────


def _cli(w: World, *args: str) -> dict[str, Any]:
    out = CliRunner().invoke(
        mcp_cli.fact, ["same-shape-siblings", "--diff-id", DIFF, *args, "--atlas", str(w.path)]
    )
    assert out.exit_code == 0, out.output
    result: dict[str, Any] = json.loads(out.output)
    return result


def test_the_command_line_and_mcp_give_the_same_answer(world: World) -> None:
    """T10: the same group object, the same members page, the same not_a_member answer.

    MUTATION (verified RED): pass the CLI another reading (members_limit) -> its page differs."""
    tool = mcp_app.make_tools(world.path)["same_shape_siblings"]
    assert _cli(world, "--evidence-ref", LISTED) == tool(DIFF, evidence_ref=LISTED)
    page = tool(DIFF, evidence_ref=LISTED, members_offset=0)
    assert page["members_truncated"] is False
    cli_page = _cli(world, "--evidence-ref", LISTED, "--members-offset", "0")
    assert {**cli_page, "members_truncated": False} == page
    assert _cli(world, "--evidence-ref", DEGRADED) == tool(DIFF, evidence_ref=DEGRADED)


@pytest.mark.parametrize("side", ["a", "b"])
def test_a_stale_run_is_refused_on_both_ways_in(world: World, side: str) -> None:
    """T10: a diff with a provably stale side is refused by the command line as by MCP, with the
    same refusal keys.

    MUTATION (verified RED): drop the read-layer refusal -> the command line answers."""
    run = "runA" if side == "a" else "runB"
    world.atlas.execute("UPDATE run SET build_hash = 'other' WHERE run_id = ?", (run,))
    world.commit()
    cli = _cli(world, "--evidence-ref", LISTED)
    mcp = mcp_app.make_tools(world.path)["same_shape_siblings"](DIFF, evidence_ref=LISTED)
    for out in (cli, mcp):
        assert out.get("stale_scan", {}).get("axis") == "extraction", out
        assert out.get("stale_scan", {}).get("diff_side") == side
        assert "remedy" in out and out["diff_id"] == DIFF
    assert cli.get("stale_scan") == mcp["stale_scan"] and cli.get("remedy") == mcp["remedy"]


def test_the_mcp_diff_tools_refuse_a_stale_diff_key_for_key(world: World) -> None:
    """A diff whose side is a provably stale scan is refused the SAME way by every MCP diff tool:
    same_shape_siblings and get_diff_patch_view both return the one _refuse_stale_diff dict, key for
    key — stale_scan and run_lineage and all. A weaker refusal on one tool would be an open door
    beside a locked one.

    MUTATION (audit M23): give same_shape_siblings its own stale refusal (the read layer's, with
    other keys) instead of the shared _refuse_stale_diff -> the two dicts differ -> RED.
    """
    world.atlas.execute("UPDATE run SET build_hash = 'other' WHERE run_id = 'runA'")
    world.commit()
    tools = mcp_app.make_tools(world.path)
    sib = tools["same_shape_siblings"](DIFF, evidence_ref=LISTED)
    view = tools["get_diff_patch_view"](DIFF)
    assert sib.get("stale_scan") and "run_lineage" in sib, sib
    assert sib == view, "both MCP diff tools must refuse a stale diff through the one shared gate"


# ── neutral, and outside the hashed code ─────────────────────────────────────────────────────

_JUDGEMENT_WORDS = {
    "complete",
    "completed",
    "incomplete",
    "completeness",
    "bypass",
    "bypassable",
    "fix",
    "fixed",
    "fixes",
    "patched",
    "unpatched",
    "remediated",
    "repaired",
    "blocked",
    "safe",
    "unsafe",
    "vulnerable",
    "exploitable",
}


def test_nothing_it_says_is_a_judgement(world: World) -> None:
    """T12: no judgement word in what it returns, in the MCP tool's description or in the
    command's help.

    MUTATION (verified RED): word the note as 'the group is complete' -> RED."""
    texts = [
        json.dumps(_group(world, LISTED)),
        json.dumps(_members(world, LISTED)),
        json.dumps(_group(world, DEGRADED)),
        json.dumps(_group(world, WRAPPED[0])),
        mcp_app.make_tools(world.path)["same_shape_siblings"].__doc__ or "",
        CliRunner().invoke(mcp_cli.fact, ["same-shape-siblings", "--help"]).output,
        ss.__doc__ or "",
    ]
    for text in texts:
        found = {w.lower() for w in re.findall(r"\w+", text)} & _JUDGEMENT_WORDS
        assert not found, (found, text[:200])


def test_the_module_is_outside_the_code_a_diff_or_baseline_is_versioned_by() -> None:
    """T13 (the part a test can hold): the module is not hashed, and no hashed module imports it.

    MUTATION (verified RED): import it from a hashed module -> RED."""
    import ast

    from treasure_map.lib.diff import code_version as cv

    name = "lib.query.same_shape_siblings"
    entries = cv.DIFF_CODE_ENTRIES + cv.OVERLAY_CODE_ENTRIES
    assert all(e.partition(":")[0] != name for e in entries)
    package = Path(cv.__file__).resolve().parents[2]
    for module in sorted({e.partition(":")[0] for e in entries}):
        tree = ast.parse(cv._module_path(package, module).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported = {node.module, *(f"{node.module}.{a.name}" for a in node.names)}
                assert f"treasure_map.{name}" not in imported, module
