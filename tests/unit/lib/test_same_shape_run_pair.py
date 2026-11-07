# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The same-shape group across every binary of a run pair's two runs
(lib/query/same_shape_run_pair), asked of same_shape_siblings by passing the run pair as its
diff_id.

Zero real data: every run, binary, address, literal and function name is synthetic. Two runs, six
diffed binaries and one binary no diff covers; each run has its own analysis.db holding the
binaries' analysis status, function names and string references.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_same_shape_siblings import (  # noqa: F401  (fixtures used by name)
    _CURRENT,
    _JUDGEMENT_WORDS,
    COMMIT,
    _ref,
    _servable,
    current,
)
from treasure_map import mcp_app
from treasure_map.lib.analyze.ghidra_runner import current_pass_version
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.query import same_shape_run_pair as rp
from treasure_map.lib.query import same_shape_siblings as ss
from treasure_map.lib.storage.connection import open_db
from treasure_map.version import UNKNOWN_VERSION

PAIR = "runA::runB"
FPV = "fpv-test"
FREE = json.dumps({"source_kind": "free_string"})
RARE = "at-cmd RARE=%s"  # referenced by the input's function and one function of each side
COMMON = "common/path"
OTHER = "other/thing"

# binary -> (content hash on A, content hash on B); None = the diff records no hash for that side.
BINS: dict[str, tuple[str, str | None]] = {
    "libx": ("1" * 64, "2" * 64),
    "aa_other": ("3" * 64, "4" * 64),
    "zz_target": ("5" * 64, "6" * 64),
    "libz": ("7" * 64, None),
    "libfail": ("8" * 64, "9" * 64),
    "libmiss": ("e" * 64, "f" * 64),
}
NOT_DIFFED = ("c" * 64, "d" * 64)  # libnd: in both runs, no diff covers it
FAILED_B = "9" * 64  # libfail on B: its analysis is recorded as failed
MISSING_B = "f" * 64  # libmiss on B: not in B's analysis.db

INPUT = _ref("runA", "00001000", "cmd", "0x10", "11111111")
TARGET = _ref("runB", "00004000", "cmd", "0x10", "66666666")  # shares RARE, in the last diff
TARGET_A = _ref("runA", "00004000", "cmd", "0x10", "55555555")
TWO_COMMON = _ref("runB", "00009000", "cmd", "0x10", "44444444")  # shares COMMON + OTHER
MISS = _ref("runB", "00001000", "cmd", "0x10", "ffffffff")
FAIL = _ref("runB", "00001000", "cmd", "0x10", "99999999")
ND = _ref("runB", "00001000", "cmd", "0x10", "dddddddd")
FALLBACK = _ref("runA", "00007000", "cmd", None, "11111111")


def _diff(name: str) -> str:
    return f"{PAIR}::{name}"


class PairWorld:
    def __init__(self, tmp: Path) -> None:
        self.path = tmp / "atlas.db"
        self.atlas = open_atlas(self.path)
        self.atlas.execute("PRAGMA synchronous = OFF")
        self.build = current_pass_version()
        self.adb: dict[str, sqlite3.Connection] = {}
        self.bid: dict[str, int] = {}
        for side, run in (("a", "runA"), ("b", "runB")):
            db = tmp / f"analysis_{side}.db"
            conn = open_db(db)
            conn.execute("PRAGMA synchronous = OFF")
            self.adb[side] = conn
            self.atlas.execute(
                "INSERT INTO run (run_id, hunt_commit, build_hash, hunt_instances, "
                "analysis_db_path) VALUES (?, ?, ?, 10, ?)",
                (run, COMMIT, self.build, str(db)),
            )
        i = 0
        for name, (sha_a, sha_b) in [*BINS.items(), ("libnd", NOT_DIFFED)]:
            for side, sha in (("a", sha_a), ("b", sha_b)):
                if sha is None or sha == MISSING_B:
                    continue
                status = "failed" if sha == FAILED_B else "ok"
                cur = self.adb[side].execute(
                    "INSERT INTO binaries (name, sha256, ghidra_status) VALUES (?, ?, ?)",
                    (name, sha, status),
                )
                self.bid[sha] = int(cur.lastrowid or 0)
            if name == "libnd":
                continue
            i += 1
            self.atlas.execute(
                "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id, binary_a, binary_b, "
                "sha256_a, sha256_b, diff_ok, version_skew, callsite_facts_a, callsite_facts_b, "
                "callsite_facts_hash_a, callsite_facts_hash_b, stub_state_a, stub_state_b) "
                "VALUES (?, 'runA', 'runB', ?, ?, ?, ?, 1, 0, 'read', 'read', ?, ?, "
                "'not_applicable', 'not_applicable')",
                (_diff(name), name, name, sha_a, sha_b, self.build, self.build),
            )

    def call(
        self,
        run: str,
        sha: str,
        func: str,
        off: str | None = "0x10",
        *,
        fp: str = "fp_cmd",
        sink: str = "system",
        flow: str = FREE,
        lits: tuple[str, ...] = (),
        cls: str = "cmd",
        sink_class: str = "cmd",
        path: str | None = None,
    ) -> str:
        ref = _ref(run, func, cls, off, sha[:8])
        self.atlas.execute(
            "INSERT INTO instance (pattern_id, evidence_ref, source_run_id, binary_content_hash, "
            "binary_path, sink_anchor, flow_evidence) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                self._pattern(fp, sink_class),
                ref,
                run,
                sha,
                path or f"/fw/bin/{sha[:4]}",
                sink,
                flow,
            ),
        )
        side = "a" if run == "runA" else "b"
        if sha in self.bid:
            self.adb[side].execute(
                "INSERT INTO functions (binary_id, name, address) VALUES (?, ?, ?)",
                (self.bid[sha], f"fn_{func}", f"0x{func}"),
            )
        for lit in lits:
            self.lit(side, sha, func, lit)
        return ref

    def lit(self, side: str, sha: str, func: str, value: str) -> None:
        self.adb[side].execute(
            "INSERT INTO string_refs (binary_id, string_addr, string_value, ref_at, "
            "ref_in_func_addr) VALUES (?, '0x90000', ?, '0x0', ?)",
            (self.bid[sha], value, f"0x{func}"),
        )

    def _pattern(self, fp: str, sink_class: str = "cmd") -> int:
        shape = f"shape_{fp}" if sink_class == "cmd" else f"shape_{fp}_{sink_class}"
        row = self.atlas.execute(
            "SELECT pattern_id FROM pattern WHERE call_sequence_shape = ?", (shape,)
        ).fetchone()
        if row is not None:
            return int(row[0])
        cur = self.atlas.execute(
            "INSERT INTO pattern (source_class, sink_class, call_sequence_shape, "
            "structural_fingerprint, fingerprint_algo_version) VALUES "
            "('external_input', ?, ?, ?, ?)",
            (sink_class, shape, fp, FPV),
        )
        return int(cur.lastrowid or 0)

    def commit(self) -> None:
        for conn in (self.atlas, *self.adb.values()):
            conn.commit()


def _build(w: PairWorld, bulk: int = 12) -> None:
    x_a, x_b = BINS["libx"]
    o_a, o_b = BINS["aa_other"]
    t_a, t_b = BINS["zz_target"]
    assert w.call("runA", x_a, "00001000", lits=(RARE, COMMON, OTHER)) == INPUT
    w.call("runA", x_a, "00003000")
    w.call("runB", str(x_b), "00002000")
    for i in range(bulk):  # many members earlier in the one-diff order, sharing nothing
        w.call("runA", o_a, f"{0x10000 + 0x100 * i:08x}")
        w.call("runB", str(o_b), f"{0x10000 + 0x100 * i:08x}")
    assert w.call("runB", str(o_b), "00009000", lits=(COMMON, OTHER)) == TWO_COMMON
    assert w.call("runB", str(t_b), "00004000", lits=(RARE,)) == TARGET
    assert w.call("runA", t_a, "00004000", lits=(RARE,)) == TARGET_A
    w.call("runA", BINS["libz"][0], "00001000")
    assert w.call("runB", MISSING_B, "00001000") == MISS
    assert w.call("runB", FAILED_B, "00001000") == FAIL
    # No diff covers libnd: its call is a member with diffed false (sharing COMMON), and its
    # literals count toward how many functions of the run reference one (B: COMMON 3, OTHER 2,
    # RARE 1; A: each of the three 2).
    assert w.call("runB", NOT_DIFFED[1], "00001000", lits=(COMMON,)) == ND
    w.lit("b", NOT_DIFFED[1], "00002000", COMMON)
    w.lit("b", NOT_DIFFED[1], "00003000", OTHER)
    w.lit("a", NOT_DIFFED[0], "00002000", COMMON)
    w.lit("a", NOT_DIFFED[0], "00002000", OTHER)
    # Not of this shape: another sink, another fingerprint; and a function-level candidate.
    w.call("runB", str(o_b), "00020000", sink="popen")
    w.call("runB", str(o_b), "00021000", fp="fp_other")
    assert w.call("runA", x_a, "00007000", None) == FALLBACK
    w.commit()


@pytest.fixture
def world(tmp_path: Path, current: None) -> PairWorld:  # noqa: F811
    w = PairWorld(tmp_path)
    _build(w)
    return w


def _sib(w: PairWorld, **kw: Any) -> dict[str, Any]:
    return ss.same_shape_siblings(
        w.atlas,
        kw.pop("diff_id", PAIR),
        build_hash=w.build,
        current=_CURRENT,
        commit=UNKNOWN_VERSION,
        **kw,
    )


def _all_members(w: PairWorld, ref: str, limit: int = 7) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    offset: int | None = 0
    while offset is not None:
        page = _sib(w, evidence_ref=ref, members_offset=offset, members_limit=limit)
        assert "error" not in page, page
        out += page["members"]
        offset = page["members_next_offset"]
    return out


def _default_order(members: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The one-diff order carried across binaries: diff, side, function entry, call, ref."""
    return sorted(
        members,
        key=lambda m: (
            m["diff_id"] or "~" + (m.get("binary") or ""),
            m["side"],
            m["function_entry"] or "",
            m["call_addr"] or "",
            m["evidence_ref"],
        ),
    )


# ── the group across the pair ───────────────────────────────────────────────────────────────


def test_a_run_pair_in_diff_id_finds_the_shape_in_the_other_diffed_binaries(
    world: PairWorld,
) -> None:
    """The run pair as diff_id: the input's key, read in every diffed binary on both sides (and
    in the binary no diff covers, counted apart), not another sink or another fingerprint.

    MUTATION (verified RED, 1 failed): read only the input's diff (_scope_side keeps the diff
    whose id is the input's) -> sides.b.by_binary lacks aa_other -> RED."""
    g = _sib(world, evidence_ref=INPUT)
    assert g.get("scope") == "run_pair" and g.get("diff_id") == PAIR, g
    assert g["input"] == {
        "evidence_ref": INPUT,
        "key_granularity": "callsite",
        "diff_id": _diff("libx"),
        "side": "a",
        "binary": "libx",
    }
    assert g["sides"]["a"]["by_binary"] == {"aa_other": 12, "libx": 2, "libz": 1, "zz_target": 1}
    assert g["sides"]["b"]["by_binary"] == {
        "aa_other": 13,
        "libfail": 1,
        "libmiss": 1,
        "libx": 1,
        "zz_target": 1,
    }
    assert g["sides"]["b"]["by_binary_not_diffed"] == {"dddd": 1}
    assert g["member_count"] == 16 + 18
    assert g["members_outside_input_diff"] == 16 + 18 - 3
    refs = {m["evidence_ref"] for m in _all_members(world, INPUT)}
    assert ND in refs and TARGET in refs and INPUT in refs
    assert g["diffs_in_scope"] == 6


def test_the_member_sharing_the_rarest_literal_comes_first(world: PairWorld) -> None:
    """R-7: the member whose function shares the input's rarest literal is first, though the
    one-diff order carried across binaries puts it far down (#34 -> #1 on the measured anchor).

    MUTATION (verified RED, 1 failed): sort the members by (diff_id, side, _order) only -> TARGET
    falls back to its default place -> RED.
    MUTATION (verified RED, 1 failed): rank the tier by most shared literals before the rarest ->
    the input (3 shared) and TWO_COMMON (2) come first -> RED."""
    members = _all_members(world, INPUT)
    default = _default_order(members)
    at = [m["evidence_ref"] for m in default].index(TARGET)
    assert at >= 25, at  # precondition: without the order it is far down
    assert members[0]["evidence_ref"] == TARGET, [m["evidence_ref"] for m in members[:4]]
    assert members[0]["shared_literals"] == 1 and members[0]["rarest_shared_literal_df"] == 1
    # RARE is referenced by 2 functions on A (the input's and TARGET_A's): the input (3 shared,
    # rarest 2) before TARGET_A (1 shared, rarest 2); TWO_COMMON's rarest is OTHER (2 on B).
    assert [m["evidence_ref"] for m in members[1:4]] == [INPUT, TWO_COMMON, TARGET_A]
    assert members[2]["shared_literals"] == 2 and members[2]["rarest_shared_literal_df"] == 2


def test_a_member_whose_literals_cannot_be_read_sits_above_those_sharing_none(
    world: PairWorld,
) -> None:
    """A binary missing from its run's analysis.db, and one whose analysis is recorded failed:
    their members' literals are unknown (null), ordered after the members sharing a literal and
    before those sharing none.

    MUTATION (verified RED, 1 failed): give the unknown tier the place after the none tier ->
    RED.
    MUTATION (verified RED, 1 failed): read a failed binary's literals as read (drop the status
    check in _member_literal) -> FAIL reads 'none' -> RED."""
    members = _all_members(world, INPUT)
    tiers = [
        "shares"
        if m["shared_literals"]
        else ("unknown" if m["shared_literals"] is None else "none")
        for m in members
    ]
    unknown = {m["evidence_ref"] for m in members if m["shared_literals"] is None}
    assert unknown == {MISS, FAIL}, unknown
    assert tiers == sorted(tiers, key=["shares", "unknown", "none"].index), tiers
    assert tiers.count("shares") == 5 and tiers.count("none") == len(tiers) - 7
    g = _sib(world, evidence_ref=INPUT)
    assert g["sides"]["b"]["literal_unknown_members"] == 2
    assert g["bounds"]["literals_unreadable"] == {
        "a": {},
        "b": {"not_in_analysis_db": 1, "analysis_status": 1},
    }


def test_the_key_is_the_one_diff_key_unchanged(world: PairWorld) -> None:
    """Gate (3): each member is grouped by the very key its own diff's group is built on — the
    one-diff group_ref of every member names the run-pair f2_key, and each binary's count here is
    that binary's one-diff member_count.

    MUTATION (verified RED, 1 failed): key the run-pair group finer (f2_key of fingerprint, sink
    and kind + sink class) -> no member, counts differ -> RED."""
    g = _sib(world, evidence_ref=INPUT)
    assert g.get("f2_key") == ss.f2_key("fp_cmd", "system", "free_string")
    assert g["input_group_ref"] == ss.group_ref(_diff("libx"), g["f2_key"], "a", FPV)
    members = _all_members(world, INPUT)
    assert len(members) == g["member_count"] > 0
    seen: dict[tuple[str, str], int] = {}
    for m in members:
        if not m["diffed"]:  # no one-diff group: its own binary's calls give it the same key
            run = "runA" if m["side"] == "a" else "runB"
            sha = NOT_DIFFED[0] if m["side"] == "a" else NOT_DIFFED[1]
            own = ss._groups(ss._calls(world.atlas, run, sha))
            assert m["evidence_ref"] in {c.ref for c in own.get(g["f2_key"], [])}, m
            continue
        one = _sib(world, diff_id=m["diff_id"], evidence_ref=m["evidence_ref"])
        assert "error" not in one, one
        assert f"#f2:{g['f2_key']}:{m['side']}@" in one["group_ref"], one["group_ref"]
        seen[(m["diff_id"], m["side"])] = one["member_count"]
    for (diff_id, side), n in seen.items():
        assert g["sides"][side]["by_binary"][diff_id.rsplit("::", 1)[1]] == n, diff_id


def test_a_binary_whose_calls_cannot_be_read_is_counted_never_read_as_no_member(
    world: PairWorld,
) -> None:
    """A diff with no content hash for side B is counted under calls_unreadable; a binary whose
    analysis is recorded failed is counted there too, and the calls it does hold stay members.

    MUTATION (verified RED, 1 failed): drop the no_content_hash record in _scope_side -> RED.
    MUTATION (verified RED, 1 failed): skip the members of a binary whose analysis status is not
    ok -> FAIL is gone -> RED."""
    g = _sib(world, evidence_ref=INPUT)
    assert g["bounds"]["calls_unreadable"] == {
        "a": {},
        "b": {
            "analysis_status:failed": {"binaries": 1, "first": ["libfail"]},
            "no_content_hash": {"binaries": 1, "first": ["libz"]},
        },
    }
    assert FAIL in {m["evidence_ref"] for m in _all_members(world, INPUT)}
    assert "libz" not in g["sides"]["b"]["by_binary"] and g["sides"]["a"]["by_binary"]["libz"] == 1


def test_the_bounds_count_function_level_and_unkeyed_calls_of_the_sink(world: PairWorld) -> None:
    """excluded_non_callsite counts the function-level candidate of this sink and kind; a call of
    another sink is not unkeyed.

    MUTATION (verified RED, 1 failed): count excluded_non_callsite over no calls -> RED."""
    g = _sib(world, evidence_ref=INPUT)
    assert g["bounds"]["excluded_non_callsite"]["a"] == {
        "wrapper": 0,
        "function_fallback": 1,
        "degraded_out_of_body": 0,
    }
    assert sum(g["bounds"]["unkeyed"]["b"].values()) == 0


def test_a_function_level_input_gets_its_shapes_with_pair_counts(world: PairWorld) -> None:
    """A function-level input is no member: its shapes come back with the run-pair member count per
    side, and asking for its members' page is refused.

    MUTATION (verified RED, 1 failed): give each shape a 0 count -> RED."""
    out = _sib(world, evidence_ref=FALLBACK)
    assert out.get("not_a_member") is True, out
    assert out["f2_keys"] == [
        {
            "f2_key": ss.f2_key("fp_cmd", "system", "free_string"),
            "sink_anchor": "system",
            "kind": "free_string",
            "member_count": {"a": 16, "b": 18},
        }
    ]
    page = _sib(world, evidence_ref=FALLBACK, members_offset=0)
    assert "no group's member" in page.get("error", ""), page


def test_an_input_outside_the_diffed_binaries_is_refused_with_where_it_is_counted(
    world: PairWorld,
) -> None:
    """A call of a binary no diff covers is refused at this scope, naming the one-diff bound that
    counts such calls; a ref of no candidate and a call naming no input are refused too.

    MUTATION (verified RED, 1 failed): leave the bound's name out of the refusal -> RED."""
    out = _sib(world, evidence_ref=ND)
    assert "binaries_not_diffed" in out.get("error", ""), out
    assert "not a candidate" in _sib(world, evidence_ref="runA#11111111:0000f000@cmd@0x10")["error"]
    assert "exactly one" in _sib(world)["error"]


def test_a_candidate_anchor_names_the_same_group(world: PairWorld) -> None:
    """A candidate anchor of the pair names its A ref (B ref when it has none) and its sink class
    narrows the rows; a class the ref is not recorded with is refused.

    MUTATION (verified RED, 1 failed): skip the sink-class narrowing -> the wrong class answers
    -> RED."""
    a_only = f"{PAIR}#candidate#callsite|cmd|{INPUT}|(none)"
    b_only = f"{PAIR}#candidate#callsite|cmd|(none)|{TARGET}"
    plain = _sib(world, evidence_ref=INPUT)
    anchored = _sib(world, candidate_anchor=a_only)
    assert "error" not in anchored, anchored
    assert {k: v for k, v in anchored.items() if k != "members_page_ref"} == {
        k: v for k, v in plain.items() if k != "members_page_ref"
    }
    assert anchored["members_page_ref"]["candidate_anchor"] == a_only
    on_b = _sib(world, candidate_anchor=b_only)
    assert on_b["input"]["side"] == "b" and on_b["input"]["diff_id"] == _diff("zz_target")
    assert on_b["f2_key"] == plain["f2_key"] and on_b["member_count"] == plain["member_count"]
    wrong = _sib(world, candidate_anchor=f"{PAIR}#candidate#callsite|copy|{INPUT}|(none)")
    assert "sink class" in wrong.get("error", ""), wrong


def test_one_binary_diff_ids_are_not_the_run_pair_scope(world: PairWorld) -> None:
    """A diff_id of one binary answers the one-diff group as before; a leftover whole-run row with
    the pair's id is read as the pair.

    MUTATION (verified RED, 1 failed): read any diff_meta row with the id as one diff (drop the
    whole-run test in run_pair_scope) -> RED."""
    assert rp.run_pair_scope(world.atlas, _diff("libx")) is None
    assert rp.run_pair_scope(world.atlas, "runA::runC") is None
    assert rp.run_pair_scope(world.atlas, PAIR) == ("runA", "runB")
    one = _sib(world, diff_id=_diff("libx"), evidence_ref=INPUT)
    assert "scope" not in one and one["member_count"] == 2
    world.atlas.execute(
        "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id) VALUES (?, 'runA', 'runB')", (PAIR,)
    )
    world.commit()
    assert rp.run_pair_scope(world.atlas, PAIR) == ("runA", "runB")
    assert _sib(world, evidence_ref=INPUT)["member_count"] == 34


# ── the binaries no diff covers ─────────────────────────────────────────────────────────────


def test_a_member_in_a_binary_no_diff_covers_is_listed_with_diffed_false(world: PairWorld) -> None:
    """libnd (no diff covers it) holds one call of the key on B: it is a member with diffed
    false, a null diff_id, its binary and not_diffed_reason, ordered by the literal it shares like
    any other member (COMMON, referenced by 3 functions of B: after TARGET_A), and counted per side
    and reason in bounds.not_diffed_same_shape; a call of the same binary with another fingerprint
    is no member. The reason is the one-diff group's for that binary (one classifier).

    MUTATION (verified RED, 8 failed): drop the calls of binaries no diff covers in _read_calls
    (``if key not in scope.diff_of: continue``) -> ND is not listed -> RED.
    MUTATION (verified RED, 2 failed): order a not-diffed member after every diffed one (put
    diffed-ness before the literal tier in _Member.order) -> ND falls below the unknown tier ->
    RED."""
    world.call("runB", NOT_DIFFED[1], "00005000", fp="fp_other")
    world.commit()
    members = _all_members(world, INPUT)
    by_ref = {m["evidence_ref"]: m for m in members}
    assert ND in by_ref, sorted(by_ref)
    nd = by_ref[ND]
    assert nd.get("diffed") is False and nd.get("diff_id") is None, nd
    assert nd.get("binary") == "dddd" and nd.get("not_diffed_reason") == "binary_not_diffed", nd
    assert nd["shared_literals"] == 1 and nd["rarest_shared_literal_df"] == 3
    assert [m["evidence_ref"] for m in members].index(ND) == 4
    assert all(m.get("diffed") is True and m["diff_id"] for m in members if m is not nd)
    g = _sib(world, evidence_ref=INPUT)
    zero = {"binaries": 0, "members": 0}
    assert g["bounds"]["not_diffed_same_shape"] == {
        "a": {"members": 0, "binaries": 0, "by_reason": dict.fromkeys(ss.NOT_DIFFED_REASONS, zero)},
        "b": {
            "members": 1,
            "binaries": 1,
            "by_reason": {
                **dict.fromkeys(ss.NOT_DIFFED_REASONS, zero),
                "binary_not_diffed": {"binaries": 1, "members": 1},
            },
        },
    }
    side_b = g["sides"]["b"]
    assert side_b["not_diffed_members"] == 1 and side_b["not_diffed_binaries"] == 1
    assert side_b["member_count"] == sum(side_b["by_binary"].values()) + 1
    # The one-diff bound gives that binary the same reason; it counts by sink name and kind, so
    # the other-fingerprint call is counted there and is no member here.
    b_ref = _ref("runB", "00002000", "cmd", "0x10", "22222222")
    one = _sib(world, diff_id=_diff("libx"), evidence_ref=b_ref)
    assert one["sibling_set_bounds"]["binaries_not_diffed"]["binary_not_diffed"] == {
        "binaries": 1,
        "calls": 2,
    }


def test_a_binary_identical_on_both_sides_gives_members_on_both_with_that_reason(
    world: PairWorld,
) -> None:
    """A binary with the same content in both runs is diffed by no diff (there was nothing to
    diff): its calls of the key are members on each side, with the reason identical_both_sides.

    MUTATION (verified RED, 1 failed): give every not-diffed member the reason binary_not_diffed
    (``basis.reason`` -> a constant in _read_calls) -> RED."""
    same = "a" * 64
    for side, run in (("a", "runA"), ("b", "runB")):
        cur = world.adb[side].execute(
            "INSERT INTO binaries (name, sha256, ghidra_status) VALUES ('libsame', ?, 'ok')",
            (same,),
        )
        world.bid[same] = int(cur.lastrowid or 0)
        world.call(run, same, "00006000", path="/fw/lib/libsame")
    world.commit()
    rows = [m for m in _all_members(world, INPUT) if m.get("binary") == "libsame"]
    assert [(m["side"], m["not_diffed_reason"], m["diffed"]) for m in rows] == [
        ("a", "identical_both_sides", False),
        ("b", "identical_both_sides", False),
    ], rows
    bound = _sib(world, evidence_ref=INPUT)["bounds"]["not_diffed_same_shape"]
    assert bound["a"]["by_reason"]["identical_both_sides"] == {"binaries": 1, "members": 1}
    assert bound["b"]["by_reason"]["identical_both_sides"] == {"binaries": 1, "members": 1}


# ── staleness, recall gaps, a pair named wrong ──────────────────────────────────────────────


def test_the_group_counts_the_pairs_diffs_by_source_stale_and_says_recall_gaps_are_not_read(
    world: PairWorld,
) -> None:
    """The group object carries source_stale_diffs — every diff of the pair counted by its
    source_stale as list_diffs gives each (here one stale, the rest unverified) — and
    bounds.recall_gaps says it is not read at this scope (null families, never an empty list).

    MUTATION (verified RED, 1 failed): count only the input's diff (``[g.inp_diff.diff_id]`` in
    _group_object) -> diffs 1 -> RED.
    MUTATION (verified RED, 1 failed): give recall_gaps an empty families list -> RED."""
    from treasure_map.lib.query.diff_align import diffs_source_staleness, staleness_summary

    g = _sib(world, evidence_ref=INPUT)
    want = staleness_summary(diffs_source_staleness(world.atlas, [_diff(n) for n in BINS]))
    assert g.get("source_stale_diffs") == want, g.get("source_stale_diffs")
    # libmiss's B binary is not in its run's analysis.db (stale); the rest record no generation.
    assert (want["diffs"], want["stale"], want["unverified"], want["current"]) == (6, 1, 5, 0)
    assert g["bounds"].get("recall_gaps") == {
        "families": None,
        "state": "not_read_at_this_scope",
    }


def test_a_pair_named_the_other_way_round_or_misspelled_gets_a_hint(world: PairWorld) -> None:
    """A run pair with its runs reversed names the pair the right way round; any other id
    that is no diff says how a run pair is written. Both keep the 'no diff' sentence.

    MUTATION (verified RED, 2 failed): return "" from pair_hint -> RED."""
    rev = _sib(world, diff_id="runB::runA", evidence_ref=INPUT)
    assert rev["error"].startswith("no diff 'runB::runA' in this atlas"), rev
    assert "the run pair is 'runA::runB'" in rev["error"], rev
    typo = _sib(world, diff_id="runA::runBx", evidence_ref=INPUT)
    assert "diff_id='<run_a_id>::<run_b_id>'" in typo["error"], typo
    assert "other way round" not in typo["error"]


def test_the_mcp_tool_hints_diff_id_for_run_pair_and_names_a_reversed_pair(
    world: PairWorld,
) -> None:
    """End to end: run_pair= on same_shape_siblings is refused naming diff_id (the server's
    unknown-parameter check), and the tool's answer to a reversed pair names the pair.

    MUTATION (verified RED, 1 failed): leave same_shape_siblings out of the run_pair synonym's
    ``only`` in mcp_cards -> no 'did you mean' -> RED."""
    import asyncio

    from mcp.server.fastmcp.exceptions import ToolError

    server = mcp_app.build_server(world.path)
    with pytest.raises(ToolError) as refused:
        asyncio.run(
            server.call_tool("same_shape_siblings", {"run_pair": PAIR, "evidence_ref": INPUT})
        )
    first = str(refused.value).split("\n", 1)[0]
    assert first.endswith("'run_pair' — did you mean 'diff_id'?"), first
    tool = mcp_app.make_tools(world.path)["same_shape_siblings"]
    rev = tool("runB::runA", evidence_ref=INPUT)
    assert "the run pair is 'runA::runB'" in rev.get("error", ""), rev


# ── the literal sides, the read-layer refusal, the key not narrowed ──────────────────────────


def test_a_b_side_input_reads_its_literals_from_its_own_run(world: PairWorld) -> None:
    """A B-side input's literals come from run B's analysis.db, and each side's members' from
    their own run's: TARGET (B, RARE) puts the members sharing RARE first — itself (RARE is
    referenced by 1 function of B), then INPUT and TARGET_A on A (2 functions of A).

    MUTATION (verified RED, 1 failed): read the input's literals from run A (``runs["a"]`` in
    _build's _input_literals call) -> state unreadable, every member unknown -> RED.
    MUTATION (verified RED, 7 failed): read every side's literals from run A (``runs["a"]`` in
    _build's _side_literals call) -> TARGET's own literals unknown -> RED."""
    g = _sib(world, evidence_ref=TARGET)
    assert g["input"]["side"] == "b" and g["input"]["diff_id"] == _diff("zz_target")
    assert g["shared_literals"]["state"] == "read" and g["shared_literals"]["input_literals"] == 1
    members = _all_members(world, TARGET)
    head = [
        (m["evidence_ref"], m["shared_literals"], m["rarest_shared_literal_df"]) for m in members
    ]
    assert head[:3] == [(TARGET, 1, 1), (INPUT, 1, 2), (TARGET_A, 1, 2)], head[:4]
    assert {m["evidence_ref"] for m in members if m["shared_literals"] is None} == {MISS, FAIL}


def test_the_read_layer_refuses_a_stale_run_pair_itself(world: PairWorld) -> None:
    """same_shape_siblings itself (not only the MCP tool, which refuses first) refuses a run
    pair one of whose runs is a proven-stale scan, echoing the pair as diff_id.

    MUTATION (verified RED, 1 failed): drop the run-pair branch's ``return {**refusal, ...}`` in
    same_shape_siblings -> the group answers -> RED."""
    world.atlas.execute("UPDATE run SET build_hash = 'other' WHERE run_id = 'runB'")
    world.commit()
    out = _sib(world, evidence_ref=INPUT)
    assert out.get("stale_scan") and out.get("diff_id") == PAIR, out
    assert "members_page_ref" not in out and "member_count" not in out
    assert out["stale_scan"]["diff_side"] == "b"


def test_members_are_not_narrowed_by_granularity_or_sink_class(world: PairWorld) -> None:
    """Gate (3), the narrowing direction: a wrapper_callsite call and a call recorded under
    another sink class, both of the key (same fingerprint, sink name and kind), are members — as
    they are of their own one-diff group.

    MUTATION (verified RED, 1 failed): keep only members of the input's granularity in _build ->
    the wrapper_callsite call is gone -> RED.
    MUTATION (verified RED, 1 failed): keep only members of the input's sink class in _build ->
    the other-class call is gone -> RED."""
    o_a = BINS["aa_other"][0]
    wrapped = world.call(
        "runA",
        o_a,
        "00030000",
        "0x20",
        cls="cmd_via_wrapper",
        flow=json.dumps({"source_kind": "free_string", "flow_path": {"wrapper": {"name": "w"}}}),
    )
    other_class = world.call("runA", o_a, "00031000", sink_class="exec")
    world.commit()
    g = _sib(world, evidence_ref=INPUT)
    members = {m["evidence_ref"]: m for m in _all_members(world, INPUT)}
    assert members.get(wrapped, {}).get("key_granularity") == "wrapper_callsite", sorted(members)
    assert other_class in members
    assert g["sides"]["a"]["by_binary"]["aa_other"] == 14
    for ref in (wrapped, other_class):
        one = _sib(world, diff_id=_diff("aa_other"), evidence_ref=ref)
        assert one.get("member_count") == 14 and g["f2_key"] in one["group_ref"], one


# ── the summary prepared for a write answer ─────────────────────────────────────────────────


def test_the_summary_is_compact_and_names_the_members_outside_the_input_diff(
    world: PairWorld,
) -> None:
    """run_pair_group_summary: the key, the per-side counts and the first members outside the
    input's diff in the run-pair order, small enough to ride on another answer.

    MUTATION (verified RED, 1 failed): list the first members without leaving out the input's
    diff -> the input itself is listed -> RED."""
    s = rp.run_pair_group_summary(world.atlas, "runA", "runB", evidence_ref=INPUT)
    g = _sib(world, evidence_ref=INPUT)
    assert s["f2_key"] == g["f2_key"]
    assert s["member_count"] == {"a": 16, "b": 18}
    assert s["not_diffed_members"] == {"a": 0, "b": 1}
    assert s["members_outside_input_diff"] == g["members_outside_input_diff"]
    assert s["shared_literal_members_outside_input_diff"] == 4
    assert s["binaries_calls_unreadable"] == 2
    assert [m["evidence_ref"] for m in s["first_outside_input_diff"]] == [
        TARGET,
        TWO_COMMON,
        TARGET_A,
    ]
    assert s["members"] == (
        f"same_shape_siblings(diff_id='{PAIR}', evidence_ref='{INPUT}', members_offset=0)"
    )
    assert len(json.dumps(s)) < 1200


# ── through the MCP tool ────────────────────────────────────────────────────────────────────


def test_the_mcp_tool_answers_the_run_pair_and_pages_it_within_the_budget(
    tmp_path: Path,
    current: None,  # noqa: F811
) -> None:
    """End to end: same_shape_siblings(diff_id=<run pair>) through MCP, a 400-member group paged
    within the response budget, every member once, TARGET first.

    MUTATION (verified RED, 1 failed): leave the run-pair hook out of same_shape_siblings -> the
    tool answers 'no diff' -> RED."""
    w = PairWorld(tmp_path)
    _build(w, bulk=200)
    tool = mcp_app.make_tools(w.path)["same_shape_siblings"]
    g = tool(PAIR, evidence_ref=INPUT)
    assert g.get("scope") == "run_pair" and g.get("member_count") == 34 + 2 * 188, g
    assert len(json.dumps(g)) <= mcp_app._RESPONSE_BYTE_BUDGET
    seen: list[str] = []
    offset: int | None = 0
    pages = 0
    while offset is not None:
        page = tool(PAIR, evidence_ref=INPUT, members_offset=offset)
        assert len(json.dumps(page)) <= mcp_app._RESPONSE_BYTE_BUDGET
        assert page["member_count"] == g["member_count"]
        seen += [m["evidence_ref"] for m in page["members"]]
        offset = page["members_next_offset"]
        pages += 1
    assert pages > 1 and len(seen) == len(set(seen)) == g["member_count"]
    assert seen[0] == TARGET


def test_the_mcp_tool_refuses_a_stale_run_pair_through_the_shared_gate(world: PairWorld) -> None:
    """A stale run refuses the run pair as it refuses every diff of it, key for key (the diff_id
    echoed is the pair).

    MUTATION (verified RED, 1 failed): pass diff_id itself to _refuse_stale_diff in the MCP tool
    -> the read layer's refusal (no run_lineage) answers -> RED."""
    world.atlas.execute("UPDATE run SET build_hash = 'other' WHERE run_id = 'runB'")
    world.commit()
    tools = mcp_app.make_tools(world.path)
    pair = tools["same_shape_siblings"](PAIR, evidence_ref=INPUT)
    view = tools["get_diff_patch_view"](_diff("libx"))
    assert pair.get("stale_scan") and "run_lineage" in pair, pair
    assert pair == {**view, "diff_id": PAIR}


def test_nothing_it_says_is_a_judgement(world: PairWorld) -> None:
    """No judgement word in the group, the members, the summary or the module's text.

    MUTATION (verified RED, 1 failed): word the note 'the set is complete' -> RED."""
    texts = [
        json.dumps(_sib(world, evidence_ref=INPUT)),
        json.dumps(_all_members(world, INPUT)),
        json.dumps(rp.run_pair_group_summary(world.atlas, "runA", "runB", evidence_ref=INPUT)),
        rp.__doc__ or "",
    ]
    for text in texts:
        found = {w.lower() for w in re.findall(r"\w+", text)} & _JUDGEMENT_WORDS
        assert not found, (found, text[:200])


def test_the_module_is_outside_the_code_a_diff_or_baseline_is_versioned_by() -> None:
    """MUTATION (verified RED, 1 failed): add the module to DIFF_CODE_ENTRIES -> RED."""
    import ast

    from treasure_map.lib.diff import code_version as cv

    name = "lib.query.same_shape_run_pair"
    entries = cv.DIFF_CODE_ENTRIES + cv.OVERLAY_CODE_ENTRIES
    assert all(e.partition(":")[0] != name for e in entries)
    package = Path(cv.__file__).resolve().parents[2]
    for module in sorted({e.partition(":")[0] for e in entries}):
        tree = ast.parse(cv._module_path(package, module).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported = {node.module, *(f"{node.module}.{a.name}" for a in node.names)}
                assert f"treasure_map.{name}" not in imported, module
