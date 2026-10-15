# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The function-level view of one diff (lib/query/patch_view).

Zero real data: every run, binary, address and function name is synthetic. One atlas holds one diff
of a binary ``libx``, and each run has its own analysis.db holding that binary's functions; the
view is read through its public function, and through the MCP tool where the tool adds something
(the stale-run refusal, the parity with get_diff_sink_overlay).
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from treasure_map import mcp_app
from treasure_map.lib import overlay
from treasure_map.lib.analyze.ghidra_runner import current_pass_version
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.diff import code_version as cv
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query import sink_overlay as so
from treasure_map.lib.storage.connection import open_db
from treasure_map.version import UNKNOWN_VERSION

SHA_A = "a" * 64
SHA_B = "b" * 64
DIFF = "runA::runB::libx"
BANCHOR = "deadbeef"
COMMIT = "facade"
DEG = json.dumps({"callsite_located": False, "anchor_degraded": "out_of_body"})


def _ref(run: str, func: str, cls: str, offset: str | None = None) -> str:
    """An evidence_ref in the real shape: {run}#{banchor}:{func}@{class}[@{offset}]."""
    return f"{run}#{BANCHOR}:{func}@{cls}" + (f"@{offset}" if offset is not None else "")


def _facts(*names: str) -> str:
    return json.dumps(
        {
            "callees": [{"name": n, "addr": None, "kind": "name_only"} for n in names],
            "targets": None,
        }
    )


class World:
    """One diff of ``libx`` between runA and runB, plus each run's analysis.db."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.path = tmp / "atlas.db"
        self.atlas = open_atlas(self.path)
        self.atlas.execute("PRAGMA synchronous = OFF")  # a test database: no need to wait on disk
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
            "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id, binary_a, binary_b, sha256_a, "
            "sha256_b, diff_ok, version_skew, callsite_facts_a, callsite_facts_b, "
            "callsite_facts_hash_a, callsite_facts_hash_b, stub_state_a, stub_state_b) "
            "VALUES (?, 'runA', 'runB', 'libx', 'libx', ?, ?, 1, 0, 'read', 'read', ?, ?, "
            "'not_applicable', 'not_applicable')",
            (DIFF, SHA_A, SHA_B, self.build, self.build),
        )

    def pair(
        self,
        a: str,
        b: str,
        conf: float,
        sim: float,
        *,
        instructions: int | None = None,
        **gaps: str | None,
    ) -> None:
        state = "aligned" if conf >= 0.9 else "alignment_undetermined"
        self.atlas.execute(
            "INSERT INTO function_alignment (diff_id, addr_a, addr_b, alignment_confidence, "
            "similarity, alignment_state, export_gap_a, export_gap_b, instructions) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (DIFF, a, b, conf, sim, state, gaps.get("gap_a"), gaps.get("gap_b"), instructions),
        )

    def unpaired(self, side: str, addr: str, state: str, gap: str | None = None) -> None:
        self.atlas.execute(
            "INSERT INTO function_presence (diff_id, side, addr, presence_state, export_gap) "
            "VALUES (?, ?, ?, ?, ?)",
            (DIFF, side, addr, state, gap),
        )

    def fn(
        self,
        side: str,
        addr: str,
        callees: list[str],
        *,
        name: str | None = None,
        truncated: int = 0,
        unresolved: list[str] | None = None,
        pseudocode: str | None = None,
        size_bytes: int | None = None,
        body_ranges: list[list[str]] | None = None,
    ) -> None:
        self.adb[side].execute(
            "INSERT INTO functions (binary_id, name, address, callees, callees_truncated, "
            "unresolved_external_calls, pseudocode, size_bytes, body_ranges) "
            "VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                name,
                addr,
                json.dumps(callees),
                truncated,
                json.dumps(unresolved or []),
                pseudocode,
                size_bytes,
                json.dumps(body_ranges or []),
            ),
        )

    def block(self, side: str, start: str, size: int) -> None:
        """One memory block of the side's binary (data_blocks: the image extents a large literal
        is read against)."""
        self.adb[side].execute(
            "INSERT INTO data_blocks (binary_id, block_name, start_addr, size, initialized) "
            "VALUES (1, '.text', ?, ?, 1)",
            (start, size),
        )

    def commit(self) -> None:
        for conn in (self.atlas, *self.adb.values()):
            conn.commit()

    def inst(
        self,
        side: str,
        ref: str,
        sink_class: str,
        sink: str | None = None,
        flow: str | None = None,
        *,
        wraps: str | None = None,
    ) -> None:
        run, sha = ("runA", SHA_A) if side == "a" else ("runB", SHA_B)
        self.atlas.execute(
            "INSERT INTO instance (pattern_id, evidence_ref, source_run_id, binary_content_hash, "
            "binary_path, sink_anchor, flow_evidence, is_thin_cmd_wrapper, wrapped_sink) "
            "VALUES (?, ?, ?, ?, '/fw/lib/libx', ?, ?, ?, ?)",
            (
                self._pattern(sink_class),
                ref,
                run,
                sha,
                sink_class if sink is None else sink,
                flow,
                1 if wraps else 0,
                wraps,
            ),
        )

    def _pattern(self, sink_class: str) -> int:
        row = self.atlas.execute(
            "SELECT pattern_id FROM pattern WHERE structural_fingerprint = ?", (f"fp_{sink_class}",)
        ).fetchone()
        if row is not None:
            return int(row[0])
        cur = self.atlas.execute(
            "INSERT INTO pattern (source_class, sink_class, call_sequence_shape, "
            "structural_fingerprint, fingerprint_algo_version) VALUES "
            "('external_input', ?, 'source->sink', ?, 'v1')",
            (sink_class, f"fp_{sink_class}"),
        )
        return int(cur.lastrowid or 0)

    def im(self, a: str, b: str, func_a: str, facts_b: str | None = None) -> None:
        self.atlas.execute(
            "INSERT INTO instruction_match (diff_id, func_addr_a, addr_a, addr_b, facts_b) "
            "VALUES (?, ?, ?, ?, ?)",
            (DIFF, func_a, a, b, facts_b),
        )

    def judge(self, diff_id: str, anchor: str, verdict: str, **kw: Any) -> overlay.UpsertResult:
        return overlay.annotate_diff(
            self.atlas,
            diff_id=diff_id,
            anchor_ref=anchor,
            verdict=verdict,
            rationale="looked at both sides",
            **kw,
        )

    def edge(self, subject_key: str, delta_kind: str) -> None:
        self.atlas.execute(
            "INSERT INTO dimension_delta (diff_id, dimension, subject_kind, subject_key, "
            "delta_kind, binary) "
            "VALUES (?, 'reachability.string_keyed_edge', 'edge', ?, ?, 'libx')",
            (DIFF, subject_key, delta_kind),
        )


def _pair_id(a: str, b: str) -> str:
    return f"pair:{a}:{b}"


def _rich(w: World) -> None:
    """Every placement the view makes, one function pair (or function) each."""
    a, b = "runA", "runB"
    # The matched call now calls another candidate's callee, none elsewhere -> A (other side a
    # candidate: the overlay's tier-1 reading).
    w.pair("00001000", "00002000", 0.97, 0.9)
    w.inst("a", _ref(a, "00001000", "cmd", "0x10"), "cmd", "system")
    w.inst("b", _ref(b, "00002000", "cmd", "0x10"), "cmd", "popen")
    w.im("00001010", "00002010", "00001000")
    w.fn("a", "00001000", ["system"])
    w.fn("b", "00002000", ["popen"])
    # ... and read from the call-site facts (the other side holds no candidate there) -> A.
    w.pair("00003000", "00004000", 0.97, 0.9)
    w.inst("a", _ref(a, "00003000", "cmd", "0x10"), "cmd", "system")
    w.im("00003010", "00004010", "00003000", _facts("execl"))
    w.fn("a", "00003000", ["system"])
    w.fn("b", "00004000", ["execl"])
    # Another callee at the matched call, but the paired function holds the same callee elsewhere.
    w.pair("00005000", "00006000", 0.97, 0.9)
    w.inst("a", _ref(a, "00005000", "cmd", "0x10"), "cmd", "system")
    w.inst("b", _ref(b, "00006000", "cmd", "0x10"), "cmd", "popen")
    w.inst("b", _ref(b, "00006000", "cmd", "0x40"), "cmd", "system")
    w.im("00005010", "00006010", "00005000")
    w.fn("a", "00005000", ["system"])
    w.fn("b", "00006000", ["popen", "system"])
    # ... and where that cannot be told (a candidate there has no readable sink name).
    w.pair("00007000", "00008000", 0.97, 0.9)
    w.inst("a", _ref(a, "00007000", "cmd", "0x10"), "cmd", "system")
    w.inst("b", _ref(b, "00008000", "cmd", "0x10"), "cmd", "popen")
    w.inst("b", _ref(b, "00008000", "cmd", "0x40"), "cmd", "")
    w.im("00007010", "00008010", "00007000")
    w.fn("a", "00007000", ["system"])
    w.fn("b", "00008000", ["popen"])
    # A call BinDiff matched to nothing, its sink not in the paired function's callees.
    w.pair("00009000", "0000a000", 0.97, 0.9)
    w.inst("a", _ref(a, "00009000", "cmd", "0x30"), "cmd", "system")
    w.fn("a", "00009000", ["system", "uci_get"])
    w.fn("b", "0000a000", ["printf"])
    # A changed pair whose candidate lines up.
    w.pair("0000b000", "0000c000", 0.97, 0.7)
    w.inst("a", _ref(a, "0000b000", "cmd", "0x10"), "cmd", "system")
    w.inst("b", _ref(b, "0000c000", "cmd", "0x10"), "cmd", "system")
    w.im("0000b010", "0000c010", "0000b000")
    w.fn("a", "0000b000", ["system"])
    w.fn("b", "0000c000", ["system", "strlen"])
    # Identical pairs: one whose candidate lines up, one with none.
    w.pair("0000d000", "0000e000", 0.97, 1.0)
    w.inst("a", _ref(a, "0000d000", "cmd", "0x10"), "cmd", "system")
    w.inst("b", _ref(b, "0000e000", "cmd", "0x10"), "cmd", "system")
    w.im("0000d010", "0000e010", "0000d000")
    w.pair("00011000", "00012000", 0.97, 1.0)
    # Changed pairs with no candidate: callee lists that differ, that are equal through the
    # alignment (FUN_ names of an aligned pair), and that cannot be identified.
    w.pair("00013000", "00014000", 0.97, 0.6)
    w.fn("a", "00013000", ["memset", "log_it"])
    w.fn("b", "00014000", ["memset"])
    w.pair("00015000", "00016000", 0.97, 0.6)
    w.fn("a", "00015000", ["FUN_00017000"])
    w.fn("b", "00016000", ["FUN_00018000"])
    w.pair("00017000", "00018000", 0.97, 1.0)
    w.pair("00019000", "0001a000", 0.97, 0.6)
    w.fn("a", "00019000", ["FUN_0001b000", "memcpy"])
    w.fn("b", "0001a000", ["memset"])
    # A changed pair with no candidate that calls a sink the hunt does not recall.
    w.pair("0001c000", "0001d000", 0.97, 0.6)
    w.fn("a", "0001c000", ["strlen"])
    w.fn("b", "0001d000", ["strlen", "wcscpy"])
    # Undetermined pairs, without and with a candidate.
    w.pair("0001e000", "0001f000", 0.5, 0.4)
    w.pair("00020000", "00021000", 0.5, 0.4)
    w.inst("a", _ref(a, "00020000", "cmd", "0x10"), "cmd", "system")
    # Functions with no counterpart, with and without a candidate.
    w.unpaired("a", "00022000", "unmatched_analysis_complete")
    w.inst("a", _ref(a, "00022000", "cmd", "0x10"), "cmd", "system")
    w.unpaired("b", "00023000", "unmatched_analysis_complete")
    # Degraded candidates counted 2 against 1.
    w.pair("00024000", "00025000", 0.97, 0.8)
    for _ in range(2):
        w.inst("a", _ref(a, "00024000", "copy"), "copy", "strcpy", DEG)
    w.inst("b", _ref(b, "00025000", "copy"), "copy", "strcpy", DEG)
    w.fn("a", "00024000", ["strcpy"])
    w.fn("b", "00025000", ["strcpy"])
    # A function-level candidate with no counterpart inside an aligned pair.
    w.pair("00026000", "00027000", 0.97, 0.8)
    w.inst("a", _ref(a, "00026000", "path_sink"), "path_sink", "fopen")
    w.fn("a", "00026000", ["fopen"])
    w.fn("b", "00027000", ["fopen"])
    # The matched instruction calls the same callee, and holds no candidate.
    w.pair("00028000", "00029000", 0.97, 0.8)
    w.inst("a", _ref(a, "00028000", "cmd", "0x10"), "cmd", "system")
    w.im("00028010", "00029010", "00028000", _facts("system"))
    w.fn("a", "00028000", ["system"])
    w.fn("b", "00029000", ["system"])
    # A copy candidate whose matched call is now a cmd candidate: the tier is the higher one.
    w.pair("0002a000", "0002b000", 0.97, 0.8)
    w.inst("a", _ref(a, "0002a000", "copy", "0x10"), "copy", "strcpy")
    w.inst("b", _ref(b, "0002b000", "cmd", "0x10"), "cmd", "system")
    w.im("0002a010", "0002b010", "0002a000")
    w.fn("a", "0002a000", ["strcpy"])
    w.fn("b", "0002b000", ["system"])
    # Wrapper candidates: a function-level one and a call to a wrapper.
    w.pair("0002c000", "0002d000", 0.97, 0.8)
    w.inst("a", _ref(a, "0002c000", "cmd_via_wrapper"), "cmd", "system")
    w.inst("a", _ref(a, "0002c000", "cmd_via_wrapper", "0x20"), "cmd", "system")
    w.fn("a", "0002c000", ["run_cmd"])
    w.fn("b", "0002d000", ["run_cmd"])
    # No counterpart: analysis incomplete; not analysed at all; held by its export degenerately.
    w.unpaired("a", "0002e000", "unmatched_analysis_incomplete")
    w.inst("a", _ref(a, "0002e000", "cmd", "0x10"), "cmd", "system")
    w.inst("a", _ref(a, "0002f000", "cmd", "0x10"), "cmd", "system")
    w.unpaired("a", "00030000", "unmatched_analysis_incomplete", "degenerate_block")
    w.inst("a", _ref(a, "00030000", "cmd", "0x10"), "cmd", "system")
    # A changed pair with no candidate whose callees name an unmodelled source: still C.
    w.pair("00031000", "00032000", 0.97, 0.6)
    w.fn("a", "00031000", ["uci_get"])
    w.fn("b", "00032000", ["uci_get", "memset"])
    # A changed pair with no candidate that now calls a thin command wrapper of B.
    w.pair("00033000", "00035000", 0.97, 0.6)
    w.fn("a", "00033000", [])
    w.fn("b", "00035000", ["run_cmd"])
    w.unpaired("b", "00034000", "unmatched_analysis_complete")
    w.fn("b", "00034000", ["system"], name="run_cmd")
    w.inst("b", _ref(b, "00034000", "cmd", "0x8"), "cmd", "system", wraps="system")
    # String-keyed edges anchored at a pair and at a B function with no counterpart.
    w.edge("libx|strcmp_gate|ping|00013000", "layer_changed")
    w.edge("libx|strcmp_gate|reboot|b:00023000", "layer_changed")
    w.commit()


@pytest.fixture(autouse=True)
def _servable(monkeypatch: pytest.MonkeyPatch) -> None:
    """The MCP gate compares a run's hunt commit with the install's; this install's is unknown. Also
    drop the process-wide pseudocode cache: every World reuses one diff_id, so a stale reading from
    another test would otherwise be served."""
    monkeypatch.setattr(mcp_app, "_installed_commit", lambda: UNKNOWN_VERSION)
    pv._clear_view_caches()


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


@pytest.fixture
def world(tmp_path: Path, current: None) -> World:
    w = World(tmp_path)
    _rich(w)
    return w


def _view(w: World, **kw: Any) -> dict[str, Any]:
    """The whole view: every page walked, entries keyed by entry_id."""
    out = pv.get_diff_patch_view(w.atlas, DIFF, limit=7, **kw)
    assert "error" not in out, out
    entries = list(out["entries"])
    while out["next_offset"] is not None:
        out = pv.get_diff_patch_view(w.atlas, DIFF, limit=7, offset=out["next_offset"], **kw)
        entries += out["entries"]
    assert len(entries) == out["total_entries"]
    out["by_id"] = {e["entry_id"]: e for e in entries}
    assert len(out["by_id"]) == len(entries)  # every entry exactly once across the pages
    out["entries"] = entries
    return out


def _entry(w: World, entry_id: str, **kw: Any) -> dict[str, Any]:
    return dict(_view(w, **kw)["by_id"][entry_id])


def _row(entry: dict[str, Any], fragment: str) -> dict[str, Any]:
    (row,) = [r for r in entry["rows"] if fragment in (r["a_ref"] or "") + (r["b_ref"] or "")]
    return dict(row)


# ── A: the matched call now calls another callee ──────────────────────────────────────────────


def test_a_is_read_from_the_matched_call_on_both_readings(world: World) -> None:
    """The other side's candidate (``present_different_callee``) and the call-site facts
    (``counterpart_different_callee``) both say it, through ``counterpart_call``.

    MUTATION (verified RED): place A by ``presence_reason == 'present_different_callee'`` -> the
    call-site facts reading falls out of A."""
    v = _view(world)
    tier1 = v["by_id"][_pair_id("00001000", "00002000")]
    facts = v["by_id"][_pair_id("00003000", "00004000")]
    assert tier1["bucket"] == facts["bucket"] == "A"
    assert tier1["subclass"] == "matched_call_other_callee"
    r = _row(tier1, "00001000@cmd@0x10")
    assert r["labels"] == {
        "mechanism": "matched_call_other_callee",
        "side": "both",
        "other_callee": ["popen"],
        "elsewhere": False,
        "other_sink_class": "cmd",
    }
    f = _row(facts, "00003000@cmd@0x10")
    assert f["presence_reason"] == "counterpart_different_callee"
    assert f["labels"]["side"] == "a_only" and f["labels"]["other_callee"] == ["execl"]


def test_elsewhere_decides_between_a_and_b(world: World) -> None:
    """True -> B ``rematch_suspected``; None -> B ``elsewhere_unreadable``; False -> A."""
    v = _view(world)
    assert v["by_id"][_pair_id("00001000", "00002000")]["bucket"] == "A"
    rematch = v["by_id"][_pair_id("00005000", "00006000")]
    assert rematch["bucket"] == "B" and "rematch_suspected" in rematch["subclasses"]
    assert _row(rematch, "00005000@cmd@0x10")["labels"]["elsewhere"] is True
    unread = v["by_id"][_pair_id("00007000", "00008000")]
    assert "elsewhere_unreadable" in unread["subclasses"]
    assert _row(unread, "00007000@cmd@0x10")["labels"]["elsewhere"] is None
    assert unread["bucket"] == "B"


def test_other_sink_class_only_where_the_matched_instruction_is_a_candidate(world: World) -> None:
    """MUTATION (verified RED): attach ``other_sink_class`` to every different-callee row -> the
    call-site facts row carries it."""
    v = _view(world)
    assert (
        "other_sink_class" in _row(v["by_id"][_pair_id("00001000", "00002000")], "@0x10")["labels"]
    )
    assert (
        "other_sink_class"
        not in _row(v["by_id"][_pair_id("00003000", "00004000")], "@0x10")["labels"]
    )


# ── which pairs are listed ───────────────────────────────────────────────────────────────────


def test_identical_pairs_are_counted_not_listed_unless_a_row_says_otherwise(world: World) -> None:
    """MUTATION (verified RED): list a pair only when its similarity is below 1 -> the identical
    pair carrying an A row disappears."""
    v = _view(world)
    # Three aligned, similarity-1 pairs place no entry. The fixture puts no function body in the
    # analysis.db for them, so all three read ``no_body`` (absent from the functions table);
    # counted by pseudocode_sameness, never dropped.
    nl = v["not_listed"]
    assert nl["aligned_pseudocode_no_body"]["count"] == 3
    assert sum(c["count"] for c in nl.values()) == 3
    assert _pair_id("0000d000", "0000e000") not in v["by_id"]
    assert _pair_id("00011000", "00012000") not in v["by_id"]
    # The same identical pair, now with the matched call calling another callee: listed, in A.
    world.atlas.execute("DELETE FROM instance WHERE evidence_ref LIKE 'runB#%:0000e000@%'")
    world.inst("b", _ref("runB", "0000e000", "cmd", "0x10"), "cmd", "popen")
    world.commit()
    assert _entry(world, _pair_id("0000d000", "0000e000"))["bucket"] == "A"


def test_every_pair_and_function_is_listed_or_counted(world: World) -> None:
    v = _view(world)
    pairs = world.atlas.execute(
        "SELECT COUNT(*) FROM function_alignment WHERE diff_id = ?", (DIFF,)
    ).fetchone()[0]
    listed_pairs = sum(1 for e in v["entries"] if e["entry_id"].startswith("pair:"))
    assert listed_pairs + sum(c["count"] for c in v["not_listed"].values()) == pairs
    assert (
        v["subject_counts"]["candidate_row"] == sum(len(e["rows"]) for e in v["entries"]) + 1
    )  # the identical pair's persisted row is the one row of a pair not listed


# ── pseudocode_sameness: the reading similarity is blind to ────────────────────────────────────


def test_pseudocode_sameness_reads_its_six_states(tmp_path: Path, current: None) -> None:
    """Each aligned similarity-1 pair that places no entry is counted by pseudocode_sameness: a
    verified match, a match whose text rests on something unchecked, a match whose callees could
    not be verified, a real difference, a stub with no body at all, and a function whose body is
    empty — each kept apart. The five earlier states read exactly as they did.

    MUTATION: fold ``identical_callee_unverified`` into ``identical`` (treat 'undetermined' callees
    as equal) -> RED; call every missing body ``unavailable`` (drop the no_body split) -> RED;
    ignore text_reasons in the fold -> the qualified match reads identical -> RED."""
    w = World(tmp_path)
    # identical: same body, same resolved callees (callee_set equal)
    w.pair("00001000", "00002000", 0.97, 1.0)
    w.fn("a", "00001000", ["foo"], pseudocode="iVar = foo(0x40);")
    w.fn("b", "00002000", ["foo"], pseudocode="iVar = foo(0x40);")
    # identical_callee_unverified: same body, a side's callee list is a prefix (truncated)
    w.pair("00003000", "00004000", 0.97, 1.0)
    w.fn("a", "00003000", ["foo"], pseudocode="iVar = foo(0x40);", truncated=1)
    w.fn("b", "00004000", ["foo"], pseudocode="iVar = foo(0x40);")
    # differs: a small constant in the body changed (normalisation keeps it)
    w.pair("00005000", "00006000", 0.97, 1.0)
    w.fn("a", "00005000", ["foo"], pseudocode="iVar = foo(0x40);")
    w.fn("b", "00006000", ["foo"], pseudocode="iVar = foo(0x3f);")
    # no_body: the b side is not in the functions table (an import / PLT stub)
    w.pair("00007000", "00008000", 0.97, 1.0)
    w.fn("a", "00007000", ["foo"], pseudocode="iVar = foo(0x40);")
    # unavailable: the b side is in the table but its pseudocode is empty
    w.pair("00009000", "0000a000", 0.97, 1.0)
    w.fn("a", "00009000", ["foo"], pseudocode="iVar = foo(0x40);")
    w.fn("b", "0000a000", ["foo"], pseudocode=None)
    # identical_text_unverified: same text and callees, but the decompiler says it gave up a table
    w.pair("0000b000", "0000c000", 0.97, 1.0)
    body = "/* WARNING: Could not recover jumptable at 0x0040b668. Too many branches */\nfoo(0x40);"
    w.fn("a", "0000b000", ["foo"], pseudocode=body)
    w.fn("b", "0000c000", ["foo"], pseudocode=body)
    w.commit()
    nl = pv.get_diff_patch_view(w.atlas, DIFF)["not_listed"]
    counts = {k.replace("aligned_pseudocode_", ""): c["count"] for k, c in nl.items()}
    assert counts == {
        "identical": 1,
        "identical_text_unverified": 1,
        "identical_callee_unverified": 1,
        "differs": 1,
        "no_body": 1,
        "unavailable": 1,
    }


def test_a_changed_length_constant_lists_an_otherwise_identical_pair(
    tmp_path: Path, current: None
) -> None:
    """★ The whole point: a persisted candidate whose length constant changed lists a similarity-1
    pair BinDiff saw as unchanged, as B|sink_arg_constant_delta, with the from->to and the callee —
    direction-neutral, no fixed/regression. It ranks between sink_presence_signal and
    sink_present_no_visible_delta.

    MUTATION: read the length from sink_arg_provenance / const_sink_arg instead of size_flow ->
    the signal is empty and the pair is not listed -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 1.0)  # similarity 1: BinDiff sees nothing
    fa = json.dumps({"size_kind": "cap_const", "size_flow": {"size_arg": "0x200"}})
    fb = json.dumps({"size_kind": "cap_const", "size_flow": {"size_arg": "0x400"}})
    w.inst("a", _ref("runA", "00001000", "copy", "0x10"), "copy", "snprintf", fa)
    w.inst("b", _ref("runB", "00002000", "copy", "0x10"), "copy", "snprintf", fb)
    w.im("00001010", "00002010", "00001000")
    w.fn("a", "00001000", ["snprintf"])
    w.fn("b", "00002000", ["snprintf"])
    w.commit()
    by_id = _view(w)["by_id"]
    assert _pair_id("00001000", "00002000") in by_id  # listed at all
    e = by_id[_pair_id("00001000", "00002000")]
    assert (e["bucket"], e["subclass"]) == ("B", "sink_arg_constant_delta")
    row = next(r for r in e["rows"] if "sink_arg_constant_delta" in r)
    assert row["sink_arg_constant_delta"] == {
        "size_kind": "cap_const",
        "from": "0x200",
        "to": "0x400",
        "callee": "snprintf",
    }
    assert e["rank_key"]["subclass_rank"] == 1  # between sink_presence_signal (0) and the rest (2)


def test_a_changed_size_kind_is_a_weak_hint_not_a_delta(tmp_path: Path, current: None) -> None:
    """The size KIND changing (const -> untraced) is ``size_kind_shifted``, never a value delta,
    and does not on its own list a similarity-1 pair.

    MUTATION: emit the kind shift as a sink_arg_constant_delta -> the pair lists in B -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 1.0)
    fa = json.dumps({"size_kind": "const", "size_flow": {"size_arg": "0x40"}})
    fb = json.dumps({"size_kind": "untraced", "size_flow": {"size_arg": "len"}})
    w.inst("a", _ref("runA", "00001000", "copy", "0x10"), "copy", "strncpy", fa)
    w.inst("b", _ref("runB", "00002000", "copy", "0x10"), "copy", "strncpy", fb)
    w.im("00001010", "00002010", "00001000")
    w.fn("a", "00001000", ["strncpy"])
    w.fn("b", "00002000", ["strncpy"])
    w.commit()
    assert (
        _pair_id("00001000", "00002000") not in _view(w)["by_id"]
    )  # not listed: a shift, no delta
    # the persisted row that exists carries size_kind_shifted, not a delta
    row = pv.get_diff_patch_view(w.atlas, DIFF, view="candidate_flat")["entries"][0]
    assert "sink_arg_constant_delta" not in row


def test_a_listed_entry_keeps_its_place_and_only_gains_pseudocode_sameness(
    tmp_path: Path, current: None
) -> None:
    """★ B1 iron law: pseudocode_sameness is a fact added to a listed entry, never a reason to drop
    one. A changed pair whose candidate lines up stays listed and reads sameness='differs' when its
    pseudocode matches but its callees differ.

    MUTATION: exclude 'differs' (or any sameness state) entries from the sink_patch listing -> the
    entry disappears -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 0.5)  # similarity below 1: a changed, listed pair
    w.inst("a", _ref("runA", "00001000", "cmd", "0x10"), "cmd", "system")
    w.inst("b", _ref("runB", "00002000", "cmd", "0x10"), "cmd", "system")
    w.im("00001010", "00002010", "00001000")
    w.fn("a", "00001000", ["system", "log_a"], pseudocode="x = FUN_00012340();")
    w.fn("b", "00002000", ["system", "log_b"], pseudocode="x = FUN_00099990();")
    w.commit()
    by_id = _view(w)["by_id"]
    assert _pair_id("00001000", "00002000") in by_id  # still listed
    e = by_id[_pair_id("00001000", "00002000")]
    assert e["bucket"] == "B"
    # the body matches after normalising the FUN_ address, but the callee sets differ -> differs
    assert e["pseudocode_sameness"] == "differs"


def test_what_the_length_signal_cannot_see_is_declared_not_guessed(
    tmp_path: Path, current: None
) -> None:
    """A changed local buffer size with the call's length argument unchanged is not a
    sink_arg_constant_delta (the signal reads the call's argument only) — and that blind spot, with
    the allocation-expression one, is named in the ledger rather than left silent.

    MUTATION: drop either key from the structural blind spots -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 1.0)
    same = json.dumps({"size_kind": "const", "size_flow": {"size_arg": "0x200"}})
    w.inst("a", _ref("runA", "00001000", "copy", "0x10"), "copy", "strncpy", same)
    w.inst("b", _ref("runB", "00002000", "copy", "0x10"), "copy", "strncpy", same)
    w.im("00001010", "00002010", "00001000")
    w.fn("a", "00001000", ["strncpy"], pseudocode="char buf[512]; strncpy(buf,s,0x200);")
    w.fn("b", "00002000", ["strncpy"], pseudocode="char buf[4096]; strncpy(buf,s,0x200);")
    w.commit()
    v = pv.get_diff_patch_view(w.atlas, DIFF)
    assert _pair_id("00001000", "00002000") not in {e["entry_id"] for e in v["entries"]}
    assert v["not_listed"]["aligned_pseudocode_differs"]["count"] == 1  # the body did change
    keys = {s["key"] for s in v["blind_spots"] if s.get("count") is None}
    assert {"size_constant_outside_sink_arg", "local_buffer_size_unread"} <= keys


def test_a_re_extraction_is_not_served_a_stale_reading(tmp_path: Path, current: None) -> None:
    """The reading is cached per process, keyed on BOTH runs' build hash: a re-extraction leaves
    the content hash alone but rewrites the pseudocode, and a long-lived server must read the new
    one.

    MUTATION: drop the build hashes from the cache key -> the old 'identical' is served -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 1.0)
    w.fn("a", "00001000", ["foo"], pseudocode="p = foo(0x40);")
    w.fn("b", "00002000", ["foo"], pseudocode="p = foo(0x40);")
    w.commit()
    nl = pv.get_diff_patch_view(w.atlas, DIFF)["not_listed"]
    assert nl["aligned_pseudocode_identical"]["count"] == 1
    w.adb["b"].execute("UPDATE functions SET pseudocode = 'p = foo(0x3f);'")
    w.atlas.execute("UPDATE run SET build_hash = 'rebuilt'")  # both runs: no generation mismatch
    w.commit()
    nl = pv.get_diff_patch_view(w.atlas, DIFF)["not_listed"]
    assert nl["aligned_pseudocode_differs"]["count"] == 1


def _size(kind: str, arg: str) -> str:
    return json.dumps({"size_kind": kind, "size_flow": {"size_arg": arg}})


def _function_world(tmp_path: Path) -> World:
    """One pair (or function) per count function_states makes."""
    w = World(tmp_path)
    a, b = "runA", "runB"
    # unchanged: same body, same resolved callees
    w.pair("00001000", "00002000", 0.97, 1.0)
    w.fn("a", "00001000", ["foo"], pseudocode="p = foo(0x40);")
    w.fn("b", "00002000", ["foo"], pseudocode="p = foo(0x40);")
    # unverified: same body, a side's callee list a prefix
    w.pair("00003000", "00004000", 0.97, 1.0)
    w.fn("a", "00003000", ["foo"], pseudocode="p = foo(0x40);", truncated=1)
    w.fn("b", "00004000", ["foo"], pseudocode="p = foo(0x40);")
    # unverified: the b body is in the table but empty
    w.pair("00005000", "00006000", 0.97, 1.0)
    w.fn("a", "00005000", ["foo"], pseudocode="p = foo(0x40);")
    w.fn("b", "00006000", ["foo"], pseudocode=None)
    # no_body: the b side is not in the functions table at all
    w.pair("00007000", "00008000", 0.97, 1.0)
    w.fn("a", "00007000", ["foo"], pseudocode="p = foo(0x40);")
    # changed, with a scoped sink delta: a persisted copy whose length constant moved
    w.pair("00009000", "0000a000", 0.97, 1.0)
    w.inst(
        "a", _ref(a, "00009000", "copy", "0x10"), "copy", "snprintf", _size("cap_const", "0x200")
    )
    w.inst(
        "b", _ref(b, "0000a000", "copy", "0x10"), "copy", "snprintf", _size("cap_const", "0x400")
    )
    w.im("00009010", "0000a010", "00009000")
    w.fn("a", "00009000", ["snprintf"], pseudocode="snprintf(d,0x200,f);")
    w.fn("b", "0000a000", ["snprintf"], pseudocode="snprintf(d,0x400,f);")
    # changed, with a scoped sink delta: bucket A (the matched call now calls another callee)
    w.pair("0000b000", "0000c000", 0.97, 0.9)
    w.inst("a", _ref(a, "0000b000", "cmd", "0x10"), "cmd", "system")
    w.inst("b", _ref(b, "0000c000", "cmd", "0x10"), "cmd", "popen")
    w.im("0000b010", "0000c010", "0000b000")
    w.fn("a", "0000b000", ["system"], pseudocode="system(c);")
    w.fn("b", "0000c000", ["popen"], pseudocode="popen(c);")
    # changed, no scoped signal: only a local buffer's declared size moved (similarity 1)
    w.pair("0000d000", "0000e000", 0.97, 1.0)
    w.fn("a", "0000d000", ["bar"], pseudocode="char buf[512]; bar(buf);")
    w.fn("b", "0000e000", ["bar"], pseudocode="char buf[4096]; bar(buf);")
    # alignment undetermined, and one function with no counterpart on each side
    w.pair("0000f000", "00010000", 0.5, 0.4)
    w.unpaired("a", "00011000", "unmatched_analysis_complete")
    w.unpaired("b", "00012000", "unmatched_analysis_incomplete")
    w.commit()
    return w


def test_function_states_count_each_function_once_by_the_views_own_facts(
    tmp_path: Path, current: None
) -> None:
    """★ The first counts a reader sees. 'unchanged' is pseudocode AND callees matching — never
    similarity 1 alone; a pseudocode match with unverified callees, and an empty body, are
    'unverified', in neither of the other two; a stub with no body is counted apart; 'changed'
    splits by whether a sink in scope moved (bucket A, or a changed length constant on a ROW), and
    a change with no such signal (a local buffer resized) is 'no_scoped_signal', not unchanged.

    MUTATION: count identical_callee_unverified as unchanged -> RED; fold no_body into
    unverified -> RED; drop bucket A from the scoped split -> RED."""
    w = _function_world(tmp_path)
    s = pv.function_states(w.atlas, DIFF)
    assert s is not None and s["withheld"] is False
    assert s["unchanged"] == 1
    assert s["changed"] == {"total": 3, "with_scoped_sink_delta": 2, "no_scoped_signal": 1}
    assert s["unverified"] == {
        "total": 2,
        "identical_text_unverified": 0,
        "identical_callee_unverified": 1,
        "unavailable": 1,
    }
    assert s["identical_text_unverified_by_body"] == {"structure_differs": 0, "unknown": 0}
    assert s["no_body"] == 1
    assert s["aligned"] == 7 == s["unchanged"] + 3 + 2 + 1
    assert s["alignment_undetermined"] == 1
    assert s["one_sided"] == {
        "a": {"unmatched_analysis_complete": 1},
        "b": {"unmatched_analysis_incomplete": 1},
    }


def test_a_diff_undetermined_as_a_whole_has_no_function_counts(
    tmp_path: Path, current: None
) -> None:
    """MUTATION: return the counts of an undetermined diff (zeros) -> RED."""
    w = _function_world(tmp_path)
    w.atlas.execute("UPDATE diff_meta SET version_skew = 1")
    w.commit()
    s = pv.function_states(w.atlas, DIFF)
    assert s is not None and s["withheld"] is True and "aligned" not in s
    assert "diff_undetermined:version_skew" in s["banners"]


def test_the_significance_lens_reorders_and_never_relabels(tmp_path: Path, current: None) -> None:
    """★ sort_by='significance' moves entries, never their labels: the same entries, buckets and
    subclasses as the default view; A / a changed length constant first; a pseudocode-identical
    entry sunk but still listed; each tier named on the entry, from facts the entry itself reports.

    MUTATION: give a pseudocode-identical entry attention 1 (do not sink) -> RED; float by bucket B
    instead of by the row's delta field -> RED."""
    w = _function_world(tmp_path)
    w.pair("00013000", "00014000", 0.97, 0.6)  # a changed pair whose candidate lines up, identical
    w.inst("a", _ref("runA", "00013000", "cmd", "0x10"), "cmd", "system")
    w.inst("b", _ref("runB", "00014000", "cmd", "0x10"), "cmd", "system")
    w.im("00013010", "00014010", "00013000")
    w.fn("a", "00013000", ["system"], pseudocode="system(FUN_00012340());")
    w.fn("b", "00014000", ["system"], pseudocode="system(FUN_00099990());")
    w.pair("00015000", "00016000", 0.97, 0.7)  # a changed pair, no candidate, identical body: C
    w.fn("a", "00015000", ["memset"], pseudocode="memset(b,0,8);")
    w.fn("b", "00016000", ["memset"], pseudocode="memset(b,0,8);")
    w.commit()
    base = _view(w)
    lens = _view(w, sort_by="significance")
    assert set(lens["by_id"]) == set(base["by_id"])
    for eid, e in lens["by_id"].items():
        assert (e["bucket"], e["subclass"]) == (
            base["by_id"][eid]["bucket"],
            base["by_id"][eid]["subclass"],
        )
        assert "significance" not in base["by_id"][eid]
    order = [e["entry_id"] for e in lens["entries"]]
    att = {e["entry_id"]: e["significance"]["attention"] for e in lens["entries"]}
    assert att[_pair_id("00009000", "0000a000")] == 0  # the length constant moved
    assert att[_pair_id("0000b000", "0000c000")] == 0  # bucket A
    assert att[_pair_id("00013000", "00014000")] == 1  # guard: sink_present_no_visible_delta
    assert lens["by_id"][_pair_id("00013000", "00014000")]["significance"]["basis"] == (
        "recheckable_no_visible_delta"
    )
    assert att[_pair_id("00015000", "00016000")] == 2  # C, sunk — still listed
    assert att[_pair_id("0000f000", "00010000")] == 1  # R
    assert order.index(_pair_id("00015000", "00016000")) > order.index(
        _pair_id("0000f000", "00010000")
    )
    for e in lens["entries"]:  # the tier follows from what the entry itself reports
        rows_delta = any("sink_arg_constant_delta" in r for r in e["rows"])
        if e["bucket"] == "A" or rows_delta:
            assert e["significance"]["attention"] == 0
        elif e["bucket"] in ("B", "C") and e["significance"]["attention"] == 2:
            assert e.get("pseudocode_sameness") == "identical" or e["bucket"] == "C"


def test_an_entry_in_b_by_another_row_keeps_its_subclass_and_the_row_keeps_the_delta(
    tmp_path: Path, current: None
) -> None:
    """An entry another row already placed in B keeps that subclass; the changed length constant
    stays a fact on its own row (and still floats the entry under the lens, which reads the row).

    MUTATION: test the delta before the B landings in ``_place`` -> the subclass becomes
    sink_arg_constant_delta -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 1.0)
    w.inst(
        "a",
        _ref("runA", "00001000", "copy", "0x10"),
        "copy",
        "snprintf",
        _size("cap_const", "0x80"),
    )
    w.inst(
        "b",
        _ref("runB", "00002000", "copy", "0x10"),
        "copy",
        "snprintf",
        _size("cap_const", "0x100"),
    )
    w.im("00001010", "00002010", "00001000")
    w.inst("a", _ref("runA", "00001000", "cmd", "0x30"), "cmd", "system")  # matched to nothing
    w.fn("a", "00001000", ["snprintf", "system"])
    w.fn("b", "00002000", ["snprintf"])
    w.commit()
    by_id = _view(w)["by_id"]
    assert _pair_id("00001000", "00002000") in by_id
    e = by_id[_pair_id("00001000", "00002000")]
    assert e["bucket"] == "B" and e["subclass"] != "sink_arg_constant_delta"
    assert any("sink_arg_constant_delta" in r for r in e["rows"])


def test_the_lens_and_the_counts_read_each_fact_through_their_wiring(
    tmp_path: Path, current: None
) -> None:
    """★ End to end through get_diff_patch_view(sort_by='significance') and function_states, three
    entries B by an unmatched call: (a) pseudocode and callees identical -> sunk on that basis;
    (b) the same, but judged changed_real -> held at 1; (c) a body that differs, with ANOTHER row
    carrying a changed length constant -> floated, its subclass still instruction_unmatched, and
    counted as a change with a scoped sink delta.

    MUTATION: hand ``significance`` None for the entry's judgement -> (b) sinks -> RED; None for
    its pseudocode_sameness -> (a) is not sunk -> RED; read the scoped delta from the entry's
    subclass in ``_carries_scoped_sink_delta`` -> (c) is not counted -> RED."""
    w = World(tmp_path)
    a, b = "runA", "runB"
    for fa, fb in (("00001000", "00002000"), ("00003000", "00004000")):  # (a), (b): identical
        w.pair(fa, fb, 0.97, 0.9)
        w.inst("a", _ref(a, fa, "cmd", "0x30"), "cmd", "system")  # its call matched to nothing
        w.fn("a", fa, ["system"], pseudocode="system(c);")
        w.fn("b", fb, ["system"], pseudocode="system(c);")
    w.pair("00005000", "00006000", 0.97, 0.9)  # (c): a changed body, a constant row beside it
    w.inst("a", _ref(a, "00005000", "copy", "0x10"), "copy", "snprintf", _size("cap_const", "0x80"))
    w.inst(
        "b", _ref(b, "00006000", "copy", "0x10"), "copy", "snprintf", _size("cap_const", "0x100")
    )
    w.im("00005010", "00006010", "00005000")
    w.inst("a", _ref(a, "00005000", "cmd", "0x30"), "cmd", "system")  # matched to nothing
    w.fn("a", "00005000", ["snprintf", "system"], pseudocode="snprintf(d,0x80,f); system(c);")
    w.fn("b", "00006000", ["snprintf", "system"], pseudocode="snprintf(d,0x100,f); system(c);")
    w.commit()
    ids = {
        "a": _pair_id("00001000", "00002000"),
        "b": _pair_id("00003000", "00004000"),
        "c": _pair_id("00005000", "00006000"),
    }
    base = _view(w)["by_id"]
    assert set(ids.values()) <= set(base)
    for k in "ab":
        assert (base[ids[k]]["bucket"], base[ids[k]]["subclass"]) == ("B", "instruction_unmatched")
        assert base[ids[k]]["pseudocode_sameness"] == "identical"
    w.judge(DIFF, base[ids["b"]]["anchor_ref"], "changed_real")
    lens = _view(w, sort_by="significance")["by_id"]
    assert lens[ids["a"]]["significance"] == {"attention": 2, "basis": "pseudocode_identical"}
    assert lens[ids["b"]]["significance"] == {"attention": 1, "basis": "judged_never_sunk"}
    assert lens[ids["c"]]["significance"] == {"attention": 0, "basis": "sink_arg_constant_delta"}
    assert (lens[ids["c"]]["bucket"], lens[ids["c"]]["subclass"]) == ("B", "instruction_unmatched")
    assert lens[ids["c"]]["pseudocode_sameness"] == "differs"
    s = pv.function_states(w.atlas, DIFF)
    assert s is not None
    assert s["changed"] == {"total": 1, "with_scoped_sink_delta": 1, "no_scoped_signal": 0}
    assert s["unchanged"] == 2


def test_a_qualified_match_outside_c_is_never_sunk(tmp_path: Path, current: None) -> None:
    """I10. Three entries B by an unmatched call, texts and callees the same: the control (equal
    byte counts, no marker) sinks on its identical pseudocode; one whose byte counts differ and one
    the decompiler marked incomplete read identical_text_unverified and stay at attention 1.

    MUTATION: sink identical_text_unverified alongside identical in ``significance`` -> the two
    qualified entries reach attention 2 -> RED."""
    w = World(tmp_path)
    marker = "/* WARNING: Removing unreachable block (ram,0x00005010) */\n"
    rows = {
        "control": ("00001000", "00002000", "system(c);", 64, 64),
        "size": ("00003000", "00004000", "system(c);", 64, 72),
        "marker": ("00005000", "00006000", marker + "system(c);", 64, 64),
    }
    for fa, fb, text, size_a, size_b in rows.values():
        w.pair(fa, fb, 0.97, 0.9)
        w.inst("a", _ref("runA", fa, "cmd", "0x30"), "cmd", "system")  # matched to nothing
        w.fn("a", fa, ["system"], pseudocode=text, size_bytes=size_a)
        w.fn("b", fb, ["system"], pseudocode=text, size_bytes=size_b)
    w.commit()
    lens = _view(w, sort_by="significance")["by_id"]
    ids = {k: _pair_id(fa, fb) for k, (fa, fb, *_rest) in rows.items()}
    for eid in ids.values():
        assert lens[eid]["bucket"] == "B"
    control = lens[ids["control"]]
    assert control["pseudocode_sameness"] == "identical"
    assert control["significance"] == {"attention": 2, "basis": "pseudocode_identical"}
    for k in ("size", "marker"):
        assert lens[ids[k]]["pseudocode_sameness"] == "identical_text_unverified", k
        assert lens[ids[k]]["significance"] == {"attention": 1, "basis": "similarity"}, k


@pytest.mark.parametrize(
    "restamp",
    [
        "UPDATE run SET updated_at = '2099-01-01T00:00:00Z' WHERE run_id = 'runB'",
        "UPDATE run SET hunt_commit = 'rehunted'",  # both runs: no generation mismatch
    ],
    ids=["updated_at", "hunt_commit"],
)
def test_a_re_hunt_is_not_served_stale_size_facts(
    tmp_path: Path, current: None, restamp: str
) -> None:
    """The size facts are cached per run, keyed on its build hash, hunt commit and last update: a
    re-hunt rewrites the evidence under the same run id and must be read again.

    MUTATION: key the cache on (run_id, build_hash) alone -> the old delta is served -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 1.0)
    w.inst(
        "a",
        _ref("runA", "00001000", "copy", "0x10"),
        "copy",
        "snprintf",
        _size("cap_const", "0x200"),
    )
    w.inst(
        "b",
        _ref("runB", "00002000", "copy", "0x10"),
        "copy",
        "snprintf",
        _size("cap_const", "0x400"),
    )
    w.im("00001010", "00002010", "00001000")
    w.fn("a", "00001000", ["snprintf"])
    w.fn("b", "00002000", ["snprintf"])
    w.commit()
    assert _pair_id("00001000", "00002000") in _view(w)["by_id"]  # listed by its delta
    w.atlas.execute(
        "UPDATE instance SET flow_evidence = ? WHERE source_run_id = 'runB'",
        (_size("cap_const", "0x200"),),
    )
    w.atlas.execute(restamp)
    w.commit()
    assert _pair_id("00001000", "00002000") not in _view(w)["by_id"]  # no delta any more


def test_pseudocode_is_read_in_the_view_never_in_the_build(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ Cost placement: build_diff_view (the path annotate_diff / promote / the cross-scope
    progress block share) must never read pseudocode; only the read face does.

    MUTATION: call _pseudo_readings from build_diff_view -> the build reads pseudocode -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 1.0)
    w.fn("a", "00001000", ["foo"], pseudocode="p")
    w.fn("b", "00002000", ["foo"], pseudocode="p")
    w.commit()
    calls: list[int] = []
    monkeypatch.setattr(pv.sameness, "read_function_bodies", lambda *a: calls.append(1) or {})
    pv.build_diff_view(w.atlas, DIFF)
    assert calls == []  # the build pays nothing for pseudocode
    pv.get_diff_patch_view(w.atlas, DIFF)
    assert calls  # the read face does read it


# ── tier ─────────────────────────────────────────────────────────────────────────────────────


def test_the_tier_reads_each_sides_class_from_its_own_candidate(world: World) -> None:
    """The row carries one class (the A candidate's copy); the B candidate at the matched call is
    cmd, so the entry's tier is cmd's.

    MUTATION (verified RED): take the tier from the row's class only -> copy's tier."""
    e = _entry(world, _pair_id("0002a000", "0002b000"))
    assert e["bucket"] == "A"
    assert e["tier"] == 3
    r = _row(e, "0002a000@copy@0x10")
    assert (r["sink_class"], r["class_a"], r["class_b"]) == ("copy", "copy", "cmd")
    assert r["labels"]["other_sink_class"] == "cmd"


def test_a_wrapper_row_is_tiered_by_the_class_it_forwards_to(world: World) -> None:
    e = _entry(world, _pair_id("0002c000", "0002d000"))
    assert e["tier"] == 3


def test_a_rows_own_class_is_read_from_the_row_not_from_its_candidate_records(
    world: World,
) -> None:
    """The ref of a cmd row also carries a log candidate, so its candidate records disagree on the
    class; the entry also holds a plain log row. The cmd row still states its own class, so the
    entry is tiered cmd — only a lookup of the OTHER side's candidate can come back unreadable.

    MUTATION (verified RED): read the row's own side from its candidate records too -> both rows
    under the ref drop out and the entry is tiered by the log row (1)."""
    ref = _ref("runA", "00020000", "cmd", "0x10")
    world.inst("a", ref, "log", "syslog")
    world.inst("a", _ref("runA", "00020000", "log", "0x30"), "log", "syslog")
    world.commit()
    e = _entry(world, _pair_id("00020000", "00021000"))
    assert e["tier"] == 3
    under_ref = [r for r in e["rows"] if r["a_ref"] == ref]
    assert sorted(r["sink_class"] for r in under_ref) == ["cmd", "log"]
    # The row view's per-side class is still read from the candidate records.
    assert {r["class_a"] for r in under_ref} == {"unknown"}


# ── the second signal: callee sets ───────────────────────────────────────────────────────────


def test_fun_names_are_compared_through_the_alignment(world: World) -> None:
    """``FUN_00017000`` and ``FUN_00018000`` are one aligned pair: the same callee.

    MUTATION (verified RED): compare FUN_ names as names -> differs."""
    e = _entry(world, _pair_id("00015000", "00016000"))
    assert e["callee_set"] == {"state": "equal"}
    assert "callee_set_unchanged" in e["facts"]
    assert e["bucket"] == "C"


def test_a_callee_that_cannot_be_identified_leaves_the_set_undetermined(world: World) -> None:
    """``FUN_0001b000`` has no aligned pair: the whole comparison is undetermined — no difference
    reported, and not called unchanged. The named callees that differ are said separately."""
    e = _entry(world, _pair_id("00019000", "0001a000"))
    cs = e["callee_set"]
    assert cs["state"] == "undetermined" and cs["reason"] == "callee_identity_unresolved"
    assert "only_in_a" not in cs and "callee_set_unchanged" not in e["facts"]
    assert cs["named_callees_differ"] == {"only_in_a": ["memcpy"], "only_in_b": ["memset"]}
    assert "callee_identity_unresolved" in e["blind_spots"]


def test_a_stub_the_extractor_could_not_name_is_unresolved(world: World) -> None:
    world.pair("00040000", "00041000", 0.97, 0.6)
    world.pair("00042000", "00043000", 0.97, 1.0)
    world.fn("a", "00040000", ["FUN_00042000"], unresolved=["0x42000"])
    world.fn("b", "00041000", ["FUN_00043000"])
    world.commit()
    cs = _entry(world, _pair_id("00040000", "00041000"))["callee_set"]
    assert cs["reason"] == "callee_identity_unresolved"
    assert cs["unresolved_a"] == ["FUN_00042000"]


def test_a_truncated_list_is_undetermined(world: World) -> None:
    world.pair("00044000", "00045000", 0.97, 0.6)
    world.fn("a", "00044000", ["memset"], truncated=1)
    world.fn("b", "00045000", ["memset", "strlen"])
    world.commit()
    e = _entry(world, _pair_id("00044000", "00045000"))
    assert e["callee_set"]["reason"] == "callees_truncated"
    assert e["subclass"] == "no_sink_candidate_unchecked"


def test_a_call_one_side_makes_is_named(world: World) -> None:
    cs = _entry(world, _pair_id("00013000", "00014000"))["callee_set"]
    assert cs == {"state": "differs", "only_in_a": ["log_it"], "only_in_b": []}


def test_a_callee_that_is_a_thin_command_wrapper_is_marked(world: World) -> None:
    e = _entry(world, _pair_id("00033000", "00035000"))
    assert e["callee_set"]["only_in_b"] == ["run_cmd"]
    assert "one_hop_sink:system" in e["facts"]


def test_an_unchanged_callee_set_never_moves_an_entry_with_a_candidate(world: World) -> None:
    """The persisted pair's lists differ; the A pair's are equal-looking elsewhere: the bucket is
    the rows', whatever the callee set says."""
    e = _entry(world, _pair_id("00028000", "00029000"))
    assert e["callee_set"] == {"state": "equal"}
    assert e["bucket"] == "B" and e["subclass"] == "same_callee_non_candidate"


# ── B: the sink presence signals ─────────────────────────────────────────────────────────────


def test_the_sink_presence_signals_are_b_never_a(world: World) -> None:
    """A degraded count mismatch, a function-level candidate with no counterpart in an aligned
    pair, and an unmatched call whose sink the paired function's callees do not name.

    MUTATION (verified RED): place any of them in A -> RED."""
    v = _view(world)
    for pair, sub in (
        (("00024000", "00025000"), "sink_presence_signal:count_mismatch"),
        (("00026000", "00027000"), "sink_presence_signal:funclevel_no_counterpart"),
        (("00009000", "0000a000"), "sink_presence_signal:sink_name_absent_in_paired_callees"),
    ):
        e = v["by_id"][_pair_id(*pair)]
        assert (e["bucket"], e["subclass"]) == ("B", sub), (pair, e["subclass"])
    r = _row(v["by_id"][_pair_id("00009000", "0000a000")], "@0x30")
    assert r["sink_name_in_paired_callees"] is False


def test_an_unmatched_call_whose_sink_the_paired_function_names_stays_plain(world: World) -> None:
    e = _entry(world, _pair_id("00005000", "00006000"))
    r = _row(e, "00006000@cmd@0x40")
    assert r["presence_reason"] == "instruction_unmatched"
    assert r["sink_name_in_paired_callees"] is True
    assert r["subclass"] == "instruction_unmatched"


def test_a_changed_pair_whose_candidates_line_up_is_b_not_c(world: World) -> None:
    """A guard added around a sink call that is still there: the candidate lines up, so the pair
    is B (``sink_present_no_visible_delta``), never C."""
    e = _entry(world, _pair_id("0000b000", "0000c000"))
    assert (e["bucket"], e["subclass"]) == ("B", "sink_present_no_visible_delta")
    assert e["callee_set"]["state"] == "differs"


def test_a_changed_flow_alone_does_not_make_a(world: World) -> None:
    """Only the candidate's flow evidence differs (another source kind): the call lines up."""
    world.atlas.execute(
        "UPDATE instance SET flow_evidence = ? WHERE evidence_ref = ?",
        (json.dumps({"source_kind": "argv"}), _ref("runB", "0000c000", "cmd", "0x10")),
    )
    world.commit()
    e = _entry(world, _pair_id("0000b000", "0000c000"))
    assert e["bucket"] == "B"
    assert all(r["landing"] == "persisted" for r in e["rows"])


# ── P and R ──────────────────────────────────────────────────────────────────────────────────


def test_a_function_with_no_counterpart_is_p_with_its_presence_state(world: World) -> None:
    """MUTATION (verified RED): place these rows in R -> RED."""
    v = _view(world)
    cases = {
        "a:00022000": ("unmatched_analysis_complete", "function_unmatched"),
        "a:0002e000": ("unmatched_analysis_incomplete", "no_counterpart_undetermined"),
        "a:0002f000": ("absent", "counterpart_not_analyzed"),
        "a:00030000": ("unmatched_analysis_incomplete", "degenerate_block_source"),
    }
    for entry_id, (state, reason) in cases.items():
        e = v["by_id"][entry_id]
        assert e["bucket"] == "P" and e["presence_state"] == state, entry_id
        (r,) = e["rows"]
        assert r["presence_reason"] == reason and r["landing"] == "P", entry_id
        assert r["alignment_confidence"] is None
    assert v["by_id"]["b:00023000"]["bucket"] == "P"
    assert v["by_id"]["b:00023000"]["tier"] == "no_sink"


def test_an_undetermined_pair_is_r_with_or_without_a_candidate(world: World) -> None:
    v = _view(world)
    bare = v["by_id"][_pair_id("0001e000", "0001f000")]
    sink = v["by_id"][_pair_id("00020000", "00021000")]
    assert (bare["bucket"], bare["tier"]) == ("R", "no_sink")
    assert (sink["bucket"], sink["tier"]) == ("R", 3)
    assert _row(sink, "@0x10")["presence_reason"] == "alignment_low_confidence"
    assert bare["callee_set"] is None  # the callee lists are compared on aligned pairs only


# ── recall and source gaps ────────────────────────────────────────────────────────────────────


def test_the_gap_lists_are_fixed() -> None:
    assert pv.RECALL_GAP_SINKS == {
        "wide_char_string": ("wcscpy", "wcscat", "vswprintf"),
        "argv_runner": ("_eval",),
        "exec_path_variant": ("execvpe",),
    }
    assert pv.SOURCE_GAP_PREFIXES == {"uci_ubus": ("uci_", "ubus_")}


def test_a_sink_the_hunt_does_not_recall_keeps_a_pair_out_of_c(world: World) -> None:
    e = _entry(world, _pair_id("0001c000", "0001d000"))
    assert (e["bucket"], e["subclass"], e["tier"]) == (
        "B",
        "recall_gap_sink:wide_char_string",
        "no_sink",
    )
    assert "recall_gap_sink:wide_char_string" in e["blind_spots"]


def test_an_unmodelled_source_is_only_a_tag(world: World) -> None:
    """MUTATION (verified RED): treat the source prefixes as a C gate -> the C pair calling
    ``uci_get`` leaves C."""
    v = _view(world)
    tagged = v["by_id"][_pair_id("00009000", "0000a000")]
    assert "source_gap:uci_ubus" in tagged["facts"] and tagged["bucket"] == "B"
    c = v["by_id"][_pair_id("00031000", "00032000")]
    assert c["bucket"] == "C" and "source_gap:uci_ubus" not in c["facts"]


# ── wrapper rows ─────────────────────────────────────────────────────────────────────────────


def test_only_function_level_wrapper_rows_are_marked_blind(world: World) -> None:
    """MUTATION (verified RED): mark ``wrapper_callsite`` rows too -> RED."""
    e = _entry(world, _pair_id("0002c000", "0002d000"))
    (fn_level,) = [r for r in e["rows"] if (r["a_ref"] or "").endswith("@cmd_via_wrapper")]
    call = _row(e, "cmd_via_wrapper@0x20")
    assert fn_level["key_granularity"] == "wrapper"
    assert fn_level["facts"] == ["wrapper_granularity_blind"]
    assert call["key_granularity"] == "wrapper_callsite" and "facts" not in call
    assert fn_level["sink_name_in_paired_callees"] == "unknown"


# ── when the callee lists cannot be compared ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("stale", "reason"), [(True, "diff_logic_changed"), (None, "source_unavailable")]
)
def test_a_diff_not_shown_current_compares_no_callee_lists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stale: bool | None, reason: str
) -> None:
    """source_stale true AND null both stop the second signal: every aligned entry's callee set is
    undetermined, and what would be C is ``no_sink_candidate_unchecked``.

    MUTATION (verified RED): stop it on true only -> the null case compares the lists."""
    w = World(tmp_path)
    _rich(w)
    monkeypatch.setattr(
        pv,
        "diff_source_staleness",
        lambda atlas, diff_id: {
            "source_stale": stale,
            "source_stale_reason": reason,
            "toolchain_checked": False,
        },
    )
    v = _view(w)
    assert (v["source_stale"], v["source_stale_reason"], v["toolchain_checked"]) == (
        stale,
        reason,
        False,
    )
    aligned = [e for e in v["entries"] if e.get("alignment_state") == "aligned"]
    assert aligned and all(e["callee_set"]["reason"] == "source_stale" for e in aligned)
    c = [e for e in v["entries"] if e["bucket"] == "C"]
    assert c and {e["subclass"] for e in c} == {"no_sink_candidate_unchecked"}
    assert not any(e["subclass"].startswith("recall_gap_sink") for e in v["entries"])
    spots = {s["key"]: s for s in v["blind_spots"]}
    assert spots["source_stale"]["count"] == len(aligned)


def test_a_current_diff_compares_them(world: World) -> None:
    v = _view(world)
    assert (v["source_stale"], v["toolchain_checked"]) == (False, True)
    assert v["by_id"][_pair_id("00013000", "00014000")]["subclass"] == "no_sink_candidate"


def test_an_unreadable_analysis_db_is_named_and_nothing_is_c(world: World) -> None:
    world.atlas.execute(
        "UPDATE run SET analysis_db_path = ? WHERE run_id = 'runA'", (str(world.tmp / "gone.db"),)
    )
    world.commit()
    v = _view(world)
    assert {e["subclass"] for e in v["entries"] if e["bucket"] == "C"} == {
        "no_sink_candidate_unchecked"
    }
    spots = {s["key"]: s for s in v["blind_spots"]}
    assert "analysis_db_unavailable:a" in spots and "analysis_db_unavailable:b" not in spots
    assert spots["analysis_db_unavailable:a"]["detail"]


# ── banners ──────────────────────────────────────────────────────────────────────────────────


def test_no_instruction_data_is_a_banner_read_from_the_table(tmp_path: Path, current: None) -> None:
    """A diff with no stored instruction pairs and no candidate at all: no row says anything, and
    the banner is still there.

    MUTATION (verified RED): raise the banner from the rows' reasons -> missing here."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 0.6)
    w.commit()
    assert "instruction_data_absent" in _view(w)["banners"]


def test_instruction_data_present_raises_no_banner(world: World) -> None:
    assert "instruction_data_absent" not in _view(world)["banners"]


@pytest.mark.parametrize(
    ("column", "value", "reason"),
    [
        ("version_skew", 1, "version_skew"),
        ("diff_ok", 0, "diff_failed"),
        ("sha256_b", None, "diff_meta_missing_sha"),
    ],
)
def test_a_diff_wide_reason_lists_nothing_and_counts_what_is_withheld(
    world: World, column: str, value: Any, reason: str
) -> None:
    """MUTATION (verified RED): let a diff-wide reason fall through to B -> entries appear."""
    world.atlas.execute(f"UPDATE diff_meta SET {column} = ?", (value,))
    world.commit()
    v = _view(world)
    assert f"diff_undetermined:{reason}" in v["banners"]
    assert v["entries"] == [] and v["counts"]["by_bucket"] == {}
    assert v["counts"]["withheld"]["function_pairs"] > 0


def test_a_diff_wide_reason_holds_with_no_candidate_at_all(tmp_path: Path, current: None) -> None:
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 0.6)
    w.atlas.execute("UPDATE run SET build_hash = 'other' WHERE run_id = 'runB'")
    w.commit()
    v = _view(w)
    assert "diff_undetermined:extraction_generation_mismatch" in v["banners"]
    assert v["entries"] == []


# ── the three views ──────────────────────────────────────────────────────────────────────────


def test_the_three_views_count_the_same_subjects(world: World) -> None:
    """MUTATION (verified RED): count the candidate rows of the listed entries only in one view ->
    the views disagree."""
    counts = [
        pv.get_diff_patch_view(world.atlas, DIFF, view=view)["subject_counts"] for view in pv.VIEWS
    ]
    assert counts[0] == counts[1] == counts[2]
    assert counts[0]["string_edge"] == 2 and counts[0]["candidate_row"] > 0


def test_string_edge_is_get_diff_deltas(world: World) -> None:
    from treasure_map.lib.query.diff_align import get_diff_deltas

    v = pv.get_diff_patch_view(world.atlas, DIFF, view="string_edge", limit=1)
    deltas = get_diff_deltas(world.atlas, DIFF, limit=1)
    assert v["entries"] == deltas["deltas"]
    assert (v["total_entries"], v["next_offset"]) == (2, 1)
    assert v["subject_unit"] == "string_edge"


def _flat_parity(w: World) -> str:
    tools = mcp_app.make_tools(w.path)
    flat = tools["get_diff_patch_view"](DIFF, view="candidate_flat", limit=5, offset=3)
    rows = tools["get_diff_sink_overlay"](diff_id=DIFF, detail="rows", limit=5, offset=3)
    assert json.dumps(flat["entries"]) == json.dumps(rows["rows"])
    assert (flat["total_entries"], flat["next_offset"]) == (rows["total_rows"], rows["next_offset"])
    return str(flat["baseline_state"])


def test_candidate_flat_is_get_diff_sink_overlay_word_for_word(world: World) -> None:
    """Computed in memory, and read back from a stored baseline: the same rows, order and fields
    (the stored callee JSON is written with sorted keys and read back in the overlay's order).

    MUTATION (verified RED): read the stored counterpart_callee back as stored -> the key order
    differs."""
    assert _flat_parity(world) == "recomputed_absent"
    so.persist_sink_overlay(world.atlas, DIFF)
    assert _flat_parity(world) == "fresh"


def test_the_string_edges_ride_on_the_entry_they_are_anchored_at(world: World) -> None:
    v = _view(world)
    pair = v["by_id"][_pair_id("00013000", "00014000")]["string_edges"]
    assert pair == {
        "by_delta_kind": {"layer_changed": 1},
        "changed": ["libx|strcmp_gate|ping|00013000"],
    }
    assert v["by_id"]["b:00023000"]["string_edges"]["by_delta_kind"] == {"layer_changed": 1}


# ── reading the stored baseline ──────────────────────────────────────────────────────────────


def _no_compute(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("computed although the stored baseline is current")

    monkeypatch.setattr(pv, "compute_sink_overlay", refuse)


def _candidate_rows(w: World) -> list[tuple[Any, ...]]:
    return [
        tuple(r)
        for r in w.atlas.execute(
            "SELECT * FROM dimension_delta WHERE subject_kind = 'candidate' ORDER BY id"
        )
    ]


def test_a_current_baseline_is_read_not_computed(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``elsewhere`` comes from the stored ``counterpart_callee``: flip it there and the entry
    moves, with nothing computed."""
    so.persist_sink_overlay(world.atlas, DIFF)
    _no_compute(monkeypatch)
    ref = _ref("runA", "00001000", "cmd", "0x10")
    key = f"callsite|cmd|{ref}|{_ref('runB', '00002000', 'cmd', '0x10')}"
    stored = world.atlas.execute(
        "SELECT counterpart_callee FROM dimension_delta WHERE subject_key = ?", (key,)
    ).fetchone()[0]
    callee = json.loads(stored)
    callee["same_callee_candidate_elsewhere"] = True
    world.atlas.execute(
        "UPDATE dimension_delta SET counterpart_callee = ? WHERE subject_key = ?",
        (json.dumps(callee, sort_keys=True), key),
    )
    world.commit()
    v = _view(world)
    assert v["baseline_state"] == "fresh" and v["overlay_coverage"] is None
    assert v["by_id"][_pair_id("00001000", "00002000")]["subclass"] == "rematch_suspected"


@pytest.mark.parametrize("state", ["recomputed_absent", "recomputed_stale"])
def test_an_absent_or_stale_baseline_is_computed_and_never_stored(
    world: World, monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    """MUTATION (verified RED): store the computed overlay -> the stored rows change."""
    if state == "recomputed_stale":
        so.persist_sink_overlay(world.atlas, DIFF)
        world.atlas.execute("UPDATE run SET hunt_instances = 11 WHERE run_id = 'runB'")
    world.atlas.execute("UPDATE diff_meta SET baseline_dropped = 1")
    world.commit()
    before = (
        _candidate_rows(world),
        world.atlas.execute("SELECT baseline_dropped FROM diff_meta").fetchone()[0],
    )
    calls: list[str] = []
    real = pv.compute_sink_overlay
    monkeypatch.setattr(pv, "compute_sink_overlay", lambda a, d: calls.append(d) or real(a, d))
    v = _view(world)
    assert v["baseline_state"] == state
    assert v["overlay_coverage"]["coverage_violation"] is False
    assert calls and set(calls) == {DIFF}
    after = (
        _candidate_rows(world),
        world.atlas.execute("SELECT baseline_dropped FROM diff_meta").fetchone()[0],
    )
    assert after == before


def test_a_baseline_whose_two_reads_disagree_is_not_used(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The rows and their callee column must name the same subjects.

    MUTATION (verified RED): skip the check -> the baseline is used with a row missing."""
    so.persist_sink_overlay(world.atlas, DIFF)
    real = pv.read_sink_overlay_baseline

    def one_short(atlas: sqlite3.Connection, diff_id: str) -> dict[str, Any]:
        out = real(atlas, diff_id)
        out["rows"] = out["rows"][1:]
        return out

    monkeypatch.setattr(pv, "read_sink_overlay_baseline", one_short)
    assert _view(world)["baseline_state"] == "recomputed_mismatch"


def test_the_two_reads_see_one_state_of_the_table(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Another connection deletes a stored row between the two reads. Read in one transaction,
    both see the table as it was, and the baseline is used.

    MUTATION (verified RED): drop the BEGIN -> the second read sees the deletion -> mismatch."""
    so.persist_sink_overlay(world.atlas, DIFF)
    real = pv.read_sink_overlay_baseline

    def then_write(atlas: sqlite3.Connection, diff_id: str) -> dict[str, Any]:
        out = real(atlas, diff_id)
        other = sqlite3.connect(world.path)
        other.execute(
            "DELETE FROM dimension_delta WHERE id = (SELECT MIN(id) FROM dimension_delta "
            "WHERE subject_kind = 'candidate')"
        )
        other.commit()
        other.close()
        return out

    monkeypatch.setattr(pv, "read_sink_overlay_baseline", then_write)
    _no_compute(monkeypatch)
    out = pv.get_diff_patch_view(world.atlas, DIFF)
    assert out["baseline_state"] == "fresh"
    assert not world.atlas.in_transaction


# ── isolation ────────────────────────────────────────────────────────────────────────────────


def _dump(path: Path) -> str:
    conn = sqlite3.connect(path)
    try:
        return hashlib.sha256("\n".join(conn.iterdump()).encode()).hexdigest()
    finally:
        conn.close()


def test_the_tool_writes_nothing_and_leaves_the_other_diff_tools_as_they_were(
    world: World,
) -> None:
    so.persist_sink_overlay(world.atlas, DIFF)
    world.atlas.execute("UPDATE run SET hunt_instances = 11 WHERE run_id = 'runB'")  # stale
    world.commit()
    tools = mcp_app.make_tools(world.path)
    deltas = tools["get_diff_deltas"](DIFF)
    overlay = tools["get_diff_sink_overlay"](diff_id=DIFF, detail="rows", limit=2000)
    before = _dump(world.path)
    for view in pv.VIEWS:
        out = tools["get_diff_patch_view"](DIFF, view=view)
        assert "error" not in out and "stale_scan" not in out, out
    assert _dump(world.path) == before
    assert tools["get_diff_deltas"](DIFF) == deltas
    assert tools["get_diff_sink_overlay"](diff_id=DIFF, detail="rows", limit=2000) == overlay


def test_the_view_is_outside_the_code_a_diff_or_baseline_is_versioned_by() -> None:
    """Its module is not hashed, and no hashed module imports it: changing the view never makes a
    stored diff or baseline read as stale.

    MUTATION (verified RED): import it from a hashed module -> RED."""
    name = "lib.query.patch_view"
    entries = cv.DIFF_CODE_ENTRIES + cv.OVERLAY_CODE_ENTRIES
    assert all(e.partition(":")[0] != name for e in entries)
    package = Path(cv.__file__).resolve().parents[2]
    for module in sorted({e.partition(":")[0] for e in entries}):
        tree = ast.parse(cv._module_path(package, module).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported = {node.module, *(f"{node.module}.{a.name}" for a in node.names)}
                assert f"treasure_map.{name}" not in imported, module


def test_the_tool_is_refused_on_a_stale_run(world: World) -> None:
    world.atlas.execute("UPDATE run SET build_hash = 'other' WHERE run_id = 'runA'")
    world.commit()
    out = mcp_app.make_tools(world.path)["get_diff_patch_view"](DIFF)
    assert out["stale_scan"]["diff_side"] == "a"


# ── where every overlay reason lands ─────────────────────────────────────────────────────────


def _documented_reasons() -> list[str]:
    """The reasons the overlay's module docstring lists (between ``presence_reason`` values and
    NOT IMPLEMENTED), less the four marks there that are not reasons."""
    doc = so.__doc__ or ""
    start = doc.index("``presence_reason`` values") + len("``presence_reason`` values")
    section = doc[start : doc.index("NOT IMPLEMENTED")]
    marks = re.findall(r"``([^`]+)``", section)
    not_reasons = {
        "build_hash",
        "hunt_commit",
        "_refuse_stale_diff",
        'callee_backend="atlas_candidates"',
    }
    return list(dict.fromkeys(m for m in marks if m not in not_reasons))


# reason -> {(confidence set, elsewhere, sink name in paired callees): (landing, subclass)};
# "*" = the same for every condition.
_SPS = "sink_presence_signal"
_EXPECTED: dict[str, Any] = {
    "diff_meta_missing_sha": ("banner", "diff_undetermined:diff_meta_missing_sha"),
    "diff_failed": ("banner", "diff_undetermined:diff_failed"),
    "version_skew": ("banner", "diff_undetermined:version_skew"),
    "extraction_generation_mismatch": (
        "banner",
        "diff_undetermined:extraction_generation_mismatch",
    ),
    "binary_not_diffed": ("banner", "diff_undetermined:binary_not_diffed"),
    "shadowed_by_name_collision": ("banner", "diff_undetermined:shadowed_by_name_collision"),
    "function_unmatched": ("P", "unmatched_analysis_complete"),
    "counterpart_not_analyzed": ("P", "absent"),
    "no_counterpart_undetermined": {
        False: ("P", "unmatched_analysis_incomplete"),
        True: ("B", f"{_SPS}:funclevel_no_counterpart"),
    },
    "alignment_low_confidence": ("R", "alignment_low_confidence"),
    "degenerate_block_source": {
        False: ("P", "unmatched_analysis_incomplete"),
        True: ("R", "degenerate_block_source"),
    },
    "crossside_match_degraded": ("B", "crossside_match_degraded"),
    "instruction_unmatched": "by_sink_name",
    "present_different_callee": "by_elsewhere",
    "crossgranularity_unresolved": ("B", "crossgranularity_unresolved"),
    "callee_unreadable": ("B", "callee_unreadable"),
    "counterpart_call_facts_absent": ("B", "counterpart_call_facts_absent"),
    "counterpart_facts_stale": ("B", "counterpart_facts_stale"),
    "counterpart_no_call_fact": ("B", "counterpart_no_call_fact"),
    "counterpart_call_ambiguous": ("B", "counterpart_call_ambiguous"),
    "counterpart_callee_unresolved": ("B", "counterpart_callee_unresolved"),
    "counterpart_same_callee": ("B", "same_callee_non_candidate"),
    "counterpart_different_callee": "by_elsewhere",
    "counterpart_not_candidate": ("B", "counterpart_not_candidate"),
    "a_counterpart_not_candidate": ("B", "a_counterpart_not_candidate"),
    "crossside_count_mismatch": ("B", f"{_SPS}:count_mismatch"),
    "coclaim_unresolved": ("B", "coclaim_unresolved"),
    "callsite_not_exported": ("R", "callsite_not_exported"),
}


def test_every_documented_reason_lands_by_its_conditions() -> None:
    """The overlay's 28 reasons, each placed — by a rule that depends only on the stated
    conditions — and never as ``unmapped_reason``. A reason the view does not know lands in B,
    named.

    MUTATION (verified RED): drop any reason from the mapping -> it lands unmapped; let a
    diff-wide reason fall through to B; stop splitting ``no_counterpart_undetermined`` or
    ``degenerate_block_source`` by confidence -> RED."""
    reasons = _documented_reasons()
    assert len(reasons) == 28 and set(reasons) == set(_EXPECTED)
    for reason in reasons:
        rule = _EXPECTED[reason]
        for conf in (None, 0.95):
            for elsewhere in (False, True, None):
                for in_paired in (False, True, None):
                    got = pv.row_landing(
                        "presence_undetermined",
                        reason,
                        "present_different_callee" if rule == "by_elsewhere" else None,
                        confidence=conf,
                        elsewhere=elsewhere,
                        sink_name_in_paired_callees=in_paired,
                        presence_state="unmatched_analysis_incomplete",
                    )
                    if rule == "by_elsewhere":
                        want = {
                            False: ("A", "matched_call_other_callee"),
                            True: ("B", "rematch_suspected"),
                            None: ("B", "elsewhere_unreadable"),
                        }[elsewhere]
                    elif rule == "by_sink_name":
                        want = (
                            ("B", f"{_SPS}:sink_name_absent_in_paired_callees")
                            if in_paired is False
                            else ("B", "instruction_unmatched")
                        )
                    elif isinstance(rule, dict):
                        want = rule[conf is not None]
                    else:
                        want = rule
                    assert got == want, (reason, conf, elsewhere, in_paired, got)
    unknown = pv.row_landing(
        "presence_undetermined",
        "a_reason_from_later",
        None,
        confidence=0.95,
        elsewhere=None,
        sink_name_in_paired_callees=None,
        presence_state=None,
    )
    assert unknown == ("B", "unmapped_reason:a_reason_from_later")


def test_an_unmapped_reason_is_counted(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    """A reason the view does not know is placed in B under its own name, and counted."""
    real = pv.compute_sink_overlay

    def renamed(atlas: sqlite3.Connection, diff_id: str) -> so.SinkOverlayResult:
        out = real(atlas, diff_id)
        rows = [
            replace(r, presence_reason="a_reason_from_later")
            if r.presence_reason == "alignment_low_confidence"
            else r
            for r in out.rows
        ]
        return so.SinkOverlayResult(rows, out.coverage)

    monkeypatch.setattr(pv, "compute_sink_overlay", renamed)
    v = _view(world)
    assert v["counts"]["by_row_subclass"] == {
        **v["counts"]["by_row_subclass"],
        "B|unmapped_reason:a_reason_from_later": 1,
    }
    spot = {s["key"]: s for s in v["blind_spots"]}["unmapped_reason"]
    assert (spot["count"], spot["unit"]) == (1, "candidate_row")


# ── the subject key read back ────────────────────────────────────────────────────────────────


def _overlay_row(a_ref: str | None, b_ref: str | None, gran: str, cls: str) -> so.SinkOverlayRow:
    return so.SinkOverlayRow(
        diff_id=DIFF,
        binary="libx",
        sink_class=cls,
        a_ref=a_ref,
        b_ref=b_ref,
        key_granularity=gran,
        presence="persisted",
        presence_reason=None,
        match_basis=None,
        counterpart_call=None,
        alignment_confidence=None,
    )


@pytest.mark.parametrize(
    ("a_ref", "b_ref", "gran", "cls"),
    [
        (
            _ref("runA", "00001000", "cmd", "0x10"),
            _ref("runB", "00002000", "cmd", "0x10"),
            "callsite",
            "cmd",
        ),
        (_ref("runA", "00001000", "cmd_via_wrapper", "-0x8"), None, "wrapper_callsite", "cmd"),
        (None, _ref("runB", "00002000", "copy"), "degraded_out_of_body", "copy"),
        (
            _ref("runA", "00001000", "cmd_via_wrapper"),
            _ref("runB", "00002000", "cmd_via_wrapper"),
            "wrapper",
            "fmt_string",
        ),
    ],
)
def test_a_subject_key_reads_back_to_its_row(
    a_ref: str | None, b_ref: str | None, gran: str, cls: str
) -> None:
    """MUTATION (verified RED): read the granularity and the class in the wrong order -> RED."""
    key = so._subject_key(_overlay_row(a_ref, b_ref, gran, cls))
    assert pv.split_subject_key(key, "runA", "runB") == (gran, cls, a_ref, b_ref)


def test_a_subject_key_that_splits_two_ways_is_not_read() -> None:
    assert pv.split_subject_key("callsite|cmd|runA#x|runB#y|runB#z", "runA", "runB") is None


# ── order ────────────────────────────────────────────────────────────────────────────────────


def _e(bucket: str, tier: int | str, subclass: str = "", sim: float = 0.5, addr: str = "x") -> Any:
    pair = pv._Pair(addr, addr, None, None, 0.95, sim, "aligned", None, None)
    e = pv._Entry(pair=None if bucket == "P" else pair, unpaired=None, bucket=bucket)
    if bucket == "P":
        e.unpaired = pv._Unpaired("a", addr, None, "unmatched_analysis_complete", None)
    e.tier, e.subclass = tier, subclass
    e.rank = pv._rank(e)
    return e


def _order(*entries: Any, sort_by: str | None = None) -> list[str]:
    return [e.entry_id for e in pv._sort(list(entries), sort_by)]


def test_a_comes_first_and_the_tier_leads_the_candidate_entries() -> None:
    """MUTATION (verified RED): sort R before B ahead of the tier -> an R of tier 1 precedes a B
    of tier 3."""
    a1 = _e("A", 1, "matched_call_other_callee", addr="a1")
    b3 = _e("B", 3, "instruction_unmatched", addr="b3")
    r1 = _e("R", 1, "alignment_low_confidence", addr="r1")
    r3 = _e("R", 3, "alignment_low_confidence", addr="r3")
    assert _order(r1, b3, a1, r3) == [a1.entry_id, r3.entry_id, b3.entry_id, r1.entry_id]


def test_an_entry_with_no_candidate_comes_after_every_entry_with_one() -> None:
    """MUTATION (verified RED): order a candidate-less R among the candidate entries -> it
    precedes a B of tier 0."""
    b0 = _e("B", 0, "instruction_unmatched", addr="b0")
    r_none = _e("R", "no_sink", "alignment_low_confidence", sim=0.0, addr="r_none")
    c = _e("C", "no_sink", "no_sink_candidate", sim=0.0, addr="c")
    gap = _e("B", "no_sink", "recall_gap_sink:wide_char_string", sim=0.9, addr="gap")
    unchecked = _e("C", "no_sink", "no_sink_candidate_unchecked", sim=0.9, addr="unchecked")
    p = _e("P", 3, "unmatched_analysis_complete", addr="p")
    assert _order(p, c, unchecked, r_none, gap, b0) == [
        b0.entry_id,
        gap.entry_id,
        r_none.entry_id,
        unchecked.entry_id,
        c.entry_id,
        p.entry_id,
    ]


def test_inside_b_the_sink_presence_signals_lead() -> None:
    plain = _e("B", 2, "instruction_unmatched", sim=0.1, addr="plain")
    signal = _e("B", 2, "sink_presence_signal:count_mismatch", sim=0.9, addr="signal")
    assert _order(plain, signal) == [signal.entry_id, plain.entry_id]


def test_an_unknown_tier_is_never_sorted_below_a_known_one() -> None:
    known = _e("B", 3, "instruction_unmatched", addr="known")
    unknown = _e("B", "unknown", "instruction_unmatched", addr="unknown")
    assert _order(known, unknown) == [unknown.entry_id, known.entry_id]


def test_sort_by_puts_one_component_first_and_p_stays_last() -> None:
    lo = _e("B", 1, "instruction_unmatched", sim=0.1, addr="lo")
    hi = _e("A", 3, "matched_call_other_callee", sim=0.9, addr="hi")
    p = _e("P", 3, "unmatched_analysis_complete", addr="0")
    assert _order(hi, p, lo, sort_by="similarity") == [lo.entry_id, hi.entry_id, p.entry_id]
    assert _order(lo, p, hi, sort_by="address") == [hi.entry_id, lo.entry_id, p.entry_id]


def test_each_entry_names_its_order(world: World) -> None:
    v = _view(world)
    first = v["entries"][0]
    assert first["bucket"] == "A" and first["rank_key"]["segment"] == 1
    assert v["entries"][-1]["bucket"] == "P"


# ── words ────────────────────────────────────────────────────────────────────────────────────

_WORDS = {"removed", "added", "gone", "new", "bounded", "safe", "fix", "patch", "regression"}


def _labels(v: dict[str, Any]) -> set[str]:
    """Every label, subclass, reason, fact, blind-spot key and sub-fact key the view emits."""
    out: set[str] = set(v["counts"]["by_subclass"]) | set(v["counts"]["by_row_subclass"])
    out |= {s["key"] for s in v["blind_spots"]} | set(v["banners"]) | set(v["not_listed"])
    for e in v["entries"]:
        out |= {e["subclass"], *e["subclasses"], *e["facts"], *e["blind_spots"]}
        out |= set((e["callee_set"] or {}).keys()) | {str((e["callee_set"] or {}).get("reason"))}
        out |= set((e["callee_set"] or {}).get("named_callees_differ", {}))
        for r in e["rows"]:
            out |= {str(r["presence_reason"]), str(r["subclass"]), str(r["landing"])}
            out |= set(r.get("labels", {})) | {str(r.get("labels", {}).get("mechanism"))}
            out |= set(r.get("facts", ())) | {str(r.get("labels", {}).get("side"))}
    return out


def test_no_label_says_what_a_change_means(world: World) -> None:
    """MUTATION (verified RED): name a subclass ``sink_removed`` -> RED."""
    labels = _labels(_view(world))
    assert len(labels) > 40
    for label in labels:
        words = set(re.split(r"[^a-z0-9]+", label.lower()))
        assert not words & _WORDS, label


# ── arguments ────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "kw",
    [
        {"view": "flat"},
        {"limit": 0},
        {"limit": 2001},
        {"offset": -1},
        {"bucket": "D"},
        {"sort_by": "score"},
        {"tier": "high"},
        {"view": "candidate_flat", "bucket": "A"},
    ],
)
def test_a_bad_argument_is_an_error_not_an_empty_page(tmp_path: Path, kw: dict[str, Any]) -> None:
    assert "error" in pv.get_diff_patch_view(World(tmp_path).atlas, DIFF, **kw)


def test_an_unknown_diff_is_said(tmp_path: Path) -> None:
    out = pv.get_diff_patch_view(World(tmp_path).atlas, "runA::runB::nothing")
    assert out["found"] is False


def test_the_filters_narrow_the_entries_not_the_counts(world: World) -> None:
    whole = _view(world)
    only_a = _view(world, bucket="A")
    assert {e["bucket"] for e in only_a["entries"]} == {"A"}
    assert only_a["counts"] == whole["counts"]
    spots = _view(world, blind_spot="callee_identity_unresolved")["entries"]
    assert [e["entry_id"] for e in spots] == [_pair_id("00019000", "0001a000")]
    by_row = _view(world, subclass="instruction_unmatched")["entries"]
    assert _pair_id("00005000", "00006000") in {e["entry_id"] for e in by_row}
    assert {e["tier"] for e in _view(world, tier=3)["entries"]} == {3}


# ── the R bucket's proposed reading, the qualified text match, hidden_region, deltas ──────────

U_PAIRS = {
    "identical_unique": ("00001000", "00002000"),
    "identical_not_unique": ("00003000", "00004000"),
    "identical_callee_unverified": ("00005000", "00006000"),
    "identical_text_unverified": ("00007000", "00008000"),
    "differs": ("00009000", "0000a000"),
    "no_body": ("0000b000", "0000c000"),
    "unavailable": ("0000d000", "0000e000"),
}
TWIN_B = "00004f00"  # a second B function holding identical_not_unique's body


def _undetermined_world(tmp_path: Path) -> World:
    """One undetermined pair per proposed-reading state, each with its own body (so no two pairs
    share one), plus one aligned, unchanged pair."""
    w = World(tmp_path)
    p = U_PAIRS
    for i, (fa, fb) in enumerate(p.values(), start=1):
        w.pair(fa, fb, 0.5, 0.8)
        w.fn("a", fa, ["foo"], pseudocode=f"foo({i});", size_bytes=16)
    w.fn("b", p["identical_unique"][1], ["foo"], pseudocode="foo(1);", size_bytes=16)
    w.fn("b", p["identical_not_unique"][1], ["foo"], pseudocode="foo(2);", size_bytes=16)
    w.fn("b", TWIN_B, ["foo"], pseudocode="foo(2);", size_bytes=16)
    w.fn("b", p["identical_callee_unverified"][1], ["foo"], pseudocode="foo(3);", truncated=1)
    w.fn("b", p["identical_text_unverified"][1], ["foo"], pseudocode="foo(4);", size_bytes=20)
    w.fn("b", p["differs"][1], ["foo"], pseudocode="foo(6);", size_bytes=16)
    # no_body: the B side is not in the functions table at all
    w.fn("b", p["unavailable"][1], ["foo"], pseudocode=None)
    w.pair("00010000", "00020000", 0.97, 1.0)  # aligned and unchanged
    w.fn("a", "00010000", ["foo"], pseudocode="bar();")
    w.fn("b", "00020000", ["foo"], pseudocode="bar();")
    w.commit()
    return w


def _proposed(v: dict[str, Any], state: str) -> dict[str, Any]:
    entry_id = _pair_id(*U_PAIRS[state])
    assert entry_id in v["by_id"], entry_id
    reading = v["by_id"][entry_id]["proposed_pair_reading"]
    assert isinstance(reading, dict)
    return reading


def test_an_undetermined_pair_carries_a_proposed_reading_never_a_sameness(
    tmp_path: Path, current: None
) -> None:
    """T1. The proposed reading sits beside the R entry; its pseudocode_sameness key is never
    there, and it moves the entry nowhere.

    MUTATION: drop the aligned gate in ``_aligned_read`` -> every R entry gains a
    pseudocode_sameness -> RED."""
    v = _view(_undetermined_world(tmp_path))
    for state, pair in U_PAIRS.items():
        e = v["by_id"][_pair_id(*pair)]
        assert e["bucket"] == "R" and e["subclass"] == "alignment_low_confidence", state
        assert "pseudocode_sameness" not in e, state
        assert e["callee_set"] is None  # the entry's own callee_set is for aligned pairs only
        assert e["proposed_pair_reading"]["pairing"] == "undetermined"
        assert e["proposed_pair_reading"]["state"] == state


def test_the_proposed_readings_never_enter_the_aligned_counts(
    tmp_path: Path, current: None
) -> None:
    """T2 / T3. Seven undetermined pairs, one per state: counted in
    alignment_undetermined_reading, whose states sum to alignment_undetermined, and never in the
    aligned counts.

    MUTATION: add each proposed state into the aligned tally -> aligned/unchanged move -> RED;
    skip one state in the proposed count -> RED."""
    s = pv.function_states(_undetermined_world(tmp_path).atlas, DIFF)
    assert s is not None
    assert (s["aligned"], s["unchanged"], s["no_body"]) == (1, 1, 0)
    assert s["changed"]["total"] == 0 and s["unverified"]["total"] == 0
    assert s["alignment_undetermined"] == 7
    assert s["alignment_undetermined_reading"] == {state: 1 for state in U_PAIRS}
    assert sum(s["alignment_undetermined_reading"].values()) == s["alignment_undetermined"]


def test_a_body_found_twice_on_a_side_is_not_unique(tmp_path: Path, current: None) -> None:
    """T4 / T7. The same body twice on B: identical_not_unique, and B's other copy is named —
    never the pair's own B function.

    MUTATION: skip the uniqueness check -> identical_unique -> RED; keep addr_b in
    a_body_elsewhere_in_b -> count 2 -> RED."""
    v = _view(_undetermined_world(tmp_path))
    twin = _proposed(v, "identical_not_unique")
    assert twin["state"] == "identical_not_unique"
    assert twin["occurrences"] == {"a": 1, "b": 2}
    assert twin["a_body_elsewhere_in_b"] == {"count": 1, "addrs": [TWIN_B]}
    assert twin["b_body_elsewhere_in_a"] == {"count": 0, "addrs": []}
    unique = _proposed(v, "identical_unique")
    assert unique["occurrences"] == {"a": 1, "b": 1}
    assert unique["a_body_elsewhere_in_b"] == {"count": 0, "addrs": []}


def test_a_proposed_reading_states_its_facts(tmp_path: Path, current: None) -> None:
    """T6 / T15c and the shape. Unverified callees stop at identical_callee_unverified; byte counts
    that differ stop a unique text match at identical_text_unverified with hidden_region; a text
    that differs carries its delta; a missing body has no occurrence counts.

    MUTATION: read undetermined callees as equal -> identical_unique -> RED; let the R fold ignore
    body_size_differs -> identical_unique -> RED."""
    v = _view(_undetermined_world(tmp_path))
    unverified = _proposed(v, "identical_callee_unverified")
    assert unverified["state"] == "identical_callee_unverified"
    assert unverified["callee_set"]["state"] == "undetermined"
    sized = _proposed(v, "identical_text_unverified")
    assert sized["state"] == "identical_text_unverified"
    assert sized["text_unverified_reasons"] == ["body_size_differs"]
    assert sized["hidden_region"]["body"] == "structure_differs"
    assert sized["hidden_region"]["size_bytes"] == {"a": 16, "b": 20}
    differs = _proposed(v, "differs")
    assert differs["pseudocode_delta"]["kind"] == "substitution_only"
    assert differs["pseudocode_delta"]["substitutions"]["number"]["first"] == [["5", "6"]]
    for state in ("no_body", "unavailable"):
        gone = _proposed(v, state)
        assert gone["occurrences"] is None and gone["a_body_elsewhere_in_b"] is None, state
        assert "pseudocode_delta" not in gone and "hidden_region" not in gone


def test_a_changed_callee_set_wins_over_an_equal_text(tmp_path: Path, current: None) -> None:
    """T5. The same text over callee sets that differ is differs — a callee change outranks every
    text reading.

    MUTATION: read the text before the callee set in the R fold -> identical_unique -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.5, 0.8)
    w.fn("a", "00001000", ["foo"], pseudocode="foo(1);")
    w.fn("b", "00002000", ["foo", "bar"], pseudocode="foo(1);")
    w.commit()
    e = _entry(w, _pair_id("00001000", "00002000"))
    assert e["proposed_pair_reading"]["state"] == "differs"
    assert e["proposed_pair_reading"]["callee_set"]["only_in_b"] == ["bar"]
    assert "pseudocode_delta" not in e["proposed_pair_reading"]  # the texts themselves agree


def test_an_r_entry_over_an_aligned_pair_is_never_sunk_on_an_identical_body(
    tmp_path: Path, current: None
) -> None:
    """T8. Reachable: an ALIGNED pair whose candidate row lands in R (its export did not hold the
    function as it is), with an identical body — the R guard holds it at attention 1.

    MUTATION: delete the R guard in ``significance`` -> attention 2 -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 0.9, gap_a="degenerate_block")
    w.inst("a", _ref("runA", "00001000", "cmd", "0x10"), "cmd", "system")
    w.fn("a", "00001000", ["system"], pseudocode="system(c);")
    w.fn("b", "00002000", ["system"], pseudocode="system(c);")
    w.commit()
    e = _entry(w, _pair_id("00001000", "00002000"), sort_by="significance")
    assert (e["bucket"], e["subclass"]) == ("R", "degenerate_block_source")
    assert e["pseudocode_sameness"] == "identical"
    assert e["significance"] == {"attention": 1, "basis": "undetermined_never_sunk"}


def test_a_settled_r_entry_closes_attention_one_ahead_of_every_sunk_entry(
    tmp_path: Path, current: None
) -> None:
    """T9. Under the significance lens an R entry read identical_unique comes after the other
    attention-1 entries (whatever its similarity) and before every attention-2 entry.

    MUTATION: drop ``settled`` from the key -> the R entry (lower similarity) comes first -> RED;
    put ``settled`` before ``attention`` -> it falls behind the sunk C entry -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 0.9)  # B, attention 1: an unmatched call, a body change
    w.inst("a", _ref("runA", "00001000", "cmd", "0x30"), "cmd", "system")
    w.fn("a", "00001000", ["system"], pseudocode="system(a);")
    w.fn("b", "00002000", ["system"], pseudocode="system(b);")
    w.pair("00003000", "00004000", 0.97, 0.8)  # C, attention 2
    w.fn("a", "00003000", ["foo"], pseudocode="foo(1);")
    w.fn("b", "00004000", ["foo"], pseudocode="foo(2);")
    w.pair("00005000", "00006000", 0.5, 0.1)  # R, identical_unique
    w.fn("a", "00005000", ["foo"], pseudocode="foo(3);")
    w.fn("b", "00006000", ["foo"], pseudocode="foo(3);")
    w.commit()
    v = _view(w, sort_by="significance")
    order = [e["entry_id"] for e in v["entries"]]
    b, c, r = (
        _pair_id("00001000", "00002000"),
        _pair_id("00003000", "00004000"),
        _pair_id("00005000", "00006000"),
    )
    assert order == [b, r, c]
    assert v["by_id"][r]["proposed_pair_reading"]["state"] == "identical_unique"
    assert v["by_id"][r]["significance"] == {"attention": 1, "basis": "undetermined_never_sunk"}
    assert v["by_id"][c]["significance"]["attention"] == 2


def test_the_judgement_facts_of_an_r_entry_do_not_carry_its_reading(
    tmp_path: Path, current: None
) -> None:
    """T10. What a judgement rests on (diff_review.entry_facts) is unchanged by the proposed
    reading: a judgement is never invalidated by a reading the view merely shows.

    MUTATION: add the proposed callee set to entry_facts -> RED."""
    from treasure_map.lib.query import diff_review

    built = pv.build_diff_view(_undetermined_world(tmp_path).atlas, DIFF)
    assert built is not None
    (e,) = [x for x in built.entries if x.entry_id == _pair_id(*U_PAIRS["identical_unique"])]
    assert diff_review.entry_facts(e) == {
        "alignment_state": "alignment_undetermined",
        "similarity": 0.8,
        "export_gap_a": None,
        "export_gap_b": None,
        "bucket": "R",
        "rows": [],
    }


def test_an_r_pairs_callee_comparison_adds_no_fact(tmp_path: Path, current: None) -> None:
    """T11. An aligned pair's callee comparison adds callee_set_unchanged / one_hop_sink as it
    always did; an undetermined pair's (for its proposed reading) adds neither.

    MUTATION: compute the R comparison with the side-effecting ``_callee_set`` -> the R entries
    gain the facts -> RED."""
    w = World(tmp_path)
    w.unpaired("b", "00005000", "unmatched_analysis_complete")
    w.fn("b", "00005000", ["system"], name="run_cmd")
    w.inst("b", _ref("runB", "00005000", "cmd", "0x8"), "cmd", "system", wraps="system")
    for fa, fb, conf in (
        ("00001000", "00002000", 0.97),
        ("00003000", "00004000", 0.97),
        ("00006000", "00007000", 0.5),
        ("00008000", "00009000", 0.5),
    ):
        w.pair(fa, fb, conf, 0.9)
    w.fn("a", "00001000", ["foo"])
    w.fn("b", "00002000", ["foo"])
    w.fn("a", "00003000", [])
    w.fn("b", "00004000", ["run_cmd"])
    w.fn("a", "00006000", ["foo"])
    w.fn("b", "00007000", ["foo"])
    w.fn("a", "00008000", [])
    w.fn("b", "00009000", ["run_cmd"])
    w.commit()
    v = _view(w)["by_id"]
    assert "callee_set_unchanged" in v[_pair_id("00001000", "00002000")]["facts"]
    assert "one_hop_sink:system" in v[_pair_id("00003000", "00004000")]["facts"]
    same_r, hop_r = v[_pair_id("00006000", "00007000")], v[_pair_id("00008000", "00009000")]
    assert same_r["proposed_pair_reading"]["callee_set"] == {"state": "equal"}
    assert hop_r["proposed_pair_reading"]["callee_set"]["only_in_b"] == ["run_cmd"]
    assert same_r["facts"] == [] and hop_r["facts"] == []


def _qualified_world(tmp_path: Path) -> World:
    """Aligned pairs whose texts match but are qualified: listed (bucket C) and not listed
    (similarity 1), by byte counts that differ and by a decompiler marker alone, plus a plain
    difference and a plain identical."""
    w = World(tmp_path)
    marker = "/* WARNING: Removing unreachable block (ram,0x00003010) */\n"
    rows = (
        ("00001000", "00002000", 0.9, "c1();", 1064, 1060),  # C, structure_differs
        ("00003000", "00004000", 0.9, marker + "c3();", 64, 64),  # C, marker only: unknown
        ("00005000", "00006000", 0.9, None, 32, 32),  # C, differs
        ("00007000", "00008000", 1.0, "n1();", 128, 120),  # not listed, structure_differs
        ("00009000", "0000a000", 1.0, marker + "n2();", 64, 64),  # not listed, unknown
        ("0000b000", "0000c000", 1.0, "same();", 32, 32),  # not listed, identical
    )
    for fa, fb, sim, text, size_a, size_b in rows:
        w.pair(fa, fb, 0.97, sim, instructions=264)
        w.fn("a", fa, ["foo"], pseudocode=text or "x = 1;", size_bytes=size_a)
        w.fn("b", fb, ["foo"], pseudocode=text or "x = 2;", size_bytes=size_b)
    w.commit()
    return w


def test_a_qualified_match_carries_its_reasons_and_hidden_region(
    tmp_path: Path, current: None
) -> None:
    """T15 / T27, wired end to end: byte counts that differ under equal texts read
    identical_text_unverified with hidden_region.body structure_differs, the BinDiff instruction
    count as its stored scalar; a marker alone reads unknown.

    MUTATION: report bindiff_matched_instructions per side ({a, b}) -> RED; attach no
    hidden_region on a size-only qualification -> RED."""
    v = _view(_qualified_world(tmp_path))["by_id"]
    sized = v[_pair_id("00001000", "00002000")]
    assert sized["pseudocode_sameness"] == "identical_text_unverified"
    assert sized["text_unverified_reasons"] == ["body_size_differs"]
    assert "hidden_region" in sized
    region = sized["hidden_region"]
    assert region["body"] == "structure_differs" and region["markers"] == []
    assert region["size_bytes"] == {"a": 1064, "b": 1060}
    assert region["bindiff_matched_instructions"] == 264 and region["similarity"] == 0.9
    marked = v[_pair_id("00003000", "00004000")]
    assert marked["text_unverified_reasons"] == ["decompile_incomplete:unreachable_block_removed"]
    assert marked["hidden_region"]["body"] == "unknown"
    assert [m["side"] for m in marked["hidden_region"]["markers"]] == ["a", "b"]
    assert v[_pair_id("00005000", "00006000")]["pseudocode_sameness"] == "differs"
    assert "hidden_region" not in v[_pair_id("00005000", "00006000")]


def test_a_zero_byte_count_is_not_recorded_and_qualifies_nothing(
    tmp_path: Path, current: None
) -> None:
    """A byte count of 0 is the ingest's default for an export that carried none: it is read as not
    recorded, so beside a known count it adds no body_size_differs and no hidden_region.

    MUTATION: read 0 as a byte count in read_function_bodies -> 0 vs 64 differ -> the pair reads
    identical_text_unverified -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 0.9)
    w.fn("a", "00001000", ["foo"], pseudocode="foo(1);", size_bytes=0)
    w.fn("b", "00002000", ["foo"], pseudocode="foo(1);", size_bytes=64)
    w.commit()
    e = _view(w)["by_id"][_pair_id("00001000", "00002000")]
    assert e["pseudocode_sameness"] == "identical"
    assert "text_unverified_reasons" not in e
    assert "hidden_region" not in e


def test_a_qualified_match_is_unverified_never_unchanged(tmp_path: Path, current: None) -> None:
    """T18. identical_text_unverified counts in unverified (its total included), never in
    unchanged; its split by body class is a key of its own and every unverified value stays an
    int.

    MUTATION: put the body split inside ``unverified`` -> a dict among the ints -> RED."""
    s = pv.function_states(_qualified_world(tmp_path).atlas, DIFF)
    assert s is not None
    assert s["unchanged"] == 1
    assert s["unverified"] == {
        "total": 4,
        "identical_text_unverified": 4,
        "identical_callee_unverified": 0,
        "unavailable": 0,
    }
    assert all(isinstance(n, int) for n in s["unverified"].values())
    assert s["identical_text_unverified_by_body"] == {"structure_differs": 2, "unknown": 2}
    assert s["changed"]["total"] == 1


def test_the_body_filter_keeps_one_class_of_qualified_match(tmp_path: Path, current: None) -> None:
    """T19. ``body`` keeps only the identical_text_unverified entries of its class — listed, and
    the not-listed ones of that category with their body named; a bad value is an error, and so is
    ``body`` beside any other not_listed_page (never a silent empty page). The MCP tool passes it
    through.

    MUTATION: ignore ``body`` when choosing the listed entries -> every entry comes back -> RED;
    drop the not_listed_page check -> an empty page, no error -> RED."""
    w = _qualified_world(tmp_path)
    ids = [e["entry_id"] for e in _view(w, body="structure_differs")["entries"]]
    assert ids == [_pair_id("00001000", "00002000")]
    ids = [e["entry_id"] for e in _view(w, body="unknown")["entries"]]
    assert ids == [_pair_id("00003000", "00004000")]
    page = pv.get_diff_patch_view(
        w.atlas,
        DIFF,
        not_listed_page="aligned_pseudocode_identical_text_unverified",
        body="structure_differs",
    )
    assert [(r["entry_id"], r["body"]) for r in page["entries"]] == [
        (_pair_id("00007000", "00008000"), "structure_differs")
    ]
    bad = pv.get_diff_patch_view(w.atlas, DIFF, body="identical")
    assert bad["error"] == (
        "body must be one of ('structure_differs', 'unknown') or null, got 'identical'"
    )
    unrelated = pv.get_diff_patch_view(
        w.atlas, DIFF, not_listed_page="aligned_pseudocode_differs", body="structure_differs"
    )
    assert unrelated.get("error") == (
        "body applies to the listed entries and to "
        "not_listed_page='aligned_pseudocode_identical_text_unverified' only"
    )
    tool = mcp_app.make_tools(w.path)["get_diff_patch_view"]
    out = tool(DIFF, body="structure_differs")
    assert [e["entry_id"] for e in out["entries"]] == [_pair_id("00001000", "00002000")]


def test_the_lens_counts_the_sunk_entries_whose_byte_counts_differ(
    tmp_path: Path, current: None
) -> None:
    """T19b. A bucket C entry whose text match is qualified by differing byte counts is still
    sunk; the lens counts it and names the filter that lists it. A held-up one stops at attention
    1 and is not counted. Without the lens there is no count.

    MUTATION: lift a qualified C entry to attention 1 -> the count is 0 -> RED; count without the
    attention test -> the held-up entry is counted too -> RED."""
    w = _qualified_world(tmp_path)
    w.pair("0000d000", "0000e000", 0.97, 0.9)  # a second C structure_differs, judged changed_real
    w.fn("a", "0000d000", ["foo"], pseudocode="c5();", size_bytes=40)
    w.fn("b", "0000e000", ["foo"], pseudocode="c5();", size_bytes=44)
    w.commit()
    held = _pair_id("0000d000", "0000e000")
    w.judge(DIFF, _view(w)["by_id"][held]["anchor_ref"], "changed_real")
    v = _view(w, sort_by="significance")
    sunk = v["by_id"][_pair_id("00001000", "00002000")]
    assert sunk["bucket"] == "C" and sunk["significance"]["attention"] == 2
    assert v["by_id"][held]["significance"]["attention"] == 1
    assert v["lens"]["sunk_with_body_size_differs"] == {
        "count": 1,
        "filter": {"body": "structure_differs"},
    }
    assert "sunk_with_body_size_differs" not in _view(w)["lens"]


def test_the_build_reads_no_body_and_function_states_computes_no_delta(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T24. build_diff_view reads neither pseudocode nor image extents; function_states reads them
    but computes no delta; only the page read does.

    MUTATION: compute the page's deltas in function_states -> RED."""
    w = _qualified_world(tmp_path)
    calls: list[str] = []
    for name in ("read_function_bodies", "read_image_ranges", "pseudocode_delta"):
        real = getattr(pv.sameness, name)

        def probe(*a: Any, _real: Any = real, _name: str = name) -> Any:
            calls.append(_name)
            return _real(*a)

        monkeypatch.setattr(pv.sameness, name, probe)
    pv.build_diff_view(w.atlas, DIFF)
    assert calls == []
    pv.function_states(w.atlas, DIFF)
    assert "read_function_bodies" in calls and "read_image_ranges" in calls
    assert "pseudocode_delta" not in calls
    pv.get_diff_patch_view(w.atlas, DIFF)
    assert "pseudocode_delta" in calls


def test_a_re_extraction_is_never_served_an_earlier_reading(tmp_path: Path, current: None) -> None:
    """T25. Same diff, same content hashes, a new build hash on both runs: the proposed reading,
    the image extents and the delta are all read again.

    MUTATION: drop the build hashes from the reading cache key -> the earlier readings are served
    -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.5, 0.8)  # R: identical_unique, then differs
    w.fn("a", "00001000", ["foo"], pseudocode="foo(1);")
    w.fn("b", "00002000", ["foo"], pseudocode="foo(1);")
    w.pair("00003000", "00004000", 0.97, 0.9)  # aligned: a moved address inside the image
    w.fn("a", "00003000", ["foo"], pseudocode="p = (char *)0x412340;")
    w.fn("b", "00004000", ["foo"], pseudocode="p = (char *)0x412560;")
    w.pair("00005000", "00006000", 0.97, 0.9)  # aligned: a changed size, its delta
    w.fn("a", "00005000", ["foo"], pseudocode="char buf[0x60];")
    w.fn("b", "00006000", ["foo"], pseudocode="char buf[0x64];")
    for side in "ab":
        w.block(side, "0x400000", 0x100000)
    w.commit()
    r, moved, sized = (
        _pair_id("00001000", "00002000"),
        _pair_id("00003000", "00004000"),
        _pair_id("00005000", "00006000"),
    )
    v = _view(w)["by_id"]
    assert v[r]["proposed_pair_reading"]["state"] == "identical_unique"
    assert v[moved]["pseudocode_sameness"] == "identical"
    assert v[sized]["pseudocode_delta"]["substitutions"]["number"]["first"] == [["0x60", "0x64"]]
    w.adb["b"].execute("UPDATE functions SET pseudocode = 'foo(9);' WHERE address = '00002000'")
    w.adb["b"].execute(
        "UPDATE functions SET pseudocode = 'char buf[0x68];' WHERE address = '00006000'"
    )
    for side in "ab":
        w.adb[side].execute("DELETE FROM data_blocks")
        w.block(side, "0x10000", 0x1000)
    w.atlas.execute("UPDATE run SET build_hash = 'rebuilt'")
    w.commit()
    v = _view(w)["by_id"]
    assert v[r]["proposed_pair_reading"]["state"] == "differs"
    assert v[moved]["pseudocode_sameness"] == "differs"
    assert v[sized]["pseudocode_delta"]["substitutions"]["number"]["first"] == [["0x60", "0x68"]]
