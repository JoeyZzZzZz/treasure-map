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
from treasure_map.lib.query import diff_align as da
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query import sameness
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
        name_a: str | None = None,
        name_b: str | None = None,
        **gaps: str | None,
    ) -> None:
        state = "aligned" if conf >= 0.9 else "alignment_undetermined"
        self.atlas.execute(
            "INSERT INTO function_alignment (diff_id, addr_a, addr_b, name_a, name_b, "
            "alignment_confidence, similarity, alignment_state, export_gap_a, export_gap_b, "
            "instructions) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                DIFF,
                a,
                b,
                name_a,
                name_b,
                conf,
                sim,
                state,
                gaps.get("gap_a"),
                gaps.get("gap_b"),
                instructions,
            ),
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
    body = "/* WARNING: Could not recover jumptable at 0x00408218. Too many branches */\nfoo(0x40);"
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
    """★ iron law: pseudocode_sameness is a fact added to a listed entry, never a reason to drop
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
    w.fn("b", "00002000", ["system", "log_b"], pseudocode="x = FUN_00407fb8();")
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
    w.fn("b", "00014000", ["system"], pseudocode="system(FUN_00407fb8());")
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
    """Three entries B by an unmatched call, texts and callees the same: the control (equal
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
    assert e["callee_set"] == {"state": "equal", "callees_complete": True}
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
    # callees_complete: the empty only_in_b is a proven-empty difference, not a list not extracted.
    assert cs == {
        "state": "differs",
        "only_in_a": ["log_it"],
        "only_in_b": [],
        "callees_complete": True,
    }


def test_a_callee_that_is_a_thin_command_wrapper_is_marked(world: World) -> None:
    e = _entry(world, _pair_id("00033000", "00035000"))
    assert e["callee_set"]["only_in_b"] == ["run_cmd"]
    assert "one_hop_sink:system" in e["facts"]


def test_an_unchanged_callee_set_never_moves_an_entry_with_a_candidate(world: World) -> None:
    """The persisted pair's lists differ; the A pair's are equal-looking elsewhere: the bucket is
    the rows', whatever the callee set says."""
    e = _entry(world, _pair_id("00028000", "00029000"))
    assert e["callee_set"] == {"state": "equal", "callees_complete": True}
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


def test_a_filter_value_this_diff_does_not_carry_is_named(world: World) -> None:
    """An empty page reads the same whether the value was misspelled or simply absent; the view
    names a value no entry carries, with the ones that do occur. A value that does occur gets no
    note.

    MUTATION: drop the filter_note -> RED."""
    typo = _view(world, subclass="instruction_unmatchd")
    assert typo["entries"] == []
    note = typo["lens"].get("filter_note") or ""
    assert "instruction_unmatchd" in note and "instruction_unmatched" in note, typo["lens"]
    spot = _view(world, blind_spot="callee_identity_unresolve")
    assert "callee_identity_unresolved" in (spot["lens"].get("filter_note") or ""), spot["lens"]
    assert "filter_note" not in _view(world, subclass="instruction_unmatched")["lens"]


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
    """The proposed reading sits beside the R entry; its pseudocode_sameness key is never
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
    """Seven undetermined pairs, one per state: counted in
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
    """The same body twice on B: identical_not_unique, and B's other copy is named —
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
    """The proposed reading's states and shape. Unverified callees stop at
    identical_callee_unverified; byte counts that differ stop a unique text match at
    identical_text_unverified with hidden_region; a text that differs carries its delta; a
    missing body has no occurrence counts.

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
    """The same text over callee sets that differ is differs — a callee change outranks every
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
    """Reachable: an ALIGNED pair whose candidate row lands in R (its export did not hold the
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
    """Under the significance lens an R entry read identical_unique comes after the other
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
    """What a judgement rests on (diff_review.entry_facts) is unchanged by the proposed
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
    """An aligned pair's callee comparison adds callee_set_unchanged / one_hop_sink as it
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
    assert same_r["proposed_pair_reading"]["callee_set"] == {
        "state": "equal",
        "callees_complete": True,
    }
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
    """Wired end to end: byte counts that differ under equal texts read
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
    """identical_text_unverified counts in unverified (its total included), never in
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
    """``body`` keeps only the identical_text_unverified entries of its class — listed, and
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
    """A bucket C entry whose text match is qualified by differing byte counts is still
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
    """build_diff_view reads neither pseudocode nor image extents; function_states reads them
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
    """Same diff, same content hashes, a new build hash on both runs: the proposed reading,
    the image extents and the delta are all read again.

    MUTATION: drop the build hashes from the reading cache key -> the earlier readings are served
    -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.5, 0.8)  # R: identical_unique, then differs
    w.fn("a", "00001000", ["foo"], pseudocode="foo(1);")
    w.fn("b", "00002000", ["foo"], pseudocode="foo(1);")
    w.pair("00003000", "00004000", 0.97, 0.9)  # aligned: a moved address inside the image
    w.fn("a", "00003000", ["foo"], pseudocode="p = (char *)0x41e8c8;")
    w.fn("b", "00004000", ["foo"], pseudocode="p = (char *)0x41eae8;")
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


def test_the_view_caches_are_bounded_and_keyed_by_atlas(tmp_path: Path) -> None:
    """A long-lived server must not keep every diff and every re-hunted run it ever showed, and
    two atlases with the same ids must not share an entry.

    MUTATION: drop the eviction loop in _BoundedCache.__setitem__ -> RED (it grows past its bound).
    MUTATION: return "" from _atlas_identity -> RED (two atlases read as one)."""
    import sqlite3 as _sqlite3

    from treasure_map.lib.query import patch_view as pv

    cache: pv._BoundedCache[int, int] = pv._BoundedCache(3)
    for i in range(10):
        cache[i] = i
    assert len(cache) == 3
    assert cache.get(0) is None and cache.get(9) == 9
    cache.get(7)  # touched: survives the next insert, 8 (now the oldest) does not
    cache[10] = 10
    assert cache.get(7) == 7 and cache.get(8) is None

    a = _sqlite3.connect(tmp_path / "a.db")
    b = _sqlite3.connect(tmp_path / "b.db")
    try:
        assert pv._atlas_identity(a) != pv._atlas_identity(b)
        assert pv._atlas_identity(a).endswith("a.db")
    finally:
        a.close()
        b.close()


# ── anchored_differs: an undetermined pair confidently paired whose reading is differs ────────


def _ud(
    w: World,
    a: str,
    b: str,
    sim: float,
    *,
    differs: bool = True,
    name_a: str | None = None,
    name_b: str | None = None,
    **gaps: str | None,
) -> str:
    """One undetermined pair (confidence 0.5) with one callee, ``foo``, on each side: its two
    bodies differ by a trailing term, or are the same text (``differs=False``). Every pair's bodies
    are its own. Returns the entry id."""
    w.pair(a, b, 0.5, sim, name_a=name_a, name_b=name_b, **gaps)
    n = int(a, 16) // 0x100
    w.fn("a", a, ["foo"], pseudocode=f"x = foo({n});", size_bytes=16)
    w.fn("b", b, ["foo"], pseudocode=f"x = foo({n})" + (" + 7;" if differs else ";"), size_bytes=16)
    return _pair_id(a, b)


def _reading(v: dict[str, Any], entry_id: str) -> dict[str, Any]:
    assert entry_id in v["by_id"], entry_id
    reading = v["by_id"][entry_id]["proposed_pair_reading"]
    assert isinstance(reading, dict)
    return reading


def test_an_anchored_differing_undetermined_pair_is_flagged(tmp_path: Path, current: None) -> None:
    """Baseline (the teeth are in the counter-examples below): no export gap, one address on both
    sides, a proposed reading of differs -> flagged, anchored by address, read first at similarity
    0.87, labelled anchored_differs under the lens, and counted."""
    w = World(tmp_path)
    eid = _ud(w, "00020000", "00020000", 0.87)
    w.commit()
    v = _view(w, sort_by="significance")
    r = _reading(v, eid)
    assert r["state"] == "differs"
    assert (r["anchored_differs"], r["anchor"], r["in_read_first"]) == (True, "addr", True)
    assert v["by_id"][eid]["significance"] == {"attention": 1, "basis": "anchored_differs"}
    s = pv.function_states(w.atlas, DIFF)
    assert s is not None
    assert s["alignment_undetermined_anchored_differs"] == 1
    assert s["alignment_undetermined_anchored_differs_all"] == 1


def test_a_pair_with_an_export_gap_is_never_flagged(tmp_path: Path, current: None) -> None:
    """A pair whose export dropped part of a side reads differs, but that difference is not one to
    trust: an export gap on either side keeps the pair unflagged and uncounted.

    MUTATION: drop the export-gap test in ``_anchored_differs`` -> both flagged -> RED."""
    w = World(tmp_path)
    ga = _ud(w, "00020000", "00020000", 0.87, gap_a="degenerate_block")
    gb = _ud(w, "00021000", "00021000", 0.87, gap_b="degenerate_block")
    w.commit()
    v = _view(w)
    for eid in (ga, gb):
        r = _reading(v, eid)
        assert r["state"] == "differs"  # it does read differs: only the gap keeps it out
        assert "anchored_differs" not in r
    s = pv.function_states(w.atlas, DIFF)
    assert s is not None and s["alignment_undetermined_anchored_differs_all"] == 0


def test_an_anchored_pair_that_does_not_read_differs_is_not_flagged(
    tmp_path: Path, current: None
) -> None:
    """Anchored at one address, similarity 0.87, but the proposed reading is a text match —
    identical_callee_unverified (a callee list is a prefix), identical_text_unverified (byte counts
    differ), identical_unique — so nothing is flagged.

    MUTATION: drop ``u_state == differs`` from ``_anchored_differs`` -> all three flagged -> RED."""
    w = World(tmp_path)
    w.pair("00020000", "00020000", 0.5, 0.87)
    w.fn("a", "00020000", ["foo"], pseudocode="x = foo(1);", truncated=1)
    w.fn("b", "00020000", ["foo"], pseudocode="x = foo(1);")
    w.pair("00021000", "00021000", 0.5, 0.87)
    w.fn("a", "00021000", ["foo"], pseudocode="x = foo(2);", size_bytes=16)
    w.fn("b", "00021000", ["foo"], pseudocode="x = foo(2);", size_bytes=20)
    unique = _ud(w, "00022000", "00022000", 0.87, differs=False)
    w.commit()
    v = _view(w)
    expected = {
        _pair_id("00020000", "00020000"): "identical_callee_unverified",
        _pair_id("00021000", "00021000"): "identical_text_unverified",
        unique: "identical_unique",
    }
    for eid, state in expected.items():
        r = _reading(v, eid)
        assert r["state"] == state
        assert "anchored_differs" not in r, state


def test_similarity_one_is_flagged_and_read_first_when_the_reading_differs(
    tmp_path: Path, current: None
) -> None:
    """BinDiff's similarity 1 does not see a buffer size or a constant: a similarity-1 pair whose
    normalized text differs is flagged and read first; one whose text matches is not flagged.

    MUTATION: require similarity < 1 in ``_anchored_differs`` -> the differing pair loses its
    flag -> RED."""
    w = World(tmp_path)
    w.pair("00020000", "00020000", 0.5, 1.0)
    w.fn("a", "00020000", ["memset"], pseudocode="char b[96]; memset(b, 0, 0x60);", size_bytes=16)
    w.fn("b", "00020000", ["memset"], pseudocode="char b[100]; memset(b, 0, 100);", size_bytes=16)
    same = _ud(w, "00021000", "00021000", 1.0, differs=False)
    w.commit()
    v = _view(w)
    sized = _reading(v, _pair_id("00020000", "00020000"))
    assert sized["state"] == "differs"
    assert (sized.get("anchored_differs"), sized.get("in_read_first")) == (True, True)
    assert "anchored_differs" not in _reading(v, same)
    s = pv.function_states(w.atlas, DIFF)
    assert s is not None and s["alignment_undetermined_anchored_differs"] == 1


def test_the_floor_bounds_the_read_first_count_and_nothing_else(
    tmp_path: Path, current: None
) -> None:
    """At similarity 0.70 a flagged pair is read first; at 0.69 it is still flagged, still
    counted among every flagged pair, and still listed by the filter — only not read first.

    MUTATION: raise the floor to 0.75 -> the 0.70 pair is not read first -> RED; use the floor as
    a condition of the flag -> the 0.69 pair loses its flag -> RED."""
    w = World(tmp_path)
    at = _ud(w, "00020000", "00020000", 0.70)
    below = _ud(w, "00021000", "00021000", 0.69)
    w.commit()
    v = _view(w)
    assert (_reading(v, at)["anchored_differs"], _reading(v, at)["in_read_first"]) == (True, True)
    low = _reading(v, below)
    assert (low.get("anchored_differs"), low.get("in_read_first")) == (True, False)
    s = pv.function_states(w.atlas, DIFF)
    assert s is not None
    assert s["alignment_undetermined_anchored_differs"] == 1
    assert s["alignment_undetermined_anchored_differs_all"] == 2
    listed = _view(w, bucket="R", anchored_differs=True)
    assert set(listed["by_id"]) == {at, below}


# ── B: micro-side surfacing, line-number demotion, unavailable_by_cause ───────────────────────


def _micro_pair(w: World, a: str, b: str, sim: float, *, callee_b: str = "foo") -> str:
    """One undetermined pair anchored at one address: side a a real body, side b a design-skipped
    micro-stub (empty, 8 bytes). ``callee_b`` controls whether the callee set also differs."""
    w.pair(a, b, 0.5, sim)
    w.fn("a", a, ["foo"], pseudocode="x = foo(1);", size_bytes=200)
    w.fn("b", b, [callee_b], pseudocode=None, size_bytes=8)
    return _pair_id(a, b)


def test_an_anchored_micro_side_pair_floats_to_read_first_and_filters(
    tmp_path: Path, current: None
) -> None:
    """One side a design-skipped micro-stub and the other a real body, anchored, no export gap:
    basis anchored_micro_side, floated to read_first inside attention 1 AHEAD of a plain R pair of
    LOWER similarity, counted, and listed by the anchored_micro_side filter.

    MUTATION: give anchored_micro_side its significance basis but not read_first order 1 -> the
    higher-similarity micro pair no longer sorts ahead of the 0.3 plain pair -> RED."""
    w = World(tmp_path)
    micro = _micro_pair(w, "00030000", "00030000", 0.8)  # same callee -> not differs, micro only
    plain = _ud(w, "00031000", "00032000", 0.3)  # reads differs, unanchored (two addresses)
    w.commit()
    v = _view(w, sort_by="significance")
    assert v["by_id"][micro]["significance"] == {"attention": 1, "basis": "anchored_micro_side"}
    r = _reading(v, micro)
    assert r["state"] == "unavailable" and "anchored_differs" not in r  # micro only, not differs
    order = [e["entry_id"] for e in v["entries"]]
    assert order.index(micro) < order.index(plain)  # read_first floats it past the lower-sim plain
    s = pv.function_states(w.atlas, DIFF)
    assert s is not None and s["alignment_undetermined_anchored_micro_side"] == 1
    # a micro pair is NOT anchored_differs: it must not inflate the anchored_differs count (the
    # ``_all`` decoupling) nor carry anchored_differs in its reading (_proposed_json decoupling).
    assert s["alignment_undetermined_anchored_differs_all"] == 0
    assert set(_view(w, bucket="R", anchored_micro_side=True)["by_id"]) == {micro}


def test_a_micro_side_needs_exactly_one_stub_against_a_real_body(
    tmp_path: Path, current: None
) -> None:
    """Two real bodies, or two micro-stubs, are not anchored_micro_side: only one stub against one
    real body is.

    MUTATION: read 'both empty' as the condition instead of exactly one skipped_micro -> the
    both-micro pair is flagged -> RED."""
    w = World(tmp_path)
    _ud(w, "00030000", "00030000", 0.8)  # two real bodies (anchored_differs, not micro)
    w.pair("00031000", "00031000", 0.5, 0.8)  # two micro-stubs
    w.fn("a", "00031000", ["foo"], pseudocode=None, size_bytes=8)
    w.fn("b", "00031000", ["foo"], pseudocode=None, size_bytes=8)
    w.commit()
    s = pv.function_states(w.atlas, DIFF)
    assert s is not None and s["alignment_undetermined_anchored_micro_side"] == 0
    assert _view(w, bucket="R", anchored_micro_side=True)["by_id"] == {}


def test_a_pair_that_is_both_micro_side_and_differs_reads_as_micro(
    tmp_path: Path, current: None
) -> None:
    """A micro-side pair whose callee sets ALSO differ is flagged both ways; the significance basis
    is anchored_micro_side (the micro branch is tried first), and it is counted under both.

    MUTATION: put the anchored_differs branch before anchored_micro_side in significance -> basis
    anchored_differs -> RED."""
    w = World(tmp_path)
    eid = _micro_pair(w, "00030000", "00030000", 0.8, callee_b="bar")  # micro AND callee differs
    w.commit()
    v = _view(w, sort_by="significance")
    assert v["by_id"][eid]["significance"]["basis"] == "anchored_micro_side"
    assert _reading(v, eid)["state"] == "differs"  # callees differ -> also anchored_differs
    s = pv.function_states(w.atlas, DIFF)
    assert s is not None
    assert s["alignment_undetermined_anchored_micro_side"] == 1
    assert s["alignment_undetermined_anchored_differs_all"] == 1  # counted under both lenses


def test_an_aligned_micro_pair_carries_the_fact_and_is_held_at_attention_one(
    tmp_path: Path, current: None
) -> None:
    """An aligned pair with one side a micro-stub carries the one_side_skipped_micro fact, and the
    significance lens holds a fact-carrying entry at attention 1 instead of sinking it to 2 as a
    bucket-C / identical pair would be.

    MUTATION: drop the one_side_skipped_micro branch in significance -> a bucket-C entry carrying
    the fact sinks to attention 2 -> RED."""
    w = World(tmp_path)
    w.pair("00050000", "00051000", 0.97, 1.0)  # aligned
    w.fn("a", "00050000", ["foo"], pseudocode="y = f();", size_bytes=200)  # ok
    w.fn("b", "00051000", ["foo"], pseudocode=None, size_bytes=8)  # micro
    w.commit()
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    readings = pv._pseudo_readings(w.atlas, built)
    pv._annotate_entries(built, readings)
    e = next(x for x in built.placed if x.pair is not None and x.pair.addr_a == "00050000")
    assert "one_side_skipped_micro" in e.facts  # the aligned micro fact was attached
    held = pv._Entry(pair=None, unpaired=None, bucket="C", facts=["one_side_skipped_micro"])
    assert pv.significance(held, None, None, None) == (
        pv.ATTENTION_MIDDLE,
        "one_side_skipped_micro",
    )
    sunk = pv._Entry(pair=None, unpaired=None, bucket="C")
    assert pv.significance(sunk, None, None, None) == (pv.ATTENTION_SINK, "no_sink_candidate")


def test_cause_of_splits_the_unavailable_pairs_strongest_gap_first(
    tmp_path: Path, current: None
) -> None:
    """The five-bucket cause of a UNAVAILABLE pair, strongest gap first: a db read failure wins over
    everything, a real empty decompile over a design skip, and one stub against a real body is
    one_side_skipped_micro.

    MUTATION: drop the DECOMPILE_EMPTY check -> a micro + decompile_empty pair falls through to
    one_side_skipped_micro -> RED; test SIZE_UNKNOWN before DECOMPILE_EMPTY -> the empty +
    unrecorded pair reads size_unknown -> RED."""
    sm = sameness

    def mk(sa: str, sb: str) -> dict[str, Any]:
        return {"a": {"status": sa, "size_bytes": 0}, "b": {"status": sb, "size_bytes": 0}}

    assert pv._cause_of(mk(sm.DB_UNAVAILABLE, sm.DECOMPILE_EMPTY)) == "db_unavailable"
    assert pv._cause_of(mk(sm.DECOMPILE_EMPTY, sm.SKIPPED_MICRO)) == "decompile_empty"
    # a real empty decompile outranks an unrecorded size, whichever side carries which
    assert pv._cause_of(mk(sm.DECOMPILE_EMPTY, sm.SIZE_UNKNOWN)) == "decompile_empty"
    assert pv._cause_of(mk(sm.SIZE_UNKNOWN, sm.DECOMPILE_EMPTY)) == "decompile_empty"
    assert pv._cause_of(mk(sm.SIZE_UNKNOWN, sm.SKIPPED_MICRO)) == "size_unknown"
    assert pv._cause_of(mk(sm.SKIPPED_MICRO, "ok")) == "one_side_skipped_micro"
    assert pv._cause_of(mk(sm.SKIPPED_MICRO, sm.SKIPPED_MICRO)) == "both_skipped_micro"
    assert pv._cause_of(None) == "db_unavailable"


def test_unavailable_by_cause_sums_to_its_count(tmp_path: Path, current: None) -> None:
    """get_diff_meta's aligned unavailable_by_cause splits the aligned unavailable count by cause,
    its values summing to it; a design-skipped micro-stub is told apart from a real decompile gap.

    MUTATION: fold decompile_empty into skipped_micro in _body_status -> the 64-byte empty pair
    lands in one_side_skipped_micro -> RED."""
    w = World(tmp_path)
    w.pair("00060000", "00060000", 0.97, 1.0)  # one side micro, one ok
    w.fn("a", "00060000", ["foo"], pseudocode="y = 1;", size_bytes=200)
    w.fn("b", "00060000", ["foo"], pseudocode=None, size_bytes=8)
    w.pair("00061000", "00061000", 0.97, 1.0)  # both micro
    w.fn("a", "00061000", ["foo"], pseudocode=None, size_bytes=8)
    w.fn("b", "00061000", ["foo"], pseudocode=None, size_bytes=8)
    w.pair("00062000", "00062000", 0.97, 1.0)  # real empty decompile (>= 10 bytes)
    w.fn("a", "00062000", ["foo"], pseudocode=None, size_bytes=64)
    w.fn("b", "00062000", ["foo"], pseudocode="y = 1;", size_bytes=200)
    w.pair("00063000", "00063000", 0.97, 1.0)  # size unrecorded
    w.fn("a", "00063000", ["foo"], pseudocode=None, size_bytes=0)
    w.fn("b", "00063000", ["foo"], pseudocode="y = 1;", size_bytes=200)
    w.commit()
    s = pv.function_states(w.atlas, DIFF)
    assert s is not None
    assert s["unavailable_by_cause"] == {
        "db_unavailable": 0,
        "decompile_empty": 1,
        "size_unknown": 1,
        "one_side_skipped_micro": 1,
        "both_skipped_micro": 1,
    }
    assert sum(s["unavailable_by_cause"].values()) == s["unverified"]["unavailable"] == 4


def test_a_line_number_shift_is_demoted_out_of_the_read_first_head(
    tmp_path: Path, current: None
) -> None:
    """An anchored_differs pair at/above the floor whose only change is a __FILE__/__LINE__ shift is
    demoted out of the read-first head: still flagged (listed by anchored_differs=true), but
    in_read_first false and carrying line_number_form. A pair with a real change stays in the head;
    the count moves from the head (N) to line_number_form (L) while _all is unchanged.

    MUTATION: lower the count only, not the read_first order -> the shift pair stays in_read_first
    true and leads the head -> RED."""
    w = World(tmp_path)
    w.pair("00040000", "00040000", 0.5, 0.9)  # anchored, undetermined, above the floor
    w.fn("a", "00040000", ["log"], pseudocode='log("x.c", 10);', size_bytes=200)
    w.fn("b", "00040000", ["log"], pseudocode='log("x.c", 17);', size_bytes=200)
    real = _ud(w, "00041000", "00041000", 0.9)  # a real change (an inserted term), stays in head
    w.commit()
    shift = _pair_id("00040000", "00040000")
    v = _view(w)
    sr = _reading(v, shift)
    assert sr["anchored_differs"] is True and sr["in_read_first"] is False
    assert sr["line_number_form"] == {"delta": 7, "sites": 1}
    hr = _reading(v, real)
    assert hr["in_read_first"] is True and "line_number_form" not in hr
    s = pv.function_states(w.atlas, DIFF)
    assert s is not None
    assert s["alignment_undetermined_anchored_differs"] == 1  # N: only the real one in the head
    assert s["alignment_undetermined_anchored_differs_line_number_form"] == 1  # L
    assert s["alignment_undetermined_anchored_differs_all"] == 2  # _all unchanged
    assert set(_view(w, bucket="R", anchored_differs=True)["by_id"]) == {shift, real}
    banner = pv.anchored_differs_banner(s)
    assert banner is not None
    assert "1 more anchored pairs were demoted" in banner and "__FILE__/__LINE__" in banner


def test_no_body_is_never_flagged_but_unavailable_with_differing_callees_is(
    tmp_path: Path, current: None
) -> None:
    """A no_body side (an import / PLT stub, absent from the table) never carries anchored_differs;
    an unavailable side (present, empty body) whose callee set is PROVEN different does — a changed
    call set is proof of change even with no body to read.

    MUTATION: extend the differs exclusion from no_body to unavailable pairs -> the second pair
    loses its flag -> RED."""
    w = World(tmp_path)
    w.pair("00070000", "00070000", 0.5, 0.9)  # side b absent from the table -> no_body
    w.fn("a", "00070000", ["foo"], pseudocode="x = foo(1);", size_bytes=200)
    w.pair("00071000", "00071000", 0.5, 0.9)  # side b present, empty body, different callee
    w.fn("a", "00071000", ["foo"], pseudocode="x = foo(1);", size_bytes=200)
    w.fn("b", "00071000", ["bar"], pseudocode=None, size_bytes=64)
    w.commit()
    v = _view(w)
    nb = _reading(v, _pair_id("00070000", "00070000"))
    assert nb["state"] == "no_body" and "anchored_differs" not in nb
    ua = _reading(v, _pair_id("00071000", "00071000"))
    assert ua["state"] == "differs" and ua["anchored_differs"] is True


def test_the_line_number_name_match_ignores_a_synthetic_name(tmp_path: Path, current: None) -> None:
    """When the line-number argument follows the function's OWN name (not a path), the match holds
    only for a REAL symbol name; a synthetic FUN_<addr> name carries no such meaning, so the caller
    passes it as None and the pair stays in the read-first head.

    MUTATION: pass the synthetic name through to pseudocode_delta -> the FUN_ pair is demoted ->
    RED."""
    w = World(tmp_path)
    w.pair("00080000", "00080000", 0.5, 0.9, name_a="realfn", name_b="realfn")
    w.fn("a", "00080000", ["log"], pseudocode='log("realfn", 10);', size_bytes=200, name="realfn")
    w.fn("b", "00080000", ["log"], pseudocode='log("realfn", 17);', size_bytes=200, name="realfn")
    w.pair("00081000", "00081000", 0.5, 0.9, name_a="FUN_00081000", name_b="FUN_00081000")
    w.fn(
        "a",
        "00081000",
        ["log"],
        pseudocode='log("FUN_00081000", 10);',
        size_bytes=200,
        name="FUN_00081000",
    )
    w.fn(
        "b",
        "00081000",
        ["log"],
        pseudocode='log("FUN_00081000", 17);',
        size_bytes=200,
        name="FUN_00081000",
    )
    w.commit()
    v = _view(w)
    real = _reading(v, _pair_id("00080000", "00080000"))
    assert real.get("line_number_form") == {"delta": 7, "sites": 1}  # real name matched -> demoted
    syn = _reading(v, _pair_id("00081000", "00081000"))
    assert "line_number_form" not in syn and syn["in_read_first"] is True  # synthetic -> head


def test_each_side_s_made_up_name_is_dropped_before_the_name_match(
    tmp_path: Path, current: None
) -> None:
    """The made-up-name filter runs on EACH side by its own address: a ``loc_<addr>`` name is made
    up only on the side whose entry it ends in, so a pair whose string equals that name on both
    sides is real on one side and made up on the other — never a name match. The same text with a
    real name on both sides is one (the control). The tails are 5 hex digits: an 8-digit one is
    blanked in the delta text itself, so the name test would never see it.

    MUTATION: pass side a's name through unfiltered -> the first pair is demoted -> RED; the same
    for side b -> the second pair is demoted -> RED."""
    w = World(tmp_path)
    for a, b, name in (
        ("00081000", "00082000", "loc_81000"),  # made up on side a only
        ("00083000", "00084000", "loc_84000"),  # made up on side b only
        ("00085000", "00086000", "realfn"),  # real on both sides (control)
    ):
        w.pair(a, b, 0.5, 0.9, name_a=name, name_b=name)
        w.fn("a", a, ["log"], pseudocode=f'log("{name}", 10);', size_bytes=200, name=name)
        w.fn("b", b, ["log"], pseudocode=f'log("{name}", 17);', size_bytes=200, name=name)
    w.commit()
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    readings = pv._pseudo_readings(w.atlas, built)
    pairs = [e.pair for e in built.placed if e.pair is not None]
    deltas = pv._deltas(readings, pairs)
    assert "line_number_form" not in deltas[("00081000", "00082000")]
    assert "line_number_form" not in deltas[("00083000", "00084000")]
    assert deltas[("00085000", "00086000")]["line_number_form"] == {"delta": 7, "sites": 1}


def test_a_micro_side_pair_needs_an_anchor(tmp_path: Path, current: None) -> None:
    """One stub against one real body is anchored_micro_side only when the pair is anchored (same
    address or same real symbol name); the same shape at two addresses with no name is not.

    MUTATION: drop the anchor condition from ``_anchored_micro_side`` -> the unanchored pair is
    flagged, counted and listed -> RED."""
    w = World(tmp_path)
    anchored = _micro_pair(w, "00030000", "00030000", 0.8)
    loose = _micro_pair(w, "00031000", "00032000", 0.8)  # two addresses, no names: no anchor
    w.commit()
    s = pv.function_states(w.atlas, DIFF)
    assert s is not None and s["alignment_undetermined_anchored_micro_side"] == 1
    assert set(_view(w, bucket="R", anchored_micro_side=True)["by_id"]) == {anchored}
    v = _view(w, sort_by="significance")
    assert v["by_id"][anchored]["significance"]["basis"] == "anchored_micro_side"
    assert v["by_id"][loose]["significance"]["basis"] != "anchored_micro_side"


def _listing_pass(w: World, side: str) -> None:
    """Mark side's binary as extracted with listing export (the ingest's per-binary row)."""
    w.adb[side].execute(
        "INSERT INTO detector_scan_status (binary_id, detector, scanned, found_count) "
        "VALUES (1, 'listing', 1, 0)"
    )


def _listing(w: World, side: str, addr: str, units: list[dict[str, Any]]) -> None:
    """Store one function's listing as the ingest does: zlib(JSON [{a,n,k,m,o}, ...])."""
    import zlib

    row = w.adb[side].execute("SELECT id FROM functions WHERE address = ?", (addr,)).fetchone()
    w.adb[side].execute(
        "INSERT INTO function_listing (function_id, listing, unit_count, insn_count) "
        "VALUES (?, ?, ?, ?)",
        (row[0], zlib.compress(json.dumps(units).encode()), len(units), len(units)),
    )


_STUB_UNITS = [
    {"a": "00030000", "n": 4, "k": "code", "m": "jr", "o": "ra"},
    {"a": "00030004", "n": 4, "k": "code", "m": "_clear", "o": "v0"},
]


def test_a_micro_side_pair_shows_which_side_is_the_stub_its_size_and_its_listing(
    tmp_path: Path, current: None
) -> None:
    """An undetermined micro-side pair's proposed reading carries ``bodies``: each side's status and
    size, and on the stub side its stored disassembly inline (address, length, kind, mnemonic,
    operands — get_disassembly's items without the bytes). The real side carries no listing.

    MUTATION: leave ``bodies`` out of the proposed reading -> RED; read no listing for the stub side
    -> RED."""
    w = World(tmp_path)
    eid = _micro_pair(w, "00030000", "00030000", 0.8)
    _listing_pass(w, "b")
    _listing(w, "b", "00030000", _STUB_UNITS)
    w.commit()
    bodies = _reading(_view(w), eid)["bodies"]
    assert bodies["a"] == {"status": "ok", "size_bytes": 200}
    assert (bodies["b"]["status"], bodies["b"]["size_bytes"]) == (sameness.SKIPPED_MICRO, 8)
    code = {"length": 4, "kind": "code"}
    assert bodies["b"]["listing"] == [
        {"address": "00030000", **code, "mnemonic": "jr", "operands": "ra"},
        {"address": "00030004", **code, "mnemonic": "_clear", "operands": "v0"},
    ]
    assert "listing_note" not in bodies["b"]


@pytest.mark.parametrize(
    ("exported", "note"),
    [(False, sameness.LISTING_NOT_EXPORTED), (True, sameness.LISTING_NOT_STORED)],
)
def test_a_stub_side_with_no_stored_listing_says_why(
    tmp_path: Path, current: None, exported: bool, note: str
) -> None:
    """A stub side with no stored listing carries ``listing: null`` and why: the binary was
    extracted before tmap stored disassembly (a re-scan stores it), or it was and holds none for
    this function.

    MUTATION: read the not-exported case off the listing table instead of the binary's listing-pass
    row -> both read the same note -> RED."""
    w = World(tmp_path)
    eid = _micro_pair(w, "00030000", "00030000", 0.8)
    if exported:
        _listing_pass(w, "b")
    w.commit()
    stub = _reading(_view(w), eid)["bodies"]["b"]
    assert (stub["listing"], stub["listing_note"]) == (None, note)


def test_an_aligned_micro_pair_shows_its_bodies_on_the_entry(tmp_path: Path, current: None) -> None:
    """An aligned pair with no text on a side carries ``bodies`` on the entry itself (beside
    pseudocode_sameness): the stub side's status, size and listing; a pair whose two texts were
    read carries none.

    MUTATION: leave ``bodies`` out of the aligned entry -> RED."""
    w = World(tmp_path)
    w.pair("00030000", "00031000", 0.97, 0.9)  # aligned, below similarity 1: listed
    w.fn("a", "00030000", ["foo"], pseudocode="y = f();", size_bytes=200)
    w.fn("b", "00031000", ["foo"], pseudocode=None, size_bytes=8)
    w.pair("00040000", "00041000", 0.97, 0.9)  # both texts read: no bodies block
    w.fn("a", "00040000", ["foo"], pseudocode="y = g();", size_bytes=200)
    w.fn("b", "00041000", ["foo"], pseudocode="y = g() + 1;", size_bytes=200)
    _listing_pass(w, "b")
    _listing(w, "b", "00031000", [{**u, "a": "0003100" + u["a"][-1]} for u in _STUB_UNITS])
    w.commit()
    v = _view(w)
    entry = v["by_id"][_pair_id("00030000", "00031000")]
    assert entry["pseudocode_sameness"] == sameness.UNAVAILABLE
    assert "one_side_skipped_micro" in entry["facts"]
    assert entry["bodies"]["b"]["size_bytes"] == 8
    assert [u["mnemonic"] for u in entry["bodies"]["b"]["listing"]] == ["jr", "_clear"]
    assert "bodies" not in v["by_id"][_pair_id("00040000", "00041000")]


def test_only_a_micro_stub_side_gets_its_listing_inline(tmp_path: Path, current: None) -> None:
    """A side with no text that is NOT a micro-stub — a body at or above the decompile size floor
    that decompiled empty — carries its status and size, but no listing: only a stub is small enough
    to be shown whole. A micro pair on the same page still gets its listing, so the read itself
    works here.

    MUTATION (verified RED): read the listing of every side with no text (``!= "ok"`` for
    ``== SKIPPED_MICRO``) -> the decompile_empty side carries its stored listing -> RED."""
    w = World(tmp_path)
    w.pair("00030000", "00031000", 0.97, 0.9)  # aligned; the b side is a micro-stub
    w.fn("a", "00030000", ["foo"], pseudocode="y = f();", size_bytes=200)
    w.fn("b", "00031000", ["foo"], pseudocode=None, size_bytes=8)
    w.pair("00050000", "00051000", 0.97, 0.9)  # aligned; the b side is a big empty decompile
    w.fn("a", "00050000", ["foo"], pseudocode="y = h();", size_bytes=200)
    w.fn("b", "00051000", ["foo"], pseudocode=None, size_bytes=200)
    _listing_pass(w, "b")
    _listing(w, "b", "00031000", [{**u, "a": "0003100" + u["a"][-1]} for u in _STUB_UNITS])
    _listing(w, "b", "00051000", [{**u, "a": "0005100" + u["a"][-1]} for u in _STUB_UNITS])
    w.commit()
    v = _view(w)
    micro, empty = _pair_id("00030000", "00031000"), _pair_id("00050000", "00051000")
    assert micro in v["by_id"] and empty in v["by_id"]
    assert [u["mnemonic"] for u in v["by_id"][micro]["bodies"]["b"]["listing"]] == ["jr", "_clear"]
    assert v["by_id"][empty]["bodies"]["b"] == {
        "status": sameness.DECOMPILE_EMPTY,
        "size_bytes": 200,
    }


def _banner_states(**kw: int) -> dict[str, Any]:
    """A function_states block carrying only the counts the read-first banner reads."""
    return {
        "withheld": False,
        "alignment_undetermined_anchored_differs": kw.get("head", 0),
        "alignment_undetermined_anchored_differs_line_number_form": kw.get("lnf", 0),
        "alignment_undetermined_anchored_differs_all": kw.get("flagged", 0),
        "alignment_undetermined_anchored_micro_side": kw.get("micro", 0),
        "alignment_undetermined_reading": {sameness.U_DIFFERS: kw.get("differs", 0)},
    }


def test_the_banner_always_says_the_head_is_not_yet_told_apart() -> None:
    """Whenever a pair is flagged anchored_differs the banner says the head pairs are NOT yet told
    apart — with a line-number demotion and without one (then no demotion sentence). A diff with
    only micro-side pairs still gets a banner (the micro count and its filter, and that R is not
    cleared), with no head sentence; with neither there is none.

    MUTATION: drop the "NOT yet told apart" sentence -> RED; banner only when a pair is flagged
    anchored_differs -> the micro-only diff has none -> RED."""
    plain = pv.anchored_differs_banner(_banner_states(head=3, flagged=4, differs=9))
    assert plain is not None
    assert "The 3 head pairs are NOT yet told apart" in plain
    assert "demoted" not in plain  # L == 0: no demotion sentence, the told-apart one stays
    demoted = pv.anchored_differs_banner(_banner_states(head=3, lnf=2, flagged=6, differs=9))
    assert demoted is not None
    assert "2 more anchored pairs were demoted" in demoted
    assert "The 3 head pairs are NOT yet told apart" in demoted
    micro_only = pv.anchored_differs_banner(_banner_states(micro=2, differs=5))
    assert micro_only is not None
    assert "2 anchored pairs have one side a design-skipped micro-stub" in micro_only
    assert "anchored_micro_side=true" in micro_only and "does NOT clear" in micro_only
    assert "told apart" not in micro_only and "read these first" not in micro_only
    both = pv.anchored_differs_banner(_banner_states(head=1, flagged=1, micro=1, differs=2))
    assert both is not None and "may also be flagged anchored_differs" in both
    assert pv.anchored_differs_banner(_banner_states(differs=5)) is None


@pytest.mark.parametrize(
    "name",
    ["sub_9abcd", "FUN_0009abcd", "thunk_FUN_0009abcd", "UndefinedFunction_0009abcd", "LAB_9abcd"],
)
def test_a_made_up_name_anchors_by_address_only(tmp_path: Path, current: None, name: str) -> None:
    """A name a decompiler makes up (its number is not this function's address, so only the whole-
    name pattern can tell) ties nothing: the same such name at two addresses is unanchored; at one
    address the pair is anchored by the address alone.

    MUTATION: drop the whole-name pattern from ``_is_synthetic_name`` -> the two-address pair is
    anchored by the name, and the one-address pair reads ``addr+name`` -> RED."""
    w = World(tmp_path)
    apart = _ud(w, "00020000", "00030000", 0.87, name_a=name, name_b=name)
    together = _ud(w, "00021000", "00021000", 0.87, name_a=name, name_b=name)
    w.commit()
    v = _view(w)
    assert _reading(v, apart)["state"] == "differs"
    assert "anchored_differs" not in _reading(v, apart)
    assert _reading(v, together)["anchor"] == "addr"


def test_a_name_ending_in_its_own_address_is_made_up_on_that_side(
    tmp_path: Path, current: None
) -> None:
    """A ``loc_<addr>`` name (a family the whole-name pattern does not list) is made up on the side
    whose own entry address it ends in, and only there — so the same name on two addresses
    anchors nothing, whichever side it names. Each side is judged against its own address.

    MUTATION: drop the own-address rule -> both pairs anchored by name -> RED; judge name_b
    against addr_a -> the second pair's B name reads as real -> anchored -> RED."""
    w = World(tmp_path)
    names_a = _ud(w, "00040000", "00050000", 0.87, name_a="loc_00040000", name_b="loc_00040000")
    names_b = _ud(w, "00060000", "00070000", 0.87, name_a="loc_00070000", name_b="loc_00070000")
    w.commit()
    v = _view(w)
    for eid in (names_a, names_b):
        assert _reading(v, eid)["state"] == "differs"
        assert "anchored_differs" not in _reading(v, eid), eid


@pytest.mark.parametrize("name", ["init_engine", "inet_aton", "localtime_r"])
def test_a_real_name_that_starts_like_a_made_up_one_still_anchors(
    tmp_path: Path, current: None, name: str
) -> None:
    """A real symbol that only starts like a made-up prefix (``in``, ``local``) is matched as a
    whole, not by its start: it stays a real name and anchors a pair at two addresses.

    MUTATION: match the pattern by prefix instead of as a whole -> the name reads as made up and
    the pair is unanchored -> RED."""
    w = World(tmp_path)
    eid = _ud(w, "00020000", "00030000", 0.87, name_a=name, name_b=name)
    w.commit()
    r = _reading(_view(w), eid)
    assert (r.get("anchored_differs"), r.get("anchor")) == (True, "name")


def test_a_pair_with_no_body_is_never_flagged(tmp_path: Path, current: None) -> None:
    """Anchored at one address, but a side has no body to read: B not in the functions table
    (no_body), or in it with empty pseudocode (unavailable) — neither reading is differs, so
    neither is flagged.

    MUTATION: let ``_anchored_differs`` accept no_body / unavailable -> RED."""
    w = World(tmp_path)
    w.pair("00020000", "00020000", 0.5, 0.87)
    w.fn("a", "00020000", ["foo", "bar"], pseudocode="x = foo(1);")
    w.pair("00021000", "00021000", 0.5, 0.87)
    w.fn("a", "00021000", ["foo"], pseudocode="x = foo(2);")
    w.fn("b", "00021000", ["foo"], pseudocode=None)
    w.commit()
    v = _view(w)
    for eid, state in (
        (_pair_id("00020000", "00020000"), "no_body"),
        (_pair_id("00021000", "00021000"), "unavailable"),
    ):
        r = _reading(v, eid)
        assert r["state"] == state
        assert "anchored_differs" not in r, state


def _ordered_world(tmp_path: Path) -> tuple[World, dict[str, str]]:
    """The function world (bucket A and a changed length constant at attention 0) plus: a flagged
    pair read first (0.9), a flagged pair below the floor (0.5), an unanchored pair reading differs
    (0.3), an R pair read identical_unique (0.2), and a bucket C pair (sunk)."""
    w = _function_world(tmp_path)
    ids = {
        "a0": _pair_id("0000b000", "0000c000"),
        "first": _ud(w, "00020000", "00020000", 0.9),
        "below": _ud(w, "00021000", "00021000", 0.5),
        "plain": _ud(w, "00022000", "00023000", 0.3),
        "settled": _ud(w, "00024000", "00025000", 0.2, differs=False),
    }
    w.pair("00026000", "00027000", 0.97, 0.7)
    w.fn("a", "00026000", ["memset"], pseudocode="memset(b,0,8);")
    w.fn("b", "00027000", ["memset"], pseudocode="memset(b,0,8);")
    ids["sunk"] = _pair_id("00026000", "00027000")
    w.commit()
    return w, ids


def test_the_lens_puts_read_first_ahead_of_below_the_floor_ahead_of_the_rest(
    tmp_path: Path, current: None
) -> None:
    """★ Under sort_by='significance': attention 0, then inside attention 1 the read-first pair,
    then the flagged pair below the floor, then the other entries (lowest similarity first, the
    identical_unique R entry closing the tier), then the sunk entry. The pair below the floor has
    the LOWER similarity, so only the read-first level keeps it behind the read-first pair.

    MUTATION: give every flagged pair one level -> the 0.5 pair comes before the 0.9 pair -> RED;
    put ``read_first`` before ``attention`` in the key -> the flagged pairs pass attention 0 ->
    RED; drop ``read_first`` from the key -> the 0.3 pair comes first -> RED."""
    w, ids = _ordered_world(tmp_path)
    v = _view(w, sort_by="significance")
    order = [e["entry_id"] for e in v["entries"]]
    for k, eid in ids.items():
        assert eid in order, k
    pos = {k: order.index(eid) for k, eid in ids.items()}
    assert pos["a0"] < pos["first"] < pos["below"] < pos["plain"] < pos["settled"] < pos["sunk"]
    assert v["by_id"][ids["a0"]]["significance"]["attention"] == 0
    assert v["by_id"][ids["sunk"]]["significance"]["attention"] == 2
    assert _reading(v, ids["settled"])["state"] == "identical_unique"


def test_a_flagged_r_entry_stays_at_attention_one(tmp_path: Path, current: None) -> None:
    """The flag orders inside attention 1; an R entry carrying it never reaches attention 2.

    MUTATION: return ATTENTION_SINK for an anchored_differs entry -> RED."""
    w, ids = _ordered_world(tmp_path)
    v = _view(w, sort_by="significance")
    for k in ("first", "below"):
        assert v["by_id"][ids[k]]["significance"] == {"attention": 1, "basis": "anchored_differs"}
    for e in v["entries"]:
        if e["bucket"] == "R":
            assert e["significance"]["attention"] <= 1, e["entry_id"]


def _banner_world(tmp_path: Path, case: str) -> World:
    w = World(tmp_path)
    if case in ("both", "below_only"):
        _ud(w, "00021000", "00021000", 0.5)  # flagged, below the floor
    if case == "both":
        _ud(w, "00020000", "00020000", 0.9)  # flagged, read first
    if case in ("both", "below_only", "none"):
        _ud(w, "00022000", "00023000", 0.3)  # reads differs, unanchored
    w.commit()
    return w


@pytest.mark.parametrize(
    ("case", "counts"),
    [("both", (1, 2, 3)), ("below_only", (0, 1, 2)), ("none", None)],
)
def test_get_diff_meta_hangs_the_read_first_banner_when_any_pair_is_flagged(
    tmp_path: Path, current: None, case: str, counts: tuple[int, int, int] | None
) -> None:
    """★ One banner whenever ANY pair is flagged — also when none is read first (every flagged
    pair below the floor) — naming the read-first count, every flagged pair, the total reading
    differs, the call that walks the rest of R, and that the flagged pairs do not clear it.
    None when no pair is flagged.

    MUTATION: hang it only when the read-first count is > 0 -> the below_only case has none ->
    RED; leave the total reading differs out of it -> RED."""
    w = _banner_world(tmp_path, case)
    meta = da.get_diff_meta(w.atlas, DIFF)
    if counts is None:
        assert meta["banners"] == []
        return
    first, flagged, differs = counts
    assert meta["functions"]["alignment_undetermined_reading"]["differs"] == differs
    assert len(meta["banners"]) == 1
    (banner,) = meta["banners"]
    assert banner.startswith(f"anchored_differs: {first} undetermined pairs are confidently paired")
    assert f"{flagged} anchored pairs differ in total" in banner
    assert f"{differs} undetermined pairs read 'differs' in total" in banner
    assert 'get_diff_patch_view(bucket="R", anchored_differs=true)' in banner
    assert 'get_diff_patch_view(bucket="R", sort_by="significance")' in banner
    assert "does NOT clear the rest of the R bucket" in banner


def test_get_diff_meta_banners_when_there_is_no_diff_or_it_is_withheld(
    tmp_path: Path, current: None
) -> None:
    """No such diff -> an empty list. A withheld diff -> its own banners as the view gives them,
    and never the read-first one (a withheld diff has no counts to put in it).

    MUTATION: drop ``banners`` from the not-found answer -> ``.get`` reads None -> RED; give a
    withheld diff an empty list instead of its own banners -> RED. (A withheld diff carries no
    counts, so the read-first banner cannot be built for it; the last assertion records that.)"""
    assert da.get_diff_meta(World(tmp_path).atlas, "runA::runB::nope").get("banners") == []
    pv._clear_view_caches()
    w = _banner_world(tmp_path / "withheld", "both")
    w.atlas.execute("UPDATE diff_meta SET version_skew = 1")
    w.commit()
    meta = da.get_diff_meta(w.atlas, DIFF)
    assert meta["functions"]["withheld"] is True
    assert meta["banners"] == meta["functions"]["banners"]
    assert "diff_undetermined:version_skew" in meta["banners"]
    assert not any(b.startswith("anchored_differs") for b in meta["banners"])


def test_function_states_keeps_its_keys_and_adds_the_read_face_counts(
    tmp_path: Path, current: None
) -> None:
    """The existing keys keep their names and shapes; the read-first / line-number / micro-side
    counts are new top-level integers and the two unavailable_by_cause blocks are new top-level
    dicts whose values sum to the unavailable count they split.

    MUTATION: put the counts inside alignment_undetermined_reading -> its keys are no longer the
    reading states -> RED."""
    w, _ids = _ordered_world(tmp_path)
    s = pv.function_states(w.atlas, DIFF)
    assert s is not None
    existing = {
        "diff_id",
        "withheld",
        "aligned",
        "unchanged",
        "changed",
        "unverified",
        "identical_text_unverified_by_body",
        "no_body",
        "alignment_undetermined",
        "alignment_undetermined_reading",
        "one_sided",
    }
    new_counts = {
        "alignment_undetermined_anchored_differs",
        "alignment_undetermined_anchored_differs_line_number_form",
        "alignment_undetermined_anchored_differs_all",
        "alignment_undetermined_anchored_micro_side",
    }
    new_by_cause = {"unavailable_by_cause", "alignment_undetermined_unavailable_by_cause"}
    assert set(s) == existing | new_counts | new_by_cause
    assert set(s["alignment_undetermined_reading"]) == set(sameness.U_STATES)
    assert all(type(s[k]) is int for k in new_counts)
    assert all(set(s[k]) == set(pv._UNAVAILABLE_CAUSES) for k in new_by_cause)
    assert s["alignment_undetermined_anchored_differs"] == 1
    assert s["alignment_undetermined_anchored_differs_all"] == 2
    # the by-cause buckets PARTITION their unavailable count: each sums to it.
    assert sum(s["unavailable_by_cause"].values()) == s["unverified"]["unavailable"]
    assert (
        sum(s["alignment_undetermined_unavailable_by_cause"].values())
        == s["alignment_undetermined_reading"]["unavailable"]
    )


def _filter_world(tmp_path: Path) -> tuple[World, dict[str, str]]:
    w = World(tmp_path)
    ids = {
        "one": _ud(w, "00020000", "00020000", 1.0),
        "high": _ud(w, "00021000", "00021000", 0.95),
        "floor": _ud(w, "00022000", "00022000", 0.75),
        "below": _ud(w, "00023000", "00023000", 0.6),
        "low": _ud(w, "00024000", "00024000", 0.3),
    }
    _ud(w, "00025000", "00026000", 0.8)  # reads differs, unanchored
    _ud(w, "00027000", "00027000", 0.8, differs=False)  # anchored, identical_unique
    w.pair("00010000", "00011000", 0.97, 0.9)  # an aligned pair whose body changed
    w.fn("a", "00010000", ["foo"], pseudocode="y = 1;")
    w.fn("b", "00011000", ["foo"], pseudocode="y = 2;")
    w.commit()
    return w, ids


def test_the_anchored_differs_filter_lists_every_flagged_pair_read_first_first(
    tmp_path: Path, current: None
) -> None:
    """★ anchored_differs=true lists exactly the flagged pairs — similarity 1 and the pairs below
    the floor included — the read-first ones first, each group by similarity, highest first; a
    sort_by orders them instead. (By construction every read-first pair has a higher similarity
    than every pair below the floor, so a similarity-descending order alone puts the groups the
    same way; the ordering's teeth are against the default order, lowest similarity first.)

    MUTATION: drop the filter's own order (fall back to the default one) -> the 0.3 pair comes
    first -> RED; drop the filter condition -> the unflagged entries are listed -> RED."""
    w, ids = _filter_world(tmp_path)
    v = _view(w, bucket="R", anchored_differs=True)
    order = [e["entry_id"] for e in v["entries"]]
    assert order == [ids[k] for k in ("one", "high", "floor", "below", "low")]
    assert [e["proposed_pair_reading"]["in_read_first"] for e in v["entries"]] == [
        True,
        True,
        True,
        False,
        False,
    ]
    assert v["lens"]["filters"]["anchored_differs"] is True
    assert "anchored_differs" in v["lens"]
    s = pv.function_states(w.atlas, DIFF)
    assert s is not None and s["alignment_undetermined_anchored_differs_all"] == len(order)
    unset = _view(w, anchored_differs=True)  # bucket unset: the same pairs
    assert [e["entry_id"] for e in unset["entries"]] == order
    by_sim = _view(w, bucket="R", anchored_differs=True, sort_by="similarity")
    assert [e["entry_id"] for e in by_sim["entries"]] == list(reversed(order))


def test_the_anchored_differs_filter_refuses_what_it_cannot_apply_to(
    tmp_path: Path, current: None
) -> None:
    """Every combination it cannot honour is an error, never an empty or unfiltered page."""
    w, _ids = _filter_world(tmp_path)
    cases = [
        ({"view": "string_edge"}, "anchored_differs applies to view='sink_patch' only"),
        ({"view": "candidate_flat"}, "anchored_differs applies to view='sink_patch' only"),
        (
            {"not_listed_page": "aligned_pseudocode_differs"},
            "anchored_differs applies to the listed entries, not to not_listed_page",
        ),
        ({"bucket": "A"}, "anchored_differs keeps bucket R entries only, got bucket='A'"),
    ]
    for kw, error in cases:
        out = pv.get_diff_patch_view(w.atlas, DIFF, anchored_differs=True, **kw)
        assert out.get("error") == error, kw
    out = pv.get_diff_patch_view(w.atlas, DIFF, anchored_differs="yes")  # type: ignore[arg-type]
    assert out.get("error") == "anchored_differs must be true or false, got 'yes'"


def test_the_mcp_tool_passes_anchored_differs_through(tmp_path: Path, current: None) -> None:
    """The call the banner names works through the MCP tool and lists the same pairs.

    MUTATION: drop the argument from the tool's call into the view -> every entry is listed ->
    RED; drop it from the tool's signature -> the call fails -> RED."""
    w, ids = _filter_world(tmp_path)
    tool = mcp_app.make_tools(w.path)["get_diff_patch_view"]
    out = tool(DIFF, bucket="R", anchored_differs=True)
    assert "error" not in out, out
    assert {e["entry_id"] for e in out["entries"]} == set(ids.values())
    assert str(pv.ANCHORED_DIFFERS_SIM_FLOOR) in (tool.__doc__ or "")


def test_the_flag_is_on_the_reading_whatever_the_sort(tmp_path: Path, current: None) -> None:
    """``anchored_differs`` / ``anchor`` / ``in_read_first`` are on the proposed reading with no
    sort_by at all; the lens's attention and basis are there only under sort_by='significance'.

    MUTATION: compute the flag fields only under the lens -> RED."""
    w, ids = _filter_world(tmp_path)
    v = _view(w)
    e = v["by_id"][ids["below"]]
    assert "significance" not in e
    r = e["proposed_pair_reading"]
    fields = (r.get("anchored_differs"), r.get("anchor"), r.get("in_read_first"))
    assert fields == (True, "addr", False)


def test_the_diff_command_line_counts_the_read_first_and_micro_pairs(
    tmp_path: Path, current: None
) -> None:
    """The diff command's per-binary line carries the read-first and micro-side counts inside its
    reading; both print even at zero, so an absent count never reads as 'not computed'.

    MUTATION: drop the counts from ``_function_line`` -> RED."""
    from treasure_map.cli.hunt_cli import _function_line

    w = _banner_world(tmp_path, "both")
    line = _function_line(pv.function_states(w.atlas, DIFF))
    assert "(read: 3 differs; anchored_differs=1, anchored_micro_side=0)" in line
    # N=0 still prints anchored_differs=0 (and anchored_micro_side=0) when any pair reads differs.
    pv._clear_view_caches()
    none = _function_line(pv.function_states(_banner_world(tmp_path / "none", "none").atlas, DIFF))
    assert "anchored_differs=0, anchored_micro_side=0" in none
