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
from treasure_map.lib.query import diff_review as dr
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query import sameness
from treasure_map.lib.query import sink_overlay as so
from treasure_map.lib.query.diff_workflow import DIFF_WORKFLOW
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
    subclasses as the candidate_tier view; A / a changed length constant first; a
    pseudocode-identical entry sunk but still listed; each tier named on the entry, from facts the
    entry itself reports.

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
    base = _view(w, sort_by="candidate_tier")
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
    """Every label, subclass, reason, fact, blind-spot key and sub-fact key the view emits — of a
    full page or a summary one (whose entries carry fewer keys), with the envelope's own."""
    out: set[str] = set(v["counts"]["by_subclass"]) | set(v["counts"]["by_row_subclass"])
    out |= {s["key"] for s in v["blind_spots"]} | set(v["banners"]) | set(v["not_listed"])
    for e in v.get("entries") or ():
        out |= {str(e.get("subclass")), *e.get("subclasses", ()), *e.get("facts", ())}
        out |= set(e.get("blind_spots", ()))
        out |= set((e.get("callee_set") or {}).keys())
        out |= {str((e.get("callee_set") or {}).get("reason"))}
        out |= set((e.get("callee_set") or {}).get("named_callees_differ", {}))
        for r in e.get("rows") or ():
            out |= {str(r["presence_reason"]), str(r["subclass"]), str(r["landing"])}
            out |= set(r.get("labels", {})) | {str(r.get("labels", {}).get("mechanism"))}
            out |= set(r.get("facts", ())) | {str(r.get("labels", {}).get("side"))}
        out |= _s7_labels(e)
        out |= _summary_labels(e)
        out |= _entry_words_labels(e)
    read_with = v.get("guards_read_with") or {}
    if read_with:
        out |= {"guards_read_with", *read_with, str(read_with.get("function"))}
    return out | _envelope_labels(v)


def _entry_words_labels(e: dict[str, Any]) -> set[str]:
    """The keys and enumerated values of an entry's entry_words block: the delta, each side's
    state / reason / block classes, and each word's keys and block class."""
    block = e.get("entry_words") or {}
    out: set[str] = set(block) | ({"entry_words", str(block.get("delta"))} if block else set())
    for side in ("a", "b"):
        one = block.get(side) or {}
        out |= set(one) | {str(one.get("state")), str(one.get("reason"))}
        out |= set(one.get("count_by_class") or {})
        for word in one.get("words") or ():
            out |= set(word) | {str(word.get("block_class"))} | set(word.get("run") or {})
    return out


def _summary_labels(e: dict[str, Any]) -> set[str]:
    """The keys and enumerated values a summary entry adds: delta_summary and its hunk,
    proposed_pair_summary, the lifted reading flags, the counts' names."""
    out: set[str] = {k for k in e if k in _S_REDUCED_OR_DERIVED}
    if "anchor" in e:
        out.add(str(e["anchor"]))
    proposed = e.get("proposed_pair_summary") or {}
    if proposed:
        out |= {"proposed_pair_summary", *proposed, str(proposed.get("state"))}
    for block in (e, proposed):
        delta = block.get("delta_summary") or {}
        out |= set(delta) | {str(delta.get("kind")), str(delta.get("reason"))}
        hunk = delta.get("hunk") or {}
        if hunk:
            out |= {"hunk", *hunk, str(hunk.get("withheld"))}
        for key in ("hidden_region", "bodies", "sink_callee_swap", "string_edges", "callers_a"):
            out |= set(block.get(key) or {})
    return out


def _envelope_labels(v: dict[str, Any]) -> set[str]:
    """The envelope keys a page adds by its detail and its place: detail / detail_with /
    detail_note, first_page_only with the paths it names, the anchor template. (The view names in
    available_views are the tool's own, as old as it, and not read here.)"""
    out: set[str] = {
        k for k in ("detail", "detail_with", "detail_note", "first_page_only") if k in v
    }
    out |= {str(v.get("detail"))} | set(v.get("detail_with") or {})
    out |= {str((v.get("lens") or {}).get("sort_by"))}
    fpo = v.get("first_page_only") or {}
    out |= set(fpo) | set(fpo.get("keys", ())) | set(fpo.get("shortened", ()))
    template = (v.get("annotation") or {}).get("anchor_ref_template") or {}
    if template:
        out |= {"anchor_ref_template", *template}
    words = v.get("entry_words_counts") or {}
    if words:
        out |= {"entry_words_counts", *words}
        out |= set(words.get("listed") or {}) | set(words.get("not_listed") or {})
        out |= set((words.get("unavailable") or {}).values())
    return out


def _s7_labels(e: dict[str, Any]) -> set[str]:
    """The keys and enumerated values of the guard scan, the guard links and the sink axes (of a
    listed entry, or of a not-listed pair, which has no rows)."""
    out: set[str] = set()
    for block in (e, e.get("proposed_pair_reading") or {}):
        out |= {k for k in ("guard_scan", "guards") if k in block}
        scan = block.get("guard_scan")
        if scan:
            out |= set(scan) | {str(scan.get(k)) for k in ("state", "reason", "shown_rule")}
            out |= set(scan.get("by_const_class") or {}) | set(scan.get("other_comparisons") or {})
        for g in block.get("guards") or ():
            out |= set(g) | {str(g["const_class"])} | set(g.get("renumbered_in_a") or {})
    for key in ("sink_axes_with", "sink_axes_withheld_rows"):
        if key in e:
            out |= {key, str(e[key])}
    for r in e.get("rows") or ():
        out |= {k for k in ("guard_links", "sink_axes") if k in r}
        links = r.get("guard_links") or {}
        out |= set(links) | {str(links.get("pairing"))}
        for link in links.values():
            if isinstance(link, dict):
                out |= set(link) | {str(link.get("unavailable"))}
        axes = r.get("sink_axes") or {}
        out |= set(axes) | {str(axes.get("withheld"))}
        for side in ("a", "b"):
            one = axes.get(side) or {}
            out |= set(one) | set(one.get("unavailable") or {})
            out |= {str((one.get("def_use") or {}).get("scope"))}
            for value in one.values():
                if isinstance(value, dict):
                    out |= set(value)
    return out


def test_no_label_says_what_a_change_means(
    world: World, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every label the view emits — the S7 guard scan, guard links and sink axes among them (a
    list page, a scan, the not-listed page and a one-entry read of every entry of a world that
    carries their rarer values too, and a read with no block match made) — is free of words that
    say what a change means.

    MUTATION (verified RED): name a subclass ``sink_removed`` -> RED; MUTATION (verified RED, 1
    failed): name the guard scan's shown_rule ``new_then_b_order`` -> RED; MUTATION (verified RED,
    1 failed): name the link reason ``other_function`` ``removed_to_other_function`` -> RED."""
    labels = _labels(_view(world))
    assert len(labels) > 40
    (tmp_path / "s7").mkdir()
    g = _vocabulary_world(tmp_path / "s7")
    listed = _view(g)
    s7 = _labels(listed) | _labels(_view(g, rows_limit=0))
    for entry_id in listed["by_id"]:
        s7 |= _labels(pv.get_diff_patch_view(g.atlas, DIFF, entry_id=entry_id))
    page = pv.get_diff_patch_view(g.atlas, DIFF, not_listed_page="aligned_pseudocode_differs")
    for row in page["entries"]:
        s7 |= _s7_labels(row)
    # The summary pages (each page, so a later page's first_page_only is read too), the
    # summary of the not-listed pairs, of the overlay rows and of the string edges.
    (tmp_path / "summary").mkdir()
    sw = _summary_world(tmp_path / "summary")
    summary: set[str] = set()
    for w in (g, sw, world):
        for page in _pages(w, detail="summary") + _pages(
            w, detail="summary", sort_by="significance"
        ):
            summary |= _labels(page)
        summary |= _labels(_pages(w, limit=1)[-1])
    for kw in (
        {"not_listed_page": "aligned_pseudocode_differs"},
        {"view": "candidate_flat"},
    ):
        summary |= _labels(pv.get_diff_patch_view(sw.atlas, DIFF, detail="summary", **kw))
    summary |= _envelope_labels(
        pv.get_diff_patch_view(world.atlas, DIFF, detail="summary", view="string_edge")
    )
    assert {
        "detail",
        "summary",
        "full",
        "detail_with",
        "one_entry",
        "its_rows",
        "its_detail",
        "detail_note",
        "first_page_only",
        "keys",
        "shortened",
        "read_with",
        "lens.order",
        "review_progress.next_page",
        "review_progress.note",
        "annotation.what",
        "anchor_ref_template",
        "function_pair",
        "function_presence",
        "delta_summary",
        "hunk",
        "structural_lines",
        "withheld",
        "substitutions_total",
        "calls_differ",
        "structural_spans",
        "line_number_form",
        "proposed_pair_summary",
        "a_body_elsewhere_in_b_count",
        "anchored_micro_side",
        "in_read_first",
        "demoted",
    } <= summary, sorted(summary)
    s7 |= summary
    # No block match made at all: every scan with a changed block on both sides is not_extracted.
    monkeypatch.setattr(sameness, "DELTA_TOKEN_PRODUCT_CAP", 0)
    pv._clear_view_caches()
    s7 |= _labels(_view(g))
    # the S7 vocabulary is really in the set read (not an empty pass)
    assert {
        "guard_scan",
        "guards_read_with",
        "linked_first_then_b_order",
        "b_order",
        "linked_not_shown",
        "renumbered_in_a",
        "a_name",
        "const_class",
        "zero",
        "nonzero",
        "pairing",
        "proposed",
        "not_extracted",
        "too_large",
        "not_recorded_for_class",
        "other_function",
        "ambiguous_ref",
        "no_evidence",
        "class_unknown",
        "not_in_record",
        "sink_axes_with",
        "entry_id",
        "callsite",
        "sink_name",
        "unscoped",
        "unavailable",
    } <= s7, sorted(s7)
    for label in labels | s7:
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
    assert "sunk_with_body_size_differs" not in _view(w, sort_by="candidate_tier")["lens"]


def test_the_build_reads_no_body_and_function_states_computes_no_delta(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """build_diff_view reads neither pseudocode nor image extents; function_states reads them
    but computes no delta; only the page read does.

    MUTATION: compute the page's deltas in function_states -> RED."""
    w = _qualified_world(tmp_path)
    calls: list[str] = []
    # The view computes a delta (and its guard scan) through pseudocode_delta_and_guards.
    for name in ("read_function_bodies", "read_image_ranges", "pseudocode_delta_and_guards"):
        real = getattr(pv.sameness, name)

        def probe(*a: Any, _real: Any = real, _name: str = name) -> Any:
            calls.append(_name)
            return _real(*a)

        monkeypatch.setattr(pv.sameness, name, probe)
    pv.build_diff_view(w.atlas, DIFF)
    assert calls == []
    pv.function_states(w.atlas, DIFF)
    assert "read_function_bodies" in calls and "read_image_ranges" in calls
    assert "pseudocode_delta_and_guards" not in calls
    pv.get_diff_patch_view(w.atlas, DIFF)
    assert "pseudocode_delta_and_guards" in calls


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
    """An anchored_differs pair at/above the floor whose text changed only by a __FILE__/__LINE__
    shift, with the same callee set and the same body size on both sides, is demoted out of the
    read-first head: still flagged (listed by anchored_differs=true), but in_read_first false,
    demoted true, and carrying line_number_form and both sizes. A pair with a real change stays in
    the head; the count moves from the head (N) to line_number_form (L) while _all is unchanged.

    MUTATION (each verified RED): lower the count only, not the read_first order -> the shift pair
    stays in_read_first true and leads the head; read the sizes off body_status (which exists only
    when a side has no text, so never here) -> the shift pair is never demoted."""
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
    assert sr.get("demoted") is True and sr.get("size_bytes") == {"a": 200, "b": 200}
    hr = _reading(v, real)
    assert hr["in_read_first"] is True and "line_number_form" not in hr
    assert "demoted" not in hr and "size_bytes" not in hr
    s = pv.function_states(w.atlas, DIFF)
    assert s is not None
    assert s["alignment_undetermined_anchored_differs"] == 1  # N: only the real one in the head
    assert s["alignment_undetermined_anchored_differs_line_number_form"] == 1  # L
    assert s["alignment_undetermined_anchored_differs_line_number_kept"] == 0
    assert s["alignment_undetermined_anchored_differs_all"] == 2  # _all unchanged
    assert set(_view(w, bucket="R", anchored_differs=True)["by_id"]) == {shift, real}
    banner = pv.anchored_differs_banner(s)
    assert banner is not None
    assert "1 more anchored pairs were demoted" in banner and "__FILE__/__LINE__" in banner


def _line_shift(
    w: World,
    addr: str,
    *,
    callees_a: list[str] | None = None,
    callees_b: list[str] | None = None,
    size_a: int = 200,
    size_b: int = 200,
    truncated_a: int = 0,
) -> str:
    """One anchored undetermined pair above the floor whose text differs only by a line-number
    shift (``log("x.c", 10)`` -> ``log("x.c", 17)``); callees ``["log"]`` and 200 bytes on each
    side unless given. Returns the entry id."""
    w.pair(addr, addr, 0.5, 0.9)
    w.fn(
        "a",
        addr,
        callees_a or ["log"],
        pseudocode='log("x.c", 10);',
        size_bytes=size_a,
        truncated=truncated_a,
    )
    w.fn("b", addr, callees_b or ["log"], pseudocode='log("x.c", 17);', size_bytes=size_b)
    return _pair_id(addr, addr)


# why a line-number shift stays in the head: (_line_shift kwargs, what its callee_set carries,
# its size_bytes a / b). FUN_00099000 has no aligned pair, so it cannot be identified.
_KEPT: dict[str, tuple[dict[str, Any], dict[str, str], tuple[int | None, int | None]]] = {
    "callee_differs": ({"callees_b": ["log", "system"]}, {"state": "differs"}, (200, 200)),
    "callee_identity_unresolved": (
        {"callees_a": ["log", "FUN_00099000"], "callees_b": ["log", "FUN_00099000"]},
        {"state": "undetermined", "reason": "callee_identity_unresolved"},
        (200, 200),
    ),
    "callees_truncated": (
        {"truncated_a": 1},
        {"state": "undetermined", "reason": "callees_truncated"},
        (200, 200),
    ),
    "size_differs": ({"size_b": 204}, {"state": "equal"}, (200, 204)),
    "size_unrecorded": ({"size_a": 0, "size_b": 0}, {"state": "equal"}, (None, None)),
}


@pytest.mark.parametrize("why", sorted(_KEPT))
def test_a_line_number_shift_stays_in_the_head_unless_callees_and_sizes_are_proven_equal(
    tmp_path: Path, current: None, why: str
) -> None:
    """A line-number shift in the text does not show a call added or dropped in a block the
    decompiler removed. It is demoted only when the two callee sets are proven equal and both body
    sizes are recorded and equal; a shift whose callee set differs or is undetermined, or whose
    sizes differ or are unrecorded, stays in the read-first head — demoted false, carrying its
    line_number_form, callee_set and size_bytes — counted in the head (N) and as kept (K), beside a
    shift on the same page that is demoted (L).

    MUTATION (each verified RED): drop the size condition -> size_differs, size_unrecorded; test
    the sizes by equality alone -> size_unrecorded; refuse only a callee set that differs ->
    callee_identity_unresolved, callees_truncated; ``demoted`` from line_number_form alone -> all;
    gate the counts but not the order -> all; gate the order but not the counts -> all; leave out
    size_bytes -> all; count no kept pair -> all; take both sizes from side a -> size_differs."""
    kw, callee_set, (sa, sb) = _KEPT[why]
    w = World(tmp_path)
    demoted = _line_shift(w, "00040000")
    kept = _line_shift(w, "00041000", **kw)
    w.commit()
    v = _view(w)
    d, k = _reading(v, demoted), _reading(v, kept)
    assert d["line_number_form"] == k["line_number_form"] == {"delta": 7, "sites": 1}
    assert (d.get("demoted"), d["in_read_first"]) == (True, False)
    assert d.get("size_bytes") == {"a": 200, "b": 200}
    assert (k.get("demoted"), k["in_read_first"]) == (False, True)
    assert {key: k["callee_set"].get(key) for key in callee_set} == callee_set
    assert k.get("size_bytes") == {"a": sa, "b": sb}
    order = [e["entry_id"] for e in _view(w, bucket="R", anchored_differs=True)["entries"]]
    assert order == [kept, demoted]  # the kept pair leads: it is in the read-first head
    s = pv.function_states(w.atlas, DIFF)
    assert s is not None
    assert s["alignment_undetermined_anchored_differs"] == 1  # N: the kept one
    assert s["alignment_undetermined_anchored_differs_line_number_kept"] == 1  # K, part of N
    assert s["alignment_undetermined_anchored_differs_line_number_form"] == 1  # L
    assert s["alignment_undetermined_anchored_differs_all"] == 2
    banner = pv.anchored_differs_banner(s)
    assert banner is not None
    assert "1 of the head pairs changed only by such a line-number shift" in banner


def test_a_line_number_shift_on_a_diff_not_shown_current_stays_in_the_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On a diff not shown current no callee list is compared (callee_set undetermined,
    source_stale), so a line-number shift stays in the head though its sizes are equal.

    MUTATION (verified RED): refuse only a callee set that differs -> it is demoted -> RED."""
    monkeypatch.setattr(
        pv,
        "diff_source_staleness",
        lambda atlas, diff_id: {
            "source_stale": True,
            "source_stale_reason": "diff_logic_changed",
            "toolchain_checked": False,
        },
    )
    w = World(tmp_path)
    shift = _line_shift(w, "00040000")
    w.commit()
    r = _reading(_view(w), shift)
    assert r["line_number_form"] == {"delta": 7, "sites": 1}
    assert r["callee_set"] == {"state": "undetermined", "reason": "source_stale"}
    assert (r.get("demoted"), r["in_read_first"]) == (False, True)
    assert r.get("size_bytes") == {"a": 200, "b": 200}
    s = pv.function_states(w.atlas, DIFF)
    assert s is not None
    assert s["alignment_undetermined_anchored_differs_line_number_kept"] == 1
    assert s["alignment_undetermined_anchored_differs_line_number_form"] == 0


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
        "alignment_undetermined_anchored_differs_line_number_kept": kw.get("kept", 0),
        "alignment_undetermined_anchored_differs_all": kw.get("flagged", 0),
        "alignment_undetermined_anchored_micro_side": kw.get("micro", 0),
        "alignment_undetermined_reading": {sameness.U_DIFFERS: kw.get("differs", 0)},
    }


def test_the_banner_always_says_the_head_is_not_yet_told_apart() -> None:
    """Whenever a pair is flagged anchored_differs the banner says the head pairs are NOT yet told
    apart — with a line-number demotion and without one (then no demotion sentence). A diff with
    only micro-side pairs still gets a banner (the micro count and its filter, and that R is not
    cleared), with no head sentence; with neither there is none.

    A line-number shift kept in the head for want of proven-equal callee sets and sizes gets its own
    sentence, only when there is one.

    MUTATION: drop the "NOT yet told apart" sentence -> RED; banner only when a pair is flagged
    anchored_differs -> the micro-only diff has none -> RED; drop the kept sentence -> RED."""
    plain = pv.anchored_differs_banner(_banner_states(head=3, flagged=4, differs=9))
    assert plain is not None
    assert "The 3 head pairs are NOT yet told apart" in plain
    assert "demoted" not in plain  # L == 0: no demotion sentence, the told-apart one stays
    demoted = pv.anchored_differs_banner(_banner_states(head=3, lnf=2, flagged=6, differs=9))
    assert demoted is not None
    assert "2 more anchored pairs were demoted" in demoted
    assert "callee sets and body sizes are equal" in demoted
    assert "The 3 head pairs are NOT yet told apart" in demoted
    assert "stay in the head" not in demoted  # K == 0: no kept sentence
    kept = pv.anchored_differs_banner(_banner_states(head=3, lnf=2, kept=1, flagged=6, differs=9))
    assert kept is not None
    assert "1 of the head pairs changed only by such a line-number shift" in kept
    assert "demoted=false" in kept and "The 3 head pairs are NOT yet told apart" in kept
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
        "alignment_undetermined_anchored_differs_line_number_kept",
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
    # the kept line-number shifts sit at or above the floor, inside the head count (N)
    kept = s["alignment_undetermined_anchored_differs_line_number_kept"]
    assert 0 <= kept <= s["alignment_undetermined_anchored_differs"]
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
    """``anchored_differs`` / ``anchor`` / ``in_read_first`` are on the proposed reading in the
    candidate_tier order too; the lens's attention and basis are there only in the significance
    order.

    MUTATION: compute the flag fields only under the lens -> RED."""
    w, ids = _filter_world(tmp_path)
    v = _view(w, sort_by="candidate_tier")
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


# ── the rows window: an entry carries a window of its rows, and every row is still counted ──────

_WIN_A, _WIN_B = "00001000", "00002000"
_WIN_ID = _pair_id(_WIN_A, _WIN_B)
_WIN_ANCHOR = f"runA::runB#function_pair#libx::{_WIN_A}::{_WIN_B}"
_IDENTICAL_ID = _pair_id("00003000", "00004000")  # placed, never listed (similarity 1, no row)
_NO_ROW_ID = _pair_id("00005000", "00006000")  # listed (C), with no candidate row at all


def _win_refs(i: int) -> tuple[str, str]:
    off = f"0x{0x10 + 4 * i:x}"
    return _ref("runA", _WIN_A, "copy", off), _ref("runB", _WIN_B, "copy", off)


def _win_index(view: dict[str, Any]) -> int:
    """The fixture position of a rendered row, read back from its a_ref's call offset."""
    return (int(view["a_ref"].rsplit("@", 1)[1], 16) - 0x10) // 4


def _win_row(kind: str, i: int) -> so.SinkOverlayRow:
    """One overlay row of the windowed pair. ``U``: a call matched to nothing (did not persist);
    ``A``: the matched call now calls another callee (did not persist, lands A); ``P``: persisted;
    ``D`` / ``K``: persisted, its size constant / size kind changed (the instances carry it)."""
    a_ref, b_ref = _win_refs(i)
    base = so.SinkOverlayRow(
        diff_id=DIFF,
        binary="libx",
        sink_class="copy",
        a_ref=a_ref,
        b_ref=b_ref,
        key_granularity="callsite",
        presence="persisted",
        presence_reason=None,
        match_basis="instruction",
        counterpart_call="present_same_callee",
        alignment_confidence=0.97,
    )
    if kind == "U":
        return replace(
            base,
            b_ref=None,
            presence="presence_undetermined",
            presence_reason="instruction_unmatched",
            counterpart_call=None,
        )
    if kind == "A":
        return replace(
            base,
            b_ref=None,
            presence="presence_undetermined",
            presence_reason="present_different_callee",
            counterpart_call="present_different_callee",
            counterpart_callee={
                "matched_addr": "00002010",
                "callees": [{"name": "popen"}],
                "same_callee_candidate_elsewhere": False,
            },
        )
    return base


_WIN_SIZES = {
    "D": (_size("cap_const", "0x200"), _size("cap_const", "0x400")),
    "K": (_size("const", "0x40"), _size("untraced", "len")),
}


def _window_world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, layout: str) -> World:
    """One changed, aligned pair whose overlay rows are ``layout`` in this order (one letter per
    row, see ``_win_row``), plus a placed-but-not-listed pair and a listed pair with no row."""
    w = World(tmp_path)
    w.pair(_WIN_A, _WIN_B, 0.97, 0.8)
    w.fn("a", _WIN_A, ["strcpy"])
    w.fn("b", _WIN_B, ["strcpy", "popen"])
    rows = []
    for i, kind in enumerate(layout):
        rows.append(_win_row(kind, i))
        a_ref, b_ref = _win_refs(i)
        flow_a, flow_b = _WIN_SIZES.get(kind, (None, None))
        w.inst("a", a_ref, "copy", "strcpy", flow_a)
        if kind in "PDK":
            w.inst("b", b_ref, "copy", "strcpy", flow_b)
    w.pair("00003000", "00004000", 0.97, 1.0)
    w.pair("00005000", "00006000", 0.97, 0.6)
    w.fn("a", "00005000", ["memset", "log_it"])
    w.fn("b", "00006000", ["memset"])
    w.commit()

    def rows_of(atlas: sqlite3.Connection, diff_id: str) -> so.SinkOverlayResult:
        return so.SinkOverlayResult(list(rows), so.SinkOverlayCoverage(0, 0, 0, 0, 0, False))

    monkeypatch.setattr(pv, "compute_sink_overlay", rows_of)
    return w


def _grouped(layout: str) -> list[int]:
    """The fixture positions in the window order, worked out from the layout alone: rows that did
    not persist, then persisted rows with a size signal, then the rest, each in fixture order."""
    return [i for kinds in ("UA", "DK", "P") for i, kind in enumerate(layout) if kind in kinds]


def _one(w: World, **kw: Any) -> dict[str, Any]:
    out = pv.get_diff_patch_view(w.atlas, DIFF, **kw)
    assert "error" not in out, out
    by_id = {e["entry_id"]: e for e in out["entries"]}
    assert _WIN_ID in by_id
    return by_id[_WIN_ID]


# 25 rows, three of them not persisted — one of those past the 20th row — and no size signal.
_MAIN = "UPPPPUPPPPPPPPPPPPPPPPUPP"


def test_an_entry_carries_a_window_of_its_rows_and_says_how_many_there_are(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A 25-row entry carries 20 rows inline, with the total and where the next window starts.

    MUTATION (verified RED, 1 failed): in _render keep ``out["rows"]`` whole (no window) -> 25
    rows inline -> RED."""
    w = _window_world(tmp_path, monkeypatch, _MAIN)
    e = _one(w)
    assert len(e["rows"]) == 20
    assert e.get("rows_total") == 25
    assert e.get("rows_next_offset") == 20


def test_the_window_never_touches_the_entrys_own_rows(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The rendered dict's ``rows`` IS the entry's own row list: the window replaces it with a new
    list. Cutting or sorting it in place would cut the rows promote and the judgement basis read,
    and break the strict pairing of rows with their views.

    MUTATION (verified RED, 1 failed): in _render write the window into the shared list
    (``out["rows"][:] = page``) -> the entry keeps 20 views of its 25 rows -> RED."""
    w = _window_world(tmp_path, monkeypatch, _MAIN)
    real = pv.build_diff_view
    seen: list[tuple[pv.BuiltDiff, dict[str, Any]]] = []

    def capture(atlas: sqlite3.Connection, diff_id: str) -> pv.BuiltDiff | None:
        built = real(atlas, diff_id)
        assert built is not None
        e = next(x for x in built.entries if x.entry_id == _WIN_ID)
        seen.append((built, json.loads(json.dumps(pv.diff_review.entry_facts(e)))))
        return built

    monkeypatch.setattr(pv, "build_diff_view", capture)
    rendered = _one(w)
    assert len(rendered["rows"]) == 20  # the window was taken
    ((built, facts_before),) = seen
    e = next(x for x in built.entries if x.entry_id == _WIN_ID)
    assert len(e.rows) == 25
    assert len(e.row_views) == 25
    assert [v["a_ref"] for v in e.row_views] == [r.a_ref for r in e.rows]  # still paired in order
    assert pv.diff_review.entry_facts(e) == facts_before
    subjects = pv.diff_review.subjects_of(built.placed, "runA", "runB", "libx")
    assert sum(1 for s in subjects.values() if s.kind == "candidate" and s.entry is e) == 25


def test_the_judgement_basis_rests_on_every_row_of_the_entry(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The basis a judgement is stored with holds all 25 rows — a number from the fixture, not
    ``rows_total`` (a cut made while building would shrink both alike) — and the snapshot equals
    the one worked out from the fixture rows alone. A build that cut the entry's rows would move
    every judgement on such an entry into needs_recheck.

    MUTATION (verified RED, 1 failed): in _Builder._place cut ``e.rows = e.rows[:20]`` before the
    row views are built -> RED; the same cut after them -> RED."""
    from treasure_map.lib.query import diff_annotations as dann

    w = _window_world(tmp_path, monkeypatch, _MAIN)
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    e = next(x for x in built.entries if x.entry_id == _WIN_ID)
    assert len(pv.diff_review.entry_facts(e)["rows"]) == 25
    rows = [_win_row(kind, i) for i, kind in enumerate(_MAIN)]
    want = {
        "diff_id": DIFF,
        "subject": "function_pair",
        "facts": {
            "alignment_state": "aligned",
            "similarity": 0.8,
            "export_gap_a": None,
            "export_gap_b": None,
            "bucket": "B",
            "rows": sorted(
                (
                    [r.a_ref, r.b_ref, r.presence, r.presence_reason, r.counterpart_call]
                    for r in rows
                ),
                key=json.dumps,
            ),
        },
    }
    assert dann.capture_diff_basis(w.atlas, DIFF, _WIN_ANCHOR) == want


# 27 rows: two did not persist, a size-constant and two size-kind rows past the 20th, the rest
# persisted plain. In fixture order the two size kinds would both fall outside the window.
_SIZED = "PUPDPPPPPPPPPPPPPPPPPUDKPKP"


def test_rows_that_did_not_persist_lead_then_the_size_signals_then_the_rest(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ More rows than the window: those that did not persist first, then the persisted rows
    carrying a size signal (both kinds), then the rest — each group in its own order — so a size
    signal past the 20th row is not left out behind plain persisted rows.

    MUTATION (verified RED, 1 failed each): take the first 20 rows as they come (no grouping) ->
    RED; two groups only (size rows sorted with the rest) -> RED; reverse each group's order ->
    RED."""
    w = _window_world(tmp_path, monkeypatch, _SIZED)
    e = _one(w)
    got = [_win_index(v) for v in e["rows"]]
    assert got == _grouped(_SIZED)[:20]
    kinds = {_SIZED[i] for i in got}
    assert {"U", "D", "K"} <= kinds  # both size kinds made it into the window
    assert e.get("rows_order") == "presence_not_persisted_then_size_signal_then_rest"


# An A entry: 21 rows that did not persist, then one persisted size-kind row, then plain ones.
_A_HEAVY = "A" * 21 + "KPP"


def test_a_size_signal_past_a_full_window_is_counted_not_hidden(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ When the rows that did not persist fill the window, a size-signal row falls outside it.
    The entry's significance speaks for the entry (bucket A here), never for its rows: what lies
    outside the window is told by ``rows_by_order_group``, and paged with ``rows_offset``.

    MUTATION (verified RED, 1 failed each): order the size-signal group ahead of the rows that did
    not persist -> RED; drop ``rows_by_order_group`` -> RED."""
    w = _window_world(tmp_path, monkeypatch, _A_HEAVY)
    e = _one(w, sort_by="significance")
    assert e["bucket"] == "A"
    assert e["significance"] == {"attention": 0, "basis": "matched_call_other_callee"}
    assert {_A_HEAVY[_win_index(v)] for v in e["rows"]} == {"A"}
    assert e.get("rows_by_order_group") == {"not_persisted": 21, "size_signal": 1, "rest": 2}
    rest = _one(w, entry_id=_WIN_ID, rows_offset=20)
    assert [_A_HEAVY[_win_index(v)] for v in rest["rows"]] == ["A", "K", "P", "P"]


def test_the_counts_are_over_every_row_and_name_every_group(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The presence and group counts are over all 25 rows, not the 20 shown; a group with no row
    is written as 0, so "no such row" is never confused with "not counted".

    MUTATION (verified RED, 1 failed each): count the window's rows only -> RED; leave out a group
    with no row (as ``_count`` does) -> RED (``size_signal`` is 0 here)."""
    w = _window_world(tmp_path, monkeypatch, _MAIN)
    e = _one(w)
    assert e.get("rows_by_presence") == {"persisted": 22, "presence_undetermined": 3}
    assert e.get("rows_by_order_group") == {"not_persisted": 3, "size_signal": 0, "rest": 22}


def test_an_entry_within_the_window_keeps_its_rows_as_they_are(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Up to 20 rows come back whole, in their own order — here a persisted row before one that
    did not persist — with no ordering or group fields.

    MUTATION (verified RED, 1 failed): group the rows of every entry, however few -> RED."""
    layout = "PUPU"
    w = _window_world(tmp_path, monkeypatch, layout)
    e = _one(w)
    assert [_win_index(v) for v in e["rows"]] == [0, 1, 2, 3]
    assert e.get("rows_total") == 4
    assert e["rows_next_offset"] is None
    assert not {"rows_order", "rows_by_presence", "rows_by_order_group"} & set(e)


@pytest.mark.parametrize("rows_limit", [pv.ROWS_INLINE_LIMIT, 6])
def test_paging_one_entrys_rows_returns_each_row_once_in_the_window_order(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch, rows_limit: int
) -> None:
    """★ entry_id + rows_offset, followed until null, return every row exactly once, in the window
    order worked out from the fixture.

    MUTATION (verified RED, 2 failed): set ``rows_next_offset`` one short (``end - 1``) -> a row
    comes back twice -> RED."""
    w = _window_world(tmp_path, monkeypatch, _SIZED)
    got: list[int] = []
    at: int | None = 0
    pages = 0
    while at is not None:
        e = _one(w, entry_id=_WIN_ID, rows_offset=at, rows_limit=rows_limit)
        assert e["rows_offset"] == at
        got += [_win_index(v) for v in e["rows"]]
        at = e["rows_next_offset"]
        pages += 1
        assert pages <= len(_SIZED)  # a window that never moves on is a failure, not a hang
    assert got == _grouped(_SIZED)


def test_a_row_outside_the_window_can_still_be_promoted(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Promote reads the entry's own rows, all of them: a persisted row past the window carries a
    judgement like any other."""
    w = _window_world(tmp_path, monkeypatch, _MAIN)
    ref = _win_refs(24)[0]
    assert ref not in {v["a_ref"] for v in _one(w)["rows"]}  # really outside the window
    res = overlay.promote(
        w.atlas,
        diff_id=DIFF,
        entry_id=_WIN_ID,
        row_ref=ref,
        verdict="suspicious",
        rationale="carried over from the diff",
    )
    assert res.written.action == "inserted"
    assert res.promoted_from is not None
    assert res.promoted_from["landing"] == "persisted"


@pytest.mark.parametrize(
    ("kw", "message"),
    [
        ({"entry_id": "runA::runB#candidate#callsite|copy|x|y"}, "not a candidate anchor"),
        ({"entry_id": _IDENTICAL_ID}, "placed but not listed"),
        (
            {"entry_id": "runA::runB#function_pair#libx::00003000::00004000"},
            "placed but not listed",
        ),
        ({"entry_id": "pair:0000dead:0000beef"}, "is not an entry get_diff_patch_view lists"),
        (
            {"entry_id": f"runX::runB#function_pair#libx::{_WIN_A}::{_WIN_B}"},
            "is not an anchor of this diff's run pair",
        ),
        ({"entry_id": f"runA::runB#function_pair#liby::{_WIN_A}::{_WIN_B}"}, "names binary"),
        ({"entry_id": _WIN_ID, "view": "string_edge"}, "entry_id apply to view='sink_patch'"),
        (
            {"entry_id": _WIN_ID, "not_listed_page": "aligned_pseudocode_differs"},
            "does not apply to not_listed_page",
        ),
        ({"entry_id": _WIN_ID, "bucket": "B"}, r"takes no filter \(got bucket\)"),
        ({"entry_id": _WIN_ID, "subclass": "x"}, r"takes no filter \(got subclass\)"),
        ({"entry_id": _WIN_ID, "tier": 1}, r"takes no filter \(got tier\)"),
        ({"entry_id": _WIN_ID, "blind_spot": "x"}, r"takes no filter \(got blind_spot\)"),
        ({"entry_id": _WIN_ID, "body": "unknown"}, r"takes no filter \(got body\)"),
        (
            {"entry_id": _WIN_ID, "anchored_differs": True},
            r"takes no filter \(got anchored_differs\)",
        ),
        (
            {"entry_id": _WIN_ID, "anchored_micro_side": True},
            r"takes no filter \(got anchored_micro_side\)",
        ),
        ({"entry_id": _WIN_ID, "offset": 1}, "with rows_offset, not offset"),
        ({"rows_offset": 0}, "pass that entry's entry_id"),
        ({"entry_id": _WIN_ID, "rows_offset": 25}, "past the entry's last row"),
        ({"entry_id": _WIN_ID, "rows_offset": True}, "rows_offset must be an integer"),
        ({"entry_id": _WIN_ID, "rows_offset": -1}, "rows_offset must be an integer"),
        ({"rows_limit": -1}, "rows_limit must be an integer"),
        ({"rows_limit": True}, "rows_limit must be an integer"),
        ({"entry_id": _WIN_ID, "rows_limit": 0}, r"rows_limit must be >= 1 there"),
        ({"entry_id": 7}, "entry_id must be"),
    ],
)
def test_reading_one_entry_refuses_what_it_cannot_honour(
    tmp_path: Path,
    current: None,
    monkeypatch: pytest.MonkeyPatch,
    kw: dict[str, Any],
    message: str,
) -> None:
    """Every combination reading one entry cannot honour is an error naming why — never ignored.
    ``rows_limit=0`` is refused only with ``entry_id`` (reading one entry's rows, it would read
    none); as a scan it is allowed (test_a_zero_row_scan_...).

    MUTATION (verified RED): drop the "rows_offset needs entry_id" check -> 1 failed; drop the
    filter check -> 7 failed; drop ``rows_limit >= 0`` -> 1 failed; accept rows_limit=0 with
    entry_id -> 1 failed; accept an offset beside entry_id -> 1 failed."""
    w = _window_world(tmp_path, monkeypatch, _MAIN)
    out = pv.get_diff_patch_view(w.atlas, DIFF, **kw)
    assert re.search(message, out.get("error") or ""), out
    assert "entries" not in out
    if "past the entry's last row" in message:
        assert out.get("rows_total") == 25


def test_a_withheld_diff_has_no_entry_to_read(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    w = _window_world(tmp_path, monkeypatch, _MAIN)
    w.atlas.execute("UPDATE diff_meta SET diff_ok = 0")
    w.commit()
    out = pv.get_diff_patch_view(w.atlas, DIFF, entry_id=_WIN_ID)
    assert "undetermined (banners)" in (out.get("error") or ""), out
    assert "diff_undetermined:diff_failed" in (out.get("banners") or [])


def test_reading_one_entry_by_either_name_keeps_the_whole_diffs_envelope(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """entry_id takes the entry's entry_id or its anchor_ref, returns that one entry, and leaves
    the envelope describing the whole diff; an entry with no row pages from 0, and a limit is
    still honoured.

    MUTATION (verified RED, 1 failed): resolve by entry_id only -> RED."""
    w = _window_world(tmp_path, monkeypatch, _MAIN)
    whole = pv.get_diff_patch_view(w.atlas, DIFF)
    for name in (_WIN_ID, _WIN_ANCHOR):
        out = pv.get_diff_patch_view(w.atlas, DIFF, entry_id=name, limit=5)
        assert "error" not in out, out
        assert [e["entry_id"] for e in out["entries"]] == [_WIN_ID]
        assert (out["total_entries"], out["next_offset"]) == (1, None)
        assert out["counts"] == whole["counts"]
        assert out["not_listed"] == whole["not_listed"]
        assert out["lens"]["filters"]["entry_id"] == name
        assert out["review_progress"]["scope"]["entry_id"] == name
    empty = pv.get_diff_patch_view(w.atlas, DIFF, entry_id=_NO_ROW_ID, rows_offset=0)
    assert "error" not in empty, empty
    (e,) = empty["entries"]
    assert (e["rows"], e["rows_total"], e["rows_next_offset"]) == ([], 0, None)


def test_one_entry_is_named_the_way_promote_names_it(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The view and promote each resolve an entry name (the view cannot import promote's side,
    which imports the view): for every kind of name, both find the same entry or both refuse.

    MUTATION (verified RED, 1 failed): resolve anchor_refs differently in the view (drop the
    anchor lookup) -> the two disagree -> RED."""
    from treasure_map.lib.errors import ConfigError
    from treasure_map.lib.query import diff_annotations as dann

    w = _window_world(tmp_path, monkeypatch, _MAIN)
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    meta = dann._binary_diff(w.atlas, DIFF)
    a_ref, b_ref = _win_refs(1)
    names = {
        _WIN_ID: _WIN_ID,
        _WIN_ANCHOR: _WIN_ID,
        _NO_ROW_ID: _NO_ROW_ID,
        f"runA::runB#candidate#callsite|copy|{a_ref}|{b_ref}": None,
        f"runX::runB#function_pair#libx::{_WIN_A}::{_WIN_B}": None,
        f"runA::runB#function_pair#liby::{_WIN_A}::{_WIN_B}": None,
        "pair:0000dead:0000beef": None,
        _IDENTICAL_ID: None,
        "runA::runB#function_pair#libx::00003000::00004000": None,
    }
    for name, want in names.items():
        found = pv._resolve_entry(built, name)
        view_says = None if isinstance(found, str) else found.entry_id
        try:
            promote_says: str | None = dann._entry(built, meta, name).entry_id
        except ConfigError:
            promote_says = None
        assert (view_says, promote_says) == (want, want), name


def test_the_mcp_tool_pages_one_entrys_rows(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """entry_id and rows_offset reach the view through the MCP tool.

    MUTATION (verified RED, 1 failed): drop rows_offset from the tool's call into the view -> the
    first window comes back again -> RED."""
    w = _window_world(tmp_path, monkeypatch, _SIZED)
    tool = mcp_app.make_tools(w.path)["get_diff_patch_view"]
    out = tool(DIFF, entry_id=_WIN_ANCHOR, rows_offset=20)
    assert "error" not in out, out
    (e,) = out["entries"]
    assert [_win_index(v) for v in e["rows"]] == _grouped(_SIZED)[20:]
    assert f"at most {pv.ROWS_INLINE_LIMIT} of its candidate" in (tool.__doc__ or "")


# ── a sink name in the callee-set difference (sink_callee_swap) ──────────────────────────────

_SWAP_IDS = {
    "c_narrow": ("00101000", "00102000"),
    "c_wide": ("00103000", "00104000"),
    "c_delete": ("00105000", "00106000"),
    "c_add": ("00107000", "00108000"),
    "c_nonsink": ("00109000", "0010a000"),
    "c_tosink": ("0010b000", "0010c000"),
    "c_partial": ("0010d000", "0010e000"),
    "c_trunc": ("0010f000", "00110000"),
    "c_noinv": ("00111000", "00112000"),
    "c_pairkey": ("00113000", "00114000"),
    "c_samekeys": ("00115000", "00116000"),
    "c_equal": ("00117000", "00118000"),
    "c_micro": ("00119000", "0011a000"),
    "r_proposed": ("0011b000", "0011c000"),
    "r_head_swap": ("0011d000", "0011d000"),
    "r_head": ("0011e000", "0011e000"),
    "r_plain": ("0011f000", "00120000"),
    "a_swap": ("00121000", "00122000"),
    "b_delta": ("00123000", "00124000"),
    "b_novis": ("00125000", "00126000"),
}
_NOT_A_PAIR = "0009f000"  # a FUN_ callee with no aligned pair: cannot be identified


def _swap_world(tmp_path: Path) -> tuple[World, dict[str, str]]:
    """One entry per shape of callee-set difference the swap reads (the names in ``_SWAP_IDS``).
    Every pair's bodies are its own text; the bucket C pairs have no candidate."""
    w = World(tmp_path)
    a, b = "runA", "runB"
    ids = {k: _pair_id(*v) for k, v in _SWAP_IDS.items()}

    def c_pair(key: str, ca: list[str], cb: list[str] | None, **kw_a: Any) -> None:
        fa, fb = _SWAP_IDS[key]
        n = int(fa, 16) // 0x1000
        w.pair(fa, fb, 0.97, 0.6)
        w.fn("a", fa, ca, pseudocode=f"x = f({n});", size_bytes=64, **kw_a)
        if cb is not None:
            w.fn("b", fb, cb, pseudocode=f"x = f({n}) + 1;", size_bytes=64)

    c_pair("c_narrow", ["memcpy"], ["strcpy"])
    c_pair("c_wide", ["strcpy", "log_a", "log_b"], [])
    c_pair("c_delete", ["system", "foo"], ["foo"])
    c_pair("c_add", ["foo"], ["foo", "popen"])
    c_pair("c_nonsink", ["strlcpy"], ["strdup"])
    c_pair("c_tosink", ["strlcpy"], ["strcpy"])
    c_pair("c_partial", [f"FUN_{_NOT_A_PAIR}", "memcpy"], ["strcpy"])
    c_pair("c_trunc", ["strcpy"], ["memcpy"], truncated=1)
    c_pair("c_noinv", ["strcpy"], None)
    # The named callees are equal on both sides; only an identified FUN_ (its aligned pair is
    # 00127000/00128000) differs.
    c_pair("c_pairkey", ["FUN_00127000", f"FUN_{_NOT_A_PAIR}", "foo"], ["foo"])
    w.pair("00127000", "00128000", 0.97, 1.0)
    c_pair("c_samekeys", [f"FUN_{_NOT_A_PAIR}", "foo"], ["foo"])
    c_pair("c_equal", ["memset"], ["memset"])
    # One side a design-skipped micro-stub (8 bytes, no text), the other a real body.
    fa, fb = _SWAP_IDS["c_micro"]
    w.pair(fa, fb, 0.97, 0.6)
    w.fn("a", fa, ["memcpy"], pseudocode="x = memcpy(d,s,n);", size_bytes=200)
    w.fn("b", fb, ["strcpy"], pseudocode=None, size_bytes=8)
    # Undetermined pairs: one at two addresses (not anchored) whose callees swap a sink, one
    # anchored at one address whose callees swap a sink, one anchored with no swap, one plain.
    fa, fb = _SWAP_IDS["r_proposed"]
    w.pair(fa, fb, 0.5, 0.5)
    w.fn("a", fa, ["memcpy"], pseudocode="x = g(1);", size_bytes=16)
    w.fn("b", fb, ["strcpy"], pseudocode="x = g(1) + 7;", size_bytes=16)
    fa, fb = _SWAP_IDS["r_head_swap"]
    w.pair(fa, fb, 0.5, 0.9)
    w.fn("a", fa, ["memcpy"], pseudocode="x = g(2);", size_bytes=16)
    w.fn("b", fb, ["strcpy"], pseudocode="x = g(2) + 7;", size_bytes=16)
    _ud(w, *_SWAP_IDS["r_head"], 0.9)
    _ud(w, *_SWAP_IDS["r_plain"], 0.3)
    # A: the matched call now calls another callee; the callee lists swap one sink for another.
    fa, fb = _SWAP_IDS["a_swap"]
    w.pair(fa, fb, 0.97, 0.9)
    w.inst("a", _ref(a, fa, "cmd", "0x10"), "cmd", "system")
    w.inst("b", _ref(b, fb, "cmd", "0x10"), "cmd", "popen")
    w.im(f"{int(fa, 16) + 0x10:08x}", f"{int(fb, 16) + 0x10:08x}", fa)
    w.fn("a", fa, ["system"], pseudocode="system(c);")
    w.fn("b", fb, ["popen"], pseudocode="popen(c);")
    # B: a persisted copy whose length constant moved, and a sink one side adds.
    fa, fb = _SWAP_IDS["b_delta"]
    w.pair(fa, fb, 0.97, 1.0)
    w.inst("a", _ref(a, fa, "copy", "0x10"), "copy", "snprintf", _size("cap_const", "0x200"))
    w.inst("b", _ref(b, fb, "copy", "0x10"), "copy", "snprintf", _size("cap_const", "0x400"))
    w.im(f"{int(fa, 16) + 0x10:08x}", f"{int(fb, 16) + 0x10:08x}", fa)
    w.fn("a", fa, ["snprintf"], pseudocode="snprintf(d,0x200,f);")
    w.fn("b", fb, ["snprintf", "strcpy"], pseudocode="snprintf(d,0x400,f); strcpy(d,s);")
    # B: a changed pair whose candidate lines up, and a sink one side adds.
    fa, fb = _SWAP_IDS["b_novis"]
    w.pair(fa, fb, 0.97, 0.7)
    w.inst("a", _ref(a, fa, "cmd", "0x10"), "cmd", "system")
    w.inst("b", _ref(b, fb, "cmd", "0x10"), "cmd", "system")
    w.im(f"{int(fa, 16) + 0x10:08x}", f"{int(fb, 16) + 0x10:08x}", fa)
    w.fn("a", fa, ["system"], pseudocode="system(c);")
    w.fn("b", fb, ["system", "popen"], pseudocode="system(c); popen(c);")
    w.commit()
    return w, ids


def _swap_view(w: World, **kw: Any) -> dict[str, Any]:
    v = _view(w, **kw)
    for eid in v["by_id"].values():
        assert "error" not in eid
    return v


def _swap(v: dict[str, Any], ids: dict[str, str], key: str) -> dict[str, Any] | None:
    assert ids[key] in v["by_id"], key
    swap = v["by_id"][ids[key]].get("sink_callee_swap")
    return dict(swap) if swap is not None else None


def test_a_sink_swapped_in_an_aligned_pairs_callees_is_named(tmp_path: Path, current: None) -> None:
    """★ The callee lists of an aligned pair differ by one copy sink each way: the field names both
    sinks, on the aligned pairing, read in full, narrow.

    MUTATION (verified RED, 1 failed): leave COPY out of SINK_CALLEE_NAMES -> no field -> RED."""
    w, ids = _swap_world(tmp_path)
    v = _swap_view(w)
    assert _swap(v, ids, "c_narrow") == {
        "pairing": "aligned",
        "callees_complete": True,
        "sinks_only_in_a": ["memcpy"],
        "sinks_only_in_b": ["strcpy"],
        "names_only_in_a": 1,
        "names_only_in_b": 1,
        "narrow": True,
        "not_narrow": None,
    }


def test_an_undetermined_pair_reads_the_difference_its_proposed_reading_compares(
    tmp_path: Path, current: None
) -> None:
    """An undetermined pair has no callee_set of its own; the swap reads the one its proposed
    reading compares, and says so.

    MUTATION (verified RED, 1 failed): read ``callee_set`` only -> no field -> RED."""
    w, ids = _swap_world(tmp_path)
    v = _swap_view(w)
    assert v["by_id"][ids["r_proposed"]]["callee_set"] is None
    swap = _swap(v, ids, "r_proposed")
    assert swap is not None
    assert (swap["pairing"], swap["narrow"]) == ("proposed", True)
    assert v["by_id"][ids["r_proposed"]]["proposed_pair_reading"]["callee_set"]["state"] == (
        "differs"
    )


def test_an_aligned_pair_in_bucket_r_reads_its_own_callee_set(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An aligned pair lands in R when one of its rows does: it is still an aligned pair, so its
    own callee_set is read (pairing aligned), not a proposed one it does not have.

    MUTATION (verified RED, 1 failed): pick the difference by bucket R instead of by alignment ->
    no field -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 0.8)
    w.fn("a", "00001000", ["memcpy"])
    w.fn("b", "00002000", ["strcpy"])
    w.commit()
    row = replace(_win_row("U", 0), presence_reason="callsite_not_exported", match_basis=None)

    def rows_of(atlas: sqlite3.Connection, diff_id: str) -> so.SinkOverlayResult:
        return so.SinkOverlayResult([row], so.SinkOverlayCoverage(0, 0, 0, 0, 0, False))

    monkeypatch.setattr(pv, "compute_sink_overlay", rows_of)
    e = _view(w)["by_id"][_pair_id("00001000", "00002000")]
    assert (e["bucket"], e["alignment_state"]) == ("R", "aligned")
    assert (e.get("sink_callee_swap") or {}).get("pairing") == "aligned"


def test_a_sink_only_one_side_calls_is_narrow(tmp_path: Path, current: None) -> None:
    """One side dropping a sink, or adding one, with nothing in its place is narrow too.

    MUTATION (verified RED, 1 failed): require names on both sides for narrow -> RED."""
    w, ids = _swap_world(tmp_path)
    v = _swap_view(w)
    gone, added = _swap(v, ids, "c_delete"), _swap(v, ids, "c_add")
    assert gone is not None and added is not None
    assert (gone["sinks_only_in_a"], gone["names_only_in_b"], gone["narrow"]) == (
        ["system"],
        0,
        True,
    )
    assert (added["sinks_only_in_b"], added["names_only_in_a"], added["narrow"]) == (
        ["popen"],
        0,
        True,
    )


def test_more_than_two_names_on_a_side_is_not_narrow_and_still_sinks(
    tmp_path: Path, current: None
) -> None:
    """Three names on a side: the field stays, not narrow, and a bucket C entry still sinks.

    MUTATION (verified RED, 1 failed): allow three names -> RED."""
    w, ids = _swap_world(tmp_path)
    swap = _swap(_swap_view(w), ids, "c_wide")
    assert swap is not None
    assert (swap["names_only_in_a"], swap["narrow"], swap["not_narrow"]) == (
        3,
        False,
        "names_exceed_two",
    )
    e = _swap_view(w, sort_by="significance")["by_id"][ids["c_wide"]]
    assert e["significance"] == {"attention": 2, "basis": "no_sink_candidate"}


def test_a_difference_read_in_part_is_never_narrow(tmp_path: Path, current: None) -> None:
    """With a callee that cannot be identified, only the identified part of the difference is read:
    the swap says so (callees_complete false) and is not narrow; the set stays undetermined.

    MUTATION (verified RED, 1 failed): treat the identified part as read in full -> RED."""
    w, ids = _swap_world(tmp_path)
    v = _swap_view(w)
    cs = v["by_id"][ids["c_partial"]]["callee_set"]
    assert (cs["state"], cs["reason"]) == ("undetermined", "callee_identity_unresolved")
    swap = _swap(v, ids, "c_partial")
    assert swap is not None
    assert (swap["callees_complete"], swap["narrow"], swap["not_narrow"]) == (
        False,
        False,
        "callee_identity_unresolved",
    )
    assert (swap["sinks_only_in_a"], swap["sinks_only_in_b"]) == (["memcpy"], ["strcpy"])


def test_a_set_that_could_not_be_read_carries_no_swap(tmp_path: Path, current: None) -> None:
    """A truncated list, or a function not in the inventory, gives no difference at all: no field
    — which is not "no sink changed".

    MUTATION (verified RED, 1 failed): give the truncated case its raw names as a partial
    difference -> a field appears -> RED."""
    w, ids = _swap_world(tmp_path)
    v = _swap_view(w)
    assert v["by_id"][ids["c_trunc"]]["callee_set"]["reason"] == "callees_truncated"
    assert v["by_id"][ids["c_noinv"]]["callee_set"]["reason"] == "not_in_inventory"
    assert _swap(v, ids, "c_trunc") is None
    assert _swap(v, ids, "c_noinv") is None


def test_the_identified_difference_includes_fun_names_through_their_pair(
    tmp_path: Path, current: None
) -> None:
    """★ Partly undetermined sets now give every identified callee that differs: a FUN_<addr>
    identified through its aligned pair counts, as the differs reading counts it. Here the named
    callees are equal on both sides and only that FUN_ differs — a named-only comparison sees no
    difference. Where the identified callees are equal there is none. A FUN_ name is never a sink.

    MUTATION (verified RED, 1 failed): compare the named callees only -> RED."""
    w, ids = _swap_world(tmp_path)
    v = _swap_view(w)
    pk = v["by_id"][ids["c_pairkey"]]["callee_set"]
    assert pk["state"] == "undetermined"
    assert pk.get("named_callees_differ") == {"only_in_a": ["FUN_00127000"], "only_in_b": []}
    assert _swap(v, ids, "c_pairkey") is None
    same = v["by_id"][ids["c_samekeys"]]["callee_set"]
    assert same["state"] == "undetermined" and "named_callees_differ" not in same


def test_the_wider_identified_difference_moves_no_judgement_basis(
    tmp_path: Path, current: None
) -> None:
    """★ The identified difference is a read-face field. The basis a judgement rests on, the bucket
    and the state of the set are what they were; an equal set still says callee_set_unchanged.

    MUTATION (verified RED, 1 failed each): fold the callee_set into entry_facts -> RED; let the
    identified difference decide the state (undetermined -> differs) -> RED."""
    w, ids = _swap_world(tmp_path)
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    by_id = {e.entry_id: e for e in built.entries}
    assert ids["c_pairkey"] in by_id
    e = by_id[ids["c_pairkey"]]
    assert pv.diff_review.entry_facts(e) == {
        "alignment_state": "aligned",
        "similarity": 0.6,
        "export_gap_a": None,
        "export_gap_b": None,
        "bucket": "C",
        "rows": [],
    }
    assert (e.bucket, e.subclass) == ("C", "no_sink_candidate")
    assert e.callee_set is not None and e.callee_set["state"] == "undetermined"
    assert "callee_set_unchanged" in by_id[ids["c_equal"]].facts


def test_only_the_hunts_sink_names_count(tmp_path: Path, current: None) -> None:
    """strlcpy -> strdup changes no sink the hunt names; strlcpy -> strcpy does.

    MUTATION (verified RED, 1 failed): add strlcpy to SINK_CALLEE_NAMES -> RED."""
    w, ids = _swap_world(tmp_path)
    v = _swap_view(w)
    assert _swap(v, ids, "c_nonsink") is None
    swap = _swap(v, ids, "c_tosink")
    assert swap is not None
    assert (swap["sinks_only_in_a"], swap["sinks_only_in_b"]) == ([], ["strcpy"])


def test_a_bucket_c_entry_with_a_narrow_swap_is_not_sunk(tmp_path: Path, current: None) -> None:
    """★ Under the lens a bucket C entry with a narrow swap stays at attention 1, basis
    sink_callee_swap_never_sunk; a wide one still sinks.

    MUTATION (verified RED, 1 failed each): hold every swap, narrow or not -> RED; drop the swap
    branch -> RED."""
    w, ids = _swap_world(tmp_path)
    v = _swap_view(w, sort_by="significance")
    assert v["by_id"][ids["c_narrow"]]["significance"] == {
        "attention": 1,
        "basis": "sink_callee_swap_never_sunk",
    }
    assert v["by_id"][ids["c_wide"]]["significance"]["attention"] == 2


def test_an_earlier_basis_of_a_bucket_c_entry_is_kept(tmp_path: Path, current: None) -> None:
    """A bucket C entry whose one side is a design-skipped micro-stub keeps that basis, though its
    callees swap a sink (the swap still orders it).

    MUTATION (verified RED, 1 failed): test the swap before the micro-stub branch -> RED."""
    w, ids = _swap_world(tmp_path)
    e = _swap_view(w, sort_by="significance")["by_id"][ids["c_micro"]]
    assert "one_side_skipped_micro" in e["facts"]
    assert e["bucket"] == "C"
    assert e["significance"] == {"attention": 1, "basis": "one_side_skipped_micro"}
    assert e["rank_key"]["sink_callee_swap"] == 1


def _judge_entry(w: World, entry: dict[str, Any], verdict: str) -> None:
    w.judge(DIFF, entry["anchor_ref"], verdict)
    w.commit()


def test_a_held_up_judgement_keeps_its_basis_over_the_swap(tmp_path: Path, current: None) -> None:
    """★ A bucket C entry with a narrow swap and a changed_real judgement reads judged_never_sunk:
    the swap never replaces a judgement's basis.

    MUTATION (verified RED, 1 failed): test the swap before the held-up judgement -> RED."""
    w, ids = _swap_world(tmp_path)
    e = _swap_view(w, sort_by="significance")["by_id"][ids["c_narrow"]]
    _judge_entry(w, e, "changed_real")
    e = _swap_view(w, sort_by="significance")["by_id"][ids["c_narrow"]]
    assert e["review_state"] == "concluded"
    assert e["significance"] == {"attention": 1, "basis": "judged_never_sunk"}


def test_a_judgement_moves_no_entry_inside_its_tier(tmp_path: Path, current: None) -> None:
    """★ Judgements move nothing unless band is on: the bucket C entry with a narrow swap keeps its
    place when a held-up judgement changes its basis, and an entry whose basis is a micro-stub is
    lifted like any other.

    MUTATION (verified RED, 1 failed): leave the judged_never_sunk / one_side_skipped_micro bases
    out of the lift -> the judged entry drops behind the read-first pairs -> RED."""
    w, ids = _swap_world(tmp_path)
    before = _swap_view(w, sort_by="significance")
    order_before = [e["entry_id"] for e in before["entries"]]
    e = before["by_id"][ids["c_narrow"]]
    assert e["rank_key"]["sink_callee_swap"] == 1
    _judge_entry(w, e, "changed_real")
    after = _swap_view(w, sort_by="significance")
    judged = after["by_id"][ids["c_narrow"]]
    assert judged["significance"]["basis"] == "judged_never_sunk"
    assert judged["rank_key"]["sink_callee_swap"] == 1
    assert [x["entry_id"] for x in after["entries"]] == order_before
    assert after["by_id"][ids["c_micro"]]["rank_key"]["sink_callee_swap"] == 1


def test_a_narrow_swap_leads_attention_one_ahead_of_the_read_first_pairs(
    tmp_path: Path, current: None
) -> None:
    """★ Inside attention 1: the entries with a narrow swap, then the read-first anchored_differs
    pairs, then the rest.

    MUTATION (verified RED, 1 failed): order by read_first before the swap -> RED."""
    w, ids = _swap_world(tmp_path)
    v = _swap_view(w, sort_by="significance")
    tier = [e for e in v["entries"] if e["significance"]["attention"] == 1]
    lifted = [e["rank_key"]["sink_callee_swap"] for e in tier]
    assert lifted == sorted(lifted, reverse=True) and 1 in lifted and 0 in lifted
    pos = {e["entry_id"]: i for i, e in enumerate(tier)}
    assert pos[ids["r_proposed"]] < pos[ids["r_head"]] < pos[ids["r_plain"]]


def test_a_read_first_pair_with_a_swap_stays_read_first(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A read-first anchored_differs pair whose callees swap a sink is still read first, and the
    read-first counts are those of the same world with no swap read at all.

    MUTATION (verified RED, 1 failed): fold the swap into _read_first_order (order 3) -> RED."""
    w, ids = _swap_world(tmp_path)
    v = _swap_view(w, sort_by="significance")
    reading = _reading(v, ids["r_head_swap"])
    assert (reading.get("anchored_differs"), reading.get("in_read_first")) == (True, True)
    assert v["by_id"][ids["r_head_swap"]]["rank_key"]["sink_callee_swap"] == 1
    states = pv.function_states(w.atlas, DIFF)
    pv._clear_view_caches()
    monkeypatch.setattr(pv, "_sink_callee_swap", lambda e: None)
    assert pv.function_states(w.atlas, DIFF) == states
    assert _reading(_swap_view(w, sort_by="significance"), ids["r_head_swap"]) == reading


def test_attention_zero_is_not_reordered_by_a_swap(tmp_path: Path, current: None) -> None:
    """A bucket A entry with a narrow swap stays at attention 0 with its own basis, unlifted.

    MUTATION (verified RED, 1 failed): lift every narrow swap whatever its attention -> RED."""
    w, ids = _swap_world(tmp_path)
    v = _swap_view(w, sort_by="significance")
    e = v["by_id"][ids["a_swap"]]
    assert (e.get("sink_callee_swap") or {}).get("narrow") is True
    assert e["significance"] == {"attention": 0, "basis": "matched_call_other_callee"}
    assert e["rank_key"]["sink_callee_swap"] == 0


def test_a_swap_never_replaces_a_b_entrys_basis(tmp_path: Path, current: None) -> None:
    """A B entry keeps its basis: a changed length constant stays at attention 0, a pair whose
    candidates line up stays recheckable_no_visible_delta — lifted inside attention 1.

    MUTATION (verified RED, 1 failed): let a narrow swap decide the basis ahead of the others ->
    RED."""
    w, ids = _swap_world(tmp_path)
    v = _swap_view(w, sort_by="significance")
    delta, novis = v["by_id"][ids["b_delta"]], v["by_id"][ids["b_novis"]]
    assert (delta.get("sink_callee_swap") or {}).get("narrow") is True
    assert (novis.get("sink_callee_swap") or {}).get("narrow") is True
    assert delta["significance"] == {"attention": 0, "basis": "sink_arg_constant_delta"}
    assert novis["significance"] == {"attention": 1, "basis": "recheckable_no_visible_delta"}
    assert novis["rank_key"]["sink_callee_swap"] == 1


@pytest.mark.parametrize(
    "sort_by", [None, "candidate_tier", "tier", "similarity", "address", "significance"]
)
def test_the_field_is_on_every_sort_and_moves_only_the_lens(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch, sort_by: str | None
) -> None:
    """The field is there in every sort; outside the lens (significance, which no sort_by also
    reads in) the order is the one with no swap read.

    MUTATION (verified RED, 4 failed): lift narrow swaps in every sort -> RED; emit the field only
    under the lens -> RED."""
    w, ids = _swap_world(tmp_path)
    v = _swap_view(w, sort_by=sort_by)
    assert _swap(v, ids, "c_narrow") is not None
    if sort_by in (None, "significance"):
        return
    order = [e["entry_id"] for e in v["entries"]]
    monkeypatch.setattr(pv, "_sink_callee_swap", lambda e: None)
    assert [e["entry_id"] for e in _swap_view(w, sort_by=sort_by)["entries"]] == order


def test_a_swap_is_not_in_what_a_judgement_rests_on(tmp_path: Path, current: None) -> None:
    """A judged entry with a swap reads its judgement as it was written, and what it rests on is
    what an entry of the same shape with no swap rests on.

    MUTATION (verified RED, 1 failed): add the swap to entry_facts -> RED."""
    w, ids = _swap_world(tmp_path)
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    by_id = {e.entry_id: e for e in built.entries}
    hit, plain = by_id[ids["c_narrow"]], by_id[ids["c_equal"]]
    assert pv.diff_review.entry_facts(hit) == pv.diff_review.entry_facts(plain)
    e = _swap_view(w)["by_id"][ids["c_narrow"]]
    _judge_entry(w, e, "change_inconclusive")
    assert _swap_view(w)["by_id"][ids["c_narrow"]]["review_state"] == "inconclusive"


def test_the_sink_names_are_the_sink_classes_and_the_unrecalled_sinks() -> None:
    """MUTATION (verified RED, 1 failed): union the RECALL_GAP_SINKS dict itself (its family keys)
    instead of its names -> RED."""
    from treasure_map.lib.pattern import classes as cl

    want = (cl.FORMAT | cl.CMD | cl.COPY | cl.FMT_STRING | cl.PATH_SINK).union(
        *pv.RECALL_GAP_SINKS.values()
    )
    assert want == pv.SINK_CALLEE_NAMES
    assert not {"strlcpy", "strlcat", "strdup"} & pv.SINK_CALLEE_NAMES
    assert {"wcscpy", "wcscat", "vswprintf", "_eval", "execvpe"} <= pv.SINK_CALLEE_NAMES
    assert not set(pv.RECALL_GAP_SINKS) & pv.SINK_CALLEE_NAMES


def test_the_lens_and_the_tool_name_the_swap() -> None:
    assert "sink_callee_swap" in pv._CAVEATS
    tool = mcp_app.make_tools(Path("unused.db"))["get_diff_patch_view"]
    assert "sink_callee_swap_never_sunk" in (tool.__doc__ or "")
    assert "sink_callee_swap" in (tool.__doc__ or "")
    assert "named_callees_differ" in (tool.__doc__ or "")


# ── S3: the caller-set edge (callers_a / callers_b) and bucket E ───────────────────────────────


def _built_entry(w: World, entry_id: str) -> pv._Entry:
    """The listed _Entry object (for reading entry_facts / rank), by its entry_id."""
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    for e in built.entries:
        if e.entry_id == entry_id:
            return e
    raise AssertionError(f"{entry_id} is not listed")


def test_a_caller_set_edge_lists_and_holds_a_similarity_1_pair(
    tmp_path: Path, current: None
) -> None:
    """★ S3: a similarity-1 aligned pair that would place no entry is listed as bucket E when its
    A-side function has a direct caller and its B-side counterpart has none found; the edge holds it
    at attention 1, never sunk, basis lost_every_direct_caller_never_sunk.

    MUTATION: do not place E (leave the pair not_listed) -> RED; sink E at attention 2 -> RED; read
    the B side's callers from the A index -> callers_b non-empty, no E -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 1.0)
    w.fn("a", "00001000", ["helper"], name="target_x", pseudocode="return helper();")
    w.fn("b", "00002000", ["helper"], name="target_x", pseudocode="return helper();")
    w.fn("a", "00000100", ["target_x"], name="a_caller")  # calls target_x on A
    w.fn("b", "00000200", ["other"], name="b_other")  # does NOT call target_x on B
    w.commit()
    pid = _pair_id("00001000", "00002000")
    e = _entry(w, pid, sort_by="significance")
    assert e["bucket"] == "E"
    assert e["callers_a"]["count"] == 1
    assert e["callers_a"]["sample"] == ["00000100"]
    assert e["callers_b"] == {"state": "none_found"}
    assert e["pairing"] == "aligned"
    assert e["significance"] == {"attention": 1, "basis": "lost_every_direct_caller_never_sunk"}


def test_a_b_side_caller_means_no_edge_and_no_e(tmp_path: Path, current: None) -> None:
    """A pair whose B-side function HAS a direct caller carries no edge: no callers field, no E, and
    the pair stays counted under not_listed (a similarity-1 pair with nothing to say).

    MUTATION: emit callers_b as an empty-list fact / 'blocked' when a caller exists -> RED; place E
    anyway -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 1.0)
    w.fn("a", "00001000", ["helper"], name="target_x")
    w.fn("b", "00002000", ["helper"], name="target_x")
    w.fn("a", "00000100", ["target_x"], name="a_caller")
    w.fn("b", "00000200", ["target_x"], name="b_caller")  # B calls target_x -> confirmed-has
    w.commit()
    v = _view(w, sort_by="significance")
    pid = _pair_id("00001000", "00002000")
    assert pid not in v["by_id"]  # not listed
    assert sum(c["count"] for c in v["not_listed"].values()) == 1  # still counted, never dropped
    # nothing anywhere claims a caller was lost or blocked
    for e in v["entries"]:
        assert "callers_a" not in e and "callers_b" not in e
        assert "blocked" not in e


def test_the_b_side_undetermined_edges_are_never_lost(tmp_path: Path, current: None) -> None:
    """The B side being undetermined — a function the scan does not hold (not_in_inventory), or a
    callee list that may be truncated — is an E entry with an undetermined callers_b and a countable
    blind spot, never dropped and never read as none_found.

    MUTATION: treat an undetermined B side as none_found -> basis lost_every... -> RED; drop the E
    placement on an undetermined B side -> RED; omit the callers_undetermined blind spot -> RED."""
    # not_in_inventory: the B function is absent from the analysis.db.
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 1.0)
    w.fn("a", "00001000", ["helper"], name="target_ni")
    w.fn("a", "00000100", ["target_ni"], name="a_caller")
    w.commit()
    e = _entry(w, _pair_id("00001000", "00002000"), sort_by="significance")
    assert e["bucket"] == "E"
    assert e["callers_b"] == {"state": "undetermined", "reason": "not_in_inventory"}
    assert e["significance"] == {"attention": 1, "basis": "caller_signal_undetermined_never_sunk"}
    assert "callers_undetermined:not_in_inventory" in e["blind_spots"]

    # callees_may_be_truncated: a (any) B function's callee list is a prefix, so no empty caller set
    # can be proven on that side.
    w2 = World(tmp_path / "t2")
    w2.pair("00001000", "00002000", 0.97, 1.0)
    w2.fn("a", "00001000", ["helper"], name="target_t")
    w2.fn("b", "00002000", ["helper"], name="target_t")
    w2.fn("a", "00000100", ["target_t"], name="a_caller")
    w2.fn("b", "00000300", ["x"], name="b_cut", truncated=1)  # B side maybe-truncated
    w2.commit()
    e2 = _entry(w2, _pair_id("00001000", "00002000"), sort_by="significance")
    assert e2["bucket"] == "E"
    assert e2["callers_b"] == {"state": "undetermined", "reason": "callees_may_be_truncated"}
    assert e2["significance"] == {"attention": 1, "basis": "caller_signal_undetermined_never_sunk"}
    assert "callers_undetermined:callees_may_be_truncated" in e2["blind_spots"]


def test_an_existing_entry_is_held_only_on_a_proven_none(tmp_path: Path, current: None) -> None:
    """On an entry that is ALREADY listed, the edge holds it off the bottom only when the B side is
    a proven none_found; an undetermined B side leaves it to sink (it is already listed, so there is
    nothing to place and nothing to float on a maybe).

    MUTATION: lift an existing entry on an undetermined B side -> RED; stop lifting an existing
    entry on a proven none_found -> RED."""
    w = World(tmp_path)
    # A changed pair with no candidate -> C; its A function has a caller, its B none -> held at 1.
    w.pair("00001000", "00002000", 0.97, 0.6)
    w.fn("a", "00001000", ["memset"], name="held_c", pseudocode="memset(b,0,8);")
    w.fn("b", "00002000", ["memset"], name="held_c", pseudocode="memset(b,0,9);")
    w.fn("a", "00000100", ["held_c"], name="a_caller")
    # A changed pair with no candidate whose B function is absent (not_in_inventory) -> C, sinks.
    w.pair("00003000", "00004000", 0.97, 0.6)
    w.fn("a", "00003000", ["memcpy"], name="sunk_c", pseudocode="memcpy(b,s,8);")
    w.fn("a", "00000110", ["sunk_c"], name="a_caller2")
    w.commit()
    v = _view(w, sort_by="significance")["by_id"]
    held = v[_pair_id("00001000", "00002000")]
    assert held["bucket"] == "C"
    assert held["callers_b"] == {"state": "none_found"}
    assert held["significance"] == {
        "attention": 1,
        "basis": "lost_every_direct_caller_never_sunk",
    }
    sunk = v[_pair_id("00003000", "00004000")]
    assert sunk["bucket"] == "C"
    assert sunk["callers_b"]["state"] == "undetermined"
    assert sunk["significance"]["attention"] == 2  # not held on a maybe


def test_a_candidate_bearing_edge_entry_takes_segment_2_lane_2(
    tmp_path: Path, current: None
) -> None:
    """An E entry that carries a persisted candidate of its own joins segment 2 in lane 2 (after the
    R lane 0 and B lane 1 that carry a candidate); one with none joins segment 3, lane 3.

    MUTATION: give a candidate-bearing E segment 3 / lane != 2 -> RED."""
    w = World(tmp_path)
    a, b = "runA", "runB"
    # candidate-bearing E: a persisted candidate lines up on both sides, pair similarity 1.
    w.pair("00001000", "00002000", 0.97, 1.0)
    w.inst("a", _ref(a, "00001000", "cmd", "0x10"), "cmd", "system")
    w.inst("b", _ref(b, "00002000", "cmd", "0x10"), "cmd", "system")
    w.im("00001010", "00002010", "00001000")
    w.fn("a", "00001000", ["system"], name="cand_e")
    w.fn("b", "00002000", ["system"], name="cand_e")
    w.fn("a", "00000100", ["cand_e"], name="a_caller")
    # no-candidate E, for the lane-3 contrast.
    w.pair("00003000", "00004000", 0.97, 1.0)
    w.fn("a", "00003000", ["helper"], name="plain_e")
    w.fn("b", "00004000", ["helper"], name="plain_e")
    w.fn("a", "00000110", ["plain_e"], name="a_caller2")
    w.commit()
    cand = _built_entry(w, _pair_id("00001000", "00002000"))
    assert cand.bucket == "E" and cand.tier != pv.NO_SINK
    assert cand.rank["segment"] == 2 and cand.rank["lane"] == 2 and cand.rank["subclass_rank"] == 0
    plain = _built_entry(w, _pair_id("00003000", "00004000"))
    assert plain.bucket == "E" and plain.tier == pv.NO_SINK
    assert plain.rank["segment"] == 3 and plain.rank["lane"] == 3


def test_the_edge_is_never_a_judgement_basis(tmp_path: Path, current: None) -> None:
    """callers_a / callers_b / pairing are a render-face fact, never part of
    diff_review.entry_facts, so adding them moves no existing judgement to needs_recheck.

    MUTATION: put callers_* into entry_facts -> the keys appear -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 1.0)
    w.fn("a", "00001000", ["helper"], name="target_x")
    w.fn("b", "00002000", ["helper"], name="target_x")
    w.fn("a", "00000100", ["target_x"], name="a_caller")
    w.commit()
    e = _built_entry(w, _pair_id("00001000", "00002000"))
    assert e.callers_b is not None  # the edge is present on the entry
    facts = dr.entry_facts(e)
    assert "callers_a" not in facts and "callers_b" not in facts and "pairing" not in facts
    assert set(facts) == {
        "alignment_state",
        "similarity",
        "export_gap_a",
        "export_gap_b",
        "bucket",
        "rows",
    }


def test_the_edge_never_rebuckets_an_already_listed_pair(tmp_path: Path, current: None) -> None:
    """E is placed ONLY on a pair that would otherwise place no entry; a pair already in a bucket
    keeps it and carries the edge as a field alone, anchored on the pair like any entry, so no
    anchor collides and the subjects stay conserved.

    MUTATION: drop the 'no bucket yet' guard on E placement -> a bucket-C pair with the edge is
    rebucketed to E -> RED."""
    w = World(tmp_path)
    # a changed pair with no candidate -> C, that also carries the caller edge (a caller on A, none
    # on B); it must stay C, the edge riding as a field.
    w.pair("00001000", "00002000", 0.97, 0.6)
    w.fn("a", "00001000", ["memset"], name="c_fn", pseudocode="memset(b,0,8);")
    w.fn("b", "00002000", ["memset"], name="c_fn", pseudocode="memset(b,0,9);")
    w.fn("a", "00000100", ["c_fn"], name="a_caller")
    # a plain similarity-1 pair that stays not_listed (nothing to say)
    w.pair("00003000", "00004000", 0.97, 1.0)
    w.fn("a", "00003000", ["foo"], name="plain", pseudocode="foo();")
    w.fn("b", "00004000", ["foo"], name="plain", pseudocode="foo();")
    w.commit()
    v = _view(w, sort_by="significance")
    e = v["by_id"][_pair_id("00001000", "00002000")]
    assert e["bucket"] == "C"  # kept, never rebucketed to E
    assert e["callers_b"] == {"state": "none_found"}  # the edge rides as a field
    assert e["anchor_ref"] == dr.pair_anchor("runA", "runB", "libx", "00001000", "00002000")
    # subjects conserved: two pairs -> one listed (C), one not_listed (the plain pair).
    assert v["total_entries"] == 1
    assert sum(c["count"] for c in v["not_listed"].values()) == 1


def test_the_no_mention_key_orders_only_under_significance(tmp_path: Path, current: None) -> None:
    """Whether another B function names an E entry's function orders the E lane under significance
    (no-mention first), as the honest field b_other_fn_mentions — but it NEVER touches the
    candidate_tier order, the rank_key or the cheap build layer (which cannot read pseudocode).

    MUTATION: fold the no-mention key into rank_key / the candidate_tier order -> that order flips /
    rank_key gains a field -> RED; include the function's OWN body in the mention index -> both read
    as mentioned -> the significance order stops splitting them -> RED."""
    w = World(tmp_path)
    # two no-candidate E pairs in the same lane; by address, mentioned sorts BEFORE unmentioned.
    w.pair("00001000", "00002000", 0.97, 1.0)  # lower address: mentioned by another B function
    w.fn("a", "00001000", ["helper"], name="m_target", pseudocode="helper();")
    w.fn("b", "00002000", ["helper"], name="m_target", pseudocode="helper();")
    w.pair("00005000", "00006000", 0.97, 1.0)  # higher address: not mentioned by ANOTHER function
    w.fn("a", "00005000", ["helper"], name="u_target", pseudocode="helper();")
    # its OWN body names u_target: excluded, so it stays unmentioned — a mutation that counts the
    # function's own body would flip it and collapse the significance split.
    w.fn("b", "00006000", ["helper"], name="u_target", pseudocode="u_target();")
    w.fn("a", "00000100", ["m_target", "u_target"], name="a_caller")
    # a B function that NAMES m_target in its body but does not CALL it (callees empty).
    w.fn("b", "00000300", [], name="b_mentioner", pseudocode="void *p = &m_target;")
    w.commit()
    m_id, u_id = _pair_id("00001000", "00002000"), _pair_id("00005000", "00006000")
    base = _view(w, sort_by="candidate_tier")
    assert base["by_id"][m_id]["b_other_fn_mentions"] is True
    assert base["by_id"][u_id]["b_other_fn_mentions"] is False
    # the candidate_tier order is by address: m (lower) before u; rank_key carries no mention
    # component.
    base_order = [e["entry_id"] for e in base["entries"]]
    assert base_order.index(m_id) < base_order.index(u_id)
    assert set(base["by_id"][m_id]["rank_key"]) == {
        "segment",
        "lane",
        "subclass_rank",
        "similarity",
        "address",
    }
    # significance reverses them inside the lane: the unmentioned one is read first.
    lens = _view(w, sort_by="significance")
    lens_order = [e["entry_id"] for e in lens["entries"]]
    assert lens_order.index(u_id) < lens_order.index(m_id)
    # the rank_key is identical under both orders (only significance adds attention / swap fields).
    for key in ("segment", "lane", "subclass_rank", "address"):
        assert base["by_id"][m_id]["rank_key"][key] == lens["by_id"][m_id]["rank_key"][key]


def test_the_edge_order_holds_page_by_page_cold_then_warm(tmp_path: Path, current: None) -> None:
    """★ Paged one entry at a time under significance, the first page (cold: the bodies are read)
    and the second (warm: everything from the cache) together read the unmentioned E first and the
    mentioned one second, each once — and the warm page still knows its entry IS mentioned. The
    mentioned one has the LOWER address, so a warm page that lost the mention set would order by
    address and repeat the first entry.

    MUTATION (verified RED): compute the no-mention set only on a cache miss and read it empty on a
    hit -> the warm page repeats the unmentioned entry, reads mentioned false -> RED."""
    w = World(tmp_path)
    for fa, fb, name in (("00001000", "00002000", "m_fn"), ("00005000", "00006000", "u_fn")):
        w.pair(fa, fb, 0.97, 1.0)
        w.fn("a", fa, ["helper"], name=name, pseudocode="helper();")
        w.fn("b", fb, ["helper"], name=name, pseudocode="helper();")
    w.fn("a", "00000100", ["m_fn", "u_fn"], name="a_caller")
    w.fn("b", "00000300", [], name="b_mentioner", pseudocode="void *p = &m_fn;")  # names m_fn
    w.commit()
    m_id, u_id = _pair_id("00001000", "00002000"), _pair_id("00005000", "00006000")
    cold = pv.get_diff_patch_view(w.atlas, DIFF, sort_by="significance", limit=1)
    warm = pv.get_diff_patch_view(w.atlas, DIFF, sort_by="significance", limit=1, offset=1)
    assert [e["entry_id"] for e in cold["entries"] + warm["entries"]] == [u_id, m_id]
    assert cold["entries"][0]["b_other_fn_mentions"] is False
    assert warm["entries"][0]["b_other_fn_mentions"] is True
    assert warm["next_offset"] is None


def test_the_swap_lift_outranks_the_caller_edge_mention_key(tmp_path: Path, current: None) -> None:
    """S3 adds the no-mention key to the TAIL of the significance tuple, after the S2 narrow-swap
    lift (which sits right after attention). So inside attention 1 the swap lift wins over the
    mention key: an E entry that itself carries a narrow swap AND is mentioned still leads an E
    entry with no swap that is unmentioned — swap first, not mention first.

    MUTATION: move the no-mention key ahead of swap_lift in the significance tuple -> the
    unmentioned no-swap E would lead -> RED."""
    w = World(tmp_path)
    # E with a narrow swap (system vs popen in its callees), and named by another B body (mentioned)
    w.pair("00005000", "00006000", 0.97, 1.0)
    w.fn("a", "00005000", ["system"], name="e_swap", pseudocode="system(a);")
    w.fn("b", "00006000", ["popen"], name="e_swap", pseudocode="popen(a);")
    # E with no swap (same callees both sides), unmentioned, at a LOWER address
    w.pair("00001000", "00002000", 0.97, 1.0)
    w.fn("a", "00001000", ["helper"], name="e_plain", pseudocode="helper();")
    w.fn("b", "00002000", ["helper"], name="e_plain", pseudocode="helper();")
    w.fn("a", "00000100", ["e_swap", "e_plain"], name="a_caller")  # callers on A
    w.fn("b", "00000300", [], name="b_mentioner", pseudocode="p = &e_swap;")  # mentions e_swap only
    w.commit()
    v = _view(w, sort_by="significance")
    swap_id, plain_id = _pair_id("00005000", "00006000"), _pair_id("00001000", "00002000")
    assert v["by_id"][swap_id]["bucket"] == "E"
    assert v["by_id"][swap_id]["rank_key"]["sink_callee_swap"] == 1  # the swap lift is on
    assert v["by_id"][swap_id]["b_other_fn_mentions"] is True  # and it is mentioned
    assert v["by_id"][plain_id]["b_other_fn_mentions"] is False
    order = [e["entry_id"] for e in v["entries"]]
    assert order.index(swap_id) < order.index(plain_id)  # swap wins over the mention key


# ── S4: rows_limit=0 scans, and the inline_hunk rides on every delta the view prints ────────────


def test_a_zero_row_scan_keeps_every_count_and_no_row(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ rows_limit=0 lists each entry with no inline row but still writes what its rows hold
    (rows_total, rows_by_presence, rows_by_order_group, rows_order) and where they resume
    (rows_next_offset 0) — for an entry with only a few rows too. The default (20) leaves such an
    entry's counts out, as before: rows_limit is only a parameter, the entries and their order are
    the same.

    MUTATION (verified RED): window against ROWS_INLINE_LIMIT instead of rows_limit (``total > n``
    -> ``total > ROWS_INLINE_LIMIT``) -> the 3-row entry has no counts -> RED; refuse rows_limit=0
    outside entry_id -> RED."""
    w = _window_world(tmp_path, monkeypatch, "UPP")
    scan = pv.get_diff_patch_view(w.atlas, DIFF, rows_limit=0)
    assert "error" not in scan, scan
    e = {x["entry_id"]: x for x in scan["entries"]}[_WIN_ID]
    assert e["rows"] == [] and e["rows_total"] == 3 and e["rows_next_offset"] == 0
    assert e["rows_by_presence"] == {"persisted": 2, "presence_undetermined": 1}
    assert e["rows_by_order_group"] == {"not_persisted": 1, "size_signal": 0, "rest": 2}
    default = _one(w)
    assert len(default["rows"]) == 3 and "rows_by_presence" not in default
    assert [x["entry_id"] for x in scan["entries"]] == [
        x["entry_id"] for x in pv.get_diff_patch_view(w.atlas, DIFF)["entries"]
    ]


def test_the_mcp_tool_passes_rows_limit_zero_through_as_a_scan(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """At the MCP tool (not just the read layer), rows_limit=0 is a scan, not an error: entries come
    back, each with rows [] and the counts the scan writes (rows_total, rows_by_presence). The tool
    must accept 0 AND hand it to the read layer.

    MUTATIONs (audit C06/C07): reject rows_limit=0 at the tool -> an error and no entries -> RED;
    drop rows_limit from the tool's call to the read layer -> entries carry inline rows, not []
    -> RED.
    """
    w = _window_world(tmp_path, monkeypatch, "UPP")
    out = mcp_app.make_tools(w.path)["get_diff_patch_view"](DIFF, rows_limit=0)
    assert "error" not in out, out
    e = {x["entry_id"]: x for x in out["entries"]}[_WIN_ID]
    assert e["rows"] == [] and e["rows_total"] == 3
    assert e["rows_by_presence"] == {"persisted": 2, "presence_undetermined": 1}


def test_the_hunk_rides_on_every_delta_the_view_prints(tmp_path: Path, current: None) -> None:
    """The view prints pseudocode_delta in three places — an aligned entry, an undetermined pair's
    proposed_pair_reading, a not-listed page row — and each carries its inline_hunk, shown from the
    original text."""
    w = World(tmp_path)
    body_a = "void f(void)\n{\n  int n;\n  n = get();\n  FUN_00409748(n);\n  put(n);\n  return;\n}"
    body_b = "void f(void)\n{\n  int n;\n  n = get();\n  put(n);\n  return;\n}"
    for a, b, conf, sim in (
        ("00001000", "00002000", 0.97, 0.6),  # aligned, changed: C
        ("00003000", "00004000", 0.5, 0.6),  # undetermined: R, proposed reading
        ("00005000", "00006000", 0.97, 1.0),  # aligned similarity 1 with a text that differs
    ):
        w.pair(a, b, conf, sim)
        w.fn("a", a, ["get", "put"], pseudocode=body_a)
        w.fn("b", b, ["get", "put"], pseudocode=body_b)
    w.commit()
    want = "-FUN_00409748(n);"
    by_id = _view(w)["by_id"]
    aligned = by_id[_pair_id("00001000", "00002000")]["pseudocode_delta"]["inline_hunk"]
    assert want in aligned["structural"][0]
    proposed = by_id[_pair_id("00003000", "00004000")]["proposed_pair_reading"]
    assert want in proposed["pseudocode_delta"]["inline_hunk"]["structural"][0]
    page = pv.get_diff_patch_view(w.atlas, DIFF, not_listed_page="aligned_pseudocode_differs")
    (row,) = page["entries"]
    assert want in row["pseudocode_delta"]["inline_hunk"]["structural"][0]


# ── S3 audit follow-up: what the caller-set edge's tests did not yet hold ──────────────────────


def _edge_pair(w: World, fa: str, fb: str, name: str, *, b: bool = True, **kw: Any) -> None:
    """A similarity-1 aligned pair with no candidate, its A function called from elsewhere on A
    (so it carries the edge); the B function is left out of the B scan when ``b`` is false."""
    w.pair(fa, fb, 0.97, 1.0, name_a=name, name_b=name)
    w.fn("a", fa, kw.get("callees_a", ["helper"]), name=name, pseudocode="helper();")
    if b:
        w.fn("b", fb, kw.get("callees_b", ["helper"]), name=name, pseudocode="helper();")
    w.fn("a", f"{int(fa, 16) + 0x800:08x}", [name], name=f"{name}_caller")


def test_a_function_the_b_scan_does_not_hold_is_looked_up_by_its_alignment_name(
    tmp_path: Path, current: None
) -> None:
    """★ The B function is not in the B scan (callers_b undetermined: not_in_inventory), so it has
    no extracted name — but other B bodies still call it by the name the alignment carries. Read
    only as FUN_<addr> it would always read "nothing mentions it": that is "could not look it up",
    not "not mentioned".

    MUTATION (verified RED): drop the alignment-name fallback -> the called one reads false
    -> RED."""
    w = World(tmp_path)
    _edge_pair(w, "00001000", "00002000", "called_fn", b=False)
    _edge_pair(w, "00003000", "00004000", "quiet_fn", b=False)
    w.fn("b", "00000300", ["called_fn"], name="b_user", pseudocode="called_fn(1);")
    w.commit()
    v = _view(w, sort_by="significance")["by_id"]
    called = v[_pair_id("00001000", "00002000")]
    assert called["callers_b"] == {"state": "undetermined", "reason": "not_in_inventory"}
    assert called["b_other_fn_mentions"] is True
    assert v[_pair_id("00003000", "00004000")]["b_other_fn_mentions"] is False


def test_a_new_e_entry_is_not_served_the_old_mention_set(tmp_path: Path, current: None) -> None:
    """The no-mention set covers the E entries of one build; a re-hunt can make another pair E
    while the readings' key (the diff, its content and build hashes) stays the same. Rendered again
    without clearing any cache, the new E entry reads its own mention state.

    MUTATION (verified RED): key the no-mention set by the readings' key alone -> the cached set,
    computed before the pair was E, reads it false -> RED."""
    w = World(tmp_path)
    _edge_pair(w, "00001000", "00002000", "first_fn")
    _edge_pair(w, "00003000", "00004000", "later_fn")
    w.inst("a", _ref("runA", "00003000", "cmd", "0x10"), "cmd", "system")  # a row places it
    w.fn("b", "00000300", [], name="b_user", pseudocode="p = &later_fn;")
    w.commit()
    later = _pair_id("00003000", "00004000")
    before = _view(w, sort_by="significance")["by_id"]
    assert before[later]["bucket"] != "E"
    w.atlas.execute("DELETE FROM instance WHERE evidence_ref LIKE '%:00003000@%'")  # the re-hunt
    w.commit()
    after = _view(w, sort_by="significance")["by_id"]
    assert after[later]["bucket"] == "E"
    assert after[later]["b_other_fn_mentions"] is True


def test_the_order_lens_and_the_tool_name_the_edge(tmp_path: Path, current: None) -> None:
    """The order a candidate_tier page's first page states, the caveats and the tool's own
    description (where the significance rules are) all name bucket E and where it sits — not only
    the module docstring.

    MUTATION (verified RED): drop E from lens.order -> RED; drop the two caller bases from the
    tool's description -> RED; drop the callers_b caveat -> RED; drop E from the tool's description
    -> RED."""
    w = World(tmp_path)
    _edge_pair(w, "00001000", "00002000", "x_fn")
    w.commit()
    v = pv.get_diff_patch_view(w.atlas, DIFF, sort_by="candidate_tier")
    order = v["lens"]["order"]
    assert "sink_presence_signal first, then E;" in order  # with a candidate: after R and B
    assert "C, then E by caller relevance" in order  # with none: the last lane
    assert {"callers_b", "E"} <= set(v["caveats"])
    assert "E" in v["legend"]
    doc = " ".join(
        (mcp_app.make_tools(Path("unused.db"))["get_diff_patch_view"].__doc__ or "").split()
    )
    for word in (
        "lost_every_direct_caller_never_sunk",
        "caller_signal_undetermined_never_sunk",
        "b_other_fn_mentions",
    ):
        assert word in doc, word
    assert "``E`` = a similarity-1 pair" in doc
    assert "b_other_fn_mentions" in doc and "R / B / E entries carrying a candidate" in doc


def test_an_edge_entry_counts_only_its_own_blind_spot(tmp_path: Path, current: None) -> None:
    """The edge entry's own blind_spots hold the countable callers_undetermined:<reason>, never the
    structural ones; those three are in the ledger once, uncounted (count null).

    MUTATION (verified RED): attach the structural caller spots to every edge entry -> RED; drop
    them from _STRUCTURAL_BLIND_SPOTS -> RED."""
    w = World(tmp_path)
    _edge_pair(w, "00001000", "00002000", "x_fn", b=False)
    w.commit()
    v = pv.get_diff_patch_view(w.atlas, DIFF)
    (e,) = v["entries"]
    structural = {
        "caller_via_function_pointer_table",
        "caller_via_data_reference",
        "caller_inlined",
    }
    assert "callers_undetermined:not_in_inventory" in e["blind_spots"]
    assert not structural & set(e["blind_spots"])
    ledger = {s["key"]: s for s in v["blind_spots"]}
    for key in structural:
        assert ledger[key]["count"] is None and ledger[key]["unit"] is None, key


def test_a_self_call_is_not_a_caller_on_either_side(tmp_path: Path, current: None) -> None:
    """A function whose only "caller" is itself has no caller from elsewhere: on the A side there is
    no edge (and no E); on the B side a self-call does not count as a caller, so the edge reads
    none_found.

    MUTATION (verified RED): count a self-recursive call as a caller -> A: an E appears; B: no edge
    -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 1.0)  # A calls only itself
    w.fn("a", "00001000", ["self_a"], name="self_a")
    w.fn("b", "00002000", ["helper"], name="self_a")
    w.pair("00003000", "00004000", 0.97, 1.0)  # B calls only itself
    w.fn("a", "00003000", ["helper"], name="self_b")
    w.fn("b", "00004000", ["self_b"], name="self_b")
    w.fn("a", "00000100", ["self_b"], name="a_caller")
    w.commit()
    v = _view(w)["by_id"]
    assert _pair_id("00001000", "00002000") not in v
    assert v[_pair_id("00003000", "00004000")]["callers_b"] == {"state": "none_found"}


def test_a_callee_list_that_does_not_record_truncation_proves_no_none(
    tmp_path: Path, current: None
) -> None:
    """A B function whose callee list does not record whether it was cut (callees_truncated NULL)
    is a list that may be a prefix, so no B caller set can be proven empty.

    MUTATION (verified RED): read only a recorded truncation (True) as a maybe -> none_found
    -> RED."""
    w = World(tmp_path)
    _edge_pair(w, "00001000", "00002000", "x_fn")
    w.fn("b", "00000300", ["other"], name="b_unrecorded", truncated=None)  # type: ignore[arg-type]
    w.commit()
    (e,) = _view(w)["entries"]
    assert e["callers_b"] == {"state": "undetermined", "reason": "callees_may_be_truncated"}


def test_the_edge_lane_orders_by_caller_relevance(tmp_path: Path, current: None) -> None:
    """★ The E lane with no candidate row orders by caller relevance (rank_key.subclass_rank): 0 = a
    callee is a sink the hunt does not recall (_eval), 1 = a callee — on EITHER side — itself holds
    a candidate, 2 = the rest; in the default order relevance leads the address.

    MUTATION (verified RED): pin E's subclass_rank to 0 -> RED; leave the recall-gap callee out of 0
    -> RED; read the one-hop callee on the A side only -> the B-only one reads 2 -> RED."""
    w = World(tmp_path)
    _edge_pair(w, "00001000", "00002000", "plain_fn")  # rest: 2, lowest address
    _edge_pair(w, "00003000", "00004000", "hop_fn", callees_b=["helper", "cand_b"])
    w.fn("b", "00009000", ["system"], name="cand_b")
    w.inst("b", _ref("runB", "00009000", "cmd", "0x10"), "cmd", "system")
    _edge_pair(w, "00005000", "00006000", "gap_fn", callees_a=["_eval"], callees_b=["_eval"])
    w.commit()
    v = _view(w)
    rank = {e["entry_id"]: e["rank_key"] for e in v["entries"] if e["bucket"] == "E"}
    plain, hop, gap = (
        _pair_id(a, b)
        for a, b in (("00001000", "00002000"), ("00003000", "00004000"), ("00005000", "00006000"))
    )
    assert (
        rank[gap]["subclass_rank"],
        rank[hop]["subclass_rank"],
        rank[plain]["subclass_rank"],
    ) == (0, 1, 2)
    assert all(rank[x]["segment"] == 3 and rank[x]["lane"] == 3 for x in (plain, hop, gap))
    order = [e["entry_id"] for e in v["entries"] if e["bucket"] == "E"]
    assert order == [gap, hop, plain]


def test_only_a_narrow_swap_lifts_and_never_above_attention_zero(
    tmp_path: Path, current: None
) -> None:
    """★ (S2, held here because S3 re-touched the significance tuple.) Inside attention 1 only a
    NARROW sink_callee_swap lifts an entry (rank_key.sink_callee_swap 1); a wide swap reads 0 and
    is not ordered ahead of the narrow one, even at a lower similarity. And the lift orders inside
    attention 1 only: every attention 0 entry still comes first.

    MUTATION (verified RED): lift a wide swap too (drop ``and swap["narrow"]``) -> RED; put
    -swap_lift ahead of attention in the tuple -> the narrow swap precedes the A entry -> RED."""
    w = World(tmp_path)
    a, b = "runA", "runB"
    # B sink_present_no_visible_delta (attention 1) with a WIDE swap, at the lower similarity
    w.pair("00001000", "00002000", 0.97, 0.5)
    w.inst("a", _ref(a, "00001000", "cmd", "0x10"), "cmd", "system")
    w.inst("b", _ref(b, "00002000", "cmd", "0x10"), "cmd", "system")
    w.im("00001010", "00002010", "00001000")
    w.fn("a", "00001000", ["system"])
    w.fn("b", "00002000", ["system", "popen", "execl", "log_a"])
    # C with a NARROW swap (attention 1), at the higher similarity
    w.pair("00003000", "00004000", 0.97, 0.9)
    w.fn("a", "00003000", ["memcpy"])
    w.fn("b", "00004000", ["strcpy"])
    # A (attention 0)
    w.pair("00005000", "00006000", 0.97, 0.9)
    w.inst("a", _ref(a, "00005000", "cmd", "0x10"), "cmd", "system")
    w.inst("b", _ref(b, "00006000", "cmd", "0x10"), "cmd", "popen")
    w.im("00005010", "00006010", "00005000")
    w.fn("a", "00005000", ["system"])
    w.fn("b", "00006000", ["popen"])
    w.commit()
    v = _view(w, sort_by="significance")
    by = v["by_id"]
    wide, narrow, a_id = (
        _pair_id(x, y)
        for x, y in (("00001000", "00002000"), ("00003000", "00004000"), ("00005000", "00006000"))
    )
    assert by[wide]["sink_callee_swap"]["narrow"] is False
    assert by[wide]["significance"]["attention"] == 1
    assert by[wide]["rank_key"]["sink_callee_swap"] == 0
    assert by[narrow]["rank_key"]["sink_callee_swap"] == 1
    assert by[a_id]["significance"]["attention"] == 0
    order = [e["entry_id"] for e in v["entries"]]
    assert order.index(a_id) < order.index(narrow) < order.index(wide)


# ── S7: the guard scan on the view, its row links, and the sink axes ──────────────────────────

_GUARD_CMD = json.dumps(
    {
        "source_kind": "unknown",
        "flow_path": {"sink_arg": "pcVar2", "one_hop": ["local_118"]},
        "sanitizer_seen": [],
        "trace_boundary": "reached_sink",
        "sink_arg_provenance": [],
    }
)
_GUARD_A = "pcVar2 = get();\nsystem(pcVar2);"
_GUARD_B = "\n".join(
    [
        "pcVar2 = get();",
        "if (pcVar2 == (char *)0x0) {",
        "return;",
        "}",
        "if (iVar9 > 5) {",
        "}",
        "system(pcVar2);",
    ]
)
ALIGNED = _pair_id("00001000", "00002000")
PROPOSED = _pair_id("00003000", "00004000")
CROSS = _pair_id("00005000", "00006000")


def _guard_world(tmp_path: Path) -> World:
    """An aligned pair and an undetermined pair, each with a cmd candidate on both sides at the
    matched call and a B body that adds two comparisons (one on the sink argument); a pair whose
    copy call became a capped formatter; and an aligned, similarity-1 pair (not listed) whose B
    body adds a comparison."""
    w = World(tmp_path)
    for a, b, conf in (("00001000", "00002000", 0.97), ("00003000", "00004000", 0.5)):
        w.pair(a, b, conf, 0.8)
        w.inst("a", _ref("runA", a, "cmd", "0x10"), "cmd", "system", _GUARD_CMD)
        w.inst("b", _ref("runB", b, "cmd", "0x10"), "cmd", "system", _GUARD_CMD)
        w.im(a[:-2] + "10", b[:-2] + "10", a)
        w.fn("a", a, ["system"], pseudocode=_GUARD_A)
        w.fn("b", b, ["system"], pseudocode=_GUARD_B)
    w.pair("00005000", "00006000", 0.97, 0.8)
    copy = {"size_flow": {"size_arg": "0x100", "size_var": None, "one_hop": []}}
    fmt = {"size_flow": {"size_arg": "0x1000", "size_var": None, "one_hop": []}}
    tail = {"clamp_seen": [], "trace_boundary": "reached_sink"}
    w.inst(
        "a",
        _ref("runA", "00005000", "copy", "0x10"),
        "copy",
        "strcpy",
        json.dumps({"size_kind": "const", **copy, **tail}),
    )
    w.inst(
        "b",
        _ref("runB", "00006000", "format", "0x10"),
        "format",
        "snprintf",
        json.dumps({"size_kind": "cap_const", "format_string": "literal_with_args", **fmt, **tail}),
    )
    w.im("00005010", "00006010", "00005000")
    w.fn("a", "00005000", ["strcpy"], pseudocode="strcpy(d, s);")
    w.fn("b", "00006000", ["snprintf"], pseudocode='snprintf(d, 0x1000, "%s", s);')
    w.pair("00007000", "00008000", 0.97, 1.0)
    w.fn("a", "00007000", ["bar"], pseudocode="n = bar();\nuse(n);")
    w.fn("b", "00008000", ["bar"], pseudocode="n = bar();\nif (n < 0x10) {\nuse(n);\n}")
    w.commit()
    return w


def _vocabulary_world(tmp_path: Path) -> World:
    """The guard world plus pairs that make the rarer guard and axis values appear: a row whose
    B-side candidate lies in another function (other_function) beside an A record without its
    sanitizer field (not_in_record) and a B body whose locals were renumbered (renumbered_in_a); a
    B ref recorded twice with two sink arguments (ambiguous_ref) beside a function-level B
    candidate (sink_name); a B candidate of an unknown class (class_unknown) beside an A one with
    no sink anchor (unscoped); one with no readable record (no_evidence); and more linked guards
    than are shown (linked_not_shown). Every new pair is listed (similarity below 1)."""
    w = _guard_world(tmp_path)
    rec = json.loads(_GUARD_CMD)
    no_sanitizer = {k: v for k, v in rec.items() if k != "sanitizer_seen"}
    base_a = "pcVar2 = get();\nlog(pcVar2);\nsystem(pcVar2);"
    base_b = "pcVar2 = get();\nif (pcVar2 == 0) {\nreturn;\n}\nnote(pcVar2, 1);\nsystem(pcVar2);"

    def pair(a: str, b: str, body_a: str = base_a, body_b: str = base_b) -> None:
        w.pair(a, b, 0.97, 0.8)
        w.im(a[:-2] + "10", b[:-2] + "10", a)
        w.fn("a", a, ["system"], pseudocode=body_a)
        w.fn("b", b, ["system"], pseudocode=body_b)

    renum_a = "uVar9 = get();\nuse(uVar9);\nkeep(uVar9);\nif (uVar9 == 0x74) {\none();\n}"
    renum_b = "uVar13 = get();\nuse(uVar13);\nkeep(uVar13);\nextra(1);\n"
    renum_b += "if (uVar13 == 0x74) {\ntwo(2);\n}"
    pair("00009000", "0000a000", renum_a, renum_b)
    w.inst("a", _ref("runA", "00009000", "cmd", "0x10"), "cmd", "system", json.dumps(no_sanitizer))
    w.inst("b", _ref("runB", "0000c000", "cmd", "0x10"), "cmd", "system", _GUARD_CMD)
    w.atlas.execute(
        "UPDATE instruction_match SET addr_b = '0000c010' WHERE func_addr_a = '00009000'"
    )
    w.fn("b", "0000c000", ["system"], pseudocode="system(pcVar2);")
    pair("0000d000", "0000e000")
    w.inst("a", _ref("runA", "0000d000", "cmd", "0x10"), "cmd", "system", _GUARD_CMD)
    for arg in ("pcVar2", "pcVar3"):
        twice = {**rec, "flow_path": {"sink_arg": arg, "one_hop": []}}
        w.inst("b", _ref("runB", "0000e000", "cmd", "0x10"), "cmd", "system", json.dumps(twice))
    w.inst("b", _ref("runB", "0000e000", "cmd"), "cmd", "system", _GUARD_CMD)
    pair("0000f000", "00010000")
    unanchored = _ref("runA", "0000f000", "cmd", "0x10")
    w.inst("a", unanchored, "cmd", "system", _GUARD_CMD)
    w.atlas.execute("UPDATE instance SET sink_anchor = NULL WHERE evidence_ref = ?", (unanchored,))
    w.inst("b", _ref("runB", "00010000", "unknown", "0x10"), "unknown", "system", _GUARD_CMD)
    pair("00011000", "00012000")
    w.inst("a", _ref("runA", "00011000", "cmd", "0x10"), "cmd", "system", _GUARD_CMD)
    w.inst("b", _ref("runB", "00012000", "cmd", "0x10"), "cmd", "system", None)
    names = [f"local_{i:x}0" for i in range(22)]
    many = "pcVar2 = get();\n" + "".join(f"if ({n} == 0) {{\nstep();\n}}\n" for n in names)
    pair("00013000", "00014000", base_a, many + "system(pcVar2);")
    w.inst("a", _ref("runA", "00013000", "cmd", "0x10"), "cmd", "system", _GUARD_CMD)
    hops = {**rec, "flow_path": {"sink_arg": "pcVar2", "one_hop": names}}
    w.inst("b", _ref("runB", "00014000", "cmd", "0x10"), "cmd", "system", json.dumps(hops))
    w.commit()
    return w


def _b_row(entry: dict[str, Any]) -> dict[str, Any]:
    (row,) = [r for r in entry["rows"] if r["b_ref"]]
    return row


def test_a_listed_pair_carries_its_guards_and_its_row_the_links(
    tmp_path: Path, current: None
) -> None:
    """★ Beside the pseudocode_delta: guard_scan (done, coverage unjudged, the counts that are not
    0), the shown guards in B order (no ``cast`` key where the variable has none); the envelope
    says once where their B body is read; the persisted row links them by name to its B-side
    candidate's sink argument. The list entry says where the axes are read (entry_id); the rows
    carry none.

    MUTATION (verified RED, 1 failed): give the axes on a list page too -> RED; MUTATION (verified
    RED, 2 failed — this test and the scan one): drop sink_axes_with -> RED; MUTATION (verified
    RED, 2 failed — this test and the not-listed one): give guards_body_ref on each entry again
    -> RED."""
    w = _guard_world(tmp_path)
    view = _view(w)
    e = view["by_id"][ALIGNED]
    keys = list(e)
    assert keys.index("pseudocode_delta") < keys.index("guard_scan")
    assert e["guard_scan"] == {
        "state": "done",
        "coverage": "unjudged",
        "var_const_total": 2,
        "by_const_class": {"zero": 1, "nonzero": 1},
        "shown_rule": "linked_first_then_b_order",
    }
    assert [(g["var"], g["const"], g["line_b"]) for g in e["guards"]] == [
        ("pcVar2", "0x0", 2),
        ("iVar9", "5", 5),
    ]
    assert all("cast" not in g for g in e["guards"])
    assert "guards_body_ref" not in e
    assert view.get("guards_read_with") == {
        "read_with": "get_pseudocode",
        "run_id": "runB",
        "binary": SHA_B,
        "function": "entry.addr_b",
    }
    assert e["addr_b"] == "00002000"
    row = _b_row(e)
    assert row["guard_links"] == {
        "sink_arg": {"yes": [0], "no": [1], "unknown": []},
        "size_arg": {"unavailable": "not_recorded_for_class"},
    }
    assert e.get("sink_axes_with") == "entry_id"
    assert all("sink_axes" not in r for r in e["rows"])


def test_an_undetermined_pair_links_into_its_proposed_reading(
    tmp_path: Path, current: None
) -> None:
    """L7: an undetermined pair's guards sit in its proposed_pair_reading (none at the top level),
    and its row's links carry pairing=proposed, their indices into those guards.

    MUTATION (verified RED, 1 failed): drop the pairing -> RED; put the proposed pair's guards at
    the top level instead -> RED."""
    w = _guard_world(tmp_path)
    e = _view(w)["by_id"][PROPOSED]
    assert "guard_scan" not in e and "guards" not in e
    reading = e["proposed_pair_reading"]
    guards = reading.get("guards") or []
    assert [g["var"] for g in guards] == ["pcVar2", "iVar9"]
    links = _b_row(e)["guard_links"]
    assert links.get("pairing") == "proposed"
    assert [guards[i]["var"] for i in links["sink_arg"]["yes"]] == ["pcVar2"]


def test_reading_one_entry_gives_each_row_both_sides_axes(tmp_path: Path, current: None) -> None:
    """X5 / X1: reading one entry, each row carries sink_axes {a, b}, each side by its own class and
    record — a copy side with a constant length beside a capped formatter — and the row's own
    size_kind_shifted is where it was; the entry carries no sink_axes_with."""
    w = _guard_world(tmp_path)
    listed = _view(w)["by_id"][CROSS]
    out = pv.get_diff_patch_view(w.atlas, DIFF, entry_id=CROSS)
    (e,) = out["entries"]
    assert "sink_axes_with" not in e
    (row,) = e["rows"]
    axes = row["sink_axes"]
    assert (axes["a"]["class"], axes["b"]["class"]) == ("copy", "format")
    assert axes["a"]["bound"]["size_kind"] == "const"
    assert (axes["b"]["bound"]["size_kind"], axes["b"]["bound"]["size_arg"]) == (
        "cap_const",
        "0x1000",
    )
    assert row["size_kind_shifted"] == listed["rows"][0]["size_kind_shifted"]
    assert row["size_kind_shifted"] == {"from_kind": "const", "to_kind": "cap_const"}
    (cmd,) = pv.get_diff_patch_view(w.atlas, DIFF, entry_id=PROPOSED)["entries"]
    by_side = {("a" if r["a_ref"] else "b"): r["sink_axes"] for r in cmd["rows"]}
    assert by_side["a"]["b"] is None and by_side["b"]["a"] is None
    assert by_side["b"]["b"]["flow_path"]["sink_arg"] == "pcVar2"


def test_with_no_row_to_link_the_guards_are_shown_in_b_order(tmp_path: Path, current: None) -> None:
    """L9c: a scan (rows_limit=0) renders no row, and a not-listed pair has none: both show their
    guards in B order (shown_rule b_order), and no row carries links."""
    w = _guard_world(tmp_path)
    scan = _view(w, rows_limit=0)["by_id"][ALIGNED]
    assert scan["rows"] == []
    assert scan["guard_scan"]["shown_rule"] == "b_order"
    assert scan.get("sink_axes_with") == "entry_id"
    page = pv.get_diff_patch_view(w.atlas, DIFF, not_listed_page="aligned_pseudocode_differs")
    (row,) = page["entries"]
    assert row["guard_scan"]["shown_rule"] == "b_order"
    assert [(g["var"], g["relation"], g["const"]) for g in row["guards"]] == [("n", "<", "0x10")]
    assert "guards_body_ref" not in row
    assert (page.get("guards_read_with") or {}).get("function") == "entry.addr_b"
    assert row["addr_b"] == "00008000"


def test_a_rehunt_is_not_served_the_earlier_axes(tmp_path: Path, current: None) -> None:
    """The axis cache is keyed by the run row's stamps: after the B candidate's record changes and
    the run row says the run was written again, one entry's read gives the new record.

    MUTATION (verified RED, 1 failed): key the axis cache without the run stamps -> the earlier
    sink argument is served -> RED."""
    w = _guard_world(tmp_path)
    (e,) = pv.get_diff_patch_view(w.atlas, DIFF, entry_id=ALIGNED)["entries"]
    row = _b_row(e)
    assert row["sink_axes"]["b"]["flow_path"]["sink_arg"] == "pcVar2"
    rec = json.loads(_GUARD_CMD)
    rec["flow_path"]["sink_arg"] = "pcVar7"
    w.atlas.execute(
        "UPDATE instance SET flow_evidence = ? WHERE evidence_ref = ?",
        (json.dumps(rec), row["b_ref"]),
    )
    w.atlas.execute("UPDATE run SET updated_at = '2099-01-01T00:00:00Z' WHERE run_id = 'runB'")
    w.commit()
    (e,) = pv.get_diff_patch_view(w.atlas, DIFF, entry_id=ALIGNED)["entries"]
    assert _b_row(e)["sink_axes"]["b"]["flow_path"]["sink_arg"] == "pcVar7"


def test_a_pair_missing_from_the_guard_cache_alone_is_recomputed(
    tmp_path: Path, current: None
) -> None:
    """L12: the delta and its guard scan are written together; with only the guard cache dropped,
    the next read still gives guard_scan.

    MUTATION (verified RED, 1 failed): treat a delta-cache hit as enough -> guard_scan missing
    -> RED."""
    w = _guard_world(tmp_path)
    assert "guard_scan" in _view(w)["by_id"][ALIGNED]
    pv._GUARD_CACHE.clear()
    assert len(pv._DELTA_CACHE) > 0
    assert _view(w)["by_id"][ALIGNED].get("guard_scan", {}).get("state") == "done"


def test_the_s7_caches_are_dropped_with_the_others(tmp_path: Path, current: None) -> None:
    """X6.

    MUTATION (verified RED, 1 failed): leave _GUARD_CACHE (or _SINK_AXIS_CACHE) out of
    _clear_view_caches -> RED."""
    w = _guard_world(tmp_path)
    pv.get_diff_patch_view(w.atlas, DIFF, entry_id=ALIGNED)
    assert len(pv._GUARD_CACHE) > 0 and len(pv._SINK_AXIS_CACHE) > 0
    pv._clear_view_caches()
    assert len(pv._GUARD_CACHE) == 0 and len(pv._SINK_AXIS_CACHE) == 0


def test_rendering_guards_and_axes_never_writes_the_build(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """I1 / I2: after a list page and a one-entry read, the build's own row views hold no
    guard_links / sink_axes, the judgement bases (entry_facts / row_facts) read as a fresh build's,
    and the cached deltas hold no guard key.

    MUTATION M8 (verified RED, 1 failed): write the links into the row views in place -> RED."""
    w = _guard_world(tmp_path)
    builds: list[pv.BuiltDiff] = []
    real = pv.build_diff_view

    def keep(atlas: Any, diff_id: str) -> Any:
        built = real(atlas, diff_id)
        builds.append(built)
        return built

    monkeypatch.setattr(pv, "build_diff_view", keep)
    pv.get_diff_patch_view(w.atlas, DIFF)
    pv.get_diff_patch_view(w.atlas, DIFF, entry_id=ALIGNED)
    pv.get_diff_patch_view(w.atlas, DIFF, entry_id=PROPOSED)
    fresh = real(w.atlas, DIFF)
    assert fresh is not None
    want = {e.entry_id: dr.entry_facts(e) for e in fresh.placed}
    rows = {e.entry_id: [dr.row_facts(v) for v in e.row_views] for e in fresh.placed}
    for built in builds:
        for e in built.placed:
            for v in e.row_views:
                assert not {"guard_links", "sink_axes"} & set(v), e.entry_id
            assert dr.entry_facts(e) == want[e.entry_id]
            assert [dr.row_facts(v) for v in e.row_views] == rows[e.entry_id]
    for delta in pv._DELTA_CACHE._data.values():
        assert not {"guards", "guard_scan", "var_const_total", "state"} & set(delta)


def test_no_s7_field_reads_as_a_verdict(tmp_path: Path, current: None) -> None:
    """I4: neither the list nor a one-entry read emits ``blocked`` anywhere.

    MUTATION (verified RED, 1 failed): put a ``blocked`` value into a row's links -> RED."""
    w = _guard_world(tmp_path)
    texts = [json.dumps(_view(w)["entries"])]
    for entry_id in (ALIGNED, PROPOSED, CROSS):
        texts.append(json.dumps(pv.get_diff_patch_view(w.atlas, DIFF, entry_id=entry_id)))
    assert not any('"blocked"' in t for t in texts)


# ── detail='summary', and what only a scope's first page carries ────────────────────────────

MANY_ROWS = _pair_id("00101000", "00102000")  # 22 candidate rows: more than the inline window
EDGE = _pair_id("00111000", "00112000")  # bucket E
P_PLAIN = "a:00121000"
P_GAP = "a:00122000"  # its export holds it degenerately: export_gap is a string
R_HEAD = _pair_id("00131000", "00131000")  # anchored_differs, read first
R_LOW = _pair_id("00132000", "00132000")  # anchored_differs below the floor: in_read_first false
R_DEMOTED = _pair_id("00133000", "00133000")  # a line-number shift with callees and sizes equal
R_KEPT = _pair_id("00134000", "00134000")  # a line-number shift, callees differ: demoted false
R_MICRO = _pair_id("00135000", "00135000")  # anchored micro side
R_GAP = _pair_id("00136000", "00137000")  # an export gap on side a
PARTIAL = _pair_id("00141000", "00142000")  # a sink in a callee difference read in part only
JUMPTABLE = _pair_id("00151000", "00152000")  # qualified match still saying UNRECOVERED_JUMPTABLE


def _summary_world(tmp_path: Path) -> World:
    """The guard world (an aligned and an undetermined pair with guards and a hunk, a pair whose
    copy call became a capped formatter, a not-listed pair with a guard) plus one entry of each
    other shape a summary prints: more candidate rows than the inline window holds, bucket E, P
    with and without an export gap, undetermined pairs read first / below the floor / demoted for a
    line-number shift / kept in the head despite one, an anchored micro-side pair, an undetermined
    pair with an export gap, a sink in a callee difference that could be read only in part, and a
    qualified text match whose body still says UNRECOVERED_JUMPTABLE."""
    w = _guard_world(tmp_path)
    w.pair("00101000", "00102000", 0.97, 0.8)
    for i in range(22):
        w.inst("a", _ref("runA", "00101000", "cmd", f"0x{0x10 + 4 * i:x}"), "cmd", "system")
    w.fn("a", "00101000", ["system"], pseudocode="system(a);")
    w.fn("b", "00102000", ["system"], pseudocode="system(b);")
    _edge_pair(w, "00111000", "00112000", "edge_fn")
    w.unpaired("a", "00121000", "unmatched_analysis_complete")
    w.inst("a", _ref("runA", "00121000", "cmd", "0x10"), "cmd", "system")
    w.unpaired("a", "00122000", "unmatched_analysis_incomplete", "degenerate_block")
    w.inst("a", _ref("runA", "00122000", "cmd", "0x10"), "cmd", "system")
    _ud(w, "00131000", "00131000", 0.9)
    _ud(w, "00132000", "00132000", 0.5)
    _line_shift(w, "00133000")
    _line_shift(w, "00134000", callees_b=["log", "system"])
    _micro_pair(w, "00135000", "00135000", 0.6)
    _ud(w, "00136000", "00137000", 0.4, gap_a="degenerate_block")
    w.pair("00141000", "00142000", 0.97, 0.6)
    w.fn("a", "00141000", [f"FUN_{_NOT_A_PAIR}", "memcpy"], pseudocode="x = f(1);", size_bytes=64)
    w.fn("b", "00142000", ["strcpy"], pseudocode="x = f(1) + 1;", size_bytes=64)
    jump = "/* WARNING: Could not recover jumptable at 0x00151010. Too many branches */\n"
    jump += "(*(code *)UNRECOVERED_JUMPTABLE)();"
    w.pair("00151000", "00152000", 0.97, 0.9, instructions=40)
    w.fn("a", "00151000", ["foo"], pseudocode=jump, size_bytes=64)
    w.fn("b", "00152000", ["foo"], pseudocode=jump, size_bytes=60)
    w.commit()
    return w


def _pages(w: World, limit: int = 4, **kw: Any) -> list[dict[str, Any]]:
    """Every page of one scope through the read layer, in order (``limit`` small, so a fixture
    takes several pages)."""
    pages = []
    offset = 0
    while True:
        out = pv.get_diff_patch_view(w.atlas, DIFF, limit=limit, offset=offset, **kw)
        assert "error" not in out, out
        pages.append(out)
        if out.get("next_offset") is None:
            return pages
        offset = out["next_offset"]


def _listed(pages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [e for p in pages for e in p["entries"]]


def _by_id(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out = {e["entry_id"]: e for e in entries}
    assert len(out) == len(entries)
    return out


def _deep_keys(value: Any) -> set[str]:
    """Every dict key at any depth."""
    if isinstance(value, dict):
        return set(value).union(*(_deep_keys(v) for v in value.values()))
    if isinstance(value, list):
        return set().union(*(_deep_keys(v) for v in value))
    return set()


def _micro_ids(w: World) -> set[str]:
    built = pv.build_diff_view(w.atlas, DIFF)
    assert built is not None
    pv._annotate_entries(built, pv._pseudo_readings(w.atlas, built))
    return {e.entry_id for e in built.entries if pv._anchored_micro_side(e)}


# The field rules of a summary entry, written out here apart from patch_view's projection so the
# two are checked against each other.
_S_COPY = (
    "entry_id bucket subclass tier blind_spots review_state addr_a addr_b name_a name_b "
    "similarity export_gap_a export_gap_b side addr name presence_state export_gap pairing "
    "callers_b b_other_fn_mentions pseudocode_sameness text_unverified_reasons significance "
    "rows_total rows_by_presence"
).split()
_S_COUNTS = {
    "rows_total",
    "count",
    "structural_spans",
    "substitutions_total",
    "calls_differ",
    "var_const_total",
    "linked_not_shown",
    "renumbered_in_a",
    "markers",
}
_S_SWAP = (
    "pairing",
    "callees_complete",
    "narrow",
    "not_narrow",
    "sinks_only_in_a",
    "sinks_only_in_b",
)
_S_REDUCED_OR_DERIVED = {
    "subclasses",
    "facts",
    "coclaimed_by_count",
    "callee_set",
    "sink_callee_swap",
    "callers_a",
    "string_edges",
    "guard_scan",
    "hidden_region",
    "bodies",
    "delta_summary",
    "anchored_differs",
    "anchor",
    "in_read_first",
    "demoted",
    "anchored_micro_side",
    "proposed_pair_summary",
}
_S_ENTRY_KEYS = set(_S_COPY) | _S_REDUCED_OR_DERIVED
# Never in a summary entry, at any depth: the rows, the bodies, the guards and their listing.
_S_NEVER = {
    "rank_key",
    "rows",
    "pseudocode_delta",
    "inline_hunk",
    "guards",
    "proposed_pair_reading",
    "anchor_ref",
    "alignment_confidence",
    "alignment_state",
    "rows_next_offset",
    "rows_order",
    "rows_by_order_group",
    "sink_axes_with",
    "sink_axes_withheld_rows",
    "structural",
    "substitution_groups",
    "substitutions",
    "calls",
    "read_with",
    "shown_rule",
    "listing",
    "listing_note",
    "sample",
    "changed",
    "occurrences",
    "named_callees_differ",
    "only_in_a",
    "only_in_b",
}


def _s_drop(key: str, value: Any) -> bool:
    if value is None or value == [] or value == {}:
        return True
    return not isinstance(value, bool) and key in _S_COUNTS and value == 0


def _s_kept(fields: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in fields.items() if not _s_drop(k, v)}


def _s_delta(d: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"kind": d["kind"]}
    if "reason" in d:
        out["reason"] = d["reason"]
    if "structural_spans" in d:
        out["structural_spans"] = d["structural_spans"]
    if "substitutions" in d:
        out["substitutions_total"] = sum(v["total"] for v in d["substitutions"].values())
    if "calls" in d:
        out["calls_differ"] = len(d["calls"])
    if "line_number_form" in d:
        out["line_number_form"] = True
    out = _s_kept(out)
    if "inline_hunk" in d:
        h = d["inline_hunk"]
        out["hunk"] = {
            k: h[k] for k in ("structural_lines", "groups", "withheld", "lines") if k in h
        }
    return out


def _s_guard_scan(g: dict[str, Any]) -> dict[str, Any]:
    if "reason" in g:
        return dict(g)
    return _s_kept({k: v for k, v in g.items() if k != "shown_rule"})


def _s_callee_set(cs: dict[str, Any]) -> dict[str, Any]:
    out = {"state": cs["state"]}
    if cs["state"] == "undetermined":
        out["reason"] = cs["reason"]
    return out


def _s_hidden(h: dict[str, Any]) -> dict[str, Any]:
    out = _s_kept({"body": h["body"], "markers": len(h["markers"])})
    refs = {s: n for s, n in h["unrecovered_jumptable_refs"].items() if n}
    if refs:
        out["unrecovered_jumptable_refs"] = refs
    return out


def _s_bodies(b: dict[str, Any]) -> dict[str, Any]:
    return {
        s: _s_kept({"status": v["status"], "size_bytes": v["size_bytes"]}) for s, v in b.items()
    }


def _s_proposed(pr: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"state": pr["state"]}
    if pr.get("text_unverified_reasons"):
        out["text_unverified_reasons"] = pr["text_unverified_reasons"]
    if pr.get("callee_set"):
        out["callee_set"] = _s_callee_set(pr["callee_set"])
    for key in ("a_body_elsewhere_in_b", "b_body_elsewhere_in_a"):
        if pr[key] is None:
            out[f"{key}_count"] = None
        elif pr[key]["count"]:
            out[f"{key}_count"] = pr[key]["count"]
    for key, fn, name in (
        ("pseudocode_delta", _s_delta, "delta_summary"),
        ("guard_scan", _s_guard_scan, "guard_scan"),
        ("hidden_region", _s_hidden, "hidden_region"),
        ("bodies", _s_bodies, "bodies"),
    ):
        if key in pr:
            out[name] = fn(pr[key])
    return out


def _rules_summary(full: dict[str, Any], micro: bool) -> dict[str, Any]:
    """The summary entry the field rules give for one full entry rendered with no inline row."""
    out: dict[str, Any] = {k: full[k] for k in _S_COPY if k in full and not _s_drop(k, full[k])}
    if full["subclasses"] and full["subclasses"] != [full["subclass"]]:
        out["subclasses"] = full["subclasses"]
    facts = [
        f for f in full["facts"] if not f.startswith("source_gap:") and f != "callee_set_unchanged"
    ]
    if facts:
        out["facts"] = facts
    if full["coclaimed_by"]:
        out["coclaimed_by_count"] = len(full["coclaimed_by"])
    if full["callee_set"]:
        out["callee_set"] = _s_callee_set(full["callee_set"])
    if "sink_callee_swap" in full:
        swap = full["sink_callee_swap"]
        out["sink_callee_swap"] = _s_kept({k: swap[k] for k in _S_SWAP})
    if full.get("callers_a"):
        out["callers_a"] = {"count": full["callers_a"]["count"]}
    if full["string_edges"] and full["string_edges"]["by_delta_kind"]:
        out["string_edges"] = {"by_delta_kind": full["string_edges"]["by_delta_kind"]}
    for key, fn, name in (
        ("guard_scan", _s_guard_scan, "guard_scan"),
        ("hidden_region", _s_hidden, "hidden_region"),
        ("bodies", _s_bodies, "bodies"),
        ("pseudocode_delta", _s_delta, "delta_summary"),
    ):
        if key in full:
            out[name] = fn(full[key])
    if "proposed_pair_reading" in full:
        pr = full["proposed_pair_reading"]
        out.update(
            {
                k: pr[k]
                for k in ("anchored_differs", "anchor", "in_read_first", "demoted")
                if k in pr
            }
        )
        out["proposed_pair_summary"] = _s_proposed(pr)
    if micro:
        out["anchored_micro_side"] = True
    return out


def _world_of(tmp_path: Path, which: int) -> World:
    """0: the summary world; 1: the placement world (string edges, P entries, the source-gap /
    callee_set_unchanged / one_hop_sink facts); 2: one undetermined pair per proposed reading (a
    body found elsewhere, text_unverified reasons, readings with no body); 3: the swap world (an
    aligned micro pair's one_side_skipped_micro, every shape of sink_callee_swap)."""
    if which == 0:
        return _summary_world(tmp_path)
    if which == 1:
        w = World(tmp_path)
        _rich(w)
        return w
    if which == 2:
        return _undetermined_world(tmp_path)
    return _swap_world(tmp_path)[0]


def test_a_summary_entry_carries_its_whitelisted_keys_only(tmp_path: Path, current: None) -> None:
    """★ A summary entry carries no row, body, guard, rank_key or anchor_ref — at any depth — and
    no key outside its whitelist, over a world holding an R entry, a hunk, a guard, more rows than
    the window, E and P; the full entries of the same world do carry the keys left out.

    MUTATION (verified RED, 7 failed): put pseudocode_delta in the copied keys -> RED."""
    w = _summary_world(tmp_path)
    summary = _listed(_pages(w, detail="summary"))
    full = _listed(_pages(w, rows_limit=0))
    assert {"A", "B", "C", "R", "E", "P"} <= {e["bucket"] for e in summary}
    by_id = _by_id(summary)
    assert by_id[MANY_ROWS].get("rows_total", 0) > pv.ROWS_INLINE_LIMIT
    assert "hunk" in by_id[ALIGNED].get("delta_summary", {})
    assert "guard_scan" in by_id[ALIGNED]
    assert "guard_scan" in by_id[PROPOSED].get("proposed_pair_summary", {})
    left_out = _S_NEVER & set().union(*(_deep_keys(e) for e in full))
    assert {"rank_key", "rows", "pseudocode_delta", "inline_hunk", "guards"} <= left_out
    assert {"proposed_pair_reading", "anchor_ref", "rows_by_order_group", "shown_rule"} <= left_out
    for e in summary:
        assert set(e) <= _S_ENTRY_KEYS, (e["entry_id"], set(e) - _S_ENTRY_KEYS)
        assert not _deep_keys(e) & _S_NEVER, (e["entry_id"], _deep_keys(e) & _S_NEVER)


@pytest.mark.parametrize("band", [False, True])
@pytest.mark.parametrize("sort_by", [None, "tier", "similarity", "address", "significance"])
def test_the_two_details_list_the_same_entries_with_the_same_counts(
    tmp_path: Path, current: None, sort_by: str | None, band: bool
) -> None:
    """★ A presentation changes nothing a reading rests on: under one sort, filter set and band,
    both details page the same entry ids in the same order, with the same totals, counts,
    not_listed and review_progress on every page.

    MUTATION (verified RED, 10 failed): order the page by entry_id before projecting -> RED."""
    w = _summary_world(tmp_path)
    first = _listed(_pages(w))
    w.judge(DIFF, _by_id(first)[R_HEAD]["anchor_ref"], "changed_real")
    w.judge(DIFF, _by_id(first)[EDGE]["anchor_ref"], "change_inconclusive")
    kw: dict[str, Any] = {"sort_by": sort_by, "band": band}
    full, summary = _pages(w, **kw), _pages(w, detail="summary", **kw)
    ids = [e["entry_id"] for e in _listed(full)]
    assert ids != sorted(ids)  # the order is not the id order, so a re-sort shows
    assert [e["entry_id"] for e in _listed(summary)] == ids
    assert len(full) == len(summary) > 2
    for f, s in zip(full, summary, strict=True):
        for key in ("total_entries", "next_offset", "counts", "not_listed", "review_progress"):
            assert s[key] == f[key], key


@pytest.mark.parametrize("which", [0, 1, 2, 3])
def test_a_summary_entry_is_its_full_entry_projected(
    tmp_path: Path, current: None, which: int
) -> None:
    """★ Each summary entry is exactly what the field rules give from the same entry rendered in
    full with no inline row (rows_limit=0): the copied fields byte for byte, the reduced and
    derived ones computed from it. Over four worlds holding every shape the rules name (each
    world's own shape asserted, so none is read empty).

    MUTATION (verified RED, 4 failed): leave rows_by_presence out of the copied keys -> RED.
    MUTATION (verified RED, 2 failed): do not lift anchored_differs onto the entry -> RED.
    MUTATION (verified RED, 4 failed): drop sink_callee_swap.pairing -> RED.
    MUTATION (verified RED, 5 failed): drop sink_callee_swap.callees_complete -> RED."""
    w = _world_of(tmp_path, which)
    micro = _micro_ids(w)
    full = _by_id(_listed(_pages(w, rows_limit=0)))
    summary = _by_id(_listed(_pages(w, detail="summary")))
    assert set(summary) == set(full)
    for eid, s in summary.items():
        assert s == _rules_summary(full[eid], eid in micro), eid
    shape = {
        0: lambda: micro == {R_MICRO} and summary[R_HEAD].get("anchored_differs") is True,
        1: lambda: any("string_edges" in s for s in summary.values()),
        2: lambda: any(
            (s.get("proposed_pair_summary") or {}).get("a_body_elsewhere_in_b_count")
            for s in summary.values()
        ),
        3: lambda: any("one_side_skipped_micro" in s.get("facts", ()) for s in summary.values()),
    }[which]
    assert shape()


def test_a_coclaimed_entry_gives_how_many_functions_coclaim_it(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An entry whose rows were co-claimed by other functions' degraded candidates gives, in a
    summary, how many co-claimers there are (both sides counted), not the list."""
    w = _window_world(tmp_path, monkeypatch, "PP")
    rows = [
        replace(_win_row("P", 0), coclaimed_by=["00009000", "0000a000"]),
        replace(_win_row("P", 1), coclaimed_by_b=["0000b000"]),
    ]
    monkeypatch.setattr(
        pv,
        "compute_sink_overlay",
        lambda atlas, diff_id: so.SinkOverlayResult(
            list(rows), so.SinkOverlayCoverage(0, 0, 0, 0, 0, False)
        ),
    )
    full = _by_id(_listed(_pages(w, rows_limit=0)))[_WIN_ID]
    s = _by_id(_listed(_pages(w, detail="summary")))[_WIN_ID]
    assert full["coclaimed_by"] == ["a:00009000", "a:0000a000", "b:0000b000"]
    assert s.get("coclaimed_by_count") == 3 and "coclaimed_by" not in s
    assert s == _rules_summary(full, False)


@pytest.mark.parametrize("which", [0, 1])
def test_the_anchor_template_rebuilds_every_entrys_anchor(
    tmp_path: Path, current: None, which: int
) -> None:
    """★ annotation.anchor_ref_template, filled with a summary entry's own addresses (addr_a /
    addr_b, or side / addr), is that entry's anchor_ref as the full entry gives it — on every page.

    MUTATION (verified RED, 2 failed): swap {addr_a} and {addr_b} in the template -> RED."""
    w = _world_of(tmp_path, which)
    full = _by_id(_listed(_pages(w)))
    pages = _pages(w, detail="summary")
    seen = {"pair": 0, "presence": 0}
    for page in pages:
        template = page["annotation"]["anchor_ref_template"]
        for e in page["entries"]:
            if "addr_a" in e:
                anchor = template["function_pair"]
                anchor = anchor.replace("{addr_a}", e["addr_a"]).replace("{addr_b}", e["addr_b"])
                seen["pair"] += 1
            else:
                anchor = template["function_presence"]
                anchor = anchor.replace("{side}", e["side"]).replace("{addr}", e["addr"])
                seen["presence"] += 1
            assert anchor == full[e["entry_id"]]["anchor_ref"], e["entry_id"]
    assert seen["pair"] > 3 and seen["presence"] > 0


# Recorded from the code before ``detail`` existed: the summary world's entries through the MCP
# tool, one key per call below. Re-record it only when a full entry changes on purpose. "default"
# and "scan" were recorded with no sort_by, when that was the order now named candidate_tier.
_FULL_GOLDEN = Path(__file__).resolve().parents[2] / "fixtures" / "patch_view_full_entries.json"
_GOLDEN_CALLS: dict[str, dict[str, Any]] = {
    "default": {"sort_by": "candidate_tier"},
    "scan": {"rows_limit": 0, "sort_by": "candidate_tier"},
    "significance": {"sort_by": "significance"},
    "not_listed": {"not_listed_page": "aligned_pseudocode_differs"},
}


def test_a_full_entry_is_byte_for_byte_what_it_was_before_the_summary(
    tmp_path: Path, current: None
) -> None:
    """★ detail='full' (the default) leaves every entry as it was: the summary world's pages
    through the MCP tool — the default window, a scan (rows_limit=0), the significance sort and
    the not-listed page — hold byte for byte the entries recorded in the fixture file from the
    code before detail existed. No entry on these pages is cut for the page budget, so only the
    envelope may differ."""
    golden = json.loads(_FULL_GOLDEN.read_text())
    assert set(golden) == set(_GOLDEN_CALLS)
    w = _summary_world(tmp_path)
    tool = mcp_app.make_tools(w.path)["get_diff_patch_view"]
    for name, kw in _GOLDEN_CALLS.items():
        entries: list[dict[str, Any]] = []
        offset: int | None = 0
        while offset is not None:
            out = tool(DIFF, offset=offset, **kw)
            assert "error" not in out and "over_budget" not in out, out
            assert "page_budget" not in json.dumps(out["entries"])
            entries += out["entries"]
            offset = out["next_offset"]
        assert len(entries) == len(golden[name]) > 0, name
        assert json.dumps(entries) == json.dumps(golden[name]), name


def test_a_summary_page_leaves_what_it_read_as_it_was(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The projection builds new objects only. In one process, after the summary pages (listed,
    significance, not-listed) are read with the caches left warm, the full pages read byte for
    byte as they did from cold caches, and every build those summary pages read keeps a fresh
    build's judgement bases (entry_facts, row_facts).

    MUTATION (verified RED, 1 failed — this test alone): in the projection, pop structural /
    substitution_groups / read_with off the cached inline_hunk in place -> RED."""
    w = _summary_world(tmp_path)
    not_listed = {"not_listed_page": "aligned_pseudocode_differs"}

    def full_pages() -> str:
        return json.dumps([_pages(w), _pages(w, rows_limit=0), _pages(w, **not_listed)])

    cold = full_pages()
    pv._clear_view_caches()
    builds: list[pv.BuiltDiff] = []
    real = pv.build_diff_view

    def keep(atlas: Any, diff_id: str) -> Any:
        built = real(atlas, diff_id)
        builds.append(built)
        return built

    monkeypatch.setattr(pv, "build_diff_view", keep)
    for kw in ({}, {"sort_by": "significance"}, not_listed):
        _pages(w, detail="summary", **kw)
    monkeypatch.setattr(pv, "build_diff_view", real)
    assert builds and len(pv._DELTA_CACHE) > 0
    assert full_pages() == cold
    fresh = real(w.atlas, DIFF)
    assert fresh is not None
    want = {e.entry_id: dr.entry_facts(e) for e in fresh.placed}
    rows = {e.entry_id: [dr.row_facts(v) for v in e.row_views] for e in fresh.placed}
    for built in builds:
        for e in built.placed:
            assert dr.entry_facts(e) == want[e.entry_id]
            assert [dr.row_facts(v) for v in e.row_views] == rows[e.entry_id]


def _env_paths(page: dict[str, Any]) -> set[str]:
    """The keys of the three envelope blocks that hold first-page texts, as paths."""
    return {f"{k}.{sub}" for k in ("lens", "review_progress", "annotation") for sub in page[k]}


_PROGRESS_EVERY_PAGE = (
    "unit",
    "scope",
    "total",
    "looked_at",
    "not_looked_at",
    "page_size",
    "pages_total",
    "pages_remaining",
    "states",
    "by_bucket",
    "verdict_shape",
    "dangling_annotations",
    "outside_this_scope",
    "blind_spots",
    "complete",
)
_ANNOTATION_EVERY_PAGE = (
    "available",
    "annotate_diff",
    "no_real_change_needs",
    "candidate_anchor",
    "promote",
    "review_with",
    "by_bucket",
    "anchor_ref_template",
)
_ENVELOPE_EVERY_PAGE = (
    "legend",
    "caveats",
    "counts",
    "not_listed",
    "subject_counts",
    "banners",
    "available_views",
    "detail",
    "baseline_state",
    "overlay_coverage",
    "guards_read_with",
)


@pytest.mark.parametrize("detail", ["full", "summary"])
@pytest.mark.parametrize(
    "scope",
    [
        {},
        {"sort_by": "significance"},
        {"band": True, "bucket": "R", "anchored_differs": True},
        {"anchored_micro_side": True},
    ],
)
def test_a_later_page_names_what_it_leaves_to_the_first(
    tmp_path: Path, current: None, detail: str, scope: dict[str, Any]
) -> None:
    """★ The long texts that are the same on every page of a scope come on its first page (offset
    0) only: the lens's order and filter texts, review_progress.next_page, annotation.what /
    promote_note. A later page lists exactly the keys it left out in first_page_only.keys, and
    gives the progress note as its 'complete' sentence alone, said in first_page_only.shortened.
    Every count, the ledger with its samples and notes, the legend, the caveats and the
    annotation calls stay on every page, named one by one — in both details.

    MUTATION (verified RED, 13 failed): treat every page as a later one -> RED.
    MUTATION (verified RED, 12 failed): leave first_page_only off a later page -> RED.
    MUTATION (verified RED, 8 failed): leave no_real_change_needs off a later page -> RED.
    MUTATION (verified RED, 8 failed): leave complete off a later page's progress (and list it
    in first_page_only.keys) -> RED.
    MUTATION (verified RED, 9 failed): shorten the note without listing it in shortened -> RED."""
    w = _summary_world(tmp_path)
    first = pv.get_diff_patch_view(w.atlas, DIFF, limit=1, detail=detail, **scope)
    later = pv.get_diff_patch_view(w.atlas, DIFF, limit=1, offset=1, detail=detail, **scope)
    assert "error" not in first and "error" not in later, (first, later)
    assert "first_page_only" not in first
    assert set(later) - set(first) == {"first_page_only"} and set(first) <= set(later)
    fpo = later["first_page_only"]
    assert set(fpo) == {"keys", "shortened", "read_with"}
    assert fpo["read_with"] == "the same call with offset=0"
    omitted = _env_paths(first) - _env_paths(later)
    assert len(fpo["keys"]) == len(set(fpo["keys"])) and set(fpo["keys"]) == omitted
    want = {"lens.order", "review_progress.next_page", "annotation.what", "annotation.promote_note"}
    want |= {f"lens.{k}" for k in ("band", "anchored_differs", "anchored_micro_side") if k in scope}
    assert omitted == want
    assert first["review_progress"]["note"] == dr.PROGRESS_NOTE
    assert later["review_progress"]["note"] == dr.PROGRESS_NOTE_COMPLETE
    assert fpo["shortened"] == ["review_progress.note"]
    for key in _PROGRESS_EVERY_PAGE:
        assert key in later["review_progress"], key
        assert later["review_progress"][key] == first["review_progress"][key], key
    for key in _ANNOTATION_EVERY_PAGE:
        assert key in later["annotation"], key
        assert later["annotation"][key] == first["annotation"][key], key
    for key in _ENVELOPE_EVERY_PAGE:
        assert later[key] == first[key], key
    assert any("sample" in s for s in later["blind_spots"])
    assert any("note" in s for s in later["blind_spots"])
    assert later["blind_spots"] == first["blind_spots"]
    lens_every_page = ["view", "sort_by", "filters", "switchable"]
    if scope.get("sort_by") == "significance":
        lens_every_page += ["significance", "sunk_with_body_size_differs"]
    for key in lens_every_page:
        assert later["lens"][key] == first["lens"][key], key


def test_a_withheld_diff_keeps_its_progress_and_annotation_on_every_page(
    tmp_path: Path, current: None
) -> None:
    """A diff undetermined as a whole has a withheld progress block and an unavailable annotation
    block: neither is shortened past the first page, and first_page_only names neither.

    MUTATION (verified RED, 1 failed): shorten a withheld progress block too -> RED."""
    w = _summary_world(tmp_path)
    w.atlas.execute("UPDATE diff_meta SET version_skew = 1")
    w.commit()
    first = pv.get_diff_patch_view(w.atlas, DIFF, limit=1)
    later = pv.get_diff_patch_view(w.atlas, DIFF, limit=1, offset=1)
    assert first["review_progress"].get("withheld") is True
    assert first["annotation"].get("available") is False
    assert later["review_progress"] == first["review_progress"]
    assert later["annotation"] == first["annotation"]
    assert "first_page_only" in later
    assert later["first_page_only"] == {
        "keys": ["lens.order"],
        "shortened": [],
        "read_with": "the same call with offset=0",
    }


def test_reading_one_entry_carries_the_first_pages_envelope(tmp_path: Path, current: None) -> None:
    """entry_id reads at offset 0, so its envelope is a first page's: every first-page text, the
    whole note, no first_page_only; the views listed by name, detail named."""
    w = _summary_world(tmp_path)
    one = pv.get_diff_patch_view(w.atlas, DIFF, entry_id=R_HEAD)
    first = pv.get_diff_patch_view(w.atlas, DIFF, limit=1)
    assert "first_page_only" not in one
    assert _env_paths(one) == _env_paths(first)
    assert one["review_progress"]["note"] == dr.PROGRESS_NOTE
    assert one["detail"] == "full" and one["available_views"] == list(pv.VIEWS)
    assert one["lens"]["switchable"].endswith(" / detail")
    assert "anchor_ref_template" in one["annotation"]


@pytest.mark.parametrize("view", ["string_edge", "candidate_flat"])
def test_the_other_views_take_the_first_page_rule_too(world: World, view: str) -> None:
    """The envelope is the same in every view, and so is its first-page rule."""
    first = pv.get_diff_patch_view(world.atlas, DIFF, view=view, limit=1)
    later = pv.get_diff_patch_view(world.atlas, DIFF, view=view, limit=1, offset=1)
    assert "error" not in later and later["entries"]
    assert "first_page_only" not in first and "order" in first["lens"]
    assert "order" not in later["lens"] and "lens.order" in later["first_page_only"]["keys"]


@pytest.mark.parametrize(
    ("kw", "match"),
    [
        ({"detail": "compact"}, "detail must be 'full' or 'summary', got 'compact'"),
        ({"detail": None}, "detail must be 'full' or 'summary', got None"),
        (
            {"detail": "summary", "entry_id": ALIGNED},
            "entry_id reads one entry in full: detail='summary' does not apply there",
        ),
        ({"detail": "summary", "view": "candidate_flat", "offset": 3}, "nothing to page"),
        ({"detail": "summary", "rows_limit": -1}, "rows_limit must be an integer >= 0"),
        ({"detail": "summary", "rows_limit": True}, "rows_limit must be an integer >= 0"),
    ],
)
def test_a_detail_it_cannot_honour_is_an_error(
    tmp_path: Path, current: None, kw: dict[str, Any], match: str
) -> None:
    """A combination the summary cannot honour is refused by name, never silently ignored.

    MUTATION (verified RED, 1 failed): let detail='summary' take an entry_id -> RED."""
    out = pv.get_diff_patch_view(_guard_world(tmp_path).atlas, DIFF, **kw)
    assert match in out.get("error", ""), out
    assert "entries" not in out


def test_a_summary_ignores_a_valid_rows_limit(tmp_path: Path, current: None) -> None:
    """A summary entry carries no row, so a valid rows_limit changes nothing on its pages (an
    invalid one is still refused, above).

    MUTATION (verified RED, 5 failed): window a summary's entries by rows_limit -> RED."""
    w = _summary_world(tmp_path)
    seen = {json.dumps(_pages(w, detail="summary", rows_limit=n)) for n in (0, 1, 7, 20)}
    assert len(seen) == 1


@pytest.mark.parametrize(
    ("make", "name"),
    [
        (_summary_world, "aligned_pseudocode_differs"),
        (_qualified_world, "aligned_pseudocode_identical_text_unverified"),
    ],
)
def test_a_not_listed_summary_gives_each_pair_its_counts(
    tmp_path: Path, current: None, make: Any, name: str
) -> None:
    """A not-listed pair in a summary: its addresses, similarity, sameness, body and reasons as
    they are, its delta as counts and its guard scan without shown_rule — no delta, no guard.
    The page's total and next offset are the full page's."""
    w = make(tmp_path)
    full = pv.get_diff_patch_view(w.atlas, DIFF, not_listed_page=name)
    summary = pv.get_diff_patch_view(w.atlas, DIFF, not_listed_page=name, detail="summary")
    assert (summary["total_entries"], summary["next_offset"]) == (
        full["total_entries"],
        full["next_offset"],
    )
    assert len(summary["entries"]) == len(full["entries"]) > 0
    copied = (
        "entry_id",
        "addr_a",
        "addr_b",
        "similarity",
        "pseudocode_sameness",
        "body",
        "text_unverified_reasons",
    )
    for f, s in zip(full["entries"], summary["entries"], strict=True):
        want = {k: f[k] for k in copied if k in f and not _s_drop(k, f[k])}
        if "pseudocode_delta" in f:
            want["delta_summary"] = _s_delta(f["pseudocode_delta"])
        if "guard_scan" in f:
            want["guard_scan"] = _s_guard_scan(f["guard_scan"])
        assert s == want
    shown = {k for s in summary["entries"] for k in s}
    assert ("delta_summary" in shown) or ("body" in shown)


def test_a_candidate_flat_summary_is_the_overlays_own_summary(
    tmp_path: Path, current: None
) -> None:
    """view='candidate_flat' with detail='summary' gives get_diff_sink_overlay(detail='summary')'s
    counts and the row count, and no row to page."""
    w = _summary_world(tmp_path)
    tools = mcp_app.make_tools(w.path)
    flat = tools["get_diff_patch_view"](DIFF, view="candidate_flat", detail="summary")
    rows = tools["get_diff_patch_view"](DIFF, view="candidate_flat")
    overlay = tools["get_diff_sink_overlay"](diff_id=DIFF, detail="summary")
    assert "error" not in flat, flat
    assert "entries" not in flat and "next_offset" not in flat
    assert flat["summary"] == overlay["summary"]
    assert flat["total_entries"] == rows["total_entries"] > pv.ROWS_INLINE_LIMIT


def test_a_string_edge_summary_changes_the_envelope_only(world: World) -> None:
    """string_edge rows have no compact form: a summary gives them as they are and says so."""
    full = pv.get_diff_patch_view(world.atlas, DIFF, view="string_edge")
    summary = pv.get_diff_patch_view(world.atlas, DIFF, view="string_edge", detail="summary")
    assert summary["entries"] == full["entries"] and len(full["entries"]) == 2
    assert summary["detail_note"] == (
        "string_edge rows have no compact form; detail='summary' changes the envelope only"
    )
    assert "detail_with" not in summary and "detail_note" not in full


@pytest.mark.parametrize("cap", ["DELTA_LINE_PRODUCT_CAP", "DELTA_TOKEN_PRODUCT_CAP"])
def test_a_delta_that_was_not_computed_counts_nothing(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch, cap: str
) -> None:
    """★ A delta over either product cap is not_computed, and its summary says only that — kind,
    reason, and the hunk's why — never a structural_spans / substitutions_total / calls_differ /
    line_number_form it does not have; its guard scan, not extracted, is given as it is.

    MUTATION (verified RED, 6 failed): give calls_differ with a fallback after the empty-value
    rule (``out["calls_differ"] = len(delta.get("calls", {}))``) -> RED. Before that rule the
    fallback's 0 is left out like any 0 count, so it cannot reach a page (verified: 0 failed, an
    equivalent mutant)."""
    monkeypatch.setattr(sameness, cap, 0)
    w = _summary_world(tmp_path)
    summary = _listed(_pages(w, detail="summary"))
    not_listed = pv.get_diff_patch_view(
        w.atlas, DIFF, detail="summary", not_listed_page="aligned_pseudocode_differs"
    )["entries"]
    proposed = [e["proposed_pair_summary"] for e in summary if "proposed_pair_summary" in e]
    blocks = [*summary, *proposed, *not_listed]
    # (an insert-only block costs no token pair, so under the token cap a few deltas still compute)
    deltas = [b["delta_summary"] for b in blocks if "delta_summary" in b]
    not_computed = [d for d in deltas if d["kind"] == "not_computed"]
    assert len(not_computed) > 5
    for d in not_computed:
        assert set(d) <= {"kind", "reason", "hunk"}, d
        assert d["reason"] == "too_large"
        assert set(d["hunk"]) <= {"withheld", "lines", "structural_lines", "groups"}
    withheld = [b["guard_scan"] for b in blocks if "reason" in b.get("guard_scan", {})]
    assert withheld
    for scan in withheld:
        assert scan == {"state": "not_extracted", "reason": "too_large"}


def test_a_zero_count_hunk_is_given_as_it_is(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A too-large delta whose trimmed middle shows nothing carries a 0 / 0 hunk: the summary
    gives it whole (the middle was computed and holds nothing to show), not as an absent hunk."""
    monkeypatch.setattr(sameness, "DELTA_LINE_PRODUCT_CAP", 10)
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 0.6)
    w.fn("a", "00001000", ["foo"], pseudocode="void f(void)\n{\n  x = y + 1;\n}")
    w.fn("b", "00002000", ["foo"], pseudocode="void f(void)\n{\n  x  =  y+1;\n\n}")
    w.commit()
    (full,) = pv.get_diff_patch_view(w.atlas, DIFF, rows_limit=0)["entries"]
    (s,) = pv.get_diff_patch_view(w.atlas, DIFF, detail="summary")["entries"]
    assert full["pseudocode_delta"]["inline_hunk"]["structural_lines"] == 0
    assert full["pseudocode_delta"]["inline_hunk"]["groups"] == 0
    assert s["delta_summary"] == {
        "kind": "not_computed",
        "reason": "too_large",
        "hunk": {"structural_lines": 0, "groups": 0},
    }


def test_substitutions_total_counts_substitutions_not_token_kinds(
    tmp_path: Path, current: None
) -> None:
    """A number substituted twice and a name once are three substitutions of two kinds.

    MUTATION (verified RED, 1 failed): count the kinds (len(substitutions)) -> RED."""
    w = World(tmp_path)
    w.pair("00001000", "00002000", 0.97, 0.6)
    w.fn("a", "00001000", ["foo"], pseudocode="x = 5;\ny = 5;\nz = a;")
    w.fn("b", "00002000", ["foo"], pseudocode="x = 6;\ny = 6;\nz = b;")
    w.commit()
    (full,) = pv.get_diff_patch_view(w.atlas, DIFF, rows_limit=0)["entries"]
    (s,) = pv.get_diff_patch_view(w.atlas, DIFF, detail="summary")["entries"]
    subs = full["pseudocode_delta"]["substitutions"]
    assert {k: v["total"] for k, v in subs.items()} == {"ident": 1, "number": 2}
    assert s["delta_summary"]["substitutions_total"] == 3


def test_every_boolean_is_given_and_only_one_reading_is_left_out(
    tmp_path: Path, current: None
) -> None:
    """★ A summary gives every boolean true or false — callees_complete / narrow false on a
    difference read in part, in_read_first false below the floor and when demoted, demoted false
    when the proof is missing, b_other_fn_mentions false on an E entry (and on no other) — and
    leaves out only what reads one way: a null export gap (a recorded one is given). The guard
    scan keeps coverage and loses shown_rule; a hidden region keeps its jump-table counts; a
    body-elsewhere count that could not be read is null, the key present.

    MUTATION (verified RED, 4 failed, and 4 for callees_complete alone): treat a false boolean
    as empty -> RED.
    MUTATION (verified RED, 2 failed): leave b_other_fn_mentions out when false -> RED.
    MUTATION (verified RED, 4 failed): keep shown_rule in the guard scan -> RED.
    MUTATION (verified RED, 6 failed): leave a null body-elsewhere count out, as a 0 -> RED."""
    w = _summary_world(tmp_path)
    full = _by_id(_listed(_pages(w, rows_limit=0)))
    s = _by_id(_listed(_pages(w, detail="summary")))
    assert PARTIAL in s and R_LOW in s and R_KEPT in s and R_DEMOTED in s and EDGE in s
    swap = s[PARTIAL].get("sink_callee_swap") or {}
    assert swap.get("callees_complete") is False and swap.get("narrow") is False
    assert swap.get("not_narrow") == "callee_identity_unresolved"
    assert s[R_LOW].get("in_read_first") is False and "demoted" not in s[R_LOW]
    assert s[R_KEPT].get("demoted") is False and s[R_KEPT].get("in_read_first") is True
    assert s[R_DEMOTED].get("demoted") is True and s[R_DEMOTED].get("in_read_first") is False
    assert s[EDGE].get("b_other_fn_mentions") is False
    assert [k for k, e in s.items() if "b_other_fn_mentions" in e] == [EDGE]
    assert full[R_GAP]["export_gap_b"] is None and "export_gap_b" not in s[R_GAP]
    assert s[R_GAP].get("export_gap_a") == "degenerate_block"
    assert s[P_GAP].get("export_gap") == "degenerate_block" and "export_gap" not in s[P_PLAIN]
    assert full[ALIGNED]["guard_scan"].get("shown_rule") == "b_order"
    assert "shown_rule" not in s[ALIGNED]["guard_scan"]
    assert s[ALIGNED]["guard_scan"].get("coverage") == "unjudged"
    assert s[JUMPTABLE].get("hidden_region") == {
        "body": "structure_differs",
        "markers": 2,
        "unrecovered_jumptable_refs": {"a": 1, "b": 1},
    }
    reading = full[R_MICRO]["proposed_pair_reading"]
    assert reading["a_body_elsewhere_in_b"] is None and reading["b_body_elsewhere_in_a"] is None
    ps = s[R_MICRO]["proposed_pair_summary"]
    for key in ("a_body_elsewhere_in_b_count", "b_body_elsewhere_in_a_count"):
        assert key in ps and ps[key] is None, key


def test_a_body_elsewhere_count_is_null_unread_left_out_at_zero_given_above(
    tmp_path: Path, current: None
) -> None:
    """The three readings of a body-elsewhere count, side by side: not read (null, given), read
    and 0 (left out), read and more (given); a proposed text_unverified reading keeps its
    reasons."""
    w = _undetermined_world(tmp_path)
    full = _by_id(_listed(_pages(w, rows_limit=0)))
    summary = _by_id(_listed(_pages(w, detail="summary")))
    seen = set()
    for eid, e in full.items():
        reading = e.get("proposed_pair_reading")
        if reading is None:
            continue
        ps = summary[eid]["proposed_pair_summary"]
        source = reading["a_body_elsewhere_in_b"]
        if source is None:
            assert "a_body_elsewhere_in_b_count" in ps and ps["a_body_elsewhere_in_b_count"] is None
            seen.add("null")
        elif source["count"] == 0:
            assert "a_body_elsewhere_in_b_count" not in ps
            seen.add("zero")
        else:
            assert ps.get("a_body_elsewhere_in_b_count") == source["count"]
            seen.add("more")
        if reading.get("text_unverified_reasons"):
            assert ps.get("text_unverified_reasons") == reading["text_unverified_reasons"]
            seen.add("reasons")
    assert seen == {"null", "zero", "more", "reasons"}


def test_a_summary_keeps_every_fact_but_the_two_said_elsewhere(
    world: World, tmp_path: Path
) -> None:
    """A summary's facts are the entry's facts less source_gap:* (in blind_spots) and
    callee_set_unchanged (in callee_set.state): one_hop_sink:* and one_side_skipped_micro stay.

    MUTATION (verified RED, 3 failed): drop facts whole -> RED.
    MUTATION (verified RED, 2 failed): drop one_hop_sink:* with the two -> RED."""
    full = _by_id(_listed(_pages(world, rows_limit=0)))
    summary = _by_id(_listed(_pages(world, detail="summary")))
    every = {f for e in full.values() for f in e["facts"]}
    assert "callee_set_unchanged" in every
    assert any(f.startswith("source_gap:") for f in every)
    assert any(f.startswith("one_hop_sink:") for f in every)
    for eid, e in full.items():
        kept = [
            f for f in e["facts"] if not f.startswith("source_gap:") and f != "callee_set_unchanged"
        ]
        assert summary[eid].get("facts", []) == kept, eid
    (tmp_path / "swap").mkdir()
    sw, ids = _swap_world(tmp_path / "swap")
    micro = _by_id(_listed(_pages(sw, detail="summary")))[ids["c_micro"]]
    assert "one_side_skipped_micro" in micro.get("facts", [])


def test_the_tool_says_how_a_summary_reads_and_which_detail_it_is() -> None:
    """The tool's description carries the reading rule of a summary word for word — with its two
    shapes that count nothing and its null — and says the two tools' detail switches differ."""
    doc = " ".join(
        (mcp_app.make_tools(Path("unused.db"))["get_diff_patch_view"].__doc__ or "").split()
    )
    assert (
        "In detail='summary' a missing count is 0 — except inside a delta_summary whose kind is "
        "not_computed, or a guard_scan that carries a reason: there nothing was counted. A "
        "body-elsewhere count that could not be read is null, not missing."
    ) in doc
    assert (
        "``detail`` here is ``full`` / ``summary``; get_diff_sink_overlay's ``detail`` is "
        "``summary`` / ``rows`` — a different switch."
    ) in doc
    assert "first_page_only" in doc and "anchor_ref_template" in doc


def test_the_complete_sentence_is_the_progress_notes_own() -> None:
    """A later page's note is the full note's own 'complete' sentence, whole."""
    assert dr.PROGRESS_NOTE_COMPLETE in dr.PROGRESS_NOTE
    assert dr.PROGRESS_NOTE_COMPLETE.startswith("'complete' means no entry in THIS scope")
    assert dr.PROGRESS_NOTE_COMPLETE.endswith("is not in any entry.")


def _copied_call(template: str, **fill: str) -> tuple[str, dict[str, Any]]:
    """A call copied from a template with its placeholders filled: its name and arguments, read by
    the Python parser — an argument left unquoted does not parse."""
    for key, value in fill.items():
        template = template.replace(f"<{key}>", value)
    try:
        node = ast.parse(template, mode="eval").body
    except SyntaxError as exc:
        pytest.fail(f"{template!r} is not a call that can be copied: {exc}")
    assert isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    return node.func.id, {kw.arg: ast.literal_eval(kw.value) for kw in node.keywords if kw.arg}


def test_a_summary_page_says_how_to_read_what_it_left_out(tmp_path: Path, current: None) -> None:
    """★ detail_with, by view: on a listed page a call reading one entry (and paging its rows) that
    works copied with a real entry_id; on a not-listed page the same call with detail='full' (no
    entry_id names such a pair); on candidate_flat the overlay rows' call; on string_edge none.

    MUTATION (verified RED, 2 failed): give the not-listed page the entry_id call -> RED.
    MUTATION (verified RED, 1 failed): leave the entry_id placeholder unquoted -> RED."""
    w = _summary_world(tmp_path)
    page = pv.get_diff_patch_view(w.atlas, DIFF, detail="summary")
    with_ = page["detail_with"]
    assert set(with_) == {"one_entry", "its_rows"}
    name, args = _copied_call(with_["one_entry"], entry_id=MANY_ROWS)
    assert (name, args) == ("get_diff_patch_view", {"diff_id": DIFF, "entry_id": MANY_ROWS})
    (one,) = pv.get_diff_patch_view(w.atlas, **args)["entries"]
    assert one["entry_id"] == MANY_ROWS and len(one["rows"]) == pv.ROWS_INLINE_LIMIT
    name, args = _copied_call(with_["its_rows"], entry_id=MANY_ROWS, n="20")
    assert (name, args) == (
        "get_diff_patch_view",
        {"diff_id": DIFF, "entry_id": MANY_ROWS, "rows_offset": 20},
    )
    (rest,) = pv.get_diff_patch_view(w.atlas, **args)["entries"]
    assert len(rest["rows"]) == 2
    nl = pv.get_diff_patch_view(
        w.atlas, DIFF, detail="summary", not_listed_page="aligned_pseudocode_differs"
    )
    assert nl["detail_with"] == {"its_detail": "the same call with detail='full'"}
    flat = pv.get_diff_patch_view(w.atlas, DIFF, detail="summary", view="candidate_flat")
    name, args = _copied_call(flat["detail_with"]["its_rows"])
    assert (name, args) == ("get_diff_sink_overlay", {"diff_id": DIFF, "detail": "rows"})
    rows = mcp_app.make_tools(w.path)["get_diff_sink_overlay"](**args)
    assert rows["total_rows"] == flat["total_entries"] and rows["rows"]
    edge = pv.get_diff_patch_view(w.atlas, DIFF, detail="summary", view="string_edge")
    assert "detail_with" not in edge
    assert "detail_with" not in pv.get_diff_patch_view(w.atlas, DIFF)


# ── the default order: significance; candidate_tier names the one before it ────────────────────

# The entry ids the candidate_tier order took on the summary world before significance became the
# default, per sort (recorded beside the fixture file's entries, which hold every one of them: on
# these pages an entry renders the same whatever the order, outside significance).
_ORDERS_BEFORE: dict[str, tuple[dict[str, Any], list[str]]] = {
    "tier": (
        {"sort_by": "tier"},
        [
            "pair:00003000:00004000",
            "pair:00001000:00002000",
            "pair:00101000:00102000",
            "pair:00005000:00006000",
            "pair:00136000:00137000",
            "pair:00132000:00132000",
            "pair:00135000:00135000",
            "pair:00131000:00131000",
            "pair:00133000:00133000",
            "pair:00134000:00134000",
            "pair:00141000:00142000",
            "pair:00151000:00152000",
            "pair:00111000:00112000",
            "a:00121000",
            "a:00122000",
        ],
    ),
    "similarity": (
        {"sort_by": "similarity"},
        [
            "pair:00136000:00137000",
            "pair:00132000:00132000",
            "pair:00135000:00135000",
            "pair:00141000:00142000",
            "pair:00005000:00006000",
            "pair:00003000:00004000",
            "pair:00001000:00002000",
            "pair:00101000:00102000",
            "pair:00131000:00131000",
            "pair:00133000:00133000",
            "pair:00134000:00134000",
            "pair:00151000:00152000",
            "pair:00111000:00112000",
            "a:00121000",
            "a:00122000",
        ],
    ),
    "address": (
        {"sort_by": "address"},
        [
            "pair:00001000:00002000",
            "pair:00003000:00004000",
            "pair:00005000:00006000",
            "pair:00101000:00102000",
            "pair:00111000:00112000",
            "pair:00131000:00131000",
            "pair:00132000:00132000",
            "pair:00133000:00133000",
            "pair:00134000:00134000",
            "pair:00135000:00135000",
            "pair:00136000:00137000",
            "pair:00141000:00142000",
            "pair:00151000:00152000",
            "a:00121000",
            "a:00122000",
        ],
    ),
    "anchored": (
        {"anchored_differs": True},
        [
            "pair:00131000:00131000",
            "pair:00134000:00134000",
            "pair:00133000:00133000",
            "pair:00132000:00132000",
        ],
    ),
}


def _tool_entries(tool: Any, **kw: Any) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    offset: int | None = 0
    while offset is not None:
        out = tool(DIFF, offset=offset, **kw)
        assert "error" not in out and "over_budget" not in out, out
        entries += out["entries"]
        offset = out["next_offset"]
    return entries


def test_the_other_orders_are_entry_for_entry_what_they_were(tmp_path: Path, current: None) -> None:
    """★ tier / similarity / address, and anchored_differs=true with no sort_by (its own order),
    list byte for byte the entries they listed before significance became the default, in the
    order they took then: no significance field, no attention in rank_key, nothing moved.

    MUTATION (verified RED, 3 failed — with the anchored-page and lens tests): judge the anchored
    page by the resolved sort (significance) instead of the sort_by given -> RED; MUTATION
    (verified RED, 3 failed, the same three): let the anchored page compute significance -> RED."""
    golden = {e["entry_id"]: e for e in json.loads(_FULL_GOLDEN.read_text())["default"]}
    w = _summary_world(tmp_path)
    tool = mcp_app.make_tools(w.path)["get_diff_patch_view"]
    for name, (kw, order) in _ORDERS_BEFORE.items():
        entries = _tool_entries(tool, **kw)
        assert [e["entry_id"] for e in entries] == order, name
        assert json.dumps(entries) == json.dumps([golden[k] for k in order]), name


def _scopes_j1() -> list[dict[str, Any]]:
    return [
        {},
        {"band": True},
        {"bucket": "B"},
        {"tier": "no_sink"},
        {"rows_limit": 0},
        {"anchored_micro_side": True},
        {"not_listed_page": "aligned_pseudocode_differs"},
    ]


@pytest.mark.parametrize("detail", ["full", "summary"])
def test_no_sort_by_reads_byte_for_byte_as_significance(
    tmp_path: Path, current: None, detail: str
) -> None:
    """★ On view='sink_patch' (anchored_differs aside) a page with no sort_by is byte for byte the
    page sort_by='significance' gives — every page of the scope, in both details, band on or off,
    under a filter, the not-listed page and one entry read alone — and it says so:
    lens.sort_by is 'significance' (a no-sort page that fell back to the candidate_tier order would
    still equal itself, so the lens is read too).

    MUTATION (verified RED, 4 failed — both details, with the lens and shape tests): resolve no
    sort_by to None (the candidate_tier order) -> RED; MUTATION (verified RED, 3 failed — both
    details, with the lens test): give a not-listed page the significance order -> RED."""
    w = _summary_world(tmp_path)
    pages = _pages(w, sort_by="candidate_tier")
    for e in _listed(pages)[:3]:
        w.judge(DIFF, e["anchor_ref"], "changed_real")
    for kw in _scopes_j1():
        plain = _pages(w, detail=detail, **kw)
        lens = _pages(w, detail=detail, sort_by="significance", **kw)
        assert json.dumps(plain) == json.dumps(lens), kw
        want = "default" if "not_listed_page" in kw else "significance"
        assert {p["lens"]["sort_by"] for p in plain} == {want}, kw
    if detail == "full":
        for e in _listed(pages):
            one = pv.get_diff_patch_view(w.atlas, DIFF, entry_id=e["entry_id"])
            same = pv.get_diff_patch_view(
                w.atlas, DIFF, entry_id=e["entry_id"], sort_by="significance"
            )
            assert json.dumps(one) == json.dumps(same)
            assert "significance" in one["entries"][0]
            assert "attention" in one["entries"][0]["rank_key"]


def test_the_lens_says_which_order_a_page_is_in(tmp_path: Path, current: None) -> None:
    """lens.sort_by is the order the page is actually in: significance with no sort_by, the name
    given otherwise, anchored_differs for that filter's own order, default for a not-listed page
    (address order, whatever sort_by says) and the other views. lens.order is the significance
    text on a significance page, the candidate_tier text on every other; lens.significance (the
    short text) only on a significance page, on every page of it; lens.band by the order.

    MUTATION (verified RED, 3 failed — with both J1 details): give a not-listed page the
    significance order's lens -> RED; MUTATION (verified RED, 1 failed — this test alone): give a
    significance page the candidate_tier band text -> RED."""
    w = _summary_world(tmp_path)

    def lens(**kw: Any) -> dict[str, Any]:
        out = pv.get_diff_patch_view(w.atlas, DIFF, **kw)
        assert "error" not in out, out
        return dict(out["lens"])

    sig = lens()
    assert sig["sort_by"] == "significance" and sig["order"] == pv._ORDER_SIGNIFICANCE
    assert sig["significance"] == pv._SIGNIFICANCE_LENS_SHORT
    assert "sunk_with_body_size_differs" in sig
    later = lens(offset=2, limit=2)
    assert later["significance"] == pv._SIGNIFICANCE_LENS_SHORT and "order" not in later
    ct = lens(sort_by="candidate_tier")
    assert ct["sort_by"] == "candidate_tier" and ct["order"] == pv._ORDER_CANDIDATE_TIER
    assert "significance" not in ct and "sunk_with_body_size_differs" not in ct
    for sort_by in ("tier", "similarity", "address"):
        other = lens(sort_by=sort_by)
        assert other["sort_by"] == sort_by and other["order"] == pv._ORDER_CANDIDATE_TIER
        assert "significance" not in other
    anchored = lens(anchored_differs=True)
    assert anchored["sort_by"] == "anchored_differs"
    assert anchored["order"] == pv._ORDER_CANDIDATE_TIER and "significance" not in anchored
    assert lens(anchored_differs=True, sort_by="significance")["sort_by"] == "significance"
    for kw in ({}, {"sort_by": "significance"}):
        nl = lens(not_listed_page="aligned_pseudocode_differs", **kw)
        assert nl["sort_by"] == "default" and nl["order"] == pv._ORDER_CANDIDATE_TIER
        assert "significance" not in nl
    for view in ("string_edge", "candidate_flat"):
        assert lens(view=view)["sort_by"] == "default"
    assert lens(band=True)["band"] == pv._BAND_SIGNIFICANCE
    assert lens(band=True, sort_by="candidate_tier")["band"] == pv._BAND_CANDIDATE_TIER
    assert lens(band=True, sort_by="tier")["band"] == pv._BAND_CANDIDATE_TIER


def test_the_short_significance_text_keeps_what_the_lens_cannot_see() -> None:
    """The text on every significance page says what the lens is blind to; the full rules are in
    the tool's description, which keeps every rule the long text gave.

    MUTATION (verified RED, 1 failed — this test alone): drop the 'Not seen by this lens'
    sentence -> RED."""
    short = pv._SIGNIFICANCE_LENS_SHORT
    assert "Not seen by this lens: " in short
    for blind in (
        "a constant in an allocation expression or a local buffer's declared size (blind_spots)",
        "the target a DAT_ / PTR_ reference points at once its address is blanked",
        "a C++ catch handler (landing pad)",
        "anything in a binary the two runs hold byte-identical",
    ):
        assert blind in short, blind
    doc = " ".join(
        (mcp_app.make_tools(Path("unused.db"))["get_diff_patch_view"].__doc__ or "").split()
    )
    for rule in (
        "a wide one still sinks",
        "a constant in an allocation expression or a local buffer's declared size",
        "anything in a binary the two runs hold byte-identical",
        "then those below it",
        "with no ``sort_by`` the page is in the ``significance`` order",
        "``sort_by='candidate_tier'`` is the order that was the default before it",
    ):
        assert rule in doc, rule


# The entries the T2 world judges: the first three of both the candidate_tier and the significance
# order (bucket A, every one of them), so that the first unjudged entry differs in each order.
_T2_JUDGED = ("pair:0002a000:0002b000", "pair:00001000:00002000", "pair:00003000:00004000")
_T2_FIRST = {
    "candidate_tier": "pair:00020000:00021000",
    "significance": "pair:0001c000:0001d000",
    "address": "pair:00005000:00006000",
}


def _t2_world(tmp_path: Path) -> World:
    w = World(tmp_path)
    _rich(w)
    base = _view(w, sort_by="candidate_tier")
    for eid in _T2_JUDGED:
        w.judge(DIFF, base["by_id"][eid]["anchor_ref"], "changed_real")
    w.commit()
    return w


def _first_named(annotation: dict[str, Any]) -> str:
    """The entry id the annotation block's promote call is filled in with."""
    found = re.search(r'entry_id="([^"]+)"', annotation["promote"])
    assert found is not None, annotation["promote"]
    return found.group(1)


def test_the_next_unjudged_entries_follow_the_order_of_the_page(
    tmp_path: Path, current: None
) -> None:
    """★ review_progress.next_page and the annotation block's first unjudged entry are named in
    the order the page is read in — significance with no sort_by, the order sort_by names
    otherwise — while every count stays the same whatever the order.

    MUTATION (verified RED, 2 failed — with the anchored-page test): name them in the
    candidate_tier order on every page -> RED; MUTATION (verified RED, 1 failed — this test alone):
    name them in the significance order on every page -> the address page goes RED."""
    w = _t2_world(tmp_path)
    by_bucket = _view(w, sort_by="candidate_tier")["by_id"]
    assert {k for k, e in by_bucket.items() if e["bucket"] == "A"} == set(_T2_JUDGED)
    counts: list[str] = []
    for sort_by in (None, "candidate_tier", "significance", "address", "tier", "similarity"):
        kw = {} if sort_by is None else {"sort_by": sort_by}
        order = [e["entry_id"] for e in _view(w, **kw)["entries"]]
        unjudged = [k for k in order if k not in _T2_JUDGED]
        page = pv.get_diff_patch_view(w.atlas, DIFF, limit=4, **kw)
        progress = page["review_progress"]
        named = [r["entry_id"] for r in progress["next_page"]]
        assert named == unjudged[: progress["page_size"]], sort_by
        assert _first_named(page["annotation"]) == unjudged[0], sort_by
        if sort_by in _T2_FIRST:
            assert unjudged[0] == _T2_FIRST[sort_by]
        counts.append(json.dumps({k: v for k, v in progress.items() if k != "next_page"}))
    assert len(set(counts)) == 1
    assert len(set(_T2_FIRST.values())) == 3  # the three orders really part here


def test_the_annotation_falls_back_to_the_whole_diff_when_the_scope_is_judged(
    tmp_path: Path, current: None
) -> None:
    """A scope with nothing left unjudged (bucket A, all three judged) names no next entry; the
    annotation block then names the whole diff's first unjudged entry in the candidate_tier order
    — not the significance order's, which differs.

    MUTATION (verified RED, 1 failed — this test alone): fall back to the diff's first entry,
    judged or not -> RED."""
    w = _t2_world(tmp_path)
    page = pv.get_diff_patch_view(w.atlas, DIFF, bucket="A")
    assert page["review_progress"]["not_looked_at"] == 0
    assert page["review_progress"]["next_page"] == []
    assert _first_named(page["annotation"]) == _T2_FIRST["candidate_tier"]


def test_the_run_pair_progress_stays_in_the_candidate_tier_order(
    tmp_path: Path, current: None
) -> None:
    """list_overlays' progress over a run pair still names the next unjudged entries in the
    candidate_tier order, and its note says where the page order is read instead.

    MUTATION (verified RED, 1 failed — this test alone): order the items' candidate_tier position
    (Item.order) by significance instead -> RED. (Only the whole list catches it: on this world the
    first unjudged entry happens to be the same in both orders.)"""
    w = _t2_world(tmp_path)
    order = [e["entry_id"] for e in _view(w, sort_by="candidate_tier")["entries"]]
    unjudged = [k for k in order if k not in _T2_JUDGED]
    out = mcp_app.make_tools(w.path)["list_overlays"](
        anchor_kind="diff_subject", run_id="runA::runB"
    )
    progress = out["review_progress"]
    named = [r["entry_id"] for r in progress["next_page"]]
    assert named == unjudged[: progress["page_size"]]
    assert named[0] == _T2_FIRST["candidate_tier"]
    assert progress["note"].endswith(
        "next_page here is in the candidate_tier order; get_diff_patch_view names the next ones "
        "in the order its page is read in."
    )


def test_the_anchored_page_names_its_next_entries_in_its_own_order(
    tmp_path: Path, current: None
) -> None:
    """anchored_differs=true with no sort_by: entries as the candidate_tier page renders them (no
    significance field), in the filter's own order, and the next unjudged ones named in that order
    — which is not the candidate_tier order's.

    MUTATION (verified RED, 3 failed — with the other-orders and lens tests): let the anchored page
    compute significance -> RED; MUTATION (verified RED, 2 failed): name the next entries in the
    candidate_tier order on every page -> RED."""
    w, ids = _filter_world(tmp_path)
    v = _view(w, anchored_differs=True)
    order = [e["entry_id"] for e in v["entries"]]
    assert order == [ids[k] for k in ("one", "high", "floor", "below", "low")]
    plain = _view(w, anchored_differs=True, sort_by="candidate_tier")["by_id"]
    assert [json.dumps(e) for e in v["entries"]] == [json.dumps(plain[k]) for k in order]
    for e in v["entries"]:
        assert "significance" not in e and "attention" not in e["rank_key"]
    page = pv.get_diff_patch_view(w.atlas, DIFF, anchored_differs=True)
    assert [r["entry_id"] for r in page["review_progress"]["next_page"]] == order
    assert _first_named(page["annotation"]) == ids["one"]
    ct = pv.get_diff_patch_view(w.atlas, DIFF, anchored_differs=True, sort_by="candidate_tier")
    assert ct["review_progress"]["next_page"][0]["entry_id"] == ids["low"]


def test_the_progress_blocks_keep_their_place_and_their_first_page_rule(
    tmp_path: Path, current: None
) -> None:
    """review_progress and annotation sit where they always did in the envelope (after
    overlay_coverage), in every view, and next_page still comes on the first page only.

    MUTATION (verified RED, 1 failed — this test alone): add the two blocks after the order is
    known instead of filling their places -> RED."""
    w = World(tmp_path)
    _rich(w)
    for kw in (
        {},
        {"not_listed_page": "aligned_pseudocode_no_body"},
        {"view": "string_edge"},
        {"view": "candidate_flat"},
    ):
        first = pv.get_diff_patch_view(w.atlas, DIFF, limit=1, **kw)
        keys = list(first)
        i = keys.index("overlay_coverage")
        assert keys[i + 1 : i + 3] == ["review_progress", "annotation"], kw
        assert "next_page" in first["review_progress"], kw
        assert first["next_offset"] == 1, kw  # a second page to read the first-page rule on
        later = pv.get_diff_patch_view(w.atlas, DIFF, limit=1, offset=1, **kw)
        assert "next_page" not in later["review_progress"], kw
        assert "review_progress.next_page" in later["first_page_only"]["keys"], kw


# ── the default order by shape: where each kind of entry lands, relative to the others ─────────


def _sim1_b(w: World, addr: str, name: str, *, same: bool = True, caller: bool = True) -> str:
    """A similarity-1 aligned pair holding a candidate on each side (bucket B), equal callee sets,
    its pseudocode the same text (``same``) or not; ``caller`` gives its A function a direct caller
    on the A side and none on B (the caller-set edge)."""
    w.pair(addr, addr, 0.97, 1.0, name_a=name, name_b=name)
    w.inst("a", _ref("runA", addr, "cmd", "0x10"), "cmd", "system")
    w.inst("b", _ref("runB", addr, "cmd", "0x10"), "cmd", "system")
    w.fn("a", addr, ["system"], name=name, pseudocode="system(x);")
    w.fn("b", addr, ["system"], name=name, pseudocode="system(x);" if same else "system(y);")
    if caller:
        w.fn("a", f"{int(addr, 16) + 0x800:08x}", [name], name=f"{name}_caller")
    return _pair_id(addr, addr)


def _shape_world(tmp_path: Path) -> tuple[World, dict[str, str]]:
    """One entry per shape the default order is asserted on, plus the competitors that tell its
    place apart: a high-tier B (sink_present_no_visible_delta) the candidate_tier order puts ahead
    of the anchored pairs, and an unanchored R with the lowest similarity."""
    w = World(tmp_path)
    ids: dict[str, str] = {}
    # 1a / 1b: an undetermined pair anchored by address, reading differs, at or above the floor —
    # with a low-tier candidate (copy) and with none.
    ids["1a"] = _ud(w, "00041000", "00041000", 0.85)
    w.inst("a", _ref("runA", "00041000", "copy", "0x10"), "copy", "strcpy")
    ids["1b"] = _ud(w, "00042000", "00042000", 0.85)
    # the high-tier competitor: a changed pair whose cmd candidate lines up.
    w.pair("00044000", "00044000", 0.97, 0.6)
    w.inst("a", _ref("runA", "00044000", "cmd", "0x10"), "cmd", "system")
    w.inst("b", _ref("runB", "00044000", "cmd", "0x10"), "cmd", "system")
    w.im("00044010", "00044010", "00044000")
    w.fn("a", "00044000", ["system"], pseudocode="system(a);")
    w.fn("b", "00044000", ["system", "strlen"], pseudocode="system(a); strlen(a);")
    ids["b_high"] = _pair_id("00044000", "00044000")
    # 2: bucket A — the matched call now calls another callee.
    w.pair("00046000", "00047000", 0.97, 0.9)
    w.inst("a", _ref("runA", "00046000", "cmd", "0x10"), "cmd", "system")
    w.inst("b", _ref("runB", "00047000", "cmd", "0x10"), "cmd", "popen")
    w.im("00046010", "00047010", "00046000")
    w.fn("a", "00046000", ["system"], pseudocode="system(c);")
    w.fn("b", "00047000", ["popen"], pseudocode="popen(c);")
    ids["2"] = _pair_id("00046000", "00047000")
    # 3: a persisted copy whose length constant moved (similarity 1).
    w.pair("00048000", "00049000", 0.97, 1.0)
    w.inst(
        "a",
        _ref("runA", "00048000", "copy", "0x10"),
        "copy",
        "snprintf",
        _size("cap_const", "0x200"),
    )
    w.inst(
        "b",
        _ref("runB", "00049000", "copy", "0x10"),
        "copy",
        "snprintf",
        _size("cap_const", "0x400"),
    )
    w.im("00048010", "00049010", "00048000")
    w.fn("a", "00048000", ["snprintf"], pseudocode="snprintf(d,0x200,f);")
    w.fn("b", "00049000", ["snprintf"], pseudocode="snprintf(d,0x400,f);")
    ids["3"] = _pair_id("00048000", "00049000")
    # 4: anchored, reading differs, below the floor.
    ids["4"] = _ud(w, "00043000", "00043000", 0.6)
    # a plain similarity entry: unanchored (another address on each side), the lowest similarity.
    ids["sim_low"] = _ud(w, "00045000", "0004a000", 0.3)
    # 5 / 6 / 7: similarity-1 B pairs with equal callee sets.
    ids["5"] = _sim1_b(w, "00051000", "b_lost_caller")
    ids["6"] = _sim1_b(w, "00052000", "b_identical", caller=False)
    ids["7"] = _sim1_b(w, "00053000", "b_differs", same=False, caller=False)
    w.commit()
    return w, ids


def test_the_default_order_places_each_shape(tmp_path: Path, current: None) -> None:
    """★ With no sort_by, by shape (relative places only):

    1a / 1b an undetermined pair anchored_differs at or above the floor, with a low-tier candidate
    or none: attention 1, in_read_first, read first — while the candidate_tier order puts the
    high-tier B ahead of both. 2 bucket A and 3 a row's sink_arg_constant_delta: attention 0.
    4 anchored_differs below the floor: still basis anchored_differs, not in the head, read after
    it and before the plain similarity entries (even one of lower similarity). 5 a similarity-1 B,
    callee sets equal, pseudocode identical, whose B side lost every direct caller: attention 1,
    ahead of the sunk entries; 6 the same without the caller edge: attention 2 (sunk, still
    listed). 7 a similarity-1 B, callee sets equal, pseudocode differs: attention 1 — what sinks
    an entry is pseudocode_sameness identical, not similarity 1 with equal callee sets.

    MUTATION (verified RED, 1 failed — this test alone): sink on similarity 1 with equal callee
    sets instead of on identical pseudocode -> 7 goes RED (5 is held at 1 by its caller edge
    either way, so it cannot tell). MUTATION (verified RED, 2 failed — with the fixture-file
    test): order candidate_tier through the significance branch -> RED."""
    w, ids = _shape_world(tmp_path)
    v = _view(w)
    assert v["lens"]["sort_by"] == "significance"
    order = [e["entry_id"] for e in v["entries"]]
    at = {k: order.index(eid) for k, eid in ids.items()}
    sig = {k: v["by_id"][eid]["significance"] for k, eid in ids.items()}
    reading = {k: v["by_id"][ids[k]]["proposed_pair_reading"] for k in ("1a", "1b", "4")}
    for k in ("1a", "1b"):
        assert sig[k] == {"attention": 1, "basis": "anchored_differs"}, k
        assert reading[k]["in_read_first"] is True, k
        assert at[k] < at["b_high"], k
    assert v["by_id"][ids["1a"]]["tier"] != v["by_id"][ids["b_high"]]["tier"]
    ct = [e["entry_id"] for e in _view(w, sort_by="candidate_tier")["entries"]]
    assert ct.index(ids["b_high"]) < ct.index(ids["1a"]) < ct.index(ids["1b"])
    assert sig["2"] == {"attention": 0, "basis": "matched_call_other_callee"}
    assert sig["3"] == {"attention": 0, "basis": "sink_arg_constant_delta"}
    assert max(at["2"], at["3"]) < min(at["1a"], at["1b"])
    assert sig["4"] == {"attention": 1, "basis": "anchored_differs"}
    assert reading["4"]["in_read_first"] is False
    assert max(at["1a"], at["1b"]) < at["4"] < at["sim_low"]
    assert sig["sim_low"] == {"attention": 1, "basis": "similarity"}
    assert sig["5"] == {"attention": 1, "basis": "lost_every_direct_caller_never_sunk"}
    assert sig["6"] == {"attention": 2, "basis": "pseudocode_identical"}
    assert at["5"] < at["6"] and at["6"] == len(order) - 1
    assert sig["7"] == {"attention": 1, "basis": "similarity"}
    for k in ("5", "6", "7"):
        e = v["by_id"][ids[k]]
        assert e["bucket"] == "B" and e["similarity"] == 1.0, k
        assert e["callee_set"]["state"] == "equal", k
    assert v["by_id"][ids["5"]]["pseudocode_sameness"] == "identical"
    assert v["by_id"][ids["6"]]["pseudocode_sameness"] == "identical"
    assert v["by_id"][ids["7"]]["pseudocode_sameness"] == "differs"


# ── start_diff_review: the entries to read first, composed from the view and the meta ──────────

_START_KEYS = {"diff_id", "workflow", "meta", "headline", "headline_note", "view", "read_next"}
_START_META_KEYS = {
    "functions",
    "banners",
    "source_stale",
    "source_stale_reason",
    "toolchain_checked",
    "version_skew",
}


def test_start_diff_review_is_the_view_and_the_meta_as_they_are(
    tmp_path: Path, current: None
) -> None:
    """★ start_diff_review computes nothing of its own: ``view`` is byte for byte the tool's
    summary page, ``headline`` the tool's first entry with rows_limit=0 (no inline rows, its
    inline_hunk kept), each ``meta`` value get_diff_meta's own (version_skew from its ``meta``),
    and no key comes from anywhere else. ``read_next.more`` is the call for the summary's next page
    (copied, it reads that page) and is absent when there is none.

    MUTATION (verified RED, 1 failed — this test alone): put a key of its own into ``view`` ->
    RED; MUTATION (verified RED, 1 failed): read the headline without rows_limit=0 -> RED."""
    w = _summary_world(tmp_path)
    tools = mcp_app.make_tools(w.path)
    start, view_tool = tools["start_diff_review"], tools["get_diff_patch_view"]
    meta_tool = tools["get_diff_meta"]
    for limit in (4, 20):
        out = start(DIFF, limit=limit)
        assert "error" not in out and "over_budget" not in out, out
        assert set(out) <= _START_KEYS and "headline_note" not in out
        assert out["workflow"] == DIFF_WORKFLOW
        view = view_tool(DIFF, detail="summary", limit=limit)
        assert json.dumps(out["view"]) == json.dumps(view)
        head = pv.get_diff_patch_view(w.atlas, DIFF, limit=1, rows_limit=0)["entries"][0]
        assert json.dumps(out["headline"]) == json.dumps(head)
        assert out["headline"]["rows"] == [] and out["headline"]["rows_total"] > 0
        assert out["headline"]["entry_id"] == view["entries"][0]["entry_id"]
        meta = meta_tool(DIFF)
        assert set(out["meta"]) == _START_META_KEYS
        for key in _START_META_KEYS - {"version_skew"}:
            assert json.dumps(out["meta"][key]) == json.dumps(meta[key]), key
        assert out["meta"]["version_skew"] == meta["meta"]["version_skew"]
        assert out["read_next"]["one_entry"] == view["detail_with"]["one_entry"]
        if view["next_offset"] is None:
            assert set(out["read_next"]) == {"one_entry"}
        else:
            name, args = _copied_call(out["read_next"]["more"])
            assert name == "get_diff_patch_view"
            assert args == {"diff_id": DIFF, "detail": "summary", "offset": view["next_offset"]}
            assert view_tool(**args)["entries"][0]["entry_id"] != view["entries"][0]["entry_id"]
    assert start(DIFF, limit=4)["read_next"].get("more") is not None
    assert "more" not in start(DIFF, limit=200)["read_next"]


def test_start_diff_review_says_why_there_is_no_headline(tmp_path: Path, current: None) -> None:
    """No entry to read first: headline null, with why — the whole diff undetermined (its banners
    in meta), or simply nothing listed."""
    w = World(tmp_path)
    w.commit()
    start = mcp_app.make_tools(w.path)["start_diff_review"]
    empty = start(DIFF)
    assert empty["headline"] is None and empty["headline_note"] == "no listed entry"
    assert empty["view"]["entries"] == []
    w.atlas.execute("UPDATE diff_meta SET version_skew = 1")
    w.commit()
    pv._clear_view_caches()
    withheld = start(DIFF)
    assert withheld["headline"] is None
    assert withheld["headline_note"] == "diff_undetermined (meta.banners)"
    assert withheld["meta"]["banners"] and withheld["meta"]["version_skew"] == 1


def test_start_diff_review_refuses_what_it_cannot_read(tmp_path: Path, current: None) -> None:
    w = World(tmp_path)
    w.commit()
    start = mcp_app.make_tools(w.path)["start_diff_review"]
    for limit in (0, 201, True, "5"):
        out = start(DIFF, limit=limit)  # type: ignore[arg-type]
        assert out.get("error") == f"limit must be an integer in 1..200, got {limit!r}", limit
    missing = start("runA::runB::nothing")
    assert missing.get("found") is False and "error" in missing


def test_start_diff_review_keeps_to_the_page_budget(
    tmp_path: Path, current: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The headline is fitted beside the rest of the response: when it does not fit, its
    inline_hunk is withheld (page_budget) and the view stays as the tool gives it; when even that
    does not fit, the response says over_budget."""
    w = _summary_world(tmp_path)
    start = mcp_app.make_tools(w.path)["start_diff_review"]
    whole = start(DIFF)
    hunk = whole["headline"]["pseudocode_delta"]["inline_hunk"]
    assert "withheld" not in hunk  # the headline really carries a hunk to withhold
    rest = len(json.dumps({**whole, "headline": None})) - len("null")
    monkeypatch.setattr(
        mcp_app, "_RESPONSE_BYTE_BUDGET", rest + len(json.dumps(whole["headline"])) - 1
    )
    cut = start(DIFF)
    assert json.dumps(cut["view"]) == json.dumps(whole["view"])
    assert cut["headline"]["pseudocode_delta"]["inline_hunk"]["withheld"] == "page_budget"
    assert "over_budget" not in cut
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", 2000)
    assert start(DIFF)["over_budget"] is True


def test_start_diff_review_is_registered_read_only_beside_the_view() -> None:
    tools = mcp_app.make_tools(Path("unused.db"))
    names = list(tools)
    assert names.index("start_diff_review") + 1 == names.index("get_diff_patch_view")
    assert mcp_app.tool_annotations("start_diff_review").readOnlyHint is True
    doc = " ".join((tools["start_diff_review"].__doc__ or "").split())
    assert doc.startswith(
        "START HERE for one diff: the entries to read first and the calls to read and judge them — "
        "composed from get_diff_patch_view and get_diff_meta, nothing computed of its own."
    )
    assert (tools["get_diff_patch_view"].__doc__ or "").startswith(
        "The function patch view of one diff"
    )


def test_no_start_diff_review_label_says_what_a_change_means(tmp_path: Path, current: None) -> None:
    """Every key start_diff_review adds, the headline notes, and the words of the workflow and the
    read_next calls (tool names aside — they are the tools' own, as old as them) are free of words
    that say what a change means.

    MUTATION (verified RED, 1 failed — this test alone): word the no-entry note 'nothing new
    listed' -> RED."""
    labels: set[str] = set()
    w = _summary_world(tmp_path)
    start = mcp_app.make_tools(w.path)["start_diff_review"]
    for out in (start(DIFF, limit=4), start(DIFF, limit=200)):
        labels |= set(out) | set(out["meta"]) | set(out["read_next"])
        for text in (out["workflow"], *out["read_next"].values()):
            labels.add(re.sub(r"\b\w+\(", "(", text))
    (tmp_path / "none").mkdir()
    empty = World(tmp_path / "none")
    empty.commit()
    out = mcp_app.make_tools(empty.path)["start_diff_review"](DIFF)
    labels |= {out["headline_note"], mcp_app._HEADLINE_WITHHELD, "headline_note"}
    assert {"workflow", "read_next", "one_entry", "more", "no listed entry"} <= labels
    for label in labels:
        words = set(re.split(r"[^a-z0-9]+", label.lower()))
        assert not words & _WORDS, label
