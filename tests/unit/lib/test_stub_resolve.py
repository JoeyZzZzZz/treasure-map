# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Recovering a stub's import name from ELF structure, so a dropped sink comes back.

A call to ``system`` that the decompiler left as ``FUN_004125b0`` is a false negative on a sink
that objectively exists. These prove the name is recovered from the ELF alone — independent of the
decompiler — and, just as important, that a binary which cannot be resolved cleanly yields no name
rather than a fabricated one, because a wrong ``system`` is a manufactured candidate.

The real-binary fixtures need the extracted firmware on disk; they skip when it is absent. The
domain-guard logic — the line between a false negative and a false positive — is exercised
directly, since a real toolchain will not emit an out-of-boundary GOT slot on demand.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from treasure_map.lib.analyze.stub_resolve import (
    _GOT_ENTRY,
    StubResolution,
    _merge_slot_names,
    global_got_slot_symbol_index,
    relabel_callees,
    resolve_stubs,
)

# The stub resolver's headline case is proven against a REAL extracted MIPS firmware, which is not
# in the repo (a real firmware image cannot be committed). Point TM_STUB_FIXTURE_ROOT at an
# extracted rootfs containing a new-ABI MIPS PLT binary and a classic global-GOT one; without it
# these skip and the pure-logic domain-guard tests below still run. The two binaries used are a
# web cgi (the origin case: FUN_00409748 calls the stub at 0x4125b0, which is system) and a shared
# library with .MIPS.stubs but no .plt.
_FW = Path(os.environ.get("TM_STUB_FIXTURE_ROOT", ""))
_IUX = _FW / "usr/www/cgi/iux_get.cgi" if _FW.name else Path("/nonexistent")
_LIBWL = _FW / "lib/libwl.so" if _FW.name else Path("/nonexistent")

_needs_fw = pytest.mark.skipif(
    not _IUX.exists(), reason="set TM_STUB_FIXTURE_ROOT to an extracted MIPS rootfs to run"
)


# ── the real binary: the name the decompiler dropped ──────────────────────────────────


@_needs_fw
def test_plt_stub_resolves_to_its_import_name() -> None:
    # ★ The origin case, end to end through the resolver. The stub at 0x4125b0 IS system, recovered
    # from .rel.plt with the decompiler nowhere in the loop.
    resolution = resolve_stubs(_IUX)
    assert resolution is not None
    assert resolution.names[0x4125B0] == "system"
    assert resolution.names[0x412450] == "popen"


@_needs_fw
def test_the_caller_the_decompiler_left_blind_gets_its_sink_back() -> None:
    # FUN_00409748's real callee list — the stub call at 0x4125b0 hides a system() never named.
    resolution = resolve_stubs(_IUX)
    assert resolution is not None
    origin = [
        "FUN_0040c890",
        "FUN_004128d0",
        "FUN_00412460",
        "FUN_004125a0",
        "FUN_00412840",
        "FUN_00412560",
        "FUN_00412890",
        "FUN_00409660",
        "FUN_00412510",
        "FUN_004125b0",
        "FUN_004127a0",
    ]
    result = relabel_callees(origin, resolution)
    assert "system" in result.callees  # the sink is back
    assert "FUN_004125b0" not in result.callees  # relabelled in place
    assert result.unresolved_stub_addrs == []  # every stub call resolved


@_needs_fw
def test_the_answer_does_not_depend_on_the_decompiler() -> None:
    # ★ The whole point of resolving from ELF: the same file resolves to the same names no matter
    # what the decompiler did with its thunks. Reading it twice is deterministic to the byte.
    a = resolve_stubs(_IUX)
    b = resolve_stubs(_IUX)
    assert a is not None and b is not None
    assert a.names == b.names
    assert a.regions == b.regions


@_needs_fw
def test_a_classic_binary_without_a_plt_fabricates_no_stub_names() -> None:
    # libwl.so has .MIPS.stubs but no .plt, so there are no FUN_<plt-addr> callees to relabel, and
    # the resolver must invent none. (Its inline %call16 calls are a different shape, out of scope.)
    resolution = resolve_stubs(_LIBWL)
    assert resolution is not None
    assert resolution.names == {}


# ── the domain guard: the line between a false negative and a false positive ──────────


def test_a_local_got_slot_is_refused() -> None:
    # ★ THE LOAD-BEARING GUARD, lower side. The formula on a slot below DT_MIPS_LOCAL_GOTNO — on a
    # new-ABI binary, a .got.plt slot — produces an index into the wrong region (a NEGATIVE one).
    # Reading it would write a wrong name. It must return None.
    #
    # MUTATION (verified RED, 1 failed): in stub_resolve.global_got_slot_symbol_index drop the
    # `if got_index < local_gotno: return None` guard -> a below-boundary slot resolves.
    pltgot, local, gotsym, symtabno = 0x10000, 10, 25, 100
    below = pltgot + 3 * _GOT_ENTRY  # got_index 3 < 10
    assert global_got_slot_symbol_index(below, pltgot, local, gotsym, symtabno) is None
    # a genuinely global slot at the boundary resolves to the first global symbol
    at_boundary = pltgot + local * _GOT_ENTRY
    assert global_got_slot_symbol_index(at_boundary, pltgot, local, gotsym, symtabno) == gotsym


def test_a_new_abi_got_plt_slot_yields_a_negative_index_and_is_refused() -> None:
    # ★ The exact real-world case the guard exists for: a .got.plt slot sits BEFORE DT_PLTGOT, so
    # its got_index is negative — deeply below the local boundary. Refused, not read.
    pltgot, local, gotsym, symtabno = 0x423980, 5, 0x74, 0x75
    got_plt_slot = 0x423080  # below pltgot -> negative got_index
    assert global_got_slot_symbol_index(got_plt_slot, pltgot, local, gotsym, symtabno) is None


def test_an_out_of_range_symbol_index_is_refused() -> None:
    # The upper guard: a computed index at or past DT_MIPS_SYMTABNO points past the symbol table.
    #
    # MUTATION (verified RED, 1 failed): in stub_resolve.global_got_slot_symbol_index drop the
    # `dynsym_index >= symtabno` term -> an out-of-range index is returned.
    pltgot, local, gotsym, symtabno = 0x10000, 2, 5, 8
    # got_index picked so dynsym_index = gotsym + (got_index - local) == symtabno (just past)
    over = pltgot + (local + (symtabno - gotsym)) * _GOT_ENTRY
    assert global_got_slot_symbol_index(over, pltgot, local, gotsym, symtabno) is None
    just_under = pltgot + (local + (symtabno - gotsym) - 1) * _GOT_ENTRY
    assert global_got_slot_symbol_index(just_under, pltgot, local, gotsym, symtabno) == symtabno - 1


# ── multi-path disagreement, and the non-MIPS / unreadable answers ────────────────────


def test_two_paths_that_disagree_drop_the_slot() -> None:
    # A slot both paths name, but differently (a corrupt or adversarial binary) -> no name.
    #
    # MUTATION (verified RED, 1 failed): in stub_resolve._merge_slot_names replace the
    # `del out[slot]` on disagreement with `pass` -> a disagreed slot keeps one path's name.
    merged = _merge_slot_names({0x1000: "system", 0x2000: "popen"}, {0x1000: "printf"})
    assert 0x1000 not in merged  # undecidable -> dropped, never guessed
    assert merged[0x2000] == "popen"  # the agreeing / unique slots survive


def test_a_non_mips_or_unreadable_file_is_a_cannot_tell(tmp_path: Path) -> None:
    # None is an honest "cannot tell", never an empty StubResolution read as "no stubs".
    not_elf = tmp_path / "x.txt"
    not_elf.write_text("hello")
    assert resolve_stubs(not_elf) is None
    assert resolve_stubs(tmp_path / "does_not_exist") is None


# ── relabel behaviour ─────────────────────────────────────────────────────────────────


def test_relabel_leaves_an_unmatched_internal_call_alone() -> None:
    # A FUN_<addr> that is NOT in a stub region is an ordinary internal function; it passes through
    # untouched and is NOT recorded as an unclassified external call.
    resolution = StubResolution(names={0x4125B0: "system"}, regions=((0x412400, 0x412A44),))
    result = relabel_callees(["FUN_00409660", "FUN_004125b0"], resolution)
    assert result.callees == ["FUN_00409660", "system"]
    assert result.unresolved_stub_addrs == []


def test_an_unresolved_stub_call_stays_visible_as_a_lead() -> None:
    # ★ A stub call in a stub region the resolver could NOT name is kept in the graph AND flagged —
    # the hole is surfaced, never silently read as an ordinary internal call.
    #
    # MUTATION (verified RED, 1 failed): in stub_resolve.relabel_callees drop the
    # `elif resolution.in_stub_region(addr)` branch -> the unresolved stub call vanishes from
    # unresolved_stub_addrs.
    resolution = StubResolution(names={}, regions=((0x412400, 0x412A44),))
    result = relabel_callees(["FUN_004125b0", "FUN_00409660"], resolution)
    assert result.callees == ["FUN_004125b0", "FUN_00409660"]  # both kept in the graph
    assert result.unresolved_stub_addrs == ["0x4125b0"]  # the stub-region one flagged


# ── the ingest wiring: the relabel actually reaches the stored callees ─────────────────


@_needs_fw
def test_ingest_writes_the_resolved_name_into_the_callees(tmp_path: Path) -> None:
    # ★ END-TO-END WIRING, not just the helper. The relabel must run where callees are stored, or
    # the whole recovery is a library nobody calls. This drives ghidra_ingest with a real
    # binary + a synthetic Ghidra JSON whose one function calls the stub at 0x4125b0, and asserts
    # the stored callees carry `system`.
    #
    # MUTATION (verified RED, 1 failed): in ghidra_ingest._ingest_one_binary use `raw_callees`
    # instead of the relabelled list -> the stored callee stays FUN_004125b0.
    import json

    from treasure_map.lib.analyze.ghidra_ingest import _ingest_one_binary
    from treasure_map.lib.storage.connection import open_db

    conn = open_db(tmp_path / "a.db")
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256) VALUES (1, 'iux_get.cgi', ?, 'h')",
        (str(_IUX),),
    )
    data = {
        "functions": [
            {"name": "caller", "address": "00409748", "callees": ["FUN_004125b0", "FUN_00409660"]}
        ]
    }
    _ingest_one_binary(conn, 1, data, _Stats(), resolve_stubs(_IUX))
    conn.commit()
    row = conn.execute("SELECT callees, unresolved_external_calls FROM functions").fetchone()
    conn.close()
    assert "system" in json.loads(row[0])
    assert "FUN_004125b0" not in json.loads(row[0])
    assert json.loads(row[1]) == []  # it resolved, so no unclassified-external lead


def test_ingest_records_an_unresolved_stub_call_as_a_lead(tmp_path: Path) -> None:
    # A stub call the resolver could not name is stored as an unclassified external call — visible,
    # not silently dropped. Uses a hand-made resolution so no firmware is needed.
    import json

    from treasure_map.lib.analyze.ghidra_ingest import _ingest_one_binary
    from treasure_map.lib.storage.connection import open_db

    conn = open_db(tmp_path / "a.db")
    conn.execute("INSERT INTO binaries (id, name, sha256) VALUES (1, 'x', 'h')")
    resolution = StubResolution(names={}, regions=((0x412400, 0x412A44),))
    data = {"functions": [{"name": "f", "address": "1000", "callees": ["FUN_004125b0"]}]}
    _ingest_one_binary(conn, 1, data, _Stats(), resolution)
    conn.commit()
    row = conn.execute("SELECT unresolved_external_calls FROM functions").fetchone()
    conn.close()
    assert json.loads(row[0]) == ["0x4125b0"]


class _Stats:
    """A stand-in for IngestStats — _ingest_one_binary only increments counters on it."""

    def __init__(self) -> None:
        self.functions_ingested = 0
        self.imports_ingested = 0
        self.exports_ingested = 0
        self.strings_ingested = 0
