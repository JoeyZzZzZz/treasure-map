# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The extractor's Java side, run for real on compiled fixtures (tests/fixtures/elfs/build.sh).

A stored JSON cannot catch a change to the Java that writes it, so what the extraction scripts
decide is checked here, through real Ghidra, on binaries whose construction is known:

* the dispatch-table detector and the ELF slot check after it (libtables / libclasses): which
  record arrays are tables, and which only look like one;
* the promotion / recovery pass (promote): undefined ranges, the pointer-only function it
  recovers, the undecodable bytes it refuses, the functions it promotes, the thunks it records.

Skipped without Ghidra (run with analyzeHeadless on PATH).
"""

from __future__ import annotations

import json
import shutil
import struct
from pathlib import Path
from typing import Any

import pytest
from elftools.elf.elffile import ELFFile

from treasure_map.lib.analyze.elf_slots import read_elf_slots
from treasure_map.lib.analyze.ghidra_ingest import checked_string_tables
from treasure_map.lib.analyze.ghidra_runner import GhidraRunner
from treasure_map.lib.config.config import GhidraConfig, GhidraLocalConfig

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "elfs"
_HEADLESS = shutil.which("analyzeHeadless")
_HOME = Path(_HEADLESS).resolve().parents[1] if _HEADLESS else None
pytestmark = pytest.mark.skipif(_HOME is None, reason="analyzeHeadless not on PATH")

_X86_64 = "x86:LE:64:default"


def _extract(work: Path, name: str) -> dict[str, Any]:
    assert _HOME is not None
    runner = GhidraRunner(GhidraConfig(local=GhidraLocalConfig(home=_HOME)))
    res = runner.run_ghidra(_FIXTURES / name, work / name, 300, _X86_64, "f1x7f1x7", retry=False)
    assert res.success and res.output_file is not None, res.reason
    data: dict[str, Any] = json.loads(res.output_file.read_text(encoding="utf-8"))
    return data


@pytest.fixture(scope="module")
def tables_json(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    return _extract(tmp_path_factory.mktemp("tables"), "libtables_x86_64.so")


@pytest.fixture(scope="module")
def classes_json(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    return _extract(tmp_path_factory.mktemp("classes"), "libclasses_x86_64.so")


@pytest.fixture(scope="module")
def promote_json(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    return _extract(tmp_path_factory.mktemp("promote"), "promote_x86_64")


def _keys(table: Any) -> list[str]:
    return [str(e.get("key")) for e in table["entries"]]


# ── the dispatch-table detector (Q8) ──────────────────────────────────────────────────────────


def test_the_detector_finds_the_tables_and_the_slot_check_refuses_the_lookalike(
    tables_json: dict[str, Any],
) -> None:
    """★ libtables holds two tables and two arrays that look like one. The detector takes the two
    tables and the {name -> imported data object + 8*i} array (each target lands on an imported
    function in Ghidra's external layout — the shape that produced false tables in firmware); it
    never takes {name -> data object}. The ELF slot check then refuses the look-alike (its slots
    name a data object, with an addend), leaving exactly the two tables, whole.

    MUTATION (verified RED): accept every slot in the check -> the look-alike stays -> RED; let the
    detector take a handler that is not a function -> the data-object array becomes a table -> RED.
    """
    tables = tables_json["string_tables"]["tables"]
    found = sorted(_keys(t) for t in tables)
    assert found == [
        ["alpha", "beta", "gamma", "delta", "epsilon"],
        ["print", "length", "compare", "lookup"],
        ["slot_one", "slot_two", "slot_three", "slot_four"],  # the look-alike (precondition)
    ]
    kept = checked_string_tables(tables, read_elf_slots(_FIXTURES / "libtables_x86_64.so"))
    assert sorted([str(e.get("key")) for e in t.entries] for t in kept) == [
        ["alpha", "beta", "gamma", "delta", "epsilon"],
        ["print", "length", "compare", "lookup"],
    ]
    handlers = {str(e.get("key")): str(e.get("func_name")) for t in kept for e in t.entries}
    assert handlers["alpha"] == "fx_alpha" and handlers["print"] == "puts"


def test_vtables_and_typeinfo_are_no_table(classes_json: dict[str, Any]) -> None:
    """Six polymorphic classes: their vtables and typeinfo records hold names and pointers side by
    side, and none of it is a dispatch table."""
    assert classes_json["string_tables"]["tables"] == []


# ── the promotion / recovery pass (Q1, Q2) ────────────────────────────────────────────────────


def _pointer_targets(path: Path, symbol: str, count: int) -> list[int]:
    """The ``count`` 64-bit pointers stored at ``symbol`` (the fixture's data pointer array)."""
    with path.open("rb") as fh:
        elf = ELFFile(fh)
        symtab = elf.get_section_by_name(".symtab")
        (sym,) = [s for s in symtab.iter_symbols() if s.name == symbol]
        addr = sym["st_value"]
        for seg in elf.iter_segments():
            lo = seg["p_vaddr"]
            if seg["p_type"] == "PT_LOAD" and lo <= addr < lo + seg["p_filesz"]:
                fh.seek(seg["p_offset"] + addr - lo)
                return list(struct.unpack(f"<{count}Q", fh.read(8 * count)))
    raise AssertionError(f"{symbol} not in a loaded segment")


def _functions(data: dict[str, Any]) -> dict[int, dict[str, Any]]:
    return {int(f["address"], 16): f for f in data["functions"]}


def test_a_function_only_a_data_pointer_reaches_is_recovered_and_bad_bytes_are_not(
    promote_json: dict[str, Any],
) -> None:
    """★ fx_pointers holds two pointers into .text, named by nothing else: to bytes that do not
    decode, and to a small function. The pass recovers the function (origin 'recovered') and
    refuses the bytes (a decode that raised errors is no function).

    MUTATION (verified RED): accept a pointer target whose disassembly raised errors -> a function
    at the undecodable bytes -> RED."""
    garbage, hidden = _pointer_targets(_FIXTURES / "promote_x86_64", "fx_pointers", 2)
    funcs = _functions(promote_json)
    assert funcs[hidden]["origin"] == "recovered"
    assert garbage not in funcs
    promote = promote_json["promote"]
    assert promote["recovered"] >= 1 and promote["recover_rejected"] >= 1


def test_undefined_ranges_below_the_minimum_are_not_recorded(promote_json: dict[str, Any]) -> None:
    """★ Two runs of bytes in .text are never executed: 32 bytes of data (with the undecodable
    bytes after it) and 8 bytes between two functions. The first is recorded as an undefined range;
    the second is below the recorded minimum (16 bytes, alignment padding's size) and is not.

    MUTATION (verified RED): drop the minimum -> the 8-byte range is recorded -> RED."""
    ranges = [(int(a, 16), int(b, 16)) for a, b in promote_json["promote"]["undefined_ranges"]]
    assert ranges, "the 32-byte range must be recorded"
    assert all(hi - lo + 1 >= 16 for lo, hi in ranges), ranges


def test_promoted_functions_are_counted_and_marked(promote_json: dict[str, Any]) -> None:
    """★ The functions the pass creates where none was are what ``created`` counts, and each one
    reads origin 'promoted' — the count and the mark agree, and there is at least one.

    MUTATION (verified RED): invert the "no function was there" guard -> nothing counted or marked
    -> RED; read whether a function was there AFTER creating it -> the same -> RED."""
    promoted = [f for f in promote_json["functions"] if f.get("origin") == "promoted"]
    assert promoted
    assert promote_json["promote"]["created"] == len(promoted)


def test_the_thunks_the_export_skips_are_recorded(promote_json: dict[str, Any]) -> None:
    """The PLT stubs (thunks) are left out of the exported functions, and recorded with their
    bodies so a reader knows they were skipped, not missed.

    MUTATION (verified RED): stop writing the thunks -> RED."""
    thunks = promote_json["thunks"]
    assert thunks
    exported = {int(f["address"], 16) for f in promote_json["functions"]}
    assert not {int(entry, 16) for entry, _body in thunks} & exported
