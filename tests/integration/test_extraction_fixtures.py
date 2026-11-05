# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The extractor's Java side, run for real on compiled fixtures (tests/fixtures/elfs/build.sh).

A stored JSON cannot catch a change to the Java that writes it, so what the extraction scripts
decide is checked here, through real Ghidra, on binaries whose construction is known:

* the dispatch-table detector and the ELF slot check after it (libtables / libclasses): which
  record arrays are tables, and which only look like one (a run one record short of the minimum
  among them); why each table stops where it does; a key that is not a C string, and the same key
  once a test-only script has defined it as a string;
* the promotion / recovery pass (promote): undefined ranges, the pointer-only function it
  recovers, the undecodable bytes it refuses, the functions it promotes, the thunks it records;
* the same pass where a block's function entry already holds a function (libtables, with one
  function's body cut to its first instruction by a test-only script before the pass runs), and
  the analysis option it freezes and must put back.

The test-only Ghidra scripts are in ``ghidra_scripts/`` beside this file. They are not package data
and no scan runs them: a test adds them to its own session's command line (``_extract``).

Skipped without Ghidra (run with analyzeHeadless on PATH).
"""

from __future__ import annotations

import json
import re
import shutil
import struct
from pathlib import Path
from typing import Any

import pytest
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from treasure_map.lib.analyze import ghidra_launch, ghidra_runner
from treasure_map.lib.analyze.elf_slots import read_elf_slots
from treasure_map.lib.analyze.ghidra_ingest import checked_string_tables
from treasure_map.lib.analyze.ghidra_runner import GhidraRunner
from treasure_map.lib.config.config import GhidraConfig, GhidraLocalConfig

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "elfs"
_TEST_SCRIPTS = Path(__file__).parent / "ghidra_scripts"
_HEADLESS = shutil.which("analyzeHeadless")
_HOME = Path(_HEADLESS).resolve().parents[1] if _HEADLESS else None
pytestmark = pytest.mark.skipif(_HOME is None, reason="analyzeHeadless not on PATH")

_X86_64 = "x86:LE:64:default"


def _extract(
    work: Path,
    name: str,
    before_promote: list[str] | None = None,
    after_promote: list[str] | None = None,
) -> tuple[dict[str, Any], str]:
    """The extraction's JSON and the session's log. ``before_promote`` / ``after_promote`` are
    further post-script arguments (``["-postScript", "<Script>.java", <args>...]``) run just before
    or just after the promotion pass, from the test-only script directory; the production command
    line is built as always and only added to here."""
    assert _HOME is not None
    real = ghidra_launch.build_cmd

    def build_cmd(*args: Any, **kwargs: Any) -> list[str]:
        cmd = real(*args, **kwargs)
        at = cmd.index(ghidra_launch.PROMOTE_SCRIPT)  # "-postScript" is right before it
        promote = cmd[at - 1 : at + 1]
        cmd = (
            cmd[: at - 1] + (before_promote or []) + promote + (after_promote or []) + cmd[at + 1 :]
        )
        sp = cmd.index("-scriptPath") + 1
        cmd[sp] = f"{cmd[sp]};{_TEST_SCRIPTS}"
        return cmd

    runner = GhidraRunner(GhidraConfig(local=GhidraLocalConfig(home=_HOME)))
    with pytest.MonkeyPatch.context() as mp:
        if before_promote or after_promote:
            mp.setattr(ghidra_runner, "build_cmd", build_cmd)
        res = runner.run_ghidra(
            _FIXTURES / name, work / name, 300, _X86_64, "f1x7f1x7", retry=False
        )
    assert res.success and res.output_file is not None, res.reason
    data: dict[str, Any] = json.loads(res.output_file.read_text(encoding="utf-8"))
    log = res.log_path.read_text(errors="replace") if res.log_path is not None else ""
    return data, log


@pytest.fixture(scope="module")
def tables_json(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    return _extract(tmp_path_factory.mktemp("tables"), "libtables_x86_64.so")[0]


@pytest.fixture(scope="module")
def classes_json(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    return _extract(tmp_path_factory.mktemp("classes"), "libclasses_x86_64.so")[0]


@pytest.fixture(scope="module")
def promote_json(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    return _extract(tmp_path_factory.mktemp("promote"), "promote_x86_64")[0]


# The function the existing-entry session cuts down: fx_dispatch in libtables, a loop with several
# blocks, so once its body is its first instruction the blocks after it are in no function.
_TRUNCATED = "fx_dispatch"


def _no_return_report(label: str) -> list[str]:
    return ["-postScript", "NoReturnOption.java", "report", label]


@pytest.fixture(scope="module")
def truncated(tmp_path_factory: pytest.TempPathFactory) -> tuple[dict[str, Any], str]:
    """libtables with fx_dispatch's body cut to its first instruction just before the promotion
    pass, and the no-return discovery option (as Ghidra's analysis left it) printed just before and
    just after that pass."""
    return _extract(
        tmp_path_factory.mktemp("truncated"),
        "libtables_x86_64.so",
        before_promote=[
            *_no_return_report("before"),
            *("-postScript", "TruncateBody.java", _TRUNCATED),
        ],
        after_promote=_no_return_report("after"),
    )


@pytest.fixture(scope="module")
def no_return_off(tmp_path_factory: pytest.TempPathFactory) -> str:
    """The log of a libtables session whose no-return discovery option is set to the non-default
    "false" before the promotion pass, and printed just before and just after it."""
    return _extract(
        tmp_path_factory.mktemp("no_return_off"),
        "libtables_x86_64.so",
        before_promote=[
            *("-postScript", "NoReturnOption.java", "set", "false"),
            *_no_return_report("before"),
        ],
        after_promote=_no_return_report("after"),
    )[1]


@pytest.fixture(scope="module")
def green_defined(tmp_path_factory: pytest.TempPathFactory) -> tuple[dict[str, Any], str]:
    """libtables with the "green" key's five printable bytes (followed by a control byte, not a
    NUL) defined as a fixed-length string before the promotion and extraction passes run."""
    return _extract(
        tmp_path_factory.mktemp("green_defined"),
        "libtables_x86_64.so",
        before_promote=["-postScript", "DefineString.java", b"green\x01".hex(), "5"],
    )


def _keys(table: Any) -> list[str]:
    return [str(e.get("key")) for e in table["entries"]]


def _table(tables: Any, first_key: str) -> dict[str, Any]:
    found = [t for t in tables if _keys(t)[:1] == [first_key]]
    assert len(found) == 1, f"one table starting at {first_key!r}: {found}"
    return dict(found[0])


# ── the dispatch-table detector (Q8) ──────────────────────────────────────────────────────────


def test_the_detector_finds_the_tables_and_the_slot_check_refuses_the_lookalike(
    tables_json: dict[str, Any],
) -> None:
    """★ libtables holds four tables and two arrays that look like one (and a run too short to be
    one: ``test_a_run_shorter_than_the_minimum_is_no_table``). The detector takes the
    four tables and the {name -> imported data object + 8*i} array (each target lands on an
    imported function in Ghidra's external layout — the shape that produced false tables in
    firmware); it never takes {name -> data object}. The ELF slot check then refuses the look-alike
    (its slots name a data object, with an addend), leaving exactly the four tables, whole.

    MUTATION (verified RED): accept every slot in the check -> the look-alike stays -> RED; let the
    detector take a handler that is not a function -> the data-object array becomes a table -> RED.
    """
    tables = tables_json["string_tables"]["tables"]
    found = sorted(_keys(t) for t in tables)
    assert found == [
        ["alpha", "beta", "gamma", "delta", "epsilon"],
        ["north", "south", "east", "west"],
        ["print", "length", "compare", "lookup"],
        ["red", "green", "blue", "cyan"],
        ["slot_one", "slot_two", "slot_three", "slot_four"],  # the look-alike (precondition)
    ]
    kept = checked_string_tables(tables, read_elf_slots(_FIXTURES / "libtables_x86_64.so"))
    assert sorted([str(e.get("key")) for e in t.entries] for t in kept) == [
        ["alpha", "beta", "gamma", "delta", "epsilon"],
        ["north", "south", "east", "west"],
        ["print", "length", "compare", "lookup"],
        ["red", "green", "blue", "cyan"],
    ]
    handlers = {str(e.get("key")): str(e.get("func_name")) for t in kept for e in t.entries}
    assert handlers["alpha"] == "fx_alpha" and handlers["print"] == "puts"


def test_a_table_records_why_it_stops_at_each_end(tables_json: dict[str, Any]) -> None:
    """★ Each table carries the reason the walk stopped at each of its ends, and the ingest turns
    those into the table's own completeness reason. The north..west table sits between two records
    the detector cannot take: before it, one whose handler points one byte into a function (an
    executable address that is no function entry: "handler_undefined", the table may go on past
    it); after it, one whose handler is an address outside the image ("handler_external", read as
    an unresolved relative handler). The commands table ends at its NULL record, which shows
    nothing more: no reason beyond the detector's scope.

    MUTATION (verified RED, 1 failed): make the extractor report a handler that is no function
    entry as "not_a_record" -> RED; (verified RED, 1 failed) make it report a handler outside the
    image as "not_a_record" -> RED."""
    tables = tables_json["string_tables"]["tables"]
    assert _table(tables, "north")["bounds"] == {
        "before": "handler_undefined",
        "after": "handler_external",
    }
    assert _table(tables, "alpha")["bounds"] == {"before": "not_a_record", "after": "not_a_record"}
    kept = checked_string_tables(tables, read_elf_slots(_FIXTURES / "libtables_x86_64.so"))
    reasons = {str(t.entries[0].get("key")): t.reason for t in kept}
    assert reasons["north"] == "got_relative_unresolved,handler_undefined"
    assert reasons["alpha"] == "scope_only"


def test_a_key_that_is_no_c_string_is_kept_and_marked(tables_json: dict[str, Any]) -> None:
    """★ A key in a data block must be a string Ghidra defined or end in a NUL. The "green" key of
    the red..cyan table is a printable run ended by a control byte, and Ghidra defines no string
    there: the record stays in the table (the table is not cut), marked as not terminated, and the
    ingest gives the table the reason "key_not_terminated" — it is not read as cleanly keyed. The
    other keys of the same table are NUL-terminated and unmarked.

    MUTATION (verified RED, 1 failed): treat every data-block key as terminated -> RED."""
    table = _table(tables_json["string_tables"]["tables"], "red")
    assert {str(e["key"]): e["key_terminated"] for e in table["entries"]} == {
        "red": True,
        "green": False,
        "blue": True,
        "cyan": True,
    }
    kept = checked_string_tables(
        tables_json["string_tables"]["tables"], read_elf_slots(_FIXTURES / "libtables_x86_64.so")
    )
    (red,) = [t for t in kept if str(t.entries[0].get("key")) == "red"]
    assert len(red.entries) == 4
    assert red.reason == "key_not_terminated"


def _symbol_size(path: Path, symbol: str) -> int:
    with path.open("rb") as fh:
        symtab = ELFFile(fh).get_section_by_name(".symtab")
        assert isinstance(symtab, SymbolTableSection)
        (sym,) = [s for s in symtab.iter_symbols() if s.name == symbol]
        return int(sym["st_size"])


def test_a_run_shorter_than_the_minimum_is_no_table(tables_json: dict[str, Any]) -> None:
    """J-2. The detector's minimum run is four records. libtables holds {name -> internal function}
    records in runs of three (short_run, NULL-ended) and of four (north..west, red..cyan): the run
    of three is no table, the runs of four are tables. Together the two pin the minimum from both
    sides.

    MUTATION (verified RED, 2 failed each — this test and the table list above): lower the Java
    detector's minimum run to 3, or to 2 -> the run of three becomes a table. Raising it to 5
    (verified RED) drops the four-record tables."""
    lib = _FIXTURES / "libtables_x86_64.so"
    assert _symbol_size(lib, "short_run") == 4 * 16  # three records and the NULL one (precondition)
    tables = tables_json["string_tables"]["tables"]
    keyed = {tuple(_keys(t)) for t in tables}
    assert not [k for k in keyed if set(k) & {"low", "mid", "high"}], sorted(keyed)
    assert ("north", "south", "east", "west") in keyed
    assert ("red", "green", "blue", "cyan") in keyed


def test_a_key_ghidra_defines_as_a_string_is_terminated(
    green_defined: tuple[dict[str, Any], str],
) -> None:
    """J-1. The other half of the rule: a data-block key Ghidra DEFINES as a string counts as
    terminated although its bytes end in a control byte, not a NUL. The same "green" key, defined
    as a five-byte string before the extraction, is read as "green", marked terminated, and the
    red..cyan table it sits in is no longer given "key_not_terminated".

    MUTATION (verified RED, 1 failed): count only a NUL-terminated run as terminated (drop the
    defined-string half, ``defined ||``) -> "green" reads not terminated again."""
    data, log = green_defined
    assert "DefineString: defined 5 bytes at" in log  # the setup held (precondition)
    table = _table(data["string_tables"]["tables"], "red")
    assert {str(e["key"]): e["key_terminated"] for e in table["entries"]} == {
        "red": True,
        "green": True,
        "blue": True,
        "cyan": True,
    }
    kept = checked_string_tables(
        data["string_tables"]["tables"], read_elf_slots(_FIXTURES / "libtables_x86_64.so")
    )
    (red,) = [t for t in kept if str(t.entries[0].get("key")) == "red"]
    assert len(red.entries) == 4
    assert red.reason == "scope_only"


def _typeinfo_runs(path: Path) -> int:
    """The longest run of the decoy's shape in the ELF itself: two-word typeinfo records, one right
    after another, each {class-type vtable + 16, name string}, so that read one word late they are
    {name, vtable + 16} records at the pointer stride."""
    with path.open("rb") as fh:
        elf = ELFFile(fh)
        dynsym = elf.get_section_by_name(".dynsym")
        assert isinstance(dynsym, SymbolTableSection)
        vptr: set[int] = set()
        name: set[int] = set()
        for sec in elf.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            for rel in sec.iter_relocations():
                sym = dynsym.get_symbol(rel["r_info_sym"]).name if rel["r_info_sym"] else ""
                if (
                    sym.startswith("_ZTVN10__cxxabiv117__class_type_infoE")
                    and rel["r_addend"] == 16
                ):
                    vptr.add(rel["r_offset"])
                elif sym.startswith("_ZTS"):
                    name.add(rel["r_offset"])
    best = 0
    for start in vptr:
        n = 0
        while start + 16 * n in vptr and start + 16 * n + 8 in name:
            n += 1
        best = max(best, n)
    return best


def test_vtables_and_typeinfo_are_no_table(classes_json: dict[str, Any]) -> None:
    """★ Six polymorphic classes with no base class: their vtables and typeinfo records hold names
    and pointers side by side, and none of it is a dispatch table. The typeinfo records are the
    decoy with teeth: emitted one after another, read one word late they are a run of {name,
    imported class-type vtable + 16} records at the pointer stride (checked in the ELF first, so a
    rebuild that loses the shape fails here instead of passing for nothing). The detector refuses
    the run only because that handler is no function Ghidra defined.

    MUTATION (verified RED, 3 failed, this test among them): let the detector take a handler that
    is not a function -> the typeinfo run becomes a five-record table -> RED. (Lowering the
    detector's minimum run to 2 leaves this test green: no record of these classes has a function
    for its handler, so no run of any length forms; that minimum is not what this decoy guards.)
    """
    assert _typeinfo_runs(_FIXTURES / "libclasses_x86_64.so") >= 4  # the decoy (precondition)
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


def _promote_line(log: str) -> dict[str, int]:
    """The integer fields of the promotion pass's summary line in a session log."""
    lines = [ln for ln in log.splitlines() if "[PromoteUndefined] tried=" in ln]
    assert len(lines) == 1, lines
    return {k: int(v) for k, v in re.findall(r"\b(\w+)=(\d+)\b", lines[0])}


def _promoted_entries(data: dict[str, Any]) -> set[int]:
    return {a for a, f in _functions(data).items() if f.get("origin") == "promoted"}


def test_a_block_whose_entry_already_holds_a_function_is_not_created_again(
    truncated: tuple[dict[str, Any], str], tables_json: dict[str, Any]
) -> None:
    """★ With fx_dispatch cut to its first instruction, its other blocks are in no function and
    the promotion pass tries them; each one's entry is fx_dispatch's own, so createFunction hands
    back the function already there. That is no creation: ``created`` and the 'promoted' mark
    stay exactly what the uncut extraction of the same binary has, and fx_dispatch keeps origin
    'analysis'. The count and the mark agree.

    MUTATION (verified RED, 2 failed): count and mark every non-null createFunction return (the
    guard bypassed) -> RED; (verified RED, 1 failed) mark outside the guard -> RED; (verified RED,
    2 failed) read whether a function was there after creating it -> nothing counted or marked
    anywhere -> RED; (verified RED, 2 failed) store the raw sum as ``created`` -> RED; the same two
    changes with the guard's text kept — (verified RED, 2 failed) overwrite ``existed`` after the
    call; (verified RED, 2 failed) overwrite ``created`` with the raw sum -> RED."""
    data, log = truncated
    assert f"TruncateBody: truncated {_TRUNCATED} at" in log  # the setup held (precondition)
    (dispatch,) = [f for f in data["functions"] if f["name"] == _TRUNCATED]
    assert dispatch["origin"] == "analysis"
    assert _promoted_entries(data), "the pass's real creations are still marked"
    assert _promoted_entries(data) == _promoted_entries(tables_json)
    assert data["promote"]["created"] == tables_json["promote"]["created"]
    assert data["promote"]["created"] == len(_promoted_entries(data))


def test_the_log_keeps_the_raw_first_pass_count_beside_the_real_one(
    truncated: tuple[dict[str, Any], str],
) -> None:
    """★ The summary line keeps, for the first pass, the old raw count — every non-null
    createFunction return, the existing function handed back included — so it can be set beside
    an older single-pass log; the stored ``created`` is the real count. Where the pass meets an
    existing entry the two differ: here the second pass creates nothing, so ``created`` is the
    first pass's real count, and the raw count is larger by the returns that landed on
    fx_dispatch.

    MUTATION (verified RED, 1 failed): log the real first-pass count -> RED; (verified RED,
    1 failed) move the raw count inside the guard, its text kept -> RED; (verified RED, 1 failed)
    stop logging the per-pass breakdown -> RED."""
    data, log = truncated
    line = _promote_line(log)
    assert {"created", "pass1_created", "pass2_created"} <= line.keys(), line
    assert line["created"] == data["promote"]["created"]
    assert line["pass2_created"] == 0
    assert line["pass1_created"] > line["created"]


def test_the_pass_puts_back_the_no_return_option_it_froze(
    truncated: tuple[dict[str, Any], str], no_return_off: str
) -> None:
    """★ The pass freezes no-return discovery while it recovers code, then must write back the
    value it saved — what the session had, not a fixed value. Printed just before and just after
    the pass, the option reads the same: Ghidra's default ("true") in one session, and the
    non-default "false" in a session that set it before the pass.

    MUTATION (verified RED, 1 failed): restore "false" instead of the saved value -> RED;
    (verified RED, 1 failed) set the saved value to "false" inside the restore, the restore's text
    kept -> RED; (verified RED, 1 failed) restore "true" instead of the saved value -> RED."""

    def reads(log: str) -> dict[str, str]:
        return dict(re.findall(r"NoReturnOption: (before|after) (\w+)", log))

    assert reads(truncated[1]) == {"before": "true", "after": "true"}
    assert reads(no_return_off) == {"before": "false", "after": "false"}


def test_the_thunks_the_export_skips_are_recorded(promote_json: dict[str, Any]) -> None:
    """The PLT stubs (thunks) are left out of the exported functions, and recorded with their
    bodies so a reader knows they were skipped, not missed.

    MUTATION (verified RED): stop writing the thunks -> RED."""
    thunks = promote_json["thunks"]
    assert thunks
    exported = {int(f["address"], 16) for f in promote_json["functions"]}
    assert not {int(entry, 16) for entry, _body in thunks} & exported
