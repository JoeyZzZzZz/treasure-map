# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The extractor's table-access observations, thunk targets and imported-function addresses, run
for real through Ghidra on compiled fixtures (tests/fixtures/elfs/build.sh).

* libaccess (src/fixture_access.c): code that reads tables in each shape the observations
  describe — a key column handed to a local matcher, a child table, a walked parameter a call
  hands a table, a function pointer read straight from data, a loop whose compare result is
  tested at its head, and a function with more rows than one function keeps. Its argument uses
  show only because an x86 ELF is imported with the System V calling convention (``-cspec gcc``
  on the production command line); under Ghidra's default for x86, Windows', its calls carry no
  arguments.
* libtables: its thunks' targets, and where the image holds each imported function — the
  addresses its {name -> imported function} table points at.

Skipped without Ghidra (run with analyzeHeadless on PATH).
"""

from __future__ import annotations

import base64
import re
import struct
from typing import Any

import pytest

from treasure_map.lib.analyze.ghidra_ingest import TABLE_ACCESS_ROW_KEYS

from .test_extraction_fixtures import _HOME, _extract

pytestmark = pytest.mark.skipif(_HOME is None, reason="analyzeHeadless not on PATH")


@pytest.fixture(scope="module")
def access_json(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    return _extract(tmp_path_factory.mktemp("access"), "libaccess_x86_64.so")[0]


@pytest.fixture(scope="module")
def tables_json(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    return _extract(tmp_path_factory.mktemp("tables_ta"), "libtables_x86_64.so")[0]


def _by_name(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Each function's table-access record, by the function's name."""
    names = {f["address"]: f["name"] for f in data["functions"]}
    return {names[f["f"]]: f for f in data["table_access"]}


def _rows(rec: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    return [r for r in rec["rows"] if r["k"] == kind]


def _bare(use: str) -> str:
    """A use with its iteration / arithmetic prefixes and its site suffixes taken off."""
    return re.sub(r"[@#>].*$", "", re.sub(r"^(?:~|arith>)+", "", use))


def test_a_key_column_handed_to_a_local_matcher_is_told_apart_from_a_guard(
    access_json: dict[str, Any],
) -> None:
    """★ The whole use list, not three kinds. fx_dispatch_local's key column goes to fx_match, a
    matcher of its own, not to a str*cmp; its guard column is only tested; its handler column is
    called; the record pointer escapes to fx_note. Read as "compared / called / tested" only, the
    key column would keep nothing but its test and read exactly like the guard.

    MUTATION (must go RED): record only str*cmp arguments, icalls and tests -> the key column's
    uses are the guard's."""
    rec = _by_name(access_json)["fx_dispatch_local"]
    reads = _rows(rec, "read")
    key = [r for r in reads if any(_bare(u) == "arg:fx_match:0" for u in r["uses"])]
    guard = [r for r in reads if r["uses"] and {_bare(u) for u in r["uses"]} == {"nz"}]
    handler = [r for r in reads if any(_bare(u) == "icall" for u in r["uses"])]
    assert key and guard and handler, reads
    assert {_bare(u) for u in key[0]["uses"]} != {_bare(u) for u in guard[0]["uses"]}
    (ptr,) = _rows(rec, "pointer")
    assert any(_bare(u) == "arg:fx_note:0" for u in ptr["uses"]), ptr


def test_a_child_table_names_its_parent_access_and_a_compare_its_peer_and_its_test(
    access_json: dict[str, Any],
) -> None:
    """fx_dispatch_nested walks the table a group record points to: those reads are nested, and
    carry the parent access (address, offset, form). Its strcmp uses carry the other operand's
    kind (a parameter) and where the result is tested (>tTmM)."""
    rec = _by_name(access_json)["fx_dispatch_nested"]
    nested = [r for r in _rows(rec, "read") if r["bk"] == "nested"]
    assert nested
    for r in nested:
        assert {"p_at", "p_off", "p_form", "p_base"} <= set(r), r
    compares = [u for r in _rows(rec, "read") for u in r["uses"] if "arg:strcmp:0" in u]
    assert compares
    assert all(re.search(r":param@0x[0-9a-f]+#b\d+>~?t\d+m-?\d+$", u) for u in compares), compares


def test_every_family_has_its_rows_and_an_unlinked_or_uncalled_read_has_none(
    access_json: dict[str, Any],
) -> None:
    """★ The scope: (1) every read of a constant base, (2) a child table, (3) a walked parameter
    a call hands a constant data address, with that call, (4) a direct read whose value is called.
    A parameter no call hands a constant address, and a direct read that is not called, are out.

    MUTATION (must go RED): keep only reads of a table already known -> the child table and the
    direct read are gone; keep every walked parameter -> fx_walk_unlinked has rows."""
    by = _by_name(access_json)
    assert {
        "fx_count",
        "fx_dispatch_nested",
        "fx_lookup",
        "fx_dispatch_helper",
        "fx_call_hook",
    } <= set(by), sorted(by)
    assert any(r["bk"] == "imm" for r in _rows(by["fx_count"], "read"))
    assert any(r["bk"] == "nested" for r in _rows(by["fx_dispatch_nested"], "read"))
    walked = _rows(by["fx_lookup"], "read")
    assert walked and all(r["bk"] == "param" and r["param"] == 0 for r in walked), walked
    assert all("base" not in r for r in walked)  # a parameter's base is no address
    args = _rows(by["fx_dispatch_helper"], "arg")
    assert len(args) == 1, args
    arg = args[0]
    assert arg["callee"] == "fx_lookup" and arg["pos"] == 0
    names = {f["name"]: f["address"] for f in access_json["functions"]}
    assert int(arg["callee_at"], 16) == int(names["fx_lookup"], 16)
    directs = _rows(by["fx_call_hook"], "read")
    assert len(directs) == 1, directs
    direct = directs[0]
    assert direct["form"] == "direct" and any(_bare(u) == "icall" for u in direct["uses"])
    assert "fx_walk_unlinked" not in by
    assert "fx_level_of" not in by


def test_a_function_past_the_row_limit_says_it_was_cut(access_json: dict[str, Any]) -> None:
    """★ fx_many calls 600 function pointers: 600 rows, of which 512 are kept, and the function
    says it was cut (with the total) — a reader must not take the prefix for the whole.

    MUTATION (must go RED): cut without saying so -> truncated false; a limit under 300 -> kept
    rows under 300."""
    rec = _by_name(access_json)["fx_many"]
    assert rec["truncated"] is True and rec["total"] == 600
    assert len(rec["rows"]) == 512


def test_the_dominator_table_is_one_list_per_function_indexed_by_block(
    access_json: dict[str, Any],
) -> None:
    """★ Per function, one immediate-dominator list whose index is the block number the rows
    name: the entry -1, every other block >= 0 (or -2, not computed), each row's block within it.
    Only a function with a called or compare-tested row carries it (fx_count has neither). No row
    carries a dominator set of its own: every row key is a listed one."""
    by = _by_name(access_json)
    for name, rec in by.items():
        for r in rec["rows"]:
            assert set(r) <= TABLE_ACCESS_ROW_KEYS, (name, r)
        idom = rec.get("idom")
        needs = any(
            "icall" in u or ">t" in u or ">~t" in u for r in rec["rows"] for u in r.get("uses", [])
        )
        if not needs:
            assert idom is None, name
            continue
        assert isinstance(idom, list) and idom[0] == -1, (name, idom)
        assert all(-2 <= d < len(idom) for d in idom) and all(d != -1 for d in idom[1:]), idom
        assert all(r["bb"] < len(idom) for r in rec["rows"] if "bb" in r), name
    assert "idom" not in by["fx_count"]


def _dominates(idom: list[int], a: int, b: int) -> bool:
    while b >= 0:
        if b == a:
            return True
        b = idom[b]
    return False


def test_a_compare_tested_at_the_loop_head_says_so_and_the_head_dominates_it(
    access_json: dict[str, Any],
) -> None:
    """★ fx_rotated compares in its loop AFTER stepping the pointer, and the result is tested at
    the loop head, next time round: the use carries ">~t<head>m<match>" (through a phi), and the
    head dominates the block of the compare. Without both, the read before the step reads as the
    previous record's key.

    MUTATION (must go RED): stop the test walk at a phi -> no "~"; drop the dominator list -> no
    way to see the head dominate."""
    rec = _by_name(access_json)["fx_rotated"]
    hits = [
        (m, r)
        for r in _rows(rec, "read")
        for u in r["uses"]
        if (m := re.search(r"arg:strcmp:0:\w+@0x[0-9a-f]+#b(\d+)>~t(\d+)m(\d+)$", u))
    ]
    assert hits, rec["rows"]
    m, _row = hits[0]
    cmp_block, head, match = int(m.group(1)), int(m.group(2)), int(m.group(3))
    assert "idom" in rec, sorted(rec)
    assert head != cmp_block and _dominates(rec["idom"], head, cmp_block), rec["idom"]
    # M is the block entered when the result is zero: the one the handler is called in, entered
    # from the head
    calls = [r for r in _rows(rec, "read") if any(_bare(u) == "icall" for u in r["uses"])]
    assert calls and all(r["bb"] == match for r in calls), (match, calls)
    assert rec["idom"][match] == head, rec["idom"]


def test_a_key_that_reaches_its_matcher_through_several_merges_is_followed_there(
    access_json: dict[str, Any],
) -> None:
    """★ fx_deep_key reads the key column, and the value reaches strcmp only through four merges
    of the variable it is held in. Each read of the column that is merged must still carry the
    strcmp argument: stopped short of the call, the key column would read like a column that is
    only tested.

    MUTATION (must go RED): follow a value through 3 copies / phis instead of 6 -> the reads
    furthest from the call keep only their merges."""
    rec = _by_name(access_json)["fx_deep_key"]
    merged = [r for r in _rows(rec, "read") if r["off"] == 0 and "phi" in r["uses"]]
    assert len(merged) >= 4, rec["rows"]
    for r in merged:
        assert any(_bare(u) == "arg:strcmp:0:param" for u in r["uses"]), r


def test_each_thunk_has_its_target_in_a_list_of_its_own(tables_json: dict[str, Any]) -> None:
    """★ thunk_targets has one entry per thunk, in the thunks' order, [entry, target | null,
    name | null]; the thunks entries stay [entry, ranges] — a third element there would make four
    strict readers drop the whole list. A PLT thunk to an import is named, its target null."""
    thunks, targets = tables_json["thunks"], tables_json["thunk_targets"]
    assert all(len(t) == 2 for t in thunks)
    assert [t[0] for t in targets] == [t[0] for t in thunks]
    assert all(len(t) == 3 for t in targets)
    named = {t[2]: t for t in targets}
    assert "strcmp" in named, targets
    assert named["strcmp"][1] is None
    assert any(t[1] is not None for t in targets)  # a thunk to a function of this image


def _words(data: dict[str, Any]) -> set[int]:
    out: set[int] = set()
    for b in data["data_blocks"]["blocks"]:
        if not b.get("initialized") or b.get("executable"):
            continue
        raw = base64.b64decode(b.get("bytes") or "")
        out.update(w for (w,) in struct.iter_unpack("<Q", raw[: len(raw) // 8 * 8]))
    return out


def test_the_imported_functions_are_where_the_tables_point(tables_json: dict[str, Any]) -> None:
    """★ external_symbols names each imported function at its address in the loader's external
    block — the address libtables' {name -> imported function} table holds — and leaves the
    imported data object (fx_blob) out: a data symbol is no handler."""
    ext = {name: int(addr, 16) for addr, name in tables_json["external_symbols"]}
    handlers = {f"fx_ext_{n}" for n in ("one", "two", "three", "four")}
    assert handlers <= set(ext)
    assert "fx_blob" not in ext
    words = _words(tables_json)
    assert {ext[n] for n in handlers} <= words
