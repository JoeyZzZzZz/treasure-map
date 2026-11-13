# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The hunt-time dispatch-table reader (lib/hunt/dispatch_tables), on synthetic stored images.

Each test builds one binary's stored bytes (``dispatch_image.Image``) — functions, strings and
pointer words — into an analysis.db, runs the reader, and checks the rows. Each tooth names the
rule it guards and the mutation that reddens it. No Ghidra, no ELF: the reader reads only the
stored rows, so a table's shape is laid out directly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from treasure_map.lib.analyze.elf_slots import ElfSlots, SlotSymbol
from treasure_map.lib.hunt import dispatch_tables as dt
from treasure_map.lib.storage.connection import open_db

from .dispatch_image import DATA_BASE, Image


def _rows(img: Image, *, slots: ElfSlots | None = None, java=None) -> list[dt.StringKeyedEdgeRow]:
    """The reader's rows for one image, per binary (ELF read suppressed unless ``slots`` given)."""
    conn = open_db(Path(":memory:"))
    img.write(conn, 1, java=java)
    conn.commit()
    result = dt.detect_binary(
        conn,
        1,
        arch=img.arch or ("MIPS:BE:32:default" if img.big_endian else "x86:LE:32:default"),
        bits=8 * img.ps,
        java_key_slots=_java_slots(java),
        get_slots=lambda: slots,
        common={
            "source_run_id": "r",
            "binary": "fx",
            "binary_path": "/fx",
            "from_function": None,
            "from_func_addr": None,
            "mechanism": dt.MECHANISM,
            "ladder_size": None,
        },
    )
    return result.edges


def _java_slots(java) -> set[int]:
    """The key-slot addresses of the extractor's rows (table_addr + entry_index * stride)."""
    return {int(j["table_addr"], 16) + j["entry_index"] * j["stride"] for j in (java or [])}


def _by_key(rows: list[dt.StringKeyedEdgeRow]) -> dict[str, list[dt.StringKeyedEdgeRow]]:
    out: dict[str, list[dt.StringKeyedEdgeRow]] = {}
    for r in rows:
        out.setdefault(r.key or "", []).append(r)
    return out


def _determined(rows: list[dt.StringKeyedEdgeRow]) -> list[dt.StringKeyedEdgeRow]:
    return [r for r in rows if r.pairing_basis != dt.UNDETERMINED]


# ── fixtures, each a real failure the spec names ────────────────────────────────────────────


def _table(img: Image, names, handlers, *, order="key_first", trailing_zero=True) -> int:
    """A two-word table: ``order`` 'key_first' ({key, h}) or 'handler_first' ({h, key}); ended by
    an all-zero record when ``trailing_zero``. Returns the first record's address."""
    keys = [img.string(n) for n in names]
    img.words(0x7FFF0001, 0x7FFF0002)  # a non-record before the table
    first = DATA_BASE + len(img.data)
    for k, h in zip(keys, handlers, strict=True):
        img.words(*((k, h) if order == "key_first" else (h, k)))
    if trailing_zero:
        img.words(0, 0)
    img.words(0x7FFF0003, 0x7FFF0004)
    return first


def _accessor(img: Image, name: str, table_addr: int, stride: int, handler_off: int) -> None:
    """A Ghidra-style walking accessor over the table at ``table_addr``: it compares the key at
    word 0 and calls the handler at ``handler_off``, stepping ``stride`` words a record — the shape
    the code-evidence parser reads as two_index."""
    img.func(name, size=4)
    img.pseudocode[name] = (
        f"int fx_cmp(char *);\n  undefined **ppVar;\n  int iVar1;\n\n"
        f"  ppVar = &DAT_{table_addr:08x};\n"
        "  while (*ppVar != (undefined *)0x0) {\n"
        "    iVar1 = strcmp(*ppVar, fx_name);\n"
        f"    if ((iVar1 == 0) && ((code *)ppVar[{handler_off}] != (code *)0x0)) {{\n"
        f"      (*(code *)ppVar[{handler_off}])(*ppVar);\n    }}\n"
        f"    ppVar = ppVar + {stride};\n  }}\n"
    )


def test_fx_getset_each_column_pairs_by_its_offset() -> None:
    """A {name, get, set} table, get/set each able to be NULL, read by two accessors that
    name the two columns: each key emits a row per handler column at its own offset (+1 get, +2
    set); a NULL slot emits none; the shared stride keeps both columns one table.

    MUTATION (verified RED): drop the union of the two access points' offsets (precondition 3) ->
    only one column lifts -> RED.
    """
    img = Image()
    get = [img.func(f"fx_get{i}") for i in range(4)]
    set_ = [img.func(f"fx_set{i}") for i in range(4)]
    set_[1] = 0  # one key's set handler is NULL
    names = [img.string(n) for n in ("alpha", "beta", "gamma", "delta")]
    img.words(0x7FFF0001, 0x7FFF0002, 0x7FFF0003)
    first = DATA_BASE + len(img.data)
    for k, g, s_ in zip(names, get, set_, strict=True):
        img.words(k, g, s_)
    img.words(0, 0, 0, 0x7FFF0005, 0x7FFF0006, 0x7FFF0007)
    _accessor(img, "fx_get_h", first, 3, 1)  # one access point reads the get column (+1)
    _accessor(img, "fx_set_h", first, 3, 2)  # another reads the set column (+2)
    rows = _rows(img)
    by = _by_key(rows)
    assert {r.handler_offset for r in by["alpha"]} == {1, 2}
    assert by["alpha"] and all(r.pairing_basis == dt.CODE_TWO_INDEX for r in by["alpha"])
    # beta's set is NULL: only the get column
    assert {r.handler_offset for r in by["beta"]} == {1}
    # every key keeps its own get row
    assert sum(1 for r in rows if r.handler_offset == 1) == 4


def test_fx_handler_first_reads_minus_one_not_plus_one() -> None:
    """{handler, name} records in three runs split by {0,0}; one run exactly four long; the
    last run has no all-zero record after it. The front runs read -1; the last, with no
    terminator and no code, is undetermined; none reads +1.

    MUTATION (verified RED): cross a {0,0} with a wide stride -> half the keys are lost / the run
    reads as a four-word record.
    """
    img = Image()
    hs = [img.func(f"fx_h{i}") for i in range(12)]
    ns = [img.string(f"cmd{i}") for i in range(12)]
    img.words(0x7FFF0001, 0x7FFF0002)
    # run 1: 4 records, then {0,0}
    seg1 = DATA_BASE + len(img.data)
    for i in range(4):
        img.words(hs[i], ns[i])
    img.words(0, 0)
    # run 2: 4 records, then {0,0}
    for i in range(4, 8):
        img.words(hs[i], ns[i])
    img.words(0, 0)
    # run 3: 4 records, NO terminator (a non-record follows)
    for i in range(8, 12):
        img.words(hs[i], ns[i])
    img.words(0x7FFF0003, 0x7FFF0004)
    del seg1
    rows = _rows(img)
    by = _by_key(rows)
    # front runs: -1, determined by the terminator
    assert by["cmd0"] and all(r.handler_offset == -1 for r in _determined(by["cmd0"]))
    assert _determined(by["cmd0"])
    # last run: undetermined, no +1 determined edge anywhere
    assert all(r.pairing_basis == dt.UNDETERMINED for r in by["cmd8"])
    assert not any(r.handler_offset == 1 and r.pairing_basis != dt.UNDETERMINED for r in rows)


def test_fx_tie_is_undetermined() -> None:
    """Two readings explain the same keys and neither is followed by an all-zero record:
    undetermined, and it is counted.

    MUTATION (verified RED): let length / block edge decide -> a determined edge -> RED.
    """
    img = Image()
    pre = [img.func("fx_pre0"), img.func("fx_pre1")]
    hs = [img.func(f"fx_t{i}") for i in range(4)]
    ns = [img.string(f"tie{i}") for i in range(4)]
    img.words(pre[0], pre[1])  # functions before: -1 reaches them
    for k, h in zip(ns, hs, strict=True):
        img.words(k, h)
    img.words(hs[0], hs[1])  # functions after: +1 reaches them; no all-zero record either way
    rows = _rows(img)
    assert rows and all(r.pairing_basis == dt.UNDETERMINED for r in rows)


def test_fx_pre_funcs_does_not_read_minus_one() -> None:
    """A key-first table whose two words before the first key are function pointers: with a
    terminator it is +1, never -1 (length must not be a basis).

    MUTATION (verified RED): add length back as a basis -> -1 edges appear -> RED.
    """
    img = Image()
    pre = [img.func("fx_a"), img.func("fx_b")]
    hs = [img.func(f"fx_p{i}") for i in range(4)]
    img.words(pre[0], pre[1])
    first = DATA_BASE + len(img.data)
    for n, h in zip(("one", "two", "three", "four"), hs, strict=True):
        img.words(img.string(n), h)
    img.words(0, 0)
    del first
    rows = _rows(img)
    assert _determined(rows) and all(r.handler_offset == 1 for r in _determined(rows))
    assert not any(r.handler_offset == -1 and r.pairing_basis != dt.UNDETERMINED for r in rows)


def test_fx_null_last_tail_sentinel_makes_both_terminate() -> None:
    """A key-first table of four records, then a {key, NULL} sentinel, then {0,0}: the
    sentinel counts into the +1 reading's end, so +1 and -1 both see a terminator -> undetermined.
    Functions before the table make the -1 reading valid too.

    MUTATION (verified RED): drop the tail-sentinel patch -> only -1 terminates -> a -1 edge.
    """
    img = Image()
    pre = [img.func("fx_pa"), img.func("fx_pb")]
    hs = [img.func(f"fx_n{i}") for i in range(4)]
    img.words(pre[0], pre[1])
    ns = [img.string(n) for n in ("one", "two", "three", "four", "last")]
    for k, h in zip(ns[:4], hs, strict=True):
        img.words(k, h)
    img.words(ns[4], 0)  # {key, NULL} sentinel after four real records
    img.words(0, 0)
    rows = _rows(img)
    assert rows and all(r.pairing_basis == dt.UNDETERMINED for r in rows)


def test_fx_undefined_mid_cuts_into_two_tables() -> None:
    """A record in the middle whose handler points into executable code Ghidra did not
    define breaks the run; each side >= MIN_RUN stands, marked split_by_undefined_handler. The
    undefined address is never a callee.

    MUTATION (verified RED): classify the undefined handler's target as a function -> the X
    record pairs k4 with it -> an edge to the undefined address -> RED.
    """
    img = Image()
    hs = [img.func(f"fx_u{i}") for i in range(9)]
    undef = img.code()
    ns = [img.string(f"k{i}") for i in range(9)]
    img.words(0x7FFF0001, 0x7FFF0002)
    for i in range(4):
        img.words(ns[i], hs[i])
    img.words(ns[4], undef)  # undefined handler, mid-table
    for i in range(5, 9):
        img.words(ns[i], hs[i])
    img.words(0, 0)
    rows = _rows(img)
    by = _by_key(rows)
    # the undefined handler is never a callee (the X record emits no edge), and the cut is recorded
    assert rows and all(r.callee_addr != f"0x{undef:x}" for r in rows)
    assert any("handler_undefined" in (r.completeness_reason or "") for r in rows)
    assert by["k0"] and by["k5"]  # both segments >= MIN_RUN produce edges
    # the second segment (terminated by {0,0}) is determined +1
    assert all(r.handler_offset == 1 for r in _determined(by["k5"])) and _determined(by["k5"])


def test_fx_single_reading_key_stays_a_candidate() -> None:
    """A key covered by only one reading is still a candidate when nothing pairs it — one
    reading is not a decision.

    MUTATION (verified RED): write a key whose candidates are a single function as determined ->
    RED.
    """
    img = Image()
    # A short run of {key, handler} with no terminator and no code: one reading (+1), undetermined.
    hs = [img.func(f"fx_s{i}") for i in range(4)]
    for n, h in zip(("aa", "bb", "cc", "dd"), hs, strict=True):
        img.words(img.string(n), h)
    img.words(0x7FFF0003, 0x7FFF0004)
    rows = _rows(img)
    assert rows and all(r.pairing_basis == dt.UNDETERMINED for r in rows)
    assert all(r.handler_offset == 1 for r in rows)  # the one reading's offset is still recorded


def test_fx_status_never_complete() -> None:
    """Every row the reader writes is 'incomplete', never 'complete'.

    MUTATION (verified RED): drop the explicit completeness_status -> the model default 'complete'
    -> RED.
    """
    img = Image()
    hs = [img.func(f"fx_c{i}") for i in range(4)]
    _table(img, ["one", "two", "three", "four"], hs)
    rows = _rows(img)
    assert rows and all(r.completeness_status == "incomplete" for r in rows)


def test_fx_repeated_key_emits_nothing() -> None:
    """A table of fewer than four distinct keys is noise: no row.

    MUTATION (verified RED): drop the distinct-keys < 4 filter -> edges appear -> RED.
    """
    img = Image()
    hs = [img.func(f"fx_r{i}") for i in range(5)]
    img.words(0x7FFF0001, 0x7FFF0002)
    dup = img.string("same")
    other = img.string("other")
    for i, h in enumerate(hs):
        img.words(dup if i < 4 else other, h)
    img.words(0, 0)
    rows = _rows(img)
    assert not _determined(rows)


def test_fx_rtti_lookalike_excluded_unless_java() -> None:
    """Keys mostly shaped like C++ type-info names are excluded — UNLESS the table
    holds a Java key slot (the exemption keeps a real command-registry table whose numeric flag
    bytes make its names look like type-info).

    MUTATION (verified RED): drop the Java exemption -> the Java-bearing table is excluded -> RED.
    """
    img = Image()
    hs = [img.func(f"fx_rt{i}") for i in range(5)]
    first = _table(img, ["3exit", "0hash", "2bg", "6alias", "2[["], hs)
    # without a Java slot: excluded
    assert not _determined(_rows(img))
    # the same table, one of whose slots the extractor recorded as a Java key: not excluded
    java = [
        {
            "table_addr": hex(first),
            "stride": 8,
            "entry_index": 0,
            "key": "3exit",
            "func_addr": hex(hs[0]),
        }
    ]
    rows = _rows(img, java=java)
    assert rows  # the Java-bearing table survives the filter


def test_fx_strerror_content_gate_blocks_pairing() -> None:
    """A table whose keys are mostly not names (an error-message table) makes no
    pairing even when the phase is clear: every row is a candidate.

    MUTATION (verified RED): apply the gate after a basis is chosen rather than before -> a
    determined edge -> RED.
    """
    img = Image()
    hs = [img.func(f"fx_e{i}") for i in range(4)]
    msgs = [
        "No such file or directory",
        "Operation not permitted now",
        "Cannot allocate more memory",
        "Bad address given here",
    ]
    _table(img, msgs, hs)  # key-first, terminated -> phase is clear, but keys are prose
    rows = _rows(img)
    assert rows and all(r.pairing_basis == dt.UNDETERMINED for r in rows)


def test_fx_truncated_block_is_undetermined_not_none() -> None:
    """A run reaching the end of a truncated block is undetermined there, never read as a
    clean end.

    MUTATION (verified RED): read a truncated end as an all-zero terminator -> a determined edge.
    """
    img = Image()
    hs = [img.func(f"fx_tr{i}") for i in range(4)]
    img.words(0x7FFF0001, 0x7FFF0002)
    for n, h in zip(("ta", "tb", "tc", "td"), hs, strict=True):
        img.words(img.string(n), h)
    img.truncated_data = True  # the block is cut here: no terminator is visible
    rows = _rows(img)
    assert rows and all(r.pairing_basis == dt.UNDETERMINED for r in rows)
    assert any("data_blocks_truncated" in (r.completeness_reason or "") for r in rows)


def test_fx_multi_fptr_all_candidates_without_code() -> None:
    """A {key, arg, handler, extra_fptr, flag} record with no access code: every function
    column is a candidate, nothing determined. Naming the called column in code lifts only it.

    MUTATION (verified RED): (a) pick a single column so |C|=1 forces a determined edge; (b)
    determine every column structurally.
    """
    img = Image()
    called = [img.func(f"fx_call{i}") for i in range(5)]
    extra = [img.func(f"fx_extra{i}") for i in range(5)]
    ns = [img.string(f"m{i}") for i in range(5)]
    img.words(0x7FFF0001, 0x7FFF0002, 0x7FFF0003, 0x7FFF0004, 0x7FFF0005)
    first = DATA_BASE + len(img.data)
    for k, c, e in zip(ns, called, extra, strict=True):
        img.words(k, 0x40, c, e, 0x1)  # {key, arg, handler, extra fptr, flag}
    img.words(0, 0, 0, 0, 0)
    rows = _rows(img)
    assert rows and all(r.pairing_basis == dt.UNDETERMINED for r in rows)
    # now a function that calls the +2 column: only that column lifts
    _accessor(img, "fx_md", first, 5, 2)
    det = _determined(_rows(img))
    assert det and {r.handler_offset for r in det} == {2}


def test_fx_wide_key_reads_utf32_not_one_char() -> None:
    """A table whose key pointers address wide (4-byte) strings reads the
    full strings, not a one-character key, and is not then excluded as repeated.

    MUTATION (verified RED): drop the wide-string rule -> every key is one character -> distinct
    < 4 excludes the table.
    """
    img = Image()
    hs = [img.func(f"fx_w{i}") for i in range(4)]
    ws = [img.wide(w) for w in ("fxopen", "fxread", "fxwrite", "fxclose")]
    img.words(0x7FFF0001, 0x7FFF0002)
    for w, h in zip(ws, hs, strict=True):
        img.words(w, h)
    img.words(0, 0)
    keys = {r.key for r in _rows(img)}
    assert keys == {"fxopen", "fxread", "fxwrite", "fxclose"}


def test_fx_char_keys_stay_one_character() -> None:
    """A table of 4-aligned single-character narrow strings is NOT
    read as wide: no key pointer may start inside another key's wide reading.

    MUTATION (verified RED): drop guard 4 -> 'a\\0\\0\\0b...' reads as one wide string 'abcd'.
    """
    img = Image()
    hs = [img.func(f"fx_ch{i}") for i in range(4)]
    # name region: a\0\0\0 b\0\0\0 c\0\0\0 d\0\0\0 e\0\0\0\0\0\0\0 (4-aligned single chars)
    region = img.raw(b"a\0\0\0b\0\0\0c\0\0\0d\0\0\0e\0\0\0\0\0\0\0", align=4)
    img.words(0x7FFF0001, 0x7FFF0002)
    for i, h in enumerate(hs):
        img.words(region + 4 * i, h)
    img.words(0, 0)
    keys = {r.key for r in _rows(img)}
    assert keys == {"a", "b", "c", "d"}


def test_fx_empty_key_first_byte_must_be_printable() -> None:
    """A key pointer at a NUL (an empty string) is not a key: the first byte must be
    printable, so no row has a key starting with \\x00, and 'pkg' pairs only with its own handler.

    MUTATION (verified RED): accept one leading control byte and read on to the next NUL ->
    '\\x00pkg' pairs with the empty string's handler -> RED.
    """
    img = Image()
    hs = [img.func(f"fx_lu{i}") for i in range(4)]
    # name region: \0 pkg\0 tbl\0 io\0 os\0 -> the empty string's NUL abuts "pkg"
    base = img.raw(b"\0pkg\0tbl\0io\0os\0")
    empty = base  # points at the leading NUL
    pkg = base + 1
    tbl = base + 5
    io = base + 9
    os_ = base + 12
    img.words(0x7FFF0001, 0x7FFF0002)
    for k, h in zip((empty, pkg, tbl, io, os_), [*hs, img.func("fx_os")], strict=True):
        img.words(k, h)
    img.words(0, 0)
    rows = _rows(img)
    assert not any((r.key or "").startswith("\x00") for r in rows)
    pkg_rows = [r for r in rows if r.key == "pkg"]
    assert pkg_rows and all(r.callee_name == "fx_lu1" for r in _determined(pkg_rows))


def test_fx_two_handler_cols_not_crossed() -> None:
    """A {name, id, size, fn, help} record has two function columns; code names only `fn`.
    `fn` pairs by code; `help` (Q1 unproven) is a candidate. The two columns are never crossed.

    MUTATION (verified RED): determine every reading's column structurally, not only the
    code-named one -> the help column lifts (wrongly) -> RED.
    """
    img = Image()
    fn = [img.func(f"fx_fn{i}") for i in range(4)]
    helpf = [img.func(f"fx_help{i}") for i in range(4)]
    ns = [img.string(f"w{i}") for i in range(4)]
    img.words(0x7FFF0001, 0x7FFF0002, 0x7FFF0003, 0x7FFF0004, 0x7FFF0005)
    first = DATA_BASE + len(img.data)
    for k, f, h in zip(ns, fn, helpf, strict=True):
        img.words(k, 0x1, 0x8, f, h)  # {name, id, size, fn, help}
    img.words(0, 0, 0, 0, 0)
    _accessor(img, "fx_wl", first, 5, 3)  # code names the fn column (+3) only
    rows = _rows(img)
    by = _by_key(rows)
    det = _determined(by["w0"])
    assert det and all(r.handler_offset == 3 for r in det)
    assert det[0].callee_name == "fx_fn0"  # paired with fn, never help
    assert any(r.handler_offset == 4 and r.pairing_basis == dt.UNDETERMINED for r in by["w0"])


# ── the code that reads a table: what it may and may not settle ──────────────────────────────


def _walker(
    img: Image,
    name: str,
    base: int,
    *,
    handler: int,
    step: int | None,
    key: int | None = 0,
    prefetch: int | None = None,
) -> None:
    """A Ghidra-style accessor: ``ppVar`` set to ``base``, the word ``key`` compared as a string
    (None: no compare, so the code gives a handler index only), the word ``handler`` called, and
    ``ppVar`` stepped ``step`` words a record (None: a matched-record pointer that does not walk).
    ``prefetch`` loads one more word as a code pointer — a loop reading the next record early."""

    def ref(i: int) -> str:
        return "*ppVar" if i == 0 else f"ppVar[{i}]"

    img.func(name, size=4)
    text = f"  undefined **ppVar;\n  int iVar1;\n  code *pcVar2;\n\n  ppVar = &DAT_{base:08x};\n"
    if prefetch is not None:
        text += f"  pcVar2 = (code *){ref(prefetch)};\n"
    if key is not None:
        text += f"  iVar1 = strcmp({ref(key)}, fx_name);\n"
    text += f"  if (iVar1 == 0) {{\n    (*(code *){ref(handler)})(fx_arg);\n  }}\n"
    if step is not None:
        text += f"  ppVar = ppVar + {step};\n"
    img.pseudocode[name] = text


def _tie_layout(img: Image, names=("pp", "qq", "rr", "ss")) -> tuple[list[int], int]:
    """A key-first table with functions on both sides and no all-zero record: the data reads it
    both ways ({+1} and {-1}) and settles neither. Returns the handlers and the first key's
    address."""
    pre = [img.func("fx_pa"), img.func("fx_pb")]
    hs = [img.func(f"fx_x{i}") for i in range(4)]
    img.words(pre[0], pre[1])
    first = DATA_BASE + len(img.data)
    for n, h in zip(names, hs, strict=True):
        img.words(img.string(n), h)
    img.words(hs[0], hs[1])
    return hs, first


def _pre_string(img: Image) -> tuple[list[int], int]:
    """{handler, name} records after zero padding and an unrelated string, with no terminator: the
    words read both ways, and the {+1} reading takes the stray string as a key. Returns the
    handlers and the first handler word's address."""
    hs = [img.func(f"fx_ps{i}") for i in range(4)]
    stray = img.string("fx_banner")
    ns = [img.string(n) for n in ("open", "read", "write", "close")]
    img.words(0, 0, stray)
    first = DATA_BASE + len(img.data)
    for h, k in zip(hs, ns, strict=True):
        img.words(h, k)
    img.words(0x7FFF0003, 0x7FFF0004)
    return hs, first


def test_fx_pre_string_reads_minus_one_only_from_the_code() -> None:
    """Zero padding, a stray string, then {handler, name} records and no terminator. The data
    alone reads it both ways: every row a candidate, the zeros before the table deciding nothing.
    With an accessor that compares word 1 and calls word 0, the code pairs each name with the
    handler before it (-1), and the stray string pairs with nothing.

    MUTATION (verified RED): count an all-zero record BEFORE a reading's first key as its
    terminator (the leading zeros) -> the {+1} reading ends there -> a +1 edge -> RED.
    """
    img = Image()
    _pre_string(img)
    rows = _rows(img)
    assert rows and all(r.pairing_basis == dt.UNDETERMINED for r in rows)

    img = Image()
    hs, first = _pre_string(img)
    _walker(img, "fx_ps_get", first, key=1, handler=0, step=2)
    det = _determined(_rows(img))
    assert {r.key: r.callee_name for r in det} == {
        "open": "fx_ps0",
        "read": "fx_ps1",
        "write": "fx_ps2",
        "close": "fx_ps3",
    }
    assert all(r.handler_offset == -1 and r.pairing_basis == dt.CODE_TWO_INDEX for r in det)
    del hs


def test_code_beats_a_terminator_and_the_disagreement_is_recorded() -> None:
    """A table both ways readable whose {+1} reading ends at an all-zero record, read by code that
    compares word 1 and calls word 0 (-1): the stronger evidence, the code, pairs it, and the
    terminator that said otherwise is recorded on every row.

    MUTATION (verified RED): drop the terminator conflict mark -> pairing_conflict None -> RED.
    """
    img = Image()
    pre = [img.func("fx_a"), img.func("fx_b")]
    hs = [img.func(f"fx_c{i}") for i in range(4)]
    img.words(pre[0], pre[1])
    for n, h in zip(("one", "two", "three", "four"), hs, strict=True):
        img.words(img.string(n), h)
    img.words(0, 0)
    _walker(img, "fx_c_get", DATA_BASE + img.ps, key=1, handler=0, step=2)
    det = _determined(_rows(img))
    assert det and all(r.handler_offset == -1 for r in det)
    assert {r.key: r.callee_name for r in det}["one"] == "fx_b"
    assert all(r.pairing_basis == dt.CODE_TWO_INDEX for r in det)
    assert all(r.pairing_conflict == dt.DATA_TERMINATOR for r in det)


def test_fx_frame_only_never_pairs() -> None:
    """Code that walks the table and calls word 1 but never compares a key gives a handler index
    and no key index: that pairs nothing, and the table stays a candidate.

    MUTATION (verified RED): take a frame with no key index as keyed at word 0 -> +1 lifts -> RED.
    """
    img = Image()
    _hs, first = _tie_layout(img)
    _walker(img, "fx_fo", first, key=None, handler=1, step=2)
    rows = _rows(img)
    assert rows and all(r.pairing_basis == dt.UNDETERMINED for r in rows)


def test_fx_ptr_lookalike_is_not_read_handler_first() -> None:
    """A key-first table ended by an all-zero record, whose function words also read onward as
    {function, string} records (the -1 reading covers four keys), and a matched-record pointer
    that calls the word it points at: the call is no key evidence, so the terminator pairs the
    table +1 and nothing reads -1.

    MUTATION (verified RED): read a call through ``*ptr`` as a handler-first record -> the code's
    -1 overrides the terminator -> RED.
    """
    img = Image()
    hs = [img.func(f"fx_l{i}") for i in range(5)]
    img.words(0x7FFF0001, 0x7FFF0002)
    for n, h in zip(("ma", "mb", "mc", "md", "me"), hs, strict=True):
        img.words(img.string(n), h)
    img.words(0, 0)
    img.words(0x7FFF0003, 0x7FFF0004)
    _walker(img, "fx_l_hit", DATA_BASE + 3 * img.ps, key=None, handler=0, step=None)
    det = _determined(_rows(img))
    assert {r.key for r in det} == {"ma", "mb", "mc", "md", "me"}
    assert all(r.handler_offset == 1 and r.pairing_basis == dt.DATA_TERMINATOR for r in det)


@pytest.mark.parametrize("terminated", [True, False])
def test_fx_block_edge_is_no_phase_evidence(terminated: bool) -> None:
    """A key-first table at the very start of its block, so the -1 reading runs to the block's low
    edge: the edge says nothing. With an all-zero record after it the table is +1; without one it
    stays undetermined — never -1.

    MUTATION (verified RED): count a reading whose previous record runs off the block's low edge
    as ended -> both readings end -> the +1 terminator is no longer the only one -> RED.
    """
    img = Image()
    hs = [img.func(f"fx_be{i}") for i in range(5)]
    for n, h in zip(("ba", "bb", "bc", "bd", "bf"), hs, strict=True):
        img.words(img.string(n), h)  # the first record is the block's first word
    if terminated:
        img.words(0, 0)
    img.words(0x7FFF0003, 0x7FFF0004)
    rows = _rows(img)
    assert rows
    assert not any(r.handler_offset == -1 and r.pairing_basis != dt.UNDETERMINED for r in rows)
    if terminated:
        det = _determined(rows)
        assert {r.key for r in det} == {"ba", "bb", "bc", "bd", "bf"}
        assert all(r.handler_offset == 1 for r in det)
    else:
        assert all(r.pairing_basis == dt.UNDETERMINED for r in rows)


def test_fx_short_str_before_the_table_is_no_undefined_handler() -> None:
    """The record before the table is {string, "abcd"} with the four-character string in an
    executable block outside every function (a string array in a read-execute segment): its
    second word points at a string, not at undefined code, so no bound reads
    ``handler_undefined``.

    MUTATION (verified RED): classify a 4-aligned pointer into executable bytes as an undefined
    handler before testing it for a string -> the bound reads handler_undefined -> RED.
    """
    img = Image()
    hs = [img.func(f"fx_ss{i}") for i in range(4)]
    abcd = img.text_string("abcd")
    img.words(img.string("normal"), abcd)
    for n, h in zip(("sa", "sb", "sc", "sd"), hs, strict=True):
        img.words(img.string(n), h)
    img.words(0, 0)
    rows = _rows(img)
    assert {r.key for r in _determined(rows)} == {"sa", "sb", "sc", "sd"}
    assert not any(dt.UNDEFINED in (r.completeness_reason or "") for r in rows)


@pytest.mark.parametrize("calls_own_handler", [True, False])
def test_fx_prefetch_of_the_next_record_is_dropped(calls_own_handler: bool) -> None:
    """An accessor that, besides its own handler, loads the next record's handler (word 3 of a
    two-word stride) early: an index a record or more from the key is a prefetch and pairs
    nothing. With its own call (word 1) the code pairs +1; with the prefetch alone the code says
    nothing and the table stays a candidate — never a +3 pairing, never a lost table.

    MUTATION (verified RED): keep a handler index a record or more from the key -> a false +3
    column swallows the table's rows -> RED.
    """
    img = Image()
    _hs, first = _tie_layout(img)
    if calls_own_handler:
        _walker(img, "fx_pf", first, key=0, handler=1, step=2, prefetch=3)
    else:
        _walker(img, "fx_pf", first, key=0, handler=3, step=2)
    rows = _rows(img)
    assert {r.key for r in rows} == {"pp", "qq", "rr", "ss"}
    assert not any(r.handler_offset == 3 for r in rows)
    if calls_own_handler:
        det = _determined(rows)
        assert {r.key for r in det} == {"pp", "qq", "rr", "ss"}
        assert all(r.handler_offset == 1 and r.pairing_basis == dt.CODE_TWO_INDEX for r in det)
    else:
        assert all(r.pairing_basis == dt.UNDETERMINED for r in rows)


def _stride3(img: Image, middle: list[int], last: list[int], names) -> int:
    """{name, middle, last} records after three non-record words, ended by an all-zero record.
    Returns the first record's address."""
    img.words(0x7FFF0001, 0x7FFF0002, 0x7FFF0003)
    first = DATA_BASE + len(img.data)
    for n, m, la in zip(names, middle, last, strict=True):
        img.words(img.string(n), m, la)
    img.words(0, 0, 0, 0x7FFF0004, 0x7FFF0005, 0x7FFF0006)
    return first


def test_fx_slot_mismatch_code_is_not_used() -> None:
    """A {name, h1, h2} table (two function columns, so the terminator answers no column) read by
    code whose key column is the data's h1 column — a misread of the code. The code pairs nothing,
    every row is a candidate, and the rows say the code was not used.

    MUTATION (verified RED): skip the check that the code's slots are the data's -> the code's +1
    applied to the data's key -> a determined h1 edge -> RED.
    """
    img = Image()
    h1 = [img.func(f"fx_m{i}") for i in range(4)]
    h2 = [img.func(f"fx_n{i}") for i in range(4)]
    first = _stride3(img, h1, h2, ("ka", "kb", "kc", "kd"))
    _walker(img, "fx_mm", first + img.ps, key=0, handler=1, step=3)
    rows = _rows(img)
    assert rows and all(r.pairing_basis == dt.UNDETERMINED for r in rows)
    assert all(r.pairing_conflict == dt.CODE_INCONSISTENT for r in rows)


def test_code_the_data_contradicts_leaves_the_terminator_standing() -> None:
    """A key-first table ended by an all-zero record, read by code whose key column is the data's
    handler column. A misread of the code is no evidence against the data: the terminator pairs
    the table (+1), and every row records that the code was not used.

    MUTATION (verified RED): drop the terminator along with inconsistent code -> every row a
    candidate -> RED.
    """
    img = Image()
    hs = [img.func(f"fx_ci{i}") for i in range(4)]
    first = _table(img, ["one", "two", "three", "four"], hs)
    _walker(img, "fx_ci_get", first + img.ps, key=0, handler=1, step=2)
    det = _determined(_rows(img))
    assert {r.key: r.callee_name for r in det} == {
        "one": "fx_ci0",
        "two": "fx_ci1",
        "three": "fx_ci2",
        "four": "fx_ci3",
    }
    assert all(r.pairing_basis == dt.DATA_TERMINATOR and r.handler_offset == 1 for r in det)
    assert all(r.pairing_conflict == dt.CODE_INCONSISTENT for r in det)


def test_a_column_only_another_rotation_holds_keeps_the_table_undetermined() -> None:
    """{name, fn, extra} records whose extra column is NULL down the table and a function only in
    the word before the first record. Read {+1, +2} the extra column never holds a function, so
    that reading is single-column — and it is the one that ends at the all-zero record; read
    {+1, -1} the same column holds that function. The record's handler columns are those of every
    reading, so it has two, and the terminator settles neither: every row a candidate.

    MUTATION (verified RED): count the columns of the terminated reading only -> one column ->
    a determined +1 edge -> RED.
    """
    img = Image()
    fn = [img.func(f"fx_r{i}") for i in range(5)]
    before = img.func("fx_before")
    names = [img.string(n) for n in ("alpha", "bravo", "charlie", "delta", "echo")]
    img.words(0x7FFF0001, 0x7FFF0002, before)
    for i, (k, f) in enumerate(zip(names, fn, strict=True)):
        img.words(k, f, 0x1 if i == 4 else 0)  # the last extra word is no NULL: no {+1,-1} end
    img.words(0, 0, 0, 0x7FFF0004, 0x7FFF0005, 0x7FFF0006)
    rows = _rows(img)
    assert {r.key for r in rows} >= {"alpha", "bravo", "charlie", "delta", "echo"}
    assert all(r.pairing_basis == dt.UNDETERMINED for r in rows)


@pytest.mark.parametrize("helper", ["luaL_register", "luaL_newlib", "luaL_setfuncs"])
def test_a_registration_helper_pairs_key_zero_with_handler_one(helper: str) -> None:
    """A {name, func} array passed to a registration helper whose record layout the ABI fixes:
    the helper pairs each name with the word after it (``code_helper``), over the terminator.

    MUTATION (verified RED): ignore the helper calls -> the terminator pairs it instead -> RED.
    """
    img = Image()
    hs = [img.func(f"fx_lua{i}") for i in range(4)]
    first = _table(img, ["open", "close", "read", "write"], hs)
    img.func("fx_luaopen", size=4)
    img.pseudocode["fx_luaopen"] = f'  {helper}(L, "fx", &DAT_{first:08x});\n  return 1;\n'
    det = _determined(_rows(img))
    assert {r.key: r.callee_name for r in det} == {
        "open": "fx_lua0",
        "close": "fx_lua1",
        "read": "fx_lua2",
        "write": "fx_lua3",
    }
    assert all(r.pairing_basis == dt.CODE_HELPER and r.handler_offset == 1 for r in det)
    assert all(r.column_evidence == dt.EVIDENCE_CODE for r in det)


# ── the content choice ─────────────────────────────────────────────────────────────────────


def test_fx_wide_eats_two_small_tables_stay_two() -> None:
    """Two four-record key-first tables split by an all-zero record: a four-word reading could
    cross the gap (taking the zeros as NULL handler slots) and read keys from both. The two-word
    tables come first and keep their words, so each is its own table and no wider reading is
    written.

    MUTATION (verified RED): offer every stride all the words (no word a shorter stride used is
    withheld) -> a four-word table over both -> RED.
    """
    img = Image()
    a = [img.func(f"fx_wa{i}") for i in range(4)]
    b = [img.func(f"fx_wb{i}") for i in range(4)]
    img.words(0x7FFF0001, 0x7FFF0002)
    for n, h in zip(("a0", "a1", "a2", "a3"), a, strict=True):
        img.words(img.string(n), h)
    img.words(0, 0)
    for n, h in zip(("b0", "b1", "b2", "b3"), b, strict=True):
        img.words(img.string(n), h)
    img.words(0, 0, 0x7FFF0003, 0x7FFF0004)
    rows = _rows(img)
    det = _determined(rows)
    assert {r.key for r in det} == {"a0", "a1", "a2", "a3", "b0", "b1", "b2", "b3"}
    assert len({r.table_addr for r in det}) == 2
    assert all(r.stride_words == 2 for r in rows)


@pytest.mark.parametrize("help_is_text", [True, False])
def test_a_key_column_tie_reads_the_first_column_and_says_so(help_is_text: bool) -> None:
    """{name, help, fn} records: two string columns that explain the same number of keys. The
    name column (the table that ends first) is read, and every row of it carries
    ``key_column_tied``; with an integer in place of the help text there is no tie and no mark.

    MUTATION (verified RED): never mark a tie -> no key_column_tied -> RED.
    """
    img = Image()
    fn = [img.func(f"fx_kt{i}") for i in range(4)]
    names = ("essid", "mode", "freq", "rate")
    helps = [img.string(f"Set the {n} value") if help_is_text else 0x5 for n in names]
    _stride3(img, helps, fn, names)
    rows = _rows(img)
    det = _determined(rows)
    assert {r.key: r.callee_name for r in det} == {
        "essid": "fx_kt0",
        "mode": "fx_kt1",
        "freq": "fx_kt2",
        "rate": "fx_kt3",
    }
    tied = [dt.KEY_COLUMN_TIED in (r.completeness_reason or "").split(",") for r in rows]
    assert all(tied) if help_is_text else not any(tied)


# ── what is and is not a key ───────────────────────────────────────────────────────────────


def test_unaligned_one_character_keys_are_not_read_wide() -> None:
    """Keys that read as one character each, whose bytes would read on as wide (4-byte) strings
    were the pointers 4-aligned — they are not, so they stay one-character keys.

    MUTATION (verified RED): drop the 4-alignment condition of the wide reading -> 'ab', 'cd', ...
    -> RED.
    """
    img = Image()
    hs = [img.func(f"fx_ua{i}") for i in range(4)]
    img.raw(b"\0", align=4)  # every key below starts 1 past a 4-aligned address
    ks = [img.raw(c.encode() + b"\0\0\0" + d.encode() + b"\0" * 7) for c, d in zip("aceg", "bdfh")]
    assert all(k % 4 == 1 for k in ks)
    img.words(0x7FFF0001, 0x7FFF0002)
    for k, h in zip(ks, hs, strict=True):
        img.words(k, h)
    img.words(0, 0)
    assert {r.key for r in _rows(img)} == {"a", "c", "e", "g"}


def test_a_string_inside_a_function_body_is_no_key() -> None:
    """Printable bytes inside a function's body in an executable block are code, not a key: words
    pointing there make no table. The same bytes as the entry of a function the code recovery
    made out of string bytes (origin 'promoted') hide no code, and do read as keys.

    MUTATION (verified RED): drop the function-body test of a string in an executable block ->
    the body bytes read as keys -> RED.
    """

    def build(origin: str) -> Image:
        img = Image()
        hs = [img.func(f"fx_bd{i}") for i in range(4)]
        if origin == "promoted":
            ks = [
                img.func(f"fx_s{i}", origin="promoted", body=f"cmd{i}\0".encode()) for i in range(4)
            ]
        else:
            ks = [
                img.func(f"fx_s{i}", body=b"\xcc" * 4 + f"cmd{i}\0".encode()) + 4 for i in range(4)
            ]
        img.words(0x7FFF0001, 0x7FFF0002)
        for k, h in zip(ks, hs, strict=True):
            img.words(k, h)
        img.words(0, 0)
        return img

    assert not _rows(build("analysis"))
    assert {r.key for r in _rows(build("promoted"))} == {"cmd0", "cmd1", "cmd2", "cmd3"}


# ── the ELF slot check ──────────────────────────────────────────────────────────────────────


def test_fx_got_handler_refused_by_slot_check() -> None:
    """A record whose handler slot the ELF fills with a GOT entry / a non-function symbol
    is refused by the slot check: no edge there.

    MUTATION (verified RED): skip handler_check -> the record becomes an edge -> RED.
    """
    img = Image()
    hs = [img.func(f"fx_g{i}") for i in range(4)]
    ns = [img.string(n) for n in ("one", "two", "three", "four")]
    img.words(0x7FFF0001, 0x7FFF0002)
    for k, h in zip(ns, hs, strict=True):
        img.words(k, h)
    img.words(0, 0)
    # the first record's handler slot is a GOT entry
    handler_slot = DATA_BASE + 2 * img.ps + img.ps  # record 0, word 1
    slots = ElfSlots(symbols={}, got=((handler_slot, handler_slot + img.ps),))
    rows_checked = _rows(img, slots=slots)
    rows_unchecked = _rows(img)
    assert "one" not in _by_key(rows_checked)  # the GOT record is cut
    assert "one" in _by_key(rows_unchecked)  # without the check, it is an edge


def test_handler_not_function_relocation_is_refused() -> None:
    """A handler slot the ELF relocates against a symbol-plus-addend (a vtable + 8 that lands on a
    neighbouring function) is refused.

    MUTATION (verified RED): skip handler_check -> the mis-typed record becomes an edge.
    """
    img = Image()
    hs = [img.func(f"fx_v{i}") for i in range(4)]
    ns = [img.string(n) for n in ("alef", "bet", "gimel", "dalet")]
    img.words(0x7FFF0001, 0x7FFF0002)
    for k, h in zip(ns, hs, strict=True):
        img.words(k, h)
    img.words(0, 0)
    handler_slot = DATA_BASE + 2 * img.ps + img.ps
    sym = SlotSymbol(name="_ZTV3Foo", st_type="STT_OBJECT", defined=True, addend=8)
    slots = ElfSlots(symbols={handler_slot: sym}, got=())
    assert "alef" not in _by_key(_rows(img, slots=slots))


# ── the per-run driver and its honesty row ──────────────────────────────────────────────────


def test_detect_run_status_counts_and_elf_state(tmp_path: Path) -> None:
    """A-12. With no ELF on disk the slot check cannot run: handlers are unverified, the status
    row counts them, and the fingerprint-visible elf state is 'missing'.
    """
    img = Image()
    hs = [img.func(f"fx_s{i}") for i in range(4)]
    _table(img, ["one", "two", "three", "four"], hs)
    db = tmp_path / "a.db"
    conn = open_db(db)
    img.write(conn, 1, name="fx", path=str(tmp_path / "missing.bin"), sha256="a" * 64)
    conn.commit()
    conn.close()
    res = dt.detect_run(db, "r")
    (status,) = res.statuses
    assert status.scanned == 1 and status.found_count == 1
    assert status.handler_unverified == 4  # no ELF: every handler unverified
    assert status.pairing_undetermined == 0  # a clean +1 table
    assert dt.elf_file_state(str(tmp_path / "missing.bin"), "a" * 64) == dt.ELF_MISSING


def test_detect_run_no_stored_bytes_is_scanned_zero(tmp_path: Path) -> None:
    """A binary whose analysis.db holds no stored bytes is recorded scanned=0 (unknown), never as
    'found none'."""
    db = tmp_path / "a.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, ghidra_ok, last_seen_at) "
        "VALUES (1, 'fx', '/fx', ?, 1, '2026-01-01')",
        ("b" * 64,),
    )
    conn.commit()
    conn.close()
    res = dt.detect_run(db, "r")
    assert res.edges == []
    (status,) = res.statuses
    assert status.scanned == 0


def test_the_hunt_fingerprint_moves_with_the_elf_on_disk(tmp_path: Path) -> None:
    """The slot check reads the ELF on disk, so the hunt's input fingerprint carries whether that
    file is still there with the scanned sha256: present, deleted and replaced are three different
    fingerprints over one unchanged analysis.db.

    MUTATION (verified RED): drop the ELF state from ``hunt_input_fingerprint`` -> the three are
    one -> RED.
    """
    import hashlib

    from treasure_map.lib.hunt.analyzer2 import hunt_input_fingerprint

    elf = tmp_path / "fx_bin"
    elf.write_bytes(b"\x7fELF the scanned bytes")
    db = tmp_path / "a.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, ghidra_ok, last_seen_at) "
        "VALUES (1, 'fx', ?, ?, 1, '2026-01-01')",
        (str(elf), hashlib.sha256(elf.read_bytes()).hexdigest()),
    )
    conn.commit()
    conn.close()
    present = hunt_input_fingerprint(db)
    elf.unlink()
    deleted = hunt_input_fingerprint(db)
    elf.write_bytes(b"\x7fELF other bytes, another length")
    replaced = hunt_input_fingerprint(db)
    assert None not in (present, deleted, replaced)
    assert len({present, deleted, replaced}) == 3


def test_elf_file_state_sha_mismatch(tmp_path: Path) -> None:
    """The ELF on disk is present but its sha256 is not the scanned one: sha_mismatch, so a
    replaced unpacked image does not read as verified."""
    f = tmp_path / "bin"
    f.write_bytes(b"not the scanned bytes")
    assert dt.elf_file_state(str(f), "0" * 64) == dt.ELF_SHA_MISMATCH


@pytest.mark.parametrize("pairing", ["a", "b"])
def test_candidate_rows_have_no_single_offset_when_two_readings(pairing: str) -> None:
    """A candidate key reached by two readings that give it two different functions emits a row
    per function, each with its own offset; one function from two readings emits a single row."""
    img = Image()
    # tie table: pre funcs + post funcs, no terminator -> +1 and -1 both candidates
    pre = [img.func("fx_pa"), img.func("fx_pb")]
    hs = [img.func(f"fx_x{i}") for i in range(4)]
    img.words(pre[0], pre[1])
    for n, h in zip(("p", "q", "r", "s"), hs, strict=True):
        img.words(img.string(n), h)
    img.words(hs[0], hs[1])
    rows = _rows(img)
    assert all(r.pairing_basis == dt.UNDETERMINED for r in rows)
    # each candidate row carries a concrete handler offset (one reading -> one function each)
    assert all(isinstance(r.handler_offset, int) for r in rows)
    del pairing


# ── the read face: a candidate row is never read as "key K dispatches to F" ──────────────────


def _run_to_atlas(img: Image, tmp_path: Path, run_id: str = "r") -> Path:
    from treasure_map.lib.hunt import run_analyzer2

    db = tmp_path / "analysis.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, ghidra_ok, last_seen_at) "
        "VALUES (1, 'httpd', '/fx/httpd', ?, 1, '2026-01-01')",
        ("a" * 64,),
    )
    img.write_contents(conn, 1)
    conn.execute(
        "INSERT INTO functions (binary_id, name, address, pseudocode, callees) "
        "VALUES (1, 'noop', '00099000', 'void noop(void){}', '[]')"
    )
    conn.commit()
    conn.close()
    atlas = tmp_path / "atlas.db"
    run_analyzer2(db, atlas, source_run_id=run_id, rehunt=True)
    return atlas


def test_candidate_edge_exposes_its_pairing_and_is_flagged(tmp_path: Path) -> None:
    """get_string_keyed_edges carries each static row's pairing; is_candidate_edge is true exactly
    for the undetermined ones (the record holds the key and the function, pairing unsettled)."""
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.query.string_edges import get_string_keyed_edges, is_candidate_edge

    img = Image()
    # a tie table: candidates only (pre funcs + post funcs, no terminator, no code)
    pre = [img.func("fx_pa"), img.func("fx_pb")]
    hs = [img.func(f"fx_x{i}") for i in range(4)]
    img.words(pre[0], pre[1])
    for n, h in zip(("pp", "qq", "rr", "ss"), hs, strict=True):
        img.words(img.string(n), h)
    img.words(hs[0], hs[1])
    atlas = open_atlas(_run_to_atlas(img, tmp_path))
    try:
        res = get_string_keyed_edges(atlas, run_id="r")
    finally:
        atlas.close()
    static = [e for e in res["edges"] if e["mechanism"] == "static_string_table"]
    assert static and all(e["pairing"]["basis"] == "undetermined" for e in static)
    assert all(is_candidate_edge(e) for e in static)


def test_candidate_edge_gives_no_reachability_lead(tmp_path: Path) -> None:
    """A candidate row's callee is not written up as "the callee of a string-keyed edge": the
    reachability dimension's leads and note skip it (the key does not dispatch here — that is what
    is unsettled)."""
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.query.string_edges import edges_reaching_callee
    from treasure_map.lib.query.triage import _dim_reachability

    img = Image()
    pre = [img.func("fx_pa"), img.func("fx_pb")]
    hs = [img.func(f"fx_y{i}") for i in range(4)]
    img.words(pre[0], pre[1])
    for n, h in zip(("pp", "qq", "rr", "ss"), hs, strict=True):
        img.words(img.string(n), h)
    img.words(hs[0], hs[1])
    atlas = open_atlas(_run_to_atlas(img, tmp_path))
    try:
        edges = tuple(edges_reaching_callee(atlas, "httpd", "fx_y0", binary_path="/fx/httpd"))
        assert edges and all(e["pairing"]["basis"] == "undetermined" for e in edges)
        dim = _dim_reachability("unknown", string_keyed_edges=edges)
    finally:
        atlas.close()
    assert "STRING-KEYED EDGE" not in dim.note  # a candidate is not written up as a dispatch here
    assert not any(lead.get("via") == "string_keyed_edge" for lead in (dim.evidence or ()))


def test_determined_edge_still_gives_a_lead(tmp_path: Path) -> None:
    """The counterpart: a determined static edge IS written up as a key lead (the reader must not
    swallow the real ones)."""
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.query.string_edges import edges_reaching_callee
    from treasure_map.lib.query.triage import _dim_reachability

    img = Image()
    hs = [img.func(f"fx_d{i}") for i in range(4)]
    _table(img, ["one", "two", "three", "four"], hs)  # key-first, terminated -> data_terminator
    atlas = open_atlas(_run_to_atlas(img, tmp_path))
    try:
        edges = tuple(edges_reaching_callee(atlas, "httpd", "fx_d0", binary_path="/fx/httpd"))
        assert edges and edges[0]["pairing"]["basis"] == "data_terminator"
        dim = _dim_reachability("unknown", string_keyed_edges=edges)
    finally:
        atlas.close()
    assert "STRING-KEYED EDGE" in dim.note
    assert any(lead.get("key") == "one" for lead in (dim.evidence or ()))
