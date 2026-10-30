# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Structural guards on the extractor's static dispatch-table detector (ExportFunctions.java).

★ HONEST SCOPE. These read the Java SOURCE, comments stripped; the unit suite has no Ghidra, so they
prove the shape of the code, not its behaviour. They pin the three rules whose loss is invisible
everywhere else — each is a one-line edit that changes no Python:

  * the walk scans executable blocks too (a binary stripped of section headers keeps its read-only
    data, keys and pointer arrays alike, inside the executable segment);
  * a handler is the entry of a function Ghidra defined, never merely an aligned address in an
    executable block (in a section-less binary that accepts the "next string" pointer of a string
    array, and string arrays read as tables);
  * a loose key (a printable run in an executable block that no defined string covers) counts only
    when it is identifier-shaped or its run is mostly strict;
and the one they must leave alone: ``strAtRodata`` still refuses an executable block, because the
default-value table reader uses it too.

Behaviour was measured on real firmware through Ghidra 11.4.3 (the session's promotion step, then
this detector), on the sample binaries of four images: the tables found and the false positives
rejected are in the change's report.
"""

from __future__ import annotations

import re
from pathlib import Path

_JAVA = (
    Path(__file__).resolve().parents[3]
    / "src"
    / "treasure_map"
    / "lib"
    / "analyze"
    / "ghidra"
    / "ExportFunctions.java"
)


def _code() -> str:
    """The source with // and /* */ comments removed (string literals here hold neither)."""
    src = _JAVA.read_text(encoding="utf-8")
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", src)


def _method(name: str) -> str:
    """The body of the one method declared as ``name(``, by brace matching."""
    code = _code()
    decls = [
        m
        for m in re.finditer(rf"\b{name}\s*\([^)]*\)\s*(throws [\w, ]+)?\s*\{{", code)
        if re.search(r"(private|public|static)[\w<>\[\], ]*\s$", code[: m.start()])
    ]
    assert len(decls) == 1, f"{name}: expected one declaration, found {len(decls)}"
    i = decls[0].end()
    depth = 1
    j = i
    while depth:
        depth += {"{": 1, "}": -1}.get(code[j], 0)
        j += 1
    return code[i : j - 1]


def test_the_walk_scans_executable_blocks_too() -> None:
    """The block loop skips only uninitialized blocks, never an executable one.

    MUTATION (must go RED): restore ``|| blk.isExecute()`` in the loop's skip test."""
    body = _method("buildStringTables")
    skip = re.search(
        r"for \(MemoryBlock blk : mem\.getBlocks\(\)\) \{\s*" r"if \(([^)]*\))\) continue;", body
    )
    assert skip is not None, "block loop skip test not found"
    assert "isExecute" not in skip.group(1)
    assert "isInitialized" in skip.group(1)


def test_a_handler_must_be_a_defined_function_entry() -> None:
    """``funcAtPtr`` answers null when no function starts at the pointer; it has no second path
    that names an undefined address.

    MUTATION (must go RED): bring back the aligned-address fallback (any return after the
    ``getFunctionAt`` miss, e.g. the old ``undefined_text`` anchor)."""
    body = _method("funcAtPtr")
    assert re.search(r"Function f = fm\.getFunctionAt\(to\);\s*if \(f == null\) return null;", body)
    assert "undefined_text" not in body
    assert "isExecute" not in body and "getFunctionContaining" not in body


def test_a_loose_key_counts_only_by_its_shape_or_a_mostly_strict_run() -> None:
    """Each record carries its key strength, and a loose one is kept only when identifier-shaped or
    its run is mostly strict; the shape is at least two characters.

    MUTATION (must go RED): keep every record (drop the shape test from ``keptRecords``), or let a
    one-character key pass the shape test."""
    kept = _method("keptRecords")
    assert re.search(
        r"kept\[i\]\s*=\s*!KEY_LOOSE\.equals\(e\[4\]\)\s*\|\|\s*mostlyFirm\s*\|\|\s*"
        r"identifierShaped\(e\[0\]\);",
        kept,
    )
    assert re.search(r"firm >= STRTBL_MIN_RUN && firm \* 2 >= entries\.size\(\)", kept)
    shape = _method("identifierShaped")
    assert re.search(r"key\.length\(\) < 2\) return false;", shape)
    record = _method("tableRecord")
    assert "tableKey(" in record and "strAtRodata(" not in record


def test_str_at_rodata_still_refuses_an_executable_block() -> None:
    """The default-value table reader shares ``strAtRodata``; the dispatch-table change must not
    widen it.

    MUTATION (must go RED): drop ``|| blk.isExecute()`` from its refusal."""
    body = _method("strAtRodata")
    assert re.search(
        r"if \(blk == null \|\| !blk\.isInitialized\(\) \|\| blk\.isExecute\(\)\) "
        r"return null;",
        body,
    )
