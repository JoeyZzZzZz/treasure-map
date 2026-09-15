# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Reading a binary's function exports from the ELF, and carrying them onto the function rows.

The decompiler's "global" flag is a symbol-NAMESPACE property, not an ELF export, and it measured
as a constant 0 on every function of every real firmware scanned — a column that was both dead and
answering a different question than its name claims. These pin the replacement: the exports come
from the ELF's DYNAMIC segment, an import is never counted as an export, a binary whose section
headers were stripped still answers, and "could not read it" never collapses into "exports
nothing".

The anchor is deliberately INDEPENDENT of the code under test: the expected set is re-derived here
from the ``.dynsym`` SECTION, a different pyelftools path than the segment the implementation
follows, so agreeing is evidence rather than a tautology.
"""

from __future__ import annotations

import json
import sqlite3
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile

from treasure_map.lib.analyze.elf_exports import dynamic_function_exports
from treasure_map.lib.analyze.elf_inventory import ElfRecord
from treasure_map.lib.analyze.ghidra_ingest import ingest_ghidra_output
from treasure_map.lib.storage.connection import open_db

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "elfs"
_LIBZ = _FIXTURES / "libz_x86_64.so"
_TRUE = _FIXTURES / "true_x86_64"


def _exports_via_section(path: Path) -> set[str]:
    """The oracle: defined STT_FUNC names read from the .dynsym SECTION, not from the segment."""
    with path.open("rb") as fh:
        section = ELFFile(fh).get_section_by_name(".dynsym")
        assert section is not None, "fixture must carry a .dynsym section to anchor against"
        return {
            sym.name
            for sym in section.iter_symbols()
            if sym.name
            and sym.entry["st_info"]["type"] == "STT_FUNC"
            and sym.entry["st_shndx"] != "SHN_UNDEF"
        }


def _strip_section_headers(source: Path, dest: Path) -> None:
    """Copy an ELF64 with its section header table zeroed out — the shape real firmware ships.

    Only the three header fields are touched; every segment, including PT_DYNAMIC, is untouched.
    That is exactly what a section-stripped shared object looks like to a reader.
    """
    raw = bytearray(source.read_bytes())
    assert raw[:4] == b"\x7fELF" and raw[4] == 2, "helper handles ELF64 only"
    endian = "<" if raw[5] == 1 else ">"
    struct.pack_into(endian + "Q", raw, 0x28, 0)  # e_shoff
    struct.pack_into(endian + "H", raw, 0x3C, 0)  # e_shnum
    struct.pack_into(endian + "H", raw, 0x3E, 0)  # e_shstrndx
    dest.write_bytes(bytes(raw))


# ── reading the ELF ───────────────────────────────────────────────────────────────────


def test_the_exports_match_an_independently_read_symbol_table() -> None:
    # The headline fact, against an anchor derived by a DIFFERENT path (section vs segment).
    #
    # MUTATION (measured: 1 failed, this test): in dynamic_function_exports drop the STT_FUNC
    # test -> non-function symbols join the set and it stops equalling the oracle.
    exports = dynamic_function_exports(_LIBZ)
    assert exports is not None
    assert set(exports) == _exports_via_section(_LIBZ)
    # and the anchor is non-empty, so "both empty" cannot be what makes this pass
    assert len(exports) > 50
    assert "compress" in exports and "adler32" in exports


def test_an_imported_function_is_not_an_export() -> None:
    # The dynamic table holds this binary's IMPORTS too, as undefined STT_FUNC entries. Counting
    # them would mark every caller of libc as exporting most of libc — the precise direction that
    # turns the column back into noise.
    #
    # MUTATION (measured: 3 failed — this test, the oracle-equality test, and the three-state
    # test): drop the `st_shndx == SHN_UNDEF` skip -> the undefined imports below join the set,
    # and an executable that exports nothing stops reading as empty.
    exports = dynamic_function_exports(_LIBZ)
    assert exports is not None
    with _LIBZ.open("rb") as fh:
        section = ELFFile(fh).get_section_by_name(".dynsym")
        assert section is not None
        undefined = {
            sym.name
            for sym in section.iter_symbols()
            if sym.name and sym.entry["st_shndx"] == "SHN_UNDEF"
        }
    assert undefined, "fixture must carry undefined imports for this to test anything"
    assert not (undefined & set(exports))


def test_a_section_stripped_binary_still_answers(tmp_path: Path) -> None:
    # ★ THE REASON THE SEGMENT IS READ AND NOT THE SECTION. Real firmware ships shared objects with
    # no section table: of the shared objects sampled from one ARM firmware, 5 of 5 were in this
    # state. A section-based read answers None for every one of them — every export lost, silently.
    #
    # MUTATION (measured: 1 failed, this test): read `.dynsym` via get_section_by_name instead of
    # the DYNAMIC segment -> this returns None where the unstripped copy returned its 88 names.
    stripped = tmp_path / "stripped.so"
    _strip_section_headers(_LIBZ, stripped)
    with stripped.open("rb") as fh:
        assert ELFFile(fh).get_section_by_name(".dynsym") is None, "the strip must really strip"
    assert dynamic_function_exports(stripped) == dynamic_function_exports(_LIBZ)


def test_exporting_nothing_is_not_the_same_as_being_unreadable(tmp_path: Path) -> None:
    # Three-state honesty. An executable that exports no functions was READ, and answers with an
    # empty set; a file that could not be read answers None. Collapsing them would let "we never
    # looked" be reported as "it has none".
    #
    # MUTATION (measured: 1 failed, this test): return frozenset() instead of None on both
    # unreadable paths -> the three states below stop being distinguishable.
    empty = dynamic_function_exports(_TRUE)
    assert empty == frozenset()
    assert dynamic_function_exports(tmp_path / "does_not_exist") is None
    assert dynamic_function_exports(tmp_path) is None  # a directory, not an ELF


# ── carrying it onto the function rows ────────────────────────────────────────────────


def _one_binary_db(tmp_path: Path) -> tuple[sqlite3.Connection, dict[str, int]]:
    conn = open_db(tmp_path / "analysis.db")
    conn.execute("INSERT INTO binaries (name, sha256) VALUES (?, ?)", ("libz", "b" * 64))
    conn.commit()
    binary_id = conn.execute("SELECT id FROM binaries WHERE sha256 = ?", ("b" * 64,)).fetchone()[0]
    return conn, {"b" * 64: binary_id}


def _write_json(output_dir: Path, name: str, sha256: str, payload: dict[str, object]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / f"{name}_{sha256[:8]}_ghidra.json").write_text(json.dumps(payload))


def _record(path: Path, name: str, sha256: str) -> ElfRecord:
    return ElfRecord(
        path=path, name=name, arch="x86:LE:64:default", elf_type="shared_library", sha256=sha256
    )


def test_ingest_flags_the_real_exports_and_not_the_claimed_ones(tmp_path: Path) -> None:
    # ★ THE WIRING, end to end. A lib-only test would pass while ingest still wrote the
    # decompiler's flag, so this goes through ingest_ghidra_output and reads the stored column.
    #
    # ★ The payload states the INVERSE of the truth on purpose: it claims the real export is not
    # exported and the invented function is. Both rows therefore come out wrong the moment anything
    # reads is_exported from the payload again, instead of both happening to agree.
    #
    # MUTATION (measured: 2 failed — this test and the unreadable-binary one): restore
    # `int(func.get("is_exported", 0))` in ghidra_ingest -> compress reads 0 and
    # not_a_real_symbol reads 1, i.e. exactly inverted.
    conn, sha_to_id = _one_binary_db(tmp_path)
    output_dir = tmp_path / "ghidra_output"
    _write_json(
        output_dir,
        "libz",
        "b" * 64,
        {
            "functions": [
                {
                    "name": "compress",  # a real export of the fixture
                    "address": "1000",
                    "size": 64,
                    "is_exported": 0,  # the payload says NO; the ELF says yes
                    "callees": ["memcpy"],
                    "pseudocode": "int compress(void){ return 0; }",
                },
                {
                    "name": "not_a_real_symbol",  # not in the fixture's dynamic table
                    "address": "2000",
                    "size": 64,
                    "is_exported": 1,  # the payload says YES; the ELF says no
                    "callees": ["memcpy"],
                    "pseudocode": "int helper(void){ return 0; }",
                },
            ],
            "imports": [],
            "exports": [],
            "strings": [],
        },
    )

    ingest_ghidra_output(conn, output_dir, [_record(_LIBZ, "libz", "b" * 64)], sha_to_id)

    flags = dict(conn.execute("SELECT name, is_exported FROM functions").fetchall())
    assert flags == {"compress": 1, "not_a_real_symbol": 0}
    conn.close()


def test_an_unreadable_binary_ingests_as_not_shown_to_be_exported(tmp_path: Path) -> None:
    # A path that is not a readable ELF must not fabricate an export, and must not stop the ingest.
    # 0 here means "not determined", which is what the schema comment says it means.
    #
    # MUTATION (measured: 2 failed — this test and the wiring one): restore
    # `int(func.get("is_exported", 0))` in ghidra_ingest -> the payload's claim of 1 is written
    # for a binary that was never read.
    conn, sha_to_id = _one_binary_db(tmp_path)
    output_dir = tmp_path / "ghidra_output"
    _write_json(
        output_dir,
        "libz",
        "b" * 64,
        {
            "functions": [
                {
                    "name": "compress",
                    "address": "1000",
                    "size": 64,
                    "is_exported": 1,
                    "callees": ["memcpy"],
                    "pseudocode": "int compress(void){ return 0; }",
                }
            ],
            "imports": [],
            "exports": [],
            "strings": [],
        },
    )

    missing = tmp_path / "no_such_binary.so"
    stats = ingest_ghidra_output(conn, output_dir, [_record(missing, "libz", "b" * 64)], sha_to_id)

    assert stats.functions_ingested == 1
    assert conn.execute("SELECT is_exported FROM functions").fetchone()[0] == 0
    conn.close()
