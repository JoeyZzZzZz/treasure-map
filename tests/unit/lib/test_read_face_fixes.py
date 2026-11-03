# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The read-face fixes that move no stamp: the .ko reading bounded by the bytes the file holds,
the whole-pair blocks of get_file_diff kept out of the first page's budget (ko_offset pages them),
three honest states for a .ko, a bounded file read, the facts a reader could not see; the
functions whose decompile did not finish, named; and the binaries an analyzer threw on, listed.

Zero real data: synthetic ELF relocatables built here, synthetic databases.
"""

from __future__ import annotations

import inspect
import json
import sqlite3
import struct
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_file_diff import FW, PAIR
from treasure_map.cli import hunt_cli
from treasure_map.lib.query import extraction_gaps as gaps
from treasure_map.lib.query import file_diff as fd
from treasure_map.lib.query import ko_changes as kc
from treasure_map.lib.storage.connection import open_db


@pytest.fixture
def fw(tmp_path: Path) -> FW:
    return FW(tmp_path)


# ── a synthetic ELF relocatable ──────────────────────────────────────────────────────────────

_SHT_PROGBITS, _SHT_SYMTAB, _SHT_STRTAB, _SHT_NOBITS = 1, 2, 3, 8
_SHF_ALLOC, _SHF_EXEC, _SHF_COMPRESSED = 0x2, 0x4, 0x800


def _ko(
    *,
    text: bytes = b"\x00" * 16,
    init: bytes = b"\x01" * 8,
    bss: int = 16,
    funcs: tuple[tuple[str, int, int], ...] = (("func_a", 1, 16), ("init_b", 2, 8)),
    bad: bool = False,
    compressed: bytes | None = None,
) -> bytes:
    """An ELF32 LE relocatable: .text and .init.text (both executable), .bss (NOBITS, ``bss`` bytes
    declared), optionally .bad (its bytes past the end of the file) and .zdbg (a compressed
    section: a zlib header then ``compressed``), and a .symtab of STT_FUNC
    ``(name, shndx, size)``."""
    secs: list[dict[str, Any]] = [
        {"name": ".text", "type": _SHT_PROGBITS, "flags": _SHF_ALLOC | _SHF_EXEC, "data": text},
        {
            "name": ".init.text",
            "type": _SHT_PROGBITS,
            "flags": _SHF_ALLOC | _SHF_EXEC,
            "data": init,
        },
        {"name": ".bss", "type": _SHT_NOBITS, "flags": _SHF_ALLOC, "data": b"", "size": bss},
    ]
    if bad:
        secs.append({"name": ".bad", "type": _SHT_PROGBITS, "flags": 0, "data": b"", "bad": True})
    if compressed is not None:
        chdr = struct.pack("<III", 1, 4096, 1)  # ELFCOMPRESS_ZLIB, 4 KiB once decompressed
        secs.append(
            {
                "name": ".zdbg",
                "type": _SHT_PROGBITS,
                "flags": _SHF_COMPRESSED,
                "data": chdr + compressed,
            }
        )
    strtab = b"\0"
    syms = struct.pack("<IIIBBH", 0, 0, 0, 0, 0, 0)
    for name, shndx, size in funcs:
        off = len(strtab)
        strtab += name.encode() + b"\0"
        syms += struct.pack("<IIIBBH", off, 0, size, (1 << 4) | 2, 0, shndx)
    symtab_idx = len(secs) + 1
    secs.append(
        {
            "name": ".symtab",
            "type": _SHT_SYMTAB,
            "flags": 0,
            "data": syms,
            "link": symtab_idx + 1,
            "info": 1,
            "entsize": 16,
        }
    )
    secs.append({"name": ".strtab", "type": _SHT_STRTAB, "flags": 0, "data": strtab})
    secs.append({"name": ".shstrtab", "type": _SHT_STRTAB, "flags": 0, "data": b""})
    shstr = b"\0"
    for s in secs:
        s["name_off"] = len(shstr)
        shstr += s["name"].encode() + b"\0"
    secs[-1]["data"] = shstr
    body = b""
    offset = 52
    for s in secs:
        s["offset"] = offset + len(body)
        body += s["data"]
    shoff = offset + len(body)
    headers = struct.pack("<IIIIIIIIII", *([0] * 10))
    for s in secs:
        size = s.get("size", len(s["data"]))
        off = s["offset"]
        if s.get("bad"):
            off, size = shoff + 10_000, 64  # past the end of the file
        headers += struct.pack(
            "<IIIIIIIIII",
            s["name_off"],
            s["type"],
            s["flags"],
            0,
            off,
            size,
            s.get("link", 0),
            s.get("info", 0),
            1,
            s.get("entsize", 0),
        )
    ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\0" * 8
    head = struct.pack(
        "<16sHHIIIIIHHHHHH",
        ident,
        1,
        40,
        1,
        0,
        0,
        shoff,
        0,
        52,
        0,
        0,
        40,
        len(secs) + 1,
        len(secs),
    )
    return head + body + headers


def _no_section_data(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every pyelftools section's data() fail: what reads declared contents must not run."""
    from elftools.elf import sections

    def boom(self: Any) -> bytes:
        raise AssertionError("Section.data() was called")

    monkeypatch.setattr(sections.Section, "data", boom)  # a compressed section's too (0.33)


def _content(fw: FW, a: bytes, b: bytes, path: str = "lib/modules/m.ko") -> dict[str, Any]:
    fw.inv("a", path, file_type="elf_rel", reason="et_rel", data=a)
    fw.inv("b", path, file_type="elf_rel", reason="et_rel", data=b)
    page = fd.whole_pair_page(fw._pf(), 0, 200)["ko_changes"]["content_differs"]
    (e,) = [x for x in page if x["path_a"] == path]
    return e


# ── B: the .ko read from the bytes the file holds ────────────────────────────────────────────


def test_a_huge_declared_nobits_section_is_never_materialised(
    fw: FW, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A .bss declared 512 MiB in a small file: the parse never calls Section.data() (which would
    allocate the declared size), still compares the module, and reads .bss by its declared size.

    MUTATION (verified RED): hash sec.data() again -> data() is called -> RED."""
    _no_section_data(monkeypatch)
    e = _content(fw, _ko(bss=512 << 20), _ko(text=b"\x02" * 16, bss=512 << 20))
    assert e["sections_differ"] == [".text"]
    e2 = _content(fw, _ko(bss=16), _ko(bss=32), path="lib/modules/n.ko")
    assert e2["sections_differ"] == [".bss"]  # NOBITS: its size is what is compared


def test_a_section_past_the_end_of_the_file_reads_unknown(
    fw: FW, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A section whose bytes run past the file is neither the same nor different: it is listed
    under sections_unknown, never in sections_differ and never read as equal.

    MUTATION (verified RED): slice without the bound (an empty slice hashes equal) -> no
    sections_unknown -> RED."""
    _no_section_data(monkeypatch)
    e = _content(fw, _ko(bad=True), _ko(text=b"\x03" * 16, bad=True))
    assert e.get("sections_unknown") == [".bad"]
    assert ".bad" not in e["sections_differ"] and e["sections_differ"] == [".text"]


def test_a_compressed_section_is_compared_by_its_stored_bytes(
    fw: FW, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A compressed section is compared by the bytes stored (never decompressed): two payloads
    that differ differ; the same payload does not.

    MUTATION (verified RED): skip non-NOBITS sections' stored bytes (hash only the size) -> the
    differing payloads read equal -> RED."""
    _no_section_data(monkeypatch)
    e = _content(fw, _ko(compressed=b"payload-1"), _ko(compressed=b"payload-2"))
    assert e["sections_differ"] == [".zdbg"]


# ── D: the Spec 2b behaviours, each guarded ─────────────────────────────────────────────────


def test_functions_of_every_executable_section_are_compared(fw: FW) -> None:
    """D1: the function deltas span every executable section, not .text alone: a function added
    in .init.text is named.

    MUTATION (verified RED): collect symbols of .text only -> init_c missing -> RED."""
    b_funcs = (("func_a", 1, 16), ("init_b", 2, 8), ("init_c", 2, 4))
    e = _content(fw, _ko(), _ko(init=b"\x05" * 8, funcs=b_funcs))
    assert e["sections_differ"] == [".init.text", ".strtab", ".symtab"]
    assert e["funcs_b_only"]["names"] == ["init_c"]


def test_a_renamed_file_is_in_the_denominator(fw: FW) -> None:
    """D2: a file moved with its bytes (paired by sha) is one changed subject — in the completion
    denominator — not two one-sided ones and not left out.

    MUTATION (verified RED): leave renamed out of CHANGED_STATUSES -> no item -> RED."""
    fw.inv("a", "etc/init.d/S10x", file_type="text", data="#!/bin/sh\n")
    fw.inv("b", "etc/init.d/S20x", file_type="text", data="#!/bin/sh\n")
    items = fd.file_subject_items(fw._pf(), {})
    assert [i.anchor_ref.rsplit("#", 1)[-1] for i in items] == ["etc/init.d/S10x=>etc/init.d/S20x"]


def test_one_sha_shared_by_several_files_is_not_read_as_a_rename(fw: FW) -> None:
    """D3 / G3: a sha256 held by two files on one side and one on the other pairs nothing — each
    stays one-sided, and each entry says why (paired_by sha_ambiguous).

    MUTATION (verified RED): pair the first of each side's list as a rename -> RED."""
    for side, path in (("a", "www/x1.txt"), ("a", "www/x2.txt"), ("b", "www/y.txt")):
        fw.inv(side, path, file_type="text", data="same\n")
    out = fw.diff()
    by = {e["path"]: e for e in out["entries"]}
    assert {p: (e["change"], e.get("paired_by")) for p, e in by.items()} == {
        "www/x1.txt": ("a_only", "sha_ambiguous"),
        "www/x2.txt": ("a_only", "sha_ambiguous"),
        "www/y.txt": ("b_only", "sha_ambiguous"),
    }


def test_symbolic_links_are_paired_across_the_version_dir(fw: FW) -> None:
    """D4: a link only the lib/modules version dir moves, with the same target, is no change.

    MUTATION (verified RED): pair links by exact path only -> listed a_only + b_only -> RED."""
    fw.inv("a", "lib/modules/4.1/kernel/a.ko", file_type="elf_rel", reason="et_rel", data=b"x")
    fw.inv("b", "lib/modules/4.2/kernel/a.ko", file_type="elf_rel", reason="et_rel", data=b"x")
    fw.symlink("a", "lib/modules/4.1/build", "/dev/null")
    fw.symlink("b", "lib/modules/4.2/build", "/dev/null")
    s = fd.symlink_changes(fw._pf())
    assert (s["a_only"], s["b_only"], s["target_differs"], s["same_count"]) == ([], [], [], 1)


def test_the_version_dir_counts_symbolic_links_too(fw: FW) -> None:
    """D5: a side whose second lib/modules directory holds only a link has two first-level dirs —
    so nothing is normalised and the module files stay one-sided.

    MUTATION (verified RED): count files only -> one dir each side -> paired -> RED."""
    fw.inv("a", "lib/modules/4.1/modules.order", file_type="text", data="m\n")
    fw.inv("b", "lib/modules/4.2/modules.order", file_type="text", data="m\n")
    fw.symlink("b", "lib/modules/extra/link", "/dev/null")
    pf = fw._pf()
    assert not fd._normalize_active(pf)
    assert {af.path: (af.status, af.paired_by) for af in fd.aligned_files(pf)} == {
        "lib/modules/4.1/modules.order=>lib/modules/4.2/modules.order": ("renamed", "sha")
    }


def test_the_whole_pair_blocks_ride_the_first_page_only(fw: FW) -> None:
    """D7: ko_changes / symlink_changes come with the first page of the file list, never again.

    MUTATION (verified RED): give them on every page -> RED."""
    for i in range(3):
        fw.inv("a", f"etc/f{i}", file_type="text", data="a\n")
        fw.inv("b", f"etc/f{i}", file_type="text", data="b\n")
    first, second = fw.diff(limit=2), fw.diff(limit=2, offset=2)
    assert "ko_changes" in first and "symlink_changes" in first
    assert "ko_changes" not in second and "symlink_changes" not in second


# ── C: the whole-pair blocks out of the first page's budget ─────────────────────────────────


def _modules(fw: FW, n: int) -> None:
    for i in range(n):
        p = f"lib/modules/k/m{i:03d}.ko"
        b_funcs = (("func_a", 1, 16), ("init_b", 2, 8), (f"added_{i}", 1, 4))
        fw.inv(
            "a", p, file_type="elf_rel", reason="et_rel", data=_ko(text=bytes([i % 255 + 1]) * 16)
        )
        fw.inv("b", p, file_type="elf_rel", reason="et_rel", data=_ko(funcs=b_funcs))
    for i in range(5):
        fw.inv("a", f"lib/modules/k/gone{i}.ko", file_type="elf_rel", reason="et_rel", data=b"g")
    for i in range(7):
        fw.inv("b", f"lib/modules/k/new{i}.ko", file_type="elf_rel", reason="et_rel", data=b"n")


def _all_pages(tools: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, list[Any]]]:
    pages, lists = [], {}
    k: int | None = 0
    while k is not None:
        page = tools["get_file_diff"](PAIR, ko_offset=k)
        assert "error" not in page, page
        pages.append(page)
        for block in ("ko_changes", "symlink_changes"):
            for name, v in page[block].items():
                if isinstance(v, list):
                    lists.setdefault(f"{block}.{name}", []).extend(v)
        k = page["ko_paging"]["next_offset"]
    return pages, lists


def test_two_hundred_changed_modules_keep_the_first_page_in_budget(
    fw: FW, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The first page gives the .ko block as counts — no module is parsed for it — and stays
    within 48,000 bytes; ko_offset pages read all 200 content-different modules and the one-sided
    ones, each page within the budget.

    MUTATION (verified RED): put the content list back on the first page -> over the budget ->
    RED; parse the modules for the counts -> the patched parse raises -> RED."""
    _modules(fw, 200)
    fw.inv("a", "etc/rc", file_type="text", data="a\n")
    fw.inv("b", "etc/rc", file_type="text", data="b\n")
    tools = fw.tools()
    real_parse = kc._parse
    monkeypatch.setattr(kc, "_parse", lambda *a: (_ for _ in ()).throw(AssertionError("parsed")))
    first = tools["get_file_diff"](PAIR)
    monkeypatch.setattr(kc, "_parse", real_parse)
    assert len(json.dumps(first)) <= 48_000 and "over_budget" not in first
    ko = first["ko_changes"]
    assert (ko["content_differs_count"], ko["a_only_count"], ko["b_only_count"]) == (200, 5, 7)
    assert not any(isinstance(v, list) for v in ko.values())
    pages, lists = _all_pages(tools)
    assert len(pages) > 1
    assert all(len(json.dumps(p)) <= 48_000 and "over_budget" not in p for p in pages)
    assert len(lists["ko_changes.content_differs"]) == 200
    assert len(lists["ko_changes.a_only"]) == 5 and len(lists["ko_changes.b_only"]) == 7
    names = {e["funcs_b_only"]["names"][0] for e in lists["ko_changes.content_differs"]}
    assert len(names) == 200


def test_five_hundred_link_changes_keep_the_first_page_in_budget(fw: FW) -> None:
    """The symbolic links ride the first page when few; 500 retargeted links come as counts, the
    page stays within the budget, and ko_offset reads all 500.

    MUTATION (verified RED): always inline the link lists -> over the budget -> RED."""
    for i in range(500):
        fw.symlink("a", f"usr/bin/tool_{i:03d}", f"../../bin/old/tool_{i:03d}")
        fw.symlink("b", f"usr/bin/tool_{i:03d}", f"../../bin/new/tool_{i:03d}")
    tools = fw.tools()
    first = tools["get_file_diff"](PAIR)
    assert len(json.dumps(first)) <= 48_000 and "over_budget" not in first
    sym = first["symlink_changes"]
    assert sym["target_differs_count"] == 500 and sym["lists_paged_by"] == "ko_offset"
    _pages, lists = _all_pages(tools)
    assert len(lists["symlink_changes.target_differs"]) == 500


def test_a_few_link_changes_stay_on_the_first_page(fw: FW) -> None:
    fw.symlink("a", "bin/ctl", "./tool")
    fw.symlink("b", "bin/ctl", "../bin/tool")
    sym = fw.diff()["symlink_changes"]
    assert [x["link_path"] for x in sym["target_differs"]] == ["bin/ctl"]


@pytest.mark.parametrize(
    "kw",
    [{"offset": 1}, {"hunk_offset": 1}, {"path": "etc/rc"}, {"ko_offset": -1}],
)
def test_ko_offset_is_passed_alone(fw: FW, kw: dict[str, Any]) -> None:
    """ko_offset pages the whole-pair lists; with offset, hunk_offset or path it is refused.

    MUTATION (verified RED): drop the exclusivity check -> no error -> RED."""
    fw.inv("a", "etc/rc", file_type="text", data="a\n")
    fw.inv("b", "etc/rc", file_type="text", data="b\n")
    args = {"ko_offset": 0, **kw}
    try:
        fw.diff(**args)
        refused = False
    except fd.FileDiffError:
        refused = True
    assert refused


def test_the_parameter_table_names_ko_offset() -> None:
    from treasure_map import mcp_cards

    names = {(p["name"], t) for p in mcp_cards.PARAMETER_NAMES for t in p["used_in"]}
    assert ("ko_offset", "get_file_diff") in names


# ── G: three honest states, a bounded read, what a reader could not see ─────────────────────


def test_a_ko_with_no_recorded_sha_is_undetermined_and_a_moved_one_renamed(fw: FW) -> None:
    """★ A .ko both runs hold whose sha256 one side did not record is undetermined — never
    a_only ("the other run has none"); a .ko moved with its bytes is renamed — never content.

    MUTATION (verified RED): fold undetermined into a_only -> RED; fold renamed into
    content_differs -> RED."""
    fw.inv("a", "lib/x/u.ko", file_type="elf_rel", reason="et_rel", data=b"u", sha=None)
    fw.inv("b", "lib/x/u.ko", file_type="elf_rel", reason="et_rel", data=b"u")
    fw.inv("a", "lib/x/old.ko", file_type="elf_rel", reason="et_rel", data=b"moved")
    fw.inv("b", "lib/y/new.ko", file_type="elf_rel", reason="et_rel", data=b"moved")
    counts = fw.diff()["ko_changes"]
    assert {k: counts[f"{k}_count"] for k in kc._LIST_KEYS} == {
        "content_differs": 0,
        "renamed": 1,
        "undetermined": 1,
        "a_only": 0,
        "b_only": 0,
    }
    page = fd.whole_pair_page(fw._pf(), 0, 50)["ko_changes"]
    assert page["undetermined"][0]["path_a"] == "lib/x/u.ko"
    assert (page["renamed"][0]["path_a"], page["renamed"][0]["path_b"]) == (
        "lib/x/old.ko",
        "lib/y/new.ko",
    )


def test_a_file_over_the_read_limit_reads_over_size_limit(
    fw: FW, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The line difference is read only up to a bound: a larger file reads over_size_limit, never
    a whole read into memory.

    MUTATION (verified RED): drop the size check -> the hunk is read -> RED."""
    monkeypatch.setattr(fd, "MAX_READ_BYTES", 8)
    fw.inv("a", "etc/big", file_type="text", data="a\n" * 10)
    fw.inv("b", "etc/big", file_type="text", data="b\n" * 10)
    (e,) = fw.diff()["entries"]
    assert e.get("hunk_unavailable") == "over_size_limit"


def test_every_entry_says_how_it_was_paired_and_the_legend_explains_it(fw: FW) -> None:
    """G3: a single-path entry carries paired_by too; the legend explains renamed, paired_by and
    the two-path anchor.

    MUTATION (verified RED): give paired_by to two-path entries only -> RED."""
    fw.inv("a", "etc/rc", file_type="text", data="a\n")
    fw.inv("b", "etc/rc", file_type="text", data="b\n")
    out = fw.diff()
    assert out["entries"][0].get("paired_by") == "path"
    assert {"renamed", "paired_by", "whole_pair_blocks"} <= set(out["legend"])
    assert "=>" in out["legend"]["renamed"]


# ── E: the functions whose decompile did not finish, named ──────────────────────────────────


def _gap_world(tmp: Path) -> tuple[Path, sqlite3.Connection]:
    db = tmp / "analysis.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, sha256, ghidra_ok, stub_names) VALUES (1, 'svc', ?, 1, ?)",
        ("ab" * 32, json.dumps({"0x401000": "popen"})),
    )
    rows = [
        ("big_fn", "00402000", "timeout", None, ["system", "FUN_00401000", "FUN_00409999", "log"]),
        ("huge_fn", "00403000", "error", "payload_exceeded", ["strcpy"]),
        ("odd_fn", "00404000", "error", "no_result", ["system"]),
        ("ok_fn", "00405000", "ok", None, ["system"]),
    ]
    for name, addr, status, err, callees in rows:
        conn.execute(
            "INSERT INTO functions (binary_id, name, address, decompile_status, decompile_error, "
            "callees) VALUES (1, ?, ?, ?, ?, ?)",
            (name, addr, status, err, json.dumps(callees)),
        )
    conn.commit()
    conn.close()
    atlas = sqlite3.connect(":memory:")
    atlas.executescript(
        "CREATE TABLE diff_meta (diff_id TEXT, run_a_id TEXT, run_b_id TEXT, sha256_a TEXT, "
        "sha256_b TEXT, diff_ok INTEGER);"
        "CREATE TABLE function_alignment (diff_id TEXT, addr_a TEXT, addr_b TEXT, "
        "alignment_state TEXT);"
        "CREATE TABLE instance (evidence_ref TEXT);"
    )
    atlas.execute(
        "INSERT INTO diff_meta VALUES ('d', 'old', 'new', ?, ?, 1)", ("cd" * 32, "ab" * 32)
    )
    atlas.execute("INSERT INTO function_alignment VALUES ('d', '00400a00', '00402000', 'aligned')")
    for i in range(3):
        atlas.execute("INSERT INTO instance VALUES (?)", (f"old#cdcdcdcd:00400a00@cmd@0x{i:06x}",))
    atlas.execute("INSERT INTO instance VALUES ('old#cdcdcdcd:00400a001@cmd@0x0')")  # not it
    return db, atlas


def test_unfinished_decompiles_are_named_with_what_remains(tmp_path: Path) -> None:
    """★ A timed-out function and one whose output passed the limit are named (another error is
    not); the sinks its call list names count after the stub table resolves a FUN_ callee, the
    unresolved stubs are counted apart, and the counterpart a stored diff pairs it with gives its
    candidate count.

    MUTATION (verified RED): match sinks without resolving stubs -> popen missing, count 1 -> RED;
    leave the payload_exceeded functions out -> RED; count instances by a bare prefix (no '@') ->
    4 candidates -> RED."""
    db, atlas = _gap_world(tmp_path)
    got = gaps.unfinished_decompiles(db, atlas=atlas, run_id="new")
    assert got is not None
    by = {g["name"]: g for g in got}
    assert set(by) == {"big_fn", "huge_fn"}
    big = by["big_fn"]
    assert big["cause"] == "timeout"
    assert big["sink_callees"]["names"] == ["popen", "system"]
    assert big["sink_callees"]["unresolved_stub_callees"] == 1
    assert big["counterparts"] == [
        {"diff_id": "d", "address": "00400a00", "alignment_state": "aligned", "candidates": 3}
    ]
    assert by["huge_fn"]["cause"] == "payload_exceeded"
    line = gaps.describe(big)
    assert "2 sink callee(s)" in line and "1 unresolved stub" in line and "3 candidate" in line


def test_the_hunt_summaries_name_them(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Both hunt summaries (tmap hunt, tmap scan) call the naming; it prints each function.

    MUTATION (verified RED): drop the call from either summary -> fewer than two calls -> RED."""
    db, _atlas = _gap_world(tmp_path)
    hunt_cli._name_unfinished_decompiles(db, None, None, "  ")
    out = capsys.readouterr().out
    assert "Decompile unfinished: 2 function(s)" in out and "big_fn" in out and "huge_fn" in out
    src = inspect.getsource(hunt_cli)
    assert src.count("_name_unfinished_decompiles(") == 3  # the definition and two summaries


# ── F: the binaries an analyzer threw on, listed on MCP ──────────────────────────────────────


def test_an_analyzer_exception_is_listed_whatever_the_function_count(tmp_path: Path) -> None:
    """★ A binary with functions and ghidra_ok 1 whose reason is an analyzer exception is listed;
    any other reason is not.

    MUTATION (verified RED): require 0 functions / ghidra_ok 0 -> RED."""
    conn = open_db(tmp_path / "analysis.db")
    conn.execute(
        "INSERT INTO binaries (id, name, sha256, ghidra_ok, ghidra_status_reason) VALUES "
        "(1, 'svc', ?, 1, 'analyzer_exception:MipsAddressAnalyzer:AssertException'), "
        "(2, 'other', ?, 0, 'timeout')",
        ("a" * 64, "b" * 64),
    )
    conn.execute("INSERT INTO functions (binary_id, name, address) VALUES (1, 'f', '0x1000')")
    conn.commit()
    assert gaps.analyzer_degraded_binaries(conn) == [
        {"binary": "svc", "reason": "analyzer_exception:MipsAddressAnalyzer:AssertException"}
    ]
    conn.close()
