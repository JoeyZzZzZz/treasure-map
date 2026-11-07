# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The diff-level ``recompile_only`` reading (lib/query/recompile_only) and where it is shown.

Zero real data: every run, binary, address, string and byte is synthetic. One diff of ``libx``
between runA and runB (the patch-view World), whose two sides store the same image — an ELF header
with a GNU build-id note, two functions and a read-only data block — that each test then changes in
one place.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_patch_view import DIFF, World
from treasure_map import mcp_app
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query import recompile_only as ro
from treasure_map.version import UNKNOWN_VERSION

BASE = 0x400000
TEXT = 0x401000
RODATA = 0x402000
NOTE_OFF = 116  # the build-id note, right after the ELF header and two program headers
DESC = BASE + NOTE_OFF + 16  # its descriptor
F1, F2 = "00401000", "00401010"
F2_A = 'void handle_req(void)\n{\n  log_msg("handle_req",0x2a);\n  return;\n}\n'
F2_B = 'void handle_req(void)\n{\n  log_msg("handle_req",0x2b);\n  return;\n}\n'
F1_TEXT = "void f1(void)\n{\n  return;\n}\n"


@pytest.fixture(autouse=True)
def _fresh(monkeypatch: pytest.MonkeyPatch) -> None:
    """The diff reads as current, the MCP gate serves it, and no reading is cached across tests."""
    monkeypatch.setattr(mcp_app, "_installed_commit", lambda: UNKNOWN_VERSION)
    monkeypatch.setattr(
        pv,
        "diff_source_staleness",
        lambda atlas, diff_id: {
            "source_stale": False,
            "source_stale_reason": None,
            "toolchain_checked": True,
        },
    )
    pv._clear_view_caches()
    ro.clear_cache()


def _elf_head(build_id: bytes) -> bytes:
    """An ELF32 little-endian header, a PT_LOAD at file offset 0 and a PT_NOTE holding one GNU
    build-id note — the bytes a scan stores at the start of the image."""
    ident = b"\x7fELF" + bytes([1, 1, 1]) + b"\0" * 9
    note = struct.pack("<III", 4, len(build_id), 3) + b"GNU\0" + build_id
    size = NOTE_OFF + len(note)
    hdr = ident + struct.pack("<HHIIIIIHHHHHH", 2, 8, 1, TEXT, 52, 0, 0, 52, 32, 2, 40, 0, 0)
    load = struct.pack("<8I", 1, 0, BASE, BASE, size, size, 5, 0x1000)
    pnote = struct.pack("<8I", 4, NOTE_OFF, BASE + NOTE_OFF, BASE + NOTE_OFF, len(note), 0, 4, 4)
    out = hdr + load + pnote
    assert len(out) == NOTE_OFF
    return out + note


def _rodata(text: str) -> bytes:
    raw = text.encode() + b"\0"
    return raw + b"\0" * (64 - len(raw))


class Rebuild:
    """The two sides of one diff, the same until a test changes them."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.side: dict[str, dict[str, Any]] = {
            s: {
                "build_id": bytes(range(20)),
                "f2_text": F2_A,
                "f2_byte": 0x2A,
                "f2_callees": ["log_msg"],
                "rodata": "ver 1.0 ready",
                "strings": [],  # (value, address) besides the rodata string
                "truncated": 0,
            }
            for s in ("a", "b")
        }

    def build(self) -> World:
        w = World(self.tmp)
        w.atlas.execute(
            "UPDATE diff_meta SET presence_computed_a = 1, presence_computed_b = 1, "
            "functions_total_a = 2, functions_total_b = 2, matched_in_domain_a = 2, "
            "matched_in_domain_b = 2, unmatched_a = 0, unmatched_b = 0"
        )
        w.pair(F1, F1, 0.99, 1.0, name_a="f1", name_b="f1")
        w.pair(F2, F2, 0.99, 0.98, name_a="handle_req", name_b="handle_req")
        for s in ("a", "b"):
            cfg = self.side[s]
            db = w.adb[s]
            db.execute(
                "UPDATE binaries SET arch = 'MIPS:LE:32:default', strings_truncated = ?",
                (cfg["truncated"],),
            )
            w.fn(s, F1, [], name="f1", pseudocode=F1_TEXT, size_bytes=16)
            callees, f2 = cfg["f2_callees"], cfg["f2_text"]
            w.fn(s, F2, callees, name="handle_req", pseudocode=f2, size_bytes=16)
            text = bytes(range(16)) + bytes([0x24, 0x04, 0x00, cfg["f2_byte"]]) + b"\x08" * 12
            head = _elf_head(cfg["build_id"])
            for name, start, data, executable in (
                ("segment_0", BASE, head, 0),
                (".text", TEXT, text, 1),
                (".rodata", RODATA, _rodata(cfg["rodata"]), 0),
            ):
                db.execute(
                    "INSERT INTO data_blocks (binary_id, block_name, start_addr, size, bytes, "
                    "initialized, executable, truncated) VALUES (1, ?, ?, ?, ?, 1, ?, 0)",
                    (name, hex(start), len(data), data, executable),
                )
            for value, addr in [(cfg["rodata"], hex(RODATA)), *cfg["strings"]]:
                db.execute(
                    "INSERT INTO strings (binary_id, value, address) VALUES (1, ?, ?)",
                    (value, addr),
                )
        w.commit()
        return w


def _same(tmp: Path) -> Rebuild:
    """Both sides recompiled: only the build-id differs."""
    r = Rebuild(tmp)
    r.side["b"]["build_id"] = bytes(range(100, 120))
    return r


def _read(w: World) -> dict[str, Any]:
    out = ro.recompile_only(w.atlas, DIFF)
    assert out is not None
    return out


# ── the teeth ────────────────────────────────────────────────────────────────────────────────


def test_a_diff_whose_only_change_is_the_build_id_reads_true(tmp_path: Path) -> None:
    """★ Only the GNU build-id note's descriptor differs: true, the bytes counted as build-id
    bytes, and every function pair given its explanation.

    MUTATION (verified RED, 1 failed): ``build_id_ranges`` returns no range (``found`` never
    filled) -> the descriptor bytes are ``bytes_other`` -> false -> RED."""
    w = _same(tmp_path).build()
    out = _read(w)
    assert out["value"] is True, out
    assert out["rule"] == ro.RULE
    assert out["explained"].get("build_id_bytes") == 1
    assert out["explained"].get("identical_pairs") == 2
    assert "unexplained" not in out and "unknown_because" not in out


def test_the_build_id_is_found_through_the_stored_program_headers(tmp_path: Path) -> None:
    """The descriptor is found from the ELF header stored at the start of the image (PT_NOTE), not
    only from a block named .note*.

    MUTATION (verified RED, 1 failed): skip the PT_NOTE walk (``p_type == 4`` -> ``== 99``) -> no
    range -> RED."""
    w = _same(tmp_path).build()
    img, why = pv._entry_words_image(w.atlas, "runA", "a" * 64)
    assert img is not None and why is None
    found, missing = ro.build_id_ranges(img)
    assert found == {(DESC, 20)}
    assert missing is None


def test_a_line_number_shift_and_its_immediate_byte_read_true(tmp_path: Path) -> None:
    """A function whose text differs only by the number passed right after its own name string
    (a __LINE__ argument), with equal callee sets and sizes: true, and the one changed byte inside
    that function is attributed to it.

    MUTATION (verified RED, 1 failed): drop ``"L"`` from ``_ACCEPTED_SITES`` -> the site is
    unexplained -> false -> RED."""
    r = _same(tmp_path)
    r.side["b"]["f2_text"] = F2_B
    r.side["b"]["f2_byte"] = 0x2B
    out = _read(r.build())
    assert out["value"] is True, out
    assert out["explained"].get("line_number_or_version_pairs") == 1
    assert out["explained"].get("function_bytes") == 1


def test_a_build_id_change_with_one_real_call_change_reads_false(tmp_path: Path) -> None:
    """★ The build-id differs AND the function now makes one more call: false, named at the pair.

    The call is caught three times over (the delta's structural shape, its call counts, the own
    line alignment), so the mutation removes the pair-level check they feed.
    MUTATION (verified RED, 1 failed): count a pair reading ``differs`` as explained instead of
    reading its sites -> true -> RED."""
    r = _same(tmp_path)
    r.side["b"]["f2_text"] = (
        'void handle_req(void)\n{\n  log_msg("handle_req",0x2a);\n  reset_all();\n  return;\n}\n'
    )
    r.side["b"]["f2_callees"] = ["log_msg", "reset_all"]
    out = _read(r.build())
    assert out["value"] is False, out
    assert out["unexplained"]["kind"] == "pair_text_differs"
    assert out["unexplained"]["entry_id"] == f"pair:{F2}:{F2}"


def test_a_call_the_text_does_not_show_keeps_a_line_number_shift_unexplained(
    tmp_path: Path,
) -> None:
    """★ The text differs only by a line number, but the B function's callee list holds a call the
    text does not show (code the decompiler dropped): the callee sets are not proven equal, so the
    shift explains nothing — false.

    MUTATION (verified RED, 1 failed): drop the callee-set gate after ``entry_explained`` -> true ->
    RED."""
    r = _same(tmp_path)
    r.side["b"]["f2_text"] = F2_B
    r.side["b"]["f2_byte"] = 0x2B
    r.side["b"]["f2_callees"] = ["log_msg", "reset_all"]
    out = _read(r.build())
    assert out["value"] is False, out
    assert out["unexplained"]["kind"] == "callee_set_not_proven_equal"


def test_a_same_size_constant_change_beside_a_version_change_reads_false(tmp_path: Path) -> None:
    """★ The counter-example shape: same sizes, same layout, the version string moves (explained)
    AND a setting constant in another string changes at the same length (not explained) — false.

    MUTATION (verified RED, 1 failed): remove the fail-closed rule (``_judge`` returns
    ``"value": True`` on an unexplained difference) -> true -> RED."""
    r = _same(tmp_path)
    r.side["a"]["rodata"] = "ver 1.0 ready"
    r.side["b"]["rodata"] = "ver 1.1 ready"
    r.side["a"]["strings"] = [("set CHANNEL 149", "0x403000")]
    r.side["b"]["strings"] = [("set CHANNEL 36 ", "0x403000")]
    out = _read(r.build())
    assert out["value"] is False, out
    assert out["unexplained"]["kind"] == "one_sided_string"
    assert "CHANNEL" in (out["unexplained"]["a"] or out["unexplained"]["b"])


def test_a_version_string_alone_reads_true(tmp_path: Path) -> None:
    """The precondition of the counter-example: the version string by itself is explained, as a
    string pair and as the bytes that hold it — so the false above is the constant's alone.

    MUTATION (verified RED, 1 failed): drop the dotted_version rule from ``_VERSION_RULES`` ->
    the pair is one-sided -> false -> RED."""
    r = _same(tmp_path)
    r.side["b"]["rodata"] = "ver 1.1 ready"
    out = _read(r.build())
    assert out["value"] is True, out
    assert out["explained"].get("version_strings") == 1
    assert out["explained"].get("string_bytes") == 1


_TOOLCHAIN_A = "/opt/build/toolchains/gcc-9.2/arm-linux-gnueabi/sysroot/usr/lib/crti.o"
_TOOLCHAIN_B = "/home/ci/work/rel/toolchains/gcc-9.2/arm-linux-gnueabi/sysroot/usr/lib/crti.o"


def test_a_toolchain_path_that_moved_is_a_build_environment_string(tmp_path: Path) -> None:
    """★ A toolchain path whose build root moved (the part from ``toolchains`` on unchanged) is
    explained by the narrow build-environment class.

    MUTATION (verified RED, 1 failed): remove the class (``build_env_tail`` returns None) -> the
    path is one-sided -> false -> RED."""
    r = _same(tmp_path)
    r.side["a"]["strings"] = [(_TOOLCHAIN_A, "0x500000")]
    r.side["b"]["strings"] = [(_TOOLCHAIN_B, "0x500000")]
    out = _read(r.build())
    assert out["value"] is True, out
    assert out["explained"].get("build_env_strings") == 1


@pytest.mark.parametrize(
    ("a", "b"),
    [
        # a configuration root, even with a build-tree component in it
        ("/etc/app/src/conf.d/wifi/a.conf", "/opt/app/src/conf.d/wifi/a.conf"),
        ("/var/run/src/x/y/pidfile", "/data/run/src/x/y/pidfile"),
        # no toolchain / build-tree anchor
        ("/data/cfg/wifi/a.conf", "/data/cfg/wifi/b.conf"),
        # an anchor with too short a tail after it
        ("/opt/a/src/x", "/opt/b/src/x"),
    ],
)
def test_the_build_environment_class_is_narrow(tmp_path: Path, a: str, b: str) -> None:
    """★ A configuration / runtime path, a path with no toolchain or build-tree anchor and one with
    too short a tail are NOT build-environment strings: false.

    MUTATION (verified RED, 2 failed): drop the runtime-root test in ``build_env_tail`` -> the
    /etc and /var cases are explained -> RED. MUTATION (verified RED, 1 failed): drop the
    ``_ANCHOR_TAIL_MIN`` test -> the short-tail case is explained -> RED."""
    r = _same(tmp_path)
    r.side["a"]["strings"] = [(a, "0x500000")]
    r.side["b"]["strings"] = [(b, "0x500000")]
    out = _read(r.build())
    assert out["value"] is False, out
    assert out["unexplained"]["kind"] == "one_sided_string"


@pytest.mark.parametrize(
    ("a", "b", "explained"),
    [
        ("server 10.0.0.1 ready", "server 10.0.0.2 ready", False),
        ("dns 1.1.1.1", "dns 8.8.8.8", False),
        ("mask 255.255.255", "mask 255.255.254", False),
        ("vlan eth0.100 up", "vlan eth1.100 up", False),
        ("ifname wl0.1", "ifname wl0.2", False),
        ("tool 1.2.3 ready", "tool 1.2.4 ready", True),
        ("fw V1.0.4.26", "fw V1.0.4.27", True),
    ],
)
def test_an_address_or_interface_shaped_dotted_number_is_not_a_version(
    a: str, b: str, explained: bool
) -> None:
    """★ A dotted number shaped like an IPv4 address / netmask, or glued to an interface name, is
    not a version; a plain or v-prefixed dotted version is.

    MUTATION (verified RED, 5 failed): ``_not_a_version`` always returns False -> the address and
    interface pairs are explained -> RED."""
    assert (ro.string_pair_classes(a, b) is not None) is explained


def test_an_address_shaped_string_pair_reads_false_through_the_whole_reading(
    tmp_path: Path,
) -> None:
    """The address-shaped pair, wired: the one-sided strings stop the reading.

    MUTATION (verified RED, 1 failed): ``_not_a_version`` always returns False -> true -> RED."""
    r = _same(tmp_path)
    r.side["a"]["strings"] = [("server 10.0.0.1 ready", "0x500000")]
    r.side["b"]["strings"] = [("server 10.0.0.2 ready", "0x500000")]
    out = _read(r.build())
    assert out["value"] is False, out
    assert out["unexplained"]["kind"] == "one_sided_string"


def test_a_build_banner_host_is_explained_only_beside_a_date(tmp_path: Path) -> None:
    """A ``user@host`` token is a build host only in a string that also carries a date / time
    shape; elsewhere (a contact address) it stays a difference.

    MUTATION (verified RED, 1 failed): rewrite ``user@host`` whatever else the string holds -> the
    contact pair is explained -> RED."""
    assert ro.string_pair_classes(
        "built by alice@hostA on Jan  5 2026", "built by bob@hostB on Feb  6 2026"
    )
    assert ro.string_pair_classes("mail alice@hostA", "mail bob@hostB") is None


def test_a_truncated_strings_side_reads_null_with_its_reason(tmp_path: Path) -> None:
    """Three-state: with a side's strings list a prefix, nothing unexplained is found but the
    reading cannot say — null, ``unknown_because`` naming the side.

    MUTATION (verified RED, 1 failed): drop the truncation test in ``_strings`` -> true -> RED."""
    r = _same(tmp_path)
    r.side["a"]["truncated"] = 1
    out = _read(r.build())
    assert out["value"] is None, out
    assert out["unknown_because"] == ["strings_truncated:a"]


def test_a_one_sided_function_reads_false(tmp_path: Path) -> None:
    """A function the other side does not hold is unexplained, whatever else is the same.

    MUTATION (verified RED, 1 failed): skip the function_presence check (``one_sided is not None``
    -> ``False``) and the placed-entry check -> true -> RED."""
    r = _same(tmp_path)
    w = r.build()
    w.unpaired("b", "00401020", "absent")
    w.commit()
    out = _read(w)
    assert out["value"] is False, out
    assert out["unexplained"]["kind"] == "one_sided_function"


def test_a_byte_no_rule_attributes_reads_false(tmp_path: Path) -> None:
    """A changed byte inside a function whose text reads identical is not explained (a text match
    does not explain its bytes).

    MUTATION (verified RED, 1 failed): accept a byte in any function (``fns[j][0] in
    accepted_fns`` -> ``True``) -> true -> RED."""
    r = _same(tmp_path)
    r.side["b"]["f2_byte"] = 0x2B  # the text still says 0x2a on both sides
    out = _read(r.build())
    assert out["value"] is False, out
    assert out["unexplained"]["kind"] == "bytes_in_function"
    assert out["unexplained"]["function"] == hex(int(F2, 16))


# ── where it is shown ────────────────────────────────────────────────────────────────────────


def test_the_mcp_tools_show_the_fact_and_the_derived_entry_label(tmp_path: Path) -> None:
    """★ End to end: get_diff_meta carries ``recompile_only`` and every patch-view entry of a true
    diff carries ``recompile_only_diff: true`` — the entries otherwise as the lib lists them.

    MUTATION (verified RED, 1 failed): drop ``_label_recompile_only(conn, diff_id, result)`` from
    the get_diff_patch_view tool -> no entry carries the key -> RED. MUTATION (verified RED, 1
    failed): drop the ``out["recompile_only"] = ...`` line from the get_diff_meta tool -> RED."""
    r = _same(tmp_path)
    r.side["b"]["f2_text"] = F2_B
    r.side["b"]["f2_byte"] = 0x2B
    w = r.build()
    tools = mcp_app.make_tools(w.path)
    meta = tools["get_diff_meta"](DIFF)
    assert "recompile_only" in meta, sorted(meta)
    assert meta["recompile_only"]["value"] is True
    view = tools["get_diff_patch_view"](DIFF)
    lib = pv.get_diff_patch_view(w.atlas, DIFF)
    assert view["entries"], view
    assert all(e.get(ro.ENTRY_KEY) is True for e in view["entries"])
    stripped = [{k: v for k, v in e.items() if k != ro.ENTRY_KEY} for e in view["entries"]]
    assert stripped == lib["entries"]


def test_a_false_diff_carries_no_entry_label(tmp_path: Path) -> None:
    """The label is absent when the diff's value is false — never ``false`` on the entry.

    MUTATION (verified RED, 1 failed): label every entry whatever the value (``is not True`` ->
    ``is None``) -> the false diff's entries carry the key -> RED."""
    r = _same(tmp_path)
    r.side["b"]["f2_text"] = F2_B
    r.side["b"]["f2_byte"] = 0x2B
    r.side["a"]["strings"] = [("set CHANNEL 149", "0x403000")]
    r.side["b"]["strings"] = [("set CHANNEL 36 ", "0x403000")]
    w = r.build()
    tools = mcp_app.make_tools(w.path)
    assert tools["get_diff_meta"](DIFF)["recompile_only"]["value"] is False
    view = tools["get_diff_patch_view"](DIFF)
    assert view["entries"]
    assert not any(ro.ENTRY_KEY in e for e in view["entries"])
