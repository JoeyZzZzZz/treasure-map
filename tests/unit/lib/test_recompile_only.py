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
F2_A = 'void handle_req(void)\n{\n  log_msg("%s:%d","handle_req",0x2a);\n  return;\n}\n'
F2_B = 'void handle_req(void)\n{\n  log_msg("%s:%d","handle_req",0x2b);\n  return;\n}\n'
F1_TEXT = "void f1(void)\n{\n  return;\n}\n"


def _f2(body: str) -> str:
    """A handle_req text with ``body`` as its statements."""
    return "void handle_req(void)\n{\n" + body + "  return;\n}\n"


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
        self.f1_conf = 0.99  # below 0.9 the F1 pair is alignment_undetermined
        self.f2_conf = 0.99
        self.stub_pairs: list[tuple[str, str, str, str]] = []  # (addr a, addr b, name a, name b)
        self.side: dict[str, dict[str, Any]] = {
            s: {
                "build_id": bytes(range(20)),
                "f1_addr": F1,
                "f1_text": F1_TEXT,
                "f1_callees": [],
                "f1_size": 16,
                "f2_name": "handle_req",
                "f2_text": F2_A,
                "f2_byte": 0x2A,
                "f2_callees": ["log_msg"],
                "f2_size": 16,
                "text_head": bytes(range(16)),  # F1's 16 bytes
                "text_tail": b"",  # stored after F2's 16 bytes
                "rodata": "ver 1.0 ready",
                "rodata_raw": None,  # the whole .rodata block, its strings then only ``strings``
                "strings": [],  # (value, address) besides the rodata string
                "blocks": [],  # (name, start, data, executable) besides the three
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
        a, b = self.side["a"], self.side["b"]
        w.pair(a["f1_addr"], b["f1_addr"], self.f1_conf, 1.0, name_a="f1", name_b="f1")
        w.pair(F2, F2, self.f2_conf, 0.98, name_a="handle_req", name_b="handle_req")
        for addr_a, addr_b, name_a, name_b in self.stub_pairs:
            w.pair(addr_a, addr_b, 0.99, 1.0, name_a=name_a, name_b=name_b)
        for s in ("a", "b"):
            cfg = self.side[s]
            db = w.adb[s]
            db.execute(
                "UPDATE binaries SET arch = 'MIPS:LE:32:default', strings_truncated = ?",
                (cfg["truncated"],),
            )
            w.fn(
                s,
                cfg["f1_addr"],
                cfg["f1_callees"],
                name="f1",
                pseudocode=cfg["f1_text"],
                size_bytes=cfg["f1_size"],
            )
            callees, f2 = cfg["f2_callees"], cfg["f2_text"]
            w.fn(s, F2, callees, name=cfg["f2_name"], pseudocode=f2, size_bytes=cfg["f2_size"])
            text = (
                cfg["text_head"]
                + bytes([0x24, 0x04, 0x00, cfg["f2_byte"]])
                + b"\x08" * 12
                + cfg["text_tail"]
            )
            head = _elf_head(cfg["build_id"])
            raw = cfg["rodata_raw"]
            for name, start, data, executable in (
                ("segment_0", BASE, head, 0),
                (".text", TEXT, text, 1),
                (".rodata", RODATA, _rodata(cfg["rodata"]) if raw is None else raw, 0),
                *cfg["blocks"],
            ):
                db.execute(
                    "INSERT INTO data_blocks (binary_id, block_name, start_addr, size, bytes, "
                    "initialized, executable, truncated) VALUES (1, ?, ?, ?, ?, 1, ?, 0)",
                    (name, hex(start), len(data), data, executable),
                )
            own = [(cfg["rodata"], hex(RODATA))] if raw is None else []
            for value, addr in [*own, *cfg["strings"]]:
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
    in a ``"%s:%d"`` log call (a __LINE__ argument), with equal callee sets and sizes: true, and
    the one changed byte inside that function is attributed to it.

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
    r.side["b"]["f2_text"] = _f2('  log_msg("%s:%d","handle_req",0x2a);\n  reset_all();\n')
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
        ("ssl_min TLSv1.0", "ssl_min TLSv1.2", False),
        ("tool 1.2.3 ready", "tool 1.2.4 ready", True),
        ("fw V1.0.4.26", "fw V1.0.4.27", True),
        ("fw v10.0.0.1", "fw v10.0.0.2", True),
    ],
)
def test_an_address_or_interface_shaped_dotted_number_is_not_a_version(
    a: str, b: str, explained: bool
) -> None:
    """★ A dotted number shaped like an IPv4 address / netmask, or glued to an interface name, is
    not a version; a plain or v-prefixed dotted version is — but a ``v`` glued to a name
    (``TLSv1.2``, a protocol name) is not: the glued test wins over the ``v`` prefix, and a
    ``v`` prefix still exempts an address-shaped number standing alone.

    MUTATION (verified RED, 6 failed): ``_not_a_version`` always returns False -> the address,
    interface and protocol pairs are explained -> RED. MUTATION (verified RED, 1 failed): the
    ``v``-prefix exemption tested before the glued test (the old order) -> the TLSv pair is a
    version -> RED. (Dropping the ``v``-prefix exemption alone stays green: a ``v``-led match never
    parses as a leading dotted number, so the address test cannot claim it — an equivalent
    mutation; the ``v10.0.0.1`` case pins the outcome.)"""
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


def test_a_null_diff_carries_no_entry_label(tmp_path: Path) -> None:
    """★ The label is absent when the diff's value is null (an input could not be read) — unknown is
    never shown as recompile-only.

    MUTATION (verified RED, 1 failed): label every entry unless the value is false (``is not
    True`` -> ``is False``) -> the null diff's entries carry the key -> RED."""
    r = _same(tmp_path)
    r.side["b"]["f2_text"] = F2_B
    r.side["b"]["f2_byte"] = 0x2B
    r.side["a"]["truncated"] = 1  # a's strings are a prefix: null
    w = r.build()
    tools = mcp_app.make_tools(w.path)
    assert tools["get_diff_meta"](DIFF)["recompile_only"]["value"] is None
    view = tools["get_diff_patch_view"](DIFF)
    assert view["entries"]
    assert not any(ro.ENTRY_KEY in e for e in view["entries"])


# ── which numbers are line numbers (strong / weak evidence, one step) ──────────────────────────


def _numbers(
    tmp: Path, a: str, b: str, *, byte_b: int = 0x2B, name_b: str | None = None
) -> dict[str, Any]:
    """The reading of a diff whose handle_req text is ``a`` / ``b`` (statements), its one immediate
    byte changed with it, everything else recompiled. ``name_b`` renames the pair's B side."""
    tmp.mkdir(parents=True, exist_ok=True)
    r = _same(tmp)
    r.side["a"]["f2_text"] = _f2(a)
    r.side["b"]["f2_text"] = _f2(b)
    r.side["b"]["f2_byte"] = byte_b
    for s in ("a", "b"):
        r.side[s]["f2_callees"] = ["log_msg", "check_len", "syslog"]
    w = r.build()
    if name_b is not None:
        w.atlas.execute("UPDATE function_alignment SET name_b = ? WHERE addr_a = ?", (name_b, F2))
        w.commit()
    return _read(w)


def test_a_length_after_an_identifier_string_is_not_a_line_number(tmp_path: Path) -> None:
    """★ ``check_len(param_1,"admin",5)`` -> ``6``: a number after an identifier-shaped string with
    no format evidence and not the function's own name is weak, and a pair with no strong site
    reads it as a changed constant — false, named at the pair.

    MUTATION (verified RED, 1 failed): every string-led number strong (``strong = fmt or
    _strong_name(prev2_a, names)`` -> ``strong = True``) -> true -> RED."""
    out = _numbers(
        tmp_path, '  check_len(param_1,"admin",5);\n', '  check_len(param_1,"admin",6);\n'
    )
    assert out["value"] is False, out
    assert out["unexplained"]["kind"] == "pair_text_differs"
    assert "number" in out["unexplained"]["why"]


def test_a_length_after_a_label_of_an_identifier_string_is_not_a_line_number(
    tmp_path: Path,
) -> None:
    """The same through a string label: ``check_len(param_1,s_admin_00402000,5)`` -> ``6``, the
    label pointing at ``admin`` on both sides — weak, no strong site beside it: false.

    MUTATION (verified RED, 1 failed): every label-led number strong (``strong = fmt or
    _strong_name(quoted, names)`` -> ``strong = True``) -> true -> RED."""
    r = _same(tmp_path)
    for s, n in (("a", 5), ("b", 6)):
        r.side[s]["rodata"] = "admin"
        r.side[s]["f2_text"] = _f2(f"  check_len(param_1,s_admin_00402000,{n});\n")
        r.side[s]["f2_callees"] = ["check_len"]
    r.side["b"]["f2_byte"] = 0x2B
    out = _read(r.build())
    assert out["value"] is False, out
    assert out["unexplained"]["kind"] == "pair_text_differs"
    # the precondition: the site was read through the label (a weak site), not as a bare number
    assert "label" in out["unexplained"]["why"], out


def test_a_format_shows_a_line_number_after_any_name_string(tmp_path: Path) -> None:
    """★ ``log_msg("%s:%d","fn",10)`` -> ``12`` in a function not named ``fn``: the
    ``%s``-then-``%d`` format on the line is the evidence — true.

    MUTATION (verified RED, 1 failed): ``_fmt_near`` returns False -> the site is weak with no
    strong one beside it -> false -> RED."""
    out = _numbers(
        tmp_path, '  log_msg("%s:%d","fn",10);\n', '  log_msg("%s:%d","fn",12);\n', byte_b=0x2C
    )
    assert out["value"] is True, out
    assert out["explained"].get("line_number_or_version_pairs") == 1


def test_a_format_on_the_line_before_counts(tmp_path: Path) -> None:
    """The format may sit on the line before the number (a call over two lines) — true.

    MUTATION (verified RED, 1 failed): look at the site's own line only (``(i - 1, i)`` ->
    ``(i,)`` in ``_fmt_near``) -> the two-line call is weak -> false -> RED."""
    out = _numbers(
        tmp_path,
        '  log_msg("%s:%d",\n          "fn",10);\n',
        '  log_msg("%s:%d",\n          "fn",11);\n',
    )
    assert out["value"] is True, out


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ('  log_msg("src/req.c",10);\n', '  log_msg("src/req.c",11);\n'),  # a source path
        ('  log_msg("handle_req",10);\n', '  log_msg("handle_req",11);\n'),  # its own name
    ],
)
def test_a_source_path_or_the_own_name_is_strong_evidence(tmp_path: Path, a: str, b: str) -> None:
    """★ Without a format, a number right after a source-path string or after the function's own
    name (a __FILE__ / __func__ argument) is a line number — true.

    MUTATION (verified RED, 2 failed): ``_strong_name`` returns False -> both sites weak -> false
    -> RED."""
    out = _numbers(tmp_path, a, b)
    assert out["value"] is True, out


def test_line_number_sites_of_two_steps_read_false(tmp_path: Path) -> None:
    """★ Two strong line-number sites in one function that shift by different steps (+2, +3) are
    not one recompile's line shift — false.

    MUTATION (verified RED, 1 failed): drop the one-step test (``len(steps) != 1 or`` removed) ->
    true -> RED."""
    out = _numbers(
        tmp_path,
        '  log_msg("%s:%d","handle_req",10);\n  log_msg("%s:%d","handle_req",20);\n',
        '  log_msg("%s:%d","handle_req",12);\n  log_msg("%s:%d","handle_req",23);\n',
    )
    assert out["value"] is False, out
    assert "one nonzero step" in out["unexplained"]["why"], out


def test_an_assigned_line_number_counts_beside_a_strong_site_of_the_same_step(
    tmp_path: Path,
) -> None:
    """★ ``uVar1 = 10;`` passed after a name string (no format: weak) plus one strong
    ``log_msg("%s:%d","handle_req",n)`` site, both +1: the weak site counts beside the strong one —
    true. The same weak site alone is a changed constant — false; with a different step — false.

    MUTATION (verified RED, 1 failed): weak sites never count (``weak_as = "L" if strong else
    "C"`` -> ``weak_as = "C"``) -> the first reading is false -> RED. MUTATION (verified RED, 1
    failed): an assigned number strong (``return "Lw", "number assigned …"`` -> ``return "L",
    …``) -> the lone weak site reads true -> RED."""
    weak = '  uVar1 = {v};\n  syslog(3,param_1,"fn",uVar1);\n'
    strong = '  log_msg("%s:%d","handle_req",{n});\n'
    both = _numbers(
        tmp_path / "both",
        weak.format(v=10) + strong.format(n=40),
        weak.format(v=11) + strong.format(n=41),
    )
    assert both["value"] is True, both
    alone = _numbers(tmp_path / "alone", weak.format(v=10), weak.format(v=11))
    assert alone["value"] is False, alone
    steps = _numbers(
        tmp_path / "steps",
        weak.format(v=10) + strong.format(n=40),
        weak.format(v=12) + strong.format(n=41),
    )
    assert steps["value"] is False, steps


def test_an_assigned_number_stays_weak_even_where_its_use_has_a_format(tmp_path: Path) -> None:
    """★ ``uVar1 = 10;`` passed beside a ``"%s:%d"`` format: the evidence is on another line than
    the number, so the assigned site stays weak — alone it is a changed constant, false (the drift
    reading's L_var reads the same way).

    MUTATION (verified RED, 1 failed): an assigned number strong (``return "Lw", "number assigned
    …"`` -> ``return "L", …``) -> true -> RED."""
    text = '  uVar1 = {v};\n  log_msg("%s:%d","fn",uVar1);\n'
    out = _numbers(tmp_path, text.format(v=10), text.format(v=11))
    assert out["value"] is False, out


def test_a_plain_constant_change_reads_false(tmp_path: Path) -> None:
    """★ A number that follows no string at all (``set_mode(param_1,5)`` -> ``6``) is a changed
    constant — false, even with callees and sizes equal and its byte inside the function.

    MUTATION (verified RED, 1 failed): any changed number is a line number (``return "C",
    "number changed"`` -> ``return "L", ...``) -> true -> RED."""
    out = _numbers(tmp_path, "  set_mode(param_1,5);\n", "  set_mode(param_1,6);\n")
    assert out["value"] is False, out
    assert out["unexplained"]["kind"] == "pair_text_differs"


def test_a_format_of_a_finished_statement_before_a_length_is_no_evidence(tmp_path: Path) -> None:
    """★ A finished ``log_msg("%s:%d","fn_x",0x2a);`` on the line before ``check_len(param_1,
    "admin",5)`` -> ``6``: the format belongs to another statement, so the length stays weak — a
    changed constant, false. (A format on the line before counts only for a call folded onto the
    number's line.)

    MUTATION (verified RED, 1 failed): drop the continuation test in line_format.format_evidence
    (``statement_continues(prev) and`` removed) -> the length reads strong -> true -> RED."""
    log = '  log_msg("%s:%d","fn_x",0x2a);\n'
    out = _numbers(
        tmp_path,
        log + '  check_len(param_1,"admin",5);\n',
        log + '  check_len(param_1,"admin",6);\n',
    )
    assert out["value"] is False, out
    assert out["unexplained"]["kind"] == "pair_text_differs"


def test_a_format_two_lines_before_the_number_is_no_evidence(tmp_path: Path) -> None:
    """★ A call folded over three lines with its format two lines above the number: only the
    number's own line and the line before are read — weak, false.

    MUTATION (verified RED, 1 failed): read the format anywhere in the function (``_fmt_near``
    -> ``any(format_evidence(t, []) for t in lines)``) -> true -> RED."""
    text = '  log_msg("%s:%d",\n          param_2,\n          "fn",{n});\n'
    out = _numbers(tmp_path, text.format(n=10), text.format(n=11))
    assert out["value"] is False, out


def test_a_format_on_one_side_only_is_no_evidence(tmp_path: Path) -> None:
    """★ The format must hold on both sides. ``"%1.2s:%d"`` -> ``"%1.3d:%d"`` differs only by a
    version-shaped run (a version-string site, explained), yet only side A's literal still has a
    ``%…s`` conversion: the number after ``"fn"`` stays weak — false.

    MUTATION (verified RED, 1 failed): evidence on either side (``_fmt_near(ta, x) and
    _fmt_near(tb, y)`` -> ``or``) -> true -> RED."""
    out = _numbers(tmp_path, '  log_msg("%1.2s:%d","fn",10);\n', '  log_msg("%1.3d:%d","fn",11);\n')
    assert out["value"] is False, out
    # the precondition: the literal pair itself is an explained version site
    assert ro.string_pair_classes("%1.2s:%d", "%1.3d:%d") is not None


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ('  log_msg("%d:%x","fn",10);\n', '  log_msg("%d:%x","fn",11);\n'),  # no %s at all
        ('  log_msg("%d bytes %d","fn",10);\n', '  log_msg("%d bytes %d","fn",11);\n'),
        # the ``%`` operators between two literals are code, not a format
        (
            '  check_len("t",n % sz,m % idx,"admin",5);\n',
            '  check_len("t",n % sz,m % idx,"admin",6);\n',
        ),
    ],
)
def test_a_line_without_a_name_then_line_format_literal_is_no_evidence(
    tmp_path: Path, a: str, b: str
) -> None:
    """★ Number conversions alone (``%d`` / ``%x``), a letter ``s`` after a ``%d``, or code
    between two literals holding ``% s`` / ``% i`` operators are no name-then-line format: the
    number after the identifier string stays weak — false.

    MUTATION (verified RED, 3 failed): any token holding a ``%`` is evidence (``return "%" in
    literal`` at the top of line_format.name_line_format; the ``%`` operator token too) -> true ->
    RED. MUTATION (verified RED, 1 failed, the operators): the whole line read as one literal
    (``any(name_line_format(t) for t in line)`` -> ``name_line_format('"' + " ".join(line) +
    '"')``) -> true -> RED."""
    out = _numbers(tmp_path, a, b)
    assert out["value"] is False, out


def test_the_own_name_of_one_side_only_is_weak(tmp_path: Path) -> None:
    """★ ``log_msg("handle_req",10)`` -> ``11`` where side B's function is named otherwise: the
    string is the own name on one side only, so the site is weak — false. (Both sides named
    ``handle_req`` is the strong case of test_a_source_path_or_the_own_name_is_strong_evidence.)

    MUTATION (verified RED, 1 failed): own name on either side (``names == (text, text)`` ->
    ``text in names``) -> true -> RED."""
    out = _numbers(
        tmp_path,
        '  log_msg("handle_req",10);\n',
        '  log_msg("handle_req",11);\n',
        name_b="handle_other",
    )
    assert out["value"] is False, out


def test_a_line_number_spelled_as_the_same_value_reads_false(tmp_path: Path) -> None:
    """★ ``10`` -> ``0xa`` after a format: the step is zero — no line shift, false.

    MUTATION (verified RED, 1 failed): allow a zero step (``or 0 in steps`` removed) -> true ->
    RED."""
    out = _numbers(
        tmp_path, '  log_msg("%s:%d","fn",10);\n', '  log_msg("%s:%d","fn",0xa);\n', byte_b=0x2A
    )
    assert out["value"] is False, out
    assert "one nonzero step" in out["unexplained"]["why"], out


def test_a_number_whose_step_cannot_be_computed_reads_false(tmp_path: Path) -> None:
    """★ A number token that is no integer literal Python reads (``010`` -> ``011``, a
    leading-zero spelling) has no computable step — fail closed, false.

    MUTATION (verified RED, 1 failed): accept an uncomputable step (``None in steps or``
    removed) -> true -> RED."""
    out = _numbers(tmp_path, '  log_msg("%s:%d","fn",010);\n', '  log_msg("%s:%d","fn",011);\n')
    assert out["value"] is False, out
    assert "one nonzero step" in out["unexplained"]["why"], out


# ── inputs that cannot be read in full ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "cut",
    [
        "UPDATE data_blocks SET truncated = 1 WHERE block_name = '.text'",  # the export's own flag
        "UPDATE data_blocks SET size = size + 4096 WHERE block_name = '.text'",  # bytes fall short
    ],
)
def test_a_cut_block_reads_null_not_true(tmp_path: Path, cut: str) -> None:
    """★ A block whose stored bytes fall short of its size (flagged truncated, or stored shorter
    than its size) on both sides: the bytes past the cut were never compared — null, named
    ``data_blocks_truncated``, never true.

    MUTATION (verified RED, 2 failed): drop the completeness test at the start of ``_bytes`` ->
    true -> RED."""
    w = _same(tmp_path).build()
    for s in ("a", "b"):
        w.adb[s].execute(cut)
    w.commit()
    out = _read(w)
    assert out["value"] is None, out
    assert out.get("unknown_because") == ["data_blocks_truncated"], out


def test_an_unexpected_error_reads_null_and_the_tool_still_answers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ An error the reading did not expect (a KeyError inside it) makes the fact null with
    ``reading_failed:KeyError``; get_diff_meta still answers.

    MUTATION (verified RED, 1 failed): catch only ``(sqlite3.Error, ValueError, struct.error)``
    in ``_judge`` -> the KeyError reaches the tool, caught here as no answer -> RED."""
    w = _same(tmp_path).build()

    def boom(*_a: Any, **_k: Any) -> None:
        raise KeyError("x")

    monkeypatch.setattr(ro, "_strings", boom)
    tools = mcp_app.make_tools(w.path)
    try:
        meta = tools["get_diff_meta"](DIFF)
    except KeyError:
        meta = {}
    assert meta.get("found") is True, meta
    fact = meta.get("recompile_only") or {}
    assert fact.get("value") is None, fact
    assert fact.get("unknown_because") == ["reading_failed:KeyError"], fact


def test_unaccounted_functions_read_null(tmp_path: Path) -> None:
    """A side whose function counts do not add up (total != matched + unmatched): the reading
    cannot say every function was compared — null, named.

    MUTATION (verified RED, 1 failed): drop the accounting test (``elif None in (total, dom, un)
    or total - dom - un != 0`` -> ``elif False``) -> true -> RED."""
    w = _same(tmp_path).build()
    w.atlas.execute("UPDATE diff_meta SET functions_total_a = 3")
    w.commit()
    out = _read(w)
    assert out["value"] is None, out
    assert out.get("unknown_because") == ["functions_not_accounted:a"], out


def test_a_changed_byte_inside_a_function_not_read_keeps_it_unknown(tmp_path: Path) -> None:
    """A pair whose body size is not recorded cannot be byte-compared; a changed byte at its entry
    is then unknown, and named so beside the size reason.

    MUTATION (verified RED, 1 failed): a byte in an unread function adds no reason
    (``st.unknown_because("bytes_in_unread_function")`` -> ``pass``) -> RED."""
    r = _same(tmp_path)
    for s in ("a", "b"):
        r.side[s]["f1_text"] = None
        r.side[s]["f1_size"] = None
    r.side["b"]["text_head"] = b"\xff" + bytes(range(1, 16))
    out = _read(r.build())
    assert out["value"] is None, out
    assert "bytes_in_unread_function" in out.get("unknown_because", []), out


# ── the fail-closed branches, each on its own ────────────────────────────────────────────────


def test_a_line_number_pair_of_unequal_sizes_reads_false(tmp_path: Path) -> None:
    """★ A line-number shift whose two bodies are recorded at different sizes: the size gate holds
    the text explanation back — false.

    MUTATION (verified RED, 1 failed): drop the size gate (``if sa is None or sb is None or sa !=
    sb`` -> ``if False``) -> true -> RED."""
    r = _same(tmp_path)
    r.side["b"]["f2_text"] = F2_B
    r.side["b"]["f2_byte"] = 0x2B
    r.side["b"]["f2_size"] = 20
    out = _read(r.build())
    assert out["value"] is False, out
    assert out["unexplained"]["kind"] == "body_sizes_not_proven_equal"


@pytest.mark.parametrize(
    ("tail_a", "tail_b"),
    [
        (b"\0" * 16, b"\0" * 8 + b"\x01" + b"\0" * 7),  # one padding byte, no string around it
        (b"mode=fast\0" + b"\0" * 6, b"mode=slow\0" + b"\0" * 6),  # an unlisted, non-version pair
    ],
)
def test_a_changed_byte_outside_every_string_and_function_reads_false(
    tmp_path: Path, tail_a: bytes, tail_b: bytes
) -> None:
    """★ A byte that lies in no function, no listed string and no build-id note is explained only
    when a string around it on both sides is a version / build pair — here none is: false,
    ``bytes_other``.

    MUTATION (verified RED, 2 failed): any context explains it (``if ctx_a is not None and ctx_b
    is not None: classes = string_pair_classes(...)`` -> ``if True: classes = True``) -> true ->
    RED."""
    r = _same(tmp_path)
    r.side["a"]["text_tail"] = tail_a
    r.side["b"]["text_tail"] = tail_b
    out = _read(r.build())
    assert out["value"] is False, out
    assert out["unexplained"]["kind"] == "bytes_other"


def test_code_that_moved_reads_false_even_with_its_bytes_inside_an_accepted_function(
    tmp_path: Path,
) -> None:
    """★ A pair aligned at different addresses (code moved) and changed executable bytes: the
    position-by-position byte comparison cannot attribute moved code — false, even though the only
    changed byte lies in a function accepted as a line-number shift.

    MUTATION (verified RED, 1 failed): drop the moved-code test (``if runs and x.executable and
    shifted`` -> ``if False``) -> the byte is attributed -> true -> RED."""
    r = _same(tmp_path)
    r.side["b"]["f1_addr"] = "00401020"  # F1 identical in text, entered elsewhere on B
    r.side["b"]["f2_text"] = F2_B
    r.side["b"]["f2_byte"] = 0x2B
    out = _read(r.build())
    assert out["value"] is False, out
    assert out["unexplained"]["kind"] == "code_moved_bytes_unattributed"


def test_a_pair_read_by_bytes_whose_bodies_differ_reads_false(tmp_path: Path) -> None:
    """★ A pair with no text to compare (no pseudocode either side) is explained only by identical
    stored bodies; here B's body (entered elsewhere, over bytes that differ from A's) is not —
    false, even though the image bytes are the same position by position.

    MUTATION (verified RED, 1 failed): accept differing bodies (``if xa != xb:`` -> ``if False:``
    in ``_bytes_identical``) -> true -> RED."""
    r = _same(tmp_path)
    for s in ("a", "b"):
        r.side[s]["f1_text"] = None
        r.side[s]["text_tail"] = bytes(range(0x80, 0x90))
    r.side["b"]["f1_addr"] = "00401020"
    out = _read(r.build())
    assert out["value"] is False, out
    assert out["unexplained"]["kind"] == "body_bytes_differ"


def test_an_undetermined_pair_whose_text_differs_reads_false(tmp_path: Path) -> None:
    """★ A pair of undetermined alignment whose texts differ: nothing explains it (the line-number
    rule reads aligned pairs only) — false, even with every stored byte the same.

    MUTATION (verified RED, 1 failed): count it as identical (``raise
    _UnexplainedError("undetermined_pair_differs", ...)`` -> ``st.explained["identical_pairs"] +=
    1``) -> true -> RED."""
    r = _same(tmp_path)
    r.f2_conf = 0.5
    r.side["b"]["f2_text"] = F2_B  # the byte stays 0x2a: only the text differs
    out = _read(r.build())
    assert out["value"] is False, out
    assert out["unexplained"]["kind"] == "undetermined_pair_differs"


def test_a_block_moved_or_added_reads_false(tmp_path: Path) -> None:
    """★ The same bytes stored at another start, or a block only one side exported: the layout is
    not the same, whatever the bytes — false, named.

    MUTATION (verified RED, 1 failed): drop the layout test (``if (x.start, x.size,
    x.initialized, x.truncated) != (...)`` -> ``if False and ...``) -> the moved block reads true
    -> RED. MUTATION (verified RED, 1 failed): drop the block-name test (``if names_a !=
    names_b`` -> ``if False``) -> the added block (never walked: the walk is over A's blocks)
    reads true -> RED."""
    (tmp_path / "moved").mkdir()
    w = _same(tmp_path / "moved").build()
    w.adb["b"].execute(
        "UPDATE data_blocks SET start_addr = '0x402100' WHERE block_name = '.rodata'"
    )
    w.commit()
    out = _read(w)
    assert out["value"] is False, out
    assert out["unexplained"]["kind"] == "block_layout_differs"
    (tmp_path / "added").mkdir()
    added = _same(tmp_path / "added")
    added.side["b"]["blocks"] = [(".data", 0x403000, b"\0" * 16, 0)]
    out = _read(added.build())
    assert out["value"] is False, out
    assert out["unexplained"]["kind"] == "block_set_differs"


def test_two_strings_that_swap_places_read_false(tmp_path: Path) -> None:
    """★ Two strings of equal length that swap places: the strings tables hold the same set (no
    one-sided string), but the bytes at each place now hold the other string — false,
    ``bytes_in_string``.

    MUTATION (verified RED, 1 failed): pass a changed byte inside a listed string (``raise
    _UnexplainedError("bytes_in_string", ...)`` -> ``continue``) -> true -> RED."""
    r = _same(tmp_path)
    for s, first, second in (("a", "alpha_on", "beta_off"), ("b", "beta_off", "alpha_on")):
        r.side[s]["rodata_raw"] = (first + "\0" + second + "\0").encode().ljust(64, b"\0")
        r.side[s]["strings"] = [(first, hex(RODATA)), (second, hex(RODATA + 9))]
    out = _read(r.build())
    assert out["value"] is False, out
    assert out["unexplained"]["kind"] == "bytes_in_string"


def test_a_stub_pair_of_two_names_reads_false(tmp_path: Path) -> None:
    """A pair of two import stubs (no body on either side) is explained only when both carry one
    name; two names — false.

    MUTATION (verified RED, 1 failed): accept any stub pair (``if p.name_a and p.name_a ==
    p.name_b`` -> ``if True``) -> true -> RED."""
    r = _same(tmp_path)
    r.stub_pairs = [("00405000", "00405000", "imp_open", "imp_close")]
    out = _read(r.build())
    assert out["value"] is False, out
    assert out["unexplained"]["kind"] == "stub_pair_name_differs"


def test_a_pair_that_differs_with_no_text_reads_false(tmp_path: Path) -> None:
    """A pair read as differing (its callee set changed) with no pseudocode on a side: there is no
    text to read as sites — false, never skipped.

    MUTATION (verified RED, 1 failed): skip it (``raise _UnexplainedError(
    "pair_differs_without_text", ...)`` -> ``continue``) -> true -> RED."""
    r = _same(tmp_path)
    r.side["b"]["f1_text"] = None
    r.side["b"]["f1_callees"] = ["reset_all"]
    out = _read(r.build())
    assert out["value"] is False, out
    assert out["unexplained"]["kind"] == "pair_differs_without_text"


def test_a_function_that_lost_its_callers_reads_false(tmp_path: Path) -> None:
    """A pair whose A function is called by name and whose B function no longer is (a caller-set
    edge): false, whatever the texts say.

    MUTATION (verified RED, 1 failed): ignore the caller-set edge (``if e.callers_b is not None``
    -> ``if False``) -> true -> RED."""
    r = _same(tmp_path)
    for s in ("a", "b"):
        r.side[s]["f1_callees"] = ["handle_req"]
    r.side["b"]["f2_name"] = "handle_req_v2"  # B's F1 still calls a name B's F2 does not carry
    out = _read(r.build())
    assert out["value"] is False, out
    assert out["unexplained"]["kind"] == "caller_set_changed"


def test_a_cached_reading_is_not_served_after_a_run_moves(tmp_path: Path) -> None:
    """★ The reading is cached per diff AND both runs' sources and stamps: once a run's record
    moves (here its ``updated_at``, with a one-sided string added under it), the reading is made
    again — never the old answer.

    MUTATION (verified RED, 1 failed): key the cache by ``(RULE, diff_id)`` only -> the old true is
    served -> RED."""
    w = _same(tmp_path).build()
    assert _read(w)["value"] is True
    w.adb["b"].execute("INSERT INTO strings (binary_id, value, address) VALUES (1, 'x9 on', '0x0')")
    w.atlas.execute("UPDATE run SET updated_at = '2099-01-01T00:00:00' WHERE run_id = 'runB'")
    w.commit()
    pv._clear_view_caches()  # the view's own caches: only this module's cache is under test
    out = _read(w)
    assert out["value"] is False, out
    assert out["unexplained"]["kind"] == "one_sided_string"
