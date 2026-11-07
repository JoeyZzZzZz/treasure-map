# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Whether an aligned pair's two pseudocode texts differ only by shifted line numbers or shifted
addresses — a FACT about one bucket S entry (``drift_only``), computed at read time.

It is a navigation fact only: it orders nothing, moves the entry nowhere and clears no judgement.
The entry stays must-read (or second tier) exactly as it was; a reader may fold the drift-only ones
below the rest, never skip them.

A pair reads ``drift_only`` only when ALL of:

* its ``pseudocode_delta`` is ``substitution_only`` with no call count changed, and
* every differing site of the two texts is explained by one of the rules in :func:`classify_site`
  (one unexplained site keeps the whole pair ``not_drift_only`` — fail closed, site by site), and
* the aligned ``callee_set`` is proven ``equal`` and both sides' body sizes are recorded and equal
  — the same extra gate the R bucket's line-number demotion uses, because the text alone cannot see
  a call added or dropped in a block the decompiler dropped as dead.

``undetermined`` (with ``why``) when an input cannot be read: a side with no text, an image whose
blocks cannot be read, or a body over the size cap. Not "drift only", and never "no change".

This reading is independent of ``sameness._line_number_form`` (the R bucket's reading): it never
calls it and does not touch it, so neither changes the other."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any

from treasure_map.lib.ro_db import ro_connect

DRIFT_ONLY = "drift_only"
NOT_DRIFT_ONLY = "not_drift_only"
UNDETERMINED = "undetermined"

# A body whose line matrix is larger than this is not read site by site (undetermined, too_large).
LINE_PRODUCT_CAP = 4_000_000
_STR_READ = 200
_STR_MIN = 4

_TOK = re.compile(r'"(?:[^"\\]|\\.)*"|0x[0-9a-fA-F]+|\d+|[A-Za-z_][A-Za-z0-9_]*|\S')
_LOCAL = re.compile(
    r"^(?:[iuplcbsfdx]Var\d+|local_[0-9a-f]+|param_\d+|a[ucilsb]*Stack_[0-9a-f]+|in_\w+|"
    r"extraout_\w+|unaff_\w+|ppcVar\d+|pp[a-z]Var\d+|p[a-z]+Var\d+|[a-z]+Var\d+|_Var\d+|"
    r"local_res\w+)$"
)
_IDENT_STR = re.compile(r'^"[A-Za-z_][A-Za-z0-9_]*"$')
_PATH_STR = re.compile(r'^"[\w./+-]*\.(?:c|cc|cpp|h)"$')
_ADDRTOK = re.compile(
    r"^(thunk_FUN|FUN|DAT|UNK|LAB|PTR_DAT|PTR_FUN|PTR_LAB|PTR_UNK|PTR_s|PTR_u|s|u|switchD|"
    r"switchdataD|caseD)_(.*?)_?([0-9a-fA-F]{6,8})$"
)
_NUM = re.compile(r"^(?:0x[0-9a-fA-F]+|\d+)$")
# The global-pointer register, as the decompiler names it when the text reads it directly. A
# base is proven gp only by its name here; nothing stored records the register otherwise.
_GP_NAMES = frozenset({"gp", "unaff_gp", "in_gp", "_gp"})

# Which explained rule is a line-number site and which is an address-shift site (for ``sites``).
_LINE_RULES = frozenset({"L_str_own", "L_str_path", "L_str_ident", "L_ptr", "L_var"})
_ADDRESS_RULES = frozenset(
    {
        "A_strptr",
        "A_fun",
        "A_strlabel",
        "A_dat",
        "A_datalabel",
        "A_ptr",
        "A_codelabel",
        "A_comment",
        "A_got",
        "A_imgaddr",
    }
)


def _hex_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value.lower().startswith("0x") else int(value, 0)
        except ValueError:
            return None
    return None


@dataclass
class ImageReader:
    """One binary's loaded blocks, read once from its analysis.db (``data_blocks``): enough to tell
    whether a value points at a string or known bytes inside the image, and to resolve a MIPS
    global-offset-table slot. Never opens the firmware file; reads only what the scan stored.

    ``blocks`` is ``(start, size, bytes, initialized)`` per block; ``ok`` is False when the binary
    or its blocks could not be read (the caller then reads undetermined)."""

    blocks: list[tuple[int, int, bytes, bool]]
    little_endian: bool
    ok: bool
    gp: int | None = None
    pltgot: int | None = None
    local_gotno: int | None = None
    gotsym: int | None = None
    symtab: int | None = None
    strtab: int | None = None

    def _block_of(self, va: int) -> tuple[int, int, bytes, bool] | None:
        for start, size, data, init in self.blocks:
            if start <= va < start + size:
                return (start, size, data, init)
        return None

    def cstring_at(self, va: int) -> bytes | None:
        """The printable C string that STARTS at ``va`` (previous byte NUL or block start), or None
        — ``va`` is not the head of a printable string of at least ``_STR_MIN`` bytes in a loaded,
        initialized block."""
        blk = self._block_of(va)
        if blk is None or not blk[3]:
            return None
        start, _size, data, _init = blk
        off = va - start
        if off > 0:
            if off - 1 >= len(data):
                return None
            if data[off - 1 : off] != b"\x00":
                return None
        chunk = data[off : off + _STR_READ]
        text = chunk.split(b"\x00")[0]
        if len(text) >= _STR_MIN and all(32 <= c < 127 or c in (9, 10) for c in text):
            return text
        return None

    def bytes_at(self, va: int, n: int) -> bytes | None:
        blk = self._block_of(va)
        if blk is None:
            return None
        start, _size, data, init = blk
        if not init:
            return b"\x00" * n
        off = va - start
        return data[off : off + n] if off + n <= len(data) else None

    def word_at(self, va: int) -> int | None:
        raw = self.bytes_at(va, 4)
        if raw is None or len(raw) < 4:
            return None
        return int(struct.unpack("<I" if self.little_endian else ">I", raw)[0])

    def content_at(self, va: int) -> tuple[str, bytes] | None:
        """What ``va`` points at inside the image: ``("str", bytes)`` when it is the head of a
        printable C string, ``("bytes", 16 bytes)`` for other INITIALIZED content, or None — ``va``
        is not in a loaded block, or in an uninitialized one (``.bss``), whose two sides cannot be
        told apart by content."""
        s = self.cstring_at(va)
        if s is not None:
            return ("str", s)
        blk = self._block_of(va)
        if blk is None or not blk[3]:
            return None
        raw = self.bytes_at(va, 16)
        return ("bytes", raw) if raw is not None else None

    def _dynstr(self, name_off: int) -> bytes | None:
        if self.strtab is None:
            return None
        raw = self.bytes_at(self.strtab + name_off, 64)
        return None if raw is None else raw.split(b"\x00")[0]

    def got_target(self, offset: int) -> tuple[str, Any] | None:
        """What the MIPS global-offset-table slot at ``gp + offset`` holds: ``("sym", name)`` for a
        global symbol slot, ``("ptr", value)`` for a local pointer slot, or None when the dynamic
        info is missing or the slot is out of the table. Used only when the base is proven gp."""
        if self.gp is None or self.pltgot is None or self.local_gotno is None:
            return None
        slot = self.gp + offset
        index = (slot - self.pltgot) // 4
        if index < 0 or (slot - self.pltgot) % 4:
            return None
        if index < self.local_gotno:
            value = self.word_at(slot)
            return None if value is None else ("ptr", value)
        if self.gotsym is None or self.symtab is None:
            return None
        sym = self.symtab + 16 * (self.gotsym + index - self.local_gotno)
        name_off = self.word_at(sym)  # Elf32_Sym.st_name is the first word
        if name_off is None:
            return None
        name = self._dynstr(name_off)
        return None if name is None else ("sym", name)


def read_image(analysis_db_path: str | None, sha: str | None) -> ImageReader:
    """An :class:`ImageReader` for one binary; ``ok`` False when it cannot be read."""
    empty = ImageReader(blocks=[], little_endian=True, ok=False)
    if not analysis_db_path or not sha:
        return empty
    try:
        conn = ro_connect(analysis_db_path)
    except Exception:  # noqa: BLE001 — read-only, never raises to a reader
        return empty
    try:
        found = conn.execute("SELECT id, arch FROM binaries WHERE sha256 = ?", (sha,)).fetchone()
        if found is None:
            return empty
        bid, arch = found
        rows = conn.execute(
            "SELECT start_addr, size, bytes, initialized FROM data_blocks WHERE binary_id = ?",
            (bid,),
        ).fetchall()
    except Exception:  # noqa: BLE001
        return empty
    finally:
        conn.close()
    blocks: list[tuple[int, int, bytes, bool]] = []
    for start, size, data, init in rows:
        lo = _hex_int(start)
        if lo is not None and isinstance(size, int) and size > 0:
            blocks.append((lo, size, bytes(data or b""), bool(init)))
    if not blocks:
        return empty
    little = not (isinstance(arch, str) and ":BE:" in arch)
    reader = ImageReader(blocks=blocks, little_endian=little, ok=True)
    _load_dynamic(reader, rows)
    return reader


# ELF32 dynamic-section tags the GOT reading needs.
_DT_PLTGOT, _DT_STRTAB, _DT_SYMTAB = 3, 5, 6
_DT_MIPS_LOCAL_GOTNO, _DT_MIPS_GOTSYM = 0x7000000A, 0x70000013
_GP_BIAS = 0x7FF0


def _load_dynamic(reader: ImageReader, rows: list[Any]) -> None:
    """Fill ``reader``'s MIPS global-pointer and symbol-table fields from the ``.dynamic`` block, so
    :meth:`ImageReader.got_target` can resolve a gp-relative slot. Best effort: any miss leaves the
    fields None and gp-relative sites read unexplained."""
    dyn = next((bytes(d or b"") for name, _s, d, _i in rows if name == ".dynamic"), None)
    if not dyn:
        return
    fmt = "<II" if reader.little_endian else ">II"
    tags: dict[int, int] = {}
    for off in range(0, len(dyn) - 7, 8):
        tag, val = struct.unpack_from(fmt, dyn, off)
        if tag == 0:  # DT_NULL ends the array
            break
        tags.setdefault(tag, val)
    reader.pltgot = tags.get(_DT_PLTGOT)
    reader.symtab = tags.get(_DT_SYMTAB)
    reader.strtab = tags.get(_DT_STRTAB)
    reader.local_gotno = tags.get(_DT_MIPS_LOCAL_GOTNO)
    reader.gotsym = tags.get(_DT_MIPS_GOTSYM)
    if reader.pltgot is not None:
        reader.gp = reader.pltgot + _GP_BIAS


# ── site classification ──────────────────────────────────────────────────────────────────────


@dataclass
class _Ctx:
    """What a site classifier needs beyond the two tokens: each side's image reader, the diff's
    aligned FUN pairs (normalized-hex a, b), the two sides' own non-synthetic names, and the two
    sides' line lists (for the L_var pattern)."""

    reader_a: ImageReader
    reader_b: ImageReader
    aligned: frozenset[tuple[str, str]]
    own: frozenset[str]
    lines_a: list[str]
    lines_b: list[str]


def _kind(tok: str) -> str:
    if tok.startswith('"'):
        return "str"
    if _NUM.match(tok):
        return "num"
    if re.match(r"^[A-Za-z_]", tok):
        return "id"
    return "punct"


def _norm(tokens: list[str]) -> list[str]:
    return ["LOCAL" if _kind(t) == "id" and _LOCAL.match(t) else t for t in tokens]


def _str_rule(s: str, own: frozenset[str]) -> str | None:
    """Which L_str rule a quoted string argument (identical on both sides) satisfies, else None."""
    if _PATH_STR.match(s):
        return "L_str_path"
    if _IDENT_STR.match(s):
        return "L_str_own" if s[1:-1] in own else "L_str_ident"
    return None


def _int(tok: str) -> int | None:
    try:
        return int(tok, 0)
    except ValueError:
        return None


def _base_and_sign(prev: list[str]) -> tuple[str, int]:
    """The base identifier before a ``base + off`` / ``base - off`` / ``base + -off`` site and the
    offset's sign: walk back over the ``+`` / ``-`` operator chain accumulating the sign, the first
    non-operator token is the base."""
    sign = 1
    j = len(prev) - 1
    while j >= 0 and prev[j] in ("+", "-"):
        if prev[j] == "-":
            sign = -sign
        j -= 1
    return (prev[j] if j >= 0 else ""), sign


def _line_var_shift(name: str, lines_a: list[str], lines_b: list[str]) -> bool:
    """Whether a variable assigned a bare number is later passed right after a name/path string or a
    DAT pointer on BOTH sides (a line number carried through a variable)."""
    arg = r'("[A-Za-z_][A-Za-z0-9_]*"|"[^"]*\.(?:c|cc|cpp|h)"|&?(?:PTR_)?DAT_[0-9a-fA-F]+)'
    use = re.compile(arg + r"\s*,\s*" + re.escape(name) + r"\b")
    return any(use.search(ln) for ln in lines_a) and any(use.search(ln) for ln in lines_b)


def classify_site(ta: str, tb: str, pa: list[str], pb: list[str], ctx: _Ctx) -> str:
    """The rule a differing token pair satisfies (an ``L_*`` / ``A_*`` name when the site is a line
    number or an address shift, else a ``C_*`` / ``U_*`` name that is NOT explained). ``pa`` /
    ``pb`` are the tokens before the site on each side (the previous line plus this line's head)."""
    ka, kb = _kind(ta), _kind(tb)
    if ka == "num" and kb == "num":
        return _num_site(ta, tb, pa, pb, ctx)
    if ka == "id" and kb == "id":
        return _id_site(ta, tb, ctx)
    # a string changed, or the kinds differ: not an explained drift
    return "C_str" if ka == "str" and kb == "str" else "U_kind"


def _num_site(ta: str, tb: str, pa: list[str], pb: list[str], ctx: _Ctx) -> str:
    va, vb = _int(ta), _int(tb)
    if va is None or vb is None:
        return "C_num"
    prev_a = pa[-1] if pa else ""
    prev_b = pb[-1] if pb else ""
    arg_a = pa[-2] if len(pa) >= 2 else ""
    arg_b = pb[-2] if len(pb) >= 2 else ""
    # a number right after a string-literal argument that is the same on both sides
    if prev_a == "," and prev_b == "," and arg_a == arg_b and _kind(arg_a) == "str":
        rule = _str_rule(arg_a, ctx.own)
        if rule is not None:
            return rule
    # a number right after a pointer to the same identifier/path string on both sides
    if prev_a == "," and prev_b == ",":
        ma, mb = _ADDRTOK.match(arg_a), _ADDRTOK.match(arg_b)
        if ma and mb:
            ca = ctx.reader_a.cstring_at(int(ma.group(3), 16))
            cb = ctx.reader_b.cstring_at(int(mb.group(3), 16))
            if ca is not None and ca == cb:
                q = '"' + ca.decode("latin-1") + '"'
                if _IDENT_STR.match(q) or _PATH_STR.match(q):
                    return "L_ptr"
    # a base+offset: explained only when the base is PROVEN gp and both offsets reach the same
    # GOT target; any other base (frame pointer, parameter, local) is not explained.
    if prev_a in ("+", "-") and prev_b in ("+", "-"):
        base_a, sign_a = _base_and_sign(pa)
        base_b, sign_b = _base_and_sign(pb)
        if base_a in _GP_NAMES and base_b in _GP_NAMES:
            ra = ctx.reader_a.got_target(sign_a * va)
            rb = ctx.reader_b.got_target(sign_b * vb)
            if ra is not None and ra == rb:
                return "A_got"
        return "U_baseoff"
    # a bare image address: same content on both sides is an address shift
    if va != vb:
        da, db = ctx.reader_a.content_at(va), ctx.reader_b.content_at(vb)
        if da is not None and db is not None and da == db:
            return "A_strptr" if da[0] == "str" else "A_imgaddr"
        if da is not None or db is not None:
            return "C_num"  # one side points at content, the other does not: undecidable
    # a number assigned to a variable later passed as a line-number argument on both sides
    for line in ctx.lines_a:
        m = re.match(r"^\s*(\w+)\s*=\s*(?:0x[0-9a-fA-F]+|\d+);\s*$", line)
        if m and _line_var_shift(m.group(1), ctx.lines_a, ctx.lines_b):
            return "L_var"
    return "C_num"


def _id_site(ta: str, tb: str, ctx: _Ctx) -> str:
    ma, mb = _ADDRTOK.match(ta), _ADDRTOK.match(tb)
    if ma and mb and ma.group(1).startswith("PTR_") and mb.group(1).startswith("PTR_"):
        fa = ctx.reader_a.word_at(int(ma.group(3), 16))
        fb = ctx.reader_b.word_at(int(mb.group(3), 16))
        if fa is None or fb is None:
            return "U_ptr"
        ca, cb = ctx.reader_a.content_at(fa), ctx.reader_b.content_at(fb)
        return "A_ptr" if ca is not None and ca == cb else "U_ptr"
    if ma and mb and ma.group(1) == mb.group(1):
        pre, _ta_txt, aa = ma.groups()
        _pb, _tb_txt, ab = mb.groups()
        if pre in ("FUN", "PTR_FUN", "thunk_FUN"):
            return "A_fun" if (aa.lower().zfill(8), ab.lower().zfill(8)) in ctx.aligned else "U_fun"
        if pre in ("s", "u"):
            return "A_strlabel" if _ta_txt == _tb_txt else "C_strlabel"
        if pre in ("DAT", "UNK"):
            ba, bb = ctx.reader_a.content_at(int(aa, 16)), ctx.reader_b.content_at(int(ab, 16))
            return "A_dat" if ba is not None and ba == bb else "U_dat"
        if pre in ("LAB", "switchD", "switchdataD", "caseD"):
            return "A_codelabel"
    return "U_ident"


# ── the entry-level reading ──────────────────────────────────────────────────────────────────


def _lines(text: str) -> tuple[list[list[str]], list[list[str]]]:
    """A text's lines as (raw tokens, locals-normalized tokens) per line, blank lines dropped."""
    raw: list[list[str]] = []
    norm: list[list[str]] = []
    for line in text.splitlines():
        toks = _TOK.findall(line)
        if not toks:
            continue
        raw.append(toks)
        norm.append(_norm(toks))
    return raw, norm


def _explained(rule: str) -> bool:
    return rule in _LINE_RULES or rule in _ADDRESS_RULES


def drift_reading(
    text_a: str,
    text_b: str,
    delta: dict[str, Any],
    reader_a: ImageReader,
    reader_b: ImageReader,
    aligned: frozenset[tuple[str, str]],
    name_a: str | None,
    name_b: str | None,
    callee_state: str | None,
    size_a: int | None,
    size_b: int | None,
) -> dict[str, Any]:
    """Whether an aligned pair is ``drift_only`` (module docstring). ``delta`` is its
    ``pseudocode_delta``; ``aligned`` the diff's aligned FUN pairs; ``callee_state`` /
    ``size_a`` / ``size_b`` the pair's aligned callee-set state and body sizes."""
    kind = delta.get("kind")
    if kind == "not_computed":
        return {"state": UNDETERMINED, "why": "pseudocode_delta not computed (too_large)"}
    if kind != "substitution_only":
        # structural, or layout_only (no token difference at all): not a drift reading
        return {"state": NOT_DRIFT_ONLY, "why": f"delta is {kind}"}
    if delta.get("calls"):
        return {"state": NOT_DRIFT_ONLY, "why": "a call count differs"}
    if not reader_a.ok or not reader_b.ok:
        return {"state": UNDETERMINED, "why": "an image could not be read"}
    raw_a, norm_a = _lines(text_a)
    raw_b, norm_b = _lines(text_b)
    if len(raw_a) * len(raw_b) > LINE_PRODUCT_CAP:
        return {"state": UNDETERMINED, "why": "too_large"}
    own = frozenset(n for n in (name_a, name_b) if n)
    ctx = _Ctx(
        reader_a=reader_a,
        reader_b=reader_b,
        aligned=aligned,
        own=own,
        lines_a=[" ".join(t) for t in raw_a],
        lines_b=[" ".join(t) for t in raw_b],
    )
    matcher = SequenceMatcher(
        None, [" ".join(n) for n in norm_a], [" ".join(n) for n in norm_b], autojunk=False
    )
    counts: dict[str, int] = {"line": 0, "address": 0}
    for op, i1, i2, j1, j2 in matcher.get_opcodes():
        if op == "equal":
            continue
        if op != "replace" or (i2 - i1) != (j2 - j1):
            return {"state": NOT_DRIFT_ONLY, "why": "a line was added or removed"}
        for x, y in zip(range(i1, i2), range(j1, j2), strict=True):
            na, nb = norm_a[x], norm_b[y]
            if len(na) != len(nb):
                return {"state": NOT_DRIFT_ONLY, "why": "a line changed length"}
            ra, rb = raw_a[x], raw_b[y]
            prev_a = raw_a[x - 1] if x > 0 else []
            prev_b = raw_b[y - 1] if y > 0 else []
            for k, (p, q) in enumerate(zip(na, nb, strict=True)):
                if p == q:
                    continue
                if _kind(ra[k]) == "num" and ra[k - 1 : k] == ["/*"]:
                    counts["address"] += 1  # an address inside a decompiler comment
                    continue
                rule = classify_site(ra[k], rb[k], prev_a + ra[:k], prev_b + rb[:k], ctx)
                if not _explained(rule):
                    return {"state": NOT_DRIFT_ONLY, "why": f"unexplained site: {rule}"}
                counts["line" if rule in _LINE_RULES else "address"] += 1
    if counts["line"] == 0 and counts["address"] == 0:
        return {"state": NOT_DRIFT_ONLY, "why": "no differing token site"}
    # The extra gate the R bucket uses: the text alone cannot see a call in a dropped dead block.
    if callee_state != "equal":
        return {"state": NOT_DRIFT_ONLY, "why": f"callee_set {callee_state or 'unknown'}"}
    if size_a is None or size_b is None or size_a != size_b:
        return {"state": NOT_DRIFT_ONLY, "why": "body sizes not recorded equal"}
    return {"state": DRIFT_ONLY, "sites": counts}
