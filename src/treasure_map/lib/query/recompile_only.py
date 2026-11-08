# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Whether every change one diff holds is explained by recompiling the same source — a diff-level
fact, read at query time, never stored.

A diff is one binary in two runs. ``recompile_only`` reads it three-state:

  * ``true``  — every difference this reading compares was given an explanation from the fixed
    list below, and every input it needs could be read;
  * ``false`` — at least one difference has no such explanation (the first one found is named; the
    reading stops there, so later ones are not counted);
  * ``null``  — no unexplained difference was found, but an input could not be read
    (``unknown_because`` names each), so the reading cannot say.

What it compares: the function pairs and one-sided functions of the diff, the import stubs it
accounted, the one-sided string literals of the two ``strings`` tables, and the stored bytes of
every block both sides exported (``data_blocks``), position by position. Sections a scan does not
store (symbol / debug sections outside the loaded image) are not compared.

The explanations, and nothing else:

  * a function pair whose normalized pseudocode is identical (address suffixes blanked by
    lib/query/sameness), a stub pair of the same name, or two bodies whose stored bytes are
    identical;
  * a pair whose text differs only at sites that are a ``__FILE__``/``__LINE__``-style line number
    (a number passed right after a function-name or source-path string, the first ``%d`` of a
    format, or the view's own line_number_form) or an embedded version / build string — only when
    its callee sets are proven equal and both body sizes are recorded and equal (the text cannot
    show calls in code the decompiler dropped). A number after a string is a line number by
    evidence (strong) only when the string is a source path or the function's own name (on both
    sides), or when, on both sides, a string literal on the number's line holds a ``%s``
    conversion followed by a ``%d`` / ``%u`` / ``%i`` / ``%x`` one — or the line before holds one
    and its statement continues onto the number's line (lib/query/line_format, the test the drift
    reading shares); after any other identifier-shaped string, or through a variable assigned the
    number, it is weak, and a pair with no strong site reads its weak ones as changed constants.
    Every line-number site of a pair must shift by one same nonzero step; a weak site is tied to
    the strong one by that step alone (not by call or place), so a real constant that moves by
    exactly a line number's step in the same function reads as a line number — the accepted cost
    of reading unlabelled line numbers at all;
  * a string pair that becomes equal once its generic date / time / version shapes are replaced by
    placeholders, or its build-environment paths (below);
  * changed bytes that lie inside a GNU build-id note's descriptor at the same place on both
    sides, inside such a string pair, or inside a function accepted by the second rule.

The build-environment class is narrow: an absolute path whose first component is not a runtime or
configuration root (``/etc``, ``/var``, ``/tmp``, ``/usr``, ...) is rewritten from its first
toolchain component (``toolchain(s)``, ``sysroot``, ``crosstool*``) — or, with none, from its first
build-tree component (``src``, ``src-*``) — on, and only when at least two components follow that
anchor. A ``user@host`` token is rewritten only in a string that also carries a date / time shape
(a build banner). A dotted number is a version only when it is not glued to a name (``eth0.1``,
``TLSv1.2``) and, without a ``v`` prefix, not shaped like an IPv4 address or netmask (four parts
each at most 255, or three with one of 100 or more).

A reading that hits an error it did not expect is null (``reading_failed:<type>``), never a crash
of the tool that asked; a block whose stored bytes fall short of its size makes it null
(``data_blocks_truncated``) — the bytes past the cut were never compared.

Fail closed: anything that is not one of these is an unexplained difference — a one-sided function,
a changed callee, a constant, a moved code block, a byte no rule attributes. ``true`` is a fact
about these comparisons, NOT a statement that the binary behaves the same: a version string can
feed a comparison, and the reading never looks at what a string is used for. It changes nothing
else a view computes — not the must-read set, not a unit, not an order, not a judgement.
"""

from __future__ import annotations

import bisect
import difflib
import re
import sqlite3
import struct
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from treasure_map.lib.query import entry_words, sameness
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query.line_format import format_evidence
from treasure_map.lib.ro_db import ro_connect

# The rule version this reading follows; part of its cache key and of every answer.
RULE = "recompile-only-v3"
# The key a patch-view entry carries when its diff reads true (and only then).
ENTRY_KEY = "recompile_only_diff"
# How many characters of a firmware string an answer quotes.
_QUOTE = 80
# Line pairs past which a pair's sites are not classified (the classification is then unknown).
_LINE_PRODUCT_CAP = sameness.DELTA_LINE_PRODUCT_CAP


# ── version / build strings ──────────────────────────────────────────────────────────────────

_MON = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
_DOW = r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)"
# Generic date / time / version shapes, longer and more specific first: a later rule never splits
# an earlier match.
_VERSION_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ctime",
        re.compile(
            rf"\b{_DOW}\s+{_MON}\s+\d{{1,2}}(?:\s+\d{{1,2}}:\d{{2}}(?::\d{{2}})?)?"
            rf"(?:\s+[A-Z]{{3,4}})?(?:\s+\d{{4}})?\b"
        ),
    ),
    ("c_date", re.compile(rf"\b{_MON}\s+\d{{1,2}}\s+\d{{4}}\b")),
    ("dmy_date", re.compile(rf"\b\d{{1,2}}\s+{_MON}\s+\d{{4}}\b")),
    (
        "iso_date",
        re.compile(r"\b(?:19|20)\d{2}[-./](?:0[1-9]|1[0-2])[-./](?:0[1-9]|[12]\d|3[01])\b"),
    ),
    (
        "ymd_stamp",
        re.compile(
            r"(?<![0-9])(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])(?:\d{4}(?:\d{2})?)?"
            r"(?![0-9])"
        ),
    ),
    ("clock", re.compile(r"(?<![0-9:])\d{1,2}:\d{2}(?::\d{2})?(?![0-9:])")),
    (
        "revision",
        re.compile(
            r"(?i)(?<![A-Za-z0-9])(?:svn|rev\.?\s?|r)\d{3,}(?![0-9])|(?<=-)g[0-9a-f]{7,12}\b"
            r"|\bgit[-_ ]?[0-9a-f]{7,40}\b"
        ),
    ),
    (
        "dotted_version",
        re.compile(
            r"(?<![0-9.])[vV]?\d+(?:\.\d+){1,3}(?:[-_.]?(?:rc|beta|alpha|p)\d*|[a-z](?![A-Za-z]))?"
            r"(?![0-9.])"
        ),
    ),
)
_DATE_SHAPES = frozenset({"ctime", "c_date", "dmy_date", "iso_date", "ymd_stamp", "clock"})
_LEADING_DOTTED = re.compile(r"\d+(?:\.\d+)*")

# An absolute path inside a string: a slash not glued to a word, and at least two components.
_PATH_TOKEN = re.compile(r"(?<![\w./-])/[\w.+-]+(?:/[\w.+-]+)+")
# First components that name where a running system keeps its files: never a build environment.
_RUNTIME_ROOTS = frozenset(
    "etc var tmp proc sys dev run mnt media usr lib lib32 lib64 bin sbin www jffs jffs2 overlay "
    "rom boot srv root config cfg nvram".split()
)
_TOOLCHAIN_COMPONENTS = frozenset({"toolchain", "toolchains", "sysroot"})
# Components that must follow the anchor, the anchor itself not counted.
_ANCHOR_TAIL_MIN = 2
_USER_AT_HOST = re.compile(
    r"(?<![\w.@-])[A-Za-z_][\w.-]*@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?![\w@-])"
)


def _toolchain_component(c: str) -> bool:
    return c.lower() in _TOOLCHAIN_COMPONENTS or c.lower().startswith("crosstool")


def _build_tree_component(c: str) -> bool:
    return c == "src" or c.startswith("src-")


def build_env_tail(path: str) -> str | None:
    """The part of an absolute path a build environment does not decide — from its first toolchain
    component, else its first build-tree component, on — or None when the path is not of the narrow
    build-environment class (a runtime / configuration root, no anchor past the first component, or
    fewer than two components after the anchor)."""
    comps = path.strip("/").split("/")
    if len(comps) < 2 or comps[0].lower() in _RUNTIME_ROOTS:
        return None
    for test in (_toolchain_component, _build_tree_component):
        for i in range(1, len(comps)):
            if test(comps[i]):
                if len(comps) - i - 1 < _ANCHOR_TAIL_MIN:
                    return None
                return "/" + "/".join(comps[i:])
    return None


def _not_a_version(s: str, m: re.Match[str]) -> bool:
    """A dotted match that is an address / netmask or glued to a name, not a version. The glued
    test comes first, so a ``v`` prefix glued to a name (``TLSv1.2``) is not a version either."""
    text = m.group(0)
    if m.start() > 0 and s[m.start() - 1].isascii() and s[m.start() - 1].isalpha():
        return True  # eth0.1, wl0.1: an interface-style name; TLSv1.2: a protocol name
    if text[:1] in ("v", "V"):
        return False
    lead = _LEADING_DOTTED.match(text)
    parts = [int(p) for p in lead.group(0).split(".")] if lead else []
    if parts and all(p <= 255 for p in parts):
        if len(parts) == 4 or (len(parts) == 3 and max(parts) >= 100):
            return True
    return False


def skeleton(s: str) -> tuple[str, tuple[str, ...]]:
    """``s`` with every build-environment path, version / date shape and (in a build banner) every
    ``user@host`` token replaced by a placeholder, and the classes replaced (sorted, with
    repeats)."""
    spans: list[tuple[int, int, str, str]] = []

    def free(a: int, b: int) -> bool:
        return not any(a < e and s0 < b for s0, e, _, _ in spans)

    for m in _PATH_TOKEN.finditer(s):
        tail = build_env_tail(m.group(0))
        if tail is not None and free(m.start(), m.end()):
            spans.append((m.start(), m.end(), "build_env", "<build_root>" + tail))
    for name, rx in _VERSION_RULES:
        for m in rx.finditer(s):
            if not free(m.start(), m.end()):
                continue
            if name == "dotted_version" and _not_a_version(s, m):
                continue
            spans.append((m.start(), m.end(), name, f"<{name}>"))
    if any(name in _DATE_SHAPES for _, _, name, _ in spans):
        for m in _USER_AT_HOST.finditer(s):
            if free(m.start(), m.end()):
                spans.append((m.start(), m.end(), "build_host", "<build_host>"))
    spans.sort()
    out: list[str] = []
    last = 0
    for s0, e, _name, text in spans:
        out.append(s[last:s0])
        out.append(text)
        last = e
    out.append(s[last:])
    return "".join(out), tuple(sorted(name for _, _, name, _ in spans))


def string_pair_classes(a: str, b: str) -> tuple[str, ...] | None:
    """The placeholder classes that explain ``a`` -> ``b`` (equal skeletons, at least one
    placeholder), else None."""
    if a == b:
        return None
    ka, na = skeleton(a)
    kb, nb = skeleton(b)
    if (na or nb) and ka == kb:
        return tuple(sorted(set(na) | set(nb)))
    return None


def _string_kind(classes: Iterable[str]) -> str:
    """The counter a string pair adds to: build_env_strings when a build-environment class carried
    it, else version_strings."""
    return (
        "build_env_strings"
        if any(c in ("build_env", "build_host") for c in classes)
        else "version_strings"
    )


# ── the image: stored bytes, read through lib/query/entry_words ──────────────────────────────


def _read(img: entry_words.Image, va: int, n: int) -> bytes | None:
    hit = img.block_at(va)
    if hit is None:
        return None
    _i, b = hit
    if not b.initialized:
        return None
    off = va - b.start
    if va + n > b.stored_end:
        return None
    return b.data[off : off + n]


def _cstr(img: entry_words.Image, va: int, limit: int = 200) -> bytes | None:
    raw = _read(img, va, 1)
    if raw is None:
        return None
    hit = img.block_at(va)
    assert hit is not None
    b = hit[1]
    chunk = b.data[va - b.start : min(va - b.start + limit, b.stored_end - b.start)]
    end = chunk.find(b"\0")
    return chunk[:end] if end >= 0 else None


def _printable(raw: bytes) -> bool:
    return bool(raw) and all(32 <= c < 127 for c in raw)


def _note_ranges(img: entry_words.Image, va: int, size: int, little: bool) -> list[tuple[int, int]]:
    """(descriptor address, descriptor size) of every GNU build-id note stored in
    ``[va, va + size)``."""
    out: list[tuple[int, int]] = []
    raw = _read(img, va, size)
    if raw is None:
        return out
    fmt = "<III" if little else ">III"
    off = 0
    while off + 12 <= len(raw):
        namesz, descsz, ntype = struct.unpack_from(fmt, raw, off)
        name_off = off + 12
        desc_off = name_off + ((namesz + 3) & ~3)
        end = desc_off + ((descsz + 3) & ~3)
        if namesz > 256 or descsz > 4096 or end > len(raw) or end <= off:
            break
        if ntype == 3 and raw[name_off : name_off + namesz] == b"GNU\0" and descsz:
            out.append((va + desc_off, descsz))
        off = end
    return out


def build_id_ranges(img: entry_words.Image) -> tuple[set[tuple[int, int]], str | None]:
    """Every GNU build-id descriptor (address, size) the stored image holds, found through the ELF
    program headers stored at the start of the image (PT_NOTE) and through any ``.note*`` block —
    and why none could be looked for (no ELF header stored), else None."""
    found: set[tuple[int, int]] = set()
    blocks = [b for b in img.blocks if b.initialized and b.data]
    for b in blocks:
        if b.name.lower().startswith(".note"):
            found.update(_note_ranges(img, b.start, b.stored_end - b.start, img.endian != "BE"))
    if not blocks:
        return found, "no_stored_block"
    head = min(blocks, key=lambda x: x.start)
    raw = head.data
    if raw[:4] != b"\x7fELF" or len(raw) < 0x40:
        return found, None if found else "no_elf_header_stored"
    little = raw[5] == 1
    e = "<" if little else ">"
    if raw[4] == 1:
        phoff, phentsize, phnum = (
            struct.unpack_from(e + "I", raw, 0x1C)[0],
            *struct.unpack_from(e + "HH", raw, 0x2A),
        )
        layout = (e + "IIIIII", 0, 1, 2, 4)  # type, offset, vaddr, filesz
    elif raw[4] == 2:
        phoff, phentsize, phnum = (
            struct.unpack_from(e + "Q", raw, 0x20)[0],
            *struct.unpack_from(e + "HH", raw, 0x36),
        )
        layout = (e + "IIQQQQ", 0, 2, 3, 5)
    else:
        return found, None if found else "elf_class_unknown"
    fmt, i_type, i_off, i_va, i_fsz = layout
    need = struct.calcsize(fmt)
    phdrs: list[tuple[int, int, int, int]] = []
    for k in range(min(phnum, 128)):
        at = phoff + k * phentsize
        if phentsize < need or at + need > len(raw):
            return found, None if found else "program_headers_not_stored"
        row = struct.unpack_from(fmt, raw, at)
        phdrs.append((row[i_type], row[i_off], row[i_va], row[i_fsz]))
    first_load = next((p for p in phdrs if p[0] == 1 and p[1] == 0), None)
    if first_load is None:
        return found, None if found else "no_load_at_file_start"
    delta = head.start - first_load[2]
    for p_type, _off, vaddr, filesz in phdrs:
        if p_type == 4 and 0 < filesz <= 65536:
            found.update(_note_ranges(img, vaddr + delta, filesz, little))
    return found, None


def _differing_runs(x: bytes, y: bytes, chunk: int = 4096) -> list[tuple[int, int]]:
    """(offset, length) of every maximal run of positions where ``x`` and ``y`` differ."""
    out: list[tuple[int, int]] = []
    n = min(len(x), len(y))
    i = 0
    while i < n:
        j = min(n, i + chunk)
        if x[i:j] == y[i:j]:
            i = j
            continue
        k = i
        while k < j:
            if x[k] != y[k]:
                end = k
                while end < n and x[end] != y[end]:
                    end += 1
                out.append((k, end - k))
                k = end
            else:
                k += 1
        i = max(j, k)
    return out


def _ctx_string(buf: bytes, off: int, ln: int, limit: int = 200) -> str | None:
    """The printable NUL-terminated string that holds ``buf[off:off+ln]``, or None."""
    st = off
    while st > 0 and off - st < limit and 32 <= buf[st - 1] < 127:
        st -= 1
    en = off + ln
    while en < len(buf) and en - off < limit and buf[en] != 0:
        en += 1
    if en >= len(buf) or buf[en] != 0:
        return None
    seg = buf[st:en]
    if len(seg) < 4 or not all(32 <= c < 127 or c in (9, 10, 13) for c in seg):
        return None
    return seg.decode()


# ── the sites of a text difference ───────────────────────────────────────────────────────────

_TOK = re.compile(r'"(?:[^"\\]|\\.)*"|0x[0-9a-fA-F]+|\d+|[A-Za-z_][A-Za-z0-9_]*|\S')
_LOCAL = re.compile(
    r"^(?:[iuplcbsfdx]Var\d+|local_[0-9a-f]+|param_\d+|a[ucilsb]*Stack_[0-9a-f]+|in_\w+"
    r"|extraout_\w+|unaff_\w+|ppcVar\d+|pp[a-z]Var\d+|p[a-z]+Var\d+|[a-z]+Var\d+|_Var\d+"
    r"|local_res\w+)$"
)
_IDENT_STR = re.compile(r'^"[A-Za-z_][A-Za-z0-9_]*"$')
_PATH_STR = re.compile(r'^"[^"]*\.(?:c|h|cpp|cc)"$')
_ADDR_TOK = re.compile(
    r"^(thunk_FUN|FUN|DAT|UNK|LAB|PTR_DAT|PTR_FUN|PTR_LAB|PTR_UNK|PTR_s|PTR_u|s|u|switchD"
    r"|switchdataD|caseD)_(.*?)_?([0-9a-fA-F]{6,8})$"
)
_NUMBER = re.compile(r"^(0x[0-9a-fA-F]+|\d+)$")
_ASSIGN_NUMBER = re.compile(r"^\s*(\w+)\s*=\s*(?:0x[0-9a-fA-F]+|\d+);\s*$")
_FMT_CONV = re.compile(r"%[-0-9.]*[a-zA-Z]")
# A variable passed right after a function-name / data-label / source-path string argument.
_PASSED_AFTER_NAME = (
    r'("[A-Za-z_][A-Za-z0-9_]*"|&?(?:PTR_)?DAT_[0-9a-fA-F]+|"[^"]*\.(?:c|h|cpp)")\s*,\s*'
)
# The site classes a recompile explains: a line number, a line number by the first %d of a format,
# an embedded version / build string. ``Lw`` (a weak line number: an identifier-shaped string or an
# assigned variable without the evidence above) counts as ``L`` only beside a strong ``L`` site of
# the same pair, else as a changed constant.
_ACCEPTED_SITES = frozenset({"L", "L2", "V"})
# The site classes that must all shift by one same nonzero step within a pair.
_LINE_SITES = frozenset({"L", "Lw", "L2"})


def _kind(t: str) -> str:
    if t.startswith('"'):
        return "str"
    if _NUMBER.match(t):
        return "num"
    if t[:1].isalpha() or t[:1] == "_":
        return "id"
    return "p"


def _norm(tokens: list[str]) -> list[str]:
    return ["LOCAL" if _kind(t) == "id" and _LOCAL.match(t) else t for t in tokens]


# The two sides' own function names (None when synthetic or unknown).
_Names = tuple[str | None, str | None]


@dataclass(frozen=True)
class _Sides:
    ia: entry_words.Image
    ib: entry_words.Image


def _word(img: entry_words.Image, va: int) -> int | None:
    raw = _read(img, va, 4)
    if raw is None or len(raw) < 4:
        return None
    return int(struct.unpack("<I" if img.endian != "BE" else ">I", raw)[0])


def _label_string(img: entry_words.Image, addr_hex: str) -> str | None:
    raw = _cstr(img, int(addr_hex, 16))
    return raw.decode() if raw is not None and _printable(raw) else None


def _string_site(ta: str, tb: str) -> tuple[str, str]:
    classes = string_pair_classes(ta[1:-1], tb[1:-1])
    if classes:
        return "V", "string literal: " + ",".join(sorted(set(classes)))
    return "C", "string literal changed"


def _ident_site(ta: str, tb: str, sides: _Sides) -> tuple[str, str]:
    ma, mb = _ADDR_TOK.match(ta), _ADDR_TOK.match(tb)
    if ma and mb and ma.group(1).startswith("PTR_") and mb.group(1).startswith("PTR_"):
        pa, pb = _word(sides.ia, int(ma.group(3), 16)), _word(sides.ib, int(mb.group(3), 16))
        if pa is None or pb is None:
            return "U", "pointer outside the stored image"
        ca, cb = _cstr(sides.ia, pa), _cstr(sides.ib, pb)
        if ca is not None and cb is not None and _printable(ca + cb):
            if ca == cb:
                return "A", "pointer to the same string"
            classes = string_pair_classes(ca.decode(), cb.decode())
            if classes:
                return "V", "pointer to a string: " + ",".join(sorted(set(classes)))
            return "C", "pointer to a changed string"
        return "A", "pointer"
    if ma and mb and ma.group(1) == mb.group(1):
        pre = ma.group(1)
        if pre in ("s", "u", "PTR_s", "PTR_u") or pre.endswith(("s", "u")):
            if ma.group(2) == mb.group(2):
                return "A", "string label, same text"
            sa = _label_string(sides.ia, ma.group(3))
            sb = _label_string(sides.ib, mb.group(3))
            if sa is not None and sb is not None:
                classes = string_pair_classes(sa, sb)
                if classes:
                    return "V", "string label: " + ",".join(sorted(set(classes)))
            return "C", "string label, text changed"
        if pre in ("DAT", "UNK"):
            ba = _read(sides.ia, int(ma.group(3), 16), 4)
            bb = _read(sides.ib, int(mb.group(3), 16), 4)
            if ba is None or bb is None:
                return "U", "data label outside the stored image"
            if ba == bb:
                return "A", "data label, same bytes"
            sa = _label_string(sides.ia, ma.group(3))
            sb = _label_string(sides.ib, mb.group(3))
            if sa is not None and sb is not None:
                classes = string_pair_classes(sa, sb)
                if classes:
                    return "V", "data label string: " + ",".join(sorted(set(classes)))
            return "C", "data label, bytes differ"
        return "A", "address label"
    return "U", "identifier changed"


def _same_name_string(sides: _Sides, tok_a: str | None, tok_b: str | None) -> str | None:
    """The quoted text when both tokens are labels of strings with the same text that is
    identifier-shaped or a source path (a __func__ / __FILE__ argument), else None."""
    if not tok_a or not tok_b:
        return None
    ma, mb = _ADDR_TOK.match(tok_a), _ADDR_TOK.match(tok_b)
    if not ma or not mb:
        return None
    ca, cb = _cstr(sides.ia, int(ma.group(3), 16)), _cstr(sides.ib, int(mb.group(3), 16))
    if not ca or ca != cb:
        return None
    quoted = '"' + ca.decode(errors="replace") + '"'
    return quoted if _IDENT_STR.match(quoted) or _PATH_STR.match(quoted) else None


def _fmt_near(lines: list[list[str]], i: int) -> bool:
    """Line ``i`` (its tokens) holds a name-then-line format literal, or the line before holds one
    and its statement continues onto line ``i`` (:func:`line_format.format_evidence`)."""
    return format_evidence(lines[i], lines[i - 1] if i > 0 else [])


def _strong_name(quoted: str, names: _Names) -> bool:
    """The string before a number is a source path, or both sides' own function name."""
    text = quoted[1:-1]
    return bool(_PATH_STR.match(quoted)) or (bool(text) and names == (text, text))


def _entry_sites(
    la: list[str], lb: list[str], sides: _Sides, names: _Names = (None, None)
) -> tuple[list[tuple[str, str, str, str]], str | None]:
    """((a token, b token, class, why) per differing site, why the text could not be read as sites
    — ``structural`` / ``too_large`` — or None)."""
    ta = [_norm(_TOK.findall(x)) for x in la]
    tb = [_norm(_TOK.findall(x)) for x in lb]
    ja, jb = [" ".join(x) for x in ta], [" ".join(x) for x in tb]
    # The equal leading and trailing lines are set aside before the cap is applied: only the
    # changed middle is aligned.
    head = 0
    while head < min(len(ja), len(jb)) and ja[head] == jb[head]:
        head += 1
    tail = 0
    while tail < min(len(ja), len(jb)) - head and ja[-1 - tail] == jb[-1 - tail]:
        tail += 1
    mid_a, mid_b = ja[head : len(ja) - tail], jb[head : len(jb) - tail]
    if len(mid_a) * len(mid_b) > _LINE_PRODUCT_CAP:
        return [], "too_large"
    sm = difflib.SequenceMatcher(None, mid_a, mid_b, False)
    sites: list[tuple[str, str, str, str]] = []
    for op, m1, m2, n1, n2 in sm.get_opcodes():
        if op == "equal":
            continue
        i1, i2, j1, j2 = m1 + head, m2 + head, n1 + head, n2 + head
        if op != "replace" or (i2 - i1) != (j2 - j1):
            return sites, "structural"
        for x, y in zip(range(i1, i2), range(j1, j2), strict=True):
            a_toks, b_toks = ta[x], tb[y]
            if len(a_toks) != len(b_toks) or any(
                _kind(p) != _kind(q) and not ({_kind(p), _kind(q)} <= {"num", "id"})
                for p, q in zip(a_toks, b_toks, strict=True)
            ):
                return sites, "structural"
            for k, (p, q) in enumerate(zip(a_toks, b_toks, strict=True)):
                if p == q:
                    continue
                sites.append((p, q, *_site(la, lb, ta, tb, x, y, k, sides, names)))
    return sites, None


def _site(
    la: list[str],
    lb: list[str],
    ta: list[list[str]],
    tb: list[list[str]],
    x: int,
    y: int,
    k: int,
    sides: _Sides,
    names: _Names = (None, None),
) -> tuple[str, str]:
    a_toks, b_toks = ta[x], tb[y]
    p, q = a_toks[k], b_toks[k]
    kp, kq = _kind(p), _kind(q)
    if la[x].lstrip().startswith("/*") and kp == "num":
        return "A", "address in a decompiler comment"
    if kp == "str" and kq == "str":
        return _string_site(p, q)
    if kp == "id" and kq == "id":
        return _ident_site(p, q, sides)
    if kp != "num" or kq != "num":
        return "U", "token kinds differ"
    # the tokens before this one, the previous line included (a call may span lines)
    pa = (ta[x - 1] if x > 0 else []) + a_toks[:k]
    pb = (tb[y - 1] if y > 0 else []) + b_toks[:k]
    prev_a, prev_b = (pa[-1] if pa else None), (pb[-1] if pb else None)
    prev2_a, prev2_b = (pa[-2] if len(pa) >= 2 else None), (pb[-2] if len(pb) >= 2 else None)
    # a number after a string is a line number by evidence (L) only beside a format of the
    # name-then-line shape on both sides, or after a source path / the function's own name; after
    # any other identifier-shaped string it is weak (Lw)
    fmt = _fmt_near(ta, x) and _fmt_near(tb, y)
    if prev_a == "," and prev_b == ",":
        if (
            prev2_a
            and prev2_a == prev2_b
            and (_IDENT_STR.match(prev2_a) or _PATH_STR.match(prev2_a))
        ):
            strong = fmt or _strong_name(prev2_a, names)
            return ("L" if strong else "Lw"), "number after a function-name / source-path string"
        quoted = _same_name_string(sides, prev2_a, prev2_b)
        if quoted is not None:
            strong = fmt or _strong_name(quoted, names)
            return (
                "L" if strong else "Lw"
            ), "number after a label of the same function-name / source-path string"
    neg = (k >= 3 and a_toks[k - 1] == "-" and a_toks[k - 2] == "+") or (
        k >= 2 and a_toks[k - 1] == "-" and _kind(a_toks[k - 2]) == "id"
    )
    if neg or (
        k >= 2 and a_toks[k - 1] == "+" and b_toks[k - 1] == "+" and _kind(a_toks[k - 2]) == "id"
    ):
        return "U", "base + offset"
    m = _ASSIGN_NUMBER.match(la[x])
    if m:
        use = re.compile(_PASSED_AFTER_NAME + re.escape(m.group(1)) + r"\b")
        if any(use.search(ln) for ln in la) and any(use.search(ln) for ln in lb):
            # always weak: the evidence sits on another line than the number (the drift reading
            # reads its L_var the same way)
            return "Lw", "number assigned to a variable passed after a function-name / path string"
    if (
        k >= 2
        and a_toks[k - 1] == ","
        and _kind(a_toks[k - 2]) == "str"
        and a_toks[k - 2] == b_toks[k - 2]
    ):
        conv = _FMT_CONV.search(a_toks[k - 2])
        if conv and conv.group(0).endswith("d"):
            return "L2", "first %d of a format string"
    return "C", "number changed"


def _number(t: str) -> int | None:
    try:
        return int(t, 0)
    except ValueError:
        return None


def entry_explained(
    la: list[str],
    lb: list[str],
    delta: dict[str, Any] | None,
    sides: _Sides,
    names: _Names = (None, None),
) -> tuple[bool | None, str]:
    """Whether a pair's text difference is all line-number / version sites: (True, why) /
    (False, why) / (None, why) when it could not be read as sites. ``names`` are the two sides'
    own function names (None when synthetic), for the strong line-number test."""
    delta = delta or {}
    calls = delta.get("calls") or {}
    if delta.get("kind") == "structural":
        return False, "structural text change"
    if any((v or {}).get("a") != (v or {}).get("b") for v in calls.values()):
        return False, "call counts differ"
    sites, why = _entry_sites(la, lb, sides, names)
    if why == "too_large":
        return None, "too large to read as sites"
    if why == "structural":
        return False, "structural text change"
    if not sites:
        return False, "no text difference behind the differing reading"
    lines = [s for s in sites if s[2] in _LINE_SITES]
    steps = {_step(a, b) for a, b, _c, _w in lines}
    if steps and (len(steps) != 1 or None in steps or 0 in steps):
        first = lines[0]
        return False, (
            "line-number sites do not shift by one nonzero step: "
            f"{first[0][:_QUOTE]} -> {first[1][:_QUOTE]}"
        )
    # weak line-number sites count only beside a strong one; else they are changed constants
    strong = any(c == "L" for _a, _b, c, _w in sites)
    weak_as = "L" if strong else "C"
    sites = [(a, b, weak_as if c == "Lw" else "L" if c == "L2" else c, w) for a, b, c, w in sites]
    kinds = {c for _a, _b, c, _w in sites}
    if delta.get("line_number_form") and kinds <= {"L", "C"}:
        kinds -= {"C"}  # the view's own reading: every changed number is a line-number argument
    if kinds and kinds <= _ACCEPTED_SITES:
        return True, "line-number / version sites"
    first = next(s for s in sites if s[2] not in _ACCEPTED_SITES)
    return False, f"{first[3]}: {first[0][:_QUOTE]} -> {first[1][:_QUOTE]}"


def _step(a: str, b: str) -> int | None:
    na, nb = _number(a), _number(b)
    return None if na is None or nb is None else nb - na


# ── the judgement ────────────────────────────────────────────────────────────────────────────


class _UnexplainedError(Exception):
    def __init__(self, kind: str, **where: Any) -> None:
        super().__init__(kind)
        self.detail = {"kind": kind, **where}


@dataclass
class _State:
    explained: Counter[str] = field(default_factory=Counter)
    unknown: list[str] = field(default_factory=list)
    # A-side entries of the pairs whose reading could not be finished: a byte inside one of them is
    # unknown, never unexplained.
    unread_fns: set[int] = field(default_factory=set)

    def unknown_because(self, reason: str) -> None:
        if reason not in self.unknown:
            self.unknown.append(reason)


def _q(s: str | None) -> str | None:
    return None if s is None else s[:_QUOTE]


_CACHE: pv._BoundedCache[tuple[str, ...], dict[str, Any]] = pv._BoundedCache(512)


def clear_cache() -> None:
    _CACHE.clear()


def _key(atlas: sqlite3.Connection, diff_id: str) -> tuple[str, ...] | None:
    row = atlas.execute(
        "SELECT run_a_id, run_b_id, sha256_a, sha256_b, diff_code_version, created_at "
        "FROM diff_meta WHERE diff_id = ?",
        (diff_id,),
    ).fetchone()
    if row is None:
        return None
    runs: list[str] = []
    for run in (row[0], row[1]):
        r = atlas.execute(
            "SELECT analysis_db_path, build_hash, updated_at FROM run WHERE run_id = ?", (run,)
        ).fetchone()
        runs.extend(str(v or "") for v in (r or (None, None, None)))
    stale = pv.view_staleness(atlas, diff_id).get("source_stale")
    return (
        RULE,
        pv._atlas_identity(atlas),
        diff_id,
        *(str(v or "") for v in row),
        *runs,
        f"stale={stale!s}",
    )


def recompile_only(atlas: sqlite3.Connection, diff_id: str) -> dict[str, Any] | None:
    """The diff's ``recompile_only`` reading (module docstring): ``{value, rule}`` plus
    ``explained`` (what was given an explanation, by kind) when not false, ``unexplained`` (the
    first difference with none) when false, ``unknown_because`` when null. None when there is no
    such diff. Cached per (diff, both runs' sources and stamps, the rule)."""
    key = _key(atlas, diff_id)
    if key is None:
        return None
    hit = _CACHE.get(key)
    if hit is None:
        hit = _judge(atlas, diff_id)
        _CACHE[key] = hit
    return {
        k: (dict(v) if isinstance(v, dict) else list(v) if isinstance(v, list) else v)
        for k, v in hit.items()
    }


def recompile_only_value(atlas: sqlite3.Connection, diff_id: str) -> bool | None:
    out = recompile_only(atlas, diff_id)
    return None if out is None else out["value"]


def label_entries(atlas: sqlite3.Connection, diff_id: str, result: dict[str, Any]) -> None:
    """Add ``recompile_only_diff: true`` to every entry of a patch-view page whose diff reads true;
    leave the page as it is otherwise (the key is then absent)."""
    entries = result.get("entries")
    if not isinstance(entries, list) or not entries or "error" in result:
        return
    if recompile_only_value(atlas, diff_id) is not True:
        return
    for e in entries:
        if isinstance(e, dict):
            e[ENTRY_KEY] = True


def _judge(atlas: sqlite3.Connection, diff_id: str) -> dict[str, Any]:
    st = _State()
    try:
        _run(atlas, diff_id, st)
    except _UnexplainedError as stop:
        return {"value": False, "rule": RULE, "unexplained": stop.detail}
    except Exception as exc:  # noqa: BLE001 — an input that would not read, or a reading bug
        st.unknown_because(f"reading_failed:{type(exc).__name__}")
    out: dict[str, Any] = {
        "value": None if st.unknown else True,
        "rule": RULE,
        "explained": dict(sorted(st.explained.items())),
    }
    if st.unknown:
        out["unknown_because"] = list(st.unknown)
    return out


def _run(atlas: sqlite3.Connection, diff_id: str, st: _State) -> None:
    meta = atlas.execute(
        "SELECT run_a_id, run_b_id, sha256_a, sha256_b, diff_ok, functions_total_a, "
        "functions_total_b, matched_in_domain_a, matched_in_domain_b, unmatched_a, unmatched_b, "
        "presence_computed_a, presence_computed_b, stub_a_only, stub_b_only, stub_pair_mismatch "
        "FROM diff_meta WHERE diff_id = ?",
        (diff_id,),
    ).fetchone()
    run_a, run_b, sha_a, sha_b, diff_ok = meta[0:5]
    if not sha_a or not sha_b:
        st.unknown_because("content_hash_missing")
        return
    if not diff_ok:
        st.unknown_because("diff_not_ok")
        return
    for i, side in enumerate(("a", "b")):
        total, dom, un, computed = meta[5 + i], meta[7 + i], meta[9 + i], meta[11 + i]
        if not computed:
            st.unknown_because(f"presence_not_computed:{side}")
        elif None in (total, dom, un) or total - dom - un != 0:
            st.unknown_because(f"functions_not_accounted:{side}")
    one_sided = atlas.execute(
        "SELECT side, addr, name, presence_state FROM function_presence WHERE diff_id = ? "
        "ORDER BY side, addr LIMIT 1",
        (diff_id,),
    ).fetchone()
    if one_sided is not None:
        raise _UnexplainedError(
            "one_sided_function", side=one_sided[0], addr=one_sided[1], name=one_sided[2]
        )
    for col, raw in (
        ("stub_a_only", meta[13]),
        ("stub_b_only", meta[14]),
        ("stub_pair_mismatch", meta[15]),
    ):
        if raw not in (None, "", "[]"):
            raise _UnexplainedError(
                "import_stub_" + col.removeprefix("stub_"), names=str(raw)[:_QUOTE]
            )
    _strings(atlas, run_a, run_b, sha_a, sha_b, st)

    built = pv.build_diff_view(atlas, diff_id)
    if built is None:
        st.unknown_because("diff_unreadable")
        return
    if built.withheld is not None:
        for b in built.banners:
            st.unknown_because(b)
        return
    stale = built.staleness.get("source_stale")
    if stale is not False:
        st.unknown_because("source_stale" if stale else "source_unverified")
        return
    if built.unavailable:
        st.unknown_because("analysis_db_unavailable")
        return
    readings = pv._pseudo_readings(atlas, built)
    pa, _ = pv._run_source(atlas, run_a)
    pb, _ = pv._run_source(atlas, run_b)
    bodies_a = sameness.read_function_bodies(pa, sha_a)
    bodies_b = sameness.read_function_bodies(pb, sha_b)
    img_a, _why_a = pv._entry_words_image(atlas, run_a, sha_a)
    img_b, _why_b = pv._entry_words_image(atlas, run_b, sha_b)
    if bodies_a is None or bodies_b is None or img_a is None or img_b is None:
        st.unknown_because("function_bodies_or_image_unreadable")
        return
    sides = _Sides(img_a, img_b)

    texts: list[Any] = []  # differing pairs, classified last (the costly step)
    for e in built.placed:
        p = e.pair
        if p is None:
            u = e.unpaired
            assert u is not None
            raise _UnexplainedError("one_sided_function", side=u.side, addr=u.addr, name=u.name)
        if e.callers_b is not None:
            raise _UnexplainedError("caller_set_changed", entry_id=e.entry_id)
        if p.aligned:
            state = pv._sameness_of(e, readings)
            if state == sameness.IDENTICAL:
                st.explained["identical_pairs"] += 1
            elif state == sameness.NO_BODY:
                _same_name_stub(p, e.entry_id, st)
            elif state == sameness.DIFFERS:
                texts.append(e)
            else:
                _bytes_identical(p, e.entry_id, str(state), bodies_a, bodies_b, sides, st)
        else:
            proposed = pv._proposed_of(e, readings)
            ustate = proposed[0] if proposed is not None else None
            if ustate == sameness.U_IDENTICAL_UNIQUE:
                st.explained["identical_pairs"] += 1
            elif ustate == sameness.U_NO_BODY:
                _same_name_stub(p, e.entry_id, st)
            elif ustate == sameness.U_DIFFERS:
                raise _UnexplainedError("undetermined_pair_differs", entry_id=e.entry_id)
            else:
                _bytes_identical(p, e.entry_id, str(ustate), bodies_a, bodies_b, sides, st)

    accepted_fns: set[int] = set()
    pairs = [e.pair for e in texts if pv._delta_pair(e, readings) is not None]
    deltas = pv._deltas(readings, pairs) if pairs else {}
    for e in texts:
        p = e.pair
        la = (bodies_a.get(p.addr_a) or {}).get("pseudocode")
        lb = (bodies_b.get(p.addr_b) or {}).get("pseudocode")
        if not la or not lb:
            raise _UnexplainedError("pair_differs_without_text", entry_id=e.entry_id)
        names = (
            p.name_a if p.name_a and not pv._is_synthetic_name(p.name_a, p.addr_a) else None,
            p.name_b if p.name_b and not pv._is_synthetic_name(p.name_b, p.addr_b) else None,
        )
        ok, why = entry_explained(
            la.splitlines(), lb.splitlines(), deltas.get((p.addr_a, p.addr_b)), sides, names
        )
        if ok is None:
            st.unknown_because(f"pair_not_read_as_sites:{e.entry_id}")
            st.unread_fns.add(int(p.addr_a, 16))
            continue
        if not ok:
            raise _UnexplainedError("pair_text_differs", entry_id=e.entry_id, why=why)
        if (e.callee_set or {}).get("state") != "equal":
            raise _UnexplainedError("callee_set_not_proven_equal", entry_id=e.entry_id)
        sa = (bodies_a.get(p.addr_a) or {}).get("size_bytes")
        sb = (bodies_b.get(p.addr_b) or {}).get("size_bytes")
        if sa is None or sb is None or sa != sb:
            raise _UnexplainedError("body_sizes_not_proven_equal", entry_id=e.entry_id)
        st.explained["line_number_or_version_pairs"] += 1
        accepted_fns.add(int(p.addr_a, 16))
    shifted = any(
        p.aligned and p.addr_a in bodies_a and p.addr_b in bodies_b and p.addr_a != p.addr_b
        for p in built.diff.pairs
    )
    _bytes(atlas, run_a, run_b, sha_a, sha_b, sides, bodies_a, accepted_fns, shifted, st)


def _same_name_stub(p: Any, entry_id: str, st: _State) -> None:
    if p.name_a and p.name_a == p.name_b:
        st.explained["same_name_stub_pairs"] += 1
        return
    raise _UnexplainedError("stub_pair_name_differs", entry_id=entry_id)


def _bytes_identical(
    p: Any,
    entry_id: str,
    state: str,
    bodies_a: sameness.Bodies,
    bodies_b: sameness.Bodies,
    sides: _Sides,
    st: _State,
) -> None:
    """A pair whose text could not prove it unchanged: explained only when its two stored bodies
    are byte-identical."""
    sa = (bodies_a.get(p.addr_a) or {}).get("size_bytes")
    sb = (bodies_b.get(p.addr_b) or {}).get("size_bytes")
    if sa is None or sb is None:
        st.unknown_because(f"body_size_unrecorded:{entry_id}")
        st.unread_fns.add(int(p.addr_a, 16))
        return
    if sa != sb:
        raise _UnexplainedError("body_sizes_differ", entry_id=entry_id, reading=state)
    xa = _read(sides.ia, int(p.addr_a, 16), sa)
    xb = _read(sides.ib, int(p.addr_b, 16), sb)
    if xa is None or xb is None:
        st.unknown_because(f"body_bytes_not_stored:{entry_id}")
        st.unread_fns.add(int(p.addr_a, 16))
        return
    if xa != xb:
        raise _UnexplainedError("body_bytes_differ", entry_id=entry_id, reading=state)
    st.explained["bytes_identical_pairs"] += 1


def _strings(
    atlas: sqlite3.Connection, run_a: str, run_b: str, sha_a: str, sha_b: str, st: _State
) -> None:
    """The one-sided string literals (patch_view's string_delta sets), paired by skeleton."""
    a_vals, a_trunc, _ra, a_err = pv._string_values_side(atlas, run_a, sha_a)
    b_vals, b_trunc, _rb, b_err = pv._string_values_side(atlas, run_b, sha_b)
    for side, err, trunc in (("a", a_err, a_trunc), ("b", b_err, b_trunc)):
        if err is not None:
            st.unknown_because(f"strings_unreadable:{side}")
        elif trunc != "clean":
            st.unknown_because(f"strings_{trunc}:{side}")
    a_only, b_only = sorted(a_vals - b_vals), sorted(b_vals - a_vals)
    by_key: dict[str, tuple[list[str], list[str]]] = {}
    for vals, k in ((a_only, 0), (b_only, 1)):
        for v in vals:
            sk, shapes = skeleton(v)
            by_key.setdefault(sk if shapes else "\0" + v, ([], []))[k].append(v)
    for _sk, (xa, xb) in sorted(by_key.items()):
        n = min(len(xa), len(xb))
        for va, vb in zip(xa[:n], xb[:n], strict=True):
            classes = string_pair_classes(va, vb)
            if classes is None:  # pragma: no cover - equal skeletons with a placeholder pair
                raise _UnexplainedError("one_sided_string", a=_q(va), b=_q(vb))
            st.explained[_string_kind(classes)] += 1
        if len(xa) > n:
            raise _UnexplainedError("one_sided_string", a=_q(xa[n]), b=None)
        if len(xb) > n:
            raise _UnexplainedError("one_sided_string", a=None, b=_q(xb[n]))


def _unaddressed_blocks(
    atlas: sqlite3.Connection, run: str, sha: str, img: entry_words.Image
) -> bool:
    """Whether the side exported a block this reading could not place (no parsable address)."""
    path, _ = pv._run_source(atlas, run)
    if path is None:
        return True
    try:
        conn = ro_connect(path)
    except sqlite3.Error:
        return True
    try:
        n = conn.execute(
            "SELECT COUNT(*) FROM data_blocks WHERE binary_id = ?", (img.binary_id,)
        ).fetchone()[0]
    except sqlite3.Error:
        return True
    finally:
        conn.close()
    return int(n) != len(img.blocks)


def _bytes(
    atlas: sqlite3.Connection,
    run_a: str,
    run_b: str,
    sha_a: str,
    sha_b: str,
    sides: _Sides,
    bodies_a: sameness.Bodies,
    accepted_fns: set[int],
    shifted: bool,
    st: _State,
) -> None:
    """Every stored byte that differs, attributed — or the first one no rule attributes."""
    ia, ib = sides.ia, sides.ib
    if ia.unavailable or ib.unavailable:
        st.unknown_because(f"blocks_unreadable:{ia.unavailable or ib.unavailable}")
        return
    if not (ia.complete and ib.complete):  # bytes past a cut were never stored, so never compared
        st.unknown_because("data_blocks_truncated")
        return
    if _unaddressed_blocks(atlas, run_a, sha_a, ia) or _unaddressed_blocks(atlas, run_b, sha_b, ib):
        st.unknown_because("block_without_address")
        return
    names_a = Counter(b.name for b in ia.blocks)
    names_b = Counter(b.name for b in ib.blocks)
    if names_a != names_b:
        raise _UnexplainedError(
            "block_set_differs",
            a_only=sorted((names_a - names_b).elements())[:5],
            b_only=sorted((names_b - names_a).elements())[:5],
        )
    if any(v > 1 for v in names_a.values()):
        st.unknown_because("block_names_repeat")
        return
    bid_a, why_a = build_id_ranges(ia)
    bid_b, _why_b = build_id_ranges(ib)
    build_ids = bid_a & bid_b
    fns = sorted(
        (int(addr, 16), int(body.get("size_bytes") or 0)) for addr, body in bodies_a.items()
    )
    fn_starts = [s for s, _ in fns]
    str_starts = sorted(ia.strings)
    b_of = {b.name: b for b in ib.blocks}
    for x in ia.blocks:
        y = b_of[x.name]
        if (x.start, x.size, x.initialized, x.truncated) != (
            y.start,
            y.size,
            y.initialized,
            y.truncated,
        ):
            raise _UnexplainedError("block_layout_differs", block=x.name)
        if not x.initialized:
            continue
        runs = _differing_runs(x.data, y.data)
        if len(x.data) != len(y.data):
            raise _UnexplainedError("block_layout_differs", block=x.name)
        if runs and x.executable and shifted:
            raise _UnexplainedError("code_moved_bytes_unattributed", block=x.name)
        for off, ln in runs:
            va = x.start + off
            end = va + ln
            if any(d0 <= va and end <= d0 + dn for d0, dn in build_ids):
                st.explained["build_id_bytes"] += 1
                continue
            k = bisect.bisect_right(str_starts, va) - 1
            if k >= 0:
                s0 = str_starts[k]
                s_a = ia.strings[s0]
                if end <= s0 + len(s_a.encode(errors="replace")) + 1:
                    s_b = ib.strings.get(s0)
                    classes = string_pair_classes(s_a, s_b) if s_b is not None else None
                    if classes:
                        st.explained["string_bytes"] += 1
                        continue
                    raise _UnexplainedError("bytes_in_string", addr=hex(va), a=_q(s_a), b=_q(s_b))
            j = bisect.bisect_right(fn_starts, va) - 1
            if j >= 0 and va < fns[j][0] + max(fns[j][1], 1):
                if fns[j][0] in accepted_fns and end <= fns[j][0] + fns[j][1]:
                    st.explained["function_bytes"] += 1
                    continue
                if fns[j][0] in st.unread_fns:
                    st.unknown_because("bytes_in_unread_function")
                    continue
                raise _UnexplainedError("bytes_in_function", addr=hex(va), function=hex(fns[j][0]))
            ctx_a, ctx_b = _ctx_string(x.data, off, ln), _ctx_string(y.data, off, ln)
            if ctx_a is not None and ctx_b is not None:
                classes = string_pair_classes(ctx_a, ctx_b)
                if classes:
                    st.explained["string_bytes"] += 1
                    continue
            raise _UnexplainedError(
                "bytes_other",
                addr=hex(va),
                block=x.name,
                build_id_lookup=why_a,
                a=x.data[off : off + min(ln, 16)].hex(),
                b=y.data[off : off + min(ln, 16)].hex(),
            )
