# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Signals a BinDiff similarity score cannot carry: whether two paired functions are really the
same, and whether a sink call's length constant changed.

similarity is blind to immediates, constants and buffer sizes: a pair can read ``similarity=1.0``
while a bound was tightened or loosened. This module holds the facts the function patch view
(lib/query/patch_view) adds to close that gap, and NOTHING that judges them — direction and meaning
are the reader's:

  * ``pseudocode_sameness`` — an honest reading of an aligned pair, folding an address-normalised
    pseudocode comparison together with the callee-set state the view already computed.
    ``identical`` only when the text matches with nothing left unverified AND the callees agree. A
    text match that rests on something this reading cannot check is ``identical_text_unverified``
    with its ``text_reasons``: a literal read as an address only because a side's image extent is
    unknown (``literal_basis_unknown``), a decompile the decompiler itself marked incomplete
    (``decompile_incomplete:<tag>``), or two bodies whose byte counts differ
    (``body_size_differs``). A text match whose callees could not be verified is
    ``identical_callee_unverified``. Neither is ever folded into "unchanged" or "changed". A changed
    callee set is ``differs`` even when there is no body to read. When there is no body, the reason
    is carried, not swallowed: ``no_body`` (an import / PLT stub absent from the functions table) is
    kept apart from ``unavailable`` (a function in the table whose pseudocode is empty), so a reader
    need not recompute which it was.
  * the same reading of an UNDETERMINED pair (``undetermined_pair_state``), as a proposal beside it,
    never a pairing: its seven states add whether the body is unique on both sides, since a body
    that occurs twice could have been paired with the wrong twin.
  * ``hidden_region`` — the facts behind a text match that may hide code (the decompiler's own
    warnings, with the address each names and whether it lies in the function's own body, and the
    two body byte counts). Facts only: ``body`` is ``structure_differs`` when the byte counts
    differ and ``unknown`` otherwise, never ``identical``.
  * ``pseudocode_delta`` — the lexical shape of a text difference (substitutions only, structural,
    layout only), and the calls whose counts differ. A shape, not a verdict.
  * the length-constant signals on a persisted candidate's two sides: ``const_delta`` when the same
    constant size kind holds a different value (0x40 -> 0x3f, and an off-by-one like 256 -> 255),
    and ``kind_shift`` when the size kind itself changed (const -> cap_const, const -> untraced). A
    kind change is never read as a value delta.

The address normalisation is defined once here (``skeleton`` + ``literal_reading``) so the "small
constants stay put" rule has a single home: synthetic-symbol address suffixes are blanked; the
addresses in a try/catch annotation are blanked only when every one of them moved by the pair's own
entry offset (``try_shift_consistent``), else the pair is read as it stands; a large hex literal is
compared position by position and read as an address only when the two values differ AND each lies
in its own side's image; small numeric constants are never touched — else a changed buffer size
would normalise away and the whole point would be lost.

BOUNDARIES: a constant whose two values differ but both happen to lie inside their images is still
read as an address (telling them apart needs data flow); the target a ``DAT_`` / ``PTR_`` name
refers to is not checked once its address is blanked (a string label keeps its content in the name,
so a changed string stays visible); a C++ catch handler (landing pad) usually lies outside every
function body, so its code is never decompiled and no reading compares it — a try/catch annotation
that moved with its function says nothing about the handler.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from difflib import SequenceMatcher
from typing import Any

from treasure_map.lib.diff.layer0 import _decompile_status, norm_hex
from treasure_map.lib.ro_db import ro_connect

# ── the six states of an aligned pair ────────────────────────────────────────────────────────

IDENTICAL = "identical"  # text matches with nothing unverified, callee sets equal: really unchanged
IDENTICAL_TEXT_UNVERIFIED = (
    "identical_text_unverified"  # text matches, but the match rests on something unchecked
)
IDENTICAL_CALLEE_UNVERIFIED = (
    "identical_callee_unverified"  # pseudocode matches, callees unverified
)
DIFFERS = "differs"  # pseudocode differs, or the callee sets differ (even with no body to read)
NO_BODY = "no_body"  # a side has no body at all — an import / PLT stub, not in the functions table
UNAVAILABLE = "unavailable"  # a side IS in the table but its pseudocode is empty, or the db failed

# ── one side's body CAUSE: finer than the pair states above, NOT a sameness state ─────────────
# Why a side had no text to compare, told apart so the read face can split the pair-level
# UNAVAILABLE by cause. The pair state stays NO_BODY / UNAVAILABLE (``sameness_state`` folds these
# back); these never enter the seven U_STATES or the aligned states. ``ok`` and ``no_body`` are
# reused from above; the four below name the ways a present body carried no pseudocode.
DB_UNAVAILABLE = "db_unavailable"  # the analysis.db could not be read at all (bodies is None)
SKIPPED_MICRO = "skipped_micro"  # empty AND under _DECOMPILE_MIN_SIZE: a design skip, not a failure
DECOMPILE_EMPTY = "decompile_empty"  # empty AND >= that size: a genuine empty decompile
SIZE_UNKNOWN = "size_unknown"  # empty AND size 0 / unrecorded: cannot be told apart

# The not_listed count name for each state (aligned, similarity-1 pairs that place no entry).
NOT_LISTED_NAME = {
    IDENTICAL: "aligned_pseudocode_identical",
    IDENTICAL_TEXT_UNVERIFIED: "aligned_pseudocode_identical_text_unverified",
    IDENTICAL_CALLEE_UNVERIFIED: "aligned_pseudocode_identical_callee_unverified",
    DIFFERS: "aligned_pseudocode_differs",
    NO_BODY: "aligned_pseudocode_no_body",
    UNAVAILABLE: "aligned_pseudocode_unavailable",
}
STATE_BY_NOT_LISTED_NAME = {name: state for state, name in NOT_LISTED_NAME.items()}

# ── the seven states of an undetermined pair's proposed reading ─────────────────────────────

U_IDENTICAL_UNIQUE = "identical_unique"
U_IDENTICAL_NOT_UNIQUE = "identical_not_unique"
U_IDENTICAL_CALLEE_UNVERIFIED = "identical_callee_unverified"
U_IDENTICAL_TEXT_UNVERIFIED = "identical_text_unverified"
U_DIFFERS = "differs"
U_NO_BODY = "no_body"
U_UNAVAILABLE = "unavailable"
U_STATES = (
    U_IDENTICAL_UNIQUE,
    U_IDENTICAL_NOT_UNIQUE,
    U_IDENTICAL_CALLEE_UNVERIFIED,
    U_IDENTICAL_TEXT_UNVERIFIED,
    U_DIFFERS,
    U_NO_BODY,
    U_UNAVAILABLE,
)

# ── why a text match is not "identical" (text_reasons) ──────────────────────────────────────

LITERAL_BASIS_UNKNOWN = "literal_basis_unknown"
DECOMPILE_INCOMPLETE = "decompile_incomplete"  # written decompile_incomplete:<tag>
BODY_SIZE_DIFFERS = "body_size_differs"

# hidden_region.body: the two byte counts differ, or nothing can be said. Never "identical": equal
# byte counts do not show an unchanged body.
BODY_STRUCTURE_DIFFERS = "structure_differs"
BODY_UNKNOWN = "unknown"
BODY_CLASSES = (BODY_STRUCTURE_DIFFERS, BODY_UNKNOWN)

# A side's function bodies: entry (normalised hex) -> {"pseudocode", "size_bytes", "body_ranges"}.
Body = dict[str, Any]
Bodies = dict[str, Body]
# Half-open [lo, hi) extents of a binary's memory blocks (data_blocks), or None when unknown.
ImageRanges = list[tuple[int, int]] | None

# ── address normalisation (single definition) ────────────────────────────────────────────────

# Ghidra's synthetic symbol names carry an absolute address after an underscore, at the END of the
# name (FUN_0040caf0, DAT_000200f8, s_hi_0001ccd0, LAB_/UNK_/SUB_), or as ``r0x<addr>`` (the branch
# labels joined_r0x00449e60 / code_r0x00449e60). Two identical functions in two binaries whose
# other code shifted read the same body with these addresses moved, so the address is blanked and
# the rest of the name kept. The threshold is six hex digits (>= 0x100000): a stack offset
# (auStack_1050) and a length constant (0x40 .. 0xfff) are far smaller and never touched — the
# "small constants stay put" rule that keeps a changed size visible to this reading and to
# const_delta alike.
#
# An address in the MIDDLE of a name is blanked for two label prefixes only, and only as exactly
# eight hex digits: the switch label switchD_004492cc_caseD_3 / switchD_<addr>_default and the
# numbered branch label LAB_0008f0a0_1. Any other hex-looking word inside a name is not an address
# — a real symbol (CRYPTO_cbc128_encrypt, AES_cfb128_encrypt), the content a string label spells out
# (s_0123456789abcdef_<addr>), a local's access offset (local._153920_4_) — and blanking it would
# read two different bodies as the same.
#
# BOUNDARY: a 64-bit image's address wider than eight digits is not blanked mid-name, so such a
# pair reads ``differs`` (the cautious direction). A name that is not a synthetic label but ENDS in
# a hex-looking word of six or more characters (foo_abcdef) is still blanked there.
_ADDR_SUFFIX = re.compile(
    r"_(?:r0x)?[0-9a-fA-F]{6,}\b"  # at the end of a name: FUN_ / DAT_ / s_..._ / joined_r0x
    r"|(?<=\bswitchD)_[0-9a-fA-F]{8}(?=_)"  # switchD_<addr>_caseD_n / switchD_<addr>_default
    r"|(?<=\bLAB)_[0-9a-fA-F]{8}(?=_)"  # LAB_<addr>_<n>
)
# A large hex literal (an absolute address, a GOT offset — or a large constant), same six-digit
# floor. Never blanked outright: literal_reading compares the values position by position.
_HEX6 = re.compile(r"\b0x[0-9a-fA-F]{6,}\b")
# Ghidra's try/catch annotation (``/* try { // try from 00406208 to 0040620f has its CatchHandler @
# 00406d84 */``) names code addresses as bare hex, which move whenever the code before them does.
# Only a comment holding ``try from`` is touched; every other comment and bare hex in the body is
# left as it is. The skeleton blanks them; a reading then keeps the match only when they all moved
# by the pair's own entry offset (try_shift_consistent).
_TRY_COMMENT = re.compile(r"/\*[^*]*?\btry from\b.*?\*/", re.S)
_BARE_HEX = re.compile(r"\b[0-9a-fA-F]{6,}\b")


def _blank_try_comment(text: str) -> str:
    return _TRY_COMMENT.sub(lambda m: _BARE_HEX.sub("@", m.group(0)), text)


def try_annotation_values(text: str) -> list[int]:
    """The addresses ``_blank_try_comment`` blanks in one body: every bare hex value inside a
    try/catch annotation, in the order they occur."""
    return [int(h, 16) for m in _TRY_COMMENT.finditer(text) for h in _BARE_HEX.findall(m.group(0))]


def try_shift_consistent(a: str, b: str, entry_a: int | None, entry_b: int | None) -> bool:
    """Whether the try/catch annotation addresses of two bodies are the same, or all moved by
    exactly the pair's entry offset (``entry_b - entry_a``) — a function that moved as a whole. An
    unknown entry proves no offset."""
    va, vb = try_annotation_values(a), try_annotation_values(b)
    if va == vb:
        return True
    if entry_a is None or entry_b is None:
        return False
    d = entry_b - entry_a
    return len(va) == len(vb) and all(y - x == d for x, y in zip(va, vb, strict=True))


def skeleton(text: str) -> tuple[str, list[int]]:
    """``(skeleton, literals)``: ``text`` with the try/catch annotation's addresses and the
    synthetic-symbol address suffixes blanked and every large hex literal replaced by ``0x#``, and
    those literals' values in the order they occur. Small numeric constants stay exactly as they
    are. The try/catch addresses are blanked unconditionally here (the skeleton keys a body's
    occurrences); a reading compares them by offset (try_shift_consistent)."""
    text = _blank_try_comment(text)
    text = _ADDR_SUFFIX.sub("_@", text)
    values: list[int] = []

    def one(m: re.Match[str]) -> str:
        values.append(int(m.group(0), 16))
        return "0x#"

    return _HEX6.sub(one, text), values


def skeleton_key(text: str) -> str:
    """A body's identity for counting where else it occurs: the hash of its skeleton TEXT alone
    (the large literals' values are left out, so a body whose addresses moved keeps its key)."""
    return hashlib.sha256(skeleton(text)[0].encode()).hexdigest()


def _hex_int(text: object) -> int | None:
    """An address string read as HEX, bare or ``0x``-prefixed (as lib/facts reads one); None when it
    is not one."""
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        return int(text.strip().lower().removeprefix("0x"), 16)
    except ValueError:
        return None


def _in_image(value: int, ranges: ImageRanges) -> bool:
    """Whether ``value`` lies in one of a side's half-open block extents; True when the extents are
    unknown (the caller records that it relied on that)."""
    return ranges is None or any(lo <= value < hi for lo, hi in ranges)


def literal_reading(
    a: str, b: str, ranges_a: ImageRanges, ranges_b: ImageRanges
) -> tuple[bool, bool]:
    """``(equal, relied_on_unknown_basis)`` of two bodies. Equal only when the skeletons match, the
    literal counts match, and at every position the two values are the same — or differ with each
    value inside its own side's image, i.e. an address that moved. A value the same on both sides
    is never looked up (an unchanged constant is not an address question). ``relied`` is True when
    a position was read as an address only because a side's image is unknown."""
    sa, va = skeleton(a)
    sb, vb = skeleton(b)
    if sa != sb or len(va) != len(vb):
        return (False, False)
    relied = False
    for x, y in zip(va, vb, strict=True):
        if x == y:
            continue
        if not (_in_image(x, ranges_a) and _in_image(y, ranges_b)):
            return (False, False)
        if ranges_a is None or ranges_b is None:
            relied = True
    return (True, relied)


# ── decompile-incomplete markers (W) ─────────────────────────────────────────────────────────

# The decompiler's own notes that what it printed is not the whole function. Matched on the raw
# text (before any normalisation); a hit on either side keeps a text match from reading
# ``identical``. Not listed, measured not to hide code: "Heritage AFTER dead removal", "Load size is
# inaccurate", "Do nothing block with infinite loop".
W_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "jumptable",
        re.compile(r"Could not recover jumptable|Could not find normalized switch variable"),
    ),
    ("bad_instruction", re.compile(r"Bad instruction - Truncating control flow here")),
    (
        "bad_instruction_data",
        re.compile(r"Control flow encountered bad instruction data|halt_baddata\("),
    ),
    ("unreachable_block_removed", re.compile(r"Removing unreachable block")),
    ("indirect_jump_as_call", re.compile(r"Treating indirect jump as call")),
    ("switch_destination_removed", re.compile(r"Switch with \d+ destination removed")),
    ("indirect_partially_resolved", re.compile(r"Ignoring partial resolution of indirect")),
    ("decompile_restarts_exceeded", re.compile(r"Exceeded maximum restarts")),
)
_MARKER_ADDR = re.compile(r"0x[0-9a-fA-F]+")


def _markers(text: str) -> list[tuple[int, str, str | None]]:
    """``(position, tag, address)`` of every W marker in one raw body, in text order. The address is
    the first ``0x`` literal after the marker on its own line, inside its comment
    (``... jumptable at 0x00408218`` / ``block (ram,0x00409860)``); None when it names none."""
    out: list[tuple[int, str, str | None]] = []
    for tag, pattern in W_MARKERS:
        for m in pattern.finditer(text):
            end = len(text)
            for stop in ("\n", "*/"):
                i = text.find(stop, m.end())
                if i != -1:
                    end = min(end, i)
            found = _MARKER_ADDR.search(text, m.end(), end)
            out.append((m.start(), tag, found.group(0).lower() if found else None))
    return sorted(out)


def incomplete_tags(a: str, b: str) -> list[str]:
    """The W tags found in either raw body, in W_MARKERS order."""
    return [tag for tag, pattern in W_MARKERS if pattern.search(a) or pattern.search(b)]


# ── a body's byte count and extents ──────────────────────────────────────────────────────────


def _size(body: Body) -> int | None:
    value = body.get("size_bytes")
    return value if isinstance(value, int) else None


def body_key(size_a: int | None, size_b: int | None) -> str:
    """hidden_region.body: ``structure_differs`` when both byte counts are known and differ, else
    ``unknown`` — never ``identical`` (equal counts do not show an unchanged body)."""
    if size_a is not None and size_b is not None and size_a != size_b:
        return BODY_STRUCTURE_DIFFERS
    return BODY_UNKNOWN


def _in_own_body(addr: str | None, ranges: list[list[int]]) -> bool | None:
    """Whether a marker's address lies in the function's own body (CLOSED ranges: Ghidra's
    AddressRange includes its max). None when the marker names no address or the body records no
    ranges."""
    n = _hex_int(addr)
    if n is None or not ranges:
        return None
    return any(lo <= n <= hi for lo, hi in ranges)


def _body_status(bodies: Bodies | None, addr: str) -> str:
    """One side's body CAUSE at ``addr`` (see the DB_UNAVAILABLE / SKIPPED_MICRO / … constants):
    ``ok`` (there is pseudocode to compare), ``no_body`` (absent from the table — an import / PLT
    stub), ``db_unavailable`` (the analysis.db could not be read), or, for a present-but-empty body,
    the exporter's own reason via ``layer0._decompile_status`` — ``skipped_micro`` (a design skip),
    ``decompile_empty`` (a real empty decompile) or ``size_unknown`` (size 0 / unrecorded). The
    pair-level state (``sameness_state``) still folds these back to NO_BODY / UNAVAILABLE; the cause
    is a read-face detail, never a verdict."""
    if bodies is None:
        return DB_UNAVAILABLE
    if addr not in bodies:
        return NO_BODY
    body = bodies[addr] or {}
    if body.get("pseudocode"):
        return "ok"
    # pseudocode empty by the branch above; classify the empty body by the exporter's own reason.
    status = _decompile_status(None, _size(body))
    return {"failed": DECOMPILE_EMPTY, "unknown": SIZE_UNKNOWN}.get(status, status)


def pair_reading(
    a_bodies: Bodies | None,
    b_bodies: Bodies | None,
    addr_a: str,
    addr_b: str,
    ranges_a: ImageRanges,
    ranges_b: ImageRanges,
) -> tuple[bool | None, str | None, tuple[str, ...], dict[str, Any] | None]:
    """``(matches, reason, text_reasons, bodies)`` for one pair: ``matches`` True / False (reason
    None) when both sides have a body to compare; else ``matches`` None with the reason a reader
    would otherwise have to recompute — ``no_body`` when a side is an import / PLT stub, else
    ``unavailable`` (``no_body`` wins when both apply, so a stub pair is named as one). Two texts
    that match only because their try/catch annotation addresses were blanked match only when those
    addresses all moved by the pair's entry offset; else the pair differs, as read.

    ``text_reasons`` qualify a MATCH (empty otherwise — a text that differs is a difference, and a
    warning does not change that): ``literal_basis_unknown``, ``decompile_incomplete:<tag>`` for
    each W tag on either side, and ``body_size_differs`` when both byte counts are known and
    differ (a count missing on a side adds nothing and infers nothing).

    ``bodies`` is populated ONLY on the no-text-to-compare branch (one side not ``ok``), None
    otherwise: ``{a, b}`` with each side's finer body ``status`` (:func:`_body_status`) and its
    ``size_bytes``, so the read face can split the pair-level UNAVAILABLE by cause and tell a
    design-skipped micro-stub from a real decompile gap. It adds no fact and changes no state."""
    sa, sb = _body_status(a_bodies, addr_a), _body_status(b_bodies, addr_b)
    if sa != "ok" or sb != "ok":
        bodies = {
            "a": {"status": sa, "size_bytes": _size((a_bodies or {}).get(addr_a) or {})},
            "b": {"status": sb, "size_bytes": _size((b_bodies or {}).get(addr_b) or {})},
        }
        return (None, NO_BODY if NO_BODY in (sa, sb) else UNAVAILABLE, (), bodies)
    ba, bb = (a_bodies or {})[addr_a], (b_bodies or {})[addr_b]
    pa, pb = ba.get("pseudocode") or "", bb.get("pseudocode") or ""
    equal, relied = literal_reading(pa, pb, ranges_a, ranges_b)
    if not equal:
        return (False, None, (), None)
    if not try_shift_consistent(pa, pb, _hex_int(addr_a), _hex_int(addr_b)):
        return (False, None, (), None)
    reasons: list[str] = [LITERAL_BASIS_UNKNOWN] if relied else []
    reasons += [f"{DECOMPILE_INCOMPLETE}:{tag}" for tag in incomplete_tags(pa, pb)]
    if body_key(_size(ba), _size(bb)) == BODY_STRUCTURE_DIFFERS:
        reasons.append(BODY_SIZE_DIFFERS)
    return (True, None, tuple(reasons), None)


def sameness_state(
    matches: bool | None,
    callee_state: str | None,
    reason: str | None,
    text_reasons: tuple[str, ...] | list[str],
) -> str:
    """Fold a pseudocode reading and the pair's callee-set state into one of the six states. A
    changed callee set is proof of change even with no body to read (so ``differs`` wins over a
    missing body); a match is ``identical`` only when nothing qualifies the text AND the callees
    are proven equal, else unverified — never silently "unchanged". When there is no body and
    nothing proves a change, the reason stands as the state (``no_body`` / ``unavailable``)."""
    if callee_state == "differs":
        return DIFFERS  # a changed call set is proof of change, even with no body to read
    if matches is None:
        return reason or UNAVAILABLE
    if not matches:
        return DIFFERS
    if text_reasons:
        return IDENTICAL_TEXT_UNVERIFIED
    if callee_state == "equal":
        return IDENTICAL
    return (
        IDENTICAL_CALLEE_UNVERIFIED  # undetermined (or no callee reading): unverified, not "same"
    )


def undetermined_pair_state(
    matches: bool | None,
    callee_state: str | None,
    reason: str | None,
    text_reasons: tuple[str, ...] | list[str],
    occurrences: dict[str, int] | None,
) -> str:
    """The proposed reading of an UNDETERMINED pair, in the order: a changed callee set, a missing
    body, a text difference, a qualified text match, unverified callees, then uniqueness — a body
    found more than once on either side (``occurrences``) is ``identical_not_unique``, since its
    pairing could have taken the wrong twin; ``identical_unique`` needs exactly one on each side.
    No occurrence count proves nothing unique."""
    if callee_state == "differs":
        return U_DIFFERS
    if matches is None:
        return U_NO_BODY if reason == NO_BODY else U_UNAVAILABLE
    if not matches:
        return U_DIFFERS
    if text_reasons:
        return U_IDENTICAL_TEXT_UNVERIFIED
    if callee_state != "equal":
        return U_IDENTICAL_CALLEE_UNVERIFIED
    if occurrences is None or occurrences.get("a") != 1 or occurrences.get("b") != 1:
        return U_IDENTICAL_NOT_UNIQUE
    return U_IDENTICAL_UNIQUE


def text_unverified_body(text_reasons: tuple[str, ...] | list[str]) -> str:
    """The ``body`` class a qualified text match is filtered and counted by: ``structure_differs``
    when its byte counts differ, else ``unknown``."""
    return BODY_STRUCTURE_DIFFERS if BODY_SIZE_DIFFERS in text_reasons else BODY_UNKNOWN


def hidden_region(
    a: Body,
    b: Body,
    text_reasons: tuple[str, ...] | list[str],
    *,
    similarity: float | None,
    instructions: int | None,
) -> dict[str, Any] | None:
    """The facts behind a text match that may hide code, or None when the match carries no W marker
    and no ``body_size_differs``. Each marker with the address its warning names and whether that
    address lies in the side's own body; ``body`` from the byte counts (never ``identical``); the
    two byte counts, BinDiff's matched-instruction count and similarity as they are stored — no
    flag derived from them, nothing compared; how often each text still says
    UNRECOVERED_JUMPTABLE."""
    hit = BODY_SIZE_DIFFERS in text_reasons or any(
        r.startswith(f"{DECOMPILE_INCOMPLETE}:") for r in text_reasons
    )
    if not hit:
        return None
    markers: list[dict[str, Any]] = []
    for side, body in (("a", a), ("b", b)):
        ranges = body.get("body_ranges") or []
        for _pos, tag, addr in _markers(body.get("pseudocode") or ""):
            markers.append(
                {"tag": tag, "addr": addr, "side": side, "in_own_body": _in_own_body(addr, ranges)}
            )
    size_a, size_b = _size(a), _size(b)
    return {
        "markers": markers,
        "body": body_key(size_a, size_b),
        "size_bytes": {"a": size_a, "b": size_b},
        "bindiff_matched_instructions": instructions,
        "similarity": similarity,
        "unrecovered_jumptable_refs": {
            "a": (a.get("pseudocode") or "").count("UNRECOVERED_JUMPTABLE"),
            "b": (b.get("pseudocode") or "").count("UNRECOVERED_JUMPTABLE"),
        },
    }


# ── the lexical shape of a text difference (pseudocode_delta) ────────────────────────────────

# The matcher's cost grows with the PRODUCT of the two sides, not with either side alone: a line
# cap of 20,000 per side let one wholly rewritten dispatcher take minutes. Measured on a real
# 8,000-line function: rewritten whole, a changed block of 58M token pairs took 2.8s, 249M took
# 8.2s, 977M took 32s; with every 7th line changed, the LINE match alone (64M line pairs, the
# repeated lines of real code being what makes it slow) took 7.9s. So both matchers are bounded
# by the product, and a function whose delta would exceed either bound is not_computed
# (too_large) as a whole — a half-analysed delta would misstate its own kind.
# Caps on the line-level match and on the token-level matches. Both run difflib's O(n*m)
# get_opcodes, a single uninterruptible call, so the product is the only lever — a wall-clock
# budget checked afterwards cannot preempt it. The token cap is ONE budget for the whole delta,
# each changed block's product drawn from it: a per-block cap let many blocks, each just under
# it, add up to a time no single block could reach. The worst-case time is strongly content- and
# machine-dependent (duplicate-heavy bodies blow difflib's matching up), and the previous 25M
# line cap was measured in the tens of seconds on a real firmware function, so both are kept
# conservative rather than tied to a promised time.
DELTA_LINE_PRODUCT_CAP = 5_000_000  # line pairs for the line-level match
DELTA_TOKEN_PRODUCT_CAP = 5_000_000  # token pairs summed over every changed block
_DELTA_FIRST = 5  # substitution pairs shown per token kind

_TOK = re.compile(
    r"""
   (?P<comment>/\*.*?\*/|//[^\n]*)
  |(?P<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')
  |(?P<number>0x[0-9a-fA-F@#]+[uUlL]*|\d+[uUlL]*)
  |(?P<ident>[A-Za-z_@#][A-Za-z0-9_@#]*)
  |(?P<punct>->|<<=|>>=|\+\+|--|<<|>>|<=|>=|==|!=|&&|\|\||[+\-*/%&|^!~<>=]=?|[^\s])
""",
    re.S | re.X,
)
_CALL_KEYWORDS = {
    "if",
    "else",
    "while",
    "for",
    "do",
    "switch",
    "case",
    "return",
    "goto",
    "sizeof",
    "break",
    "continue",
    "default",
}


def _delta_text(text: str, ranges: ImageRanges, blank_try: bool) -> str:
    """The skeleton a delta reads: as ``skeleton``, except that a large literal outside its own
    side's image keeps its value — a changed large constant shows as a substitution instead of
    vanishing into ``0x#`` — and that the try/catch annotation's addresses are blanked only when
    ``blank_try`` (they moved by the pair's entry offset, as the reading requires). Unknown extents
    read every literal as an address, as the match does."""
    text = _ADDR_SUFFIX.sub("_@", _blank_try_comment(text) if blank_try else text)
    return _HEX6.sub(
        lambda m: "0x#" if _in_image(int(m.group(0), 16), ranges) else m.group(0), text
    )


def _tokens(text: str) -> list[tuple[str, str]]:
    return [(m.lastgroup or "punct", m.group(0)) for m in _TOK.finditer(text)]


def _calls(tokens: list[tuple[str, str]]) -> dict[str, int]:
    """Call counts by callee name, after the body's first ``{``: an identifier directly followed by
    ``(``, keywords excluded, a name holding a blanked address counted as ``unnamed``. A call
    through a function pointer (``(*p)(...)``) is not counted."""
    counts: dict[str, int] = {}
    try:
        start = tokens.index(("punct", "{")) + 1
    except ValueError:
        return counts
    for (kind, text), nxt in zip(tokens[start:], tokens[start + 1 :], strict=False):
        if kind != "ident" or nxt != ("punct", "(") or text in _CALL_KEYWORDS:
            continue
        name = "unnamed" if ("@" in text or "#" in text) else text
        counts[name] = counts.get(name, 0) + 1
    return counts


def pseudocode_delta(
    a: str,
    b: str,
    ranges_a: ImageRanges,
    ranges_b: ImageRanges,
    addr_a: str,
    addr_b: str,
    name_a: str | None = None,
    name_b: str | None = None,
) -> dict[str, Any]:
    """The lexical shape of how two bodies' texts differ. Lines (stripped, blank lines dropped) are
    matched first; inside each block that differs, tokens are. A same-length run of tokens each of
    the same non-punctuation kind is a SUBSTITUTION (recorded by kind, with the first few pairs);
    anything else is a structural span. ``kind``: ``structural`` (any structural span),
    ``substitution_only``, or ``layout_only`` (the token streams agree — only spacing or line
    breaks differ); ``not_computed`` (``too_large``) above the product caps. ``calls`` lists
    the callees whose call counts differ. A shape, never a verdict: a number-only substitution is
    exactly what a size fix looks like, and nothing here ranks or files it. The try/catch
    annotation's addresses are blanked under the reading's own rule (``addr_a`` / ``addr_b`` are
    the pair's entries): when they did not all move by the entry offset, the changed annotation is
    a ``comment`` substitution, never ``layout_only``.

    ``name_a`` / ``name_b`` are the two sides' own function names, already stripped of synthetic
    names by the caller (a FUN_/loc_ name is passed as None). When they are given and the shape is
    ``substitution_only``, :func:`_line_number_form` adds ``line_number_form`` ``{delta, sites}``
    iff every changed number is a ``__FILE__``/``__LINE__`` build-info argument that shifted by one
    constant step. A shape, still never a verdict — it says the numbers look like line numbers, not
    that nothing else changed; the read face uses it only to DEMOTE such a pair out of the
    read-first head, never to clear it."""
    blank_try = try_shift_consistent(a, b, _hex_int(addr_a), _hex_int(addr_b))
    la = [ln.strip() for ln in _delta_text(a, ranges_a, blank_try).splitlines() if ln.strip()]
    lb = [ln.strip() for ln in _delta_text(b, ranges_b, blank_try).splitlines() if ln.strip()]
    too_large = {"kind": "not_computed", "reason": "too_large"}
    if len(la) * len(lb) > DELTA_LINE_PRODUCT_CAP:
        return too_large
    spans = 0
    token_pairs = 0  # drawn from the one DELTA_TOKEN_PRODUCT_CAP budget, block by block
    subs: dict[str, dict[str, Any]] = {}
    lines = SequenceMatcher(None, la, lb, autojunk=False)
    for op, i1, i2, j1, j2 in lines.get_opcodes():
        if op == "equal":
            continue
        ta, tb = _tokens("\n".join(la[i1:i2])), _tokens("\n".join(lb[j1:j2]))
        token_pairs += len(ta) * len(tb)
        if token_pairs > DELTA_TOKEN_PRODUCT_CAP:
            return too_large
        toks = SequenceMatcher(None, [t[1] for t in ta], [t[1] for t in tb], autojunk=False)
        for top, k1, k2, m1, m2 in toks.get_opcodes():
            if top == "equal":
                continue
            run_a, run_b = ta[k1:k2], tb[m1:m2]
            if (
                top == "replace"
                and len(run_a) == len(run_b)
                and all(x[0] == y[0] != "punct" for x, y in zip(run_a, run_b, strict=True))
            ):
                for x, y in zip(run_a, run_b, strict=True):
                    entry = subs.setdefault(x[0], {"total": 0, "first": []})
                    entry["total"] += 1
                    if len(entry["first"]) < _DELTA_FIRST:
                        entry["first"].append([x[1], y[1]])
            else:
                spans += 1
    ca = _calls(_tokens("\n".join(la)))
    cb = _calls(_tokens("\n".join(lb)))
    calls = {
        name: {"a": ca.get(name, 0), "b": cb.get(name, 0)}
        for name in sorted(set(ca) | set(cb))
        if ca.get(name, 0) != cb.get(name, 0)
    }
    kind = "structural" if spans else ("substitution_only" if subs else "layout_only")
    out: dict[str, Any] = {
        "kind": kind,
        "structural_spans": spans,
        "substitutions": dict(sorted(subs.items())),
        "calls": calls,
    }
    if kind == "substitution_only":
        lnf = _line_number_form(la, lb, name_a, name_b)
        if lnf is not None:
            out["line_number_form"] = lnf
    return out


# ── line-number form: a __FILE__/__LINE__ shift, told apart from a real substitution ─────────

_SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".h")


def _parse_int_token(text: str) -> int | None:
    """A number token's integer value — decimal or ``0x`` hex, a trailing u/U/l/L dropped; None when
    it carries a blanked address marker (``@`` / ``#``) or does not parse."""
    t = text.strip().rstrip("uUlL")
    if not t or "@" in t or "#" in t:
        return None
    try:
        return int(t, 16) if t[:2].lower() == "0x" else int(t, 10)
    except ValueError:
        return None


def _dequote(text: str) -> str:
    """A string token's content, outer quotes dropped (the token keeps them)."""
    return text[1:-1] if len(text) >= 2 and text[0] in "\"'" else text


def _is_source_path(s: str) -> bool:
    return s.lower().endswith(_SOURCE_SUFFIXES)


def _preceding_string_arg(toks: list[tuple[str, str]], idx: int) -> str | None:
    """The dequoted string literal that is the call argument immediately before ``toks[idx]``, when
    ``toks[idx]`` is ALONE a top-level argument of a call (a callee identifier, then ``(``) and the
    argument before it is exactly one string token; else None. The walk back to the call's ``(``
    stops at ``;`` ``{`` ``}`` (statement bounds), so a bare number not inside a call is rejected.
    Only ``()`` drive the enclosing-call depth; ``[]`` / ``{}`` inside an argument stay opaque."""
    depth = 0
    open_paren = -1
    j = idx - 1
    while j >= 0:
        t = toks[j][1]
        if t in (";", "{", "}") and depth == 0:
            return None
        if t == ")":
            depth += 1
        elif t == "(":
            if depth == 0:
                open_paren = j
                break
            depth -= 1
        j -= 1
    if open_paren <= 0:
        return None
    callee = toks[open_paren - 1]
    if callee[0] != "ident" or callee[1] in _CALL_KEYWORDS:
        return None
    depth = 0
    close = -1
    for m in range(open_paren, len(toks)):
        t = toks[m][1]
        if t == "(":
            depth += 1
        elif t == ")":
            depth -= 1
            if depth == 0:
                close = m
                break
    if close < 0:
        return None
    args: list[list[int]] = [[]]
    depth = 0
    for m in range(open_paren + 1, close):
        t = toks[m][1]
        if t in ("(", "[", "{"):
            depth += 1
            args[-1].append(m)
        elif t in (")", "]", "}"):
            depth -= 1
            args[-1].append(m)
        elif t == "," and depth == 0:
            args.append([])
        else:
            args[-1].append(m)
    for ai, arg in enumerate(args):
        if arg == [idx]:
            if ai == 0:
                return None
            prev = args[ai - 1]
            if len(prev) == 1 and toks[prev[0]][0] == "string":
                return _dequote(toks[prev[0]][1])
            return None
    return None


def _line_number_form(
    la: list[str], lb: list[str], name_a: str | None, name_b: str | None
) -> dict[str, Any] | None:
    """``{delta, sites}`` when the ONLY difference between the two bodies is a set of numbers that
    each look like a ``__FILE__``/``__LINE__`` build-info argument shifted by one constant step,
    else None. Parsed on the WHOLE two-sided normalized text (a call may span lines) at token level:
    the alignment must be substitutions only, every substitution a number, every changed number a
    top-level call argument whose immediately preceding argument is a single string literal that is
    either a source-file path or that side's own function name, and every pair must shift by the
    same nonzero integer step. Any miss leaves the pair in the read-first head — the safe direction.
    A shape, not a verdict; it never asserts nothing else changed."""
    ta = _tokens("\n".join(la))
    tb = _tokens("\n".join(lb))
    if len(ta) * len(tb) > DELTA_TOKEN_PRODUCT_CAP:
        return None
    matcher = SequenceMatcher(None, [t[1] for t in ta], [t[1] for t in tb], autojunk=False)
    number_subs: list[tuple[int, int]] = []  # (index in ta, index in tb)
    for op, i1, i2, j1, j2 in matcher.get_opcodes():
        if op == "equal":
            continue
        run_a, run_b = ta[i1:i2], tb[j1:j2]
        if (
            op != "replace"
            or len(run_a) != len(run_b)
            or not all(x[0] == y[0] != "punct" for x, y in zip(run_a, run_b, strict=True))
        ):
            return None  # not a pure substitution over the whole text
        for off, (x, _y) in enumerate(zip(run_a, run_b, strict=True)):
            if x[0] != "number":
                return None  # a non-number substitution: not a line-number shape
            number_subs.append((i1 + off, j1 + off))
    if not number_subs:
        return None
    delta: int | None = None
    for ka, kb in number_subs:
        va, vb = _parse_int_token(ta[ka][1]), _parse_int_token(tb[kb][1])
        if va is None or vb is None:
            return None
        step = vb - va
        if step == 0 or (delta is not None and step != delta):
            return None
        delta = step
        sa = _preceding_string_arg(ta, ka)
        sb = _preceding_string_arg(tb, kb)
        if sa is None or sb is None:
            return None
        if not (_is_source_path(sa) or (name_a is not None and sa == name_a)):
            return None
        if not (_is_source_path(sb) or (name_b is not None and sb == name_b)):
            return None
    return {"delta": delta, "sites": len(number_subs)}


# ── reading a run's analysis.db ──────────────────────────────────────────────────────────────


def _closed_ranges(raw: Any) -> list[list[int]]:
    """``body_ranges`` (JSON ``[["0x<lo>","0x<hi>"], ...]``, closed) as integer pairs; ``[]`` when
    absent or unreadable."""
    try:
        data = json.loads(raw) if isinstance(raw, str) else None
    except ValueError:
        return []
    out: list[list[int]] = []
    for item in data if isinstance(data, list) else []:
        if isinstance(item, list) and len(item) == 2:
            lo, hi = _hex_int(item[0]), _hex_int(item[1])
            if lo is not None and hi is not None:
                out.append([lo, hi])
    return out


def read_function_bodies(analysis_db_path: str | None, sha: str | None) -> Bodies | None:
    """function entry (normalised hex) -> ``{"pseudocode", "size_bytes", "body_ranges"}`` for one
    diffed binary, read in one pass from the run's own analysis.db (read-only). EVERY function the
    table holds is a key — so a key's absence means the function is not in the table at all (an
    import / PLT stub), told apart from a present-but-empty body (``pseudocode`` None).
    ``size_bytes`` is None when not recorded — the ingest writes 0 for an export that carried no
    size, and no function body holds zero addresses; ``body_ranges`` is ``[]`` when not recorded.
    None when the db or binary cannot be read."""
    if not analysis_db_path or not sha:
        return None
    try:
        conn = ro_connect(analysis_db_path)
    except sqlite3.Error:
        return None
    try:
        found = conn.execute("SELECT id FROM binaries WHERE sha256 = ?", (sha,)).fetchone()
        if found is None:
            return None
        cols = {r[1] for r in conn.execute("PRAGMA table_info(functions)")}
        select = "SELECT address, pseudocode"
        select += ", size_bytes" if "size_bytes" in cols else ", NULL"
        select += ", body_ranges" if "body_ranges" in cols else ", NULL"
        rows = conn.execute(select + " FROM functions WHERE binary_id = ?", (found[0],)).fetchall()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    out: Bodies = {}
    for address, pseudocode, size, ranges in rows:
        addr = norm_hex(address) if address else None
        if addr is not None:
            out[addr] = {
                "pseudocode": pseudocode or None,
                "size_bytes": size if isinstance(size, int) and size > 0 else None,
                "body_ranges": _closed_ranges(ranges),
            }
    return out


def read_image_ranges(analysis_db_path: str | None, sha: str | None) -> ImageRanges:
    """The binary's memory-block extents (``data_blocks``: code and data alike), each half-open
    ``[start, start + size)``, read-only. None — unknown, never "no image" — when the binary has no
    block rows, the table is absent, or the read fails."""
    if not analysis_db_path or not sha:
        return None
    try:
        conn = ro_connect(analysis_db_path)
    except sqlite3.Error:
        return None
    try:
        found = conn.execute("SELECT id FROM binaries WHERE sha256 = ?", (sha,)).fetchone()
        if found is None:
            return None
        rows = conn.execute(
            "SELECT start_addr, size FROM data_blocks WHERE binary_id = ?", (found[0],)
        ).fetchall()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    out: list[tuple[int, int]] = []
    for start, size in rows:
        lo = _hex_int(start)
        if lo is not None and isinstance(size, int) and size > 0:
            out.append((lo, lo + size))
    return out or None


# ── the length-constant signals (size evidence of a copy / buffer-formatter candidate) ───────

# The size kinds that carry a readable constant (lib/reachability/copy_size): a raw copy length, a
# formatter's cap, a strncat append amount. Only these are compared as numbers. A candidate's
# (size_kind, size_arg) is read from its flow_evidence by the caller (patch_view extracts them in
# SQL); ``size_kind`` is None for a candidate with no size axis (a command / format-string one).
CONST_SIZE_KINDS = ("const", "cap_const", "append_const")


def _as_int(text: object) -> int | None:
    """A length expression as a number: a string parsed base-0 (``0x40`` / ``64``), an int as it
    is; anything else (a variable name, a non-literal) is None."""
    if isinstance(text, bool):
        return None
    if isinstance(text, int):
        return text
    if not isinstance(text, str):
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def const_delta(
    a_kind: str | None, a_arg: str | None, b_kind: str | None, b_arg: str | None
) -> dict[str, Any] | None:
    """A changed length constant between a candidate's two sides: the SAME constant size kind
    holding a different value (0x40 -> 0x3f, 256 -> 255). None when either side is not constant, the
    kinds differ (that is a kind shift, not a value delta), a value cannot be parsed, or they are
    equal. Direction-neutral and never "±1 is noise": an off-by-one IS a real delta, so the exact
    off-by-one fixes this signal exists to surface are not filtered out."""
    if a_kind not in CONST_SIZE_KINDS or a_kind != b_kind:
        return None
    a_val, b_val = _as_int(a_arg), _as_int(b_arg)
    if a_val is None or b_val is None or a_val == b_val:
        return None
    return {"size_kind": a_kind, "from": a_arg, "to": b_arg}


def kind_shift(a_kind: str | None, b_kind: str | None) -> dict[str, Any] | None:
    """A weaker hint: the size KIND itself changed between the two sides (const -> cap_const,
    const -> untraced), with both sides carrying a size axis. Never a value delta — a kind change
    is reported here, not as a changed constant. None when a side has no size axis or the kinds
    agree."""
    if a_kind is None or b_kind is None or a_kind == b_kind:
        return None
    return {"from_kind": a_kind, "to_kind": b_kind}
