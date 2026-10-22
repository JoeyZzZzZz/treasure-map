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
    layout only), and the calls whose counts differ, plus ``inline_hunk``: the changed blocks
    themselves, aligned on the normalised text but SHOWN from the original text, with a few lines of
    context, and the substitutions grouped one line each — or why they are withheld. A shape, not a
    verdict.
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
from collections import Counter
from difflib import SequenceMatcher
from itertools import zip_longest
from typing import Any, NamedTuple

from treasure_map.lib.diff.layer0 import _decompile_status, norm_hex
from treasure_map.lib.facts import listing_items
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
    read-first head, never to clear it.

    ``inline_hunk`` (:func:`_inline_hunk`) is the one field added on top, LAST, and never changes
    another: every other field is what it was before the hunk existed. It is omitted when there is
    nothing to show (``layout_only``); a ``not_computed`` delta still carries one when the changed
    middle, once the identical leading and trailing lines are set aside, fits the line cap
    (:func:`_trimmed_hunk`).

    The same pass also reads the comparisons the change introduces:
    :func:`pseudocode_delta_and_guards` returns them beside this delta, which they never enter."""
    return pseudocode_delta_and_guards(a, b, ranges_a, ranges_b, addr_a, addr_b, name_a, name_b)[0]


def pseudocode_delta_and_guards(
    a: str,
    b: str,
    ranges_a: ImageRanges,
    ranges_b: ImageRanges,
    addr_a: str,
    addr_b: str,
    name_a: str | None = None,
    name_b: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """(``pseudocode_delta``, the guard scan) of two bodies, from ONE line match and one block
    match: the delta is byte for byte what :func:`pseudocode_delta` returns, and the guard scan
    (:func:`_guard_scan`) is a separate object that never enters it and holds no block position.

    The scan is ``not_extracted`` (``too_large``) exactly when no block match was made: a body over
    the token cap, or a too-large body whose changed middle is itself over a cap. When the middle
    of a too-large body was matched, the scan reads that middle's blocks (its lines mapped back past
    the identical head). A hunk withheld by the gate does not affect it: the blocks were matched."""
    blank_try = try_shift_consistent(a, b, _hex_int(addr_a), _hex_int(addr_b))
    la, ra, na = _delta_lines(a, ranges_a, blank_try)
    lb, rb, nb = _delta_lines(b, ranges_b, blank_try)
    sides = _Sides(ra, na, rb, nb)
    too_large: dict[str, Any] = {"kind": "not_computed", "reason": "too_large"}
    if len(la) * len(lb) > DELTA_LINE_PRODUCT_CAP:
        middle = _middle_blocks(la, lb)
        p, _ma, _mb, mid_blocks = middle
        scan = (
            _guard_scan(mid_blocks, p, la, lb, sides)
            if mid_blocks is not None
            else dict(_GUARDS_TOO_LARGE)
        )
        return _with_hunk(too_large, _trimmed_hunk(la, lb, sides, middle)), scan
    blocks = _delta_blocks(la, lb)
    if blocks is None:
        # The TOKEN cap was hit over the whole body. Trimming the identical head and tail and
        # re-matching the middle would, in practice, hit the same cap again — the middle is almost
        # the whole body — at up to twice the cost, so withhold straight away with the middle's
        # line counts, the same shape _trimmed_hunk returns when its own middle is over a cap.
        _p, _s, ma, mb = _trim(la, lb)
        hunk = {
            "withheld": "too_large",
            "lines": {"a": len(ma), "b": len(mb)},
            "read_with": _READ_WITH,
        }
        return _with_hunk(too_large, hunk), dict(_GUARDS_TOO_LARGE)
    spans = 0
    subs: dict[str, dict[str, Any]] = {}
    for blk in blocks:
        spans += blk.spans
        for k, m in blk.subs:
            x, y = blk.ta[k], blk.tb[m]
            entry = subs.setdefault(x[0], {"total": 0, "first": []})
            entry["total"] += 1
            if len(entry["first"]) < _DELTA_FIRST:
                entry["first"].append([x[1], y[1]])
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
    delta = _with_hunk(out, _inline_hunk(blocks, 0, len(la), len(lb), sides))
    return delta, _guard_scan(blocks, 0, la, lb, sides)


# ── inline_hunk: the changed blocks themselves, read from the original text ──────────────────

# The hunk is given only while the change itself is small: structural lines (both sides) plus
# substitution groups at most this many. Above it the hunk is withheld with those two counts — the
# delta's own fields are never touched by the gate.
INLINE_HUNK_GATE = 50
# Context lines shown around a structural block; two blocks with at most twice this many lines
# between them are shown as one, so no context line is printed twice.
INLINE_HUNK_CONTEXT = 2
_READ_WITH = "get_pseudocode"
# Names the decompiler makes up for a stack slot, a parameter or a register temporary. A
# substitution of one such name by another is grouped with the comment substitutions as one rename
# group. A GROUPING rule only: it is never applied to the text the lines are aligned on, so a
# changed stack slot (local_10 -> local_14, possibly another buffer) still shows, as a group.
_DECOMPILER_LOCAL = re.compile(
    r"^(local_|param_|in_|extraout_|unaff_|auStack_|abStack_|acStack_|asStack_|aiStack_|auVar|"
    r"uStack_|iStack_|lStack_|cStack_|bStack_|sStack_|fStack_|dStack_|pStack_|ppStack_|puStack_|"
    r"piStack_|[a-z]{1,4}Var\d+$)"
)


class _Sides(NamedTuple):
    """Each side's original lines (stripped, blank lines dropped — index for index with the
    normalised lines a delta aligns on) and their 1-based line numbers in the original text."""

    ra: list[str]
    na: list[int]
    rb: list[str]
    nb: list[int]


class _Block(NamedTuple):
    """One block the line match found unequal: its line ranges (``la[i1:i2]`` / ``lb[j1:j2]``), how
    many token spans in it are structural, and the token pairs that are substitutions, in order, as
    indices into its two token lists. PRIVATE: block positions are never output and never cached —
    the hunk and a later caller read them, the delta's fields are derived from them."""

    i1: int
    i2: int
    j1: int
    j2: int
    spans: int
    subs: tuple[tuple[int, int], ...]
    ta: list[tuple[str, str, int]]
    tb: list[tuple[str, str, int]]
    text_a: str
    text_b: str


def _tokens_at(text: str) -> list[tuple[str, str, int]]:
    """:func:`_tokens` with each token's start offset (the same tokens, in the same order)."""
    return [(m.lastgroup or "punct", m.group(0), m.start()) for m in _TOK.finditer(text)]


def _delta_lines(
    text: str, ranges: ImageRanges, blank_try: bool
) -> tuple[list[str], list[str], list[int]]:
    """(normalised lines, original lines, their 1-based numbers) of one body: every line split and
    stripped, blank lines dropped, the normalised and the original kept index for index. The
    normalisation only rewrites inside a line, so the two line lists are the same length; if they
    ever were not, the normalised text stands in for the original (never a wrong line)."""
    norm = _delta_text(text, ranges, blank_try).splitlines()
    raw = text.splitlines()
    if len(raw) != len(norm):
        raw = norm
    lines: list[str] = []
    originals: list[str] = []
    numbers: list[int] = []
    for k, (n, r) in enumerate(zip(norm, raw, strict=True)):
        s = n.strip()
        if s:
            lines.append(s)
            originals.append(r.strip() or s)
            numbers.append(k + 1)
    return lines, originals, numbers


def _delta_blocks(la: list[str], lb: list[str]) -> list[_Block] | None:
    """Every block the line match finds unequal, its tokens matched and classified: a same-length
    run of tokens each of the same non-punctuation kind is a substitution, anything else a
    structural span. None when the token pairs, summed over the blocks, exceed
    ``DELTA_TOKEN_PRODUCT_CAP``. The one match pseudocode_delta and its hunk both read."""
    blocks: list[_Block] = []
    token_pairs = 0  # drawn from the one DELTA_TOKEN_PRODUCT_CAP budget, block by block
    for op, i1, i2, j1, j2 in SequenceMatcher(None, la, lb, autojunk=False).get_opcodes():
        if op == "equal":
            continue
        text_a, text_b = "\n".join(la[i1:i2]), "\n".join(lb[j1:j2])
        ta, tb = _tokens_at(text_a), _tokens_at(text_b)
        token_pairs += len(ta) * len(tb)
        if token_pairs > DELTA_TOKEN_PRODUCT_CAP:
            return None
        spans = 0
        subs: list[tuple[int, int]] = []
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
                subs.extend((k1 + o, m1 + o) for o in range(k2 - k1))
            else:
                spans += 1
        blocks.append(_Block(i1, i2, j1, j2, spans, tuple(subs), ta, tb, text_a, text_b))
    return blocks


def _with_hunk(delta: dict[str, Any], hunk: dict[str, Any] | None) -> dict[str, Any]:
    """The delta with ``inline_hunk`` as its LAST field, or as it is when there is none to give."""
    if hunk is not None:
        delta["inline_hunk"] = hunk
    return delta


def _group_key(x: tuple[str, str, int], y: tuple[str, str, int]) -> tuple[Any, ...]:
    """The substitution group a token pair falls in: a number by its step (or the pair itself when
    a value cannot be read), a decompiler-local rename or a comment in the one rename group, any
    other identifier or string by the pair."""
    if x[0] == "number":
        va, vb = _parse_int_token(x[1]), _parse_int_token(y[1])
        if va is not None and vb is not None:
            return ("number", vb - va)
        return ("number", None, x[1], y[1])
    if x[0] == "comment" or (
        x[0] == "ident" and _DECOMPILER_LOCAL.match(x[1]) and _DECOMPILER_LOCAL.match(y[1])
    ):
        return ("local_or_comment",)
    return (x[0], x[1], y[1])


def _inline_hunk(
    blocks: list[_Block], off: int, len_a: int, len_b: int, sides: _Sides
) -> dict[str, Any] | None:
    """The changed blocks of one delta, shown — or why not. None when there is nothing to show (no
    structural block and no substitution: a layout-only difference). ``off`` is where the matched
    lines start in the whole body (the trimmed head of a too-large one, else 0).

    Gate (counted, never shown): ``structural_lines`` = the lines of every block holding any
    structural span, both sides added; ``groups`` = the substitution groups of the blocks holding
    none (a substitution inside a structural block is already in its shown lines). Over
    ``INLINE_HUNK_GATE`` the hunk is ``{withheld: over_gate, structural_lines, groups, read_with}``.

    Shown: ``structural`` — one list of lines per run of structural blocks, each line prefixed
    ``-`` (the A side's line), ``+`` (the B side's line), `` `` (a context line, A side) or ``=``
    (the B side's own text at this point, given only where it differs from the A line — the
    difference is an address, or a substitution already counted in substitution_groups; where B has
    more lines than A, several ``=`` lines can follow one another); ``INLINE_HUNK_CONTEXT`` lines
    around each run, runs that close
    merged. ``substitution_groups`` — one per group, in the order first met: ``kind`` (number /
    ident / string / local_or_comment), a number group's ``step``, ``total``, and ``first``: up to
    five ``[a, b, line_a, line_b]``, the token as each side's original text has it and its 1-based
    line there (blank lines counted). Every shown line is the original text, never the normalised
    one the lines were aligned on. No block position is given."""
    struct = [b for b in blocks if b.spans]
    struct_lines = sum((b.i2 - b.i1) + (b.j2 - b.j1) for b in struct)
    groups: dict[tuple[Any, ...], tuple[int, list[tuple[_Block, int, int]]]] = {}
    for b in blocks:
        if b.spans:
            continue
        for k, m in b.subs:
            key = _group_key(b.ta[k], b.tb[m])
            total, first = groups.get(key, (0, []))
            if len(first) < _DELTA_FIRST:
                first.append((b, k, m))
            groups[key] = (total + 1, first)
    if not struct and not groups:
        return None
    counts = {"structural_lines": struct_lines, "groups": len(groups)}
    if struct_lines + len(groups) > INLINE_HUNK_GATE:
        return {"withheld": "over_gate", **counts, "read_with": _READ_WITH}
    return {
        **counts,
        "structural": _structural_runs(blocks, off, len_a, len_b, sides),
        "substitution_groups": [
            {
                "kind": key[0],
                **({"step": key[1]} if key[0] == "number" else {}),
                "total": total,
                "first": [_shown_pair(b, k, m, off, sides) for b, k, m in first],
            }
            for key, (total, first) in groups.items()
        ],
    }


def _shown_pair(b: _Block, k: int, m: int, off: int, sides: _Sides) -> list[Any]:
    """``[a, b, line_a, line_b]`` of one substituted token pair: each token as its side's original
    line has it (the block re-tokenised from the original lines, used only when it tokenises the
    same way; else the normalised token), and its 1-based line in that side's original text."""
    out: list[Any] = []
    for toks, text, start, idx, raw, nums in (
        (b.ta, b.text_a, b.i1, k, sides.ra, sides.na),
        (b.tb, b.text_b, b.j1, m, sides.rb, sides.nb),
    ):
        lo = off + start
        orig = _tokens_at("\n".join(raw[lo : lo + text.count("\n") + 1]))
        same = len(orig) == len(toks) and all(o[0] == t[0] for o, t in zip(orig, toks, strict=True))
        out.append((orig if same else toks)[idx][1])
        out.append(nums[lo + text.count("\n", 0, toks[idx][2])])
    return [out[0], out[2], out[1], out[3]]


def _structural_runs(
    blocks: list[_Block], off: int, len_a: int, len_b: int, sides: _Sides
) -> list[list[str]]:
    """The structural blocks as shown runs of prefixed lines (see :func:`_inline_hunk`). The whole
    body is laid out as units — a context line pair, or one structural block — so the context of a
    block is the units beside it, whatever they are; a substitution block's lines are context here,
    their B text given where it differs."""
    units: list[tuple[str, int | None, int | None, int, int]] = []
    prev_a = prev_b = 0
    for b in blocks:
        a1, a2, b1, b2 = off + b.i1, off + b.i2, off + b.j1, off + b.j2
        units.extend(("ctx", prev_a + t, prev_b + t, 0, 0) for t in range(a1 - prev_a))
        if b.spans:
            units.append(("chg", a1, b1, a2, b2))
        else:
            units.extend(("ctx", i, j, 0, 0) for i, j in zip_longest(range(a1, a2), range(b1, b2)))
        prev_a, prev_b = a2, b2
    units.extend(("ctx", prev_a + t, prev_b + t, 0, 0) for t in range(len_a - prev_a))
    changes = [n for n, u in enumerate(units) if u[0] == "chg"]
    runs: list[list[int]] = []
    for n in changes:
        if runs and n - runs[-1][-1] - 1 <= 2 * INLINE_HUNK_CONTEXT:
            runs[-1].append(n)
        else:
            runs.append([n])
    shown: list[list[str]] = []
    for run in runs:
        lo, hi = run[0], run[-1]
        for _ in range(INLINE_HUNK_CONTEXT):
            if lo > 0 and units[lo - 1][0] == "ctx":
                lo -= 1
        for _ in range(INLINE_HUNK_CONTEXT):
            if hi + 1 < len(units) and units[hi + 1][0] == "ctx":
                hi += 1
        lines: list[str] = []
        for kind, i, j, i2, j2 in units[lo : hi + 1]:
            if kind == "chg":
                assert i is not None and j is not None
                lines += ["-" + sides.ra[t] for t in range(i, i2)]
                lines += ["+" + sides.rb[t] for t in range(j, j2)]
                continue
            if i is not None:
                lines.append(" " + sides.ra[i])
            if j is not None and (i is None or sides.rb[j] != sides.ra[i]):
                lines.append("=" + sides.rb[j])
        shown.append(lines)
    return shown


def _trim(la: list[str], lb: list[str]) -> tuple[int, int, list[str], list[str]]:
    """The identical leading (``p``) and trailing (``s``) line counts the two sides share, and the
    changed middle of each — what a too-large delta's hunk is computed from, past the set-aside
    head."""
    n = min(len(la), len(lb))
    p = 0
    while p < n and la[p] == lb[p]:
        p += 1
    s = 0
    while s < n - p and la[-1 - s] == lb[-1 - s]:
        s += 1
    return p, s, la[p : len(la) - s], lb[p : len(lb) - s]


def _middle_blocks(
    la: list[str], lb: list[str]
) -> tuple[int, list[str], list[str], list[_Block] | None]:
    """``(p, middle_a, middle_b, blocks)`` of a body too large to match whole: the identical leading
    lines (``p``) and trailing lines set aside, and the changed middle matched as usual when ITS
    line pairs fit ``DELTA_LINE_PRODUCT_CAP``; ``blocks`` is None when the middle is over the line
    cap or its token pairs over the token cap. One match, read by both the hunk and the guard scan
    (their block lines lie ``p`` past the start of the whole body)."""
    p, _s, ma, mb = _trim(la, lb)
    if len(ma) * len(mb) > DELTA_LINE_PRODUCT_CAP:
        return p, ma, mb, None
    return p, ma, mb, _delta_blocks(ma, mb)


def _trimmed_hunk(
    la: list[str],
    lb: list[str],
    sides: _Sides,
    middle: tuple[int, list[str], list[str], list[_Block] | None],
) -> dict[str, Any] | None:
    """The hunk of a delta too large to compute whole, from its changed middle
    (:func:`_middle_blocks`): the middle's blocks shown as usual (lines and line numbers mapped back
    past the set-aside head) when it was matched, else ``{withheld: too_large, lines {a, b},
    read_with}`` with the middle's line counts. The delta itself stays ``not_computed``: this is
    only the hunk."""
    p, ma, mb, blocks = middle
    if blocks is None:
        return {
            "withheld": "too_large",
            "lines": {"a": len(ma), "b": len(mb)},
            "read_with": _READ_WITH,
        }
    hunk = _inline_hunk(blocks, p, len(la), len(lb), sides)
    if hunk is None:
        # The middle computed but shows nothing — only layout or address differences, normalised
        # away. A ``not_computed`` delta with NO hunk leaves the reader unable to tell why; give a
        # zero-count hunk (the same field shape as a real one) so that state cannot arise here.
        return {"structural_lines": 0, "groups": 0, "structural": [], "substitution_groups": []}
    return hunk


# ── the guard scan: comparisons the B side's structural change introduces ─────────────────────

# How many of a pair's introduced variable-against-constant comparisons are kept (in B order); the
# counts are always over all of them.
GUARD_STORE_LIMIT = 200
_GUARDS_TOO_LARGE: dict[str, Any] = {"state": "not_extracted", "reason": "too_large"}
_ORDERING = frozenset({"<", "<=", ">", ">="})
_EQUALITY = frozenset({"==", "!="})
_RELATIONS = _ORDERING | _EQUALITY
# The relation read from the other side, for a constant written on the left (``0x40 < n`` is
# ``n > 0x40``).
_FLIPPED = {"<": ">", ">": "<", "<=": ">=", ">=": "<=", "==": "==", "!=": "!="}
_ASSIGNMENTS = frozenset({"=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="})
_LEFT_STOPS = frozenset({",", ";", "&&", "||", "?", ":", "{", "}"}) | _ASSIGNMENTS
_RIGHT_STOPS = frozenset({",", ";", "&&", "||", "?", ":", "{"})
_BITWISE = frozenset({"&", "|", "^"})
_STOP_KEYWORDS = frozenset(_CALL_KEYWORDS - {"sizeof"})
_OTHER_KINDS = ("var_var", "call", "field", "other")
_Tok = tuple[str, str, int]


class _Cmp(NamedTuple):
    """One relational comparison on a line: its key, what kind it is, and — for a variable against
    a constant (``kind == "guard"``) — the token index of the variable and the token ranges
    ``[start, end)`` of the variable's cast and of the constant (its own cast left out)."""

    key: tuple[tuple[str, ...], str, tuple[str, ...]]
    kind: str
    relation: str
    var: int = -1
    cast: tuple[int, int] | None = None
    const: tuple[int, int] = (0, 0)


def _is_binary_op(toks: list[_Tok], j: int) -> bool:
    """Whether the ``&`` / ``|`` / ``^`` at ``j`` is a binary operator: the token before it ends an
    operand (a name that is not a keyword, a number, ``)`` or ``]``). Else it is a unary ``&``."""
    if j == 0:
        return False
    kind, text, _start = toks[j - 1]
    return (
        (kind == "ident" and text not in _CALL_KEYWORDS)
        or kind == "number"
        or (kind == "punct" and text in (")", "]"))
    )


def _left_start(toks: list[_Tok], k: int, rel_stops: frozenset[str]) -> int:
    """The first token of the left operand of the comparison at ``k``: scanning left, bracket depth
    counted, it stops at depth 0 on the line's start, an unmatched ``(`` / ``[``, a separator
    (``,`` ``;`` ``&&`` ``||`` ``?`` ``:`` ``{`` ``}``), an assignment, a binary ``&`` ``|`` ``^``,
    a statement keyword (``return``, ``case``, …; not ``sizeof``) or one of ``rel_stops``."""
    j, depth = k - 1, 0
    while j >= 0:
        kind, text, _start = toks[j]
        if kind == "punct" and text in (")", "]"):
            depth += 1
        elif kind == "punct" and text in ("(", "["):
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and (
            (kind == "punct" and (text in _LEFT_STOPS or text in rel_stops))
            or (kind == "punct" and text in _BITWISE and _is_binary_op(toks, j))
            or (kind == "ident" and text in _STOP_KEYWORDS)
        ):
            break
        j -= 1
    return j + 1


def _right_end(toks: list[_Tok], k: int, rel_stops: frozenset[str]) -> int:
    """One past the last token of the right operand of the comparison at ``k``: scanning right,
    bracket depth counted, it stops at depth 0 on the line's end, an unmatched ``)`` / ``]``, a
    separator (``,`` ``;`` ``&&`` ``||`` ``?`` ``:`` ``{``), a binary ``&`` ``|`` ``^`` or one of
    ``rel_stops``."""
    j, depth, n = k + 1, 0, len(toks)
    while j < n:
        kind, text, _start = toks[j]
        if kind == "punct" and text in ("(", "["):
            depth += 1
        elif kind == "punct" and text in (")", "]"):
            if depth == 0:
                break
            depth -= 1
        elif (
            depth == 0
            and kind == "punct"
            and (
                text in _RIGHT_STOPS
                or text in rel_stops
                or (text in _BITWISE and _is_binary_op(toks, j))
            )
        ):
            break
        j += 1
    return j


def _cast_len(op: list[_Tok]) -> int:
    """How many tokens a leading cast takes in an operand: ``(`` then only names and ``*`` (at
    least one name) then ``)``, followed by more of the operand; 0 when it starts with none."""
    if len(op) < 3 or op[0][:2] != ("punct", "("):
        return 0
    m, names = 1, 0
    while m < len(op) and (op[m][0] == "ident" or op[m][:2] == ("punct", "*")):
        names += op[m][0] == "ident"
        m += 1
    if names and m < len(op) - 1 and op[m][:2] == ("punct", ")"):
        return m + 1
    return 0


def _form(op: list[_Tok]) -> tuple[str, int]:
    """(``var`` / ``const`` / ``compound``, the leading cast's token count) of one operand: after at
    most one leading cast, one name that is not a keyword is a variable; one number, or ``-`` and a
    number, is a constant; anything else is compound."""
    cast = _cast_len(op)
    rest = op[cast:]
    if len(rest) == 1 and rest[0][0] == "ident" and rest[0][1] not in _CALL_KEYWORDS:
        return "var", cast
    if len(rest) == 1 and rest[0][0] == "number":
        return "const", cast
    if len(rest) == 2 and rest[0][:2] == ("punct", "-") and rest[1][0] == "number":
        return "const", cast
    return "compound", cast


def _calls_in(op: list[_Tok]) -> bool:
    return any(
        x[0] == "ident" and x[1] not in _CALL_KEYWORDS and y[:2] == ("punct", "(")
        for x, y in zip(op, op[1:], strict=False)
    )


def _comparisons(toks: list[_Tok]) -> list[_Cmp]:
    """Every relational comparison (``<`` ``<=`` ``>`` ``>=`` ``==`` ``!=``) of one line, in order,
    each operand read to its boundaries (:func:`_left_start` / :func:`_right_end`) — ONE line, no
    syntax tree: a comparison split over two lines is cut at the line's start or end. Between
    comparison operators C's precedence holds: scanning from ``==`` / ``!=``, an ordering operator
    belongs to the operand (``(int)x < 0 == b``: the left operand of ``==`` is ``(int)x < 0``,
    compound), while from an ordering operator every comparison operator is a boundary.

    A variable against a constant is a ``guard``, its sides normalised as pure syntax: the variable
    is put on the left, the relation flipped with it (``0x40 < n`` reads ``n > 0x40``). Its key
    keeps the variable's cast (``(int)n < 0x20`` is another comparison than ``n < 0x20``) and drops
    the constant's (``p == (byte *)0x0`` and ``p == (char *)0x0`` are one comparison: only the type
    the decompiler gave a null constant differs). Any other comparison is keyed by its two operands
    as written and kinded ``var_var`` (two variables), ``call`` (an operand calls something),
    ``field`` (an operand reads a member) or ``other``."""
    out: list[_Cmp] = []
    for k, (kind, rel, _start) in enumerate(toks):
        if kind != "punct" or rel not in _RELATIONS:
            continue
        stops = _EQUALITY if rel in _EQUALITY else _RELATIONS
        lo, hi = _left_start(toks, k, stops), _right_end(toks, k, stops)
        left, right = toks[lo:k], toks[k + 1 : hi]
        (lf, lc), (rf, rc) = _form(left), _form(right)
        lt, rt = tuple(t[1] for t in left), tuple(t[1] for t in right)
        if lf == "var" and rf == "const":
            cmp = _Cmp(
                key=(lt, rel, rt[rc:]),
                kind="guard",
                relation=rel,
                var=lo + lc,
                cast=(lo, lo + lc) if lc else None,
                const=(k + 1 + rc, hi),
            )
            out.append(cmp)
        elif lf == "const" and rf == "var":
            flipped = _FLIPPED[rel]
            cmp = _Cmp(
                key=(rt, flipped, lt[lc:]),
                kind="guard",
                relation=flipped,
                var=k + 1 + rc,
                cast=(k + 1, k + 1 + rc) if rc else None,
                const=(lo + lc, k),
            )
            out.append(cmp)
        else:
            if lf == "var" and rf == "var":
                other = "var_var"
            elif _calls_in(left) or _calls_in(right):
                other = "call"
            elif any(t[:2] in (("punct", "->"), ("punct", ".")) for t in (*left, *right)):
                other = "field"
            else:
                other = "other"
            out.append(_Cmp((lt, rel, rt), other, rel))
    return out


def _is_zero(const: str) -> bool:
    """Whether a constant's value is 0 (``0``, ``0x0``, ``0U``, ``-0``); a value that cannot be read
    is not."""
    return _parse_int_token(const.lstrip("-").strip()) == 0


def _guard_scan(
    blocks: list[_Block], off: int, la: list[str], lb: list[str], sides: _Sides
) -> dict[str, Any]:
    """The comparisons the B side's structural change introduces — a syntax fact, never a reading of
    what they check or whether they hold. ``blocks`` were matched on ``la[off:]`` / ``lb[off:]``.

    Only the blocks holding a structural span are read; whatever lies in a substitution-only block
    (a threshold that merely changed, ``len > 0x100`` -> ``len > 0x40``) is the hunk's, not this.
    Inside each such block, the B lines' comparisons less the A lines' (as a multiset, by key, the
    keys read on the normalised lines so a moved address is no change); then, per key, at most as
    many are kept as the B body holds MORE of that key than the A body (the first in B order), so
    a comparison that only moved or was reordered is not introduced. What is left are the
    introduced comparisons: the variable-against-constant ones (``guards``) are given — the
    variable, constant and cast as the B side's original line writes them (the normalised tokens
    when that line does not tokenise the same way), the relation, ``const_class`` (``zero`` when the
    constant is 0, ``nonzero`` otherwise or when its value cannot be read) and ``line_b`` (its
    1-based line in the original B text) — in B order, at most ``GUARD_STORE_LIMIT``; the rest only
    counted by kind (``other_comparisons``). No block position is kept."""
    memo: dict[str, list[_Cmp]] = {}

    def cmps(line: str) -> list[_Cmp]:
        found = memo.get(line)
        if found is None:
            plain = "<" in line or ">" in line or "==" in line or "!=" in line
            found = memo[line] = _comparisons(_tokens_at(line)) if plain else []
        return found

    introduced: list[tuple[_Cmp, int]] = []  # (comparison, index into lb), in B order
    for blk in blocks:
        if not blk.spans:
            continue
        seen = Counter(c.key for i in range(off + blk.i1, off + blk.i2) for c in cmps(la[i]))
        for j in range(off + blk.j1, off + blk.j2):
            for c in cmps(lb[j]):
                if seen[c.key] > 0:
                    seen[c.key] -= 1
                else:
                    introduced.append((c, j))
    if introduced:
        wanted = {c.key for c, _j in introduced}
        excess = Counter(c.key for line in lb for c in cmps(line) if c.key in wanted)
        excess.subtract(c.key for line in la for c in cmps(line) if c.key in wanted)
        kept: list[tuple[_Cmp, int]] = []
        for c, j in introduced:
            if excess[c.key] > 0:
                excess[c.key] -= 1
                kept.append((c, j))
        introduced = kept
    others = dict.fromkeys(_OTHER_KINDS, 0)
    by_class = {"zero": 0, "nonzero": 0}
    guards: list[dict[str, Any]] = []
    total = 0
    for c, j in introduced:
        if c.kind != "guard":
            others[c.kind] += 1
            continue
        total += 1
        line, toks = lb[j], _tokens_at(lb[j])
        raw = sides.rb[j]
        raw_toks = _tokens_at(raw)
        if len(raw_toks) == len(toks) and all(
            x[0] == y[0] for x, y in zip(raw_toks, toks, strict=True)
        ):
            line, toks = raw, raw_toks

        def span(lo: int, hi: int, line: str = line, toks: list[_Tok] = toks) -> str:
            return line[toks[lo][2] : toks[hi - 1][2] + len(toks[hi - 1][1])]

        const = span(*c.const)
        const_class = "zero" if _is_zero(const) else "nonzero"
        by_class[const_class] += 1
        if len(guards) < GUARD_STORE_LIMIT:
            guards.append(
                {
                    "var": toks[c.var][1],
                    "const": const,
                    "relation": c.relation,
                    "cast": span(*c.cast) if c.cast is not None else None,
                    "const_class": const_class,
                    "line_b": sides.nb[j],
                }
            )
    return {
        "state": "done",
        "var_const_total": total,
        "by_const_class": by_class,
        "other_comparisons": others,
        "guards": guards,
    }


# ── line-number form: a __FILE__/__LINE__ shift, told apart from a real substitution ─────────

# A source-file path as __FILE__ expands it: the WHOLE string a path-like token ending in a C/C++
# source suffix. Matched whole, never by suffix — "cannot open config.c" or "%s/%s.h" end in one
# too, and are messages / formats, not a path.
_SOURCE_PATH = re.compile(r"[\w./+-]*\.(?:c|cc|cpp|h)")


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
    return _SOURCE_PATH.fullmatch(s) is not None


def _preceding_string_arg(toks: list[tuple[str, str]], idx: int) -> str | None:
    """The dequoted string literal that is the call argument immediately before ``toks[idx]``, when
    ``toks[idx]`` is ALONE a top-level argument of a call (a callee identifier, then ``(``) and the
    argument before it is exactly one string token; else None. The walk back to the call's ``(``
    stops at ``;`` ``{`` ``}`` (statement bounds), so a bare number not inside a call is rejected.
    Only ``()`` drive the enclosing-call depth; ``[]`` / ``{}`` inside an argument stay opaque. The
    callee must be a plain identifier: a call through a function pointer (``(*p)(…)``) is never read
    as such a site, so a shift there stays in the read-first head — narrower than the shape, never
    wider."""
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


# Why a micro-stub side carries no inline listing (``listing_note``): the binary was extracted
# before tmap stored disassembly (a re-scan stores it), or it was and holds none for this function
# (get_disassembly says why).
LISTING_NOT_EXPORTED = "not_exported_by_this_scan"
LISTING_NOT_STORED = "not_stored"


def read_micro_listings(
    analysis_db_path: str | None, sha: str | None, addrs: set[str]
) -> dict[str, dict[str, Any]]:
    """entry (normalised hex) -> the stored disassembly of each of ``addrs`` in one diffed binary,
    read-only: ``{"listing": [...]}`` (facts.listing_items: get_disassembly's items without the
    bytes), else ``{"listing": None, "listing_note": ...}`` (:data:`LISTING_NOT_EXPORTED` /
    :data:`LISTING_NOT_STORED`). Meant for the design-skipped micro-stub sides of one rendered page:
    a body under the decompile size floor is a handful of units, so it is shown whole. Every one of
    ``addrs`` gets an answer; a db that cannot be read reads as not stored."""
    exported = True
    blobs: dict[str, Any] = {}
    if addrs and analysis_db_path and sha:
        try:
            conn = ro_connect(analysis_db_path)
        except sqlite3.Error:
            conn = None
        if conn is not None:
            try:
                found = conn.execute("SELECT id FROM binaries WHERE sha256 = ?", (sha,)).fetchone()
                if found is not None:
                    exported = (
                        conn.execute(
                            "SELECT 1 FROM detector_scan_status WHERE binary_id = ? "
                            "AND detector = 'listing' LIMIT 1",
                            (found[0],),
                        ).fetchone()
                        is not None
                    )
                    ids: dict[int, str] = {}
                    for fid, address in conn.execute(
                        "SELECT id, address FROM functions WHERE binary_id = ? "
                        "AND (pseudocode IS NULL OR pseudocode = '')",
                        (found[0],),
                    ):
                        addr = norm_hex(address) if address else None
                        if addr in addrs:
                            ids[fid] = addr
                    if ids:
                        marks = ", ".join("?" * len(ids))
                        for fid, blob in conn.execute(
                            "SELECT function_id, listing FROM function_listing "
                            f"WHERE function_id IN ({marks})",
                            tuple(ids),
                        ):
                            blobs[ids[fid]] = blob
            except sqlite3.Error:
                pass
            finally:
                conn.close()
    out: dict[str, dict[str, Any]] = {}
    for addr in addrs:
        units = listing_items(blobs.get(addr))
        if units is not None:
            out[addr] = {"listing": units}
        else:
            note = LISTING_NOT_STORED if exported else LISTING_NOT_EXPORTED
            out[addr] = {"listing": None, "listing_note": note}
    return out


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
