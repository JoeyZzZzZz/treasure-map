# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Signals a BinDiff similarity score cannot carry: whether two aligned functions are really the
same, and whether a sink call's length constant changed.

similarity is blind to immediates, constants and buffer sizes: a pair can read ``similarity=1.0``
while a bound was tightened or loosened. This module holds the two facts the function patch view
(lib/query/patch_view) adds to close that gap, and NOTHING that judges them — direction and meaning
are the reader's:

  * ``pseudocode_sameness`` — an honest reading of an aligned pair, folding an address-normalised
    pseudocode comparison together with the callee-set state the view already computed.
    ``identical`` only when both agree; a pseudocode match whose callees could not be verified is
    ``identical_callee_unverified``, never folded into "unchanged" or "changed". A changed callee
    set is ``differs`` even when there is no body to read. When there is no body, the reason is
    carried, not swallowed: ``no_body`` (an import / PLT stub absent from the functions table) is
    kept apart from ``unavailable`` (a function in the table whose pseudocode is empty), so a
    reader need not recompute which it was.
  * the length-constant signals on a persisted candidate's two sides: ``const_delta`` when the same
    constant size kind holds a different value (0x40 -> 0x3f, and an off-by-one like 256 -> 255),
    and ``kind_shift`` when the size kind itself changed (const -> cap_const, const -> untraced). A
    kind change is never read as a value delta.

The address normalisation is defined once here (``normalize_pseudocode``) so the "small constants
stay put" rule has a single home: absolute addresses and the hex suffixes of Ghidra's synthetic
symbol names are blanked, numeric constants are not — else a changed buffer size would normalise
away and the whole point would be lost.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Any

from treasure_map.lib.diff.layer0 import norm_hex

# ── the four states of an aligned pair ───────────────────────────────────────────────────────

IDENTICAL = "identical"  # pseudocode matches and the callee sets are equal: really unchanged
IDENTICAL_CALLEE_UNVERIFIED = (
    "identical_callee_unverified"  # pseudocode matches, callees unverified
)
DIFFERS = "differs"  # pseudocode differs, or the callee sets differ (even with no body to read)
NO_BODY = "no_body"  # a side has no body at all — an import / PLT stub, not in the functions table
UNAVAILABLE = "unavailable"  # a side IS in the table but its pseudocode is empty, or the db failed

# The not_listed count name for each state (aligned, similarity-1 pairs that place no entry).
NOT_LISTED_NAME = {
    IDENTICAL: "aligned_pseudocode_identical",
    IDENTICAL_CALLEE_UNVERIFIED: "aligned_pseudocode_identical_callee_unverified",
    DIFFERS: "aligned_pseudocode_differs",
    NO_BODY: "aligned_pseudocode_no_body",
    UNAVAILABLE: "aligned_pseudocode_unavailable",
}
STATE_BY_NOT_LISTED_NAME = {name: state for state, name in NOT_LISTED_NAME.items()}

# ── address normalisation (single definition) ────────────────────────────────────────────────

# Ghidra's synthetic symbol names carry an absolute address after an underscore, at the END of the
# name (FUN_00012a40, DAT_000200f8, s_hi_0001ccd0, LAB_/UNK_/SUB_), or as ``r0x<addr>`` (the branch
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
# A bare absolute address / GOT offset literal, same six-digit floor.
_ABS_HEX = re.compile(r"\b0x[0-9a-fA-F]{6,}\b")


def normalize_pseudocode(text: str) -> str:
    """``text`` with absolute addresses and synthetic-symbol address suffixes blanked, numeric
    constants left exactly as they are."""
    text = _ADDR_SUFFIX.sub("_@", text)
    return _ABS_HEX.sub("0x@", text)


def _body_status(bodies: dict[str, str | None] | None, addr: str) -> str:
    """One side's body status at ``addr``: ``ok`` (there is pseudocode to compare), ``no_body`` (the
    function is absent from the table — an import / PLT stub), or ``unavailable`` (in the table but
    its pseudocode is empty, or the analysis.db could not be read)."""
    if bodies is None:
        return UNAVAILABLE
    if addr not in bodies:
        return NO_BODY
    return "ok" if bodies[addr] else UNAVAILABLE


def pair_reading(
    a_bodies: dict[str, str | None] | None,
    b_bodies: dict[str, str | None] | None,
    addr_a: str,
    addr_b: str,
) -> tuple[bool | None, str | None]:
    """``(matches, reason)`` for one aligned pair: ``matches`` True / False (reason None) when both
    sides have a body to compare after normalisation; else ``matches`` None with the reason a reader
    would otherwise have to recompute — ``no_body`` when a side is an import / PLT stub, else
    ``unavailable`` (``no_body`` wins when both apply, so a stub pair is named as one)."""
    sa, sb = _body_status(a_bodies, addr_a), _body_status(b_bodies, addr_b)
    if sa == "ok" and sb == "ok":
        pa, pb = (a_bodies or {})[addr_a], (b_bodies or {})[addr_b]
        return (normalize_pseudocode(pa or "") == normalize_pseudocode(pb or ""), None)
    return (None, NO_BODY if NO_BODY in (sa, sb) else UNAVAILABLE)


def sameness_state(matches: bool | None, callee_state: str | None, reason: str | None) -> str:
    """Fold a pseudocode reading and the pair's callee-set state into one state. A changed callee
    set is proof of change even with no body to read (so ``differs`` wins over a missing body); a
    match is ``identical`` only when the callees are proven equal, else unverified — never silently
    "unchanged". When there is no body and nothing proves a change, the reason stands as the state
    (``no_body`` / ``unavailable``)."""
    if callee_state == "differs":
        return DIFFERS  # a changed call set is proof of change, even with no body to read
    if matches is None:
        return reason or UNAVAILABLE
    if not matches:
        return DIFFERS
    if callee_state == "equal":
        return IDENTICAL
    return (
        IDENTICAL_CALLEE_UNVERIFIED  # undetermined (or no callee reading): unverified, not "same"
    )


# ── reading pseudocode from a run's analysis.db ──────────────────────────────────────────────


def read_function_bodies(
    analysis_db_path: str | None, sha: str | None
) -> dict[str, str | None] | None:
    """function entry (normalised hex) -> its pseudocode (None when the row's pseudocode is empty),
    for one diffed binary, read in one pass from the run's own analysis.db (read-only). EVERY
    function the table holds is a key — so a key's absence means the function is not in the table at
    all (an import / PLT stub), told apart from a present-but-empty body. None when the db or binary
    cannot be read."""
    if not analysis_db_path or not sha:
        return None
    try:
        conn = sqlite3.connect(f"file:{analysis_db_path}?mode=ro", uri=True)
    except sqlite3.Error:
        return None
    try:
        found = conn.execute("SELECT id FROM binaries WHERE sha256 = ?", (sha,)).fetchone()
        if found is None:
            return None
        rows = conn.execute(
            "SELECT address, pseudocode FROM functions WHERE binary_id = ?", (found[0],)
        ).fetchall()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    out: dict[str, str | None] = {}
    for address, pseudocode in rows:
        addr = norm_hex(address) if address else None
        if addr is not None:
            out[addr] = pseudocode
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
