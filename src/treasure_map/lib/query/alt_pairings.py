# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Where a function's counterpart may be other than where the diff's pairing puts it: the publish
rules of ``alt_pairings`` (lib/query/patch_view), and the same-body reading (``via="twin"``).

Three sources, each read as its own fact beside the entry, never a re-pairing and never a choice
between them:

* ``string`` — the function's unique strings (each referenced from exactly one function on each
  side, the format-only ones left out) point to one function on the other side; published when at
  least ``STRING_MIN`` distinct values point to that same function.
* ``key`` — a dispatch key with exactly one handler on each side; published from one key
  (``KEY_MIN``): a key selects its handler.
* ``twin`` — the function's body (``sameness.skeleton_key``) occurs exactly once on the other side,
  in another function than its partner (:func:`twin_readings`).

A target must lie elsewhere than the entry's own partner on that side. Every published reading is
given, in a fixed order (:func:`order_key`), never ranked by its evidence or its text ratio.

THE SAME-BODY READING. ``skeleton_key`` leaves the large literals' values out, so a shared key is
only an index: a target is given when every gate below passes, else only how many same-key bodies
there are and the first gate that held it back (``twin_not_given``):

* no reading at all when the current partner has the same skeleton (that body's other copies are
  read by the pair's own reading), or when no other-side function has it;
* ``decompile_incomplete`` — the body, or a same-key body on the other side, carries a decompiler
  note that it is not the whole function (sameness.W_MARKERS);
* ``not_unique`` — the key occurs more than once on either side;
* ``short_body`` — the skeleton is at most ``TWIN_MIN_LINES`` non-blank lines (signature and
  braces counted), or holds nothing but ``return`` statements;
* ``callee_identity_elsewhere`` — at some reference position (the i-th ``FUN_<addr>`` of each
  text, the function's own name left out, a call or an address taken alike), one side's callee is
  aligned to a function with its own body, and that function is not the one the other text names
  there (whose body differs). An unaligned, undetermined or changed callee refutes nothing;
* ``literal_values_differ`` — sameness.literal_reading does not read the two bodies equal.

Pure functions over bodies already read (lib/query/patch_view reads them once per diff)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from treasure_map.lib.query import sameness

VIA_STRING, VIA_KEY, VIA_TWIN = "string", "key", "twin"
STRING_MIN = 5  # distinct unique strings pointing to one function
KEY_MIN = 1  # single-handler keys pointing to one function
TWIN_MIN_LINES = 5  # a same-body target needs a skeleton of more than this many lines

TWIN_DECOMPILE_INCOMPLETE = "decompile_incomplete"
TWIN_NOT_UNIQUE = "not_unique"
TWIN_SHORT_BODY = "short_body"
TWIN_CALLEE_ELSEWHERE = "callee_identity_elsewhere"
TWIN_LITERALS_DIFFER = "literal_values_differ"

_FUN_REF = re.compile(r"\bFUN_([0-9a-fA-F]{6,})\b")


def anchor_published(via: str, evidence_count: int) -> bool:
    """Whether a string / key reading pointing elsewhere is published."""
    return evidence_count >= (STRING_MIN if via == VIA_STRING else KEY_MIN)


def order_key(item: dict[str, Any]) -> tuple[str, str, str]:
    """The fixed order of an entry's readings: by source, direction, then target address."""
    return (str(item["via"]), str(item["direction"]), str(item["target_addr"]))


@dataclass(frozen=True)
class Twin:
    """One function's same-body reading on the other side: ``target`` when every gate passed, else
    None with ``basis`` (the first gate that held it back). ``count`` is how many other-side
    functions carry the same skeleton key."""

    direction: str  # to_b: an A body found on B; to_a: a B body found on A
    target: str | None
    count: int
    basis: str | None


@dataclass(frozen=True)
class TwinReadings:
    """Every function's same-body reading of one diff, by (side, address); ``unreadable`` when a
    side's bodies could not be read (nothing can be said, which is not "none found")."""

    facts: dict[tuple[str, str], Twin]
    unreadable: bool = False


Index = dict[str, list[str]]  # skeleton_key -> the entries of one side with that body


def skeleton_index(bodies: sameness.Bodies) -> tuple[dict[str, str], Index]:
    """(entry -> skeleton_key, skeleton_key -> entries) over every function of one side with
    text."""
    keys: dict[str, str] = {}
    index: Index = {}
    for addr, body in bodies.items():
        text = body.get("pseudocode")
        if text:
            k = sameness.skeleton_key(text)
            keys[addr] = k
            index.setdefault(k, []).append(addr)
    return keys, index


def short_body(text: str) -> bool:
    """Gate 1: at most ``TWIN_MIN_LINES`` non-blank skeleton lines, or nothing but ``return`` after
    the signature (braces aside)."""
    lines = [ln.strip() for ln in sameness.skeleton(text)[0].splitlines() if ln.strip()]
    if len(lines) <= TWIN_MIN_LINES:
        return True
    return all(ln.startswith("return") for ln in lines[1:] if ln not in ("{", "}"))


def _fun_refs(text: str, own: str) -> list[str]:
    """Every ``FUN_<addr>`` the text names, in order, the function's own entry left out (addresses
    padded to eight digits, as entries are stored)."""
    out = []
    for m in _FUN_REF.finditer(text):
        addr = m.group(1).lower().zfill(8)
        if addr != own:
            out.append(addr)
    return out


def twin_readings(
    bodies: dict[str, sameness.Bodies | None],
    ranges: dict[str, sameness.ImageRanges],
    partner: dict[str, dict[str, str]],
    aligned: dict[str, dict[str, str]],
    prebuilt: dict[str, tuple[dict[str, str], Index]] | None = None,
) -> TwinReadings:
    """The same-body reading of every function with text on both sides (module docstring).

    ``partner[side][addr]`` is the other-side function a pair (aligned or not) puts ``addr`` with;
    ``aligned[side][addr]`` the same for the aligned pairs only (the callee gate reads those).
    ``prebuilt``: each side's :func:`skeleton_index`, when the caller already holds it."""
    ba, bb = bodies["a"], bodies["b"]
    if ba is None or bb is None:
        return TwinReadings({}, unreadable=True)
    texts = {"a": ba, "b": bb}
    built = prebuilt or {"a": skeleton_index(ba), "b": skeleton_index(bb)}
    keys = {s: built[s][0] for s in ("a", "b")}
    index = {s: built[s][1] for s in ("a", "b")}
    marked: dict[str, dict[str, bool]] = {"a": {}, "b": {}}

    def text(side: str, addr: str) -> str:
        return str((texts[side].get(addr) or {}).get("pseudocode") or "")

    def incomplete(side: str, addr: str) -> bool:
        hit = marked[side].get(addr)
        if hit is None:
            hit = bool(sameness.incomplete_tags(text(side, addr), ""))
            marked[side][addr] = hit
        return hit

    def refutes(x: str, z: str) -> bool:
        """A's callee ``x`` and B's ``z`` at one position: one is aligned to a same-body function
        that is not the other, whose body differs."""
        kx, kz = keys["a"].get(x), keys["b"].get(z)
        bx = aligned["a"].get(x)
        if bx is not None and bx != z and kx is not None:
            if kx == keys["b"].get(bx) and kx != kz:
                return True
        az = aligned["b"].get(z)
        if az is not None and az != x and kz is not None:
            if kz == keys["a"].get(az) and kz != kx:
                return True
        return False

    out: dict[tuple[str, str], Twin] = {}
    for side, other, direction in (("a", "b", "to_b"), ("b", "a", "to_a")):
        for addr, k in keys[side].items():
            mate = partner[side].get(addr)
            if mate is not None and keys[other].get(mate) == k:
                continue  # the partner has this body: read by the pair's own reading
            cands = index[other].get(k, [])
            if not cands:
                continue
            count = len(cands)
            basis: str | None = None
            if incomplete(side, addr) or any(incomplete(other, c) for c in cands):
                basis = TWIN_DECOMPILE_INCOMPLETE
            elif len(index[side][k]) != 1 or count != 1:
                basis = TWIN_NOT_UNIQUE
            elif short_body(text(side, addr)):
                basis = TWIN_SHORT_BODY
            else:
                (twin,) = cands
                fa, fb = (addr, twin) if side == "a" else (twin, addr)
                ta, tb = text("a", fa), text("b", fb)
                if any(
                    refutes(x, z)
                    for x, z in zip(_fun_refs(ta, fa), _fun_refs(tb, fb), strict=False)
                ):
                    basis = TWIN_CALLEE_ELSEWHERE
                elif not sameness.literal_reading(ta, tb, ranges["a"], ranges["b"])[0]:
                    basis = TWIN_LITERALS_DIFFER
            target = cands[0] if basis is None else None
            out[(side, addr)] = Twin(direction, target, count, basis)
    return TwinReadings(out)
