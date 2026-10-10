# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Read the suffix of an ``evidence_ref`` back: its class, and the call address it names.

A ref ends ``…:<func_entry>@<class>`` with an optional callsite tail: ``@<offset>`` (a signed hex
delta from the function entry, the per-callsite form) or ``#<n>`` (the legacy text ordinal). It is
built by lib/hunt/refs.py (build_evidence_ref + callsite_offset_suffix + _norm_offset). This is a
READER of that shape for the layers that must not import lib/hunt (the read layer does not depend
on the write layer) — the query layer and the diff layer both use it. It is kept in step with the
single forge by a round-trip test rather than by importing it.

Two kinds of class share the shape, and they name DIFFERENT calls:

* a direct sink class (``cmd``, ``copy``, …): the offset is the call to the SINK itself —
  ``callsite_abs_addr``.
* a wrapper class (``<axis>_via_wrapper``): the sink is one hop away inside a thin wrapper ``W``;
  the offset is the candidate function's call to ``W`` — ``wrapper_call_abs_addr``. It is never the
  sink's address, so ``callsite_abs_addr`` answers None for it: a reader scoping sink records by
  that address would otherwise match a call that is not a sink call at all.

A leaf module on purpose: no treasure_map imports, so any layer can depend on it.
"""

from __future__ import annotations

import re

# The ONE parser of the suffix. ``:<entry>@<class>`` then optionally ``@[-]0x<offset>`` or
# ``#<ordinal>``, anchored at the end, so ``@<class>`` is never mistaken for an offset.
_SUFFIX_RE = re.compile(r":([0-9a-f]+)@([a-z_]+)(?:@(-?)0x([0-9a-f]+)|#(\d+))?$")

_WRAPPER_CLASS_TAIL = "_via_wrapper"


def _parse(evidence_ref: str | None) -> tuple[int, str, int | None, int | None] | None:
    m = _SUFFIX_RE.search(evidence_ref or "")
    if m is None:
        return None
    entry = int(m.group(1), 16)
    offset: int | None = None
    if m.group(4) is not None:
        off = int(m.group(4), 16)
        offset = -off if m.group(3) else off
    ordinal = int(m.group(5)) if m.group(5) is not None else None
    return entry, m.group(2), offset, ordinal


def ref_suffix_parts(evidence_ref: str | None) -> tuple[str, int | None, int | None] | None:
    """``(class, offset, ordinal)`` of a ref's suffix, or None when the ref has no
    ``:<hex entry>@<class>`` tail (a legacy ``#fn<N>`` anchor, a name-anchored function, empty).

    ``offset`` is the signed delta of the ``@<offset>`` form, ``ordinal`` the ``#<n>`` form; both
    are None for a bare ``@<class>``, and at most one is set."""
    parsed = _parse(evidence_ref)
    if parsed is None:
        return None
    _entry, cls, offset, ordinal = parsed
    return cls, offset, ordinal


def is_wrapper_class(cls: str) -> bool:
    """True for a wrapper-propagated candidate's class (``cmd_via_wrapper``, …)."""
    return cls.endswith(_WRAPPER_CLASS_TAIL)


def callsite_abs_addr(evidence_ref: str | None) -> int | None:
    """The absolute address of the SINK call a per-callsite ref names, or None.

    Reconstructs ``func_entry + offset`` from the addressed suffix of a DIRECT sink class. None (no
    sink address to scope by, so the caller keeps the function-level reading) for every other
    shape: a function-level ``…@<class>``, a legacy ordinal ``…@<class>#<n>``, a wrapper class with
    or without an offset (its offset names the call to the wrapper, not to the sink — see
    ``wrapper_call_abs_addr``), a non-hex function anchor, the empty string, or None."""
    parsed = _parse(evidence_ref)
    if parsed is None:
        return None
    entry, cls, offset, _ordinal = parsed
    if offset is None or is_wrapper_class(cls):
        return None
    return entry + offset


def wrapper_call_abs_addr(evidence_ref: str | None) -> int | None:
    """The absolute address of the candidate function's call to its thin wrapper ``W``, for a
    wrapper-class ref carrying an offset; None for every other shape, including every direct sink
    ref (whose address is ``callsite_abs_addr``'s answer, not this one's)."""
    parsed = _parse(evidence_ref)
    if parsed is None:
        return None
    entry, cls, offset, _ordinal = parsed
    if offset is None or not is_wrapper_class(cls):
        return None
    return entry + offset
