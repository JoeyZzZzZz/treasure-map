# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Read the absolute callsite address back out of a per-callsite ``evidence_ref``.

A per-callsite ref ends ``…:<func_entry>@<class>@<offset>`` (built by lib/hunt/refs.py:
build_evidence_ref + callsite_offset_suffix + _norm_offset). The function anchor is canonical hex
and the offset is a signed hex delta from it. This is a READER of that shape for the layers that
must not import lib/hunt (the read layer does not depend on the write layer) — the query layer and
the diff layer both use it. It is kept in step with the single forge by a round-trip test rather
than by importing it.

A leaf module on purpose: no treasure_map imports, so any layer can depend on it.
"""

from __future__ import annotations

import re

# The two ``@`` matter: the first joins the sink CLASS, the second the address offset — split
# greedily on the last so a function-level ``…@<class>`` (no offset) never matches.
_CALLSITE_REF_RE = re.compile(r":([0-9a-f]+)@[a-z_]+@(-?)0x([0-9a-f]+)$")


def callsite_abs_addr(evidence_ref: str | None) -> int | None:
    """The absolute sink address a per-callsite ref names, or None when the ref carries no address.

    Reconstructs ``func_entry + offset`` from the addressed suffix. None (no address to scope by,
    so the caller keeps the function-level reading) for every other shape: a function-level
    ``…@<class>``, a wrapper ``…@<class>_via_wrapper``, a legacy ordinal ``…@<class>#<n>``, a
    non-hex function anchor, the empty string, or None."""
    m = _CALLSITE_REF_RE.search(evidence_ref or "")
    if m is None:
        return None
    off = int(m.group(3), 16)
    return int(m.group(1), 16) + (-off if m.group(2) else off)
