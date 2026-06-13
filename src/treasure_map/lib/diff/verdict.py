# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Neutral, mechanism-level description of a single function change (L tier).

The output is strictly a description of WHAT THE CODE DOES DIFFERENTLY — control flow,
calls, buffer/length handling. It never judges whether a change is good, intended, or
significant, and the committed prompt never asks for such a judgment. Any higher-order
interpretation of a change is a downstream consumer's concern, made entirely outside
this primitive.
"""

from __future__ import annotations

from treasure_map.lib.diff.matcher import _DiffRouter

# Bump on ANY change to _PATCH_VERDICT_PROMPT (invalidates the router cache).
PATCH_VERDICT_PROMPT_VERSION = "patchverdict-v1"

_PATCH_VERDICT_PROMPT = (
    "You are given a unified diff between two versions of one C function. Describe, in "
    "one neutral sentence, what the diff changes in the function's mechanism — its "
    "control flow, the calls it makes, and how it handles buffers or lengths. State "
    "only what the code mechanically does differently. Do not judge whether the change "
    "is good or bad, intended or not, or what it might mean for a caller; do not rate "
    "or prioritize it. Mechanism only."
)


async def describe_change(diff_text: str, router: _DiffRouter) -> str:
    """Return a one-sentence neutral mechanism description of a unified diff."""
    resp = await router.call(
        "patch_verdict",
        diff_text,
        _PATCH_VERDICT_PROMPT,
        PATCH_VERDICT_PROMPT_VERSION,
    )
    return resp.content.strip()
