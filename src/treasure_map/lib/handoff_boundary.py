# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The one non-neutral string of the findings hand-off: the boundary it tells the reviewing agent,
spelling out what NOT to write. It lives here, outside the neutral query layer, for the same reason
the exploit ledger does — it is agent-instruction framing, not analysis, so the neutral layer
(lib/query) imports it rather than spelling it. review_report embeds it in the hand-off placeholders
and review_driver puts it in the hand-off prompt; both reference this constant.
"""

from __future__ import annotations

# Agent-facing: the hand-off is hypotheses and device checks only, never a working attack, and the
# status stays "awaiting human verification". Kept verbatim across the prompt and the placeholders.
HANDOFF_BOUNDARY = (
    "Fill in hypotheses and device checks only — not exploit code, a payload or attack steps. "
    "The status stays: awaiting human verification."
)
