# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Central registry mapping every LLM task to its cost tier.

Adding a new task: add one entry here. Calling router.call() with an
unregistered task name raises UnknownTaskError immediately.
"""

from __future__ import annotations

from treasure_map.lib.llm.types import Tier

# task_name → Tier.  All tasks across all milestones are declared here.
TASK_TIER_MAP: dict[str, Tier] = {
    # M1
    "function_summary": Tier.S,
    "wrapper_detect": Tier.S,
    # M1-Stretch
    "string_categorize": Tier.S,
    # M2
    "function_match_assist": Tier.M,
    "patch_verdict": Tier.L,
    # M3
    "vuln_scan_deep": Tier.M,
    "audit_class_a": Tier.M,
    "audit_class_b": Tier.M,
    "audit_class_c": Tier.M,
    "audit_class_d": Tier.L,
    # M5/M6
    "case_study_compose": Tier.L,
}
