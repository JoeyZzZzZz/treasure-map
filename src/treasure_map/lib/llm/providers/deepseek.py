# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""DeepSeek provider — thin wrapper around OpenAICompatProvider."""

from __future__ import annotations

from treasure_map.lib.config.config import TierConfig
from treasure_map.lib.llm.providers.openai_compat import OpenAICompatProvider
from treasure_map.lib.llm.types import Tier


def build_deepseek_provider(tier_cfg: TierConfig, tier: Tier) -> OpenAICompatProvider:
    """Instantiate a DeepSeek provider from a TierConfig.

    DeepSeek exposes an OpenAI-compatible API, so we reuse OpenAICompatProvider.
    """
    return OpenAICompatProvider(
        model=tier_cfg.model,
        base_url=tier_cfg.base_url,
        api_key=tier_cfg.resolve_api_key(),
        tier=tier,
        thinking=tier_cfg.thinking,
        reasoning_effort=tier_cfg.reasoning_effort,
    )
