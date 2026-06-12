# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Build a fully wired LLMRouter from a Config object."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from treasure_map.lib.config.config import LLMConfig
from treasure_map.lib.cost_guard.guard import CostGuard
from treasure_map.lib.llm.providers.anthropic import build_anthropic_provider
from treasure_map.lib.llm.providers.deepseek import build_deepseek_provider
from treasure_map.lib.llm.providers.openai_compat import OpenAICompatProvider
from treasure_map.lib.llm.router import LLMProvider, LLMRouter
from treasure_map.lib.llm.types import Tier
from treasure_map.lib.llm_cache.cache import LLMCache

_ANTHROPIC_PROVIDERS = {"anthropic"}
_DEEPSEEK_PROVIDERS = {"deepseek"}


def _build_provider(tier: Tier, cfg: LLMConfig) -> LLMProvider:
    tier_cfg = getattr(cfg.tiers, tier.value)
    provider_name = tier_cfg.provider.lower()

    if provider_name in _ANTHROPIC_PROVIDERS:
        return build_anthropic_provider(tier_cfg, tier)
    if provider_name in _DEEPSEEK_PROVIDERS:
        return build_deepseek_provider(tier_cfg, tier)
    # Generic OpenAI-compatible fallback
    return OpenAICompatProvider(
        model=tier_cfg.model,
        base_url=tier_cfg.base_url,
        api_key=tier_cfg.resolve_api_key(),
        tier=tier,
    )


def build_router(
    llm_config: LLMConfig,
    ledger_path: Path,
    *,
    agent_mode: bool = False,
    agent_max_cost_usd: float | None = None,
    tiers: Iterable[Tier] | None = None,
) -> LLMRouter:
    """Create a ready-to-use LLMRouter with cache, cost guard, and providers wired up.

    tiers limits which tier providers are built (and thus which API keys must
    resolve). Default None builds all tiers; pass e.g. [Tier.S] for a task that
    only uses the cheap tier so a missing M/L key does not block it.
    """
    cache = LLMCache(llm_config.cache.path)
    guard = CostGuard(
        llm_config.cost_guards,
        ledger_path,
        agent_mode=agent_mode,
        agent_max_cost_usd=agent_max_cost_usd,
    )
    router = LLMRouter(llm_config, cache, guard)

    for tier in tiers if tiers is not None else list(Tier):
        router.register_provider(tier, _build_provider(tier, llm_config))

    return router
