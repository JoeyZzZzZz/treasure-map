# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Anthropic (Claude) provider using the native Anthropic SDK."""

from __future__ import annotations

import logging

import anthropic as sdk

from treasure_map.lib.config.config import TierConfig
from treasure_map.lib.errors import ProviderError
from treasure_map.lib.llm.types import LLMResponse, Tier

logger = logging.getLogger(__name__)

# Approximate pricing per 1M tokens for cost estimation (USD)
_COST_PER_1M: dict[str, tuple[float, float]] = {
    "claude-opus-4-7": (15.0, 75.0),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-haiku-4-5-20251001": (0.25, 1.25),
}
_DEFAULT_COST = (3.0, 15.0)


def _estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    in_rate, out_rate = _COST_PER_1M.get(model, _DEFAULT_COST)
    return (input_tokens * in_rate + output_tokens * out_rate) / 1_000_000


class AnthropicProvider:
    """Calls Anthropic Claude via the native SDK."""

    def __init__(self, model: str, api_key: str, tier: Tier) -> None:
        self._model = model
        self._tier = tier
        self._client = sdk.AsyncAnthropic(api_key=api_key, max_retries=0)

    @property
    def model_id(self) -> str:
        return self._model

    async def complete(self, prompt: str, input_text: str, max_tokens: int) -> LLMResponse:
        try:
            resp = await self._client.messages.create(
                model=self._model,
                max_tokens=max_tokens,
                system=prompt,
                messages=[{"role": "user", "content": input_text}],
            )
        except sdk.RateLimitError as exc:
            raise ProviderError(f"Anthropic rate limit: {exc}") from exc
        except sdk.APIError as exc:
            raise ProviderError(f"Anthropic API error: {exc}") from exc
        except Exception as exc:
            raise ProviderError(f"Unexpected Anthropic error: {exc}") from exc

        content_blocks = [b.text for b in resp.content if hasattr(b, "text")]
        content = "\n".join(content_blocks)
        usage = resp.usage
        cost = _estimate_cost(self._model, usage.input_tokens, usage.output_tokens)

        return LLMResponse(
            content=content,
            model_id=self._model,
            cost_usd=cost,
            cached=False,
            tier=self._tier,
            raw={
                "usage": {
                    "input_tokens": usage.input_tokens,
                    "output_tokens": usage.output_tokens,
                }
            },
        )


def build_anthropic_provider(tier_cfg: TierConfig, tier: Tier) -> AnthropicProvider:
    return AnthropicProvider(
        model=tier_cfg.model,
        api_key=tier_cfg.resolve_api_key(),
        tier=tier,
    )
