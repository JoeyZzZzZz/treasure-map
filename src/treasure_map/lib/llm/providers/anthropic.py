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


class AnthropicProvider:
    """Calls Anthropic Claude via the native SDK."""

    def __init__(
        self,
        model: str,
        api_key: str,
        tier: Tier,
        input_price_per_1m: float | None = None,
        output_price_per_1m: float | None = None,
    ) -> None:
        self._model = model
        self._tier = tier
        self._input_price_per_1m = input_price_per_1m
        self._output_price_per_1m = output_price_per_1m
        self._client = sdk.AsyncAnthropic(api_key=api_key, max_retries=0)

    @property
    def model_id(self) -> str:
        return self._model

    def _estimate_cost(self, input_tokens: int, output_tokens: int) -> float | None:
        """Real cost from operator-supplied prices × token usage; None if prices unset.

        The tool ships no vendor prices. When the operator has not configured both prices,
        real cost is unknown — return None so the cost-guard falls back to count-based
        accounting rather than inventing a dollar figure.
        """
        if self._input_price_per_1m is None or self._output_price_per_1m is None:
            return None
        return (
            input_tokens * self._input_price_per_1m + output_tokens * self._output_price_per_1m
        ) / 1_000_000

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
        cost = self._estimate_cost(usage.input_tokens, usage.output_tokens)

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
        input_price_per_1m=tier_cfg.input_price_per_1m,
        output_price_per_1m=tier_cfg.output_price_per_1m,
    )
