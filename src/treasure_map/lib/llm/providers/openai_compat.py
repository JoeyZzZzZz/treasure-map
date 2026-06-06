# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""OpenAI-compatible HTTP client (used by DeepSeek and any OpenAI-compat endpoint)."""
from __future__ import annotations

import logging
from typing import Any, cast

from openai import APIError, AsyncOpenAI, RateLimitError

from treasure_map.lib.errors import ProviderError
from treasure_map.lib.llm.types import LLMResponse, Tier

logger = logging.getLogger(__name__)

# Pricing is approximate and changes over time; used only for cost estimation.
# Actual cost is computed from usage tokens when the API returns them.
_COST_PER_1M_TOKENS: dict[str, tuple[float, float]] = {
    "deepseek-chat": (0.27, 1.10),       # input, output per 1M tokens
    "deepseek-reasoner": (0.55, 2.19),
}
_DEFAULT_COST = (0.50, 2.00)


def _estimate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    input_rate, output_rate = _COST_PER_1M_TOKENS.get(model, _DEFAULT_COST)
    return (prompt_tokens * input_rate + completion_tokens * output_rate) / 1_000_000


class OpenAICompatProvider:
    """Wraps openai.AsyncOpenAI for any OpenAI-compatible endpoint."""

    def __init__(
        self,
        model: str,
        base_url: str,
        api_key: str,
        tier: Tier,
        timeout: float = 120.0,
    ) -> None:
        self._model = model
        self._tier = tier
        self._client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
            timeout=timeout,
            max_retries=0,  # retry handled by LLMRouter
        )

    @property
    def model_id(self) -> str:
        return self._model

    async def complete(self, prompt: str, input_text: str, max_tokens: int) -> LLMResponse:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": input_text},
        ]
        try:
            resp = await self._client.chat.completions.create(
                model=self._model,
                messages=cast("Any", messages),
                max_tokens=max_tokens,
                temperature=0,
            )
        except RateLimitError as exc:
            raise ProviderError(f"Rate limit: {exc}") from exc
        except APIError as exc:
            raise ProviderError(f"API error: {exc}") from exc
        except Exception as exc:
            raise ProviderError(f"Unexpected provider error: {exc}") from exc

        content = resp.choices[0].message.content or ""
        usage = resp.usage
        cost = 0.0
        if usage:
            cost = _estimate_cost(self._model, usage.prompt_tokens, usage.completion_tokens)

        return LLMResponse(
            content=content,
            model_id=self._model,
            cost_usd=cost,
            cached=False,
            tier=self._tier,
            raw={"usage": {"prompt_tokens": usage.prompt_tokens if usage else 0,
                           "completion_tokens": usage.completion_tokens if usage else 0}},
        )
