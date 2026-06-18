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


class OpenAICompatProvider:
    """Wraps openai.AsyncOpenAI for any OpenAI-compatible endpoint."""

    def __init__(
        self,
        model: str,
        base_url: str,
        api_key: str,
        tier: Tier,
        timeout: float = 120.0,
        thinking: bool | None = None,
        reasoning_effort: str | None = None,
        input_price_per_1m: float | None = None,
        output_price_per_1m: float | None = None,
    ) -> None:
        self._model = model
        self._tier = tier
        self._thinking = thinking
        self._reasoning_effort = reasoning_effort
        self._input_price_per_1m = input_price_per_1m
        self._output_price_per_1m = output_price_per_1m
        self._client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
            timeout=timeout,
            max_retries=0,  # retry handled by LLMRouter
        )

    @property
    def model_id(self) -> str:
        return self._model

    def _estimate_cost(self, prompt_tokens: int, completion_tokens: int) -> float | None:
        """Real cost from operator-supplied prices × token usage; None if prices unset.

        The tool ships no vendor prices. When the operator has not configured both prices,
        real cost is unknown — return None so the cost-guard falls back to count-based
        accounting rather than inventing a dollar figure.
        """
        if self._input_price_per_1m is None or self._output_price_per_1m is None:
            return None
        return (
            prompt_tokens * self._input_price_per_1m + completion_tokens * self._output_price_per_1m
        ) / 1_000_000

    async def complete(self, prompt: str, input_text: str, max_tokens: int) -> LLMResponse:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": input_text},
        ]
        # DeepSeek-V4 thinking is default-on, so we only touch it when explicitly set.
        # None -> send nothing (legacy behavior, byte-identical to before this option).
        extra_body: dict[str, Any] = {}
        create_kwargs: dict[str, Any] = {}
        if self._thinking is not None:
            extra_body["thinking"] = {"type": "enabled" if self._thinking else "disabled"}
            if self._thinking and self._reasoning_effort:
                # openai>=2.x accepts reasoning_effort as a first-class kwarg.
                create_kwargs["reasoning_effort"] = self._reasoning_effort
        try:
            resp = await self._client.chat.completions.create(
                model=self._model,
                messages=cast("Any", messages),
                max_tokens=max_tokens,
                temperature=0,  # accepted-but-ignored in thinking mode; harmless
                extra_body=extra_body or None,
                **create_kwargs,
            )
        except RateLimitError as exc:
            raise ProviderError(f"Rate limit: {exc}") from exc
        except APIError as exc:
            raise ProviderError(f"API error: {exc}") from exc
        except Exception as exc:
            raise ProviderError(f"Unexpected provider error: {exc}") from exc

        content = resp.choices[0].message.content or ""
        usage = resp.usage
        cost = self._estimate_cost(usage.prompt_tokens, usage.completion_tokens) if usage else None

        return LLMResponse(
            content=content,
            model_id=self._model,
            cost_usd=cost,
            cached=False,
            tier=self._tier,
            raw={
                "usage": {
                    "prompt_tokens": usage.prompt_tokens if usage else 0,
                    "completion_tokens": usage.completion_tokens if usage else 0,
                }
            },
        )
