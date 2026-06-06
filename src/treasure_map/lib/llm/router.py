# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol

from treasure_map.lib.cost_guard.guard import CheckResult, CostGuard
from treasure_map.lib.errors import CostLimitReachedError, ProviderError, UnknownTaskError
from treasure_map.lib.llm.task_registry import TASK_TIER_MAP
from treasure_map.lib.llm.types import BatchItem, LLMResponse, Tier
from treasure_map.lib.llm_cache.cache import LLMCache

if TYPE_CHECKING:
    from treasure_map.lib.config.config import LLMConfig

logger = logging.getLogger(__name__)


class LLMProvider(Protocol):
    """Minimal interface every provider must implement."""

    async def complete(
        self,
        prompt: str,
        input_text: str,
        max_tokens: int,
    ) -> LLMResponse: ...

    @property
    def model_id(self) -> str: ...


class LLMRouter:
    """Single entry point for all LLM calls.

    Execution order for each call:
      1. Validate task is registered
      2. cache.get → return cached result if hit
      3. cost_guard.check_before_call → enforce L4/L5 limits
      4. provider.complete with retry/backoff (4 attempts max, from config)
      5. cost_guard.record_call (L3 + L4 + L5 updates)
      6. cache.set
      7. Return LLMResponse
    """

    def __init__(
        self,
        config: LLMConfig,
        cache: LLMCache,
        cost_guard: CostGuard,
        providers: dict[Tier, LLMProvider] | None = None,
    ) -> None:
        self._cfg = config
        self._cache = cache
        self._guard = cost_guard
        self._providers: dict[Tier, LLMProvider] = providers or {}

    def register_provider(self, tier: Tier, provider: LLMProvider) -> None:
        self._providers[tier] = provider

    async def call(
        self,
        task: str,
        input_text: str,
        prompt: str,
        prompt_version: str,
        max_tokens: int = 1500,
        progress_callback: Callable[[str], None] | None = None,
    ) -> LLMResponse:
        """Main entry point. See class docstring for execution order."""
        if task not in TASK_TIER_MAP:
            raise UnknownTaskError(task)

        tier = TASK_TIER_MAP[task]

        # Step 1: cache check
        cached = self._cache.get(task, input_text, prompt_version)
        if cached is not None:
            return LLMResponse(
                content=cached.get("content", ""),
                model_id=cached.get("model_id", "cached"),
                cost_usd=0.0,
                cached=True,
                tier=tier,
                raw=cached,
            )

        # Step 2: L4/L5 guard
        if self._guard.is_task_blocked(task):
            raise CostLimitReachedError("L3_task_blocked", 0, 0)

        check = self._guard.check_before_call(task, tier.value)
        if check == CheckResult.DAILY_LIMIT:
            raise CostLimitReachedError(
                "daily",
                self._cfg.cost_guards.max_cost_per_day_usd,
                0,
            )
        if check == CheckResult.RUN_LIMIT:
            raise CostLimitReachedError(
                "run",
                self._cfg.cost_guards.max_cost_per_run_usd,
                0,
            )

        if progress_callback:
            progress_callback(f"calling {task} [{tier.value}]")

        # Step 3: call provider with retry
        provider = self._get_provider(tier)
        response = await self._call_with_retry(provider, prompt, input_text, max_tokens, task)

        # Step 4: record cost
        tier_cfg = getattr(self._cfg.tiers, tier.value)
        self._guard.record_call(
            task,
            tier.value,
            response.cost_usd,
            response.model_id,
            max_cost_per_call_usd=tier_cfg.max_cost_per_call_usd,
        )

        # Step 5: cache the result
        self._cache.set(
            task,
            input_text,
            prompt_version,
            response.model_id,
            tier.value,
            {"content": response.content, "model_id": response.model_id, **response.raw},
            response.cost_usd,
        )

        return response

    async def call_batch(
        self,
        task: str,
        items: list[BatchItem],
        prompt_builder: Callable[[list[BatchItem]], str],
        prompt_version: str,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> list[LLMResponse | None]:
        """Batch → single-item fallback pattern (adapted from 07_ai_summarize.py)."""
        if task not in TASK_TIER_MAP:
            raise UnknownTaskError(task)

        tier = TASK_TIER_MAP[task]
        concurrency = getattr(self._cfg.concurrency, tier.value)
        sem = asyncio.Semaphore(concurrency)
        results: list[LLMResponse | None] = [None] * len(items)

        async def process_one(idx: int, item: BatchItem) -> None:
            async with sem:
                if self._guard.is_stop_requested():
                    return
                prompt = prompt_builder([item])
                try:
                    results[idx] = await self.call(
                        task, item.input_text, prompt, prompt_version
                    )
                except (CostLimitReachedError, ProviderError) as exc:
                    logger.warning("Item %s failed: %s", item.id, exc)
                finally:
                    if progress_callback:
                        done = sum(1 for r in results if r is not None)
                        progress_callback(done, len(items))

        await asyncio.gather(*[process_one(i, item) for i, item in enumerate(items)])
        return results

    def _get_provider(self, tier: Tier) -> LLMProvider:
        provider = self._providers.get(tier)
        if provider is None:
            raise ProviderError(
                f"No provider registered for tier {tier.value}. "
                "Call router.register_provider() or check config."
            )
        return provider

    async def _call_with_retry(
        self,
        provider: LLMProvider,
        prompt: str,
        input_text: str,
        max_tokens: int,
        task: str,
    ) -> LLMResponse:
        retry_cfg = self._cfg.retry
        last_exc: Exception | None = None

        for attempt in range(retry_cfg.max_attempts):
            try:
                return await provider.complete(prompt, input_text, max_tokens)
            except ProviderError as exc:
                last_exc = exc
                if attempt < retry_cfg.max_attempts - 1:
                    wait = retry_cfg.backoff_base_seconds * (2**attempt)
                    logger.warning(
                        "Provider error for task=%s (attempt %d/%d), retrying in %.0fs: %s",
                        task,
                        attempt + 1,
                        retry_cfg.max_attempts,
                        wait,
                        exc,
                    )
                    await asyncio.sleep(wait)

        raise ProviderError(
            f"All {retry_cfg.max_attempts} attempts failed for task={task}"
        ) from last_exc
