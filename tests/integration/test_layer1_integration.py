# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Integration tests for Layer 1: Cache + CostGuard + Router wired together.

These tests do NOT make real network requests. They verify that the full
stack (cache → guard → provider → record → cache-write) works end-to-end
using a mock provider.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from treasure_map.lib.cost_guard.guard import CostGuard
from treasure_map.lib.errors import CostLimitReachedError, UnknownTaskError
from treasure_map.lib.llm.router import LLMRouter
from treasure_map.lib.llm.types import LLMResponse, Tier
from treasure_map.lib.llm_cache.cache import LLMCache


class _CfgCostGuard:
    max_cost_per_run_usd = 5.0
    max_cost_per_day_usd = 20.0
    require_confirm_above_usd = 1.0


@dataclass
class _FakeTierCfg:
    provider: str = "deepseek"
    model: str = "deepseek-chat"
    base_url: str = "https://api.deepseek.com"
    api_key_env: str = "DEEPSEEK_API_KEY"
    max_cost_per_call_usd: float = 0.01

    def resolve_api_key(self) -> str:
        return "sk-fake"


class _FakeTiersCfg:
    S = _FakeTierCfg()
    M = _FakeTierCfg(model="deepseek-reasoner", max_cost_per_call_usd=0.10)
    L = _FakeTierCfg(provider="anthropic", model="claude-opus-4-7", max_cost_per_call_usd=1.00)


class _FakeLLMCfg:
    tiers = _FakeTiersCfg()
    cost_guards = _CfgCostGuard()

    class cache:  # noqa: N801
        enabled = True

    class concurrency:  # noqa: N801
        S = 50
        M = 20
        L = 5

    class retry:  # noqa: N801
        max_attempts = 2
        backoff_base_seconds = 0.01


class CountingProvider:
    def __init__(self, response: str = "ok", cost: float = 0.002) -> None:
        self._response = response
        self._cost = cost
        self.calls = 0

    @property
    def model_id(self) -> str:
        return "fake-model"

    async def complete(self, prompt: str, input_text: str, max_tokens: int) -> LLMResponse:
        self.calls += 1
        return LLMResponse(
            content=self._response,
            model_id=self.model_id,
            cost_usd=self._cost,
            cached=False,
            tier=Tier.S,
        )


def _make_stack(tmp_path, cost_cfg=None):
    cache = LLMCache(tmp_path / "cache.db")
    guard = CostGuard(cost_cfg or _CfgCostGuard(), tmp_path / "ledger.json")
    router = LLMRouter(_FakeLLMCfg(), cache, guard)
    provider = CountingProvider()
    for tier in Tier:
        router.register_provider(tier, provider)
    return router, cache, guard, provider


@pytest.mark.asyncio
async def test_full_stack_cache_hit_on_second_call(tmp_path):
    router, _, _, provider = _make_stack(tmp_path)
    args = ("function_summary", "int foo(){}\n---CALLEES---\n[]", "summarize", "v1")

    r1 = await router.call(*args)
    assert not r1.cached
    assert provider.calls == 1

    r2 = await router.call(*args)
    assert r2.cached
    assert provider.calls == 1  # no new network call


@pytest.mark.asyncio
async def test_cost_recorded_in_guard_and_ledger(tmp_path):
    router, _, guard, _ = _make_stack(tmp_path)
    await router.call("function_summary", "x\n---CALLEES---\n[]", "p", "v1")
    report = guard.report()
    assert report["total_calls"] == 1
    assert report["total_cost_usd"] > 0


@pytest.mark.asyncio
async def test_graceful_stop_on_run_limit(tmp_path):
    class TinyCfg:
        max_cost_per_run_usd = 0.001
        max_cost_per_day_usd = 100.0
        require_confirm_above_usd = 999.0

    router, _, guard, _ = _make_stack(tmp_path, TinyCfg())
    # First call should succeed then trigger stop
    await router.call("function_summary", "a\n---CALLEES---\n[]", "p", "v1")
    assert guard.is_stop_requested()

    # Second call should raise
    with pytest.raises(CostLimitReachedError):
        await router.call("function_summary", "b\n---CALLEES---\n[]", "p", "v1")


@pytest.mark.asyncio
async def test_prompt_version_bump_causes_re_call(tmp_path):
    router, _, _, provider = _make_stack(tmp_path)
    input_text = "int bar(){}\n---CALLEES---\n[]"

    await router.call("function_summary", input_text, "p", "summarize_v1")
    await router.call("function_summary", input_text, "p", "summarize_v2")
    # v2 is not cached, so provider is called for both
    assert provider.calls == 2


@pytest.mark.asyncio
async def test_unknown_task_raises_cleanly(tmp_path):
    router, _, _, _ = _make_stack(tmp_path)
    with pytest.raises(UnknownTaskError, match="not registered"):
        await router.call("ghost_task", "input", "prompt", "v1")


@pytest.mark.asyncio
async def test_offline_cache_replay(tmp_path):
    """Simulate 'offline' mode: populate cache, then router without network should hit cache."""
    cache = LLMCache(tmp_path / "cache.db")
    cache.set(
        "function_summary",
        "offline_fn\n---CALLEES---\n[]",
        "v1",
        "deepseek-chat",
        "S",
        {"content": "offline result"},
        0.001,
    )
    cache.close()

    # New router instance, no provider registered
    cache2 = LLMCache(tmp_path / "cache.db")
    guard2 = CostGuard(_CfgCostGuard(), tmp_path / "ledger.json")
    router2 = LLMRouter(_FakeLLMCfg(), cache2, guard2)
    # No provider registered — if cache misses, this would raise ProviderError

    result = await router2.call(
        "function_summary",
        "offline_fn\n---CALLEES---\n[]",
        "any_prompt",
        "v1",
    )
    assert result.cached
    assert result.content == "offline result"
    assert result.cost_usd == 0.0
