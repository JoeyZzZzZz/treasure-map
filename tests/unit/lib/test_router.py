# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

from dataclasses import dataclass

import pytest

from treasure_map.lib.cost_guard.guard import CostGuard
from treasure_map.lib.errors import CostLimitReachedError, UnknownTaskError
from treasure_map.lib.llm.router import LLMRouter
from treasure_map.lib.llm.types import LLMResponse, Tier
from treasure_map.lib.llm_cache.cache import LLMCache


class _FakeCostGuardConfig:
    max_cost_per_run_usd = 5.0
    max_cost_per_day_usd = 20.0
    require_confirm_above_usd = 1.0


@dataclass
class _FakeTierConfig:
    provider: str = "deepseek"
    model: str = "deepseek-chat"
    base_url: str = "https://api.deepseek.com"
    api_key_env: str = "DEEPSEEK_API_KEY"
    max_cost_per_call_usd: float = 0.01

    def resolve_api_key(self) -> str:
        return "sk-fake"


class _FakeTiersConfig:
    S = _FakeTierConfig()
    M = _FakeTierConfig(model="deepseek-reasoner", max_cost_per_call_usd=0.10)
    L = _FakeTierConfig(provider="anthropic", model="claude-opus-4-7", max_cost_per_call_usd=1.00)


class _FakeLLMConfig:
    tiers = _FakeTiersConfig()
    cost_guards = _FakeCostGuardConfig()

    class cache:  # noqa: N801
        enabled = True

    class concurrency:  # noqa: N801
        S = 50
        M = 20
        L = 5

    class retry:  # noqa: N801
        max_attempts = 4
        backoff_base_seconds = 0.01  # fast for tests


class MockProvider:
    def __init__(self, response_content: str = "mock summary", cost: float = 0.001) -> None:
        self._content = response_content
        self._cost = cost
        self.call_count = 0

    @property
    def model_id(self) -> str:
        return "mock-model"

    async def complete(self, prompt: str, input_text: str, max_tokens: int) -> LLMResponse:
        self.call_count += 1
        return LLMResponse(
            content=self._content,
            model_id=self.model_id,
            cost_usd=self._cost,
            cached=False,
            tier=Tier.S,
        )


def _make_router(tmp_path, provider: MockProvider | None = None):
    cache = LLMCache(tmp_path / "cache.db")
    guard = CostGuard(_FakeCostGuardConfig(), tmp_path / "ledger.json")
    router = LLMRouter(_FakeLLMConfig(), cache, guard)
    if provider:
        router.register_provider(Tier.S, provider)
        router.register_provider(Tier.M, provider)
        router.register_provider(Tier.L, provider)
    return router, cache, guard


@pytest.mark.asyncio
async def test_unknown_task_raises(tmp_path):
    router, _, _ = _make_router(tmp_path, MockProvider())
    with pytest.raises(UnknownTaskError):
        await router.call("nonexistent_task", "input", "prompt", "v1")


@pytest.mark.asyncio
async def test_cache_miss_calls_provider(tmp_path):
    provider = MockProvider("hello world")
    router, _, _ = _make_router(tmp_path, provider)
    result = await router.call(
        "function_summary",
        "int foo(){}\n---CALLEES---\n[]",
        "Summarize this",
        "summarize_v1",
    )
    assert result.content == "hello world"
    assert not result.cached
    assert provider.call_count == 1


@pytest.mark.asyncio
async def test_cache_hit_skips_provider(tmp_path):
    provider = MockProvider("first result")
    router, cache, _ = _make_router(tmp_path, provider)
    input_text = "int bar(){}\n---CALLEES---\n[]"

    # First call: populates cache
    await router.call("function_summary", input_text, "prompt", "summarize_v1")
    assert provider.call_count == 1

    # Second call: should hit cache
    result = await router.call("function_summary", input_text, "prompt", "summarize_v1")
    assert result.cached
    assert provider.call_count == 1  # provider not called again


@pytest.mark.asyncio
async def test_cost_recorded_after_call(tmp_path):
    provider = MockProvider(cost=0.005)
    router, _, guard = _make_router(tmp_path, provider)
    await router.call(
        "function_summary",
        "fn\n---CALLEES---\n[]",
        "prompt",
        "v1",
    )
    report = guard.report()
    assert report["total_calls"] == 1
    assert report["total_cost_usd"] == pytest.approx(0.005)


@pytest.mark.asyncio
async def test_run_limit_raises(tmp_path):
    cfg = _FakeCostGuardConfig()
    cfg.max_cost_per_run_usd = 0.001  # tiny limit

    cache = LLMCache(tmp_path / "cache.db")
    guard = CostGuard(cfg, tmp_path / "ledger.json")
    guard.record_call("function_summary", "S", 0.002, "mock-model")  # exceed limit

    router = LLMRouter(_FakeLLMConfig(), cache, guard)
    router.register_provider(Tier.S, MockProvider())

    with pytest.raises(CostLimitReachedError):
        await router.call("function_summary", "x\n---CALLEES---\n[]", "p", "v1")


@pytest.mark.asyncio
async def test_prompt_version_change_invalidates_cache(tmp_path):
    provider = MockProvider()
    router, _, _ = _make_router(tmp_path, provider)
    input_text = "int baz(){}\n---CALLEES---\n[]"

    await router.call("function_summary", input_text, "prompt", "summarize_v1")
    assert provider.call_count == 1

    # Different prompt_version → cache miss → provider called again
    await router.call("function_summary", input_text, "prompt", "summarize_v2")
    assert provider.call_count == 2
