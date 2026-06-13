# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for OpenAICompatProvider thinking control + TierConfig round-trip.

DeepSeek-V4 thinking defaults to ENABLED, so the provider must send an explicit
thinking param per tier. These tests assert the exact kwargs handed to
chat.completions.create for each tri-state, using a recording fake client (no network).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from treasure_map.lib.config.config import TierConfig
from treasure_map.lib.llm.providers.openai_compat import OpenAICompatProvider
from treasure_map.lib.llm.types import Tier


class _RecordingClient:
    """Stands in for AsyncOpenAI; records the kwargs passed to create()."""

    def __init__(self) -> None:
        self.create_kwargs: dict[str, Any] = {}
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    async def _create(self, **kwargs: Any) -> Any:
        self.create_kwargs = kwargs
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))],
            usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5),
        )


def _provider_with_recorder(
    *, thinking: bool | None, reasoning_effort: str | None = None
) -> tuple[OpenAICompatProvider, _RecordingClient]:
    provider = OpenAICompatProvider(
        model="deepseek-v4-flash",
        base_url="https://api.deepseek.com",
        api_key="sk-test",
        tier=Tier.S,
        thinking=thinking,
        reasoning_effort=reasoning_effort,
    )
    recorder = _RecordingClient()
    provider._client = recorder  # type: ignore[assignment]
    return provider, recorder


def _run(provider: OpenAICompatProvider) -> None:
    asyncio.run(provider.complete("system prompt", "user input", max_tokens=128))


# ── thinking tri-state → create() kwargs ─────────────────────────────────────────


def test_thinking_false_sends_explicit_disabled() -> None:
    provider, rec = _provider_with_recorder(thinking=False)
    _run(provider)
    assert rec.create_kwargs["extra_body"] == {"thinking": {"type": "disabled"}}
    assert "reasoning_effort" not in rec.create_kwargs


def test_thinking_true_sends_enabled_with_effort() -> None:
    provider, rec = _provider_with_recorder(thinking=True, reasoning_effort="high")
    _run(provider)
    assert rec.create_kwargs["extra_body"] == {"thinking": {"type": "enabled"}}
    assert rec.create_kwargs["reasoning_effort"] == "high"


def test_thinking_true_without_effort_omits_reasoning_effort() -> None:
    provider, rec = _provider_with_recorder(thinking=True)
    _run(provider)
    assert rec.create_kwargs["extra_body"] == {"thinking": {"type": "enabled"}}
    assert "reasoning_effort" not in rec.create_kwargs


def test_thinking_none_is_legacy_no_extra_body() -> None:
    provider, rec = _provider_with_recorder(thinking=None)
    _run(provider)
    # Legacy behavior: extra_body falls back to None, no thinking key, no reasoning_effort.
    assert rec.create_kwargs["extra_body"] is None
    assert "reasoning_effort" not in rec.create_kwargs


def test_common_kwargs_unchanged() -> None:
    provider, rec = _provider_with_recorder(thinking=None)
    _run(provider)
    assert rec.create_kwargs["model"] == "deepseek-v4-flash"
    assert rec.create_kwargs["max_tokens"] == 128
    assert rec.create_kwargs["temperature"] == 0


# ── TierConfig round-trip ────────────────────────────────────────────────────────


def test_tierconfig_round_trips_thinking_fields() -> None:
    cfg = TierConfig.model_validate(
        {
            "provider": "deepseek",
            "model": "deepseek-v4-flash",
            "base_url": "https://api.deepseek.com",
            "api_key_env": "DEEPSEEK_API_KEY",
            "thinking": True,
            "reasoning_effort": "high",
        }
    )
    assert cfg.thinking is True
    assert cfg.reasoning_effort == "high"


def test_tierconfig_defaults_preserve_none() -> None:
    cfg = TierConfig.model_validate(
        {
            "provider": "anthropic",
            "model": "claude-opus-4-7",
            "base_url": "https://api.anthropic.com/v1",
            "api_key_env": "ANTHROPIC_API_KEY",
        }
    )
    assert cfg.thinking is None
    assert cfg.reasoning_effort is None


def test_tierconfig_rejects_bad_reasoning_effort() -> None:
    with pytest.raises(ValidationError):
        TierConfig.model_validate(
            {
                "provider": "deepseek",
                "model": "deepseek-v4-flash",
                "base_url": "https://api.deepseek.com",
                "api_key_env": "DEEPSEEK_API_KEY",
                "reasoning_effort": "medium",  # only high|max accepted
            }
        )
