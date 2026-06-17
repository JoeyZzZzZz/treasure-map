# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""build_router provider dispatch is config-driven (no built-in bias toward any vendor).

A diff/A1 run picks its provider from the tier config's `provider` field; switching to
deepseek (or any OpenAI-compatible endpoint) is a config change, not a code change, and
must not require an ANTHROPIC key.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from treasure_map.lib.config.config import LLMConfig
from treasure_map.lib.llm.factory import build_router
from treasure_map.lib.llm.providers.openai_compat import OpenAICompatProvider
from treasure_map.lib.llm.types import Tier


def _deepseek_tier() -> dict[str, str]:
    return {
        "provider": "deepseek",
        "model": "deepseek-chat",
        "base_url": "https://api.deepseek.com",
        "api_key_env": "DEEPSEEK_API_KEY",
    }


def test_build_router_provider_is_config_driven_not_anthropic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No anthropic key in the environment; a deepseek-configured diff run must still build.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test-deepseek")

    tier = _deepseek_tier()
    cfg = LLMConfig.model_validate(
        {"tiers": {"S": tier, "M": tier, "L": tier}, "cache": {"path": str(tmp_path / "c.db")}}
    )

    # build_router resolves keys only for the tiers it builds; deepseek dispatch must not look
    # for an ANTHROPIC key. The M/L tiers the diff path uses build cleanly.
    router = build_router(cfg, tmp_path / "ledger.json", tiers=[Tier.M, Tier.L])

    # deepseek dispatches through the OpenAI-compatible provider (config-driven, not anthropic).
    provider = router._providers[Tier.M]  # noqa: SLF001 — assert the wired provider type
    assert isinstance(provider, OpenAICompatProvider)
    assert provider.model_id == "deepseek-chat"
