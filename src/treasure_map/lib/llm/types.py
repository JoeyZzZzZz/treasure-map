# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Tier(StrEnum):
    S = "S"
    M = "M"
    L = "L"


@dataclass
class LLMResponse:
    content: str
    model_id: str
    cost_usd: float
    cached: bool
    tier: Tier
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "content": self.content,
            "model_id": self.model_id,
            "cost_usd": self.cost_usd,
            "cached": self.cached,
            "tier": self.tier.value,
        }


@dataclass
class BatchItem:
    id: str
    input_text: str
    metadata: dict[str, Any] = field(default_factory=dict)
