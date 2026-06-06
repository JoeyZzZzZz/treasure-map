# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations


class TreasureMapError(Exception):
    """Base class for all Treasure Map errors."""


class ConfigError(TreasureMapError):
    """Invalid or missing configuration."""


class WorkspaceError(TreasureMapError):
    """Workspace / checkpoint operation failed."""


class LLMCacheError(TreasureMapError):
    """LLM cache operation failed."""


class CostGuardError(TreasureMapError):
    """Cost guard limit exceeded."""


class CostLimitReachedError(CostGuardError):
    """A cost limit was triggered and the current run must stop."""

    def __init__(self, limit_type: str, limit_usd: float, actual_usd: float) -> None:
        self.limit_type = limit_type
        self.limit_usd = limit_usd
        self.actual_usd = actual_usd
        super().__init__(
            f"{limit_type} limit ${limit_usd:.4f} exceeded (actual ${actual_usd:.4f})"
        )


class UnknownTaskError(TreasureMapError):
    """Task name not registered in TASK_TIER_MAP."""

    def __init__(self, task: str) -> None:
        super().__init__(
            f"Task '{task}' is not registered in TASK_TIER_MAP. "
            "Register it in lib/llm/task_registry.py before calling router."
        )


class ProviderError(TreasureMapError):
    """LLM provider call failed after all retries."""


class GhidraNotFoundError(TreasureMapError):
    """Ghidra installation not found."""


class InvalidFirmwareError(TreasureMapError):
    """Firmware path does not point to a valid filesystem root."""
