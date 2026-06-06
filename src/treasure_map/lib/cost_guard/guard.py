# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from treasure_map.lib.cost_guard.ledger import CostLedger

logger = logging.getLogger(__name__)


class CheckResult(Enum):
    OK = "ok"
    DAILY_LIMIT = "daily_limit"
    RUN_LIMIT = "run_limit"


@dataclass
class RunStats:
    total_calls: int = 0
    total_cost_usd: float = 0.0
    by_tier: dict[str, float] = field(default_factory=dict)
    by_task: dict[str, int] = field(default_factory=dict)
    blocked_tasks: set[str] = field(default_factory=set)


class CostGuard:
    """Six-layer cost defence for LLM spending.

    L1: Config defaults loaded at init.
    L2: estimate_and_confirm() — pre-run estimate (CLI only).
    L3: record_call() — per-call circuit breaker.
    L4: check_before_call() + is_stop_requested() — run accumulation cap.
    L5: check_before_call() — daily cap via ledger.
    L6: retry limits enforced by providers (not here).
    """

    def __init__(
        self,
        config: Any,  # CostGuardConfig
        ledger_path: Path,
        *,
        agent_mode: bool = False,
        agent_max_cost_usd: float | None = None,
    ) -> None:
        self._cfg = config
        self._ledger = CostLedger(ledger_path)
        self._agent_mode = agent_mode
        self._run_stats = RunStats()
        self._stop_flag = False

        # In agent mode, apply independent per-call budget
        self._run_limit = (
            agent_max_cost_usd
            if agent_mode and agent_max_cost_usd is not None
            else min(0.50, config.max_cost_per_run_usd) if agent_mode
            else config.max_cost_per_run_usd
        )

    # ── L2: pre-run estimate ──────────────────────────────────────────────────

    def estimate_and_confirm(
        self,
        task_type: str,
        expected_calls: int,
        tier: str,
        avg_cost_per_call: float = 0.01,
    ) -> bool:
        """Estimate total cost and prompt for confirmation if above threshold.

        In agent mode this always returns True (no interactive TTY).
        Returns True to proceed, False if user declined.
        """
        estimated = expected_calls * avg_cost_per_call
        threshold = self._cfg.require_confirm_above_usd

        if estimated <= threshold:
            return True

        if self._agent_mode:
            logger.info(
                "Agent mode: skipping confirmation for estimated $%.4f (threshold $%.4f)",
                estimated,
                threshold,
            )
            return True

        # CLI mode: ask user
        import click  # local import to avoid hard dependency in agent paths

        answer = click.confirm(
            f"Estimated cost ${estimated:.4f} for {expected_calls} × {task_type} calls "
            f"(tier {tier}). Proceed?",
            default=False,
        )
        return bool(answer)

    # ── L4 + L5: pre-call checks ─────────────────────────────────────────────

    def check_before_call(self, task_type: str, tier: str) -> CheckResult:
        """Run L4 (run limit) and L5 (daily limit) checks before each LLM call."""
        if self._stop_flag:
            return CheckResult.RUN_LIMIT

        # L5: daily limit
        today_total = self._ledger.today_total()
        if today_total >= self._cfg.max_cost_per_day_usd:
            logger.warning(
                "Daily cost limit $%.4f reached (spent $%.4f today)",
                self._cfg.max_cost_per_day_usd,
                today_total,
            )
            return CheckResult.DAILY_LIMIT

        # L4: run limit
        if self._run_stats.total_cost_usd >= self._run_limit:
            logger.warning(
                "Run cost limit $%.4f reached (spent $%.4f this run)",
                self._run_limit,
                self._run_stats.total_cost_usd,
            )
            self._stop_flag = True
            return CheckResult.RUN_LIMIT

        return CheckResult.OK

    # ── L3: per-call circuit breaker + L4/L5 record ──────────────────────────

    def record_call(
        self,
        task_type: str,
        tier: str,
        cost_usd: float,
        model_id: str,
        *,
        max_cost_per_call_usd: float | None = None,
    ) -> None:
        """Record a completed LLM call. Triggers L3 circuit breaker if cost is excessive."""
        # L3: single-call circuit breaker
        if max_cost_per_call_usd and cost_usd > max_cost_per_call_usd:
            self._run_stats.blocked_tasks.add(task_type)
            logger.warning(
                "L3 circuit breaker: call cost $%.6f > limit $%.6f for task=%s; "
                "blocking further calls for this task",
                cost_usd,
                max_cost_per_call_usd,
                task_type,
            )

        # Accumulate
        self._run_stats.total_calls += 1
        self._run_stats.total_cost_usd = round(
            self._run_stats.total_cost_usd + cost_usd, 6
        )
        self._run_stats.by_tier[tier] = round(
            self._run_stats.by_tier.get(tier, 0.0) + cost_usd, 6
        )
        self._run_stats.by_task[task_type] = self._run_stats.by_task.get(task_type, 0) + 1

        # L5: persist to daily ledger
        self._ledger.record(tier, cost_usd)

        # L4: check if we've hit the run limit
        if self._run_stats.total_cost_usd >= self._run_limit:
            logger.warning(
                "L4 graceful stop triggered: run total $%.4f >= limit $%.4f",
                self._run_stats.total_cost_usd,
                self._run_limit,
            )
            self._stop_flag = True

    def is_stop_requested(self) -> bool:
        """True when L4 graceful stop has been triggered."""
        return self._stop_flag

    def is_task_blocked(self, task_type: str) -> bool:
        """True when L3 circuit breaker fired for this task."""
        return task_type in self._run_stats.blocked_tasks

    def report(self) -> dict[str, Any]:
        """Summary of this run's spending, suitable for CLI/Agent output."""
        return {
            "total_calls": self._run_stats.total_calls,
            "total_cost_usd": self._run_stats.total_cost_usd,
            "run_limit_usd": self._run_limit,
            "stop_triggered": self._stop_flag,
            "by_tier": dict(self._run_stats.by_tier),
            "by_task": dict(self._run_stats.by_task),
            "blocked_tasks": sorted(self._run_stats.blocked_tasks),
            "today_total_usd": self._ledger.today_total(),
        }
