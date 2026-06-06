# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import pytest

from treasure_map.lib.cost_guard.guard import CheckResult, CostGuard
from treasure_map.lib.cost_guard.ledger import CostLedger


class _MockCostGuardConfig:
    max_cost_per_run_usd = 1.0
    max_cost_per_day_usd = 10.0
    require_confirm_above_usd = 0.5


def _make_guard(tmp_path, run_limit=None, agent=False, agent_max=None):
    cfg = _MockCostGuardConfig()
    if run_limit is not None:
        cfg.max_cost_per_run_usd = run_limit
    return CostGuard(
        cfg,
        tmp_path / "ledger.json",
        agent_mode=agent,
        agent_max_cost_usd=agent_max,
    )


def test_initial_check_ok(tmp_path):
    guard = _make_guard(tmp_path)
    assert guard.check_before_call("function_summary", "S") == CheckResult.OK


def test_run_limit_triggers_stop(tmp_path):
    guard = _make_guard(tmp_path, run_limit=0.05)
    guard.record_call("function_summary", "S", 0.06, "deepseek-chat")
    assert guard.is_stop_requested()
    assert guard.check_before_call("function_summary", "S") == CheckResult.RUN_LIMIT


def test_l3_circuit_breaker(tmp_path):
    guard = _make_guard(tmp_path)
    guard.record_call("function_summary", "S", 0.50, "deepseek-chat", max_cost_per_call_usd=0.01)
    assert guard.is_task_blocked("function_summary")


def test_daily_limit(tmp_path):
    cfg = _MockCostGuardConfig()
    cfg.max_cost_per_day_usd = 0.01
    guard = CostGuard(cfg, tmp_path / "ledger.json")
    guard.record_call("function_summary", "S", 0.02, "deepseek-chat")
    assert guard.check_before_call("function_summary", "S") == CheckResult.DAILY_LIMIT


def test_report_structure(tmp_path):
    guard = _make_guard(tmp_path)
    guard.record_call("function_summary", "S", 0.01, "deepseek-chat")
    report = guard.report()
    assert report["total_calls"] == 1
    assert report["total_cost_usd"] == pytest.approx(0.01)
    assert "S" in report["by_tier"]
    assert "function_summary" in report["by_task"]


def test_agent_mode_uses_default_limit(tmp_path):
    """Agent mode without explicit budget defaults to min(0.5, run_limit)."""
    guard = _make_guard(tmp_path, run_limit=2.0, agent=True)
    assert guard._run_limit == pytest.approx(0.50)


def test_agent_mode_explicit_budget(tmp_path):
    guard = _make_guard(tmp_path, agent=True, agent_max=0.25)
    assert guard._run_limit == pytest.approx(0.25)


def test_ledger_persistence(tmp_path):
    ledger_path = tmp_path / "ledger.json"
    ledger = CostLedger(ledger_path)
    ledger.record("S", 0.05)
    assert ledger.today_total() == pytest.approx(0.05)

    ledger2 = CostLedger(ledger_path)
    assert ledger2.today_total() == pytest.approx(0.05)
