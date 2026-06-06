# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import json
import logging
from datetime import date
from pathlib import Path

logger = logging.getLogger(__name__)

_MAX_DAYS = 30


def _today() -> str:
    return date.today().isoformat()


class CostLedger:
    """Persistent daily cost tracker stored in a JSON file.

    Format: {"YYYY-MM-DD": {"total_usd": N, "by_tier": {"S": N, "M": N, "L": N}}}
    Only keeps the most recent _MAX_DAYS entries.
    """

    def __init__(self, ledger_path: Path) -> None:
        self.ledger_path = ledger_path
        self._data: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if self.ledger_path.exists():
            try:
                with self.ledger_path.open() as f:
                    self._data = json.load(f)
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Ledger corrupt, starting fresh: %s", exc)
                self._data = {}

    def _save(self) -> None:
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        # Prune old entries before saving
        all_days = sorted(self._data.keys(), reverse=True)
        self._data = {d: self._data[d] for d in all_days[:_MAX_DAYS]}
        with self.ledger_path.open("w") as f:
            json.dump(self._data, f, indent=2)

    def today_total(self) -> float:
        today = _today()
        return self._data.get(today, {}).get("total_usd", 0.0)

    def record(self, tier: str, cost_usd: float) -> None:
        today = _today()
        day = self._data.setdefault(today, {"total_usd": 0.0, "by_tier": {}})
        day["total_usd"] = round(day["total_usd"] + cost_usd, 6)
        tiers = day.setdefault("by_tier", {})
        tiers[tier] = round(tiers.get(tier, 0.0) + cost_usd, 6)
        self._save()

    def snapshot(self) -> dict:
        return dict(self._data)
