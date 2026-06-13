# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Neutral read-side aggregation views over the atlas.

density / twins / dormant — mechanism aggregations only. Every row is a lead/candidate;
nothing here scores, ranks, or judges.
"""

from __future__ import annotations

from treasure_map.lib.query.views import DensityRow, TwinRow, density, dormant, twins

__all__ = ["DensityRow", "TwinRow", "density", "dormant", "twins"]
