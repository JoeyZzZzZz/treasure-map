# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Atlas — cross-firmware pattern store (the moat, PRD §13).

Append-and-corroborate; never wiped. Schema in lib/storage/atlas_schema.sql.
"""

from __future__ import annotations

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow, PatternRow
from treasure_map.lib.atlas.writer import AtlasStats, add_instance, add_instances, upsert_pattern

__all__ = [
    "AtlasStats",
    "InstanceRow",
    "PatternRow",
    "add_instance",
    "add_instances",
    "open_atlas",
    "upsert_pattern",
]
