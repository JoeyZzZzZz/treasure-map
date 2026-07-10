# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Atlas — persistent cross-firmware pattern store.

Append-and-corroborate; never wiped. Schema in lib/storage/atlas_schema.sql.
"""

from __future__ import annotations

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import InstanceRow, PatternRow, RunRow
from treasure_map.lib.atlas.writer import (
    AtlasStats,
    add_instance,
    add_instances,
    begin_run,
    finish_run,
    upsert_pattern,
)

__all__ = [
    "AtlasStats",
    "InstanceRow",
    "PatternRow",
    "RunRow",
    "add_instance",
    "add_instances",
    "begin_run",
    "finish_run",
    "open_atlas",
    "upsert_pattern",
]
