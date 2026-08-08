# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Atlas — persistent cross-firmware pattern store.

Append-and-corroborate; never wiped. Schema in lib/storage/atlas_schema.sql.
"""

from __future__ import annotations

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import (
    InstanceRow,
    PatternRow,
    PublicCvePatternRow,
    RunRow,
)
from treasure_map.lib.atlas.writer import (
    AtlasStats,
    add_instance,
    add_instances,
    add_private_exploit,
    add_public_cve_patterns,
    begin_run,
    delete_private_exploit,
    finish_run,
    upsert_pattern,
)

__all__ = [
    "AtlasStats",
    "InstanceRow",
    "PatternRow",
    "PublicCvePatternRow",
    "RunRow",
    "add_instance",
    "add_instances",
    "add_private_exploit",
    "add_public_cve_patterns",
    "begin_run",
    "delete_private_exploit",
    "finish_run",
    "open_atlas",
    "upsert_pattern",
]
