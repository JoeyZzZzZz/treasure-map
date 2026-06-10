# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Non-binary file analysis framework.

Adding an ingester: implement its module, then append its NonBinaryIngester here.
Order matters: first detect()-match wins.

Current registry:
  [0] shell_script  — ShellScript ingester (Round C)
  [1] config_file   — ConfigFile ingester (Round D)
  [ ] credential    — placeholder (Round E)
  [ ] web_asset     — placeholder (Round F, M2)
  [ ] kernel_module — placeholder (Round G, M3)
"""

from __future__ import annotations

from treasure_map.lib.analyze.non_binary.config_file import CONFIG_FILE_INGESTER
from treasure_map.lib.analyze.non_binary.framework import (
    DetectFn,
    IngestFn,
    NonBinaryFile,
    NonBinaryIngester,
)
from treasure_map.lib.analyze.non_binary.orchestrator import NonBinaryStats, run_all_ingesters
from treasure_map.lib.analyze.non_binary.shell_script import SHELL_SCRIPT_INGESTER

INGESTER_REGISTRY: list[NonBinaryIngester] = [
    SHELL_SCRIPT_INGESTER,
    CONFIG_FILE_INGESTER,
    # Round E: credential ingester (append here)
    # Round F: web_asset ingester (append here, M2)
    # Round G: kernel_module ingester (append here, M3)
]

__all__ = [
    "INGESTER_REGISTRY",
    "CONFIG_FILE_INGESTER",
    "DetectFn",
    "IngestFn",
    "NonBinaryFile",
    "NonBinaryIngester",
    "NonBinaryStats",
    "run_all_ingesters",
]
