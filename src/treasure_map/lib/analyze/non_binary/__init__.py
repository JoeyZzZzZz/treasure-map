# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Non-binary file analysis framework.

Adding an ingester: implement its module, then append its NonBinaryIngester here.
Order matters: first detect()-match wins.

Current registry:
  [0] shell_script  — ShellScript ingester (Round C)
  [1] config_file   — ConfigFile ingester (Round D)
  [2] credential    — Credential ingester (Round E)
  [3] web_asset     — WebAsset ingester (Round F, M2)
  [ ] kernel_module — placeholder (Round G, M3)
"""

from __future__ import annotations

from treasure_map.lib.analyze.non_binary.config_file import CONFIG_FILE_INGESTER
from treasure_map.lib.analyze.non_binary.credential import CREDENTIAL_INGESTER
from treasure_map.lib.analyze.non_binary.framework import (
    DetectFn,
    IngestFn,
    NonBinaryFile,
    NonBinaryIngester,
)
from treasure_map.lib.analyze.non_binary.orchestrator import NonBinaryStats, run_all_ingesters
from treasure_map.lib.analyze.non_binary.shell_script import SHELL_SCRIPT_INGESTER
from treasure_map.lib.analyze.non_binary.web_asset import WEB_ASSET_INGESTER

INGESTER_REGISTRY: list[NonBinaryIngester] = [
    SHELL_SCRIPT_INGESTER,  # [0] Round C
    CONFIG_FILE_INGESTER,  # [1] Round D
    CREDENTIAL_INGESTER,  # [2] Round E
    WEB_ASSET_INGESTER,  # [3] Round F
    # Round G: kernel_module ingester (append here, M3)
]

__all__ = [
    "INGESTER_REGISTRY",
    "CONFIG_FILE_INGESTER",
    "CREDENTIAL_INGESTER",
    "DetectFn",
    "IngestFn",
    "NonBinaryFile",
    "NonBinaryIngester",
    "NonBinaryStats",
    "WEB_ASSET_INGESTER",
    "run_all_ingesters",
]
