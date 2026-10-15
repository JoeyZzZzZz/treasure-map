# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Non-binary file analysis framework.

Adding an ingester: implement its module, then append its NonBinaryIngester here.
Order matters: first detect()-match wins.

Current registry:
  [0] shell_script  — ShellScript ingester
  [1] config_file   — ConfigFile ingester
  [2] credential    — Credential ingester
  [3] web_asset     — WebAsset ingester
  [ ] kernel_module — placeholder (not implemented)
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
    SHELL_SCRIPT_INGESTER,  # [0]
    CONFIG_FILE_INGESTER,  # [1]
    CREDENTIAL_INGESTER,  # [2]
    WEB_ASSET_INGESTER,  # [3]
    # a kernel_module ingester would be appended here
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
