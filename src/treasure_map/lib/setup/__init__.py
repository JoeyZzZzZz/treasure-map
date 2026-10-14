# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Setup — `tmap init` / `tmap doctor` / `tmap uninstall`: config, the pinned toolchain (the only
network access tmap has, after the plan is confirmed) and agent registration."""

from __future__ import annotations

from treasure_map.lib.setup.initializer import InitResult, run_init

__all__ = ["InitResult", "run_init"]
