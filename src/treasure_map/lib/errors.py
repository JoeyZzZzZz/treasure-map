# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations


class TreasureMapError(Exception):
    """Base class for all Treasure Map errors."""


class ConfigError(TreasureMapError):
    """Invalid or missing configuration."""


class WorkspaceError(TreasureMapError):
    """Workspace / checkpoint operation failed."""


class GhidraNotFoundError(TreasureMapError):
    """Ghidra installation not found."""


class InvalidFirmwareError(TreasureMapError):
    """Firmware path does not point to a valid filesystem root."""
