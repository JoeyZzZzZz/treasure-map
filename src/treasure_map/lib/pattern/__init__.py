# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Call-sequence pattern primitive.

Given one analysis.db, find functions whose callee set forms a dangerous call-sequence
shape and compute a coarse structural fingerprint for each. Pure-static, hermetic (no
LLM); returns in-memory candidate shapes — it writes nothing, claims no bug, and depends
on no downstream store.
"""

from __future__ import annotations

from treasure_map.lib.pattern.models import PatternMatch, ScanResult
from treasure_map.lib.pattern.scanner import scan

__all__ = ["PatternMatch", "ScanResult", "scan"]
