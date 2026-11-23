# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Version-diff pipeline — map-model projection over an EXTERNAL alignment.

The alignment between two firmware versions is produced by an external, deterministic
differ (BinExport + BinDiff) and parsed into the atlas by ``alignment``; ``dimension_delta``
then PROJECTS each already-computed dimension annotation into a tri-state delta. Neither
layer re-analyses, judges quality, or invents a change verdict — a delta is a projection,
never a defect. Submodules are imported by their full path; this package intentionally
re-exports nothing.
"""

from __future__ import annotations
