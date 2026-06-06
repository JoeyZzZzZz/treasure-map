# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Agent tool wrapper for the analyze capability.

Thin wrapper only — calls lib/analyze/pipeline.py (to be implemented in Week 2).
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

TOOL_SCHEMA = {
    "name": "analyze_firmware",
    "description": (
        "Analyze an IoT firmware filesystem root to extract binaries, functions, "
        "cross-references, and component summaries. Returns a database path that "
        "other tools can query."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "fs_root": {
                "type": "string",
                "description": "Path to the extracted firmware filesystem root directory.",
            },
            "workspace": {
                "type": "string",
                "description": "Optional workspace directory path. Created if absent.",
            },
            "max_cost_usd": {
                "type": "number",
                "description": "Maximum LLM spend for this call (default: 0.50).",
            },
        },
        "required": ["fs_root"],
    },
}


async def analyze_firmware(
    fs_root: str,
    workspace: str | None = None,
    max_cost_usd: float = 0.50,
) -> dict[str, Any]:
    """Entry point called by the agent runtime.

    Week 1: stub implementation. Week 2 will wire lib/analyze/pipeline.py.
    """
    fs_path = Path(fs_root)
    if not fs_path.is_dir():
        return {"status": "error", "message": f"fs_root is not a directory: {fs_root}"}

    logger.info("analyze_firmware stub: fs_root=%s max_cost=%.2f", fs_root, max_cost_usd)
    return {
        "status": "not_implemented",
        "message": "analyze_firmware will be implemented in Week 2",
        "fs_root": str(fs_path),
        "max_cost_usd": max_cost_usd,
    }
