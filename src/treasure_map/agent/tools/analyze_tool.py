# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Agent tool wrapper for the analyze capability.

Thin async wrapper only — all logic lives in lib/analyze/pipeline.py.
"""

from __future__ import annotations

import logging
import uuid
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
    """Entry point called by the agent runtime."""
    from treasure_map.lib.analyze.pipeline import run_analyze
    from treasure_map.lib.config.config import load_config
    from treasure_map.lib.errors import GhidraNotFoundError
    from treasure_map.lib.workspace.workspace import Workspace

    fs_path = Path(fs_root)
    if not fs_path.is_dir():
        return {"status": "error", "message": f"fs_root is not a directory: {fs_root}"}

    cfg = load_config()
    # max_cost_usd will wire into LLM cost guard in Week 3 (no LLM calls yet)

    ws_path = (
        Path(workspace)
        if workspace
        else cfg.workspace_dir / f"analyze_{fs_path.name}_{uuid.uuid4().hex[:8]}"
    )

    try:
        with Workspace(ws_path) as ws:
            result = await run_analyze(fs_path, ws, cfg)
    except GhidraNotFoundError as exc:
        return {"status": "error", "message": str(exc)}
    except Exception as exc:
        logger.error("analyze_firmware failed: %s", exc, exc_info=True)
        return {"status": "error", "message": str(exc)}

    return {
        "status": "ok",
        "db_path": str(result.db_path),
        "binary_count": result.binary_count,
        "ghidra_ok": result.ghidra_ok,
        "ghidra_failed": result.ghidra_failed,
        "elapsed_s": round(result.elapsed, 1),
    }
