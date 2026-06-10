# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Agent tool wrapper for the analyze capability.

Thin async wrapper only — all logic lives in lib/analyze/pipeline.py.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, dict[str, Any]], None]

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
        },
        "required": ["fs_root"],
    },
}


async def analyze_firmware(
    fs_root: str,
    workspace: str | None = None,
    progress_callback: ProgressCallback | None = None,
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
    ws_path = (
        Path(workspace)
        if workspace
        else cfg.workspace_dir / f"analyze_{fs_path.name}_{uuid.uuid4().hex[:8]}"
    )

    try:
        with Workspace(ws_path) as ws:
            result = await run_analyze(fs_path, ws, cfg, progress_callback)
    except GhidraNotFoundError as exc:
        return {"status": "error", "message": str(exc)}
    except Exception as exc:
        logger.error("analyze_firmware failed: %s", exc, exc_info=True)
        return {"status": "error", "message": str(exc)}

    return {
        "status": "ok",
        "db_path": str(result.db_path),
        "binary_count": result.binary_count,
        "dirty_count": result.dirty_count,
        "ghidra_ok": result.ghidra_ok,
        "ghidra_failed": result.ghidra_failed,
        "ghidra_skipped": result.ghidra_skipped,
        "functions_ingested": result.functions_ingested,
        "imports_ingested": result.imports_ingested,
        "exports_ingested": result.exports_ingested,
        "strings_ingested": result.strings_ingested,
        "layer0_xrefs": result.layer0_xrefs,
        "layer1_xrefs": result.layer1_xrefs,
        "layer2_xrefs": result.layer2_xrefs,
        "layer3_xrefs": result.layer3_xrefs,
        "strings_classified": result.strings_classified,
        "total_xrefs": result.total_xrefs,
        "non_binary_files_ingested": result.non_binary_files_ingested,
        "script_calls_ingested": result.script_calls_ingested,
        "config_entries_ingested": result.config_entries_ingested,
        "credentials_ingested": result.credentials_ingested,
        "web_endpoints_ingested": result.web_endpoints_ingested,
        "elapsed_s": round(result.elapsed, 1),
    }
