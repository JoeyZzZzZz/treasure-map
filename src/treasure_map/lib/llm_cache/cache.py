# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
from pathlib import Path
from typing import Any, cast

from treasure_map.lib.errors import LLMCacheError

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS llm_cache (
    cache_key       TEXT PRIMARY KEY,
    task_type       TEXT NOT NULL,
    input_hash      TEXT NOT NULL,
    prompt_version  TEXT NOT NULL,
    model_id        TEXT NOT NULL,
    tier            TEXT NOT NULL,
    response_json   TEXT NOT NULL,
    cost_usd        REAL DEFAULT 0,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_hit_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    hit_count       INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_llm_cache_task  ON llm_cache(task_type);
CREATE INDEX IF NOT EXISTS idx_llm_cache_model ON llm_cache(model_id);
"""

_WS_RE = re.compile(r"\s+")


def _normalize_whitespace(text: str) -> str:
    """Collapse runs of whitespace, strip leading/trailing, unify newlines."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [_WS_RE.sub(" ", line).strip() for line in text.split("\n")]
    return "\n".join(lines)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _input_hash_for(task_type: str, input_text: str) -> str:
    """Compute a deterministic hash of the normalized input for *task_type*."""
    if task_type == "function_summary":
        # input_text is expected to be "<pseudocode>\n---CALLEES---\n<json list>"
        parts = input_text.split("\n---CALLEES---\n", 1)
        pcode = _normalize_whitespace(parts[0])
        callees: list[str] = json.loads(parts[1]) if len(parts) > 1 else []
        return _sha256(pcode + "\n" + json.dumps(sorted(callees)))

    if task_type == "patch_verdict":
        # input_text is expected to be "<old_pcode>\n---NEW---\n<new_pcode>"
        parts = input_text.split("\n---NEW---\n", 1)
        old = _normalize_whitespace(parts[0])
        new = _normalize_whitespace(parts[1]) if len(parts) > 1 else ""
        return _sha256(old + "\n----\n" + new)

    # Generic fallback: normalize and hash as-is
    return _sha256(_normalize_whitespace(input_text))


def _cache_key(task_type: str, input_text: str, prompt_version: str) -> str:
    ih = _input_hash_for(task_type, input_text)
    return _sha256(task_type + ih + prompt_version)


class LLMCache:
    """SQLite-backed cache for LLM responses, keyed by (task_type, input, prompt_version)."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        logger.debug("LLMCache opened at %s", db_path)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> LLMCache:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def get(self, task_type: str, input_text: str, prompt_version: str) -> dict[str, Any] | None:
        """Return cached response dict on hit, None on miss. Updates hit metadata."""
        key = _cache_key(task_type, input_text, prompt_version)
        row = self._conn.execute(
            "SELECT response_json FROM llm_cache WHERE cache_key = ?", (key,)
        ).fetchone()
        if row is None:
            logger.debug("Cache miss: task=%s pv=%s", task_type, prompt_version)
            return None
        try:
            self._conn.execute(
                "UPDATE llm_cache SET hit_count = hit_count + 1, "
                "last_hit_at = CURRENT_TIMESTAMP WHERE cache_key = ?",
                (key,),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            logger.warning("Failed to update hit metadata: %s", exc)
        logger.debug("Cache hit: task=%s pv=%s", task_type, prompt_version)
        return cast("dict[str, Any]", json.loads(row["response_json"]))

    def set(
        self,
        task_type: str,
        input_text: str,
        prompt_version: str,
        model_id: str,
        tier: str,
        response: dict[str, Any],
        cost_usd: float,
    ) -> None:
        """Write or overwrite a cache entry."""
        key = _cache_key(task_type, input_text, prompt_version)
        ih = _input_hash_for(task_type, input_text)
        try:
            self._conn.execute(
                """INSERT OR REPLACE INTO llm_cache
                   (cache_key, task_type, input_hash, prompt_version,
                    model_id, tier, response_json, cost_usd)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    key,
                    task_type,
                    ih,
                    prompt_version,
                    model_id,
                    tier,
                    json.dumps(response),
                    cost_usd,
                ),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            raise LLMCacheError(f"Cache write failed: {exc}") from exc
        logger.debug("Cache set: task=%s pv=%s model=%s", task_type, prompt_version, model_id)

    def stats(self) -> dict[str, Any]:
        """Return aggregate cache statistics."""
        total = self._conn.execute("SELECT COUNT(*) FROM llm_cache").fetchone()[0]
        hits_total = self._conn.execute(
            "SELECT COALESCE(SUM(hit_count), 0) FROM llm_cache"
        ).fetchone()[0]

        by_task: dict[str, int] = {}
        for row in self._conn.execute(
            "SELECT task_type, SUM(hit_count) as h FROM llm_cache GROUP BY task_type"
        ):
            by_task[row["task_type"]] = row["h"]

        by_model: dict[str, int] = {}
        for row in self._conn.execute(
            "SELECT model_id, SUM(hit_count) as h FROM llm_cache GROUP BY model_id"
        ):
            by_model[row["model_id"]] = row["h"]

        return {
            "total_entries": total,
            "hits_total": hits_total,
            "by_task": by_task,
            "by_model": by_model,
        }

    def purge_by_prompt_version(self, task_type: str, prompt_version: str) -> int:
        """Delete all cache entries for a given task + prompt version. Returns count deleted."""
        cursor = self._conn.execute(
            "DELETE FROM llm_cache WHERE task_type = ? AND prompt_version = ?",
            (task_type, prompt_version),
        )
        self._conn.commit()
        deleted = cursor.rowcount
        logger.info("Purged %d entries for task=%s pv=%s", deleted, task_type, prompt_version)
        return deleted
