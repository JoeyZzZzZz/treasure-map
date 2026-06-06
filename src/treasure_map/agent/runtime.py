# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Agent runtime — natural language → tool call loop.

Week 1 stub: scaffolds the class interface. Real implementation in Week 2+.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AgentEvent:
    type: str  # "thinking" | "tool_call" | "tool_progress" | "tool_result" | "response"
    data: dict[str, Any]


class TreasureMapAgent:
    """Main agent loop. Translates user natural language into tool calls."""

    def __init__(self, config: Any, tools: list[Any] | None = None) -> None:
        self._config = config
        self._tools: dict[str, Any] = {t.name: t for t in (tools or [])}
        self._conversation: list[dict[str, Any]] = []

    async def chat(self, user_message: str) -> AsyncIterator[AgentEvent]:
        """Handle one user turn, yielding events as they occur."""
        # TODO: implement in Week 2 when agent/tools are wired up
        logger.info("Agent received: %s", user_message)
        yield AgentEvent(type="response", data={"message": "Agent not yet implemented."})
