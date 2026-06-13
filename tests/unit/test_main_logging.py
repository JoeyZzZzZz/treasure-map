# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""The root CLI group quiets third-party HTTP loggers unless --debug is set."""

from __future__ import annotations

import logging

import pytest

from treasure_map.cli.main import main

_NOISY = ("httpx", "httpcore", "openai", "anthropic")


@pytest.fixture(autouse=True)
def _reset_logger_levels() -> None:
    for name in _NOISY:
        logging.getLogger(name).setLevel(logging.NOTSET)


def test_noisy_loggers_quieted_without_debug() -> None:
    main.callback(debug=False)  # type: ignore[misc]
    for name in _NOISY:
        assert logging.getLogger(name).level == logging.WARNING


def test_noisy_loggers_verbose_under_debug() -> None:
    main.callback(debug=True)  # type: ignore[misc]
    # Left untouched (NOTSET) so they inherit the DEBUG root level.
    for name in _NOISY:
        assert logging.getLogger(name).level == logging.NOTSET
