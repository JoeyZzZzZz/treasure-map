# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only

from treasure_map import __version__


def test_version_is_defined() -> None:
    """Smoke test: version is accessible."""
    assert __version__
    assert isinstance(__version__, str)
