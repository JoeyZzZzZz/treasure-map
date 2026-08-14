# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Package-level guards for the version-diff pipeline (lib/diff).

The self-built-alignment differ was retired; what remains is the map-model pipeline
(layer0 parse + layer2 projection) plus the read-only ``loader``. These tests pin the two
properties that must survive the retirement: the loader surfaces a missing input instead of
masking it, and no module in the package carries judgment vocabulary or private-doc refs.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest

from treasure_map.lib.diff.loader import load_functions

_DIFF_PKG = Path(__file__).resolve().parents[3] / "src" / "treasure_map" / "lib" / "diff"


def test_load_functions_rejects_missing_db(tmp_path: Path) -> None:
    # Read-only mode does not create the file; a missing input surfaces, not masked.
    with pytest.raises(sqlite3.OperationalError):
        load_functions(tmp_path / "nope.db")


# ── BOUNDARY: no judgment vocabulary, no section cites ──────────────────────────────


def test_diff_package_is_boundary_clean() -> None:
    judgment = re.compile(
        r"fix_quality|incomplete_patch|vulnerab|severity|exploit|\bsecurity\b",
        re.IGNORECASE,
    )
    section_ref = re.compile(r"§|PRD\s")
    for path in _DIFF_PKG.glob("*.py"):
        text = path.read_text()
        assert not judgment.search(text), f"judgment vocab in {path.name}"
        assert not section_ref.search(text), f"section/private-doc ref in {path.name}"
