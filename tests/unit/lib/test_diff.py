# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Package-level guards for the version-diff pipeline (lib/diff).

The self-built-alignment differ was retired; what remains is the map-model pipeline (the
``alignment`` parse + the ``dimension_delta`` projection), reading the function rows that
``lib/hunt/function_rows`` loads. These tests pin the two properties that must survive the
retirement: that loader surfaces a missing input instead of masking it, and no module of the
pipeline carries judgment vocabulary or private-doc refs.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest

from treasure_map.lib.hunt.function_rows import load_functions

from ..boundary_words import listed_words_in

_SRC = Path(__file__).resolve().parents[3] / "src" / "treasure_map"
_DIFF_PKG = _SRC / "lib" / "diff"
# The row loader the pipeline reads through. It lived in lib/diff until it was moved to the
# package whose modules import it; the vocabulary guard follows the file, not the directory.
_FUNCTION_ROWS = _SRC / "lib" / "hunt" / "function_rows.py"


def test_load_functions_rejects_missing_db(tmp_path: Path) -> None:
    # Read-only mode does not create the file; a missing input surfaces, not masked.
    with pytest.raises(sqlite3.OperationalError):
        load_functions(tmp_path / "nope.db")


# ── BOUNDARY: no judgment vocabulary, no section cites ──────────────────────────────


def test_diff_package_is_boundary_clean() -> None:
    judgment = re.compile(
        r"vulnerab|severity|exploit|\bsecurity\b",
        re.IGNORECASE,
    )
    section_ref = re.compile(r"§|PRD\s")
    for path in [*_DIFF_PKG.glob("*.py"), _FUNCTION_ROWS]:
        text = path.read_text()
        assert not judgment.search(text), f"judgment vocab in {path.name}"
        assert not listed_words_in(text), f"listed vocab in {path.name}"
        assert not section_ref.search(text), f"section/private-doc ref in {path.name}"
