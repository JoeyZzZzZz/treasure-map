# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Integration test for GhidraRunner — skipped when Ghidra is not installed."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from treasure_map.lib.analyze.ghidra_runner import GhidraRunner
from treasure_map.lib.config.config import GhidraConfig

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "elfs"
_TRUE_ELF = _FIXTURES / "true_x86_64"

no_ghidra = shutil.which("analyzeHeadless") is None
no_fixture = not _TRUE_ELF.exists()


@pytest.mark.skipif(no_ghidra, reason="analyzeHeadless not in PATH")
@pytest.mark.skipif(no_fixture, reason="fixture true_x86_64 missing")
def test_run_ghidra_real_binary(tmp_path: Path) -> None:
    """Run Ghidra on the true_x86_64 fixture and verify output JSON structure."""
    runner = GhidraRunner(GhidraConfig())
    result = runner.run_ghidra(
        binary=_TRUE_ELF,
        output_dir=tmp_path / "output",
        timeout=120,
        arch="x86:LE:64:default",
        sha8="deadbeef",
    )

    assert result.success, f"Ghidra failed; log: {result.log_path}"
    assert result.output_file is not None
    assert result.output_file.exists()

    data = json.loads(result.output_file.read_text())
    assert "binary" in data
    assert "functions" in data
    assert "imports" in data
    assert "exports" in data
    assert "strings" in data
    assert isinstance(data["functions"], list)
