# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Integration test for GhidraRunner — skipped when Ghidra is not installed."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from treasure_map.lib.analyze.ghidra_runner import GhidraRunner
from treasure_map.lib.config.config import GhidraConfig

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "elfs"
_EXE_ELF = _FIXTURES / "exe_x86_64"

no_ghidra = shutil.which("analyzeHeadless") is None
no_fixture = not _EXE_ELF.exists()


@pytest.mark.skipif(no_ghidra, reason="analyzeHeadless not in PATH")
@pytest.mark.skipif(no_fixture, reason="fixture exe_x86_64 missing")
def test_run_ghidra_real_binary(tmp_path: Path) -> None:
    """Run Ghidra on the exe_x86_64 fixture and verify output JSON structure."""
    runner = GhidraRunner(GhidraConfig())
    result = runner.run_ghidra(
        binary=_EXE_ELF,
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

    # Reference lists come out in a total order — by source address — so the same binary extracted
    # twice yields the same bytes (Ghidra's getReferencesTo iterates in no fixed order). This
    # fixture holds a string and functions referenced from several places, so the order is real.
    # MUTATION (verified RED): emit the references in iteration order -> one list of each kind
    # comes out unsorted on this fixture.
    def addresses(rows: list[dict[str, str]], key: str) -> list[int]:
        return [int(r[key], 16) for r in rows]

    ref_lists = [addresses(s["refs"], "ref_at") for s in data["string_refs"]["strings"]]
    take_lists = [addresses(f["address_taken"]["edges"], "taken_at") for f in data["functions"]]
    assert any(len(x) > 1 for x in ref_lists) and any(len(x) > 1 for x in take_lists)
    assert all(x == sorted(x) for x in ref_lists)
    assert all(x == sorted(x) for x in take_lists)

    # The image base the decompiler reports, against the shift computed from the ELF alone (the
    # one the stub table is moved by): this PIE is linked at 0 and loaded at +0x100000.
    from treasure_map.lib.analyze.stub_resolve import ghidra_load_shift

    applied = int(data["image_base"], 16) - int(data["elf_original_image_base"], 16)
    assert applied == ghidra_load_shift(_EXE_ELF) == 0x100000
