# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""What the extraction JVM is started with is fingerprinted, and nothing else reaches it.

The JVM used to inherit the whole parent environment, so a stray ``_JAVA_OPTIONS`` (the heap), a
leftover ``TMAP_EXTRA_SINKS`` (extra sinks) or an ``XDG_*`` (Ghidra's settings) could change an
extraction while its fingerprint said nothing had. These pin the whitelist, tie it to what the
extractor reads, and keep the module that builds it inside the extraction pass's fingerprint.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from treasure_map.lib.analyze import ghidra_launch as gl
from treasure_map.lib.analyze import ghidra_runner

_SCRIPT_DIR = Path(ghidra_runner.__file__).parent / "ghidra"
_EXTRACTOR = _SCRIPT_DIR / "ExportFunctions.java"

_STRAY = {
    "_JAVA_OPTIONS": "-Xmx1m",
    "JDK_JAVA_OPTIONS": "-Xmx1m",
    "TMAP_EXTRA_SINKS": "my_sink",
    "TMAP_STUB_NAMES": "/stale/table",
    "TMAP_DECOMPILE_PAYLOAD_MB": "1",
    "XDG_CONFIG_HOME": "/home/someone/.config",
    "XDG_DATA_HOME": "/home/someone/.local/share",
    "HOME": "/home/someone",
    "SOME_SECRET": "x",
}


def _env(**kw: Any) -> dict[str, str]:
    args: dict[str, Any] = {
        "output_dir": Path("/out"),
        "sha8": "deadbeef",
        "pass_version": "p1",
        "heap_mb": 64,
        "xms_mb": 16,
        "user_home": Path("/tmp/home"),
        "stub_table": None,
        "retry_budget_s": 30,
        "deadline_ms": 123,
        "payload_mb": None,
    }
    args.update(kw)
    parent = {"PATH": "/usr/bin", "JAVA_HOME": "/jdk", "LANG": "C.UTF-8", **_STRAY}
    return gl.build_env(parent, **args)


def test_the_jvm_sees_the_keys_set_for_it_and_the_launcher_needs_and_nothing_else() -> None:
    """★ A parent environment full of strays: the JVM gets PATH / JAVA_HOME / the locale, and the
    keys set from this binary's arguments — no heap override, no extra sinks, no inherited stub
    table or output limit, no Ghidra settings directory, nothing else.

    MUTATION (verified RED): inherit the parent environment whole -> RED."""
    env = _env()
    assert set(env) == {"PATH", "JAVA_HOME", "LANG"} | (
        gl.JVM_SET_KEYS - {"TMAP_STUB_NAMES", "TMAP_DECOMPILE_PAYLOAD_MB"}
    )
    assert env["JAVA_TOOL_OPTIONS"] == "-Xmx64m -Xms16m -Duser.home=/tmp/home"
    full = _env(stub_table=Path("/out/x.stubs.tsv"), payload_mb=256)
    assert full["TMAP_STUB_NAMES"] == "/out/x.stubs.tsv"
    assert full["TMAP_DECOMPILE_PAYLOAD_MB"] == "256"


def test_the_keys_set_are_the_keys_the_extractor_reads() -> None:
    """★ The keys the extractor reads from its environment are the keys this module sets (the JVM
    options apart, read by the JVM itself) — and TMAP_EXTRA_SINKS, which it still reads but is never
    passed: a firmware-specific sink belongs in the fingerprinted registry, not in an environment
    nobody records. A new read in the extractor without a key set for it, or a key set that nothing
    reads, is RED.

    MUTATION (verified RED): read one more variable in the extractor -> RED."""
    src = _EXTRACTOR.read_text(encoding="utf-8")
    reads = set(re.findall(r'System\.getenv\("([A-Z0-9_]+)"\)', src))
    reads |= set(re.findall(r'envCount\("([A-Z0-9_]+)"', src))
    assert reads == (gl.JVM_SET_KEYS - {"JAVA_TOOL_OPTIONS"}) | {"TMAP_EXTRA_SINKS"}
    assert "TMAP_EXTRA_SINKS" not in gl.JVM_SET_KEYS | gl.JVM_INHERITED_KEYS


def test_a_real_launch_hands_the_jvm_only_the_whitelist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ Through the runner: with strays in the process environment, the environment the JVM is
    started with holds only whitelisted keys.

    MUTATION (verified RED): build the environment in the runner from os.environ again -> RED."""
    from treasure_map.lib.config.config import GhidraConfig

    for k, v in _STRAY.items():
        monkeypatch.setenv(k, v)
    binary = tmp_path / "httpd"
    binary.write_bytes(b"\x7fELF" + b"\0" * 100)
    seen: dict[str, str] = {}

    def fake_sub(cmd: list[str], env: dict[str, str], timeout: int, cwd: Any = None) -> Any:
        seen.update(env)
        return 1, "boom"

    runner = ghidra_runner.GhidraRunner(GhidraConfig(), headless=tmp_path / "analyzeHeadless")
    with patch.object(ghidra_runner, "_run_subprocess", fake_sub):
        runner.run_ghidra(binary, tmp_path / "out", 60, "ARM:LE:32:v7", "deadbeef", retry=False)
    assert seen, "the JVM was never started"
    assert set(seen) <= gl.JVM_SET_KEYS | gl.JVM_INHERITED_KEYS, set(seen) - gl.JVM_SET_KEYS


def test_the_launch_module_is_in_the_extraction_fingerprint() -> None:
    """The module that builds the JVM's command line and environment, and patches the ELF it may be
    handed, is hashed into the pass version: editing any of it re-extracts.

    MUTATION (verified RED): leave ghidra_launch.py out of the declared modules -> RED."""
    files = ghidra_runner.pass_version_source_files(_SCRIPT_DIR)
    assert Path(gl.__file__).resolve() in {f.resolve() for f in files}
