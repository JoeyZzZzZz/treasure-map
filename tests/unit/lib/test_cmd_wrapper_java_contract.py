# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Structural guards on the extractor's thin-command-wrapper recovery (ExportFunctions.java).

★ HONEST SCOPE, stated up front. These read the Java SOURCE. They cannot run it — the extractor
needs Ghidra, which the unit suite does not have — so they prove the shape of the code, not its
behaviour. What they are for is the two regressions that would be invisible everywhere else:
a name-keyed global registry (which judges one binary's caller against another binary's body), and
recording the wrapper's own name as the sink (which leaves every recovered record unmatched and the
whole recovery silently inert). Both are one-line edits away, and neither changes any Python.

Behaviour was verified against real firmware through Ghidra 12.1.2 while building this:
  * one binary yielded 28 recovered records (17 stack-buffer, 11 direct literal), washing
    `system("/usr/sbin/mesh_connect.sh meshed")` to constant and recording
    `snprintf(buf, "uci set account.common.admin='%s'", …)` as a dominating writer;
  * the same function NAME in two binaries — one forking, one calling system — registered 0 and 1
    wrappers respectively, i.e. the body decided, not the name;
  * the extra decompilation touched 7 functions in a 66 KB binary (only shell-sink callers are
    decompiled twice).
The reading side of that behaviour is pinned by the C-CMD block in test_triage_controllability.
"""

from __future__ import annotations

import re
from pathlib import Path

_JAVA = (
    Path(__file__).resolve().parents[3]
    / "src"
    / "treasure_map"
    / "lib"
    / "analyze"
    / "ghidra"
    / "ExportFunctions.java"
)


def _source() -> str:
    return _JAVA.read_text(encoding="utf-8")


def test_wrapper_registry_is_per_program_not_static() -> None:
    """The registry must be INSTANCE state, rebuilt per program, never static.

    Headless analysis runs one program per JVM, so an instance field cannot outlive a binary while
    a static one would — and the same helper name really does carry different bodies in different
    binaries here (one `shell_cmd` forks, another calls system). A static registry judges the
    second binary's caller against the first binary's body.

    MUTATION (must go RED): declare either map `static`."""
    src = _source()
    for field in ("cmdWrapperSink", "cmdWrapperKeyArg"):
        decl = re.search(rf"^\s*private\s+(static\s+)?.*\b{field}\s*=", src, re.MULTILINE)
        assert decl is not None, f"{field} declaration not found"
        assert decl.group(1) is None, f"{field} must not be static (per-program registry)"
        # and it is re-initialised when the registry is built, so nothing can leak across programs
        assert re.search(rf"\b{field}\s*=\s*new\s+HashMap<>\(\);", src), field


def test_wrapper_recovery_does_not_ride_the_global_extra_sinks_map() -> None:
    """The recovery must not register wrappers into the global sink lexicon.

    `TMAP_EXTRA_SINKS` exists and does exactly that — `sinkKeyArg.put(name, 0)` — which is both
    name-keyed across binaries and hard-coded to argument 0. Reusing it would reintroduce the
    cross-binary confusion this recovery is careful to avoid.

    MUTATION (must go RED): register wrappers with `sinkKeyArg.put(...)` instead of the registry."""
    src = _source()
    puts = re.findall(r"sinkKeyArg\.put\(([^)]*)\)", src)
    # the only writers into the global lexicon are the static lexicon and the env-var escape hatch
    assert len(puts) <= 2, f"unexpected writes into the global sink lexicon: {puts}"
    for call in puts:
        assert "cmdWrapper" not in call, "wrapper recovery must not write the global lexicon"


def test_recorded_sink_is_the_wrapped_sink_not_the_wrapper() -> None:
    """A recovered record must name the sink that RUNS the command.

    The read side scopes a candidate's records by matching the record's sink against the sink the
    candidate is anchored to, and a wrapper-recovered candidate is anchored to the wrapped sink. If
    the wrapper's own name were recorded, every record would sit unmatched: evidence present,
    nothing judged by it, and no error anywhere.

    MUTATION (must go RED): emit `cn` (the wrapper's name) as the record's sink."""
    src = _source()
    assert re.search(
        r"String\s+recordedSink\s*=\s*viaWrapper\s*\?\s*cmdWrapperSink\.get\(cn\)\s*:\s*cn\s*;", src
    ), "the recorded sink must resolve to the wrapped sink for a wrapper call"
    assert re.search(
        r'append\("\\",\\\\"sink\\\\":\\\\""\)\.append\(esc\(recordedSink\)\)', src
    ) or ("esc(recordedSink)" in src), "the emitted sink field must use recordedSink"
    # and the wrapper's own name is still surfaced, so a reader knows the call site is one hop away
    assert '"via_wrapper"' in src or "via_wrapper" in src


def test_command_argument_index_is_recovered_not_assumed_zero() -> None:
    """The command's parameter POSITION is recovered from the wrapper's signature.

    The recognition test only requires the sink's first argument to be SOME parameter, so
    `W(int flag, char *cmd){system(cmd);}` is a real wrapper whose command is parameter 1. Reading
    the caller's argument 0 there judges the flag — and a constant flag beside a variable command
    reads as a safe constant, which is the exact false negative shape this whole area keeps hitting.

    MUTATION (must go RED): hard-code the key argument to 0 for a wrapper call."""
    src = _source()
    assert "cmdWrapperKeyArg.get(cn)" in src, "the key argument must come from the registry"
    # the index is derived from the signature slot the command parameter occupies
    assert "slots.indexOf(arg)" in src
    # …and an unestablished position declines rather than defaulting
    assert re.search(r"if\s*\(idx\s*<\s*0\)\s*\{", src)


def test_unnamed_signature_slots_keep_their_position() -> None:
    """A typed-but-unnamed parameter must occupy its slot rather than vanish.

    Dropping it renumbers every parameter after it, so `f(int, char *cmd)` would report the command
    at position 0 and the caller's argument 0 would be judged while argument 1 reaches the sink.

    MUTATION (must go RED): skip unnamed slots instead of adding null."""
    src = _source()
    assert re.search(r"slots\.add\(null\)", src), "unnamed slots must hold their position"


def test_only_shell_sink_callers_are_decompiled_twice() -> None:
    """The pre-pass must keep its cheap gate: decompile only functions that call a shell sink.

    Without the gate the registry pass decompiles every function, doubling the slowest stage of the
    scan. Measured across three firmware images, only 0.22%-0.38% of functions call a shell sink.

    MUTATION (must go RED): remove the `callsShell` gate before the decompile."""
    src = _source()
    start = src.index("private void buildCmdWrapperRegistry")
    body = src[start : src.index("\n    private ", start + 10)]
    gate = body.index("if (!callsShell) continue;")
    decompile = body.index("decomp.decompileFunction")
    assert gate < decompile, "the shell-sink gate must precede the decompile"
