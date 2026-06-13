# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the reachability grading primitive (R2, intra-procedural v1).

Hermetic: synthetic, vendor-neutral pseudocode strings, no network, no LLM. Proves the
grading table, the never-auto-confirm hard invariant, the mis-block caution, and
degrade-and-flag.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from treasure_map.lib.reachability import grade_candidate
from treasure_map.lib.reachability.filters import VALIDATOR_PATTERNS

_REACH_PKG = Path(__file__).resolve().parents[3] / "src" / "treasure_map" / "lib" / "reachability"


# ── blocked: validator applied to the value before the sink ─────────────────────────


def test_blocked_when_validator_applied() -> None:
    pseudo = "char* v = param_1; if (check_field(v)) { system(v); }"
    verdict = grade_candidate(pseudo, ["check_field", "system"], "system")
    assert verdict.status == "blocked"
    assert verdict.blocking_mechanism is not None
    assert not verdict.degraded


# ── unknown: parameter-sourced sink (the section-6.4 invariant) ─────────────────────


def test_unknown_when_parameter_sourced() -> None:
    pseudo = (
        "void run_external_tool(char* param_1){ char cmd[128]; "
        'snprintf(cmd,128,"/usr/bin/x %s",param_1); system(cmd); }'
    )
    verdict = grade_candidate(pseudo, ["snprintf", "system"], "system")
    assert verdict.status == "unknown"  # caller control unprovable intra-procedurally
    assert verdict.status != "confirmed"
    assert not verdict.degraded


# ── confirmed: in-function source, unfiltered, fully visible ────────────────────────


def test_confirmed_when_in_function_source_unfiltered() -> None:
    pseudo = (
        "char buf[64]; recv(fd,buf,64); char cmd[128]; "
        'snprintf(cmd,128,"/usr/bin/x %s",buf); system(cmd);'
    )
    verdict = grade_candidate(pseudo, ["recv", "snprintf", "system"], "system")
    assert verdict.status == "confirmed"
    assert verdict.blocking_mechanism is None
    assert not verdict.degraded


def test_confirmed_via_strong_return_value_source() -> None:
    # A strong (request) return-value source flows straight into the sink, unfiltered.
    pseudo = 'char* v = websGetVar(wp,"name"); system(v);'
    verdict = grade_candidate(pseudo, ["websGetVar", "system"], "system")
    assert verdict.status == "confirmed"


# ── source strength: a WEAK source unfiltered is unknown, NOT confirmed ─────────────


def test_weak_env_source_is_unknown_not_confirmed() -> None:
    # getenv is a locally-influenced (weak) source; unfiltered to a copy is still unknown.
    pseudo = 'char dst[64]; char* e = getenv("PATH"); memcpy(dst, e, 64);'
    verdict = grade_candidate(pseudo, ["getenv", "memcpy"], "memcpy")
    assert verdict.status == "unknown"
    assert verdict.status != "confirmed"


# ── inline bound: a clamp before a copy is bounded, never confirmed ─────────────────


def test_inline_clamp_before_copy_is_not_confirmed() -> None:
    # The "clamp-before-copy" shape: a strong source, but the length is clamped to a const
    # before the copy — bounded, must not grade confirmed.
    pseudo = (
        "char dst[32]; char src[64]; recv(fd,src,64); int len = get_len(); "
        "if (0x20 < len) len = 0x20; memcpy(dst, src, len);"
    )
    verdict = grade_candidate(pseudo, ["recv", "get_len", "memcpy"], "memcpy")
    assert verdict.status != "confirmed"
    assert verdict.status == "blocked"


# ── co-located source that does NOT flow to the sink -> not confirmed ───────────────


def test_param_sink_with_unrelated_source_is_unknown() -> None:
    # A strong source exists in the function, but the sink arg derives from a parameter;
    # co-occurrence must not be read as flow.
    pseudo = "void h(char* param_1){ char buf[64]; recv(fd,buf,64); system(param_1); }"
    verdict = grade_candidate(pseudo, ["recv", "system"], "system")
    assert verdict.status == "unknown"


def test_device_self_builder_source_is_unknown() -> None:
    # Sink fed by assembled device-self values (no external source flows to it).
    pseudo = (
        "void h(){ char info[64]; char ip[16]; get_lan_ip(ip); "
        'snprintf(info,64,"%s",ip); system(info); }'
    )
    verdict = grade_candidate(pseudo, ["get_lan_ip", "snprintf", "system"], "system")
    assert verdict.status == "unknown"


# ── degrade-and-flag ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("pseudo", "callees", "sink"),
    [
        ("system(cmd);", [], "system"),  # no callees
        ("", ["recv", "system"], "system"),  # no body
        ("   ", ["recv", "system"], "system"),  # whitespace body
        ("recv(fd,buf,64);", ["recv", "system"], "system"),  # sink not present
    ],
)
def test_degrade_returns_unknown_flagged(pseudo: str, callees: list[str], sink: str) -> None:
    verdict = grade_candidate(pseudo, callees, sink)
    assert verdict.status == "unknown"
    assert verdict.degraded is True


# ── never-auto-confirm hard invariant ───────────────────────────────────────────────


@pytest.mark.parametrize(
    "pseudo",
    [
        'char cmd[128]; snprintf(cmd,128,"/usr/bin/x %s",param_1); system(cmd);',
        "system(param_1);",
        'char* v = param_2; popen(v, "r");',
        "char cmd[64]; strcpy(cmd, param_1); system(cmd);",
    ],
)
def test_parameter_sourced_never_confirmed(pseudo: str) -> None:
    sink = "popen" if "popen" in pseudo else "system"
    verdict = grade_candidate(pseudo, ["snprintf", "strcpy", "popen", "system"], sink)
    assert verdict.status != "confirmed"


# ── mis-block caution: prefer unknown when the validator relationship is unclear ────


def test_validator_not_on_value_prefers_unknown_not_blocked() -> None:
    # check_field guards `other`, not the value reaching the sink; origin is in-function.
    pseudo = (
        "char buf[64]; recv(fd,buf,64); "
        "char other[8]; check_field(other); "
        'char cmd[128]; snprintf(cmd,128,"/usr/bin/x %s",buf); system(cmd);'
    )
    verdict = grade_candidate(pseudo, ["recv", "check_field", "snprintf", "system"], "system")
    assert verdict.status == "unknown"  # neither a confident block nor a confirm
    assert verdict.status != "blocked"
    assert verdict.status != "confirmed"


# ── validator on the data-flow path (through renames) -> blocked ────────────────────


def test_validator_blocks_through_renaming_copies() -> None:
    # The validated value reaches the sink under renamed intermediates (copy + format);
    # the guard is real and on the path, so the verdict is blocked, not unknown.
    pseudo = (
        "char* buf_a = b64_decode(input); check_field(buf_a); "
        "memcpy(buf_b, buf_a, n); "
        'sprintf(cmd, "x %s", buf_b); system(cmd);'
    )
    callees = ["b64_decode", "check_field", "memcpy", "sprintf", "system"]
    verdict = grade_candidate(pseudo, callees, "system")
    assert verdict.status == "blocked"
    assert verdict.blocking_mechanism is not None


def test_off_path_validator_does_not_block() -> None:
    # A validator guards an unrelated value; the sink arg derives from a parameter. The
    # off-path guard must NOT block (no over-broad backward tainting) -> stays unknown.
    pseudo = (
        "char* buf_x = get_x(); check_other(buf_x); "
        "char* val = param_1; "
        'sprintf(cmd, "%s", val); system(cmd);'
    )
    verdict = grade_candidate(pseudo, ["check_other", "sprintf", "system"], "system")
    assert verdict.status != "blocked"
    assert verdict.status == "unknown"


# ── coverage: block only when ALL dangerous inputs to the sink are covered ──────────


def test_mixed_sink_one_uncovered_input_does_not_block() -> None:
    # The sink is built from a validated value and an UNVALIDATED weak (nvram) value;
    # a covered sibling must not mask the uncovered input -> not blocked, grades unknown.
    pseudo = (
        'char* nv = nvram_get("k"); char* cv = websGetVar(wp, "v"); check_field(cv); '
        'sprintf(cmd, "x %s %s", nv, cv); system(cmd);'
    )
    callees = ["nvram_get", "websGetVar", "check_field", "sprintf", "system"]
    verdict = grade_candidate(pseudo, callees, "system")
    assert verdict.status != "blocked"
    assert verdict.status == "unknown"


def test_fully_covered_multi_input_sink_blocks() -> None:
    # Every input reaching the sink is validated (validated buffer copied before the sink).
    pseudo = (
        "char buf_a[64]; recv(fd, buf_a, 64); check_field(buf_a); "
        "memcpy(buf_b, buf_a, n); system(buf_b);"
    )
    callees = ["recv", "check_field", "memcpy", "system"]
    verdict = grade_candidate(pseudo, callees, "system")
    assert verdict.status == "blocked"


def test_mixed_sink_uncovered_strong_source_is_confirmed() -> None:
    # One input is a validated value; the other is an UNCOVERED strong in-function source.
    # The covered sibling must not mask the live strong path -> confirmed.
    pseudo = (
        'char x[64]; recv(fd, x, 64); char* cv = websGetVar(wp, "v"); check_field(cv); '
        'sprintf(cmd, "%s %s", x, cv); system(cmd);'
    )
    callees = ["recv", "websGetVar", "check_field", "sprintf", "system"]
    verdict = grade_candidate(pseudo, callees, "system")
    assert verdict.status == "confirmed"


# ── BOUNDARY: no vendor/spike symbols, no bug-labeling vocab, generic validators ────


def test_reachability_package_is_boundary_clean() -> None:
    banned = re.compile(
        r"\b(vuln\w*|exploit\w*|payload|\bpoc\b|finding|check_id_char|incomplete_patch|fix_quality)\b",
        re.IGNORECASE,
    )
    section_ref = re.compile(r"§|PRD\s")
    for path in _REACH_PKG.glob("*.py"):
        text = path.read_text()
        assert not banned.search(text), f"banned vocab/spike symbol in {path.name}"
        assert not section_ref.search(text), f"section/private-doc ref in {path.name}"


def test_validator_patterns_are_generic() -> None:
    # Every validator pattern is a generic name shape, not a specific firmware symbol.
    for pat in VALIDATOR_PATTERNS:
        src = pat.pattern
        assert src.startswith("^")
        # Anchored prefix only; no literal full symbol like a specific check_id_char.
        assert "id_char" not in src
