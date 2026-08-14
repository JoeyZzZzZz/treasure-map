# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
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


# ── covered (apparent validator) -> unknown in v1, never blocked ────────────────────


def test_covered_validator_is_unknown() -> None:
    # A validator appears to cover the value, but v1 cannot prove non-reachability soundly,
    # so it grades unknown (NOT blocked) — blocked is reserved for R2-deep.
    pseudo = "char* v = param_1; if (check_field(v)) { system(v); }"
    verdict = grade_candidate(pseudo, ["check_field", "system"], "system")
    assert verdict.status == "unknown"
    assert verdict.blocking_mechanism is None
    assert not verdict.degraded  # input was complete; v1 just cannot prove non-reachability


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


# ── inline bound: a clamp downgrades a would-be confirm to unknown, never blocked ───


def test_inline_clamp_before_copy_is_unknown_not_blocked() -> None:
    # The "clamp-before-copy" shape: a strong source with a length clamp. A function-wide
    # clamp does not prove THIS path is bounded, so it downgrades confirmed -> unknown; it
    # must NEVER produce blocked (that would hide a possibly-reachable path).
    pseudo = (
        "char dst[32]; char src[64]; recv(fd,src,64); int len = get_len(); "
        "if (0x20 < len) len = 0x20; memcpy(dst, src, len);"
    )
    verdict = grade_candidate(pseudo, ["recv", "get_len", "memcpy"], "memcpy")
    assert verdict.status != "confirmed"
    assert verdict.status != "blocked"
    assert verdict.status == "unknown"


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


# ── validator on the data-flow path (through renames) -> unknown in v1 ──────────────


def test_validator_through_rename_is_unknown() -> None:
    # The validator appears to cover the value (reached under renamed intermediates), but v1
    # cannot prove non-reachability soundly -> unknown, not blocked (reserved for R2-deep).
    pseudo = (
        "char* buf_a = b64_decode(input); check_field(buf_a); "
        "memcpy(buf_b, buf_a, n); "
        'sprintf(cmd, "x %s", buf_b); system(cmd);'
    )
    callees = ["b64_decode", "check_field", "memcpy", "sprintf", "system"]
    verdict = grade_candidate(pseudo, callees, "system")
    assert verdict.status == "unknown"


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


def test_fully_covered_multi_input_is_unknown() -> None:
    # Every input reaching the sink appears validated, but v1 grades unknown (not blocked) —
    # proving the copy actually carries the validated content is R2-deep's job.
    pseudo = (
        "char buf_a[64]; recv(fd, buf_a, 64); check_field(buf_a); "
        "memcpy(buf_b, buf_a, n); system(buf_b);"
    )
    callees = ["recv", "check_field", "memcpy", "system"]
    verdict = grade_candidate(pseudo, callees, "system")
    assert verdict.status == "unknown"


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


# ── hard invariant: a possibly-reachable path is NEVER downgraded to blocked ────────


def test_clamp_elsewhere_does_not_block_unfiltered_path() -> None:
    # An unfiltered strong-source path to the sink, with an UNRELATED clamp elsewhere in
    # the function. The clamp must not block this path (a function-wide clamp proves
    # nothing about it) -> not blocked.
    pseudo = (
        "char buf[64]; recv(fd, buf, 64); int n = get_n(); if (n < 0x40) n = 0; "
        'sprintf(cmd, "%s", buf); system(cmd);'
    )
    verdict = grade_candidate(pseudo, ["recv", "get_n", "sprintf", "system"], "system")
    assert verdict.status != "blocked"


def test_downstream_only_validator_does_not_block() -> None:
    # The validator guards a value DERIVED FROM the sink value (downstream), not on its path
    # into the sink. It must not block.
    pseudo = (
        "char buf[64]; recv(fd, buf, 64); "
        'sprintf(cmd, "%s", buf); system(cmd); '
        "char* d = derive(cmd); check_field(d);"
    )
    callees = ["recv", "sprintf", "system", "derive", "check_field"]
    verdict = grade_candidate(pseudo, callees, "system")
    assert verdict.status != "blocked"


def test_polluted_partial_coverage_does_not_block() -> None:
    # Two strong inputs reach the sink through copies (with function-name noise); only one
    # is validated. The unvalidated input must not be masked as covered -> not blocked.
    pseudo = (
        "char buf_a[64]; recv(fd, buf_a, 64); char buf_b[64]; recv(fd, buf_b, 64); "
        "check_field(buf_a); "
        "memcpy(out_a, buf_a, strlen(buf_a)); memcpy(out_b, buf_b, strlen(buf_b)); "
        'sprintf(cmd, "%s %s", out_a, out_b); system(cmd);'
    )
    callees = ["recv", "check_field", "memcpy", "strlen", "sprintf", "system"]
    verdict = grade_candidate(pseudo, callees, "system")
    assert verdict.status != "blocked"


def test_clean_single_input_validator_is_unknown() -> None:
    # Even the clean single-input validated shape grades unknown in v1: blocked is not a v1
    # verdict (it is reserved for R2-deep), so v1 never returns it.
    pseudo = "char buf[64]; recv(fd, buf, 64); check_field(buf); system(buf);"
    verdict = grade_candidate(pseudo, ["recv", "check_field", "system"], "system")
    assert verdict.status == "unknown"
    assert verdict.status != "blocked"


# ── v1 hard invariant: blocked is never emitted; the two real-firmware shapes ────────

_BLOCKED_PRONE_SHAPES: list[tuple[str, list[str], str]] = [
    # apparent direct validator on the value
    ("char* v = param_1; if (check_field(v)) { system(v); }", ["check_field", "system"], "system"),
    # clean single input, validator on the value
    (
        "char buf[64]; recv(fd, buf, 64); check_field(buf); system(buf);",
        ["recv", "check_field", "system"],
        "system",
    ),
    # validated value renamed through a copy before the sink
    (
        'char* a = b64_decode(input); check_field(a); memcpy(b, a, n); sprintf(cmd, "%s", b);'
        " system(cmd);",
        ["b64_decode", "check_field", "memcpy", "sprintf", "system"],
        "system",
    ),
    # cross-branch leakage: validator in one switch case, unfiltered sink in another, on a
    # different offset of the same (collapsed) base name (the ipd_rcv regression shape).
    (
        "switch (op) { case 1: check_field(st + 0x12); break; case 2: system(st + 0x14); break; }",
        ["check_field", "system"],
        "system",
    ),
    # base+offset aliasing: validator on one struct field, sink fed from another field.
    (
        "check_field(base + 0x12); memcpy(dst, base + 0x14, n); system(dst);",
        ["check_field", "memcpy", "system"],
        "system",
    ),
]


def test_v1_never_emits_blocked() -> None:
    for pseudo, callees, sink in _BLOCKED_PRONE_SHAPES:
        verdict = grade_candidate(pseudo, callees, sink)
        assert verdict.status != "blocked", pseudo


def test_cross_branch_validator_does_not_block() -> None:
    # A check_* in one switch case must not be read as covering an unfiltered sink in a
    # different case (whole-body validator scan is unsound) -> unknown, not blocked.
    pseudo = (
        "switch (op) { case 1: check_field(st + 0x12); break; case 2: system(st + 0x14); break; }"
    )
    verdict = grade_candidate(pseudo, ["check_field", "system"], "system")
    assert verdict.status != "blocked"


def test_offset_aliased_validator_does_not_block() -> None:
    # Validating base+0x12 must not be read as validating base+0x14 (the tokenizer collapses
    # both to "base") -> unknown, not blocked.
    pseudo = "check_field(base + 0x12); memcpy(dst, base + 0x14, n); system(dst);"
    verdict = grade_candidate(pseudo, ["check_field", "memcpy", "system"], "system")
    assert verdict.status != "blocked"


def test_confirmed_unchanged() -> None:
    # The strong-source-unfiltered confirmed path is NOT touched by this round.
    pseudo = "char buf[64]; recv(fd, buf, 64); system(buf);"
    verdict = grade_candidate(pseudo, ["recv", "system"], "system")
    assert verdict.status == "confirmed"


# ── copy sinks: graded on write length, never confirmed; bounded kinds get a form note ──


@pytest.mark.parametrize(
    ("pseudo", "sink", "callees", "note"),
    [
        # provably-bounded lengths -> a downweight form note, still unknown (never confirmed)
        ("memcpy(dst, src, 0x20);", "memcpy", ["memcpy"], "const_size"),
        ("memcpy(dst, src, sizeof(dst));", "memcpy", ["memcpy"], "sizeof_bound"),
        (
            "n = recv(fd, src, 0x400); if (0x100 < n) goto fail; memcpy(dst, src, n);",
            "memcpy",
            ["recv", "memcpy"],
            "clamp_size",
        ),
        # lengths not proven bounded -> NO note (kept at normal rank, recall-neutral)
        ("n = recv(fd, src, 0x400); memcpy(dst, src, n);", "memcpy", ["recv", "memcpy"], None),
        ("strncpy(dst, src, strlen(src));", "strncpy", ["strncpy", "strlen"], None),
    ],
)
def test_copy_graded_on_size_never_confirmed(
    pseudo: str, sink: str, callees: list[str], note: str | None
) -> None:
    verdict = grade_candidate(pseudo, callees, sink)
    assert verdict.status == "unknown"  # a copy never confirms within one function
    assert verdict.status != "confirmed"
    assert verdict.blocking_mechanism == note


# ── format-string sinks: graded on the FORMAT argument (per-sink position) ───────────


def test_fmtstr_confirmed_when_strong_source_is_the_format() -> None:
    # syslog's format is arg1; a strong in-function source flows into it unfiltered -> confirmed.
    pseudo = "char buf[64]; recv(fd, buf, 64); syslog(3, buf);"
    verdict = grade_candidate(pseudo, ["recv", "syslog"], "syslog")
    assert verdict.status == "confirmed"


def test_fmtstr_parameter_format_is_unknown() -> None:
    # The CVE shape with a caller-supplied format: caller control is unprovable here -> unknown.
    pseudo = "void h(char* param_1){ syslog(3, param_1); }"
    verdict = grade_candidate(pseudo, ["syslog"], "syslog")
    assert verdict.status == "unknown"
    assert verdict.status != "confirmed"


def test_fmtstr_position_arg1_not_arg0_for_fprintf() -> None:
    # fprintf's format is arg1: a strong source in arg1 confirms; the FILE* in arg0 is not the axis.
    pseudo = "char buf[64]; recv(fd, buf, 64); fprintf(fp, buf);"
    assert grade_candidate(pseudo, ["recv", "fprintf"], "fprintf").status == "confirmed"


def test_fmtstr_literal_format_grades_unknown_degraded() -> None:
    # A literal format has no controllable identifier on the danger axis -> no sink arg located.
    pseudo = 'syslog(3, "msg %s", x);'
    verdict = grade_candidate(pseudo, ["syslog"], "syslog")
    assert verdict.status == "unknown"


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


# ── unrecovered calling convention (stripped MIPS/ARM) -> never confirmed ───────────
# Root cause of the intra-procedural false-confirm: caller-supplied args/state render as
# in_stack_*/unaff_*/in_<reg> rather than param_N, so the parameter-origin rule was missed.


@pytest.mark.parametrize(
    "pseudo,callees,sink",
    [
        # strong return-value source -> copy, but the request handle is an unrecovered stack arg
        (
            "uVar1 = websGetVar(wp, in_stack_0xffffff80); strcpy(acStack_120, uVar1);",
            ["websGetVar", "strcpy"],
            "strcpy",
        ),
        # strong buffer source -> copy, but the frame is unrecovered (unaff_/in_ placeholders).
        # The copy length is a variable (no bound shown) so no size form note is attached.
        (
            "recvfrom(in_a0, auStack_88, n, 0); memcpy(unaff_s0, auStack_88, n);",
            ["recvfrom", "memcpy"],
            "memcpy",
        ),
        # a prior-call output the decompiler could not thread through normal flow
        ("extraout_v0 = helper(); strcpy(dst, extraout_v0);", ["helper", "strcpy"], "strcpy"),
    ],
)
def test_unrecovered_abi_never_confirmed(pseudo: str, callees: list[str], sink: str) -> None:
    verdict = grade_candidate(pseudo, callees, sink)
    assert verdict.status == "unknown"  # the flow is not fully visible within the function
    assert verdict.status != "confirmed"
    assert verdict.blocking_mechanism is None  # demote to unknown, never fabricate blocked


def test_in_register_arg_is_caller_supplied() -> None:
    # A caller-supplied value arriving in an arg register (in_a0) is a parameter, not an
    # in-function source: caller control is unprovable here, so never confirmed.
    pseudo = "void h(void){ char dst[64]; strcpy(dst, in_a0); }"
    verdict = grade_candidate(pseudo, ["strcpy"], "strcpy")
    assert verdict.status != "confirmed"


def test_clean_recovered_frame_still_confirms() -> None:
    # No placeholders: an in-function strong source flowing unfiltered to a COMMAND sink still
    # confirms — the unrecovered-ABI guard must not suppress legitimate clean flows. A recovered
    # frame with an ordinary web handle (wp is not a placeholder) confirms.
    pseudo2 = 'uVar1 = websGetVar(wp, "name"); system(uVar1);'
    assert grade_candidate(pseudo2, ["websGetVar", "system"], "system").status == "confirmed"


def test_copy_sink_is_never_confirmed() -> None:
    # A copy sink is graded on its write length and never confirms within one function (proving
    # the length is unbounded/controllable needs cross-function context). A clean strong-source
    # copy with a source-length write is unknown + suspect, NOT confirmed.
    pseudo = "char buf[64]; recv(fd,buf,64); strcpy(dst,buf);"
    verdict = grade_candidate(pseudo, ["recv", "strcpy"], "strcpy")
    assert verdict.status == "unknown"
    assert verdict.blocking_mechanism is None  # source_len is a suspect; no bounded-safe downweight


def test_abi_unrecovered_helper_precision() -> None:
    # True only on real unrecovered-frame prefixes; ordinary stack locals and names like
    # in_addr must NOT trip it (else every stripped function would be suppressed).
    from treasure_map.lib.reachability.taint import abi_unrecovered

    assert abi_unrecovered("strcpy(d, in_stack_0xffffff80);")
    assert abi_unrecovered("x = unaff_s0;")
    assert abi_unrecovered("y = extraout_v0;")
    assert abi_unrecovered("/* WARNING: Unknown calling convention */ void f(){}")
    assert not abi_unrecovered("char acStack_120[256]; char auStack_88[64]; int local_10;")
    assert not abi_unrecovered("struct in_addr a; recv(fd, buf, 64);")
