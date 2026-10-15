# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Every provably-constant marker is a proof over every danger argument, every call and every
caller — held to it by an adversarial case per dimension, or a written reason the dimension does
not apply.

A marker in ``PROVABLY_CONSTANT_MARKERS`` sinks a candidate out of the first screen, so a marker
that proves less than it claims hides a live candidate. Each one this module has lost — the first
call standing in for the second, rename's source standing in for its destination, a parenthesis
inside a literal ending the call early, a one-hop caller set read as complete — was a dimension
nobody had asked about. A new marker does not get into the set without answering all of them."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from treasure_map.lib.hunt.downweight import CONST_SINK_ARG, detect_form_signal
from treasure_map.lib.pattern.classes import all_path_calls_literal
from treasure_map.lib.query.sink_impact import PROVABLY_CONSTANT_MARKERS
from treasure_map.lib.reachability.copy_size import (
    SIZE_CONST,
    SIZE_SIZEOF,
    classify_copy_size,
    copy_size_form_note,
)

DIMENSIONS = ("every_call", "every_danger_arg", "every_caller", "literal_parse", "arg_is_param")


def _cmd(pc: str, sink: str, occurrence: int, sink_arg: str | None) -> str | None:
    return detect_form_signal(
        sink_name=sink,
        pseudocode=pc,
        callees=[sink],
        sink_arg=sink_arg,
        occurrence=occurrence,
        sink_class="cmd",
    )


def _path(pc: str, sink: str) -> str | None:
    """What the hunt writes for a path sink: const_sink_arg exactly when every call is literal."""
    return CONST_SINK_ARG if all_path_calls_literal(pc, sink) else None


def _copy(pc: str, sink: str, occurrence: int) -> str | None:
    return copy_size_form_note(classify_copy_size(pc, sink, occurrence=occurrence).kind)


# marker -> dimension -> adversarial cases (each must NOT produce the marker) | "N/A: <reason>"
Case = Callable[[], str | None]
REGISTRY: dict[str, dict[str, list[Case] | str]] = {
    "const_sink_arg": {
        "every_call": [
            lambda: _cmd('void f(char *v){ system("reboot"); system(v); }', "system", 1, "v"),
            lambda: _path('void f(char *p){ fopen("/etc/x", "r"); fopen(p, "r"); }', "fopen"),
        ],
        "every_danger_arg": [
            lambda: _path('void f(char *p){ rename("/tmp/a", p); }', "rename"),
            lambda: _path('void f(char *p){ renameat(0, "/tmp/a", 0, p); }', "renameat"),
            lambda: _cmd('void f(char *n){ doSystem("ifconfig %s up", n); }', "doSystem", 0, None),
        ],
        "every_caller": "N/A: read from the call's own text; nothing about callers enters it",
        "literal_parse": [
            lambda: _path('void f(char *q){ fopen(q, "("); fopen("/etc/x", "r"); }', "fopen"),
            lambda: _path('void f(char *q){ fopen(q, \')\'); fopen("/etc/x", "r"); }', "fopen"),
        ],
        "arg_is_param": "N/A: the literal at the call IS the value; no parameter stands for it",
    },
    "const_size": {
        "every_call": [
            lambda: _copy("void f(int n){ memcpy(d, s, 16); memcpy(d, s, n); }", "memcpy", 1),
        ],
        "every_danger_arg": (
            "N/A: a copy's danger is its length, the one argument read; whether a fixed length "
            "fits the destination is not claimed (a fixed length is treated as provable)"
        ),
        "every_caller": "N/A: read from the call's own text; nothing about callers enters it",
        "literal_parse": [
            lambda: _copy('void f(int n){ memcpy(d, ",", n); }', "memcpy", 0),
            lambda: _copy('void f(int n){ memcpy(d, "16)", n); }', "memcpy", 0),
        ],
        "arg_is_param": "N/A: the literal length at the call IS the value",
    },
    "sizeof_bound": {
        "every_call": [
            lambda: _copy(
                "void f(int n){ memcpy(d, s, sizeof(d)); memcpy(d, s, n); }", "memcpy", 1
            ),
        ],
        "every_danger_arg": [
            lambda: _copy("void f(int n){ memcpy(d, s, n * sizeof(int)); }", "memcpy", 0),
            lambda: _copy("void f(int n){ memcpy(d, s, n - sizeof(hdr)); }", "memcpy", 0),
        ],
        "every_caller": "N/A: read from the call's own text; nothing about callers enters it",
        "literal_parse": [
            lambda: _copy('void f(int n){ memcpy(d, "sizeof(x)", n); }', "memcpy", 0),
        ],
        "arg_is_param": "N/A: a sizeof is fixed at compile time; no parameter stands for it",
    },
}

_FORM_NOTE = {"const_size": copy_size_form_note(SIZE_CONST), "sizeof_bound": "sizeof_bound"}


def test_the_provable_set_is_exactly_the_registered_markers() -> None:
    """MUTATION: add a marker to PROVABLY_CONSTANT_MARKERS (caller_constant back, say) without
    registering it here -> RED."""
    assert set(REGISTRY) == set(PROVABLY_CONSTANT_MARKERS)
    assert copy_size_form_note(SIZE_SIZEOF) == "sizeof_bound"


@pytest.mark.parametrize("marker", sorted(REGISTRY))
def test_every_dimension_is_answered(marker: str) -> None:
    dims = REGISTRY[marker]
    assert set(dims) == set(DIMENSIONS), marker
    for dim, answer in dims.items():
        if isinstance(answer, str):
            assert answer.startswith("N/A: ") and len(answer) > 20, (marker, dim)
        else:
            assert answer, (marker, dim)


_CASES = [
    (marker, dim, i, case)
    for marker, dims in sorted(REGISTRY.items())
    for dim, answer in dims.items()
    if not isinstance(answer, str)
    for i, case in enumerate(answer)
]


@pytest.mark.parametrize(
    ("marker", "case"),
    [(m, c) for m, _d, _i, c in _CASES],
    ids=[f"{m}-{d}-{i}" for m, d, i, _c in _CASES],
)
def test_no_adversarial_case_earns_the_marker(marker: str, case: Case) -> None:
    assert case() != _FORM_NOTE.get(marker, marker)
