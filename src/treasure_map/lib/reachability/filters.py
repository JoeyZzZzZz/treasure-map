# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Validator / filter recognition — GENERIC name patterns only.

This is a name-based heuristic, not semantic analysis: a callee whose name looks like a
validator is treated as one. It carries no firmware-specific symbol. Being name-based, it
can mis-recognize (a check_* that does not sanitize) or miss an oddly-named sanitizer; the
grader therefore prefers "unknown" over a confident "blocked" whenever the relationship
between a validator-style call and the value reaching the sink is not clear.
"""

from __future__ import annotations

import re

# Generic validator/sanitizer name shapes. No specific firmware symbol is hardcoded.
VALIDATOR_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^check_"),
    re.compile(r"^validate_"),
    re.compile(r"^valid_"),
    re.compile(r"^is_valid"),
    re.compile(r"^saniti[sz]e_"),
    re.compile(r"^escape_"),
    re.compile(r"^filter_"),
    re.compile(r"^verify_"),
)

_BLOCKING_MECHANISM = "a validator-style call is applied to the value before the sink"


def _is_validator_name(name: str) -> bool:
    return any(p.search(name) for p in VALIDATOR_PATTERNS)


def validator_present(callees: list[str]) -> bool:
    """True if any callee name looks like a validator (regardless of what it guards)."""
    return any(_is_validator_name(c.strip()) for c in callees if c.strip())


def has_validator(callees: list[str], pseudocode: str, var: str) -> tuple[bool, str | None]:
    """Whether a validator-style callee is applied to ``var`` in the body.

    Returns (True, neutral mechanism) when a validator-named callee is called with var
    among its arguments; otherwise (False, None). Presence of a validator that is NOT
    applied to var is deliberately not reported here — the grader treats that ambiguity
    as a reason for "unknown", not "blocked".
    """
    for callee in callees:
        name = callee.strip()
        if not name or not _is_validator_name(name):
            continue
        # name( ... var ... ) within a single call's argument list.
        if re.search(rf"\b{re.escape(name)}\s*\([^;{{}}]*\b{re.escape(var)}\b", pseudocode):
            return True, _BLOCKING_MECHANISM
    return False, None
