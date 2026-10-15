# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Identifiers the neutral layers must never spell, checked by digest.

The boundary tests used to carry these as a plain regex, which published the very vocabulary they
keep out of the code. Only sha256 digests live here: a test tokenises a text into identifiers,
lowercases each one, and fails on any whose digest is listed. Matching is whole-identifier, the
way the regexes it replaces matched (``\\bword\\b``); a hyphenated name is also tried whole, so
a directory name like ``a-b-c`` is caught as one token as well as by its parts.
"""

from __future__ import annotations

import hashlib
import re

_DIGESTS: frozenset[str] = frozenset(
    {
        "13760a6190bb3c6945857350bdf7547ebf656e6e9ed29c503c074f6e85fa927f",
        "8c054c20fc6047e4ef1cb014d78889b5c813062226b9eaf5d22e514e7814e053",
        "ecb786167799a33005e67a28471f9f6881abacded911fae6b44264c8692eb91f",
        "572a6724c55265fef7b4e7bbd80667dad9f9af1fd798790b267791c8af7e1fa8",
    }
)

_IDENT_RE = re.compile(r"\w+")
_HYPHENATED_RE = re.compile(r"\w+(?:-\w+)+")


def is_listed(word: str) -> bool:
    """Whether ``word`` (case-insensitive, whole) is one of the listed identifiers."""
    return hashlib.sha256(word.lower().encode("utf-8")).hexdigest() in _DIGESTS


def listed_words_in(text: str) -> list[str]:
    """The listed identifiers ``text`` spells, in order of appearance (empty when clean)."""
    words = _IDENT_RE.findall(text) + _HYPHENATED_RE.findall(text)
    return [w for w in words if is_listed(w)]
