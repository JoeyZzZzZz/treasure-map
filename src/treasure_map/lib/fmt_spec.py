# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""printf-style format string scanning, in one place.

Three layers need to know how many arguments a format string consumes and which argument each
conversion takes: the extractor that records a writer's varargs, the read layer that trims varargs
the format never consumes, and the launch-edge layer that substitutes a constant argument back into
a template to recover the program name. Written three times, they drift — and a scanner that is off
by one does not fail loudly, it silently attributes the wrong argument to a conversion. Hence one
scanner, used by all of them.

What counts as consuming an argument: every conversion except ``%%``, plus one for each ``*`` taken
as a width or precision. Flags, digit widths, precisions and length modifiers are skipped over
without consuming anything.
"""

from __future__ import annotations

from dataclasses import dataclass

_FLAGS = "-+ 0#"
_LENGTH_MODIFIERS = "hljztL"


@dataclass(frozen=True)
class Conversion:
    """One conversion in a format string, and where its arguments sit.

    ``start``/``end`` bound the whole conversion in the source text (``end`` exclusive), so a
    caller can replace it. ``arg_index`` is the position of the argument this conversion CONSUMES
    within the vararg list; ``stars`` is how many extra arguments a ``*`` width/precision took
    just before it — those occupy ``arg_index - stars`` through ``arg_index - 1``."""

    start: int
    end: int
    char: str
    arg_index: int
    stars: int = 0


def conversions(fmt: str) -> list[Conversion]:
    """Every argument-consuming conversion in ``fmt``, in order.

    A trailing partial conversion (``"%"`` at the end, or one that runs off the string) is dropped:
    it consumes nothing, and inventing an argument for it would shift every later index."""
    out: list[Conversion] = []
    arg = 0
    i = 0
    length = len(fmt)
    while i < length:
        if fmt[i] != "%":
            i += 1
            continue
        j = i + 1
        if j < length and fmt[j] == "%":  # a literal percent consumes nothing
            i = j + 1
            continue
        stars = 0
        while j < length and fmt[j] in _FLAGS:
            j += 1
        while j < length and (fmt[j].isdigit() or fmt[j] == "*"):  # width
            if fmt[j] == "*":
                stars += 1
            j += 1
        if j < length and fmt[j] == ".":  # precision
            j += 1
            while j < length and (fmt[j].isdigit() or fmt[j] == "*"):
                if fmt[j] == "*":
                    stars += 1
                j += 1
        while j < length and fmt[j] in _LENGTH_MODIFIERS:
            j += 1
        if j >= length:  # ran off the end: not a conversion
            break
        arg += stars
        out.append(Conversion(start=i, end=j + 1, char=fmt[j], arg_index=arg, stars=stars))
        arg += 1
        i = j + 1
    return out


def arity(fmt: str) -> int:
    """How many arguments ``fmt`` consumes in total."""
    convs = conversions(fmt)
    if not convs:
        return 0
    last = convs[-1]
    return last.arg_index + 1
