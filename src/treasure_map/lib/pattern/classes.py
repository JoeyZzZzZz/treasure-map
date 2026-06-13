# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Semantic call classes — generic taint source/sink knowledge.

These frozensets describe WHAT COUNTS AS a source/formatter/command-sink/copy in
static security analysis — universal, mechanism-only knowledge. They carry only
generic, public C/libc and common-embedded API names; no vendor-proprietary symbol.
"""

from __future__ import annotations

# External-input getters, split by strength of external controllability (neutral,
# mechanism-based). Strength gates reachability grading only; R-pattern's shape detection
# uses the SOURCE union below and is unaffected by the split.

# Strong: network / request input — externally controllable by a remote party.
SOURCE_STRONG: frozenset[str] = frozenset(
    {
        "recv",
        "recvfrom",
        # Generic web/CGI parameter getters (public webserver API style).
        "websGetVar",
        "webGetVar",
        "getKeyValue",
        "get_cgi",
    }
)

# Weak: locally-influenced input — file/stream reads, environment, config/device-self
# values. External controllability is not establishable within a single function.
SOURCE_WEAK: frozenset[str] = frozenset(
    {
        "read",
        "fread",
        "fgets",
        "gets",
        "scanf",
        "sscanf",
        "fscanf",
        "getenv",
        # Generic embedded config store ("non-volatile RAM") getters.
        "nvram_get",
        "nvram_safe_get",
        "nvram_bufget",
        # Generic base64 decoders.
        "b64_decode",
        "base64_decode",
    }
)

# Union — the set R-pattern uses for "is this callee an external-input source" (shape, not
# strength). Keep this equal to the historical SOURCE so R-pattern stays unchanged.
SOURCE: frozenset[str] = SOURCE_STRONG | SOURCE_WEAK

# String formatters: build a buffer from a format and arguments.
FORMAT: frozenset[str] = frozenset(
    {
        "snprintf",
        "sprintf",
        "vsnprintf",
        "vsprintf",
        "strcat",
        "strncat",
    }
)

# Command sinks: hand a string to a shell / new process image.
CMD: frozenset[str] = frozenset(
    {
        "system",
        "popen",
        "execl",
        "execlp",
        "execle",
        "execv",
        "execvp",
        "execve",
        # Generic "run a shell command" wrapper, common across embedded code.
        "doSystem",
    }
)

# Copies: move bytes into a destination buffer (length-taking or not).
COPY: frozenset[str] = frozenset(
    {
        "strcpy",
        "strncpy",
        "memcpy",
    }
)
