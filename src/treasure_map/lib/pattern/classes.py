# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Semantic call classes — generic taint source/sink knowledge.

These frozensets describe WHAT COUNTS AS a source/formatter/command-sink/copy in
static security analysis — universal, mechanism-only knowledge. They carry only
generic, public C/libc and common-embedded API names; no vendor-proprietary symbol.
"""

from __future__ import annotations

# External-input getters: data that originates outside the program.
SOURCE: frozenset[str] = frozenset(
    {
        "recv",
        "recvfrom",
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
        # Generic web/CGI parameter getters (public webserver API style).
        "websGetVar",
        "webGetVar",
        "getKeyValue",
        "get_cgi",
        # Generic base64 decoders.
        "b64_decode",
        "base64_decode",
    }
)

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
