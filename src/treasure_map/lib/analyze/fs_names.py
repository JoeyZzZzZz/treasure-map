# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A firmware's file names as text the analysis database can store.

A name that is not UTF-8 (a GBK or Latin-1 file name in an unpacked image) reaches Python as a
str carrying surrogate escapes (PEP 383), and SQLite refuses those — one such file used to stop
the whole analysis. ``db_text`` writes its undecodable bytes as ``\\xNN`` escapes instead: the
name stays readable and distinct, and every UTF-8 name is stored unchanged."""

from __future__ import annotations

import os


def db_text(name: str) -> str:
    """``name`` unchanged when it is valid text, else with its raw bytes escaped as ``\\xNN``."""
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        return os.fsencode(name).decode("utf-8", "backslashreplace")
    return name
