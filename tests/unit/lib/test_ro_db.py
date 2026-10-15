# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A read-only open must target the file it was given, whatever the path contains — never a
different file, and never a freshly created empty one."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from treasure_map.lib.ro_db import ro_connect, ro_uri


@pytest.mark.parametrize("name", ["ws#1", "ws?x", "w%20s", "plain"])
def test_a_path_with_uri_metacharacters_opens_that_exact_file(tmp_path: Path, name: str) -> None:
    """MUTATION: build the URI as f"file:{path}?mode=ro" -> a '#' or '?' path opens elsewhere (or
    creates an empty db), a '%' path fails -> RED."""
    d = tmp_path / name
    d.mkdir()
    db = d / "analysis.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE t (x)")
    conn.execute("INSERT INTO t VALUES (42)")
    conn.commit()
    conn.close()

    ro = ro_connect(db)
    try:
        assert ro.execute("SELECT x FROM t").fetchone()[0] == 42
    finally:
        ro.close()


def test_ro_open_does_not_create_a_missing_database(tmp_path: Path) -> None:
    """mode=ro must survive the escaping: opening a path that does not exist fails, never creates.

    MUTATION: lose the query string (the f-string bug on a '#'/'?' path) -> a new empty db is
    created and the open succeeds -> RED."""
    missing = tmp_path / "ws#2" / "nope.db"
    missing.parent.mkdir()
    with pytest.raises(sqlite3.OperationalError):
        ro_connect(missing)
    assert not missing.exists()
    assert "%23" in ro_uri(missing)  # the '#' is escaped, not a fragment
