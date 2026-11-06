# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""A script that starts a binary without naming it first on the line: through a function's
positional parameter, a variable holding a literal command, or the first command of a command
substitution. Each recorded row says where its command came from (``via``) and the line it was
derived from (``via_line``); the hunt's literal sites stay exactly as they were.

Synthetic fixtures only (``svc_a`` / ``svc_b`` / ``$BASE``)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from treasure_map.cli import mcp_cli
from treasure_map.lib import facts
from treasure_map.lib.analyze.non_binary.framework import NonBinaryFile
from treasure_map.lib.analyze.non_binary.shell_script import (
    _ingest_shell,
    _split_respecting_quotes,
    launched_command,
)
from treasure_map.lib.hunt.evidence import load_entry_index
from treasure_map.lib.query.triage import _entry_reach_status
from treasure_map.lib.storage.connection import open_db

BINARIES = ("svc_a", "svc_b", "svc_c")


def _db(tmp_path: Path, binaries: tuple[str, ...] = BINARIES) -> sqlite3.Connection:
    conn = open_db(tmp_path / "analysis.db")
    for i, name in enumerate(binaries, start=1):
        conn.execute(
            "INSERT INTO binaries (id, name, path, sha256, last_seen_at) VALUES (?, ?, ?, ?, ?)",
            (i, name, f"usr/sbin/{name}", f"{i:064d}", "2026-01-01 00:00:00"),
        )
    conn.commit()
    return conn


def _ingest(conn: sqlite3.Connection, text: str, rel: str = "etc/init.d/svc") -> int:
    raw = text.encode()
    file_id = conn.execute(
        "INSERT INTO non_binary_files (kind, subtype, name, path, sha256, size_bytes, detected_via)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("shell_script", "sh", Path(rel).name, rel, "0" * 64, len(raw), "shebang"),
    ).lastrowid
    f = NonBinaryFile(
        path=Path(rel),
        rel_path=rel,
        name=Path(rel).name,
        sha256="0" * 64,
        size_bytes=len(raw),
        head=raw[:512],
        text=text,
    )
    _ingest_shell(conn, int(file_id or 0), f)
    conn.commit()
    return int(file_id or 0)


def _rows(conn: sqlite3.Connection) -> list[tuple[Any, ...]]:
    return [
        tuple(r)
        for r in conn.execute(
            "SELECT line_number, command, via, via_line FROM script_calls ORDER BY line_number, id"
        )
    ]


_FRESH = iter(range(10**6))


def _all_rows(tmp_path: Path, text: str) -> list[tuple[Any, ...]]:
    """Every row the ingester writes for ``text``, launch and risk rows alike (a fresh db)."""
    where = tmp_path / f"db{next(_FRESH)}"
    where.mkdir()
    conn = _db(where)
    try:
        _ingest(conn, text)
        return _rows(conn)
    finally:
        conn.close()


def _launches(tmp_path: Path, text: str) -> list[tuple[Any, ...]]:
    """The rows that launch one of the fixture's binaries."""
    return [r for r in _all_rows(tmp_path, text) if r[1].rsplit("/", 1)[-1] in BINARIES]


# ── T-1 quote-aware splitting ─────────────────────────────────────────────────────────────────


def test_a_quoted_value_with_spaces_is_one_word_and_names_no_command() -> None:
    """``X="a b c"`` is one assignment: its second word is no command.

    MUTATION (verified RED): launched_command splits with line.split() again -> RED."""
    assert _split_respecting_quotes('X="a b c" foo') == ["X=a b c", "foo"]
    assert launched_command('X="a b c"') is None
    assert launched_command('X="/usr/sbin/svc_a -d" ') is None


def test_unpaired_quotes_fall_back_to_whitespace_splitting() -> None:
    assert _split_respecting_quotes('foo "bar') == ["foo", '"bar']
    assert launched_command('foo "bar') == "foo"


def test_the_direct_launch_reading_is_unchanged() -> None:
    """MUTATION (verified RED): name the command of a VAR=$(cmd) assignment again -> RED."""
    assert launched_command("nohup foo &") == "foo"
    assert launched_command("start-stop-daemon -x /bin/foo") == "/bin/foo"
    # an assignment's substitution runs its command inside $( ): named by the inline reading
    assert launched_command("VAR=$(foo)") is None
    assert launched_command("/usr/sbin/svc_a -p 80 &") == "/usr/sbin/svc_a"


def test_a_spaced_quoted_assignment_records_no_launch(tmp_path: Path) -> None:
    """The second word of a quoted assignment happened to be a binary path: no row."""
    assert _launches(tmp_path, 'OPTS="-d /usr/sbin/svc_a"\n') == []


# ── T-2 a function that runs its positional parameter ─────────────────────────────────────────


def test_a_function_running_its_parameter_launches_the_literal_argument(tmp_path: Path) -> None:
    """MUTATION (verified RED): _scan_symbols records no parameter positions -> RED."""
    text = "check()  { $BASE/$1 & }\ncheck svc_a\n"
    assert _launches(tmp_path, text) == [(2, "svc_a", "function_arg", 1)]


def test_an_unquoted_parameter_runs_the_first_word_of_the_argument(tmp_path: Path) -> None:
    """The shell word-splits an unquoted ``$1``, so ``check "svc_a -x"`` runs ``svc_a``.

    MUTATION (verified RED): take the whole argument even when the body's $1 is unquoted -> RED."""
    text = 'check() {\n  $BASE/$1 &\n}\ncheck "svc_a -x"\n'
    assert _launches(tmp_path, text) == [(4, "svc_a", "function_arg", 1)]


def test_a_quoted_parameter_takes_the_whole_argument_which_names_no_binary(
    tmp_path: Path,
) -> None:
    """A quoted ``"$1"`` runs the whole argument as one name; ``svc_a -x`` is no binary, and
    neither is a spaced argument whose last path segment happens to be one.

    MUTATION (verified RED): keep a spaced whole argument (read by its basename) -> RED."""
    text = 'check() {\n  "$1" &\n}\ncheck "svc_a -x"\ncheck "x -c /usr/sbin/svc_c"\ncheck svc_b\n'
    assert _launches(tmp_path, text) == [(6, "svc_b", "function_arg", 1)]


def test_only_the_launch_lines_quoting_decides_how_the_argument_splits(tmp_path: Path) -> None:
    """A quoted ``"... $1"`` on a line that does not run ``$1`` (a log line) says nothing about the
    line that does: there ``$1`` is bare, the shell splits ``"svc_a -x"``, and ``svc_a`` runs.

    MUTATION (verified RED): decide the quoting from any line of the body again -> no row."""
    text = 'check() {\n  logger "start $1"\n  $BASE/$1 &\n}\ncheck "svc_a -x"\n'
    assert _launches(tmp_path, text) == [(5, "svc_a", "function_arg", 1)]


def test_launch_lines_that_quote_the_parameter_differently_leave_a_spaced_argument_unread(
    tmp_path: Path,
) -> None:
    """One launch line runs ``"$1"``, another ``$1``: a spaced argument has two readings and is
    not read; a one-word argument reads the same either way and is.

    MUTATION (verified RED): read the mixed case as unquoted -> svc_a recorded from line 6."""
    text = 'check() {\n  "$1" &\n  $1 -d &\n}\ncheck svc_b\ncheck "svc_a -x"\n'
    assert _launches(tmp_path, text) == [(5, "svc_b", "function_arg", 1)]


def test_a_variable_argument_or_another_parameter_is_not_read(tmp_path: Path) -> None:
    """The variable argument's last segment is a binary's name, so only the ``$`` rule keeps it out.

    MUTATION (verified RED): drop the ``"$" in arg`` check -> svc_a recorded."""
    text = (
        "check() {\n  $BASE/$1 &\n}\n"
        "check $DIR/svc_a\n"
        "two() {\n  $BASE/$2 &\n}\n"
        "two svc_a\n"
        "all() {\n  $@ &\n}\n"
        "all svc_b\n"
    )
    assert _launches(tmp_path, text) == []


def test_a_function_whose_braces_do_not_pair_is_not_read(tmp_path: Path) -> None:
    assert _launches(tmp_path, "check() {\n  $BASE/$1 &\ncheck svc_a\n") == []


# ── T-3 a variable holding a literal command ─────────────────────────────────────────────────


def test_every_literal_value_of_a_variable_is_a_launch(tmp_path: Path) -> None:
    """Two assignments, two binaries: one row each, each pointing at its own assignment line.

    MUTATION (verified RED): take only the variable's first literal value -> RED."""
    text = "FOO=/usr/sbin/svc_a\nFOO=/usr/sbin/svc_b\n$FOO &\n"
    assert _launches(tmp_path, text) == [
        (3, "svc_a", "variable", 1),
        (3, "svc_b", "variable", 2),
    ]


def test_a_variable_after_a_base_path_is_read_as_its_value(tmp_path: Path) -> None:
    text = "BASE=/usr/sbin\nX=svc_a\n$BASE/$X\n"
    assert _launches(tmp_path, text) == [(3, "svc_a", "variable", 2)]


def test_a_substituted_value_is_not_a_literal(tmp_path: Path) -> None:
    assert _launches(tmp_path, "X=$(which foo)\n$X &\n") == []


def test_start_stop_daemon_exec_through_a_variable(tmp_path: Path) -> None:
    text = "VAR=/sbin/svc_a\nstart-stop-daemon -S -x $VAR -- -d\n"
    assert _launches(tmp_path, text) == [(2, "svc_a", "variable", 1)]


# ── T-4 the first command of a command substitution ──────────────────────────────────────────


def test_a_backquoted_command_is_an_inline_launch(tmp_path: Path) -> None:
    assert _launches(tmp_path, "echo `svc_a -x`\n") == [(1, "svc_a", "inline", 1)]


def test_a_quoted_substitution_assignment_is_one_inline_row(tmp_path: Path) -> None:
    """★ An assignment whose value is a command substitution runs that command inside the
    substitution: one row, via inline (the line names no command of its own) — not a literal one.

    MUTATION (verified RED): read the assignment as a literal launch again -> RED."""
    assert _launches(tmp_path, 'RES="$(svc_a | grep x)"\n') == [(1, "svc_a", "inline", 1)]


def test_a_substitution_inside_a_test_is_read(tmp_path: Path) -> None:
    assert _launches(tmp_path, 'if [ "$(svc_a)" = y ]; then\n') == [(1, "svc_a", "inline", 1)]


def test_only_the_first_pipeline_segment_is_the_command(tmp_path: Path) -> None:
    """MUTATION (verified RED): _subst_command reads the whole pipeline -> RED."""
    assert _launches(tmp_path, "echo $(cat /x | svc_a)\n") == []
    assert _launches(tmp_path, "echo $(svc_b | cat)\n") == [(1, "svc_b", "inline", 1)]


def test_a_single_quoted_substitution_is_not_expanded(tmp_path: Path) -> None:
    assert _launches(tmp_path, "echo '$(svc_a)'\n") == []


def test_a_variable_command_inside_a_substitution_is_read_as_its_value(tmp_path: Path) -> None:
    """★ A substitution whose command is a variable runs that variable's value — in an assignment
    (``$( )`` and backquotes alike), and inside a test. Each gives one ``variable`` row pointing at
    the assignment line; the line itself names no command (an assignment is not a literal launch).

    MUTATION (verified RED, 1 failed): stop resolving the variable on the substitution path —
    delete ``out.extend(_variable_launches(command, symtab))`` in _launches_from_line."""
    text = (
        "CFG=/usr/sbin/svc_a\n"
        "IP=$($CFG get lan_ip)\n"
        'if [ "$(${CFG} get x)" = 1 ]; then\n'
        "V=`$CFG get y`\n"
    )
    assert _launches(tmp_path, text) == [
        (2, "svc_a", "variable", 1),
        (3, "svc_a", "variable", 1),
        (4, "svc_a", "variable", 1),
    ]
    # the assignment form still names no command of its own
    assert launched_command("IP=$($CFG get lan_ip)") is None


# ── T-5 one row per (line, command); risk rows ───────────────────────────────────────────────


def test_a_line_gives_one_row_per_distinct_command(tmp_path: Path) -> None:
    """Two binaries on a line are two rows; the same command reached twice is one row with the
    higher-priority via.

    MUTATION (verified RED): dedupe on (line, command, via) -> RED."""
    assert _launches(tmp_path, "/usr/sbin/svc_a $(svc_b)\n") == [
        (1, "/usr/sbin/svc_a", "literal", None),
        (1, "svc_b", "inline", 1),
    ]
    assert _launches(tmp_path, "X=$(svc_c)\n") == [(1, "svc_c", "inline", 1)]


def test_a_launch_line_writes_no_extra_risk_row(tmp_path: Path) -> None:
    """A line that launches a binary and matches a risk rule is one row; a risk-only line keeps
    its single row, as before.

    MUTATION (verified RED): also write the risk row on a launch line -> RED."""
    assert _all_rows(tmp_path, "svc_a $(nvram get x)\n") == [(1, "svc_a", "literal", None)]
    assert _all_rows(tmp_path, "echo `svc_b`\n") == [(1, "svc_b", "inline", 1)]
    assert _all_rows(tmp_path, "eval $CMD\n") == [(1, "eval", "literal", None)]


# ── T-6 provenance on the read sides; literal hunt sites unchanged; older databases ─────────


_INDIRECT = "check() {\n  $BASE/$1 &\n}\ncheck svc_a\n/usr/sbin/svc_b -d &\n"


def test_the_callsites_carry_via_and_an_indirect_launch_is_an_entry(tmp_path: Path) -> None:
    conn = _db(tmp_path)
    _ingest(conn, _INDIRECT)
    out = facts.get_script_callsites(conn, binary="svc_a")
    assert [(s["line_number"], s["via"], s["via_line"]) for s in out["callsites"]] == [
        (4, "function_arg", 1)
    ]
    assert out["by_via"] == {"function_arg": 1}
    lit = facts.get_script_callsites(conn, binary="svc_b")["callsites"]
    assert [(s["via"], s["via_line"]) for s in lit] == [("literal", None)]
    sites = load_entry_index(conn).sites_for("svc_a", "usr/sbin/svc_a")
    fe = {"entry_reach": {"status": "found", "sites": sites}}
    assert _entry_reach_status(fe) == "entry:script"
    conn.close()


def test_a_literal_hunt_site_is_the_exact_dict_it_always_was(tmp_path: Path) -> None:
    """The hunt stores these dicts in each candidate's flow_evidence, which an overlay basis
    compares as text: a literal site keeps its four keys, only an indirect one names its via.

    MUTATION (verified RED): write via / via_line on literal sites too -> RED."""
    conn = _db(tmp_path)
    _ingest(conn, _INDIRECT)
    index = load_entry_index(conn)
    conn.close()
    literal = index.sites_for("svc_b", "usr/sbin/svc_b")
    assert json.dumps(literal) == json.dumps(
        [{"kind": "script_call", "script": "etc/init.d/svc", "line": 5, "arg_source": "literal"}]
    )
    indirect = index.sites_for("svc_a", "usr/sbin/svc_a")
    assert indirect == [
        {
            "kind": "script_call",
            "script": "etc/init.d/svc",
            "line": 4,
            "arg_source": "literal",
            "via": "function_arg",
            "via_line": 1,
        }
    ]


def _older_db(tmp_path: Path) -> Path:
    """An analysis.db as an older scan wrote it: script_calls without via / via_line."""
    conn = _db(tmp_path)
    conn.execute("ALTER TABLE script_calls DROP COLUMN via")
    conn.execute("ALTER TABLE script_calls DROP COLUMN via_line")
    file_id = conn.execute(
        "INSERT INTO non_binary_files (kind, name, path, sha256, size_bytes) "
        "VALUES ('shell_script', 'svc', 'etc/init.d/svc', ?, 1)",
        ("0" * 64,),
    ).lastrowid
    conn.execute(
        "INSERT INTO script_calls (file_id, command, raw_line, line_number, args_pattern) "
        "VALUES (?, '/usr/sbin/svc_a', '/usr/sbin/svc_a &', 3, 'literal')",
        (file_id,),
    )
    conn.commit()
    conn.close()
    return tmp_path / "analysis.db"


def test_an_older_database_read_only_keeps_its_entries(tmp_path: Path) -> None:
    """Read-only, no migration runs: the entry index still finds the site (never silently none),
    and the callsites read without a missing-column error, via reading literal.

    MUTATION (verified RED): drop the column checks -> RED (no site / no such column)."""
    path = _older_db(tmp_path)
    conn = facts.open_analysis_ro(str(path))
    try:
        sites = load_entry_index(conn).sites_for("svc_a", "usr/sbin/svc_a")
        assert sites == [
            {"kind": "script_call", "script": "etc/init.d/svc", "line": 3, "arg_source": "literal"}
        ]
        try:
            out = facts.get_script_callsites(conn, binary="svc_a")
        except sqlite3.OperationalError as exc:  # read as a failed assertion, not a crash
            out = {"error": str(exc)}
        assert out.get("callsites") is not None, out
        assert [(s["via"], s["via_line"]) for s in out["callsites"]] == [("literal", None)]
    finally:
        conn.close()


# ── T-7 paging ───────────────────────────────────────────────────────────────────────────────


def test_the_callsites_page_by_size_and_every_site_is_reachable(tmp_path: Path) -> None:
    """MUTATION (verified RED): return every site on one page again -> RED."""
    conn = _db(tmp_path)
    _ingest(
        conn, "".join(f"/usr/sbin/svc_a --instance {i} --pad {'x' * 60} &\n" for i in range(400))
    )
    seen: list[int] = []
    offset: int | None = 0
    pages = 0
    while offset is not None:
        out = facts.get_script_callsites(conn, binary="svc_a", offset=offset)
        page = out["callsites"]
        assert sum(len(str(s)) for s in page) <= facts._FACT_PAGE_CHARS
        assert out["by_via"] == {"literal": 400}
        paging = out.get("paging") or {}
        assert paging.get("total_matched") == 400 and paging.get("total_chars")
        seen.extend(s["line_number"] for s in page)
        offset = paging.get("next_offset")
        assert (offset is None) == (paging.get("how_to_get_rest") is None)
        pages += 1
    conn.close()
    assert pages > 1
    assert seen == list(range(1, 401))


def test_the_cli_pages_with_offset(tmp_path: Path) -> None:
    conn = _db(tmp_path)
    _ingest(
        conn, "".join(f"/usr/sbin/svc_a --instance {i} --pad {'x' * 60} &\n" for i in range(400))
    )
    conn.close()
    db = str(tmp_path / "analysis.db")

    def run(*extra: str) -> dict[str, Any]:
        result = CliRunner().invoke(
            mcp_cli.fact, ["script-callsites", "svc_a", "--analysis-db", db, *extra]
        )
        assert result.exit_code == 0, result.output
        return dict(json.loads(result.output))

    first = run()
    nxt = first["paging"]["next_offset"]
    assert nxt is not None and first["callsites"][0]["line_number"] == 1
    second = run("--offset", str(nxt))
    assert second["callsites"][0]["line_number"] == nxt + 1


@pytest.mark.parametrize("offset", [-1, "3", True])
def test_a_bad_offset_is_an_error(tmp_path: Path, offset: Any) -> None:
    conn = _db(tmp_path)
    out = facts.get_script_callsites(conn, binary="svc_a", offset=offset)
    conn.close()
    assert "error" in out and "callsites" not in out


def test_an_older_database_opened_for_writing_gains_the_columns(tmp_path: Path) -> None:
    """open_db adds via / via_line to an older script_calls (NULL on its rows, which reads
    literal), and a re-ingest then writes them.

    MUTATION (verified RED): leave the two columns out of _ADDED_COLUMNS -> RED."""
    path = _older_db(tmp_path)
    conn = open_db(path)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(script_calls)")}
    assert {"via", "via_line"} <= cols
    assert [tuple(r) for r in conn.execute("SELECT via, via_line FROM script_calls")] == [
        (None, None)
    ]
    _ingest(conn, "X=svc_b\n$X &\n", rel="etc/init.d/other")
    assert ("svc_b", "variable", 1) in [
        tuple(r) for r in conn.execute("SELECT command, via, via_line FROM script_calls")
    ]
    conn.close()


# ── a stop line launches nothing; a hand-off to a function elsewhere is recorded apart ─────────

_INIT = """#!/bin/sh
SERVICE_PATH="/usr/sbin/httpd"
. /lib/functions/service.sh
start() {
    ${SVCDBG}service_start ${SERVICE_PATH} -d
}
stop() {
    service_stop ${SERVICE_PATH}
    start-stop-daemon -K -x ${SERVICE_PATH} -s SIGKILL
    start-stop-daemon --stop --exec /usr/sbin/dropbear
    ls /usr/sbin/httpd
    start-stop-daemon -S -x /usr/sbin/dropbear
}
"""


def _handoffs(conn: sqlite3.Connection) -> list[tuple[Any, ...]]:
    return [
        tuple(r)
        for r in conn.execute(
            "SELECT line_number, binary_path, function, via_line FROM script_handoffs "
            "ORDER BY line_number"
        )
    ]


def test_a_stop_line_is_no_launch(tmp_path: Path) -> None:
    """★ `start-stop-daemon -K` / `--stop` names the binary it stops: no launch row. A `-S` line
    launches.

    MUTATION (verified RED): read the -x of a stop line as a launch again -> RED."""
    conn = _db(tmp_path, ("httpd", "dropbear"))
    conn.execute("INSERT INTO fs_symlinks (link_name) VALUES ('ls')")
    _ingest(conn, _INIT)
    assert _rows(conn) == [(12, "/usr/sbin/dropbear", "literal", None)]


def test_a_binary_handed_to_a_function_defined_elsewhere_is_recorded_apart_not_launched(
    tmp_path: Path,
) -> None:
    """★ `service_start ${SERVICE_PATH}` (service_start defined in a sourced file) hands httpd to a
    function this file does not define: recorded in script_handoffs, with the function and the
    variable's line — not as a launch, so it is no entry evidence. A command of the firmware (`ls`,
    a link here) hands nothing; get_script_callsites lists the hand-offs apart, as not launches.

    MUTATION (verified RED): record nothing -> RED; take a firmware command for a function ->
    `ls` reads as a hand-off -> RED."""
    conn = _db(tmp_path, ("httpd", "dropbear"))
    conn.execute("INSERT INTO fs_symlinks (link_name) VALUES ('ls')")
    _ingest(conn, _INIT)
    assert _handoffs(conn) == [
        (5, "/usr/sbin/httpd", "service_start", 2),
        (8, "/usr/sbin/httpd", "service_stop", 2),
    ]
    got = facts.get_script_callsites(conn, binary="httpd")
    assert got["callsites"] == []
    assert [h["function"] for h in got["handoffs"]] == ["service_start", "service_stop"]
    assert "not launches" in got["handoffs_note"]
    index = load_entry_index(conn)
    assert index.sites_for("httpd", "usr/sbin/httpd") == []  # no entry evidence


def test_a_risk_line_in_an_assignment_names_the_command_its_substitution_runs(
    tmp_path: Path,
) -> None:
    """A risk-marked VAR=$(cmd …) line keeps its one row, naming cmd (via inline) — never a row
    with no command.

    MUTATION (verified RED): keep launched_command's None as the row's command -> RED."""
    assert _all_rows(tmp_path, "X=$(eval $CMD)\n") == [(1, "eval", "inline", 1)]


def test_a_risk_line_names_the_first_substitution_the_shell_runs(tmp_path: Path) -> None:
    """The risk-line fallback names the substitution that runs first: by position, so the outer
    one wins over one nested inside it, and never one inside single quotes, which the shell does
    not expand (``awk '{print $(NF-1)}'`` runs no ``NF-1``). The launch reading skips the same ones.

    MUTATION (verified RED, 1 failed): fallback takes the first of ``_substitutions`` unsorted and
    unfiltered (all ``$(`` before any backquote, single quotes not excluded) -> RED (``NF-1``).
    MUTATION (verified RED, 1 failed): substitutions not sorted by position (single quotes still
    excluded) -> RED (``echo`` for the backquoted ``printf``)."""
    text = "v=`echo $x | awk '{print $(NF-1)}'`\n"
    assert _all_rows(tmp_path, text) == [(1, "echo", "inline", 1)]
    text = "t=`printf '%x' $(echo $y)`\n"
    assert _all_rows(tmp_path, text) == [(1, "printf", "inline", 1)]


def test_a_backquoted_substitution_continued_on_the_next_line_names_its_command(
    tmp_path: Path,
) -> None:
    """A backquote left open at a line's end (continued with ``\\``) runs to the end of that line,
    as an open ``$(`` does: the command it starts is read, and launches a binary of the firmware.

    MUTATION (verified RED, 1 failed): only paired backquotes read -> RED (no launch row)."""
    where = tmp_path / "db"
    where.mkdir()
    conn = _db(where, ("foo",))
    try:
        _ingest(conn, "X=`/usr/sbin/foo get a \\\n | cut -f1`\n")
        launches = [r for r in _rows(conn) if r[1] and r[1].rsplit("/", 1)[-1] == "foo"]
    finally:
        conn.close()
    assert launches == [(1, "/usr/sbin/foo", "inline", 1)]


def test_a_declared_or_spaced_substitution_assignment_names_the_substituted_command(
    tmp_path: Path,
) -> None:
    """``local x=$(cat f)`` and ``x=$( cat f )`` run ``cat`` in a substitution: the line names no
    command of its own (not ``local``, not the assignment), and the risk row names ``cat`` inline.

    MUTATION (verified RED, 1 failed): declaration keyword not passed over -> RED (``local``,
    literal). MUTATION (verified RED, 1 failed): old assignment pattern requiring a non-space
    right after ``$(`` -> RED (``$( cat f )`` reads as a literal line)."""
    assert launched_command("local x=$(cat f)") is None
    assert launched_command("export x=`cat f`") is None
    assert launched_command("x=$( cat f )") is None
    assert launched_command("local x") == "local"  # a bare declaration is still the builtin
    assert _all_rows(tmp_path, "local x=$(cat f)\n") == [(1, "cat", "inline", 1)]
    assert _all_rows(tmp_path, "x=$( cat f )\n") == [(1, "cat", "inline", 1)]


def test_an_unpaired_quote_before_a_substitution_still_names_its_command(tmp_path: Path) -> None:
    """``v="$(grep x f \\`` cannot be split by the shell's quoting rules (its quote is closed on a
    later line), so its words keep the quote: the assignment is still recognized as a substitution
    and the risk row names ``grep`` inline, never the literal word ``x`` after it.

    MUTATION (verified RED, 1 failed): optional quote dropped from the assignment pattern -> RED
    (literal ``x``)."""
    assert _all_rows(tmp_path, 'v="$(grep x f \\\n') == [(1, "grep", "inline", 1)]
