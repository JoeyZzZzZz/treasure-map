# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Launch edges through a runner (lib/hunt/exec_runners).

A runner is a function that execs the argv array its caller built. The projection pass reads only
the runner's own exec call (a parameter, unresolved); this pass reads the caller's text for the
program it named, by the runner's shape, and lands the row in the same exec_edge table.

Every name below is synthetic. Each test names the mutation that turns it red; the recipes were
run against the code and the result is recorded with them.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from treasure_map.lib import rescan_version as rv
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.diff import code_version as dcv
from treasure_map.lib.diff.loader import FuncRow
from treasure_map.lib.hunt import exec_runners as er
from treasure_map.lib.hunt import run_analyzer2
from treasure_map.lib.hunt.exec_edges import (
    EXEC_SINKS,
    ExecEdgeInventory,
    _build_row,
    _exec_facts,
    build_symlink_index,
    exec_entry_sites,
)
from treasure_map.lib.query import exec_edges as qee
from treasure_map.lib.query import launched_by
from treasure_map.lib.storage.connection import open_db

# ── builders ──────────────────────────────────────────────────────────────────────────

_CALL_NAME_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


def _tokens(pseudocode: str, base: int) -> str:
    """Call tokens the way the extractor's bridge emits them: one per call name in the body, with
    the call instruction's address. Every call gets its own address, so two calls to one runner
    never share a sink_addr."""
    brace = pseudocode.find("{")
    toks: list[dict[str, Any]] = []
    for i, m in enumerate(_CALL_NAME_RE.finditer(pseudocode, brace + 1)):
        if m.group(1) in ("if", "while", "for", "return", "sizeof"):
            continue
        toks.append(
            {
                "call_token": m.group(1),
                "token_addr": f"0x{base + 4 * i:x}",
                "op_addr": f"0x{base + 4 * i:x}",
                "opcode": 7,
                "text_off": m.start(1),
                "line": pseudocode.count("\n", 0, m.start()),
            }
        )
    return json.dumps(toks)


def _fn(
    fid: int,
    name: str,
    body: str,
    *,
    binary: str = "tool_a",
    bid: int = 1,
    callees: tuple[str, ...] = (),
) -> FuncRow:
    return FuncRow(
        func_id=fid,
        binary_id=bid,
        binary_name=binary,
        binary_path=f"/usr/sbin/{binary}",
        binary_sha256=str(bid) * 64,
        name=name,
        address=f"{0x10000 * bid + fid:08x}",
        pseudocode=body,
        pseudocode_hash=None,
        callees=json.dumps(list(callees)),
        call_tokens=_tokens(body, 0x10000 * bid + 0x100 * fid),
    )


def _inventory(*names: str) -> ExecEdgeInventory:
    return ExecEdgeInventory(
        symlinks=build_symlink_index([]),
        bin_names={n: (f"usr/bin/{n}",) for n in names},
    )


def _no_links() -> er.LinkTables:
    return er.LinkTables(exported_calls={}, imports=frozenset())


def _edges(
    funcs: list[FuncRow],
    links: er.LinkTables | None = None,
    inventory: ExecEdgeInventory | None = None,
) -> list[Any]:
    runners = er.find_runners(funcs)
    callers = er.link_callers(funcs, runners, links or _no_links())
    return er.build_runner_edges(funcs, callers, inventory or _inventory(), "run1")


# Runner bodies, one per image shape.
_HEAD_RUNNER = """
int FUN_00012000(char **param_1,int param_2)

{
  int iVar1;
  iVar1 = fork();
  if (iVar1 == 0) {
    execvp(*param_1,param_1);
  }
  return iVar1;
}
"""
_PATH_RUNNER = """
int launch_it(char *param_1,char **param_2,int param_3)

{
  execve(param_1,param_2,env_list);
  return 0;
}
"""
_CONST_RUNNER = """
void fixed_tool_main(int param_1,char **param_2)

{
  param_2 = param_2 + 1;
  execvp("/usr/sbin/fixed_tool",param_2);
  return;
}
"""


def _caller(name: str, lines: str) -> str:
    return f"\nvoid {name}(void)\n\n{{\n  undefined4 local_28;\n{lines}\n  return;\n}}\n"


# ── recognising a runner ──────────────────────────────────────────────────────────────


def test_the_three_image_shapes_are_recognised() -> None:
    """Each body reads as exactly the shape its exec call has.

    MUTATION (verified RED, 1 failed): in runner_shapes drop the ``SHAPE_PATH_PARAM`` branch
    (``if False and path.form in ...``) -> the path-parameter runner reads as no runner."""
    shapes = {
        name: er.runner_shapes(name, body)
        for name, body in (
            ("FUN_00012000", _HEAD_RUNNER),
            ("launch_it", _PATH_RUNNER),
            ("fixed_tool_main", _CONST_RUNNER),
        )
    }
    assert shapes["FUN_00012000"] == {er.RunnerShape(er.SHAPE_ARGV_HEAD, 0)}
    assert shapes["launch_it"] == {er.RunnerShape(er.SHAPE_PATH_PARAM, 1, path_index=0)}
    assert shapes["fixed_tool_main"] == {
        er.RunnerShape(er.SHAPE_PATH_CONST, 1, path_const="/usr/sbin/fixed_tool")
    }


def test_a_c_library_exec_wrapper_is_never_a_runner() -> None:
    """The C library's own ``execv`` wraps ``execve`` with its parameters passed straight through —
    the runner shape exactly. It is excluded by NAME: every call to it is a command sink the
    projection already reads from the caller, and a second edge would repeat it.

    MUTATION (verified RED, 1 failed): in find_runners drop ``or func.name in NOT_RUNNER_NAMES``
    -> the wrapper is a runner."""
    body = """
int execv(char *__path,char **__argv)

{
  int iVar1;
  iVar1 = execve(__path,__argv,environ);
  return iVar1;
}
"""
    libc = _fn(1, "execv", body, binary="libc_like.so", callees=("execve",))
    # The precondition: the body alone DOES read as a runner, so the exclusion is what decides.
    assert er.runner_shapes("execv", body) == {er.RunnerShape(er.SHAPE_PATH_PARAM, 1, path_index=0)}
    assert er.find_runners([libc]) == {}
    assert "execv" in er.NOT_RUNNER_NAMES and "system" in er.NOT_RUNNER_NAMES


def test_parameters_are_read_off_the_signature_not_matched_by_a_param_n_pattern() -> None:
    """A runner whose parameters carry real names counts the same as a stripped one.

    MUTATION (verified RED, 1 failed): in signature_params keep only ``param_<n>`` names
    (``names.append(idents[-1] if idents and re.fullmatch(r"param_\\d+", idents[-1]) else "")``)
    -> the named runner is no runner."""
    body = """
int spawn_tool(const char *path,char *const *argv)

{
  return execv(path,(char **)argv);
}
"""
    assert er.signature_params("spawn_tool", body) == ["path", "argv"]
    assert er.runner_shapes("spawn_tool", body) == {
        er.RunnerShape(er.SHAPE_PATH_PARAM, 1, path_index=0)
    }


def test_a_log_message_naming_an_exec_call_is_not_a_call() -> None:
    """``call_offsets`` skips text inside a string literal, so a message that spells out a runner
    call does not make its function a runner; its real exec call uses a local buffer.

    MUTATION (verified RED, 1 failed): in runner_shapes find the exec calls with a bare pattern
    (``for off in (m.end() - 1 for m in re.finditer(rf"\\b{api}\\s*\\(", pseudocode))``) -> the
    message's ``execv(*param_1,param_1)`` reads as a shape (i) call."""
    body = """
int FUN_00013000(char **param_1)

{
  char acStack_100 [256];
  log_line("execv(*param_1,param_1) failed: %s",acStack_100);
  return execv(acStack_100,param_1);
}
"""
    assert er.runner_shapes("FUN_00013000", body) == frozenset()


def test_a_rebound_image_parameter_is_not_a_runner_but_a_constant_image_does_not_care() -> None:
    """A parameter assigned in the body no longer holds the caller's value: the image read from it
    is not the caller's. The guard applies to the parameter the image is read FROM — a constant
    image (shape iii) does not depend on argv, however argv was shifted.

    MUTATION (verified RED, 1 failed): in runner_shapes drop ``and not _rebound(body, argv.root)``
    -> the shifted head runner reads as shape (i).
    MUTATION (verified RED, 1 failed): in runner_shapes skip every rebound argv up front
    (``if _rebound(body, argv.root): continue`` before the constant check) -> the constant runner,
    whose argv is shifted, is no runner."""
    shifted = _HEAD_RUNNER.replace(
        "  iVar1 = fork();", "  param_1 = param_1 + 1;\n  iVar1 = fork();"
    )
    assert er.runner_shapes("FUN_00012000", shifted) == frozenset()
    assert er.runner_shapes("fixed_tool_main", _CONST_RUNNER) != frozenset()


def test_the_variadic_family_is_never_a_runner() -> None:
    """``execl`` passes argv as a variadic list — structurally invisible, never read."""
    body = """
int FUN_00014000(char *param_1,char *param_2)

{
  return execl(param_1,param_1,param_2,0);
}
"""
    assert er.runner_shapes("FUN_00014000", body) == frozenset()


# ── reading the target, by shape ──────────────────────────────────────────────────────


def test_shape_one_reads_the_first_slot_of_the_array_the_caller_passed() -> None:
    """MUTATION (verified RED, 1 failed): in _target_values return ``[None]`` for SHAPE_ARGV_HEAD
    before reading the slot -> the token is gone."""
    runner = _fn(1, "FUN_00012000", _HEAD_RUNNER, callees=("fork", "execvp"))
    caller = _fn(
        2,
        "start_helper",
        _caller("start_helper", '  local_28 = "helper_tool";\n  FUN_00012000(&local_28,0);'),
        callees=("FUN_00012000",),
    )
    rows = _edges([runner, caller], inventory=_inventory("helper_tool"))
    assert [(r.launcher_function, r.exec_api, r.target_token) for r in rows] == [
        ("start_helper", "FUN_00012000", "helper_tool")
    ]
    assert rows[0].target_resolution == "resolved_direct"
    assert rows[0].target_binary == "usr/bin/helper_tool"


def test_shape_two_reads_the_path_argument_not_the_display_name() -> None:
    """The image of ``execve(path, argv, env)`` is ``path``. The caller's argv[0] is a display
    name — here a different string on purpose, so reading the wrong field is visible.

    MUTATION (verified RED, 1 failed): in _target_values read the argv head for SHAPE_PATH_PARAM
    too (``if shape.kind == SHAPE_PATH_PARAM and False:``) -> the token is "shown_name"."""
    runner = _fn(1, "launch_it", _PATH_RUNNER, callees=("execve",))
    caller = _fn(
        2,
        "start_real",
        _caller(
            "start_real",
            '  local_28 = "shown_name";\n  launch_it("/usr/sbin/real_image",&local_28,0);',
        ),
        callees=("launch_it",),
    )
    rows = _edges([runner, caller])
    assert [r.target_token for r in rows] == ["/usr/sbin/real_image"]


def test_shape_three_reads_the_runners_own_constant() -> None:
    """MUTATION (verified RED, 1 failed): in _target_values return ``[None]`` for SHAPE_PATH_CONST
    -> the constant is not the token."""
    runner = _fn(1, "fixed_tool_main", _CONST_RUNNER, callees=("execvp",))
    caller = _fn(
        2,
        "start_fixed",
        _caller("start_fixed", '  local_28 = "other_name";\n  fixed_tool_main(1,&local_28);'),
        callees=("fixed_tool_main",),
    )
    rows = _edges([runner, caller])
    assert [r.target_token for r in rows] == ["/usr/sbin/fixed_tool"]


def test_an_unreadable_target_still_produces_its_edge_with_no_token() -> None:
    """A head slot copied from a ``.data`` word is not read as the word's bytes: the edge is kept,
    with no token and an unresolved state — never guessed, never dropped.

    MUTATION (verified RED, 1 failed): in _target_values take a non-literal write's text as the
    token (``values = [string_literal(w) or w for w in writes]``) -> token "DAT_00456000".
    MUTATION (verified RED, 1 failed): in build_runner_edges skip a None value
    (``if value is None: continue``) -> no row at all."""
    runner = _fn(1, "FUN_00012000", _HEAD_RUNNER, callees=("fork", "execvp"))
    caller = _fn(
        2,
        "start_template",
        _caller("start_template", "  local_28 = DAT_00456000;\n  FUN_00012000(&local_28,0);"),
        callees=("FUN_00012000",),
    )
    rows = _edges([runner, caller])
    assert len(rows) == 1
    assert rows[0].target_token is None
    assert rows[0].target_resolution == "unresolved"
    assert rows[0].argv_provenance == er.RUNNER_PROVENANCE


def test_a_mixed_slot_yields_each_literal_plus_one_unresolved_row() -> None:
    """Every write to the head slot is read (the projection's over-approximation): each literal is
    a row and any non-literal write adds one unresolved row.

    MUTATION (verified RED, 1 failed): in _target_values keep only the first write
    (``writes = writes[:1]``) -> one row instead of three."""
    runner = _fn(1, "FUN_00012000", _HEAD_RUNNER, callees=("fork", "execvp"))
    lines = (
        "  if (g_mode == 0) {\n"
        '    local_28 = "tool_one";\n'
        "  }\n"
        "  else {\n"
        '    local_28 = "tool_two";\n'
        "  }\n"
        "  if (g_mode == 2) {\n"
        "    local_28 = pcVar_from_elsewhere;\n"
        "  }\n"
        "  FUN_00012000(&local_28,0);"
    )
    caller = _fn(2, "start_mixed", _caller("start_mixed", lines), callees=("FUN_00012000",))
    rows = _edges([runner, caller])
    assert sorted((r.target_token or "") for r in rows) == ["", "tool_one", "tool_two"]
    assert len({r.sink_addr for r in rows}) == 1


def test_two_calls_with_one_token_are_two_rows_keyed_by_their_addresses() -> None:
    """The fold key is the projection's: (binary, function, sink address, token). Two calls to the
    runner are two call instructions, so the same token at both is two rows.

    MUTATION (verified RED, 1 failed): in build_runner_edges record no address
    (``sink_addr = None``) -> the two rows fold into one with occurrences 2."""
    runner = _fn(1, "FUN_00012000", _HEAD_RUNNER, callees=("fork", "execvp"))
    lines = '  local_28 = "tool_one";\n  FUN_00012000(&local_28,0);\n  FUN_00012000(&local_28,1);'
    caller = _fn(2, "start_twice", _caller("start_twice", lines), callees=("FUN_00012000",))
    rows = _edges([runner, caller])
    assert [r.target_token for r in rows] == ["tool_one", "tool_one"]
    assert len({r.sink_addr for r in rows}) == 2
    assert all(r.sink_addr for r in rows)
    assert all(r.occurrences == 1 for r in rows)


def test_the_stack_alias_names_one_cell_twice() -> None:
    """``&stack0xN`` at the call and ``in_stack_N`` at the write are the decompiler's two names for
    one cell; the slot is read through that alias.

    MUTATION (verified RED, 1 failed): in _head_slot drop the alias (``alias = None``) -> the
    edge is unresolved."""
    runner = _fn(1, "FUN_00012000", _HEAD_RUNNER, callees=("fork", "execvp"))
    lines = '  in_stack_00000124 = "tool_vlan";\n  FUN_00012000(&stack0x00000124,0);'
    caller = _fn(2, "start_alias", _caller("start_alias", lines), callees=("FUN_00012000",))
    rows = _edges([runner, caller])
    assert [r.target_token for r in rows] == ["tool_vlan"]


def test_facts_follow_the_projection_rules_and_a_shell_is_not_read_into() -> None:
    """Every row is built by the projection's own ``_exec_facts`` + ``_build_row``: a shell image
    is ``shell_wrapped`` with ``inner_command_visible=0``, argv stays structurally invisible, and
    the command in the next slot is never read.

    MUTATION (verified RED, 1 failed): in build_runner_edges build the facts locally with the next
    slot as the template (``dataclasses.replace(_exec_facts(value), argv_template="-c")``) -> the
    row carries a template.
    MUTATION (verified RED, 1 failed): in build_runner_edges drop the provenance mark
    (``row = row``) -> argv_provenance is the projection's token kind."""
    runner = _fn(1, "FUN_00012000", _HEAD_RUNNER, callees=("fork", "execvp"))
    lines = (
        '  local_28 = "/bin/sh";\n  local_24 = "-c";\n  local_20 = "tool_inner --flag";\n'
        "  FUN_00012000(&local_28,0);"
    )
    caller = _fn(2, "start_shell", _caller("start_shell", lines), callees=("FUN_00012000",))
    (row,) = _edges([runner, caller])
    assert row.shell_wrapped == 1
    assert row.inner_command_visible == 0
    assert row.argv_visibility == "structurally_invisible"
    assert row.argv_template is None
    expected = _build_row(
        caller, "FUN_00012000", row.sink_addr, _exec_facts("/bin/sh"), _inventory(), "run1"
    )
    assert row == dataclasses.replace(expected, argv_provenance=er.RUNNER_PROVENANCE)


# ── linking the callers ───────────────────────────────────────────────────────────────


def test_a_same_binary_runner_is_linked_through_the_callers_callee_list() -> None:
    """A non-exported runner is linked within its binary through the caller's callee list; the
    import gate does not apply there.

    MUTATION (verified RED, 1 failed): in link_callers drop the within-binary loop (only the
    exported-call links remain, as with an "exported only" requirement) -> no link.
    MUTATION (verified RED, 1 failed): in link_callers apply the import gate within the binary
    too (``if not hits or (f.binary_id, callee) not in links.imports: continue``) -> no link."""
    runner = _fn(1, "FUN_00012000", _HEAD_RUNNER, callees=("fork", "execvp"))
    caller = _fn(
        2,
        "start_local",
        _caller("start_local", '  local_28 = "tool_one";\n  FUN_00012000(&local_28,0);'),
        callees=("FUN_00012000",),
    )
    runners = er.find_runners([runner, caller])
    assert er.link_callers([runner, caller], runners, _no_links()) == {
        2: {"FUN_00012000": runners[1]}
    }


def test_a_name_several_functions_hold_is_left_unresolved() -> None:
    """Two functions of one binary share the runner's name: which one the call reaches is not
    decided, so the edge is kept unresolved rather than read through one of them.

    MUTATION (verified RED, 1 failed): in link_callers read through the first hit regardless
    (``named[callee] = runners[hits[0]]``) -> the edge carries "tool_one"."""
    runner = _fn(
        1, "run_helper", _HEAD_RUNNER.replace("FUN_00012000", "run_helper"), callees=("execvp",)
    )
    other = _fn(3, "run_helper", "\nint run_helper(int param_1)\n\n{\n  return 0;\n}\n")
    caller = _fn(
        2,
        "start_dup",
        _caller("start_dup", '  local_28 = "tool_one";\n  run_helper(&local_28,0);'),
        callees=("run_helper",),
    )
    rows = _edges([runner, other, caller])
    assert [(r.target_token, r.target_resolution) for r in rows] == [(None, "unresolved")]


def test_a_cross_binary_runner_needs_the_callers_import() -> None:
    """Across binaries the exported-call table links a call by NAME; the caller's binary must also
    record an import of that name.

    MUTATION (verified RED, 1 failed): in link_callers drop the import gate -> the caller without
    the import is linked too."""
    runner = _fn(
        1,
        "run_list",
        _HEAD_RUNNER.replace("FUN_00012000", "run_list"),
        binary="libtool.so",
        bid=1,
        callees=("execvp",),
    )
    importer = _fn(
        2,
        "start_imported",
        _caller("start_imported", '  local_28 = "tool_one";\n  run_list(&local_28,0);'),
        binary="daemon_one",
        bid=2,
        callees=("run_list",),
    )
    stranger = _fn(
        3,
        "start_unimported",
        _caller("start_unimported", '  local_28 = "tool_two";\n  run_list(&local_28,0);'),
        binary="daemon_two",
        bid=3,
        callees=("run_list",),
    )
    links = er.LinkTables(exported_calls={2: (1,), 3: (1,)}, imports=frozenset({(2, "run_list")}))
    rows = _edges([runner, importer, stranger], links=links)
    assert [(r.launcher_binary, r.target_token) for r in rows] == [("daemon_one", "tool_one")]


def test_exporters_that_read_differently_leave_the_link_unresolved() -> None:
    """Two binaries export the name and do not read the same way: which one the caller reaches is
    not decided, so the edge is kept with no token. The two exporters read DIFFERENT arguments of
    the one call and each would find a literal there, so reading through either one shows.

    MUTATION (verified RED, 1 failed): in link_callers read through any one exporter
    (``named[callee_name] = next(s for s in shapes if s)``) -> a token appears."""
    head = _fn(
        1,
        "run_list",
        _HEAD_RUNNER.replace("FUN_00012000", "run_list"),
        binary="libone.so",
        bid=1,
        callees=("execvp",),
    )
    path_second = (
        "\nint run_list(char **param_1,char *param_2)\n\n{\n"
        "  execve(param_2,param_1,env_list);\n  return 0;\n}\n"
    )
    assert er.runner_shapes("run_list", path_second) == {
        er.RunnerShape(er.SHAPE_PATH_PARAM, 0, path_index=1)
    }
    path = _fn(
        4,
        "run_list",
        path_second,
        binary="libtwo.so",
        bid=4,
        callees=("execve",),
    )
    caller = _fn(
        2,
        "start_either",
        _caller(
            "start_either",
            '  local_28 = "tool_one";\n  run_list(&local_28,"/usr/sbin/real_image");',
        ),
        binary="daemon_one",
        bid=2,
        callees=("run_list",),
    )
    links = er.LinkTables(exported_calls={2: (1, 4)}, imports=frozenset({(2, "run_list")}))
    rows = _edges([head, path, caller], links=links)
    assert [(r.target_token, r.target_resolution) for r in rows] == [(None, "unresolved")]


# ── entry sites and the honesty row ───────────────────────────────────────────────────


def test_only_a_runner_edge_resolved_to_a_binary_is_an_entry_site() -> None:
    """The projection's entry filter applies unchanged to runner rows: only a target resolved to a
    real binary is offered. A script target carries a path but is no binary; an unmatched or an
    unresolved token carries none.

    MUTATION (verified RED, 1 failed): in exec_edges.exec_entry_sites keep only the path test
    (``if not row.target_binary: continue``) -> the script target is offered as an entry site."""
    runner = _fn(1, "FUN_00012000", _HEAD_RUNNER, callees=("fork", "execvp"))
    lines = (
        '  local_28 = "helper_tool";\n  FUN_00012000(&local_28,0);\n'
        '  local_24 = "not_in_inventory";\n  FUN_00012000(&local_24,0);\n'
        '  local_20 = "tool_script";\n  FUN_00012000(&local_20,0);\n'
        "  local_1c = DAT_00456000;\n  FUN_00012000(&local_1c,0);"
    )
    caller = _fn(2, "start_four", _caller("start_four", lines), callees=("FUN_00012000",))
    inventory = dataclasses.replace(
        _inventory("helper_tool"), scripts={"tool_script": ("etc/tool_script",)}
    )
    rows = _edges([runner, caller], inventory=inventory)
    assert sorted(r.target_resolution for r in rows) == [
        "resolved_direct",
        "resolved_script",
        "unmatched",
        "unresolved",
    ]
    sites = exec_entry_sites(rows)
    assert list(sites) == ["usr/bin/helper_tool"]
    assert [s["exec_api"] for s in sites["usr/bin/helper_tool"]] == ["FUN_00012000"]


def test_the_status_row_is_written_for_every_binary_even_at_zero_edges() -> None:
    """MUTATION (verified RED, 1 failed): in runner_scan_status take the binaries from the rows
    alone (``binaries = set(found)``) -> the quiet binary has no row."""
    runner = _fn(1, "FUN_00012000", _HEAD_RUNNER, callees=("fork", "execvp"))
    quiet = _fn(5, "idle", "\nint idle(void)\n\n{\n  return 0;\n}\n", binary="quiet_bin", bid=5)
    unread = dataclasses.replace(
        _fn(6, "start_dark", "", binary="dark_bin", bid=6, callees=("FUN_00012000",)),
        pseudocode=None,
    )
    funcs = [runner, quiet, unread]
    links = _no_links()
    runners = er.find_runners(funcs)
    callers = er.link_callers(funcs, runners, links)
    status = er.runner_scan_status([], funcs, callers, links, {"FUN_00012000"}, "run1")
    by_binary = {s.binary: s for s in status}
    assert set(by_binary) == {"tool_a", "quiet_bin", "dark_bin"}
    assert {s.detector for s in status} == {er.RUNNER_DETECTOR}
    assert by_binary["quiet_bin"].scanned == 1
    assert by_binary["dark_bin"].scanned == 0
    assert all(s.found_count == 0 for s in status)
    assert "in_stack" in er.UNSUPPORTED_NOTE and ".data" in er.UNSUPPORTED_NOTE


# ── end to end: the hunt writes the rows, the read layer answers ─────────────────────


_WORK_BODY = (
    '\nvoid NAME(char *arg)\n\n{\n  char cmd[64];\n  sprintf(cmd,"/bin/ping %s",arg);\n'
    "  system(cmd);\n  return;\n}\n"
)


def _runner_db(tmp_path: Path, *, import_gate: bool = True) -> Path:
    """A four-binary firmware: ``libtool.so`` exports a runner ``run_list`` (shape i);
    ``daemon_one`` calls it with ``helper_tool`` and also calls the C library's ``execv`` with a
    literal path to ``quiet_bin`` (the projection's edge). ``helper_tool`` holds a command-sink
    candidate nothing else in the rootfs mentions, so only the runner edge can give it an entry
    site; ``quiet_bin`` and ``daemon_one`` hold candidates of the same shape whose readings this
    pass must not move."""
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    for bid, name in ((1, "libtool.so"), (2, "daemon_one"), (3, "helper_tool"), (4, "quiet_bin")):
        conn.execute(
            "INSERT INTO binaries (id, name, path, sha256, last_seen_at) "
            "VALUES (?, ?, ?, ?, '2026-01-01T00:00:00')",
            (bid, name, f"/usr/sbin/{name}", str(bid) * 64),
        )
    runner_body = _HEAD_RUNNER.replace("FUN_00012000", "run_list")
    caller_body = _caller(
        "daemon_main",
        '  local_28 = "helper_tool";\n  run_list(&local_28,0);\n'
        '  execv("/usr/sbin/quiet_bin",argv_list);',
    )
    prov = [
        {
            "sink_idx": 0,
            "sink": "execv",
            "sink_addr": "0x20140",
            "arg_idx": 0,
            "provenance": {
                "kind": "constant",
                "value": "/usr/sbin/quiet_bin",
                "value_kind": "literal_string",
            },
        }
    ]
    work = ["sprintf", "system"]
    rows = (
        (1, 1, "run_list", runner_body, ["fork", "execvp"], "[]"),
        (2, 2, "daemon_main", caller_body, ["run_list", "execv"], json.dumps(prov)),
        (3, 3, "do_work", _WORK_BODY.replace("NAME", "do_work"), work, "[]"),
        (4, 4, "qwork", _WORK_BODY.replace("NAME", "qwork"), work, "[]"),
        (5, 2, "dwork", _WORK_BODY.replace("NAME", "dwork"), work, "[]"),
    )
    for fid, bid, name, body, callees, sp in rows:
        conn.execute(
            "INSERT INTO functions (id, binary_id, name, address, pseudocode, callees, "
            "sink_provenance, call_tokens) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                fid,
                bid,
                name,
                f"{0x10000 * bid + 0x100 * fid:08x}",
                body,
                json.dumps(callees),
                sp,
                _tokens(body, 0x10000 * bid + 0x100 * fid + 0x10),
            ),
        )
    conn.execute(
        "INSERT INTO exports (binary_id, func_name, address) VALUES (1, 'run_list', '00010000')"
    )
    if import_gate:
        conn.execute("INSERT INTO imports (binary_id, func_name) VALUES (2, 'run_list')")
    conn.execute(
        "INSERT INTO xrefs (caller_binary_id, caller_func_id, callee_binary_id, callee_func_id, "
        "xref_type) VALUES (2, 2, 1, 1, 'callees_exports')"
    )
    conn.commit()
    conn.close()
    return db


def _hunt(tmp_path: Path, **kw: Any) -> Path:
    atlas_path = tmp_path / "atlas.db"
    run_analyzer2(_runner_db(tmp_path, **kw), atlas_path, source_run_id="run1")
    return atlas_path


def test_the_hunt_lands_runner_rows_beside_the_projection_and_keeps_them_apart(
    tmp_path: Path,
) -> None:
    """The runner row and the projection row share the table; the runner row is marked by its
    exec_api (the runner) and argv_provenance, so the two never read alike.

    MUTATION (verified RED, 1 failed): in analyzer2 write only the projection's rows
    (``add_exec_edges(atlas, exec_edge_rows, commit=False)``) -> launched_by finds no edge."""
    atlas_path = _hunt(tmp_path)
    conn = open_atlas(atlas_path)
    try:
        rows = conn.execute(
            "SELECT launcher_function, exec_api, argv_provenance, target_token, target_resolution "
            "FROM exec_edge WHERE source_run_id = 'run1' ORDER BY exec_api"
        ).fetchall()
        answer = launched_by(conn, "helper_tool", run_id="run1")
    finally:
        conn.close()
    assert [tuple(r) for r in rows] == [
        ("daemon_main", "execv", "clean_literal", "/usr/sbin/quiet_bin", "resolved_direct"),
        ("daemon_main", "run_list", er.RUNNER_PROVENANCE, "helper_tool", "resolved_direct"),
    ]
    runner_rows = [r for r in rows if r[2] == er.RUNNER_PROVENANCE]
    assert not {r[1] for r in runner_rows} & EXEC_SINKS
    assert answer["count"] == 1
    edge = answer["edges"][0]
    assert edge["exec_api"] == "run_list"
    assert edge["command"]["argv_provenance"] == er.RUNNER_PROVENANCE
    assert edge["note"] == qee._RUNNER_NOTE


def test_the_projection_status_keeps_its_own_count(tmp_path: Path) -> None:
    """The projection's exec_argv row counts the projection's rows only; the runner pass has its
    own row per binary, also where it found nothing.

    MUTATION (verified RED, 1 failed): in analyzer2 feed both row sets to the projection's status
    (``_exec_scan_status(exec_edge_rows + runner_edge_rows, ...)``) -> daemon_one's exec_argv
    count is 2.
    MUTATION (verified RED, 1 failed): in analyzer2 drop ``detector_status_rows +=
    runner_status_rows`` -> no runner status row."""
    atlas_path = _hunt(tmp_path)
    conn = open_atlas(atlas_path)
    try:
        rows = conn.execute(
            "SELECT detector, binary, found_count FROM detector_scan_status "
            "WHERE source_run_id = 'run1' AND detector IN ('exec_argv', ?)",
            (er.RUNNER_DETECTOR,),
        ).fetchall()
    finally:
        conn.close()
    counts = {(r[0], r[1]): r[2] for r in rows}
    assert counts.get(("exec_argv", "daemon_one")) == 1
    assert counts.get((er.RUNNER_DETECTOR, "daemon_one")) == 1
    assert counts.get((er.RUNNER_DETECTOR, "helper_tool")) == 0
    assert {b for d, b in counts if d == er.RUNNER_DETECTOR} == {
        "libtool.so",
        "daemon_one",
        "helper_tool",
        "quiet_bin",
    }


def test_an_empty_answer_carries_the_runner_pass_status(tmp_path: Path) -> None:
    """With the import gate closed the runner edge is not built; the empty answer for its target
    carries the runner pass's per-binary rows, so the silence is not read as "nothing launches it
    through a runner".

    MUTATION (verified RED, 1 failed): in the read layer's _exec_scan_status ignore ``detector``
    (``params: list[Any] = ["exec_argv"]``) -> the runner block holds exec_argv rows."""
    atlas_path = _hunt(tmp_path, import_gate=False)
    conn = open_atlas(atlas_path)
    try:
        answer = launched_by(conn, "helper_tool", run_id="run1")
    finally:
        conn.close()
    assert answer["count"] == 0
    block = answer["exec_runner_status"]
    assert block["pass_scope"] == er.RUNNER_DETECTOR
    assert block["supported_scope"] == er.SUPPORTED_SCOPE
    assert block["unsupported_note"] == er.UNSUPPORTED_NOTE
    assert {s["binary"] for s in block["statuses"]} == {
        "libtool.so",
        "daemon_one",
        "helper_tool",
        "quiet_bin",
    }
    assert answer["exec_argv_status"]["pass_scope"] == "exec_argv"
    assert answer["exec_argv_status"]["unsupported_note"] != er.UNSUPPORTED_NOTE


def _order_and_atoms(atlas_path: Path) -> tuple[list[str], dict[str, dict[str, int]]]:
    from treasure_map.lib.query import triage
    from treasure_map.lib.query.triage import _sort_atoms

    conn = open_atlas(atlas_path)
    try:
        ranked = triage(conn, run_id="run1")
    finally:
        conn.close()
    order = [str(c.evidence_ref) for c in ranked]
    atoms = {str(c.evidence_ref): _sort_atoms(c, None) for c in ranked}
    return order, atoms


def _run_dir(tmp_path: Path, name: str) -> Path:
    d = tmp_path / name
    d.mkdir()
    return d


def test_the_runner_edge_moves_only_the_launched_binarys_candidates(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """With the pass, ``helper_tool``'s candidate reads ``entry:exec`` (reach rank 1 -> 2,
    reach_promote 0 -> 1); every other candidate keeps its sort atoms and their relative order is
    unchanged. Measured against the same firmware hunted with the pass switched off.

    MUTATION (verified RED, 1 failed): in analyzer2 build the entry index from the projection's
    rows alone (``exec_entry_sites(exec_edge_rows)``) -> do_work's reach rank stays 1.
    MUTATION (verified RED, 1 failed): in build_runner_edges send every row's target to the
    launcher's own file (``row = replace(row, argv_provenance=RUNNER_PROVENANCE,
    target_binary=func.binary_path)``) -> daemon_one's candidate is lifted too and the relative
    order of the untouched candidates changes."""
    from treasure_map.lib.hunt import analyzer2

    on_order, on_atoms = _order_and_atoms(_hunt(_run_dir(tmp_path, "on")))
    real = analyzer2._runner_exec_edges
    monkeypatch.setattr(analyzer2, "_runner_exec_edges", lambda *a, **k: ([], real(*a, **k)[1]))
    off_order, off_atoms = _order_and_atoms(_hunt(_run_dir(tmp_path, "off")))

    assert set(on_order) == set(off_order)
    # helper_tool is binary 3 (content hash "3" * 64), the one the runner edge names
    lifted = [ref for ref in on_order if "#33333333:" in ref]
    assert lifted, "the launched binary's candidate is missing from the fixture"
    for ref in lifted:
        assert (off_atoms[ref]["reach_rank"], on_atoms[ref]["reach_rank"]) == (1, 2)
        assert (off_atoms[ref]["reach_promote"], on_atoms[ref]["reach_promote"]) == (0, 1)
    untouched = [ref for ref in on_order if ref not in lifted]
    assert len(untouched) >= 3, "the fixture needs several unaffected candidates to compare"
    for ref in untouched:
        assert on_atoms[ref] == off_atoms[ref], ref
    assert [r for r in on_order if r in untouched] == [r for r in off_order if r in untouched]


def test_the_pass_builds_no_candidate(tmp_path: Path, monkeypatch: Any) -> None:
    """The pass writes edges and status rows only: the candidate set is the same with and without
    it. A structural guarantee — ``runner_pass`` returns edge and status rows and has no channel
    into the candidate set — pinned here against the hunt as a regression guard (there is no
    one-line mutation inside the pass that reaches the candidate set)."""
    from treasure_map.lib.hunt import analyzer2

    def _identities(path: Path) -> list[tuple[Any, ...]]:
        conn = open_atlas(path)
        try:
            return [
                tuple(r)
                for r in conn.execute(
                    "SELECT binary_path, evidence_ref, pattern_id FROM instance ORDER BY 1, 2, 3"
                )
            ]
        finally:
            conn.close()

    with_pass = _identities(_hunt(_run_dir(tmp_path, "on")))
    monkeypatch.setattr(analyzer2, "_runner_exec_edges", lambda *a, **k: ([], []))
    without = _identities(_hunt(_run_dir(tmp_path, "off")))
    assert with_pass == without
    assert len(with_pass) >= 3


# ── the boundaries that keep this pass where it belongs ──────────────────────────────


def test_the_read_layer_spells_the_hunt_constants_the_same() -> None:
    assert qee.RUNNER_DETECTOR == er.RUNNER_DETECTOR
    assert qee.RUNNER_PROVENANCE == er.RUNNER_PROVENANCE


def test_the_module_is_in_the_hunt_closure_only() -> None:
    """Stamps are computed over import closures: this module must reach the hunt's and no other,
    so an edit to it re-stamps hunts only.

    MUTATION (verified RED, 1 failed): import ``runner_pass`` from lib/analyze/pipeline.py -> it
    is in the pipeline closure."""
    pkg = rv._PACKAGE
    assert "lib.hunt.exec_runners" in rv._closure(pkg, rv.HUNT_ROOT)
    assert "lib.hunt.exec_runners" not in rv._closure(pkg, rv.PIPELINE_ROOT)
    entries = dcv.DIFF_CODE_ENTRIES + dcv.OVERLAY_CODE_ENTRIES
    assert not [e for e in entries if e.split(":")[0] == "lib.hunt.exec_runners"]


def test_the_projection_module_is_untouched_by_this_pass() -> None:
    """The projection stays a projection: this pass imports its fact rules and adds nothing to it.
    (Its file is compared with the parent commit at landing; here the shape this pass relies on is
    pinned — the projection's own builder still reads only provenance.)"""
    src = Path(er.__file__).with_name("exec_edges.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    names = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assert {"_exec_facts", "_build_row", "build_exec_edges", "exec_entry_sites"} <= names
    assert "exec_runners" not in src


def test_the_link_tables_degrade_to_empty_on_a_database_without_them(tmp_path: Path) -> None:
    db = tmp_path / "bare.db"
    sqlite3.connect(db).close()
    assert er.load_link_tables(db) == er.LinkTables(exported_calls={}, imports=frozenset())
