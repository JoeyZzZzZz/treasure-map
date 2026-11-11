# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The batch driver records what each launch used (lib/review_driver ``agent_usage``): read from
claude-code's ``--output-format json`` result before the output is cut to its tail, with lines
printed before it (a warning on stderr) and a result printed over several lines read alike
(``final_json``, the one reader the hand-off uses too); the agent's stdin is closed. A record
only: a unit's success is still read from the overlay alone.

Zero real data: the callee-group World of test_callee_groups; the agent's output comes from a
real child process where that output is the point."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_callee_groups import _fresh, _world  # noqa: F401 — autouse fixture
from treasure_map.lib import overlay
from treasure_map.lib import review_driver as rd
from treasure_map.lib import tool_call_log as tcl
from treasure_map.lib.query import review_units as ru

WARNING = "Warning: no stdin data received in 3s, proceeding without it."
# The shape claude-code prints with --output-format json (the fields read, and a few others).
RESULT: dict[str, Any] = {
    "type": "result",
    "subtype": "success",
    "is_error": False,
    "num_turns": 7,
    "result": "judged every member. " * 300,  # longer than the 4,000-character tail
    "total_cost_usd": 0.4321,
    "usage": {
        "input_tokens": 12,
        "cache_creation_input_tokens": 3_000,
        "cache_read_input_tokens": 90_000,
        "output_tokens": 1_500,
    },
    "modelUsage": {"model-b": {"costUSD": 0.4}, "model-a": {"costUSD": 0.0321}},
}
USAGE = {
    "cost_usd": 0.4321,
    "input_tokens": 12,
    "output_tokens": 1_500,
    "cache_read_input_tokens": 90_000,
    "turns": 7,
    "model": ["model-a", "model-b"],
}


def _printer(tmp: Path, text: str, *, warn: bool = True) -> list[str]:
    """A child process that prints the warning on stderr, then ``text`` on stdout."""
    body = tmp / "out.txt"
    body.write_text(text, encoding="utf-8")
    script = (
        "import sys\n"
        + (f"sys.stderr.write({WARNING!r} + '\\n'); sys.stderr.flush()\n" if warn else "")
        + f"sys.stdout.write(open({str(body)!r}, encoding='utf-8').read())\n"
    )
    return [sys.executable, "-c", script]


def _judging_runner(w: Any, tmp: Path, text: str, *, judge: bool = True) -> Any:
    """A launch that judges every entry member of the unit its prompt names (as an agent would)
    and prints ``text`` from a real child process."""

    def run(argv: list[str], *, cwd: Path, timeout: float) -> rd.Launch:
        uid = re.search(r'unit="([0-9a-f]{16})"', argv[-1])
        assert uid is not None
        r = ru.review_pair(
            w.atlas,
            "runA",
            "runB",
            k=50,
            pair_staleness={"source_stale": False},
            server_commit=None,
        )
        u = r.unit(uid.group(1))
        for m in u.members if u is not None and judge else []:
            if m.kind != "entry":
                continue
            group = str(u.group.get("ref")) if u.group is not None else None
            if u.kind == ru.REDUCE:
                group = next(x.split(":", 1)[1] for x in m.reasons if x.startswith("group_ref:"))
            overlay.annotate_diff(
                w.atlas,
                anchor_ref=m.anchor_ref,
                verdict="changed_real",
                rationale="r",
                diff_id=m.stream,
                group_ref=group,
                ctx=overlay.WriteContext(channel="mcp", unit_id=uid.group(1), session="agent"),
            )
        return rd.run_agent(_printer(tmp, text), cwd=cwd, timeout=timeout)

    return run


def _drive_log(w: Any, tmp: Path, runner: Any, preset: rd.Preset) -> list[dict[str, Any]]:
    rd.drive(
        w.path,
        "runA",
        "runB",
        preset,
        workdir=tmp,
        k=50,
        runner=runner,
        echo=lambda s: None,
        max_units=1,
        retries=0,
    )
    lines = tcl.read_lines(tcl.log_path_for(w.path).with_name(rd.DRIVER_LOG))
    assert lines is not None
    got = list(lines)
    assert got
    return got


def test_the_usage_is_read_past_a_warning_line(tmp_path: Path) -> None:
    """★ T-F3a: a claude-code launch whose output starts with a stderr warning line and ends in
    its JSON result (``result`` longer than the kept tail): the driver's line for it carries
    ``agent_usage``.

    MUTATION (verified RED, 1 failed): read the whole output with json.loads (as _launch_result
    did) -> RED."""
    w = _world(tmp_path)
    runner = _judging_runner(w, tmp_path, json.dumps(RESULT) + "\n")
    line = _drive_log(w, tmp_path, runner, rd.PRESETS["claude-code"])[0]
    assert line.get("agent_usage") == USAGE, line
    assert "agent_usage_unavailable" not in line
    assert line["success"] is True


def test_a_result_printed_over_several_lines_is_read_whole(tmp_path: Path) -> None:
    """★ T-F3b: the JSON result printed over several lines, after the warning: read whole.

    MUTATION (verified RED, 1 failed): try only the output's last line -> RED."""
    launch = rd.run_agent(
        _printer(tmp_path, json.dumps(RESULT, indent=2) + "\n"), cwd=tmp_path, timeout=30
    )
    assert launch.output.startswith(WARNING) is False  # the tail only, cut
    assert rd.agent_usage(rd.PRESETS["claude-code"], launch) == (USAGE, None)
    assert rd.final_json(WARNING + "\n" + json.dumps(RESULT, indent=2)) == RESULT


def test_the_usage_is_read_before_the_output_is_cut(tmp_path: Path) -> None:
    """★ T-F3c: a per-unit launch keeps only the tail of its output (``keep_full`` False), cut
    inside the JSON; the usage was read from the whole output first.

    MUTATION (verified RED, 1 failed): read final_json of the kept tail -> RED."""
    launch = rd.run_agent(_printer(tmp_path, json.dumps(RESULT)), cwd=tmp_path, timeout=30)
    assert len(launch.output) == 4_000 and rd.final_json(launch.output) is None  # cut
    assert rd.agent_usage(rd.PRESETS["claude-code"], launch) == (USAGE, None)


def test_the_agent_reads_no_inherited_stdin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ T-F3d: the launch's stdin is closed (``subprocess.DEVNULL``): an agent never waits on
    the driver's own stdin; and the child really reads end of input at once.

    MUTATION (verified RED, 1 failed): leave stdin unset (inherited) -> RED."""
    seen: list[dict[str, Any]] = []
    real = subprocess.Popen

    def spy(*a: Any, **kw: Any) -> Any:
        seen.append(kw)
        return real(*a, **kw)

    monkeypatch.setattr(rd.subprocess, "Popen", spy)
    script = "import sys; print(repr(sys.stdin.read()))"
    launch = rd.run_agent([sys.executable, "-c", script], cwd=tmp_path, timeout=30)
    assert seen and seen[0].get("stdin") is subprocess.DEVNULL
    assert launch.output.strip() == "''"


def test_the_hand_off_reads_its_result_past_a_warning_line(tmp_path: Path) -> None:
    """★ T-F3e: a hand-off launch's output (kept whole) with the warning line and a JSON result
    printed over several lines: both readers of it — the analysis (extract_handoff) and the
    final message kept on a refusal (_launch_result) — read it.

    MUTATION (verified RED, 1 failed): read the whole output with json.loads in _launch_result
    -> RED. MUTATION (verified RED, 1 failed): the same in extract_handoff -> RED."""
    message = '{"analysis": {}}'
    data = {**RESULT, "result": message}
    text = WARNING + "\n" + json.dumps(data, indent=2) + "\n"
    launch = rd.run_agent(
        _printer(tmp_path, text, warn=False), cwd=tmp_path, timeout=30, keep_full=True
    )
    assert launch.output.startswith(WARNING)  # the precondition: kept whole
    assert rd._launch_result(launch) == message
    texts, err = rd.extract_handoff(rd.PRESETS["claude-code"], launch)
    assert err is None and texts is not None, err


def test_the_usage_never_decides_a_units_success(tmp_path: Path) -> None:
    """★ T-F3f: output that is no JSON reads ``agent_usage`` null with why, and the unit whose
    members were all judged is a success; a launch that judged nothing is not, whatever usage it
    reports. Another preset's output is not read.

    MUTATION (verified RED, 1 failed): count a unit done only with its usage read -> RED."""
    w = _world(tmp_path)
    garbled = _judging_runner(w, tmp_path, "no json here\n")
    line = _drive_log(w, tmp_path, garbled, rd.PRESETS["claude-code"])[-1]
    assert line["agent_usage"] is None
    assert line["agent_usage_unavailable"] == "the launch's output does not end in a JSON object"
    assert line["success"] is True
    w2 = _world(tmp_path / "w2")
    idle = _judging_runner(w2, tmp_path, json.dumps(RESULT), judge=False)
    line = _drive_log(w2, tmp_path / "w2", idle, rd.PRESETS["claude-code"])[-1]
    assert line["agent_usage"] == USAGE and line["success"] is False
    other = rd.Preset("other", ("agent", "{prompt}"))
    assert rd.agent_usage(other, rd.Launch(0, 0.0, False, final=RESULT)) == (
        None,
        "not read for this preset",
    )


def test_final_json_reads_the_object_the_output_ends_with() -> None:
    """``final_json``: the JSON object the output ends with, lines before it skipped; None when it
    ends in none (trailing text after it, or no JSON at all)."""
    assert rd.final_json('a warning\n{"x": 1}\n') == {"x": 1}
    assert rd.final_json('{"x": 1}') == {"x": 1}
    assert rd.final_json('{\n  "x": [\n    1,\n    2\n  ]\n}\n\n') == {"x": [1, 2]}
    assert rd.final_json('{"x": 1}\ntrailing text\n') is None
    assert rd.final_json("") is None


# ── spec Y M-1: the parser reads plain text and pseudocode in linear time ───────────────────


def _pseudocode(functions: int) -> str:
    """Decompiler-style C: every function body's ``{`` and ``}`` on lines of their own."""
    return "".join(
        f"void FUN_{i:08x}(int param_1)\n{{\n  int local_8;\n\n  local_8 = param_1 + {i};\n"
        "  return;\n}\n\n"
        for i in range(functions)
    )


_NO_OBJECT_OUTPUTS = {
    "plain_text": "".join(f"line {i} of a long transcript\n" for i in range(40_000)),
    "pseudocode_then_text": _pseudocode(10_000) + "the function above was read.\n",
    "pseudocode_ending_in_brace": _pseudocode(10_000).rstrip(),
    "jsonl_then_text": "".join(f'{{"i": {i}}}\n' for i in range(40_000)) + "done\n",
}


@pytest.mark.parametrize("name", sorted(_NO_OBJECT_OUTPUTS))
def test_an_output_ending_in_no_object_is_read_without_a_parse(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ T-M1a: four outputs ending in no JSON object (40,000 lines of plain text; 10,000
    decompiled functions with each ``{`` on a line of its own, then a line of text; the same
    ending in ``}``; 40,000 JSONL lines, then a line of text) read None with no parse tried. The
    count is the tooth, the time a second check. "0 tries" holds for these four only: an output
    with many lines opening a whole object, none of them last, is tried once per such line.

    MUTATION (verified RED): the earlier reader (every non-blank line tried) -> all four RED;
    the earlier reader trying only lines that start with ``{`` -> both pseudocode cases and
    jsonl_then_text RED; the opening pattern replaced by ``lstrip().startswith("{")`` (the end
    check kept) -> pseudocode_ending_in_brace RED; the ``}`` end check dropped ->
    jsonl_then_text RED; the opening pattern dropped (every non-blank line tried after the end
    check) -> pseudocode_ending_in_brace RED."""
    import time

    output = _NO_OBJECT_OUTPUTS[name]
    tries = {"n": 0}
    real = rd.json.loads

    def counted(text: Any, *a: Any, **kw: Any) -> Any:
        tries["n"] += 1
        return real(text, *a, **kw)

    monkeypatch.setattr(rd.json, "loads", counted)
    t0 = time.monotonic()
    assert rd.final_json(output) is None
    assert tries["n"] == 0, tries
    assert time.monotonic() - t0 < 2.0


def test_an_object_after_text_is_read_whatever_its_first_line_holds() -> None:
    """T-M1b: an indented object after a warning line, and an object whose ``{`` is followed by
    a blank line, are read whole.

    MUTATION (verified RED): the opening pattern not spanning a line end (``\\{[ \\t]*``) -> the
    second RED."""
    assert rd.final_json('a warning\n  {"x": 1}') == {"x": 1}
    assert rd.final_json('{\n\n  "k": 1}') == {"k": 1}
