# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The batch driver: tmap hands a run pair's review out one work unit at a time, each to a fresh
run of the user's own agent command line — tmap runs the loop, the agent judges one unit and exits.

tmap calls no model API. Each launch is non-interactive, loads the tmap MCP server (a config file
written here) and, for a preset, is limited to tmap's tools: an agent CLI's "allowed tools" flag
usually means "no confirmation needed", not "nothing else", so a preset also switches every
built-in tool off. Before any unit, a probe checks it: the agent must reach a tmap tool, and an
attempt to write a file with a built-in tool must fail. An experimental template is run only once
that probe passes on this machine.

A unit succeeds only when, after its launch, overlay_history holds a judgement naming the unit for
EVERY one of its members — neither the agent's exit code nor its output is believed. A launch is
killed at its deadline; a failed unit is retried, then left (named in the log) and the loop moves
on. The first unit doubles as a probe of the whole chain: when it writes nothing, the loop stops
and says why. An audit unit's launch is also denied the tool that returns the judgements
(list_overlays), so it reads blind.

Each launch is logged — unit, attempt, exit status, seconds, members written — in
``<atlas dir>/logs/review_driver.jsonl`` (outside the atlas, like the tool-call log).
"""

from __future__ import annotations

import json
import os
import shlex
import signal
import sqlite3
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from treasure_map.lib import tool_call_log as tcl
from treasure_map.lib.query import review_report as _rr
from treasure_map.lib.query import review_units as ru

DEFAULT_TIMEOUT = 15 * 60
DEFAULT_RETRIES = 2
SERVER_NAME = "treasure-map"
DRIVER_LOG = "review_driver.jsonl"
# Environment markers an agent's shell sets: not passed to the launched agent, which is a fresh one.
_PARENT_AGENT_ENV = ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT")


@dataclass(frozen=True)
class Preset:
    """An agent command line: argv with ``{prompt}`` / ``{mcp_config}`` / ``{workdir}`` /
    ``{atlas}`` / ``{unit_id}`` / ``{run_pair}`` placeholders, and the argv added for a blind
    (audit) launch. ``experimental``: not verified here — it runs only after its probe passes."""

    name: str
    argv: tuple[str, ...]
    blind_argv: tuple[str, ...] = ()
    experimental: bool = False
    note: str = ""


PRESETS: dict[str, Preset] = {
    "claude-code": Preset(
        "claude-code",
        (
            "claude",
            "-p",
            "--mcp-config",
            "{mcp_config}",
            "--strict-mcp-config",
            "--tools",
            "",
            "--allowedTools",
            f"mcp__{SERVER_NAME}__*",
            "--permission-mode",
            "dontAsk",
            "--setting-sources",
            "",
            "--output-format",
            "json",
            "--no-session-persistence",
            "{prompt}",
        ),
        # One token with ``=`` — ``--disallowedTools mcp__…`` as two tokens is parsed greedily and
        # swallows the prompt that follows it (A-4); ``--disallowedTools=mcp__…`` binds just the one
        # value and leaves the prompt a clean positional.
        blind_argv=(f"--disallowedTools=mcp__{SERVER_NAME}__list_overlays",),
        note=(
            '--allowedTools only skips confirmation; --tools "" switches every built-in tool '
            'off and --setting-sources "" loads no user or project settings'
        ),
    ),
    "codex": Preset(
        "codex",
        (
            "codex",
            "exec",
            "--skip-git-repo-check",
            "-c",
            f'mcp_servers.{SERVER_NAME}.command="{{tmap}}"',
            "-c",
            f'mcp_servers.{SERVER_NAME}.args=["mcp","--atlas","{{atlas}}"]',
            "{prompt}",
        ),
        experimental=True,
        note="experimental: calls have been reported cancelled or hanging; probe first",
    ),
    "cursor": Preset(
        "cursor",
        ("cursor-agent", "-p", "--approve-mcps", "--trust", "{prompt}"),
        experimental=True,
        note=(
            "experimental: needs the tmap MCP server registered and an Mcp(treasure-map:*) "
            "allow-list in its own configuration; probe first"
        ),
    ),
}


def preset_or_template(agent: str) -> Preset:
    """A preset by name, or a command template (it must hold ``{prompt}``), taken as
    experimental."""
    if agent in PRESETS:
        return PRESETS[agent]
    argv = tuple(shlex.split(agent))
    if not argv or not any("{prompt}" in a for a in argv):
        raise ValueError(
            f"--agent takes a preset ({', '.join(PRESETS)}) or a command template holding "
            "{prompt}"
        )
    return Preset("template", argv, experimental=True, note="a command template: probe first")


def tmap_command() -> list[str]:
    """How the launched agent starts tmap's MCP server: the installed executable, else this
    interpreter running the package."""
    from treasure_map.lib.setup.clients import tmap_executable

    exe = tmap_executable()
    return [str(exe)] if exe is not None else [sys.executable, "-m", "treasure_map.cli.main"]


def write_mcp_config(path: Path, atlas: Path) -> Path:
    cmd = tmap_command()
    config = {
        "mcpServers": {
            SERVER_NAME: {"command": cmd[0], "args": [*cmd[1:], "mcp", "--atlas", str(atlas)]}
        }
    }
    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return path


def render(preset: Preset, values: dict[str, str], *, blind: bool = False) -> list[str]:
    """The argv of one launch: the preset's placeholders filled; a blind launch adds its argv
    before the last argument (the prompt)."""
    argv = [a.format(**values) if "{" in a else a for a in preset.argv]
    if blind and preset.blind_argv:
        argv = [*argv[:-1], *preset.blind_argv, argv[-1]]
    return argv


def unit_prompt(run_pair: str, u: ru.Unit, k: int) -> str:
    kk = f", k={k}" if k != ru.DEFAULT_K else ""
    text = (
        f"You are reviewing ONE work unit of the firmware version diff {run_pair} with the tmap "
        "tools. tmap draws no conclusion: the judgment is yours, and it records nothing for you. "
        f'1. Call start_diff_review(run_pair="{run_pair}", unit="{u.unit_id}"{kk}) and read its '
        "material; when it says material_cut, read the rest with the calls it names. "
        "2. Judge EVERY member with annotate_diff (or annotate_diff_batch), passing "
        f'unit_id="{u.unit_id}": changed_real (with evidence and change_kind when you can), '
        "no_real_change (checked + why_unchanged), or change_inconclusive (what is missing). "
        "3. Then stop. Do not judge anything outside this unit."
    )
    if u.kind == ru.AUDIT:
        text += (
            " This is an AUDIT: read the subject afresh and judge it yourself; do not look for an "
            "earlier judgment (list_overlays is not available to you)."
        )
    if u.group is not None:
        text += f' Pass group_ref="{u.group.get("ref")}" with each member.'
    if u.kind == ru.REDUCE:
        text += (
            " This is the REDUCE: each member is owed a judgment leaning on its callee group — "
            "pass the group_ref its reasons name (group_ref:<ref>) with it."
        )
    return text


@dataclass
class Launch:
    exit: int | None
    seconds: float
    timed_out: bool
    output: str = ""


def run_agent(argv: Sequence[str], *, cwd: Path, timeout: float, keep_full: bool = False) -> Launch:
    """Run one agent launch in its own process group, killed whole at ``timeout``. A per-unit
    launch keeps only the tail of the output (the judgement is read from the overlay history, not
    the text); the hand-off launch (``keep_full``) keeps all of it, because the driver reads the
    agent's analysis texts out of it — the agent, with every built-in tool off, cannot write a
    file."""
    env = {k: v for k, v in os.environ.items() if k not in _PARENT_AGENT_ENV}
    t0 = time.monotonic()
    proc = subprocess.Popen(  # noqa: S603 — the user's own agent command line
        list(argv),
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    try:
        out, _ = proc.communicate(timeout=timeout)
        return Launch(
            proc.returncode, time.monotonic() - t0, False, out if keep_full else out[-4000:]
        )
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        proc.communicate()
        return Launch(None, time.monotonic() - t0, True)


def history_mark(atlas: sqlite3.Connection) -> int:
    row = atlas.execute("SELECT COALESCE(MAX(id), 0) FROM overlay_history").fetchone()
    return int(row[0])


def members_written(atlas: sqlite3.Connection, u: ru.Unit, after: int) -> set[str]:
    """The unit's members that overlay_history holds a judgement on, naming the unit, written after
    history row ``after``."""
    rows = atlas.execute(
        "SELECT DISTINCT anchor_ref FROM overlay_history WHERE unit_id = ? AND id > ? "
        "AND event IN ('insert', 'update', 'shadow')",
        (u.unit_id, after),
    ).fetchall()
    got = {r[0] for r in rows}
    return {m.anchor_ref for m in u.members} & got


@dataclass
class ProbeResult:
    ok: bool
    tmap_reached: bool
    builtin_blocked: bool
    why: str
    launch: Launch | None = None


def probe(
    preset: Preset,
    *,
    atlas_path: Path,
    workdir: Path,
    timeout: float,
    runner: Callable[..., Launch] = run_agent,
) -> ProbeResult:
    """Each launch must reach a tmap tool (list_runs, seen in the tool-call log) and must fail to
    create a file with a built-in tool (the marker file must not exist after it). A preset with
    ``blind_argv`` is probed twice — once plain, once blind — so the blind argv is proven not to
    swallow the prompt (A-4: the blind launch still reaches a tmap tool). The result combines both:
    reached / blocked hold only when every launch did."""
    marker = workdir / "probe_marker.txt"
    prompt = (
        "This is a check of your tool set, nothing else. Step 1: call the tmap tool list_runs. "
        f"Step 2: if you have any tool that writes files or runs commands, use it to create the "
        f"file {marker} containing the word probe; if you have none, say so. Then stop."
    )
    values = _values(preset, atlas_path, workdir, prompt, "probe", "probe")
    blinds = [False, True] if preset.blind_argv else [False]
    reached = blocked = True
    why: list[str] = []
    launch: Launch | None = None
    for blind in blinds:
        marker.unlink(missing_ok=True)
        started = time.time()
        launch = runner(render(preset, values, blind=blind), cwd=workdir, timeout=timeout)
        lines = tcl.read_lines(tcl.log_path_for(atlas_path)) or iter(())
        r = any(
            ln.get("tool") == "list_runs" and float(ln.get("ts") or 0) >= started for ln in lines
        )
        b = not marker.exists()
        tag = " (blind)" if blind else ""
        if not r:
            why.append(
                f"the agent never reached a tmap tool{tag} (is the MCP server loaded and allowed?)"
            )
        if not b:
            why.append(f"the agent created a file with a built-in tool{tag}: built-in tools are on")
        if launch.timed_out:
            why.append(f"the probe launch{tag} hit its deadline")
        reached, blocked = reached and r, blocked and b
    return ProbeResult(reached and blocked, reached, blocked, "; ".join(why) or "ok", launch)


def _values(
    preset: Preset, atlas_path: Path, workdir: Path, prompt: str, unit_id: str, run_pair: str
) -> dict[str, str]:
    cfg = write_mcp_config(workdir / "mcp.json", atlas_path)
    return {
        "prompt": prompt,
        "mcp_config": str(cfg),
        "workdir": str(workdir),
        "atlas": str(atlas_path),
        "unit_id": unit_id,
        "run_pair": run_pair,
        "tmap": tmap_command()[0],
    }


@dataclass
class DriveResult:
    units_tried: int = 0
    units_done: int = 0
    failed: list[dict[str, Any]] = field(default_factory=list)
    stopped: str | None = None
    statement: str | None = None


def _log(path: Path, line: dict[str, Any]) -> None:
    tcl.append(path, {"ts": time.time(), **line})


def drive(
    atlas_path: Path,
    run_a: str,
    run_b: str,
    preset: Preset,
    *,
    workdir: Path,
    k: int = ru.DEFAULT_K,
    worker: int | None = None,
    workers: int | None = None,
    max_units: int | None = None,
    max_minutes: float | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    pair_staleness: dict[str, Any] | None = None,
    runner: Callable[..., Launch] = run_agent,
    echo: Callable[[str], None] = print,
) -> DriveResult:
    """Hand the pair's units out, one launch each, until none is left (or a limit is reached);
    see the module docstring."""
    from treasure_map.lib.atlas.connection import open_atlas

    run_pair = f"{run_a}::{run_b}"
    log_path = tcl.log_path_for(atlas_path).with_name(DRIVER_LOG)
    out = DriveResult()
    skip: set[str] = set()
    done_ids: set[str] = set()
    deadline = time.monotonic() + max_minutes * 60 if max_minutes else None
    staleness = pair_staleness or {"source_stale": False, "source_stale_reason": None}
    while True:
        if max_units is not None and out.units_tried >= max_units:
            out.stopped = f"max_units {max_units} reached"
            break
        if deadline is not None and time.monotonic() > deadline:
            out.stopped = f"max_minutes {max_minutes} reached"
            break
        atlas = open_atlas(atlas_path)
        try:
            review = ru.review_pair(
                atlas, run_a, run_b, k=k, pair_staleness=staleness, server_commit=None
            )
            nxt = next(
                (
                    u
                    for u in review.units
                    if u.unit_id not in skip
                    and ru.in_shard(u.unit_id, worker, workers)
                    and not ru.unit_disposed(u, review.progress.states)
                ),
                None,
            )
            out.statement = review.report["coverage_statement"]
            if nxt is None:
                out.stopped = "no unit left"
                break
            mark = history_mark(atlas)
        finally:
            atlas.close()
        if nxt.unit_id in done_ids:
            # Every member was written, yet the unit is still owed (a reduce member written
            # without its group_ref, say): counted failed once, never handed out again here.
            out.units_done -= 1
            out.failed.append(
                {
                    "unit_id": nxt.unit_id,
                    "kind": nxt.kind,
                    "written": len(nxt.members),
                    "members": len(nxt.members),
                    "why": "written but still owed",
                }
            )
            skip.add(nxt.unit_id)
            continue
        out.units_tried += 1
        prompt = unit_prompt(run_pair, nxt, k)
        values = _values(preset, atlas_path, workdir, prompt, nxt.unit_id, run_pair)
        argv = render(preset, values, blind=nxt.kind == ru.AUDIT)
        done = False
        written: set[str] = set()
        for attempt in range(1, retries + 2):
            launch = runner(argv, cwd=workdir, timeout=timeout)
            atlas = open_atlas(atlas_path)
            try:
                written = members_written(atlas, nxt, mark)
            finally:
                atlas.close()
            done = len(written) == len(nxt.members)
            _log(
                log_path,
                {
                    "run_pair": run_pair,
                    "unit_id": nxt.unit_id,
                    "kind": nxt.kind,
                    "attempt": attempt,
                    "exit": launch.exit,
                    "timed_out": launch.timed_out,
                    "seconds": round(launch.seconds, 1),
                    "members_written": len(written),
                    "members": len(nxt.members),
                    "success": done,
                },
            )
            echo(
                f"{nxt.unit_id} {nxt.kind} attempt {attempt}: "
                f"{len(written)}/{len(nxt.members)} written"
                + (" (deadline)" if launch.timed_out else f" (exit {launch.exit})")
            )
            if done:
                break
        if done:
            out.units_done += 1
            done_ids.add(nxt.unit_id)
            continue
        out.failed.append(
            {
                "unit_id": nxt.unit_id,
                "kind": nxt.kind,
                "written": len(written),
                "members": len(nxt.members),
            }
        )
        skip.add(nxt.unit_id)
        if out.units_tried == 1 and not written:
            out.stopped = (
                "the first unit wrote nothing in any attempt: the agent cannot judge through "
                "tmap here (run the probe; check the agent's MCP and tool settings)"
            )
            break
    return out


# ── the findings hand-off launch (B-5) ──────────────────────────────────────────────────────────
# A FINAL launch, run once the review is done (no unit left): one agent reads the whole findings
# skeleton through the MCP tool get_diff_handoff and prints, as its final message, only its two
# analysis texts per finding — a JSON object keyed by anchor_ref. The driver writes the document
# itself: handoff_document (the CLI's function) with those texts under each block's placeholders,
# so every fact line, the basis and the status are tmap's own text, never the agent's retyping. Its
# full output is kept and read out of it — the agent, with every built-in tool off, cannot write a
# file. Only claude-code's result is read this version; an experimental preset is refused, never
# served a silent miss.
HANDOFF_PRESETS = frozenset({"claude-code"})
# The two texts the agent writes per finding, under the block's two placeholders.
HANDOFF_FIELDS = ("hypotheses", "device_checks")


def handoff_prompt(run_pair: str) -> str:
    """The hand-off agent's prompt (B-7): read the skeleton, write hypotheses and device checks per
    finding as one JSON object — and the boundary, never a working attack."""
    return (
        f"You are writing the findings hand-off for the firmware version diff {run_pair} with the "
        "tmap tools. tmap draws no conclusion: the analysis is yours, and it is unverified. "
        f'1. Page the whole skeleton: get_diff_handoff(run_pair="{run_pair}", offset=0), then '
        "follow next_offset until it is null (re-start from offset 0 if findings_digest changes). "
        "2. It has one block per finding, headed by its anchor_ref (the text inside ## `...`), "
        "each with tmap's facts and two analysis placeholders: 'agent analysis — unverified "
        "hypotheses' and 'to check on a device'. 3. Your final message is ONE JSON object and "
        "nothing else: each key a block's anchor_ref exactly as written, each value "
        '{"hypotheses": "<your unverified hypotheses>", "device_checks": "<concrete things a '
        'person could verify on a device>"}. Do not repeat the facts — tmap writes the document '
        "and puts your two texts under each block's placeholders. " + _rr.HANDOFF_BOUNDARY
    )


def _strip_fence(text: str) -> str:
    """``text`` without one code fence around it (```json … ```), as an agent may wrap JSON."""
    body = text.strip()
    if body.startswith("```") and body.endswith("```") and "\n" in body:
        body = body[body.index("\n") + 1 : -3].strip()
    return body


def parse_handoff_analysis(text: str) -> tuple[dict[str, dict[str, str]] | None, str | None]:
    """The agent's ``{anchor_ref: {"hypotheses": …, "device_checks": …}}`` from its final message,
    or ``(None, error)``: not JSON, not an object, a value not an object, a field that is not text
    or a key that is neither field — each refused, never half-read."""
    try:
        data = json.loads(_strip_fence(text))
    except ValueError as exc:
        return None, f"the agent's final message is not the JSON object asked for ({exc})"
    if not isinstance(data, dict):
        return None, "the agent's final message is JSON but not an object keyed by anchor_ref"
    out: dict[str, dict[str, str]] = {}
    for anchor, value in data.items():
        if not isinstance(value, dict):
            return None, f"the value for {str(anchor)[:120]!r} is not an object"
        extra = sorted(set(value) - set(HANDOFF_FIELDS))
        if extra:
            return None, f"the value for {str(anchor)[:120]!r} has keys {extra} besides the two"
        texts: dict[str, str] = {}
        for name in HANDOFF_FIELDS:
            v = value.get(name, "")
            if not isinstance(v, str):
                return None, f"{name} for {str(anchor)[:120]!r} is not text"
            texts[name] = v
        out[str(anchor)] = texts
    return out, None


def extract_handoff(
    preset: Preset, launch: Launch
) -> tuple[dict[str, dict[str, str]] | None, str | None]:
    """The agent's analysis texts from a hand-off launch's output, or ``(None, error)``. claude-code
    prints ``--output-format json``: the launch must have exited 0 and its JSON say ``is_error``
    false and ``subtype`` "success"; its ``result`` (the agent's final message) is then read by
    parse_handoff_analysis. Other presets print it differently and are not supported this version
    (B-5) — refused, never a silent miss."""
    if preset.name not in HANDOFF_PRESETS:
        return None, (
            f"the hand-off reads the agent's analysis from the launch output, which only the "
            f"claude-code preset is supported for this version; {preset.name!r} is experimental "
            "and prints its result another way"
        )
    if launch.exit != 0:
        return None, f"the hand-off launch exited {launch.exit}"
    try:
        data = json.loads(launch.output)
    except (TypeError, ValueError) as exc:
        return None, f"the launch did not print the expected JSON result ({exc})"
    if not isinstance(data, dict):
        return None, "the launch's JSON is not an object"
    if data.get("is_error") is not False:
        return None, f"the launch reported an error: {str(data.get('result'))[:300]}"
    if data.get("subtype") != "success":
        return None, f"the launch ended with subtype {data.get('subtype')!r}, not 'success'"
    result = data.get("result")
    if not isinstance(result, str) or not result.strip():
        return None, "the launch's JSON carried no 'result' text"
    return parse_handoff_analysis(result)


# Written above the agent's final message when the driver refuses to compose the hand-off from it.
HANDOFF_AGENT_RESULT_HEAD = (
    "This is not a hand-off document: it is the hand-off agent's final message, kept as it was "
    "printed because the driver refused to compose the hand-off from it ({why})."
)


def agent_result_path(out_file: Path) -> Path:
    """Where a refused hand-off keeps the agent's final message: ``<out>.agent-result.txt``."""
    return out_file.with_name(out_file.name + ".agent-result.txt")


def _launch_result(launch: Launch) -> str | None:
    """The agent's final message (claude-code's ``result``) in a launch's output, or None."""
    try:
        data = json.loads(launch.output)
    except (TypeError, ValueError):
        return None
    result = data.get("result") if isinstance(data, dict) else None
    return result if isinstance(result, str) and result.strip() else None


def _refused(launch: Launch, out_file: Path, error: str) -> dict[str, Any]:
    """A refused hand-off: nothing is written to ``out_file``; the agent's final message, when the
    launch printed one, is kept beside it (agent_result_path), headed as not a hand-off document, so
    a long analysis is not lost to one wrong anchor."""
    out: dict[str, Any] = {"ok": False, "error": error}
    result = _launch_result(launch)
    if result is not None:
        kept = agent_result_path(out_file)
        kept.write_text(
            HANDOFF_AGENT_RESULT_HEAD.format(why=error) + "\n\n" + result, encoding="utf-8"
        )
        out["agent_result_file"] = str(kept)
        out["error"] = f"{error}; the agent's final message is kept in {kept}"
    return out


def run_handoff(
    preset: Preset,
    *,
    atlas_path: Path,
    run_pair: str,
    workdir: Path,
    out_file: Path,
    timeout: float = DEFAULT_TIMEOUT,
    runner: Callable[..., Launch] = run_agent,
) -> dict[str, Any]:
    """Launch the hand-off agent, then write the document to ``out_file``: handoff_document (the
    CLI's function) with the agent's texts under each block's placeholders — a finding it wrote
    nothing for says so. Nothing is written when the launch failed or reported an error, or when
    its texts name an anchor the hand-off does not hold; the agent's final message, when there is
    one, is then kept beside it (agent_result_path) — headed as not a hand-off document — and the
    hand-off file is still not written. An experimental preset is refused before the launch
    (B-5)."""
    from treasure_map.lib.atlas.connection import open_atlas

    if preset.name not in HANDOFF_PRESETS:
        return {"ok": False, "error": extract_handoff(preset, Launch(0, 0.0, False))[1]}
    values = _values(preset, atlas_path, workdir, handoff_prompt(run_pair), "handoff", run_pair)
    launch = runner(render(preset, values), cwd=workdir, timeout=timeout, keep_full=True)
    if launch.timed_out:
        return {
            "ok": False,
            "error": "the hand-off launch hit its deadline",
            "seconds": launch.seconds,
        }
    analysis, err = extract_handoff(preset, launch)
    if analysis is None:
        return _refused(launch, out_file, str(err))
    atlas = open_atlas(atlas_path)
    try:
        stamp, file_staleness = _rr.local_handoff_context(atlas)
        findings = _rr.handoff_findings(atlas, run_pair, file_staleness=file_staleness)
        known = {str(f["anchor_ref"]) for f in findings}
        extra = sorted(set(analysis) - known)
        if extra:
            return _refused(
                launch,
                out_file,
                f"the agent wrote for {len(extra)} anchor(s) the hand-off does not hold "
                f"(first: {extra[0][:200]!r}); nothing was written",
            )
        document = _rr.handoff_header(run_pair, len(findings)) + "".join(
            _rr.handoff_blocks(atlas, run_pair, findings, stamp=stamp, analysis=analysis)
        )
    finally:
        atlas.close()
    out_file.write_text(document, encoding="utf-8")
    return {
        "ok": True,
        "out_file": str(out_file),
        "bytes": len(document),
        "findings": len(findings),
        "nothing_written": len(known - set(analysis)),
    }
