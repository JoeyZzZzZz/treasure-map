# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The standardized findings hand-off (Design B): the fact/analysis blocks review_report renders,
one per changed_real finding, each with every cell stated (no blanks), neutral section titles and
the standing "awaiting human verification" status."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib import test_same_shape_siblings as sst
from tests.unit.lib.test_diff_review import DX, World, _pair_anchor, a_row  # noqa: F401
from tests.unit.lib.test_file_diff import FW, SECRET_VALUE
from treasure_map import mcp_app, version
from treasure_map.lib import overlay
from treasure_map.lib.query import diff_align as dalign
from treasure_map.lib.query import diff_annotations as dann
from treasure_map.lib.query import diff_review as dr
from treasure_map.lib.query import patch_view as pv
from treasure_map.lib.query import review_report as rr
from treasure_map.lib.query import same_shape_siblings as sss
from treasure_map.version import UNKNOWN_VERSION

PAIR = "runA::runB"

# Words that would read as a verdict in a tmap-rendered template string (B-6 / acceptance 7). The
# embedded verdict / change_kind / rationale / pseudocode are NOT template strings and not scanned.
_JUDGEMENT_WORDS = {
    "exploit",
    "exploitable",
    "bypass",
    "vulnerable",
    "vulnerability",
    "complete",
    "proven",
    "safe",
    "unsafe",
    "blocked",
}


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> World:
    w = World(tmp_path, monkeypatch)
    w.pair(DX, "00001000", "00001000")
    w.rows[DX] = [a_row("00001000")]
    return w


def _stamp() -> rr.HandoffStamp:
    """The same staleness context the CLI builds (installed_commit, the current code stamp)."""
    from treasure_map.lib import rescan_version
    from treasure_map.lib.analyze.ghidra_runner import current_pass_version
    from treasure_map.lib.config.config import load_config
    from treasure_map.version import installed_commit

    return rr.HandoffStamp(
        build_hash=current_pass_version(),
        current=rescan_version.current_code_stamp(load_config()),
        commit=installed_commit(),
    )


def _judge_changed_real(w: World, anchor: str) -> None:
    overlay.annotate_diff(
        w.atlas,
        diff_id=DX,
        anchor_ref=anchor,
        verdict="changed_real",
        rationale="looked at both sides",
        verdict_basis={"change_kind": ["sink_replaced"], "evidence": [anchor]},
        ctx=overlay.WriteContext(channel="mcp", session="s"),
    )


def _fact_cells(block: str) -> list[tuple[str, str]]:
    """The ``- label: value`` fact lines of a block, as (label, value)."""
    out = []
    for line in block.splitlines():
        m = re.match(r"- ([^:]+): (.*)$", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def test_a_changed_real_finding_renders_a_block_with_every_cell_stated(world: World) -> None:
    """★ B-2 / B-3: a changed_real finding renders one block — the recorded judgment, the tmap facts
    for its shape, the two analysis placeholders and the status. EVERY fact cell is stated (an
    unavailable one names its reason); none is blank. The status is always "awaiting human
    verification", and tmap emits no reachability/exploitability verdict and never "blocked".

    MUTATION (verified RED): let a fact cell render an empty value -> a blank cell -> RED; drop the
    status line -> RED."""
    anchor = _pair_anchor(DX, "00001000", "00001000")
    _judge_changed_real(world, anchor)
    findings = rr.handoff_findings(world.atlas, PAIR)
    assert len(findings) == 1 and findings[0]["subject_kind"] == "function_pair"
    block = rr.handoff_chunk(world.atlas, PAIR, findings[0], stamp=_stamp())
    assert anchor in block
    cells = dict(_fact_cells(block))
    # the recorded judgment, kept apart from the facts
    assert cells["recorded verdict"] == "changed_real"
    assert cells["recorded change kind"] == "sink_replaced"
    # every fact cell is non-blank; an unavailable one states a reason
    for label, value in _fact_cells(block):
        assert value.strip(), (label, "blank cell")
        if value.startswith("unavailable"):
            assert value != "unavailable ()" and "(" in value, (label, value)
    # the standing status, and no conclusion drawn by tmap
    assert f"status: {rr.HANDOFF_STATUS}" in block
    assert rr.HANDOFF_STATUS == "awaiting human verification"
    assert "blocked" not in block.lower()


@pytest.mark.parametrize(
    ("kind", "anchor", "diff_id"),
    [
        ("function_presence", f"{PAIR}#function_presence#libx::b:00004000", f"{PAIR}::libx"),
        ("non_binary", f"{PAIR}#non_binary#etc/rc", None),
        ("binary_presence", f"{PAIR}#binary_presence#a_only:bin/busybox", None),
    ],
    ids=["presence", "file", "binary_presence"],
)
def test_each_subject_shape_states_every_cell(
    world: World, kind: str, anchor: str, diff_id: str | None
) -> None:
    """★ B-2: the single-side, file and single-binary shapes each render with every fact cell stated
    — "single side", "not applicable (file)" or "not applicable (whole-binary …)" — never a blank.

    MUTATION (verified RED): leave a shape's fact cells unwritten -> a block with no fact line ->
    RED."""
    finding = {
        "anchor_ref": anchor,
        "subject_kind": kind,
        "diff_id": diff_id,
        "verdict": "changed_real",
        "rationale": "r",
        "review_state": "concluded",
        "verdict_basis": {"change_kind": ["restructured"]},
    }
    block = rr.handoff_chunk(world.atlas, PAIR, finding, stamp=_stamp())
    cells = _fact_cells(block)
    labels = {label for label, _ in cells}
    change_labels = {
        "change (tmap facts)",
        "file difference (tmap facts)",
        "whole-binary presence (tmap facts)",
    }
    assert labels & change_labels, labels
    assert "reachable shape (tmap facts)" in labels or "file difference (tmap facts)" in labels
    for _label, value in cells:
        assert value.strip()
    assert f"status: {rr.HANDOFF_STATUS}" in block


def test_the_template_titles_and_labels_carry_no_verdict_word() -> None:
    """★ B-6 / acceptance 7: the structural labels and section titles tmap renders carry no verdict
    word (the embedded judgment / rationale / pseudocode are not scanned). The two analysis titles
    are the neutral ones.

    MUTATION (verified RED): title the hypotheses section 'exploitability' -> RED."""
    assert rr.HANDOFF_HYPOTHESES_TITLE == "agent analysis — unverified hypotheses"
    assert rr.HANDOFF_DEVICE_TITLE == "to check on a device"
    for label in rr._HANDOFF_LABELS:
        words = set(re.findall(r"[a-z]+", label.lower()))
        assert not (words & _JUDGEMENT_WORDS), (label, words & _JUDGEMENT_WORDS)


def test_the_boundary_is_carried_in_every_block(world: World) -> None:
    """★ B-7 / acceptance 14: a block's analysis placeholders carry the boundary — hypotheses and
    checks only, no exploit code / payload / attack steps, status awaiting human verification.

    MUTATION (verified RED): drop the boundary from the block -> RED."""
    for phrase in ("exploit code", "payload", "attack steps", "awaiting human verification"):
        assert phrase in rr.HANDOFF_BOUNDARY, phrase
    anchor = _pair_anchor(DX, "00001000", "00001000")
    _judge_changed_real(world, anchor)
    findings = rr.handoff_findings(world.atlas, PAIR)
    block = rr.handoff_chunk(world.atlas, PAIR, findings[0], stamp=_stamp())
    assert block.count(rr.HANDOFF_BOUNDARY) == 2  # under each analysis placeholder
    assert f"### {rr.HANDOFF_HYPOTHESES_TITLE}" in block
    assert f"### {rr.HANDOFF_DEVICE_TITLE}" in block


# ── the MCP paging tool get_diff_handoff (B-4) ──────────────────────────────────────────────────


def _server_call_on(atlas_path: Path, name: str, args: dict[str, Any]) -> dict[str, Any]:
    from tests.unit.test_tool_surface import _call
    from treasure_map import mcp_app

    return _call(mcp_app.build_server(atlas_path), name, args)


def _wide_findings_world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, n: int) -> World:
    # The command line and the local context read the install's commit as the server does here.
    monkeypatch.setattr(version, "installed_commit", lambda: UNKNOWN_VERSION)
    w = World(tmp_path, monkeypatch)
    w.rows[DX] = [a_row("00001000")]
    for i in range(1, n + 1):
        addr = f"0000{i}000"
        w.pair(DX, addr, addr)
        anchor = _pair_anchor(DX, addr, addr)
        overlay.annotate_diff(
            w.atlas,
            diff_id=DX,
            anchor_ref=anchor,
            verdict="changed_real",
            rationale="r",
            verdict_basis={"change_kind": ["restructured"], "evidence": [anchor]},
            ctx=overlay.WriteContext(channel="mcp", session="s"),
        )
    return w


def test_the_mcp_pages_concatenate_to_the_cli_document(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ B-4 / acceptance 5: get_diff_handoff's pages (offset 0 onward) concatenate byte-for-byte
    to the document review_report writes; blocks are in a stable anchor order, paged with no gap
    and no repeat. Here the budget is squeezed so the findings span several pages.

    MUTATION (verified RED): page from a wrong offset (off by one) -> a block repeats or is skipped
    -> the concatenation differs from the document -> RED."""
    from treasure_map import mcp_app

    w = _wide_findings_world(tmp_path, monkeypatch, 5)
    # Effective budget (3_300 - 2_000 = 1_300) fits any one block (max ~1,003) but not two, so the
    # findings span several pages without a single block being truncated.
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", 3_300)
    server = mcp_app.build_server(w.path)
    from tests.unit.test_tool_surface import _call

    pages, offsets, off = [], [], 0
    while off is not None:
        r = _call(server, "get_diff_handoff", {"run_pair": PAIR, "offset": off})
        assert "error" not in r, r
        pages.append(r["text"])
        offsets.append(off)
        off = r["next_offset"]
    assert len(offsets) >= 3  # the squeezed budget really paged
    assert offsets == sorted(set(offsets))  # strictly increasing: no repeat, no gap
    mcp_text = "".join(pages)
    document = rr.handoff_document(w.atlas, PAIR, stamp=_stamp())
    assert mcp_text == document


def test_a_single_block_over_budget_is_cut_with_a_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ B-4: a block larger than a page's budget is served cut, with a note saying how much is
    left, rather than dropping it or stalling the paging.

    MUTATION (verified RED): return the block whole when it is over budget -> no cut note -> RED."""
    from treasure_map import mcp_app

    w = _wide_findings_world(tmp_path, monkeypatch, 2)
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", 300)  # smaller than any one block
    r = _server_call_on(w.path, "get_diff_handoff", {"run_pair": PAIR, "offset": 0})
    assert r["block_truncated"] is True
    assert "truncated" in r["text"]
    assert r["next_offset"] == 1  # paging still advances one block at a time


def test_findings_digest_changes_when_a_judgment_is_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ B-4: findings_digest moves when a changed_real judgment is written, so a client paging
    across such a write can tell and re-fetch from offset 0.

    MUTATION (verified RED): make the digest a constant -> it never moves -> RED."""
    w = _wide_findings_world(tmp_path, monkeypatch, 1)
    first = _server_call_on(w.path, "get_diff_handoff", {"run_pair": PAIR})["findings_digest"]
    addr = "00009000"
    w.pair(DX, addr, addr)
    anchor = _pair_anchor(DX, addr, addr)
    overlay.annotate_diff(
        w.atlas,
        diff_id=DX,
        anchor_ref=anchor,
        verdict="changed_real",
        rationale="r",
        verdict_basis={"change_kind": ["restructured"], "evidence": [anchor]},
        ctx=overlay.WriteContext(channel="mcp", session="s2"),
    )
    second = _server_call_on(w.path, "get_diff_handoff", {"run_pair": PAIR})["findings_digest"]
    assert first != second


def test_a_stale_run_is_refused_not_served_a_skeleton(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ B-4(a) / acceptance 9: get_diff_handoff reads the pair's files through the same stale-run
    gate as the other pair tools — a run produced by provably different code is refused, not served
    a skeleton.

    MUTATION (verified RED): skip the _file_pair_gate call -> a stale pair yields a skeleton ->
    RED."""
    from treasure_map import mcp_app
    from treasure_map.lib.analyze import ghidra_runner

    w = _wide_findings_world(tmp_path, monkeypatch, 1)
    # Build the server against a pass version that the runs (recorded at the real one) cannot match.
    monkeypatch.setattr(ghidra_runner, "current_pass_version", lambda: "STALE-PASS-VERSION")
    monkeypatch.setattr(mcp_app, "_current_pass_version", lambda: "STALE-PASS-VERSION")
    r = _server_call_on(w.path, "get_diff_handoff", {"run_pair": PAIR, "offset": 0})
    # The stale-run refusal itself, carrying the server block like the other pair tools' refusals
    # (MUTATION, verified RED: drop ``refusal["server"] = server`` -> no server key -> RED; return
    # any other error -> no stale_scan -> RED).
    assert "stale_scan" in r and "server" in r and "text" not in r, sorted(r)


def test_a_served_handoff_page_carries_the_server_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The served page names the server answering, as start_diff_review's does.

    MUTATION (verified RED): leave ``server`` out of the page -> RED."""
    w = _wide_findings_world(tmp_path, monkeypatch, 1)
    r = _server_call_on(w.path, "get_diff_handoff", {"run_pair": PAIR})
    assert "text" in r and isinstance(r.get("server"), dict), sorted(r)


# ── the CLI: review report --handoff (B-4) ──────────────────────────────────────────────────────


def test_the_cli_handoff_file_is_the_mcp_pages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ B-4(d) / acceptance 5: `review report --handoff -o <file>` writes exactly what
    get_diff_handoff's pages concatenate to — the CLI and the MCP build the same staleness context
    (installed_commit), so the text matches.

    MUTATION (verified RED): give the CLI a different commit than the MCP -> the siblings cells and
    so the files differ -> RED."""
    from click.testing import CliRunner

    from treasure_map.cli import review_cli

    w = _wide_findings_world(tmp_path, monkeypatch, 3)
    out_file = tmp_path / "handoff.md"
    res = CliRunner().invoke(
        review_cli.review,
        ["report", PAIR, "--handoff", "-o", str(out_file), "--atlas", str(w.path)],
    )
    assert res.exit_code == 0, res.output
    cli_text = out_file.read_text(encoding="utf-8")
    # concatenate the MCP pages
    pages, off = [], 0
    while off is not None:
        r = _server_call_on(w.path, "get_diff_handoff", {"run_pair": PAIR, "offset": off})
        pages.append(r["text"])
        off = r["next_offset"]
    assert cli_text == "".join(pages)
    assert "3 findings" in res.output


# ── the driver hand-off launch (B-5) ────────────────────────────────────────────────────────────


def _claude_result(result: str, **kw: Any) -> str:
    """claude-code's --output-format json line for a finished launch."""
    import json as _json

    return _json.dumps(
        {"type": "result", "subtype": "success", "is_error": False, **kw, "result": result}
    )


def _run_handoff(w: World, out_file: Path, output: str, exit_code: int = 0) -> dict[str, Any]:
    from treasure_map.lib import review_driver as rd

    def runner(argv: list[str], *, cwd: Path, timeout: float, keep_full: bool = False) -> rd.Launch:
        assert keep_full is True  # the hand-off launch keeps all output
        return rd.Launch(exit_code, 0.1, False, output)

    return rd.run_handoff(
        rd.PRESETS["claude-code"],
        atlas_path=w.path,
        run_pair=PAIR,
        workdir=w.tmp,
        out_file=out_file,
        runner=runner,
    )


def test_run_handoff_composes_the_document_from_the_agents_texts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ B-5: the agent prints only its two texts per finding (a JSON object keyed by anchor_ref);
    the driver writes the document itself with handoff_document's text — every fact line, basis and
    status tmap's own — and the texts under each block's placeholders. A finding the agent wrote
    nothing for says so in both sections. Taking the agent's lines back out leaves exactly the
    document the CLI writes.

    MUTATION (verified RED): write the agent's result as the document -> RED; drop the
    nothing-written line -> RED."""
    import json as _json

    w = _wide_findings_world(tmp_path, monkeypatch, 2)
    anchors = [f["anchor_ref"] for f in rr.handoff_findings(w.atlas, PAIR)]
    texts = {anchors[0]: {"hypotheses": "HYP-ONE", "device_checks": "CHECK-ONE"}}
    out_file = tmp_path / "handoff.md"
    res = _run_handoff(w, out_file, _claude_result(_json.dumps(texts)))
    assert res["ok"] is True, res
    assert res["findings"] == 2 and res["nothing_written"] == 1
    written = out_file.read_text(encoding="utf-8")
    first, second = written.split(f"## `{anchors[1]}`")
    assert "HYP-ONE" in first and "CHECK-ONE" in first
    assert second.count(rr.HANDOFF_NOTHING_WRITTEN) == 2 and "HYP-ONE" not in second
    stamp, file_staleness = rr.local_handoff_context(w.atlas)
    skeleton = rr.handoff_document(w.atlas, PAIR, stamp=stamp, file_staleness=file_staleness)
    stripped = written
    for text in ("HYP-ONE", "CHECK-ONE"):  # the agent's texts, fenced
        stripped = stripped.replace(f"```\n{text}\n```\n\n", "")
    stripped = stripped.replace(f"{rr.HANDOFF_NOTHING_WRITTEN}\n\n", "")
    assert stripped == skeleton


@pytest.mark.parametrize(
    ("output", "exit_code", "why"),
    [
        (_claude_result("{}", is_error=True), 0, "reported an error"),
        (_claude_result("{}", subtype="error_max_turns"), 0, "subtype"),
        (_claude_result("{}"), 1, "exited 1"),
        (_claude_result("here is the document: ..."), 0, "not the JSON object"),
    ],
    ids=["is_error", "subtype", "returncode", "not_json"],
)
def test_run_handoff_writes_nothing_from_a_failed_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: str, exit_code: int, why: str
) -> None:
    """★ B-5: a launch that reported an error, ended other than "success", exited non-zero or did
    not print the JSON object asked for writes no file — the error text is never taken as the
    hand-off.

    MUTATION (verified RED, each case): drop the is_error / subtype / returncode check -> a file
    is written -> RED."""
    w = _wide_findings_world(tmp_path, monkeypatch, 1)
    out_file = tmp_path / "handoff.md"
    res = _run_handoff(w, out_file, output, exit_code)
    assert res["ok"] is False and why in res["error"], res
    assert not out_file.exists()


def test_run_handoff_refuses_texts_for_an_anchor_it_does_not_hold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ B-5: the agent's texts naming an anchor the hand-off does not hold (retyped wrong, or
    made up) are an error — nothing is written, rather than silently dropping its analysis.

    MUTATION (verified RED): skip the check -> a file is written -> RED."""
    import json as _json

    w = _wide_findings_world(tmp_path, monkeypatch, 1)
    texts = {f"{PAIR}#function_pair#libx::0badc0de::0badc0de": {"hypotheses": "h"}}
    out_file = tmp_path / "handoff.md"
    res = _run_handoff(w, out_file, _claude_result(_json.dumps(texts)))
    assert res["ok"] is False and "does not hold" in res["error"], res
    assert not out_file.exists()


def test_run_handoff_refuses_an_experimental_preset(tmp_path: Path) -> None:
    """★ B-5 / acceptance 15: an experimental preset prints its result another way; the hand-off is
    refused with an error, never a silent empty file.

    MUTATION (verified RED): extract from any preset -> codex silently yields nothing -> RED."""
    from treasure_map.lib import review_driver as rd

    launched = []

    def runner(argv: list[str], *, cwd: Path, timeout: float, keep_full: bool = False) -> rd.Launch:
        launched.append(argv)
        return rd.Launch(0, 0.0, False, "codex output")

    res = rd.run_handoff(
        rd.PRESETS["codex"],
        atlas_path=tmp_path / "atlas.db",
        run_pair=PAIR,
        workdir=tmp_path,
        out_file=tmp_path / "x.md",
        runner=runner,
    )
    assert res["ok"] is False and "experimental" in res["error"]
    assert launched == []  # refused before any launch
    assert not (tmp_path / "x.md").exists()


def test_extract_handoff_reads_only_claude_codes_result() -> None:
    """★ B-5: claude-code's result is read as the agent's texts (a fenced object too); another
    preset is refused, never a silent miss; a value that is not the two texts is refused whole."""
    from treasure_map.lib import review_driver as rd

    body = '{"r1": {"hypotheses": "h", "device_checks": "d"}}'
    good = rd.Launch(0, 0.0, False, _claude_result(body))
    texts, err = rd.extract_handoff(rd.PRESETS["claude-code"], good)
    assert texts == {"r1": {"hypotheses": "h", "device_checks": "d"}} and err is None
    fenced = rd.Launch(0, 0.0, False, _claude_result(f"```json\n{body}\n```"))
    assert rd.extract_handoff(rd.PRESETS["claude-code"], fenced)[0] == texts
    texts, err = rd.extract_handoff(rd.PRESETS["codex"], good)
    assert texts is None and err and "experimental" in err
    # claude-code but no JSON result
    texts, err = rd.extract_handoff(rd.PRESETS["claude-code"], rd.Launch(0, 0.0, False, "x"))
    assert texts is None and err
    for bad in ('{"r1": "text"}', '{"r1": {"notes": "x"}}', '{"r1": {"hypotheses": 3}}', "[1]"):
        texts, err = rd.parse_handoff_analysis(bad)
        assert texts is None and err, bad


def test_the_handoff_prompt_carries_the_boundary_and_the_tool() -> None:
    """★ B-7 / acceptance 14: the hand-off prompt tells the agent to read via get_diff_handoff and
    carries the boundary — hypotheses and checks only, no exploit code / payload / attack steps.

    MUTATION (verified RED): drop the boundary from the prompt -> RED."""
    from treasure_map.lib import review_driver as rd

    prompt = rd.handoff_prompt(PAIR)
    assert "get_diff_handoff" in prompt
    for phrase in ("exploit code", "payload", "attack steps", "awaiting human verification"):
        assert phrase in prompt, phrase
    assert "unverified hypotheses" in prompt and "to check on a device" in prompt


def test_run_agent_keep_full_keeps_all_output(tmp_path: Path) -> None:
    """★ B-5: run_agent(keep_full=True) keeps all the output (the per-unit launch keeps only the
    tail); the hand-off launch needs the agent's whole final message.

    MUTATION (verified RED): truncate even when keep_full -> RED."""
    import sys

    from treasure_map.lib import review_driver as rd

    argv = [sys.executable, "-c", "print('x' * 5000)"]
    full = rd.run_agent(argv, cwd=tmp_path, timeout=30, keep_full=True)
    assert len(full.output) >= 5000
    tail = rd.run_agent(argv, cwd=tmp_path, timeout=30)
    assert len(tail.output) <= 4000


def test_a_finding_whose_basis_moved_is_marked_not_passed_off_as_current() -> None:
    """★ B-1: a changed_real finding whose basis has moved (review_state not concluded) is marked
    MOVED in the skeleton, so it is not read as a standing conclusion.

    MUTATION (verified RED): render 'current' regardless of review_state -> RED."""
    current = {"review_state": "concluded"}
    moved = {"review_state": "needs_recheck", "basis_state": "basis_moved", "basis_moved": {"x": 1}}
    assert rr._finding_basis_line(current) == "current"
    line = rr._finding_basis_line(moved)
    assert "MOVED" in line and "re-read" in line


# ── the facts each block reads, through the lib call its own tool makes ─────────────────────────
# A diff of libx whose overlay is the real one (computed from the atlas's instances), each run with
# an analysis.db holding the functions: the pair 00001000 / 00002000 has a lined-up strcpy call and
# a changed body, the pair 00003000 / 00004000 the same call shape unchanged, and caller_b calls
# the changed function on side B.

FA, FB = "00001000", "00002000"
BODY_A = "void f(void)\n{\n  strcpy(d, s);\n  return;\n}"
BODY_B = "void f(void)\n{\n  if (n < 8) {\n  strcpy(d, s);\n  }\n  return;\n}"
HUNK_LINE = "+if (n < 8) {"


def _servable(monkeypatch: pytest.MonkeyPatch) -> None:
    """The runs are read as current (their stamps are not under test), by the MCP server and by
    the local context alike."""

    def fresh(atlas: Any, diff_id: str) -> dict[str, Any]:
        return {"source_stale": False, "source_stale_reason": None, "toolchain_checked": True}

    def many(atlas: Any, ids: Any) -> dict[str, dict[str, Any]]:
        return {d: fresh(atlas, d) for d in sorted(set(ids))}

    monkeypatch.setattr(mcp_app, "_installed_commit", lambda: UNKNOWN_VERSION)
    monkeypatch.setattr(version, "installed_commit", lambda: UNKNOWN_VERSION)
    monkeypatch.setattr(pv, "diff_source_staleness", fresh)
    monkeypatch.setattr(sss, "diff_source_staleness", fresh)
    monkeypatch.setattr(dalign, "diffs_source_staleness", many)
    pv._clear_view_caches()


def _body(w: sst.World, side: str, addr: str, text: str, name: str) -> None:
    w.adb[side].execute(
        "UPDATE functions SET pseudocode = ?, name = ? WHERE address = ?", (text, name, addr)
    )


def _judge(
    atlas: Any, diff_id: str | None, anchor: str, rationale: str = "read both sides"
) -> None:
    overlay.annotate_diff(
        atlas,
        diff_id=diff_id,
        run_pair=None if diff_id else PAIR,
        anchor_ref=anchor,
        verdict="changed_real",
        rationale=rationale,
        verdict_basis={"change_kind": ["restructured"]},
        ctx=overlay.WriteContext(channel="mcp", session="s"),
    )


@pytest.fixture
def full(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> sst.World:
    _servable(monkeypatch)
    w = sst.World(tmp_path)
    w.lined(FA, FB, 0.8)
    w.lined("00003000", "00004000", 1.0)
    _body(w, "a", FA, BODY_A, "fa")
    _body(w, "b", FB, BODY_B, "fb")
    w.fn("b", "00005000", ["fb"], name="caller_b")
    w.commit()
    return w


def _files_world(full: sst.World) -> FW:
    """A second atlas, beside ``full``'s, whose run pair compares non-binary files."""
    (full.tmp / "files").mkdir()
    return FW(full.tmp / "files")


def _pair_ref(a: str = FA, b: str = FB) -> str:
    return dr.pair_anchor("runA", "runB", "libx", a, b)


def _block(atlas: Any, anchor: str) -> str:
    stamp, file_staleness = rr.local_handoff_context(atlas)
    findings = rr.handoff_findings(atlas, PAIR, file_staleness=file_staleness)
    (finding,) = [f for f in findings if f["anchor_ref"] == anchor]
    return rr.handoff_chunk(atlas, PAIR, finding, stamp=stamp)


def _cell_value(block: str, label: str) -> str:
    return dict(_fact_cells(block)).get(label, f"<no {label} cell>")


def test_the_callers_cell_names_the_caller_its_sides_analysis_db_records(full: sst.World) -> None:
    """★ The one-level callers are get_xrefs(direction="callers") on the finding's side, read from
    that run's own analysis.db (never the atlas) with that side's binary: the caller is named.

    MUTATION (verified RED): hand get_xrefs the atlas connection again -> "xref error" -> RED."""
    _judge(full.atlas, sst.DIFF, _pair_ref())
    cell = _cell_value(_block(full.atlas, _pair_ref()), "one-level callers")
    assert cell.startswith("1 caller(s) on side b: caller_b"), cell


def test_a_function_the_run_does_not_hold_is_not_resolved_never_zero_callers(
    full: sst.World,
) -> None:
    """★ A function the side's analysis.db does not resolve reads "function not resolved", never
    "0 caller(s)" — that would read as a function nobody calls.

    MUTATION (verified RED): render found False as "0 caller(s)" -> RED."""
    _judge(full.atlas, sst.DIFF, _pair_ref())
    full.adb["b"].execute("DELETE FROM functions WHERE address = ?", (FB,))
    full.commit()
    cell = _cell_value(_block(full.atlas, _pair_ref()), "one-level callers")
    assert cell.startswith("unavailable (function not resolved: 00002000 on side b"), cell
    assert "0 caller(s)" not in cell


def test_the_change_is_the_entrys_inline_hunk(full: sst.World) -> None:
    """★ The change cell shows the entry's inline hunk as the view gives it — its structural lines,
    in the original text.

    MUTATION (verified RED): join the hunk object's keys (the old rendering) -> RED."""
    _judge(full.atlas, sst.DIFF, _pair_ref())
    block = _block(full.atlas, _pair_ref())
    assert "- change (tmap facts):\n```\n" in block
    assert HUNK_LINE in block.splitlines()


def test_an_undetermined_pair_shows_the_hunk_of_its_proposed_pairing(full: sst.World) -> None:
    """★ An entry whose alignment is undetermined has no pseudocode_delta of its own; the hunk read
    as if paired (proposed_pair_reading) is shown, titled as the proposed pairing.

    MUTATION (verified RED): drop the proposed_pair_reading fallback -> "unavailable" -> RED."""
    full.pair("00007000", "00008000", 0.5, 0.6)
    full.fn("a", "00007000", ["strcpy"], name="ua")
    full.fn("b", "00008000", ["strcpy"], name="ub")
    _body(full, "a", "00007000", BODY_A, "ua")
    _body(full, "b", "00008000", BODY_B, "ub")
    full.commit()
    anchor = _pair_ref("00007000", "00008000")
    _judge(full.atlas, sst.DIFF, anchor)
    block = _block(full.atlas, anchor)
    assert "- change (tmap facts, proposed pairing — alignment undetermined):" in block
    assert HUNK_LINE in block.splitlines()


def _wide_rows(w: sst.World) -> None:
    """24 more B-side copy calls in the changed function (25 rows with the lined-up one), two
    shapes alternating (source_len / const)."""
    for k in range(24):
        flow = sst.SRC if k % 2 == 0 else sst.CONST
        ref = sst._ref("runB", FB, "copy", f"0x{0x100 + 8 * k:x}")
        w.inst("runB", ref, "copy", "strcpy", flow)
    w.commit()


def test_the_candidate_rows_are_written_out_and_their_cut_is_named(full: sst.World) -> None:
    """★ Every row shown is one line (a_ref, b_ref, sink_class, landing, size kind / argument,
    source kind); rows past the first page are counted and their call named; the same-shape
    groups are given per row, one line per group.

    MUTATION (verified RED): read only the first row -> RED; drop "of {total}" -> RED."""
    _wide_rows(full)
    _judge(full.atlas, sst.DIFF, _pair_ref())
    block = _block(full.atlas, _pair_ref())
    shape = _cell_value(block, "reachable shape (tmap facts)")
    assert shape.startswith("rows shown 20 of 25 — rest: get_diff_patch_view("), shape
    assert "rows_offset=20)" in shape
    rows = [x for x in block.splitlines() if x.startswith("  - row ")]
    assert len(rows) == 20
    assert any("· size_kind,size_arg b source_len,null ·" in x for x in rows), rows
    assert any("· size_kind,size_arg b const,null ·" in x for x in rows), rows
    groups = [x for x in block.splitlines() if x.startswith("  - group `")]
    assert len(groups) == 2, groups
    assert "(of the 20 rows shown)" in _cell_value(block, "sink class")


def _presence_finding(full: sst.World) -> str:
    """A B-only function of the same diff with one candidate row; its anchor, judged."""
    full.atlas.execute(
        "INSERT INTO function_presence (diff_id, side, addr, presence_state) "
        "VALUES (?, 'b', '00006000', 'unmatched_analysis_complete')",
        (sst.DIFF,),
    )
    full.inst("runB", sst._ref("runB", "00006000", "copy", "0x10"), "copy", "strcpy", sst.SRC)
    full.fn("b", "00006000", ["strcpy"], name="fnew")
    full.commit()
    anchor = dr.presence_anchor("runA", "runB", "libx", "b", "00006000")
    _judge(full.atlas, sst.DIFF, anchor)
    return anchor


def test_the_handoff_builds_each_diffs_view_once_for_its_sibling_cells(
    full: sst.World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ FC10: one hand-off pass builds each diff's view once for all its same-shape cells (and
    reads each side's calls once) — not once per row ref — and the blocks are byte for byte the
    ones a separate same_shape_siblings call per ref gives.

    MUTATION (verified RED, ``1 failed``): let handoff_blocks hand no shared reads to its blocks
    (``reads = None``) -> the view is built once per block -> RED; let the siblings cell call
    same_shape_siblings without the reads (``reads=None``) -> once per row ref -> RED."""
    _wide_rows(full)
    _judge(full.atlas, sst.DIFF, _pair_ref())
    _presence_finding(full)
    stamp, file_staleness = rr.local_handoff_context(full.atlas)
    findings = rr.handoff_findings(full.atlas, PAIR, file_staleness=file_staleness)
    assert len(findings) == 2 and {f["diff_id"] for f in findings} == {sst.DIFF}
    real_view, real_calls, real_sss = sss.build_diff_view, sss._calls, sss.same_shape_siblings
    built: list[str] = []
    read: list[tuple[str, str]] = []

    def counting_view(atlas: Any, diff_id: str) -> Any:
        built.append(diff_id)
        return real_view(atlas, diff_id)

    def counting_calls(atlas: Any, run_id: str, sha: str) -> Any:
        read.append((run_id, sha))
        return real_calls(atlas, run_id, sha)

    monkeypatch.setattr(sss, "build_diff_view", counting_view)
    monkeypatch.setattr(sss, "_calls", counting_calls)
    shared = rr.handoff_blocks(full.atlas, PAIR, findings, stamp=stamp)
    assert built == [sst.DIFF], built  # one diff involved, one build
    assert len(read) == len(set(read)), read  # each side's calls read once
    # the per-call path: every same_shape_siblings call reads afresh, once per distinct row ref
    built.clear()

    def fresh(*a: Any, **k: Any) -> Any:
        k.pop("reads", None)
        return real_sss(*a, **k)

    monkeypatch.setattr(sss, "same_shape_siblings", fresh)
    separate = rr.handoff_blocks(full.atlas, PAIR, findings, stamp=stamp)
    assert len(built) == 21  # 20 rows shown of the pair, 1 of the single-side function
    assert shared == separate


def test_a_single_side_function_states_its_sink_class_and_callers(full: sst.World) -> None:
    """★ A function on one side only has no counterpart to compare, but its own candidate rows,
    sink class and callers are read as a pair's are — not written off as 'single side'.

    MUTATION (verified RED): render the fixed single-side cells again -> no sink class -> RED."""
    full.atlas.execute(
        "INSERT INTO function_presence (diff_id, side, addr, presence_state) "
        "VALUES (?, 'b', '00006000', 'unmatched_analysis_complete')",
        (sst.DIFF,),
    )
    full.inst("runB", sst._ref("runB", "00006000", "copy", "0x10"), "copy", "strcpy", sst.SRC)
    full.fn("b", "00006000", ["strcpy"], name="fnew")
    full.fn("b", "00009000", ["fnew"], name="caller_new")
    full.commit()
    anchor = dr.presence_anchor("runA", "runB", "libx", "b", "00006000")
    _judge(full.atlas, sst.DIFF, anchor)
    block = _block(full.atlas, anchor)
    assert _cell_value(block, "sink class") == "copy"
    assert _cell_value(block, "one-level callers").startswith("1 caller(s) on side b: caller_new")
    assert "function on side b only" in _cell_value(block, "change (tmap facts)")


def _callers_expected(xr: dict[str, Any], side: str = "b") -> str:
    """The callers cell a get_xrefs answer gives: the count, the names, the tool's note verbatim."""
    names = [e["anchor"]["function"] for e in xr["edges"]]
    body = f"{len(names)} caller(s) on side {side}" + (f": {', '.join(names)}" if names else "")
    return f"{body} — {xr['note']}" if xr.get("note") else body


def _null(value: Any) -> str:
    return "null" if value is None else str(value)


def _side_values(axes: dict[str, Any], axis: str, fields: tuple[str, ...]) -> list[str]:
    """``<side> <v1>,<v2>`` for each side of a row's sink_axes that gives ``axis``."""
    out = []
    for side in ("a", "b"):
        value = (axes.get(side) or {}).get(axis)
        if isinstance(value, dict):
            vals = ",".join(_null(value.get(f)) for f in fields)
            out.append(f"{side} {vals}")
    return out


def _cross_check_world(full: sst.World) -> None:
    """Rows of three shapes in the changed function (copy / source_len, copy / const, a command
    call with a recorded source kind), a constant changed in its body, and an undetermined pair
    whose B function nobody calls."""
    for k, (cls, sink, flow) in enumerate(
        [
            ("copy", "strcpy", sst.SRC),
            ("copy", "strcpy", sst.CONST),
            ("cmd", "system", json.dumps({"source_kind": "free_string"})),
            ("copy", "strcpy", sst.CONST),
        ]
    ):
        full.inst("runB", sst._ref("runB", FB, cls, f"0x{512 + 8 * k:x}"), cls, sink, flow)
    _body(full, "a", FA, "void f(void)\n{\n  strcpy(d, s);\n  n = 4;\n  return;\n}", "fa")
    _body(full, "b", FB, "void f(void)\n{\n  strcpy(d, s);\n  n = 8;\n  return;\n}", "fb")
    full.pair("00007000", "00008000", 0.5, 0.6)
    full.fn("a", "00007000", ["strcpy"], name="ua")
    full.fn("b", "00008000", ["strcpy"], name="ub")
    full.commit()


def test_each_fact_is_what_its_own_tool_answers(full: sst.World) -> None:
    """★ FC08: the block's facts are the values the MCP tools answer for the same subject, cell by
    cell — the callers cell (count, names and the note) of get_xrefs, for a function with a caller
    and one with none; each row's a_ref / b_ref / sink_class / landing / size kind and argument /
    source kind of get_diff_patch_view; the change's structural lines and substitution groups of
    its inline_hunk; and every distinct row ref's group (group_ref, member_count, by_landing, the
    rows in it) of same_shape_siblings. A tool whose answer changes shape turns this red.

    MUTATION (verified RED each, ``1 failed``): read the caller name from a key the edge does not
    have; key the siblings on the A ref; drop the get_xrefs note (``return body``); read source_kind
    from ``kind``; render the row's sink_class as null; render no substitution group; leave
    by_landing out of the group line (``json.dumps({})``)."""
    _cross_check_world(full)
    undetermined = _pair_ref("00007000", "00008000")
    _judge(full.atlas, sst.DIFF, _pair_ref())
    _judge(full.atlas, sst.DIFF, undetermined)
    block = _block(full.atlas, _pair_ref())
    tools = mcp_app.make_tools(full.path)
    # the callers: one caller here, none for the undetermined pair's B function
    xr = tools["get_xrefs"](function=FB, direction="callers", run_id="runB", binary=sst.SHA_B)
    assert xr["edges"] and _cell_value(block, "one-level callers") == _callers_expected(xr)
    xr0 = tools["get_xrefs"](function="00008000", direction="callers", run_id="runB")
    assert not xr0["edges"] and xr0["note"]
    assert _cell_value(_block(full.atlas, undetermined), "one-level callers") == (
        _callers_expected(xr0)
    )
    view = tools["get_diff_patch_view"](sst.DIFF, entry_id=_pair_ref())
    (entry,) = view["entries"]
    assert len(entry["rows"]) == entry["rows_total"] == 5  # all shown: every row is checked
    assert {r["sink_class"] for r in entry["rows"]} == {"copy", "cmd"}
    for i, row in enumerate(entry["rows"], 1):
        line = next(x for x in block.splitlines() if x.startswith(f"  - row {i}: "))
        refs = f"a_ref {_null(row['a_ref'])} · b_ref {_null(row['b_ref'])}"
        assert f"{refs} · sink_class {_null(row['sink_class'])} · landing {row['landing']}" in line
        size_part = line.split("· size_kind,size_arg ", 1)[1].split(" · source_kind ", 1)
        for v in _side_values(row["sink_axes"], "bound", ("size_kind", "size_arg")):
            assert v in size_part[0], (v, line)
        for v in _side_values(row["sink_axes"], "source", ("source_kind",)):
            assert v in size_part[1], (v, line)
    assert any(_side_values(r["sink_axes"], "source", ("source_kind",)) for r in entry["rows"])
    # the change: every structural line and every substitution group of the tool's inline hunk
    hunk = entry["pseudocode_delta"]["inline_hunk"]
    lines = block.splitlines()
    for run in hunk["structural"]:
        for x in run:
            assert x in lines, x
    subs = [x for x in lines if x.startswith("  - substitution group: ")]
    assert hunk["substitution_groups"] and len(subs) == len(hunk["substitution_groups"])
    for g, line in zip(hunk["substitution_groups"], subs, strict=True):
        assert f"{g['kind']}" in line and f", {g['total']} time(s): " in line, (g, line)
    # the groups: each distinct row ref's group as same_shape_siblings answers it
    by_group: dict[str, tuple[dict[str, Any], list[int]]] = {}
    for i, row in enumerate(entry["rows"], 1):
        g = tools["same_shape_siblings"](sst.DIFF, evidence_ref=row["b_ref"] or row["a_ref"])
        by_group.setdefault(g["group_ref"], (g, []))[1].append(i)
    assert len(by_group) == 3
    group_lines = [x for x in lines if x.startswith("  - group `")]
    assert group_lines == [
        f"  - group `{ref}`: {g['member_count']} member(s), by landing "
        f"{json.dumps(g['by_landing'], sort_keys=True)} — row(s) {', '.join(map(str, idx))}"
        for ref, (g, idx) in by_group.items()
    ]


def test_the_file_facts_are_what_get_file_diff_answers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ FC08: a file block's facts are get_file_diff's for the path — the change, the kind, the
    hunk stats and the structured counts of its summary, and the first page of its hunk lines.

    MUTATION (verified RED, ``1 failed``): leave the structured counts out of the file cell -> RED;
    leave the hunk stats out -> RED."""
    _servable(monkeypatch)
    fw = FW(tmp_path)
    fa = fw.file("a", "etc/app.conf", "config_file", "port=80\nmode=a\n")
    fb = fw.file("b", "etc/app.conf", "config_file", "port=8080\nmode=a\n")
    fw.row("a", "config_entries", fa, section=None, key="port", value="80", is_sensitive=0)
    fw.row("b", "config_entries", fb, section=None, key="port", value="8080", is_sensitive=0)
    anchor = f"{PAIR}#non_binary#etc/app.conf"
    tools = fw.tools()
    conn = fw.atlas()
    try:
        _judge(conn, None, anchor)
        block = _block(conn, anchor)
    finally:
        conn.close()
    summary = tools["get_file_diff"](PAIR, path="etc/app.conf", detail="summary")["entry"]
    page = tools["get_file_diff"](PAIR, path="etc/app.conf")["entry"]
    assert summary["structured_counts"], summary  # the fixture really has structured rows
    assert _cell_value(block, "file difference (tmap facts)") == ", ".join(
        [
            f"change {page['change']}",
            f"kind {page['kind']}",
            f"hunk stats {json.dumps(summary['hunk_stats'], sort_keys=True)}",
            f"structured counts {json.dumps(summary['structured_counts'], sort_keys=True)}",
        ]
    )
    lines = block.splitlines()
    start = lines.index("- file hunk (tmap facts):") + 2
    assert lines[start : start + len(page["hunk"]["lines"])] == page["hunk"]["lines"]


def test_the_callers_cell_reads_this_diffs_binary_of_two_at_one_address(
    full: sst.World,
) -> None:
    """★ FC07: the side's analysis.db holds two binaries with a function at the finding's address;
    the callers cell reads the diff's own binary (by its content hash), so the caller of THAT
    function is named — never "ambiguous".

    MUTATION (verified RED, ``1 failed``): drop the binary qualifier (``binary=None``) -> the
    address names two functions -> "function not resolved … ambiguous" -> RED."""
    full.adb["b"].execute("INSERT INTO binaries (name, sha256) VALUES ('liby', ?)", ("e" * 64,))
    full.adb["b"].execute(
        "INSERT INTO functions (binary_id, name, address, callees, callees_truncated, "
        "unresolved_external_calls) VALUES (2, 'other', ?, '[]', 0, '[]')",
        (FB,),
    )
    full.adb["b"].execute(
        "INSERT INTO functions (binary_id, name, address, callees, callees_truncated, "
        "unresolved_external_calls) VALUES (2, 'caller_y', '00005800', '[\"other\"]', 0, '[]')"
    )
    full.commit()
    _judge(full.atlas, sst.DIFF, _pair_ref())
    cell = _cell_value(_block(full.atlas, _pair_ref()), "one-level callers")
    assert cell.startswith("1 caller(s) on side b: caller_b"), cell
    assert "caller_y" not in cell


def test_a_function_with_no_caller_carries_the_get_xrefs_note(full: sst.World) -> None:
    """★ FC09: the callers cell reads through the get_xrefs tool's own lib call
    (entry_words.xrefs_with_entry_words): a function nobody calls carries the tool's note verbatim,
    the sentence on the data words holding its entry value included.

    MUTATION (verified RED, ``1 failed``): call facts.get_xrefs again -> the note lacks the
    entry-words sentence -> RED; drop the note -> RED."""
    full.pair("00007000", "00008000", 0.5, 0.6)
    full.fn("a", "00007000", ["strcpy"], name="ua")
    full.fn("b", "00008000", ["strcpy"], name="ub")
    full.commit()
    anchor = _pair_ref("00007000", "00008000")
    _judge(full.atlas, sst.DIFF, anchor)
    cell = _cell_value(_block(full.atlas, anchor), "one-level callers")
    tools = mcp_app.make_tools(full.path)
    xr = tools["get_xrefs"](function="00008000", direction="callers", run_id="runB")
    assert xr["edges"] == [] and "entry_words" in xr, xr
    assert cell.startswith("0 caller(s) on side b — ")
    assert cell.endswith(xr["note"]), (cell, xr["note"])
    assert " | " in xr["note"]  # the entry-words sentence after get_xrefs' own note


def test_a_fully_read_finding_states_no_cell_unavailable(full: sst.World) -> None:
    """★ Acceptance 6 with teeth: a finding whose hunk, callers, rows and groups all resolve — and
    a file whose difference resolves — has no cell reading "unavailable". Any fact read wrong
    (the wrong connection, a key the answer does not have) brings one back.

    MUTATION (verified RED): callers through the atlas -> RED; the file read from ``files`` -> RED;
    the change from a key the entry does not have -> RED."""
    _judge(full.atlas, sst.DIFF, _pair_ref())
    block = _block(full.atlas, _pair_ref())
    assert "unavailable" not in block, block
    fw = _files_world(full)
    fw.file("a", "etc/rc", "shell_script", "echo old\n")
    fw.file("b", "etc/rc", "shell_script", "echo new\n")
    conn = fw.atlas()
    try:
        _judge(conn, None, f"{PAIR}#non_binary#etc/rc")
        file_block = _block(conn, f"{PAIR}#non_binary#etc/rc")
    finally:
        conn.close()
    assert "unavailable" not in file_block, file_block


def test_a_file_finding_shows_its_difference_and_never_a_sensitive_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A file finding carries get_file_diff's entry: its change, kind and hunk stats and the first
    page of its line difference; a file whose difference file_diff holds back (a sensitive entry)
    shows only its shape — the value never reaches the block.

    MUTATION (verified RED): read ``files`` / a top-level ``path`` again -> "not in the pair's
    diff" -> RED; drop the shape branch -> no "held back" -> RED."""
    _servable(monkeypatch)
    fw = FW(tmp_path)
    fw.file("a", "etc/rc", "shell_script", "echo old\n")
    fw.file("b", "etc/rc", "shell_script", "echo new\n")
    fw.file("a", "etc/app.conf", "config_file", "pass=old-synthetic\n")
    b = fw.file("b", "etc/app.conf", "config_file", f"pass={SECRET_VALUE}\n")
    fw.row("b", "config_entries", b, section=None, key="pass", value=SECRET_VALUE, is_sensitive=1)
    conn = fw.atlas()
    try:
        for path in ("etc/rc", "etc/app.conf"):
            _judge(conn, None, f"{PAIR}#non_binary#{path}")
        rc = _block(conn, f"{PAIR}#non_binary#etc/rc")
        conf = _block(conn, f"{PAIR}#non_binary#etc/app.conf")
        stamp, staleness = rr.local_handoff_context(conn)
        doc = rr.handoff_document(conn, PAIR, stamp=stamp, file_staleness=staleness)
    finally:
        conn.close()
    assert _cell_value(rc, "file difference (tmap facts)").startswith(
        "change content_differs, kind shell_script, hunk stats"
    )
    assert "+echo new" in rc.splitlines()
    assert "hunk held back (sensitive: sensitive_entry)" in conf
    assert SECRET_VALUE not in doc and "old-synthetic" not in doc


def test_a_file_finding_reads_current_as_list_overlays_reads_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A file finding is read with the same stale-run reading of its two runs list_overlays uses
    — current when they are — on the MCP page and in the CLI file alike, not marked moved for want
    of it.

    MUTATION (verified RED): call handoff_findings without file_staleness on the MCP side ->
    "MOVED" -> RED."""
    _servable(monkeypatch)
    fw = FW(tmp_path)
    fw.file("a", "etc/rc", "shell_script", "echo old\n")
    fw.file("b", "etc/rc", "shell_script", "echo new\n")
    tools = fw.tools()
    anchor = f"{PAIR}#non_binary#etc/rc"
    assert tools["annotate_diff"](anchor, "changed_real", "read it", run_pair=PAIR)["written"]
    listed = tools["list_overlays"](anchor_kind="diff_subject", run_id=PAIR)["overlays"]
    assert [r["review_state"] for r in listed] == ["concluded"]
    page = tools["get_diff_handoff"](PAIR)
    assert "- basis: current" in page["text"], page["text"]
    conn = fw.atlas()
    try:
        assert "- basis: current" in _block(conn, anchor)
    finally:
        conn.close()


def test_a_moved_basis_names_why(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """★ A finding whose diff now reads stale is marked moved with the reason the source gives
    (diff_logic_changed), not the basis state "unchanged" it still has.

    MUTATION (verified RED): write ``basis_state or state`` as the reason again -> "(unchanged)"
    -> RED."""
    w = _wide_findings_world(tmp_path, monkeypatch, 1)
    w.stale[DX] = {"source_stale": True, "source_stale_reason": "diff_logic_changed"}
    (finding,) = rr.handoff_findings(w.atlas, PAIR)
    line = rr.handoff_chunk(w.atlas, PAIR, finding, stamp=_stamp())
    assert "- basis: MOVED since the judgment (diff_logic_changed)" in line


def test_the_findings_read_builds_only_this_pairs_judged_views(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The hand-off reads only its pair's judgements and builds only their diffs' views (no
    review_progress): another pair whose view cannot be built does not stop it, and a diff of the
    pair with no finding is not built.

    MUTATION (verified RED): read every pair's judgements (no run_id) -> the other pair's view
    raises -> RED; ignore ``progress`` -> the unjudged diff is built -> RED."""
    w = _wide_findings_world(tmp_path, monkeypatch, 1)
    for run in ("runP", "runQ"):
        w.atlas.execute(
            "INSERT INTO run (run_id, hunt_commit, build_hash, hunt_instances) "
            "VALUES (?, 'facade', 'x', 1)",
            (run,),
        )
    w.atlas.execute(
        "INSERT INTO diff_meta (diff_id, run_a_id, run_b_id, binary_a, binary_b, sha256_a, "
        "sha256_b, diff_ok, version_skew) "
        "VALUES ('runP::runQ::libq', 'runP', 'runQ', 'libq', 'libq', 'aa', 'bb', 1, 0)"
    )
    w.atlas.execute(
        "INSERT INTO overlay (anchor_kind, anchor_ref, run_id, verdict, rationale, attributed_to) "
        "VALUES ('diff_subject', 'runP::runQ#function_pair#libq::00001000::00001000', "
        "'runP::runQ', 'changed_real', 'o', 'agent-via-mcp')"
    )
    w.atlas.commit()
    real = dann.build_diff_view
    built: list[str] = []

    def guarded(atlas: Any, diff_id: str) -> Any:
        if diff_id.startswith("runP::"):
            raise RuntimeError("the other pair's view is broken")
        built.append(diff_id)
        return real(atlas, diff_id)

    monkeypatch.setattr(dann, "build_diff_view", guarded)
    try:
        findings: Any = rr.handoff_findings(w.atlas, PAIR)
    except RuntimeError as exc:
        findings = exc
    assert isinstance(findings, list), f"another pair's view stopped this pair's read: {findings}"
    assert [f["run_id"] for f in findings] == [PAIR]
    assert set(built) == {DX}  # DY has no finding: not built


def test_blocks_are_in_anchor_order_whatever_order_they_were_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The blocks page in anchor_ref order, not the order (or recency) of the judgements.

    MUTATION (verified RED): drop the sort -> newest first -> RED; sort in reverse -> RED."""
    w = _wide_findings_world(tmp_path, monkeypatch, 3)
    anchors = sorted(f["anchor_ref"] for f in rr.handoff_findings(w.atlas, PAIR))
    for anchor, ts in zip(
        anchors, ("2026-01-01 00:00:02", "2026-01-01 00:00:03", "2026-01-01 00:00:01"), strict=True
    ):
        w.atlas.execute("UPDATE overlay SET updated_at = ? WHERE anchor_ref = ?", (ts, anchor))
    w.atlas.commit()
    text = _server_call_on(w.path, "get_diff_handoff", {"run_pair": PAIR})["text"]
    heads = [x[len("## `") : -1] for x in text.splitlines() if x.startswith("## `")]
    assert heads == anchors


# ── the page cache: a page is never served from blocks the findings no longer match ─────────────


def _pages_of(tools: dict[str, Any]) -> str:
    out, off = [], 0
    while off is not None:
        r = tools["get_diff_handoff"](PAIR, off)
        out.append(r["text"])
        off = r["next_offset"]
    return "".join(out)


def _same_second(w: World) -> None:
    """Every judgement stamped with one updated_at: writes within one second, as the clock shows."""
    w.atlas.execute("UPDATE overlay SET updated_at = '2026-01-01 00:00:00'")
    w.atlas.commit()


def test_a_moved_basis_is_not_served_from_the_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The judgement is unchanged but its basis moved (the diff reads stale): the next page is
    the document as it reads now, not the cached one.

    MUTATION (verified RED): digest the count and newest updated_at again -> "current" served ->
    RED."""
    w = _wide_findings_world(tmp_path, monkeypatch, 1)
    tools = mcp_app.make_tools(w.path)
    assert "- basis: current" in _pages_of(tools)
    w.stale[DX] = {"source_stale": True, "source_stale_reason": "diff_logic_changed"}
    assert _pages_of(tools) == rr.handoff_document(
        w.atlas, PAIR, stamp=_stamp(), file_staleness=_local_staleness(w)
    )


def _local_staleness(w: World) -> Any:
    return rr.local_handoff_context(w.atlas)[1]


def test_a_rewrite_within_one_second_is_not_served_from_the_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The rationale rewritten within the same second (count and newest updated_at unchanged):
    the next page carries the new one.

    MUTATION (verified RED): digest the count and newest updated_at again -> the old rationale is
    served -> RED."""
    w = _wide_findings_world(tmp_path, monkeypatch, 1)
    (anchor,) = [f["anchor_ref"] for f in rr.handoff_findings(w.atlas, PAIR)]
    tools = mcp_app.make_tools(w.path)
    _judge(w.atlas, DX, anchor, "OLD-RATIONALE")
    _same_second(w)
    assert "OLD-RATIONALE" in _pages_of(tools)
    _judge(w.atlas, DX, anchor, "NEW-RATIONALE")
    _same_second(w)
    second = _pages_of(tools)
    assert "NEW-RATIONALE" in second and "OLD-RATIONALE" not in second


def test_a_judgement_swapped_within_one_second_is_not_dropped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ Within one second one finding stops being changed_real and another becomes one (count and
    newest updated_at unchanged): the new finding is in the next page, the old one is not.

    MUTATION (verified RED): digest the count and newest updated_at again -> the new finding is
    missing -> RED."""
    w = _wide_findings_world(tmp_path, monkeypatch, 2)
    a1, a2 = sorted(f["anchor_ref"] for f in rr.handoff_findings(w.atlas, PAIR))
    overlay.annotate_diff(
        w.atlas,
        diff_id=DX,
        anchor_ref=a2,
        verdict="change_inconclusive",
        rationale="not read yet",
        ctx=overlay.WriteContext(channel="mcp", session="s"),
    )
    _same_second(w)
    tools = mcp_app.make_tools(w.path)
    first = _pages_of(tools)
    assert a1 in first and a2 not in first
    overlay.annotate_diff(
        w.atlas,
        diff_id=DX,
        anchor_ref=a1,
        verdict="change_inconclusive",
        rationale="re-read",
        ctx=overlay.WriteContext(channel="mcp", session="s"),
    )
    _judge(w.atlas, DX, a2, "the real one")
    _same_second(w)
    second = _pages_of(tools)
    assert a2 in second and a1 not in second


def test_two_atlases_with_one_pair_name_are_cached_apart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ Two atlases in one process with the same pair name and findings that read the same (same
    judgement, same stamp) but different facts (the changed function's caller): each is served its
    own blocks.

    MUTATION (verified RED): key the cache on the pair alone -> the second atlas gets the first's
    caller -> RED."""
    _servable(monkeypatch)
    texts = []
    for caller in ("caller_one", "caller_two"):
        (tmp_path / caller).mkdir()
        w = sst.World(tmp_path / caller)
        w.lined(FA, FB, 0.8)
        _body(w, "a", FA, BODY_A, "fa")
        _body(w, "b", FB, BODY_B, "fb")
        w.fn("b", "00005000", ["fb"], name=caller)
        w.commit()
        _judge(w.atlas, sst.DIFF, _pair_ref())
        w.atlas.execute("UPDATE overlay SET updated_at = '2026-01-01 00:00:00'")
        w.atlas.commit()
        texts.append(_pages_of(mcp_app.make_tools(w.path)))
        pv._clear_view_caches()
    assert "caller_one" in texts[0] and "caller_two" in texts[1] and "caller_one" not in texts[1]


# ── the page: its byte budget, its bounds, a block cut where it is rendered ──────────────────────


def test_every_page_keeps_within_the_response_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The page contract is json.dumps' default form of the whole response: a hand-off whose text
    is mostly non-ASCII (escaped six bytes a character there) pages within it, and the pages still
    concatenate to the CLI document.

    MUTATION (verified RED): measure the text's UTF-8 bytes (the old budget) -> a page over the
    budget -> RED."""
    w = _wide_findings_world(tmp_path, monkeypatch, 9)
    for f in rr.handoff_findings(w.atlas, PAIR):
        _judge(w.atlas, DX, f["anchor_ref"], "réécrit → " * 400)
    tools = mcp_app.make_tools(w.path)
    out, off, pages = [], 0, 0
    while off is not None:
        r = tools["get_diff_handoff"](PAIR, off)
        assert len(json.dumps(r)) <= mcp_app._RESPONSE_BYTE_BUDGET, (off, len(json.dumps(r)))
        assert r["block_truncated"] is False
        out.append(r["text"])
        off = r["next_offset"]
        pages += 1
    assert pages >= 3
    assert "".join(out) == rr.handoff_document(
        w.atlas, PAIR, stamp=_stamp(), file_staleness=_local_staleness(w)
    )


def test_a_block_over_the_cap_is_cut_where_it_is_rendered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A block longer than the cap is cut by the renderer, with a note naming the call that reads
    the rest — the same cut in the CLI file and the MCP pages, so they stay one text; its
    placeholders and status are kept whole.

    MUTATION (verified RED): leave the cut to the pager -> the pages differ from the file -> RED."""
    from click.testing import CliRunner

    from treasure_map.cli import review_cli

    w = _wide_findings_world(tmp_path, monkeypatch, 2)
    for f in rr.handoff_findings(w.atlas, PAIR):
        _judge(w.atlas, DX, f["anchor_ref"], "x" * 6_000)
    monkeypatch.setattr(rr, "HANDOFF_BLOCK_CAP", 2_500)
    monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", 5_000)
    out_file = tmp_path / "handoff.md"
    res = CliRunner().invoke(
        review_cli.review,
        ["report", PAIR, "--handoff", "-o", str(out_file), "--atlas", str(w.path)],
    )
    assert res.exit_code == 0, res.output
    cli_text = out_file.read_text(encoding="utf-8")
    assert _pages_of(mcp_app.make_tools(w.path)) == cli_text
    assert cli_text.count("- [block cut to fit a page: ") == 2
    assert cli_text.count(f"- status: {rr.HANDOFF_STATUS}") == 2
    assert cli_text.count(rr.HANDOFF_BOUNDARY) == 5  # the header's, and two per block
    assert 'read them with get_diff_patch_view(diff_id="runA::runB::libx", entry_id=' in cli_text


def test_an_offset_past_the_blocks_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ An offset past the last block is an error naming the block count — never a silent empty
    page that reads as the end.

    MUTATION (verified RED): serve the empty page again -> RED."""
    w = _wide_findings_world(tmp_path, monkeypatch, 1)
    r = _server_call_on(w.path, "get_diff_handoff", {"run_pair": PAIR, "offset": 2})
    assert r.get("error") == "offset past total_blocks 2" and "text" not in r, r
    assert "error" not in _server_call_on(
        w.path, "get_diff_handoff", {"run_pair": PAIR, "offset": 1}
    )


def test_an_over_long_run_pair_is_echoed_cut(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A run pair naming no two runs is echoed back cut, not whole: a 60,000-character pair does
    not become a 60 KB error — on get_diff_handoff and get_file_diff, which share the check.

    MUTATION (verified RED): echo the pair whole -> RED."""
    w = _wide_findings_world(tmp_path, monkeypatch, 1)
    pair = "x" * 60_000
    for tool in ("get_diff_handoff", "get_file_diff"):
        r = _server_call_on(w.path, tool, {"run_pair": pair})
        assert "(60000 chars)" in r["error"] and len(json.dumps(r)) < 10_000, (
            tool,
            len(json.dumps(r)),
        )


# ── the template is neutral where tmap renders it, not only in its label list ────────────────────


def _template_text(doc: str) -> str:
    """``doc`` with what tmap embeds rather than writes taken out: code blocks (firmware text), the
    boundary, the recorded judgment's values, backticked anchors and refs."""
    out: list[str] = []
    fence: str | None = None
    for line in doc.replace(rr.HANDOFF_BOUNDARY, "").splitlines():
        if re.fullmatch(r"`{3,}", line):
            if fence is None:
                fence = line
            elif len(line) >= len(fence):
                fence = None
            continue
        if fence is not None:
            continue
        for label in ("recorded verdict", "recorded change kind", "recorded rationale"):
            if line.startswith(f"- {label}: "):
                line = f"- {label}:"
        line = re.sub(r"`[^`]*`", "", line)
        line = re.sub(r"[ab]_ref \S+", "", line)
        out.append(line)
    return "\n".join(out)


def test_the_rendered_blocks_carry_no_verdict_word(full: sst.World) -> None:
    """★ Acceptance 7 with teeth: each subject shape rendered for real (a function pair, a single-
    side function, a file, a whole binary), its embedded values taken out, says no verdict word —
    and the whole document passes the public-surface scan. B2-m5: the branches a plain fixture does
    not reach are rendered too — a finding whose basis MOVED, a file whose hunk is held back
    (sensitive), and a block cut to its cap.

    MUTATION (verified RED): write "single side — safe, no exploitable delta" into the single-side
    change cell -> RED; render the sink class label as "vulnerable sink class" -> RED; write
    "possibly exploitable" into the MOVED line, "safe to skip" into the held-back file line, or
    "(safe to skip)" into the cut note -> RED (``1 failed``) each."""
    from tests.unit.test_public_surface_wording import _flag

    full.atlas.execute(
        "INSERT INTO function_presence (diff_id, side, addr, presence_state) "
        "VALUES (?, 'b', '00006000', 'unmatched_analysis_complete')",
        (sst.DIFF,),
    )
    full.inst("runB", sst._ref("runB", "00006000", "copy", "0x10"), "copy", "strcpy", sst.SRC)
    full.fn("b", "00006000", ["strcpy"], name="fnew")
    full.commit()
    _judge(full.atlas, sst.DIFF, _pair_ref())
    _judge(full.atlas, sst.DIFF, dr.presence_anchor("runA", "runB", "libx", "b", "00006000"))
    stamp, staleness = rr.local_handoff_context(full.atlas)
    docs = [rr.handoff_document(full.atlas, PAIR, stamp=stamp, file_staleness=staleness)]
    binary = {
        "anchor_ref": f"{PAIR}#binary_presence#b_only:bin/tool",
        "subject_kind": "binary_presence",
        "verdict": "changed_real",
        "review_state": "concluded",
    }
    docs.append(rr.handoff_chunk(full.atlas, PAIR, binary, stamp=stamp))
    # B2-m5: a moved basis, and a block cut to its cap
    (pair,) = [
        f
        for f in rr.handoff_findings(full.atlas, PAIR, file_staleness=staleness)
        if f["anchor_ref"] == _pair_ref()
    ]
    moved = {
        **pair,
        "review_state": "needs_recheck",
        "basis_state": "unchanged",
        "source_stale_reason": "diff_logic_changed",
    }
    docs.append(rr.handoff_chunk(full.atlas, PAIR, moved, stamp=stamp))
    docs.append(rr.handoff_chunk(full.atlas, PAIR, pair, stamp=stamp, cap=1_000))
    fw = _files_world(full)
    fw.file("a", "etc/rc", "shell_script", "echo old\n")
    fw.file("b", "etc/rc", "shell_script", "echo new\n")
    fw.file("a", "etc/app.conf", "config_file", "pass=old-synthetic\n")
    conf = fw.file("b", "etc/app.conf", "config_file", f"pass={SECRET_VALUE}\n")
    fw.row(
        "b", "config_entries", conf, section=None, key="pass", value=SECRET_VALUE, is_sensitive=1
    )
    conn = fw.atlas()
    try:
        _judge(conn, None, f"{PAIR}#non_binary#etc/rc")
        _judge(conn, None, f"{PAIR}#non_binary#etc/app.conf")
        stamp, staleness = rr.local_handoff_context(conn)
        docs.append(rr.handoff_document(conn, PAIR, stamp=stamp, file_staleness=staleness))
    finally:
        conn.close()
    doc = "\n".join(docs)
    assert all(
        s in doc for s in ("function_pair", "function_presence", "non_binary", "binary_presence")
    )
    for branch in (
        "- basis: MOVED since the judgment",
        "hunk held back (sensitive: ",
        "- [block cut",
    ):
        assert branch in doc, branch  # each branch really rendered
    # a stored value (an identifier with an underscore) is a value, not prose
    words = {w.lower() for w in re.findall(r"[A-Za-z_]+", _template_text(doc)) if "_" not in w}
    assert not (words & _JUDGEMENT_WORDS), words & _JUDGEMENT_WORDS
    assert _flag(doc) == []


def _template_strings() -> list[tuple[int, str]]:
    """Every string literal the hand-off part of review_report renders from — each constant and
    each constant part of an f-string, docstrings left out — with its line number."""
    import ast
    import inspect

    source = inspect.getsource(rr)
    start = source.index("# ── the findings handoff (Design B)")
    first_line = source[:start].count("\n") + 1
    tree = ast.parse(source)
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.ClassDef | ast.Module)
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
    }
    return [
        (node.lineno, node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.lineno >= first_line
        and id(node) not in docstrings
    ]


def test_every_handoff_template_string_carries_no_verdict_word() -> None:
    """★ B2-m5: every string the hand-off renders from — every branch of the four entry forms,
    each unavailable reason, the MOVED line, the held-back and cut notes — carries no verdict word,
    whether or not a fixture reaches its branch. (The boundary is imported; values such as a
    sink class or a stored state are not template text.)

    MUTATION (verified RED, ``1 failed``): write "possibly exploitable" into the MOVED line, "safe
    to skip" into the held-back file line, or "(safe to skip)" into the cut note -> RED each."""
    strings = _template_strings()
    assert any("MOVED since the judgment" in x for _n, x in strings)  # the scan reaches them
    assert any("function not resolved" in x for _n, x in strings)
    hits = []
    for lineno, text in strings:
        words = {w.lower() for w in re.findall(r"[A-Za-z_]+", text) if "_" not in w}
        if words & _JUDGEMENT_WORDS:
            hits.append((lineno, text, sorted(words & _JUDGEMENT_WORDS)))
    assert hits == []


# ── the driver's command line: when the hand-off runs, and with which preset ────────────────────


def _patch_run(
    monkeypatch: pytest.MonkeyPatch, stopped: str, failed: list[dict[str, Any]] | None = None
) -> dict[str, list[Any]]:
    """review run with every launch faked: the probe passes, the drive ends ``stopped`` with the
    ``failed`` units."""
    from treasure_map.cli import review_cli
    from treasure_map.lib import review_driver as rd
    from treasure_map.lib.query import review_units as ru

    calls: dict[str, list[Any]] = {"drive": [], "handoff": [], "probe": []}

    class _Conn:
        def close(self) -> None:
            pass

    monkeypatch.setattr(review_cli, "_open", lambda atlas, pair: (_Conn(), "runA", "runB", "a.db"))
    monkeypatch.setattr(ru, "pair_staleness", lambda *a, **k: {"source_stale": False})

    def probe(*a: Any, **k: Any) -> rd.ProbeResult:
        calls["probe"].append(a)
        return rd.ProbeResult(True, True, True, "faked")

    def drive(*a: Any, **k: Any) -> rd.DriveResult:
        calls["drive"].append(a)
        return rd.DriveResult(
            units_tried=1, units_done=1, stopped=stopped, failed=list(failed or [])
        )

    def run_handoff(*a: Any, **k: Any) -> dict[str, Any]:
        calls["handoff"].append(a)
        return {"ok": True, "out_file": "h.md", "bytes": 1, "findings": 1, "nothing_written": 0}

    monkeypatch.setattr(rd, "probe", probe)
    monkeypatch.setattr(rd, "drive", drive)
    monkeypatch.setattr(rd, "run_handoff", run_handoff)
    return calls


def test_the_handoff_is_skipped_while_the_review_is_not_done(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ B-5: the hand-off launch runs only once no unit is left; a review stopped at a limit says
    the hand-off was skipped and launches nothing for it.

    MUTATION (verified RED): launch the hand-off whatever the drive's end -> RED."""
    from click.testing import CliRunner

    from treasure_map.cli import review_cli

    calls = _patch_run(monkeypatch, "max_units 1 reached")
    out = tmp_path / "h.md"
    res = CliRunner().invoke(
        review_cli.review, ["run", PAIR, "--agent", "claude-code", "--handoff", str(out)]
    )
    assert "hand-off skipped" in res.output, res.output
    assert calls["handoff"] == [] and len(calls["drive"]) == 1
    calls = _patch_run(monkeypatch, "no unit left")
    res = CliRunner().invoke(
        review_cli.review, ["run", PAIR, "--agent", "claude-code", "--handoff", str(out)]
    )
    assert len(calls["handoff"]) == 1, res.output


def test_handoff_with_an_experimental_preset_is_refused_before_driving(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ B-5 / acceptance 15: --handoff with an experimental preset is a usage error, raised before
    the probe or any unit is launched.

    MUTATION (verified RED): drop the command line's preset check -> the drive runs -> RED."""
    from click.testing import CliRunner

    from treasure_map.cli import review_cli

    calls = _patch_run(monkeypatch, "no unit left")
    res = CliRunner().invoke(
        review_cli.review, ["run", PAIR, "--agent", "codex", "--handoff", str(tmp_path / "h.md")]
    )
    assert res.exit_code == 2 and "claude-code preset" in res.output, res.output
    assert calls == {"drive": [], "handoff": [], "probe": []}


# ── the block's own lines: the basis kept, fences closed, embedded text contained ──────────────


def _outside_fences(text: str) -> tuple[list[str], bool]:
    """The lines of ``text`` a markdown reader takes as outside any code fence (a fence opens with
    up to three spaces and three or more backticks, and closes with as many or more), and whether
    the text ends inside one."""
    out: list[str] = []
    fence: str | None = None
    for line in text.splitlines():
        m = re.fullmatch(r" {0,3}(`{3,})([^`]*)", line)
        if fence is None:
            if m:
                fence = m.group(1)
                continue
            out.append(line)
        elif m and len(m.group(1)) >= len(fence) and not m.group(2).strip():
            fence = None
    return out, fence is not None


def test_a_long_rationale_never_cuts_the_basis_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ B2-m1: the basis line comes before the recorded rationale, so a rationale long enough to
    cut the block — one long line, or many — never cuts the MOVED line with it.

    MUTATION (verified RED, ``1 failed``): put the basis line back after the rationale -> the cut
    takes it -> RED."""
    w = _wide_findings_world(tmp_path, monkeypatch, 2)
    a1, a2 = sorted(f["anchor_ref"] for f in rr.handoff_findings(w.atlas, PAIR))
    _judge(w.atlas, DX, a1, "z" * 31_000)
    _judge(w.atlas, DX, a2, "a line of the rationale\n" * 2_000)
    w.stale[DX] = {"source_stale": True, "source_stale_reason": "diff_logic_changed"}
    for finding in rr.handoff_findings(w.atlas, PAIR):
        block = rr.handoff_chunk(w.atlas, PAIR, finding, stamp=_stamp())
        lines, _open = _outside_fences(block)
        assert any(x.startswith("- [block cut to fit a page: ") for x in lines)  # really cut
        assert any(
            x.startswith("- basis: MOVED since the judgment (diff_logic_changed)") for x in lines
        ), lines


def test_a_cut_inside_a_fence_closes_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """★ B2-m6: a block cut where a fence is open (here inside a long rationale) closes the fence
    before the cut note, so the note, the placeholders and the status read as the block's own
    lines, not as code.

    MUTATION (verified RED, ``1 failed``): drop the closing of the open fence -> the cut note and
    the status sit inside the code block -> RED."""
    w = _wide_findings_world(tmp_path, monkeypatch, 1)
    (anchor,) = [f["anchor_ref"] for f in rr.handoff_findings(w.atlas, PAIR)]
    _judge(w.atlas, DX, anchor, "a line of the rationale\n" * 400)
    (finding,) = rr.handoff_findings(w.atlas, PAIR)
    block = rr.handoff_chunk(w.atlas, PAIR, finding, stamp=_stamp(), cap=3_000)
    lines, ends_open = _outside_fences(block)
    assert not ends_open
    all_lines = block.splitlines()
    cut = next(i for i, x in enumerate(all_lines) if x.startswith("- [block cut"))
    assert all_lines[cut - 1] == "```" and "a line of the rationale" in all_lines[cut - 2]
    assert all_lines[cut] in lines and f"- status: {rr.HANDOFF_STATUS}" in lines


def test_embedded_text_cannot_forge_the_blocks_own_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ B2-m8: a rationale or an agent's text holding a "- status: …" or "- basis: …" line, a
    heading, or an unpaired code fence stays inside its own fence: every block's only status line
    outside a fence is tmap's, its basis line is tmap's, and the document never ends inside a code
    block — in the skeleton and in the driver's document alike.

    MUTATION (verified RED, ``1 failed`` each): render the rationale as a plain cell again; put the
    agent's text under the placeholder unfenced again."""
    w = _wide_findings_world(tmp_path, monkeypatch, 2)
    a1, a2 = sorted(f["anchor_ref"] for f in rr.handoff_findings(w.atlas, PAIR))
    forged = "line one\n- basis: MOVED by hand\n- status: confirmed by a person\n````\n## `x`"
    _judge(w.atlas, DX, a1, forged)
    stamp, staleness = rr.local_handoff_context(w.atlas)

    def check(doc: str, n_findings: int) -> None:
        lines, ends_open = _outside_fences(doc)
        assert not ends_open
        assert [x for x in lines if x.startswith("- status:")] == [
            f"- status: {rr.HANDOFF_STATUS}"
        ] * n_findings, lines
        assert [x for x in lines if x.startswith("- basis:")] == ["- basis: current"] * n_findings
        assert [x for x in lines if x.startswith("## ")] == [f"## `{a1}`", f"## `{a2}`"]

    skeleton = rr.handoff_document(w.atlas, PAIR, stamp=stamp, file_staleness=staleness)
    assert "- status: confirmed by a person" in skeleton  # the text is there, contained
    check(skeleton, 2)
    texts = {a1: {"hypotheses": "H\n```", "device_checks": "D\n- status: verified\n## `y`"}}
    out_file = tmp_path / "handoff.md"
    res = _run_handoff(w, out_file, _claude_result(json.dumps(texts)))
    assert res["ok"] is True, res
    written = out_file.read_text(encoding="utf-8")
    assert "- status: verified" in written
    check(written, 2)


def test_a_refused_handoff_keeps_the_agents_message_beside_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ B2-m9: when the driver refuses to compose the hand-off from the agent's final message (it
    names an anchor the hand-off does not hold, or is not the JSON asked for), the hand-off file is
    still not written, and the message is kept as it was printed in ``<out>.agent-result.txt``,
    headed as not a hand-off document — a long analysis is not lost to one wrong anchor.

    MUTATION (verified RED, ``1 failed``): keep nothing (skip the write in ``_refused``) -> RED."""
    from treasure_map.lib import review_driver as rd

    w = _wide_findings_world(tmp_path, monkeypatch, 1)
    wrong = json.dumps({f"{PAIR}#function_pair#libx::0badc0de::0badc0de": {"hypotheses": "h"}})
    for name, result in (("anchor", wrong), ("prose", "here is my analysis, not JSON")):
        out_file = tmp_path / f"{name}.md"
        res = _run_handoff(w, out_file, _claude_result(result))
        assert res["ok"] is False and not out_file.exists(), res
        kept = rd.agent_result_path(out_file)
        assert kept == tmp_path / f"{name}.md.agent-result.txt"
        assert kept.is_file(), res
        assert res.get("agent_result_file") == str(kept) and str(kept) in res["error"]
        text = kept.read_text(encoding="utf-8")
        assert text.startswith("This is not a hand-off document")
        assert text.endswith("\n\n" + result)


def test_the_last_page_keeps_within_the_budget_at_its_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ B2-m2: a page is measured with next_offset at its widest — null (four bytes) is wider than
    a block count under 1000 — so the last page, whose next_offset becomes null, never goes over
    the budget, at any budget around the one that just fits; the pages still concatenate to the
    document.

    MUTATION (verified RED, ``1 failed``): measure with ``"next_offset": total`` again -> the last
    page is 3 bytes over -> RED."""
    w = _wide_findings_world(tmp_path, monkeypatch, 5)
    for i, f in enumerate(rr.handoff_findings(w.atlas, PAIR), 1):
        _judge(w.atlas, DX, f["anchor_ref"], "r" * (100 * i))
    tools = mcp_app.make_tools(w.path)
    whole = tools["get_diff_handoff"](PAIR, 0)
    assert whole["next_offset"] is None and whole["total_blocks"] < 10
    fits = len(json.dumps(dict(whole, next_offset=whole["total_blocks"])))
    document = rr.handoff_document(
        w.atlas, PAIR, stamp=_stamp(), file_staleness=_local_staleness(w)
    )
    for budget in range(fits - 4, fits + 5):
        monkeypatch.setattr(mcp_app, "_RESPONSE_BYTE_BUDGET", budget)
        out, off = [], 0
        while off is not None:
            r = tools["get_diff_handoff"](PAIR, off)
            assert len(json.dumps(r)) <= budget, (budget, off, len(json.dumps(r)))
            out.append(r["text"])
            off = r["next_offset"]
        assert "".join(out) == document


def test_a_long_file_hunk_is_cut_at_its_cap_and_names_the_page_that_follows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ B2-m3: a file whose line difference is over the block's file-hunk cap shows the pieces
    that fit (whole pieces, the next one would pass the cap) and names the get_file_diff call that
    reads on from the first piece not shown — whose first piece is that piece.

    MUTATION (verified RED, ``1 failed`` each): name hunk_offset one past the pieces shown; lift
    the cap -> no continuation line -> RED."""
    _servable(monkeypatch)
    fw = FW(tmp_path)
    fw.file("a", "etc/big", "shell_script", "echo old\n")
    body = "".join(f"echo line-{i:04d} {'p' * 30}\n" for i in range(400))
    fw.file("b", "etc/big", "shell_script", body)
    anchor = f"{PAIR}#non_binary#etc/big"
    tools = fw.tools()
    conn = fw.atlas()
    try:
        _judge(conn, None, anchor)
        block = _block(conn, anchor)
    finally:
        conn.close()
    hunk = tools["get_file_diff"](PAIR, path="etc/big")["entry"]["hunk"]
    pieces = hunk["lines"]
    assert hunk["next_hunk_offset"] is None  # the tool's first page holds every piece
    lines = block.splitlines()
    start = lines.index("- file hunk (tmap facts):") + 2
    end = lines.index("```", start)
    shown = lines[start:end]
    n = len(shown)
    assert 0 < n < len(pieces) and shown == pieces[:n]
    size = sum(len(json.dumps(x + "\n")) - 2 for x in shown)
    assert size <= rr.HANDOFF_FILE_HUNK_BYTES < size + len(json.dumps(pieces[n] + "\n")) - 2
    more = (
        f"  - hunk shown {n} of {hunk['total_pieces']} piece(s) — rest: "
        f'get_file_diff(run_pair="{PAIR}", path="etc/big", hunk_offset={n})'
    )
    assert more in lines, [x for x in lines if "hunk shown" in x]
    rest = tools["get_file_diff"](PAIR, path="etc/big", hunk_offset=n)["entry"]["hunk"]
    assert rest["lines"][0] == pieces[n]


def test_an_undetermined_pair_with_no_proposed_hunk_states_the_proposed_reading(
    full: sst.World,
) -> None:
    """★ B2-m4: an undetermined pair whose proposed pairing gives no pseudocode delta says so with
    the state the view's proposed_pair_reading gives, under the proposed-pairing label.

    MUTATION (verified RED, ``1 failed``): leave the proposed state out -> RED."""
    full.pair("00007000", "00008000", 0.5, 0.6)
    full.fn("a", "00007000", ["strcpy"], name="ua")
    full.fn("b", "00008000", ["strcpy"], name="ub")
    full.commit()
    anchor = _pair_ref("00007000", "00008000")
    _judge(full.atlas, sst.DIFF, anchor)
    block = _block(full.atlas, anchor)
    view = mcp_app.make_tools(full.path)["get_diff_patch_view"](sst.DIFF, entry_id=anchor)
    (entry,) = view["entries"]
    proposed = entry["proposed_pair_reading"]
    assert "pseudocode_delta" not in proposed and proposed["state"]
    label = "change (tmap facts, proposed pairing — alignment undetermined)"
    assert _cell_value(block, label) == (
        f"unavailable (no pseudocode delta; the proposed pairing reads {proposed['state']})"
    )


def test_the_handoff_is_skipped_when_a_unit_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ B2-m7: a drive that ran out of units but had a unit fail is not a finished review — the
    hand-off is skipped and nothing launched for it.

    MUTATION (verified RED, ``1 failed``): decide on ``stopped`` alone -> the hand-off launches ->
    RED."""
    from click.testing import CliRunner

    from treasure_map.cli import review_cli

    failed = [{"unit_id": "u-1", "kind": "function_pair", "written": 0, "members": 1}]
    calls = _patch_run(monkeypatch, "no unit left", failed)
    res = CliRunner().invoke(
        review_cli.review,
        ["run", PAIR, "--agent", "claude-code", "--handoff", str(tmp_path / "h.md")],
    )
    assert "hand-off skipped" in res.output, res.output
    assert calls["handoff"] == [] and len(calls["drive"]) == 1
    assert res.exit_code == 3  # a failed unit still fails the run
