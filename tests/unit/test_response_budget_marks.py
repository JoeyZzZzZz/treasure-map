# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""No tool answer is over the response budget silently.

The page fitters bound the tools that page, but a tool that returns one structured record (an
explanation, a provenance record set, an import table) never passed through them, so an answer of
any size went out unmarked. Two parts:

- one fallback on the MCP call path marks EVERY tool's answer larger than the budget with
  ``over_budget: true`` — measured as the fitters measure it (``json.dumps``' default form, one
  copy, against ``_RESPONSE_BYTE_BUDGET``);
- explain_candidate, whose one growing field is the per-sink summary, withholds summary entries
  from the end back (never the candidate's own callsite) and says which, and how to read them.
"""

from __future__ import annotations

import asyncio
import functools
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_sink_provenance import _addr_ref, _seed
from treasure_map import mcp_app
from treasure_map.mcp_app import _RESPONSE_BYTE_BUDGET

_FUNC = 0x400000
_OWN = 190  # the candidate's own sink: near the end, where withholding starts


def _call(server: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
    """One call through the server's own call path, its answer as the client reads it."""
    res = asyncio.run(server.call_tool(name, args))
    blocks = res[0] if isinstance(res, tuple) else res
    payload: dict[str, Any] = json.loads(blocks[0].text)
    return payload


def _sized(size: int, **extra: Any) -> dict[str, Any]:
    """An answer of exactly ``size`` bytes as the budget measures it."""
    out = {**extra, "notice": ""}
    out["notice"] = "x" * (size - len(json.dumps(out)))
    assert len(json.dumps(out)) == size
    return out


def _server_answering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: Callable[[], dict[str, Any]]
) -> Any:
    """The real server (real wrapper, real FastMCP), with legal_notice answering ``answer()``."""
    real = mcp_app.make_tools

    def tools(*a: Any, **k: Any) -> dict[str, Callable[..., Any]]:
        out = real(*a, **k)

        @functools.wraps(out["legal_notice"])
        def legal_notice() -> dict[str, Any]:
            return answer()

        out["legal_notice"] = legal_notice
        return out

    monkeypatch.setattr(mcp_app, "make_tools", tools)
    return mcp_app.build_server(tmp_path / "atlas.db")


# ── the fallback: every answer over the budget is marked, on the server path ─────────────────


def test_an_answer_one_byte_over_the_budget_is_marked_and_one_under_is_not(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Through build_server().call_tool: an answer of _RESPONSE_BYTE_BUDGET + 1 bytes carries
    over_budget: true; one of exactly the budget, or one byte under it, carries no such key.

    MUTATION (verified RED, 1 failed): drop the _mark_over_budget call from the wrapper -> RED.
    MUTATION (verified RED, 1 failed): measure against _RESPONSE_BYTE_BUDGET / 2.5 -> the answer
    one byte under is marked -> RED.
    MUTATION (verified RED, 1 failed): ``>=`` for ``>`` -> the answer at the budget is marked."""
    size = [0]
    server = _server_answering(tmp_path, monkeypatch, lambda: _sized(size[0]))
    size[0] = _RESPONSE_BYTE_BUDGET + 1
    assert _call(server, "legal_notice", {}).get("over_budget") is True
    for within in (_RESPONSE_BYTE_BUDGET, _RESPONSE_BYTE_BUDGET - 1):
        size[0] = within
        out = _call(server, "legal_notice", {})
        assert "over_budget" not in out, within
        assert len(json.dumps(out)) == within  # the answer is exactly what the tool gave


def test_an_answer_that_says_so_already_is_left_as_it_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tool's own over_budget stays (one key, true); an over-budget error answer is marked
    too — the fallback marks, it never cuts or rewrites.

    MUTATION (verified RED): drop the _mark_over_budget call from the wrapper -> RED."""
    answers = iter(
        [
            _sized(_RESPONSE_BYTE_BUDGET + 500, over_budget=True),
            _sized(_RESPONSE_BYTE_BUDGET + 500, error="too much"),
        ]
    )
    server = _server_answering(tmp_path, monkeypatch, lambda: next(answers))
    own = _call(server, "legal_notice", {})
    assert own.get("over_budget") is True and list(own).count("over_budget") == 1
    assert len(own["notice"]) > _RESPONSE_BYTE_BUDGET
    err = _call(server, "legal_notice", {})
    assert err.get("over_budget") is True and err.get("error") == "too much"


# ── explain_candidate: the sink summary is withheld from the end, never the own callsite ─────


def _wide_records(n: int) -> list[dict[str, Any]]:
    """``n`` sink records of one function, each with a dominating writer and its format string
    inlined in the summary (the field that makes a real many-sink summary large)."""
    out = []
    for i in range(n):
        writer = f"snprintf@{hex(_FUNC + 0x10 * i - 4)}"
        out.append(
            {
                "sink_idx": i,
                "sink": "system",
                "sink_addr": hex(_FUNC + 0x10 * i),
                "arg_idx": 0,
                "provenance": {
                    "kind": "stack_buf",
                    "stack_key": f"frame[{i}]",
                    "writer_count": 1,
                    "nearest_dominating_writer": writer,
                    "writers": [
                        {
                            "writer": writer,
                            "dominates_sink": True,
                            "fmt": f"/usr/sbin/tool --opt {i} " + "c" * 300,
                            "varargs": [],
                        }
                    ],
                },
            }
        )
    return out


def _many_sinks(tmp_path: Path, n: int = 200) -> str:
    ref = _addr_ref(_FUNC, _FUNC + 0x10 * _OWN)
    _seed(tmp_path, ref=ref, provenance=_wide_records(n))
    return ref


def test_a_many_sink_explanation_fits_by_withholding_from_the_end(tmp_path: Path) -> None:
    """A function with 200 sink records: the explanation is within the budget and unmarked; the
    summary keeps a prefix plus the candidate's own callsite (flagged); every other entry is
    named, in order, under sink_arg_provenance_summary_withheld — none is lost — and each is read
    in full by the call it names.

    MUTATION (verified RED): return data without _fit_sink_summary -> 138,023 bytes -> RED.
    MUTATION (verified RED): withhold the own callsite like any other entry -> RED.
    MUTATION (verified RED): withhold from the front (the summary reversed first) -> RED."""
    ref = _many_sinks(tmp_path)
    tools = mcp_app.make_tools(tmp_path / "atlas.db")
    out = tools["explain_candidate"](evidence_ref=ref)
    assert out.get("found") is True
    size = len(json.dumps(out))
    assert size <= _RESPONSE_BYTE_BUDGET and "over_budget" not in out
    assert size > _RESPONSE_BYTE_BUDGET - 1_000  # only as much withheld as the budget needs
    summary = out.get("sink_arg_provenance_summary") or []
    kept = [e["sink_idx"] for e in summary]
    withheld = out.get("sink_arg_provenance_summary_withheld") or {}
    held = withheld.get("sink_idx") or []
    assert withheld.get("count") == len(held) > 0
    assert sorted(kept + held) == list(range(200))
    assert kept == [*range(len(kept) - 1), _OWN]  # a prefix, then the own callsite
    assert held == sorted(held) and min(held) == len(kept) - 1
    own = [e for e in summary if e.get("is_candidate_callsite") is True]
    assert [e["sink_idx"] for e in own] == [_OWN]
    read_with = withheld.get("read_with") or ""
    assert read_with.startswith("get_sink_provenance(evidence_ref, sink_idx=")
    full = tools["get_sink_provenance"](evidence_ref=ref, sink_idx=held[-1])
    assert full["record"]["sink_idx"] == held[-1]


def test_a_small_explanation_is_given_whole_with_no_withheld_key(tmp_path: Path) -> None:
    """Twenty sinks fit: every entry is there and the withheld key is absent (not an empty
    one) — an answer within the budget is exactly what it was."""
    ref = _addr_ref(_FUNC, _FUNC + 0x10 * 5)
    _seed(tmp_path, ref=ref, provenance=_wide_records(20))
    out = mcp_app.make_tools(tmp_path / "atlas.db")["explain_candidate"](evidence_ref=ref)
    assert len(json.dumps(out)) <= _RESPONSE_BYTE_BUDGET
    assert "sink_arg_provenance_summary_withheld" not in out and "over_budget" not in out
    assert [e["sink_idx"] for e in out["sink_arg_provenance_summary"]] == list(range(20))


def test_an_explanation_over_the_budget_with_nothing_left_to_withhold_says_so() -> None:
    """Only the own callsite left and still over: it is kept, the withheld entries are named,
    and the answer says it is over (never an empty summary that reads as no sinks).

    MUTATION (verified RED): withhold the own callsite like any other entry -> RED."""
    own = {"sink_idx": 3, "is_candidate_callsite": True, "pad": "x" * 60_000}
    other = {"sink_idx": 4, "is_candidate_callsite": False}
    data = {"found": True, "sink_arg_provenance_summary": (own, other)}
    out = mcp_app._fit_sink_summary(data)
    assert out["sink_arg_provenance_summary"] == [own]
    assert out.get("sink_arg_provenance_summary_withheld", {}).get("sink_idx") == [4]
    assert out.get("over_budget") is True


def test_the_server_marks_an_unpaged_tool_and_fits_the_explanation(tmp_path: Path) -> None:
    """End to end on the real server, two real tools on the same 200-sink function:
    get_sink_provenance without sink_idx (it does not page) answers over the budget and is
    marked by the fallback; explain_candidate answers within it, its summary cut and named.

    MUTATION (verified RED): drop the _mark_over_budget call from the wrapper -> RED.
    MUTATION (verified RED): return data without _fit_sink_summary -> explanation marked -> RED."""
    ref = _many_sinks(tmp_path)
    server = mcp_app.build_server(tmp_path / "atlas.db")
    prov = _call(server, "get_sink_provenance", {"evidence_ref": ref})
    assert len(prov.get("records") or []) == 200
    assert prov.get("over_budget") is True
    ex = _call(server, "explain_candidate", {"evidence_ref": ref})
    assert "over_budget" not in ex
    assert (ex.get("sink_arg_provenance_summary_withheld") or {}).get("count", 0) > 0
