# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the nvram key-flow query (gap② phase 2): the three-tier honesty contract over
the atlas nvram_key_flow table — exact (constant), template (parametric, flagged), and unresolved
(never connected to a concrete key, but exposed via completeness)."""

from __future__ import annotations

from pathlib import Path

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import NvramDefaultRow, NvramFlowRow
from treasure_map.lib.atlas.writer import add_nvram_default_rows, add_nvram_flow_rows
from treasure_map.lib.query import get_nvram_key_flow
from treasure_map.lib.query.nvram import (
    _template_matches,
    _template_to_regex,
    template_has_anchor,
)


def _seed(
    tmp_path: Path,
    rows: list[NvramFlowRow],
    defaults: list[NvramDefaultRow] | None = None,
) -> Path:
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    try:
        add_nvram_flow_rows(conn, rows)
        if defaults:
            add_nvram_default_rows(conn, defaults)
    finally:
        conn.close()
    return atlas


def _default(
    key: str | None,
    *,
    default_value: str | None = None,
    flags: int | None = None,
    member_index: int = 0,
    binary: str = "libshared.so",
    run: str = "run_a",
) -> NvramDefaultRow:
    return NvramDefaultRow(
        source_run_id=run,
        key=key,
        default_value=default_value,
        flags=flags,
        member_index=member_index,
        binary=binary,
    )


def _flow(
    key: str | None,
    key_kind: str,
    binary: str,
    func: str,
    op: str,
    *,
    value_source: str | None = None,
    api: str = "nvram_set",
    run: str = "run_a",
    via_wrapper: str | None = None,
) -> NvramFlowRow:
    return NvramFlowRow(
        source_run_id=run,
        key=key,
        key_kind=key_kind,
        binary=binary,
        func=func,
        op=op,
        value_source=value_source,
        api=api,
        via_wrapper=via_wrapper,
    )


# ── exact: constant key connects writers and readers across binaries ────────────────


def test_exact_cross_binary_writers_and_readers(tmp_path: Path) -> None:
    atlas = _seed(
        tmp_path,
        [
            _flow(
                "sw_mode",
                "constant",
                "rc",
                "set_mode",
                "write",
                value_source='{"kind": "param", "name": "param_2"}',
                api="nvram_set",
            ),
            _flow("sw_mode", "constant", "httpd", "read_mode", "read", api="nvram_get"),
        ],
    )
    conn = open_atlas(atlas)
    try:
        res = get_nvram_key_flow(conn, "sw_mode")
    finally:
        conn.close()

    assert res["found"] is True
    assert res["match"] == "exact"
    # both sides present + no unresolved -> no specific blind spot, but NEVER a bare "complete":
    # wrapper-indirect access is structurally unresolved, so the graph is 'direct_only'.
    assert res["completeness"] == "direct_only"
    assert res["notes"] == []
    assert "DIRECT nvram_get/set" in res["coverage"]  # standing boundary always stated
    assert [w["binary"] for w in res["writers"]] == ["rc"]
    assert [r["binary"] for r in res["readers"]] == ["httpd"]
    # write-side value source is parsed and surfaced (a controllability signal)
    assert res["writers"][0]["value_source"] == {"kind": "param", "name": "param_2"}
    assert res["template_matches"] == []


# ── template: a parametric template is a POSSIBLE match, flagged separately ──────────


def test_parametric_template_match_is_flagged_separately(tmp_path: Path) -> None:
    atlas = _seed(
        tmp_path,
        [_flow("wl%d_ssid", "parametric", "rc", "set_wl", "write")],
    )
    conn = open_atlas(atlas)
    try:
        hit = get_nvram_key_flow(conn, "wl0_ssid")
        miss = get_nvram_key_flow(conn, "lan_ifname")
    finally:
        conn.close()

    # a concrete key satisfying the template surfaces ONLY under template_matches, never as exact
    assert hit["writers"] == [] and hit["readers"] == []
    assert hit["found"] is True
    assert hit["match"] == "template"  # top-level match reflects: only template hits, no exact
    assert len(hit["template_matches"]) == 1
    tm = hit["template_matches"][0]
    assert tm["template"] == "wl%d_ssid" and tm["match"] == "template" and tm["binary"] == "rc"
    # a key that does NOT satisfy the template matches nothing
    assert miss["template_matches"] == []
    assert miss["found"] is False
    assert miss["match"] == "none"


def test_anchorless_template_never_false_matches(tmp_path: Path) -> None:
    # 缺口 (probe): an over-broad %s%s "template" regex-matches ANY key. It must NOT surface as a
    # possible match for a random key — the query rejects anchorless templates (defense-in-depth,
    # even if a stale row stored one as parametric).
    atlas = _seed(
        tmp_path,
        [
            _flow("%s%s", "parametric", "rc", "f1", "write"),
            _flow("%s", "parametric", "rc", "f2", "write"),
        ],
    )
    conn = open_atlas(atlas)
    try:
        res = get_nvram_key_flow(conn, "foobar123")
    finally:
        conn.close()
    assert res["template_matches"] == []
    assert res["found"] is False
    assert res["match"] == "none"


# ── A2: a one-hop wrapper-indirect edge is surfaced, flagged via_wrapper ─────────────


def test_wrapper_indirect_edge_is_surfaced_and_flagged(tmp_path: Path) -> None:
    # A2: the caller reads a key THROUGH a thin wrapper; the key was a literal at the call site, so
    # it resolves as a constant reader — but flagged via_wrapper + indirect so it is never mistaken
    # for a direct call. This is the oauth-code case A2 recovers (readers no longer falsely empty).
    atlas = _seed(
        tmp_path,
        [
            _flow("oauth_auth_code", "constant", "rc", "save", "write", api="nvram_set"),
            _flow(
                "oauth_auth_code",
                "constant",
                "rc",
                "biz_caller",
                "read",
                api="nvram_get",
                via_wrapper="FUN_indirect_getter",
            ),
        ],
    )
    conn = open_atlas(atlas)
    try:
        res = get_nvram_key_flow(conn, "oauth_auth_code")
    finally:
        conn.close()
    assert res["match"] == "exact"
    (reader,) = res["readers"]
    assert reader["func"] == "biz_caller"
    assert reader["via_wrapper"] == "FUN_indirect_getter"
    assert reader["indirect"] is True
    # both sides present -> no empty-side note; coverage now states one-hop wrappers ARE captured
    assert "via_wrapper" in res["coverage"] and "one-hop" in res["coverage"]
    assert not any("empty readers" in n for n in res["notes"])


# ── unresolved: never connected to a concrete key, but exposed via completeness ─────


def test_unresolved_ops_drive_completeness_not_the_graph(tmp_path: Path) -> None:
    atlas = _seed(
        tmp_path,
        [
            _flow("sw_mode", "constant", "rc", "set_mode", "write"),
            _flow(None, "unresolved", "httpd", "fwd", "write"),
            _flow(None, "unresolved", "httpd", "fwd2", "read"),
        ],
    )
    conn = open_atlas(atlas)
    try:
        res = get_nvram_key_flow(conn, "sw_mode")
    finally:
        conn.close()

    # the unresolved ops are NOT attributed to sw_mode (they could touch any key)...
    assert [w["func"] for w in res["writers"]] == ["set_mode"]
    # ...but they are exposed: the result is honestly marked possibly-incomplete with a count,
    # and the dynamic-key note is kept SEPARATE from the wrapper-indirect note.
    assert res["completeness"] == "may_be_incomplete"
    assert res["unresolved_count"] == 2
    dyn = [n for n in res["notes"] if "unresolved/dynamically-built" in n]
    assert len(dyn) == 1 and "2 nvram ops" in dyn[0]
    # sw_mode has a direct writer but no direct reader -> a distinct wrapper-indirect note fires
    assert any("empty readers" in n and "wrapper" in n for n in res["notes"])


# ── the red line: empty readers/writers is NEVER "confirmed no consumer" ────────────


def test_absent_key_is_never_confirmed_unused(tmp_path: Path) -> None:
    # The oauth-code audit case: a key with no DIRECT reader must NOT read as "unused" — a wrapper
    # could read it. No unresolved ops in the atlas, yet completeness stays may_be_incomplete and a
    # note warns that absence is not proof (wrapper-indirect access is uncaptured).
    atlas = _seed(tmp_path, [_flow("other_key", "constant", "rc", "f", "write")])
    conn = open_atlas(atlas)
    try:
        res = get_nvram_key_flow(conn, "oauth_auth_code")
    finally:
        conn.close()
    assert res["found"] is False
    assert res["match"] == "none"
    assert res["completeness"] == "may_be_incomplete"  # NOT "complete" — wrapper blind spot
    assert res["unresolved_count"] == 0  # the caveat is NOT (mis)attributed to dynamic keys
    wrapper_note = [n for n in res["notes"] if "wrapper" in n]
    assert wrapper_note and "NOT proof the key is unused" in wrapper_note[0]
    assert "does NOT mean the key is unused" in res["coverage"]


def test_direct_writer_but_no_direct_reader_warns_wrapper(tmp_path: Path) -> None:
    # A key written directly but read only via a wrapper: readers is empty, but the tool must warn
    # that a wrapper reader is uncaptured — never letting readers:[] read as "no consumer".
    atlas = _seed(tmp_path, [_flow("oauth_auth_code", "constant", "httpd", "save", "write")])
    conn = open_atlas(atlas)
    try:
        res = get_nvram_key_flow(conn, "oauth_auth_code")
    finally:
        conn.close()
    assert [w["binary"] for w in res["writers"]] == ["httpd"]
    assert res["readers"] == []
    assert res["completeness"] == "may_be_incomplete"
    assert any("empty readers" in n and "non-literal" in n for n in res["notes"])


# ── web_settable: source-side writability from router_defaults (naming-bridge phase 1) ──


def test_web_settable_true_carries_default_and_flags(tmp_path: Path) -> None:
    # The OAuth acceptance shape: the key IS a router_defaults member -> in_router_defaults True,
    # with its default (an empty string, distinct from null) and flags surfaced as facts.
    atlas = _seed(
        tmp_path,
        [_flow("oauth_auth_code", "constant", "httpd", "save", "write")],
        defaults=[_default("oauth_auth_code", default_value="", flags=0x80, member_index=894)],
    )
    conn = open_atlas(atlas)
    try:
        res = get_nvram_key_flow(conn, "oauth_auth_code")
    finally:
        conn.close()
    ws = res["web_settable"]
    assert ws["in_router_defaults"] is True
    assert ws["default_value"] == ""  # a real empty-string default, not null
    assert ws["flags"] == 0x80
    assert "router_defaults" in ws["source"]


def test_web_settable_false_only_when_located_and_complete(tmp_path: Path) -> None:
    # Table located (has members) AND complete (no unresolved) AND key absent -> a definite False.
    atlas = _seed(
        tmp_path,
        [],
        defaults=[_default("sw_mode", default_value="0", flags=0, member_index=0)],
    )
    conn = open_atlas(atlas)
    try:
        res = get_nvram_key_flow(conn, "not_a_member")
    finally:
        conn.close()
    assert res["web_settable"]["in_router_defaults"] is False


def test_web_settable_uncertain_when_table_not_located(tmp_path: Path) -> None:
    # ★ false-negative red line: no router_defaults rows in the atlas -> uncertain, NEVER False.
    atlas = _seed(tmp_path, [_flow("sw_mode", "constant", "rc", "set_mode", "write")])
    conn = open_atlas(atlas)
    try:
        res = get_nvram_key_flow(conn, "sw_mode")
    finally:
        conn.close()
    ws = res["web_settable"]
    assert ws["in_router_defaults"] == "uncertain"
    assert ws["in_router_defaults"] is not False
    assert "not located" in ws["reason"]


def test_web_settable_uncertain_when_located_but_incomplete(tmp_path: Path) -> None:
    # Table located but a member failed to parse (key NULL row) -> a not-found key is uncertain (it
    # could be the unparsed member), never a false "not settable".
    atlas = _seed(
        tmp_path,
        [],
        defaults=[
            _default("sw_mode", default_value="0", flags=0, member_index=0),
            _default(None, member_index=500),  # an unresolved member -> table is incomplete
        ],
    )
    conn = open_atlas(atlas)
    try:
        res = get_nvram_key_flow(conn, "some_other_key")
    finally:
        conn.close()
    assert res["web_settable"]["in_router_defaults"] == "uncertain"
    assert "incomplete" in res["web_settable"]["reason"]


# ── template-to-regex grammar (unit) ────────────────────────────────────────────────


def test_template_matching_grammar() -> None:
    assert _template_matches("wl%d_ssid", "wl0_ssid")
    assert _template_matches("wl%d_ssid", "wl12_ssid")
    assert not _template_matches("wl%d_ssid", "wlx_ssid")  # %d is digits only
    assert _template_matches("%s_bss_enabled", "guest_bss_enabled")
    assert _template_matches("wl%d.%d_bss", "wl0.1_bss")
    # an opaque strcpy-built key is not a decidable template -> never matches
    assert _template_to_regex("<built:strcpy>") is None
    assert not _template_matches("<built:strcpy>", "anything")
    # anchorless templates match ANY key by regex, but are rejected as "key unknown" (no anchor)
    assert not _template_matches("%s%s", "foobar123")
    assert not _template_matches("%s", "anything")


def test_template_has_anchor() -> None:
    # real templates: a fixed-literal part survives placeholder removal (>= 2 chars)
    assert template_has_anchor("wl%d_ssid")  # -> wl_ssid
    assert template_has_anchor("%s_bss_enabled")  # -> _bss_enabled
    assert template_has_anchor("wan%d_ifname")  # -> wan_ifname
    # anchorless: only placeholders, or an opaque marker -> not a meaningful template
    assert not template_has_anchor("%s%s")
    assert not template_has_anchor("%s")
    assert not template_has_anchor("%d")
    assert not template_has_anchor("<built:strcpy>")
    assert not template_has_anchor("a%s")  # 1 fixed char < threshold
