# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the nvram key-flow query (gap② phase 2): the three-tier honesty contract over
the atlas nvram_key_flow table — exact (constant), template (parametric, flagged), and unresolved
(never connected to a concrete key, but exposed via completeness)."""

from __future__ import annotations

from pathlib import Path

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.models import NvramDefaultRow, NvramFlowRow, WebFormFieldRow
from treasure_map.lib.atlas.writer import (
    add_nvram_default_rows,
    add_nvram_flow_rows,
    add_web_form_field_rows,
)
from treasure_map.lib.query import get_nvram_key_flow
from treasure_map.lib.query.nvram import (
    _template_matches,
    _template_to_regex,
    _web_settable,
    template_has_anchor,
)


def _seed(
    tmp_path: Path,
    rows: list[NvramFlowRow],
    defaults: list[NvramDefaultRow] | None = None,
    form_fields: list[WebFormFieldRow] | None = None,
) -> Path:
    atlas = tmp_path / "atlas.db"
    conn = open_atlas(atlas)
    try:
        add_nvram_flow_rows(conn, rows)
        if defaults:
            add_nvram_default_rows(conn, defaults)
        if form_fields:
            add_web_form_field_rows(conn, form_fields)
    finally:
        conn.close()
    return atlas


def _field(keyword: str, *, rule: str = "input", run: str = "run_a") -> WebFormFieldRow:
    return WebFormFieldRow(
        source_run_id=run, field_keyword=keyword, source_asset="Feedback.asp", source_rule=rule
    )


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


# ── web_settable: source-side writability by the SaTC front-end x back-end cross (M2) ──


def test_web_settable_yes_when_frontend_editable_and_backend_key(tmp_path: Path) -> None:
    # The money path: an editable front-end field AND a back-end nvram key -> a web-settable key.
    atlas = _seed(
        tmp_path,
        [_flow("fb_comment", "constant", "httpd", "save", "write")],
        form_fields=[_field("fb_comment", rule="textarea")],
    )
    conn = open_atlas(atlas)
    try:
        ws = _web_settable(conn, "fb_comment")
        res = get_nvram_key_flow(conn, "fb_comment")
    finally:
        conn.close()
    assert ws["web_settable"] == "yes"
    assert ws["frontend"] is True and ws["backend"] is True
    assert res["web_settable"]["web_settable"] == "yes"  # surfaced through the key-flow reader


def test_web_settable_carries_frontend_evidence_rows(tmp_path: Path) -> None:
    # Drill-down: web_settable exposes the CONCRETE web_form_fields rows behind the front-end match
    # (real field / asset / rule), not just the bool — so an agent can confirm the web reach or
    # demote a keyword collision. The verdict itself is unchanged (still 'yes').
    atlas = _seed(
        tmp_path,
        [_flow("fb_comment", "constant", "httpd", "save", "write")],
        form_fields=[_field("fb_comment", rule="textarea")],
    )
    conn = open_atlas(atlas)
    try:
        ws = _web_settable(conn, "fb_comment")
        res = get_nvram_key_flow(conn, "fb_comment")
    finally:
        conn.close()
    assert ws["web_settable"] == "yes"  # verdict unchanged by exposing evidence
    assert ws["evidence"] == [
        {
            "field_keyword": "fb_comment",
            "source_asset": "Feedback.asp",
            "source_rule": "textarea",
            "match_kind": "exact",
        }
    ]
    # The same evidence rides through the key-flow reader (the free drill-down surface).
    assert res["web_settable"]["evidence"] == ws["evidence"]


def test_web_settable_naming_variant_evidence_is_tagged(tmp_path: Path) -> None:
    # A key whose only front-end field is a naming-variant mirror (http_username -> http_username_x)
    # is 'uncertain', but the evidence still exposes the variant row tagged naming_variant, so an
    # agent sees WHY it is uncertain — a mirror field, not an exact editable field.
    atlas = _seed(
        tmp_path,
        [_flow("http_username", "constant", "httpd", "auth", "read")],
        form_fields=[_field("http_username_x")],
    )
    conn = open_atlas(atlas)
    try:
        ws = _web_settable(conn, "http_username")
    finally:
        conn.close()
    assert ws["web_settable"] == "uncertain"  # variant is not a proven exact editable field
    assert ws["evidence"] == [
        {
            "field_keyword": "http_username_x",
            "source_asset": "Feedback.asp",
            "source_rule": "input",
            "match_kind": "naming_variant",
        }
    ]


def test_web_settable_three_state_never_emits_no(tmp_path: Path) -> None:
    # ④/M2 THREE-STATE {yes, likely, uncertain}: back-end-only (firmver, a read-only display) and
    # front-end-only (Connect_btn, a UI control), NEITHER a router_defaults member (no defaults
    # seeded -> table not located), both land 'uncertain' — NEVER 'no' (inferring 'not settable'
    # from a missing side is a false-negative) and NEVER 'likely' (not a defaults member). The
    # frontend/backend flags still expose which side was present, honestly.
    atlas = _seed(
        tmp_path,
        [_flow("firmver", "constant", "httpd", "show", "read")],
        form_fields=[_field("fb_comment", rule="textarea"), _field("Connect_btn")],
    )
    conn = open_atlas(atlas)
    try:
        firmver = _web_settable(conn, "firmver")  # back-end only
        btn = _web_settable(conn, "Connect_btn")  # front-end only
    finally:
        conn.close()
    assert firmver["web_settable"] == "uncertain"
    assert firmver["web_settable"] not in ("no", "likely")
    assert firmver["backend"] is True and firmver["frontend"] is False
    assert btn["web_settable"] == "uncertain"
    assert btn["web_settable"] not in ("no", "likely")
    assert btn["frontend"] is True and btn["backend"] is False


def test_web_settable_likely_when_router_defaults_member_but_not_a_cross(tmp_path: Path) -> None:
    # M2 positive: a key that is NOT a proven SaTC cross (back-end read only, no editable front-end
    # field) but IS a router_defaults member -> 'likely' (the OAuth shape: oauth_auth_code is
    # read back-end and sits in router_defaults, but is not a front-end form field).
    atlas = _seed(
        tmp_path,
        [_flow("oauth_auth_code", "constant", "httpd", "wrap_read", "read")],
        defaults=[_default("oauth_auth_code", default_value="")],
    )
    conn = open_atlas(atlas)
    try:
        ws = _web_settable(conn, "oauth_auth_code")
        res = get_nvram_key_flow(conn, "oauth_auth_code")
    finally:
        conn.close()
    assert ws["web_settable"] == "likely"  # router_defaults member, not a proven cross
    assert res["web_settable"]["web_settable"] == "likely"  # surfaced through the key-flow reader


def test_web_settable_not_likely_when_not_a_router_defaults_member(tmp_path: Path) -> None:
    # ★ SEAM #13 guardrail: a key that is NOT a router_defaults member (the table is located AND
    # complete, another key is present) must NOT read 'likely' — it stays 'uncertain'. This is the
    # M3 red line in test form: the likely gate is in_router_defaults membership ONLY, never
    # widened. log_wlstat_dir / productid are exactly this internal-key case.
    atlas = _seed(
        tmp_path,
        [_flow("log_wlstat_dir", "constant", "httpd", "wrap_read", "read")],
        defaults=[_default("http_passwd", default_value="")],  # located+complete, other key present
    )
    conn = open_atlas(atlas)
    try:
        ws = _web_settable(conn, "log_wlstat_dir")
    finally:
        conn.close()
    assert ws["router_defaults"]["in_router_defaults"] is False  # definite non-member
    assert ws["web_settable"] == "uncertain"
    assert ws["web_settable"] != "likely"  # gate held: membership-only, no false promote


def test_web_settable_uncertain_when_frontend_not_collected(tmp_path: Path) -> None:
    # ★ false-negative red line: no web_form_fields rows (M1 not run) -> uncertain, NEVER 'no'.
    atlas = _seed(tmp_path, [_flow("sw_mode", "constant", "rc", "set_mode", "write")])
    conn = open_atlas(atlas)
    try:
        ws = _web_settable(conn, "sw_mode")
    finally:
        conn.close()
    assert ws["web_settable"] == "uncertain"
    assert ws["web_settable"] != "no"


def test_web_settable_yes_via_wl_index_normalization(tmp_path: Path) -> None:
    # The wl mapping: a front-end generic 'wl_ssid' matches a back-end indexed 'wl0_ssid'.
    atlas = _seed(
        tmp_path,
        [_flow("wl0_ssid", "constant", "httpd", "save", "write")],
        form_fields=[_field("wl_ssid", rule="input")],
    )
    conn = open_atlas(atlas)
    try:
        ws = _web_settable(conn, "wl0_ssid")
    finally:
        conn.close()
    assert ws["web_settable"] == "yes"


def test_web_settable_uncertain_for_naming_variant_field(tmp_path: Path) -> None:
    # http_username: the editable field is http_username_x (a naming variant); the bare key is
    # front-end-missed -> uncertain, NOT a false 'no' (a variant may be the editable mirror).
    atlas = _seed(
        tmp_path,
        [_flow("http_username", "constant", "httpd", "read_cred", "read")],
        form_fields=[_field("http_username_x", rule="input")],
    )
    conn = open_atlas(atlas)
    try:
        ws = _web_settable(conn, "http_username")
    finally:
        conn.close()
    assert ws["web_settable"] == "uncertain"
    assert ws["web_settable"] != "no"


def test_web_settable_router_defaults_rides_along_as_auxiliary(tmp_path: Path) -> None:
    # router_defaults is kept as an auxiliary reference field, not the primary judgement.
    atlas = _seed(
        tmp_path,
        [_flow("fb_comment", "constant", "httpd", "save", "write")],
        defaults=[_default("fb_comment", default_value="", flags=0x80, member_index=894)],
        form_fields=[_field("fb_comment", rule="textarea")],
    )
    conn = open_atlas(atlas)
    try:
        ws = _web_settable(conn, "fb_comment")
    finally:
        conn.close()
    assert ws["web_settable"] == "yes"
    assert ws["router_defaults"]["in_router_defaults"] is True  # auxiliary, still surfaced


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


def test_run_id_scopes_every_part_of_the_graph(tmp_path: Path) -> None:
    # ★ Scoping has to reach all three reads. Narrowing only the exact hits would answer with this
    # run's writers beside another firmware's templates and unresolved count — an answer that looks
    # scoped and is not, which is worse than not offering the option.
    conn = open_atlas(tmp_path / "atlas.db")
    rows = [
        # (run, key, kind) — the same key in two firmwares, plus a template and an unresolved op
        ("fw_a", "http_passwd", "constant"),
        ("fw_b", "http_passwd", "constant"),
        ("fw_a", "http_%s", "parametric"),
        ("fw_b", "http_%s", "parametric"),
        ("fw_a", None, "unresolved"),
        ("fw_b", None, "unresolved"),
    ]
    add_nvram_flow_rows(
        conn,
        [
            NvramFlowRow(
                source_run_id=run,
                key=key,
                key_kind=kind,
                binary=f"{run}d",
                func="f",
                op="read",
                api="nvram_get",
            )
            for run, key, kind in rows
        ],
    )

    everywhere = get_nvram_key_flow(conn, "http_passwd")
    assert {e["source_run_id"] for e in everywhere["readers"]} == {"fw_a", "fw_b"}
    assert len(everywhere["template_matches"]) == 2
    assert everywhere["unresolved_count"] == 2

    scoped = get_nvram_key_flow(conn, "http_passwd", run_id="fw_a")
    assert {e["source_run_id"] for e in scoped["readers"]} == {"fw_a"}
    assert [t["source_run_id"] for t in scoped["template_matches"]] == ["fw_a"]
    assert scoped["unresolved_count"] == 1  # the caveat is now about THIS run, not the atlas
    conn.close()
