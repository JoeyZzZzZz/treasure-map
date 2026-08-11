# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Cross-binary launch edges: token reading, six-state resolution, and the honesty flags.

Fixtures are synthetic and vendor-neutral. The link shapes they exercise are the ones real
extracted rootfs images produce: an interpreter link onto the multi-call binary, a bare name that
several links claim, a link the unpacker flattened onto /dev/null, and a link whose target never
made it into the binary inventory.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.diff.loader import FuncRow
from treasure_map.lib.hunt import run_analyzer2
from treasure_map.lib.hunt.exec_edges import (
    EXEC_SINKS,
    SHELL_SINKS,
    TARGET_RESOLUTIONS,
    ExecEdgeInventory,
    build_exec_edges,
    build_symlink_index,
    classify_target_resolution,
    enters_entry_reach,
    exec_entry_sites,
    parse_shell_command,
    resolve_symlink,
)
from treasure_map.lib.query import launched_by
from treasure_map.lib.storage.connection import open_db

# ── fixture helpers ───────────────────────────────────────────────────────────────────


def _func(
    name: str = "handler", binary: str = "web_daemon", fid: int = 1, addr: str = "00011000"
) -> FuncRow:
    return FuncRow(
        func_id=fid,
        binary_id=1,
        binary_name=binary,
        binary_path=f"/usr/sbin/{binary}",
        binary_sha256="a" * 64,
        name=name,
        address=addr,
        pseudocode="",
        pseudocode_hash=None,
        callees=None,
    )


def _const(value: str) -> dict[str, Any]:
    return {"kind": "constant", "value": value, "value_kind": "literal_string"}


def _prov(sink: str, provenance: dict[str, Any], addr: str = "0x11020") -> dict[str, Any]:
    return {"sink_idx": 0, "sink": sink, "sink_addr": addr, "arg_idx": 0, "provenance": provenance}


def _inventory(
    links: list[tuple[str, str, str | None, str | None]] | None = None,
    binaries: set[str] | None = None,
    scripts: set[str] | None = None,
) -> ExecEdgeInventory:
    """``links`` rows are (link_path, link_name, target_name, corrupt_reason)."""
    return ExecEdgeInventory(
        symlinks=build_symlink_index(list(links or [])),
        bin_names=frozenset(binaries or {"web_daemon", "busybox"}),
        script_names=frozenset(scripts or set()),
    )


def _edges(
    records: list[dict[str, Any]],
    inventory: ExecEdgeInventory | None = None,
    funcs: list[FuncRow] | None = None,
) -> list[Any]:
    funcs = funcs or [_func()]
    return build_exec_edges(
        funcs, {f.func_id: records for f in funcs}, inventory or _inventory(), "run1"
    )


# ── the sink lexicon (the extractor's own list is the authority) ──────────────────────


def test_sink_families_are_disjoint_and_exclude_the_unextracted_ones() -> None:
    # posix_spawn and execvpe are NOT in the extractor's provenance lexicon, so no provenance
    # record can ever name them. Claiming them here would promise coverage that does not exist —
    # the scan status declares the gap instead. (Soft teeth: this pins the declared scope.)
    assert SHELL_SINKS & EXEC_SINKS == frozenset()
    assert "posix_spawn" not in (SHELL_SINKS | EXEC_SINKS)
    assert "execvpe" not in (SHELL_SINKS | EXEC_SINKS)


# ── the interpreter link: the headline case ───────────────────────────────────────────


def test_exec_of_interpreter_link_resolves_to_the_multicall_binary() -> None:
    # execl("/bin/sh", ...) with bin/sh -> busybox: a resolved_symlink edge onto busybox, on the
    # image layer, flagged shell_wrapped — and with the inner command NOT claimed, because for
    # this family it rides in argv, which is structurally invisible.
    #
    # MUTATION (verified RED, 1 failed): in exec_edges._exec_facts force the token unreadable —
    # `token_kind=TOKEN_NONE,` in place of the conditional -> resolution becomes 'unresolved',
    # target_binary None.
    inv = _inventory(links=[("bin/sh", "sh", "busybox", None)])
    (edge,) = _edges([_prov("execl", _const("/bin/sh"))], inv)
    assert edge.target_resolution == "resolved_symlink"
    assert edge.target_binary == "busybox"
    assert edge.resolved_via == "busybox"
    assert edge.target_layer == "exec_image"
    assert (edge.shell_wrapped, edge.inner_command_visible) == (1, 0)
    assert edge.argv_visibility == "structurally_invisible"
    assert edge.argv_template is None


def test_symlinked_target_edge_is_not_lost_when_the_link_table_is_empty() -> None:
    # Without the link inventory the SAME callsite still produces a row — unmatched, carrying the
    # token form — instead of vanishing. Recall first: an edge is never dropped for failing to
    # resolve.
    (edge,) = _edges([_prov("execl", _const("/bin/sh"))], _inventory(links=[]))
    assert (edge.target_resolution, edge.token_form) == ("unmatched", "absolute")
    assert (edge.symlink_ambiguous, edge.symlink_corrupt, edge.symlink_target_unresolved) == (
        0,
        0,
        0,
    )


# ── the two families ──────────────────────────────────────────────────────────────────


def test_target_layer_splits_the_two_families() -> None:
    # A command string names its program in the first word (shell_command); an exec call names the
    # image itself (exec_image). The /bin/sh image behind a system() call is deliberately NOT a
    # second edge — it would be a constant on every row.
    inv = _inventory(binaries={"web_daemon", "busybox", "helper"})
    (shell_edge,) = _edges([_prov("system", _const("helper -x"))], inv)
    (exec_edge,) = _edges([_prov("execv", _const("/bin/helper"))], inv)
    assert shell_edge.target_layer == "shell_command"
    assert (shell_edge.target_token, shell_edge.target_binary) == ("helper", "helper")
    assert exec_edge.target_layer == "exec_image"
    assert exec_edge.target_binary == "helper"


def test_shell_wrapped_pipeline_is_read_through_to_its_first_stage() -> None:
    # `sh -c "a | b"` handed to system(): the wrapping interpreter is peeled, the pipeline is
    # flagged, and the launched program is the FIRST stage.
    #
    # MUTATION (verified RED, 1 failed): in exec_edges.parse_shell_command compute `piped` on the
    # already-peeled text only for the outer level — replace `piped = _has_pipe(text)` with
    # `piped = False` -> piped comes back 0.
    inv = _inventory(binaries={"web_daemon", "logger_tool"})
    (edge,) = _edges([_prov("system", _const('sh -c "logger_tool x | grep y"'))], inv)
    assert (edge.shell_wrapped, edge.piped) == (1, 1)
    assert edge.target_token == "logger_tool"
    assert edge.inner_command_visible == 1


def test_shell_prefixes_are_peeled_before_the_first_word_is_taken() -> None:
    # A subshell paren and VAR= assignments configure a command; they are not the command.
    inv = _inventory(binaries={"web_daemon", "helper"})
    (edge,) = _edges([_prov("system", _const("( LD_PRELOAD=/lib/x.so helper -v )"))], inv)
    assert edge.target_token == "helper"


def test_exec_family_never_reconstructs_argv() -> None:
    # ★ VARIADIC IRON LAW. execl carries argv as a variadic list and execv as a caller-built
    # array; neither is in the provenance. arg0 is recorded, argv is declared invisible, and no
    # command template is invented for it.
    for api in sorted(EXEC_SINKS):
        (edge,) = _edges([_prov(api, _const("/usr/sbin/web_daemon"))])
        assert edge.argv_visibility == "structurally_invisible", api
        assert edge.argv_template is None, api
        assert edge.inner_command_visible == 0, api


def test_placeholder_command_keeps_its_template_but_not_a_claimed_target() -> None:
    # A built command line stays visible as a template, and the fact that it holds a placeholder is
    # recorded — but a token still carrying one is NOT matched against the inventory.
    (edge,) = _edges([_prov("system", _const("%s -x"))])
    assert edge.argv_visibility == "known_with_placeholder"
    assert edge.argv_template == "%s -x"
    assert edge.target_resolution == "unresolved"


# ── unreadable tokens are reported, never dropped ─────────────────────────────────────


def test_unreadable_argument_still_produces_a_row() -> None:
    # A parameter-sourced argument cannot be read here. That is 'unresolved' — a stated coverage
    # gap — and the callsite is still on the table. Dropping it would hide the callsite entirely.
    #
    # MUTATION (verified RED, 1 failed): in exec_edges.build_exec_edges skip unreadable values —
    # add `if value is None: continue` before `facts = facts_of(value)` -> zero rows.
    edges = _edges([_prov("system", {"kind": "param", "name": "param_1"})])
    assert len(edges) == 1
    assert edges[0].target_resolution == "unresolved"
    assert edges[0].target_token is None


def test_constant_with_unreadable_text_is_not_matched_as_a_name() -> None:
    # A constant the extractor confirms but cannot read out as a string ("ambiguous_0x") is a
    # constant whose TEXT is unknown. Treating "0x1234" as a program name would be a fabrication.
    (edge,) = _edges(
        [_prov("system", {"kind": "constant", "value": "0x8f20", "value_kind": "ambiguous_0x"})]
    )
    assert edge.target_resolution == "unresolved"


def test_phi_merge_yields_one_edge_per_origin() -> None:
    # A command argument merged from two branches can launch either program: both become edges.
    inv = _inventory(binaries={"web_daemon", "helper", "other_tool"})
    edges = _edges(
        [
            _prov(
                "system", {"kind": "multiple", "sources": [_const("helper"), _const("other_tool")]}
            )
        ],
        inv,
    )
    assert sorted(e.target_binary for e in edges) == ["helper", "other_tool"]


def test_every_stack_writer_contributes_an_edge() -> None:
    # ★ ALL writers, not only the dominating ones. A verdict layer filters to dominating writers so
    # it never over-asserts; an ENUMERATION must not, or a command built on a conditional branch
    # would disappear from the launch table.
    #
    # MUTATION (verified RED, 1 failed): in exec_edges._arg_values filter the stack_buf writers to
    # dominating ones — `for writer in [w for w in (prov.get("writers") or []) if
    # w.get("dominates_sink")]:` -> the branch writer's target (other_tool) is gone.
    inv = _inventory(binaries={"web_daemon", "helper", "other_tool"})
    prov = {
        "kind": "stack_buf",
        "stack_key": "sp-0x40",
        "writers": [
            {"writer": "snprintf@0x1", "dominates_sink": True, "fmt": "helper -a %s"},
            {"writer": "snprintf@0x2", "dominates_sink": False, "fmt": "other_tool -b"},
        ],
    }
    edges = _edges([_prov("system", prov)], inv)
    assert sorted(e.target_binary for e in edges) == ["helper", "other_tool"]


# ── the six states: total and mutually exclusive ──────────────────────────────────────


_CLASSIFY_INPUTS: list[dict[str, Any]] = [
    {"token": "/proc/self/exe", "token_kind": "clean_literal"},
    {"token": "anything", "token_kind": "none"},
    {"token": "busybox", "token_kind": "clean_literal", "in_binaries": True},
    {"token": "sh", "token_kind": "clean_literal", "via_symlink": True},
    {"token": "boot.sh", "token_kind": "clean_literal", "in_non_binary": True, "sh": True},
    {"token": "nothing_here", "token_kind": "clean_literal"},
    {"token": "", "token_kind": "none"},
    {"token": "/usr/bin/x", "token_kind": "clean_literal", "ambiguous": True},
    {"token": "x", "token_kind": "clean_literal", "corrupt": True},
    {"token": "x", "token_kind": "clean_literal", "target_unresolved": True},
]


def _classify(spec: dict[str, Any]) -> str:
    from treasure_map.lib.hunt.exec_edges import SymlinkMatch

    return classify_target_resolution(
        spec["token"],
        spec["token_kind"],
        in_binaries=spec.get("in_binaries", False),
        match=SymlinkMatch(
            via_symlink=spec.get("via_symlink", False),
            ambiguous=spec.get("ambiguous", False),
            corrupt=spec.get("corrupt", False),
            target_unresolved=spec.get("target_unresolved", False),
        ),
        in_non_binary=spec.get("in_non_binary", False),
        is_sh_script=spec.get("sh", False),
    )


def test_classification_is_total_and_lands_in_exactly_one_of_six_states() -> None:
    # Every input gets exactly one state, and the image over the inputs is the whole six-state set
    # — no input falls through, and no seventh state exists.
    #
    # MUTATION (verified RED, 1 failed): in exec_edges.classify_target_resolution delete the final
    # `return UNMATCHED` and let the function fall off the end -> the unmatched inputs come back
    # None, so the image is no longer a subset of the six states.
    produced = {_classify(spec) for spec in _CLASSIFY_INPUTS}
    assert produced <= TARGET_RESOLUTIONS
    assert produced == TARGET_RESOLUTIONS  # the fixtures cover every state
    for spec in _CLASSIFY_INPUTS:
        assert _classify(spec) in TARGET_RESOLUTIONS


def test_entry_reach_admission_is_total_and_two_valued() -> None:
    # ★ Only a target resolved to a real binary may become an entry site, and the answer is a plain
    # yes/no over EVERY string — an unrecognized state must never silently grant a site.
    #
    # MUTATION (verified RED, 1 failed): in exec_edges.enters_entry_reach add RESOLVED_SCRIPT to
    # the tuple -> a script target starts granting entry sites.
    admitted = {r for r in TARGET_RESOLUTIONS if enters_entry_reach(r)}
    assert admitted == {"resolved_direct", "resolved_symlink"}
    assert {enters_entry_reach(r) for r in [*TARGET_RESOLUTIONS, "a_state_from_the_future"]} == {
        True,
        False,
    }
    assert enters_entry_reach("a_state_from_the_future") is False


# ── symlink resolution: ambiguity, damage, and the default-deny catch-all ─────────────


def test_bare_name_with_two_verifiable_targets_is_undecided() -> None:
    # A bare name claimed by two links whose targets are BOTH real binaries is genuinely
    # ambiguous. tmap does not pick one.
    #
    # MUTATIONS (each verified RED, 1 failed):
    #  (a) judge ambiguity on the hits instead of the verifiable targets — in resolve_symlink
    #      replace `valid = tuple(sorted(t for t in hits if t in bin_names))` with
    #      `valid = tuple(sorted(hits))` -> the single-valid case below breaks (a real edge is
    #      thrown away as ambiguous).
    #  (b) drop full-path priority — in resolve_symlink delete the whole
    #      `if token.startswith("/"):` block so every token matches by basename -> the absolute
    #      token below stops resolving to its own link and turns ambiguous too.
    index = build_symlink_index(
        [
            ("bin/fetch_tool", "fetch_tool", "busybox", None),
            ("usr/sbin/fetch_tool", "fetch_tool", "uclient_fetch", None),
        ]
    )
    bins = frozenset({"busybox", "uclient_fetch"})
    bare = resolve_symlink("fetch_tool", index, bins)
    assert bare.ambiguous is True
    assert bare.via_symlink is False
    assert bare.matched_targets == ("busybox", "uclient_fetch")
    # the absolute spelling names ONE link, so it is not ambiguous at all
    absolute = resolve_symlink("/usr/sbin/fetch_tool", index, bins)
    assert (absolute.via_symlink, absolute.matched_targets) == (True, ("uclient_fetch",))


def test_one_verifiable_target_among_several_hits_still_resolves() -> None:
    # Only one of the two link targets is a known binary. Calling that ambiguous would throw away
    # a real edge for the sake of a target that does not exist.
    index = build_symlink_index(
        [
            ("bin/fetch_tool", "fetch_tool", "busybox", None),
            ("usr/sbin/fetch_tool", "fetch_tool", "never_extracted", None),
        ]
    )
    match = resolve_symlink("fetch_tool", index, frozenset({"busybox"}))
    assert (match.via_symlink, match.ambiguous, match.matched_targets) == (
        True,
        False,
        ("busybox",),
    )


def test_ambiguous_token_lands_unmatched_carrying_the_ambiguity_fact() -> None:
    inv = _inventory(
        links=[
            ("bin/fetch_tool", "fetch_tool", "busybox", None),
            ("usr/sbin/fetch_tool", "fetch_tool", "uclient_fetch", None),
        ],
        binaries={"web_daemon", "busybox", "uclient_fetch"},
    )
    (edge,) = _edges([_prov("system", _const("fetch_tool http://x"))], inv)
    assert edge.target_resolution == "unmatched"
    assert edge.symlink_ambiguous == 1
    assert (edge.symlink_corrupt, edge.symlink_target_unresolved) == (0, 0)
    assert edge.target_binary is None
    assert edge.token_form == "bare"


def test_damaged_link_is_reported_as_damage_not_as_a_miss() -> None:
    # The unpacker flattened bin/ifconfig onto /dev/null. Saying "token not found" would blame the
    # firmware for the extraction tool's damage.
    #
    # MUTATION (verified RED, 1 failed): in exec_edges.build_symlink_index treat a damaged link as
    # an ordinary one — delete the `if corrupt_reason:` branch -> the row resolves (or reports a
    # plain miss) and symlink_corrupt is 0.
    inv = _inventory(
        links=[("bin/ifconfig", "ifconfig", "null", "devnull_placeholder")],
        binaries={"web_daemon", "busybox"},
    )
    (edge,) = _edges([_prov("system", _const("ifconfig eth0 up"))], inv)
    assert edge.target_resolution == "unmatched"
    assert edge.symlink_corrupt == 1
    assert (edge.symlink_ambiguous, edge.symlink_target_unresolved) == (0, 0)


def test_link_whose_target_is_not_a_known_binary_is_default_denied() -> None:
    # ★ THE CATCH-ALL. The link exists and points at `helper_tool`, but that target never became a
    # binary in the inventory (not extracted, a script, another link, or a damage shape nobody has
    # met). The row must say so — and name the target it hit — so a reader is not misled into
    # "probably a shell built-in" or "the token was mistyped".
    #
    # MUTATIONS (each verified RED, 1 failed):
    #  (a) claim it resolved — in resolve_symlink change the final
    #      `return SymlinkMatch(target_unresolved=True, matched_targets=tuple(sorted(hits)))` to
    #      `return SymlinkMatch(via_symlink=True, matched_targets=tuple(sorted(hits)))`
    #      -> resolution becomes resolved_symlink, a target_binary is claimed.
    #  (b) lose the fact — change the same line to `return SymlinkMatch()` -> all three flags read
    #      0 and resolved_via is None, so "the link IS there" is gone.
    inv = _inventory(
        links=[("bin/tool_x", "tool_x", "helper_tool", None)],
        binaries={"web_daemon", "busybox"},
    )
    (edge,) = _edges([_prov("system", _const("tool_x --run"))], inv)
    assert edge.target_resolution == "unmatched"
    assert edge.symlink_target_unresolved == 1
    assert (edge.symlink_ambiguous, edge.symlink_corrupt) == (0, 0)
    assert edge.resolved_via == "helper_tool"
    assert edge.target_binary is None


def test_script_target_resolves_but_never_grants_an_entry_site() -> None:
    inv = _inventory(binaries={"web_daemon"}, scripts={"restart.sh"})
    (edge,) = _edges([_prov("system", _const("/etc/init.d/restart.sh reload"))], inv)
    assert edge.target_resolution == "resolved_script"
    assert exec_entry_sites([edge]) == {}


def test_self_exec_is_its_own_state() -> None:
    (edge,) = _edges([_prov("execv", _const("/proc/self/exe"))])
    assert edge.target_resolution == "self_exec"
    assert edge.target_binary is None


# ── de-duplication ────────────────────────────────────────────────────────────────────


def test_identical_callsite_and_token_fold_into_one_counted_row() -> None:
    # Two provenance records for the same callsite and token are one edge with occurrences=2 —
    # never two rows, and never one row that silently forgot the second.
    inv = _inventory(binaries={"web_daemon", "helper"})
    rec = _prov("system", _const("helper -x"))
    edges = _edges([rec, dict(rec, sink_idx=1)], inv)
    assert len(edges) == 1
    assert edges[0].occurrences == 2


def test_two_tokens_at_one_callsite_stay_two_rows() -> None:
    inv = _inventory(binaries={"web_daemon", "helper", "other_tool"})
    edges = _edges(
        [
            _prov(
                "system", {"kind": "multiple", "sources": [_const("helper"), _const("other_tool")]}
            )
        ],
        inv,
    )
    assert {(e.sink_addr, e.target_token) for e in edges} == {
        ("0x11020", "helper"),
        ("0x11020", "other_tool"),
    }


# ── entry sites ───────────────────────────────────────────────────────────────────────


def test_entry_sites_are_keyed_by_the_launched_binary() -> None:
    inv = _inventory(links=[("bin/sh", "sh", "busybox", None)])
    edges = _edges([_prov("execl", _const("/bin/sh"))], inv)
    sites = exec_entry_sites(edges)
    assert list(sites) == ["busybox"]
    assert sites["busybox"][0]["kind"] == "exec_edge"
    assert sites["busybox"][0]["launcher_binary"] == "web_daemon"


def test_unresolved_edges_never_become_entry_sites() -> None:
    # A site placed on the strength of a token that matched nothing would be a fabricated entry.
    edges = _edges([_prov("system", {"kind": "param", "name": "param_1"})])
    assert exec_entry_sites(edges) == {}


# ── shell parsing units ───────────────────────────────────────────────────────────────


def test_boolean_or_is_not_a_pipeline() -> None:
    assert parse_shell_command("helper -a || fallback").piped is False
    assert parse_shell_command("helper -a | tee log").piped is True


def test_parse_of_empty_command_yields_an_empty_first_word() -> None:
    parsed = parse_shell_command("")
    assert (parsed.first_word, parsed.piped, parsed.shell_wrapped) == ("", False, False)


# ── end-to-end: the hunt writes the table, the status, and the capability ─────────────


def _analysis_db(tmp_path: Path, *, with_links: bool = True) -> Path:
    """A minimal analysis.db: a daemon that execs /bin/sh, plus the link making that busybox."""
    db_path = tmp_path / "analysis.db"
    conn = open_db(db_path)
    for bid, name in ((1, "web_daemon"), (2, "busybox")):
        conn.execute(
            "INSERT INTO binaries (id, name, path, sha256) VALUES (?, ?, ?, ?)",
            (bid, name, f"/usr/sbin/{name}", str(bid) * 64),
        )
    conn.execute(
        "INSERT INTO functions (binary_id, name, address, pseudocode, callees, sink_provenance) "
        "VALUES (1, 'handler', '00011000', ?, ?, ?)",
        (
            'void handler(char *p){ execl("/bin/sh", "sh", "-c", p, 0); }',
            json.dumps(["execl"]),
            json.dumps([_prov("execl", _const("/bin/sh"))]),
        ),
    )
    if with_links:
        conn.execute(
            "INSERT INTO fs_symlinks (link_path, link_name, target_raw, target_name, resolved, "
            "corrupt_reason) VALUES ('bin/sh', 'sh', 'busybox', 'busybox', 1, NULL)"
        )
    conn.commit()
    conn.close()
    return db_path


def test_hunt_writes_the_edge_and_the_consumer_reads_it_back(tmp_path: Path) -> None:
    # ★ END-TO-END WIRING, not just the helper: the hunt must flatten the edge into the atlas and
    # the read tool must answer from it. A test of build_exec_edges alone stays green even if the
    # analyzer never calls it.
    #
    # MUTATION (verified RED, 1 failed): in analyzer2.run_analyzer2 comment out
    # `add_exec_edges(atlas, exec_edge_rows, commit=False)` -> launched_by returns 0 edges.
    db = _analysis_db(tmp_path)
    atlas_path = tmp_path / "atlas.db"
    run_analyzer2(db, atlas_path, source_run_id="run1")

    conn = open_atlas(atlas_path)
    try:
        result = launched_by(conn, "busybox", run_id="run1")
    finally:
        conn.close()
    assert result["count"] == 1
    edge = result["edges"][0]
    assert edge["launcher"]["binary"] == "web_daemon"
    assert edge["target_resolution"] == "resolved_symlink"
    assert edge["target_layer"] == "exec_image"
    assert edge["command"]["argv_visibility"] == "structurally_invisible"
    assert result["launcher_binaries"] == ["web_daemon"]


def test_hunt_registers_the_capability_unconditionally(tmp_path: Path) -> None:
    # No edges in this firmware, yet the capability is registered: the pass RAN. Absence of edges
    # is not absence of the capability, and a cross-version comparison relies on the difference.
    #
    # MUTATION (verified RED, 1 failed): in analyzer2.run_analyzer2 delete the
    # `RunCapabilityRow(... "reachability.exec_argv_edge" ...)` entry -> the capability is missing.
    db = tmp_path / "empty.db"
    conn = open_db(db)
    conn.execute("INSERT INTO binaries (id, name, sha256) VALUES (1, 'quiet', ?)", ("c" * 64,))
    conn.commit()
    conn.close()
    atlas_path = tmp_path / "atlas.db"
    run_analyzer2(db, atlas_path, source_run_id="run1")

    conn2 = open_atlas(atlas_path)
    try:
        caps = {
            r[0]
            for r in conn2.execute("SELECT capability FROM run_capability WHERE run_id = 'run1'")
        }
    finally:
        conn2.close()
    assert "reachability.exec_argv_edge" in caps


def test_zero_edge_result_carries_a_visible_scan_status(tmp_path: Path) -> None:
    # ★ An empty answer must not read as "nothing launches this binary". The status row says the
    # pass ran and names what it cannot see — including the thin-wrapper gap.
    #
    # MUTATION (verified RED, 1 failed): in analyzer2.run_analyzer2 drop the
    # `detector_status_rows += _exec_scan_status(...)` line -> statuses come back empty, so an
    # empty result carries no honesty at all.
    db = _analysis_db(tmp_path)
    atlas_path = tmp_path / "atlas.db"
    run_analyzer2(db, atlas_path, source_run_id="run1")

    conn = open_atlas(atlas_path)
    try:
        result = launched_by(conn, "no_such_binary", run_id="run1")
    finally:
        conn.close()
    assert result["count"] == 0
    statuses = result["exec_argv_status"]["statuses"]
    assert statuses, "an empty result with no status reads as a confident 'nothing launches it'"
    assert all(s["scanned"] == 1 for s in statuses)
    note = statuses[0]["unsupported_note"]
    assert "thin command wrapper" in note
    assert "posix_spawn" in note


def test_scan_status_covers_a_binary_that_produced_no_edges(tmp_path: Path) -> None:
    # ★ A binary whose code holds no launch callsite must STILL get a status row. Writing rows only
    # for binaries that produced edges is the silent-gap shape: "no row" and "scanned, found none"
    # would look identical to the reader, and only the second one is trustworthy.
    #
    # MUTATION (verified RED, 1 failed): in analyzer2._exec_scan_status derive the binary set from
    # the edges alone — `binaries = set(found)` in place of
    # `binaries = {f.binary_name for f in all_funcs} | set(found)` -> the quiet binary loses its
    # row, so found_count 0 becomes indistinguishable from never-scanned.
    from treasure_map.lib.hunt.analyzer2 import _exec_scan_status

    db = _analysis_db(tmp_path)
    conn = open_db(db)
    # busybox has code of its own, and none of it launches anything.
    conn.execute(
        "INSERT INTO functions (binary_id, name, address, pseudocode, callees, sink_provenance) "
        "VALUES (2, 'applet_main', '00033000', 'int applet_main(void){ return 0; }', '[]', '[]')"
    )
    conn.commit()
    conn.close()

    atlas_path = tmp_path / "atlas.db"
    run_analyzer2(db, atlas_path, source_run_id="run1")

    conn2 = open_atlas(atlas_path)
    try:
        rows = dict(
            conn2.execute(
                "SELECT binary, found_count FROM detector_scan_status "
                "WHERE detector = 'exec_argv' AND source_run_id = 'run1'"
            ).fetchall()
        )
    finally:
        conn2.close()
    assert rows == {"web_daemon": 1, "busybox": 0}

    # and the same shape holds at the unit level, with no edges at all in the run
    only_quiet = _exec_scan_status([], [_func(name="applet_main", binary="busybox")], "run1")
    assert [(r.binary, r.found_count, r.scanned) for r in only_quiet] == [("busybox", 0, 1)]


def test_exec_edge_grants_an_entry_site_that_can_only_be_found_or_unknown(tmp_path: Path) -> None:
    # ★ THE IRON LAW AT THE SEAM. A launch edge may raise a candidate's entry reading to
    # entry:exec — it may NEVER produce 'blocked'. The evidence layer only knows found/unknown.
    #
    # MUTATION (verified RED, 1 failed): in analyzer2.run_analyzer2 build the entry index without
    # the edges — `entry_index = _load_entry_index(db_path)` -> the candidate reads 'unknown'.
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    for bid, name in ((1, "web_daemon"), (2, "helper")):
        conn.execute(
            "INSERT INTO binaries (id, name, path, sha256) VALUES (?, ?, ?, ?)",
            (bid, name, f"/usr/sbin/{name}", str(bid) * 64),
        )
    # binary 1 launches binary 2 ...
    conn.execute(
        "INSERT INTO functions (binary_id, name, address, pseudocode, callees, sink_provenance) "
        "VALUES (1, 'starter', '00011000', ?, ?, ?)",
        (
            'void starter(void){ system("helper -d"); }',
            json.dumps(["system"]),
            json.dumps([_prov("system", _const("helper -d"))]),
        ),
    )
    # ... and binary 2 holds a command-sink candidate nothing in the rootfs mentions.
    conn.execute(
        "INSERT INTO functions (binary_id, name, address, pseudocode, callees, sink_provenance) "
        "VALUES (2, 'do_work', '00022000', ?, ?, '[]')",
        (
            'void do_work(char *arg){ char cmd[64]; sprintf(cmd, "/bin/ping %s", arg);'
            " system(cmd); }",
            json.dumps(["sprintf", "system"]),
        ),
    )
    conn.commit()
    conn.close()

    atlas_path = tmp_path / "atlas.db"
    run_analyzer2(db, atlas_path, source_run_id="run1")

    from treasure_map.lib.query import triage

    conn3 = open_atlas(atlas_path)
    try:
        reach = {c.function: c.dim("reachability") for c in triage(conn3)}
    finally:
        conn3.close()
    dim = reach["do_work"]
    assert dim.value == "entry:exec"
    assert dim.state != "blocked"
    assert "blocked" not in dim.note


def test_entry_reach_label_joins_several_kinds_in_a_stable_order() -> None:
    # The existing two-kind spelling must not shift when a third kind joins — a stored value, a
    # filter string, and a cross-version comparison all match on it.
    #
    # MUTATION (verified RED, 1 failed): in triage._ENTRY_KIND_LABELS put ("exec_edge", "exec")
    # first -> the combined label becomes 'entry:exec+web+script'.
    from treasure_map.lib.query.triage import _entry_reach_status

    def _fe(*kinds: str) -> str:
        return json.dumps({"entry_reach": {"sites": [{"kind": k} for k in kinds]}})

    assert _entry_reach_status(_fe("web_endpoint", "script_call")) == "entry:web+script"
    assert _entry_reach_status(_fe("exec_edge")) == "entry:exec"
    assert (
        _entry_reach_status(_fe("script_call", "exec_edge", "web_endpoint"))
        == "entry:web+script+exec"
    )
    assert _entry_reach_status(_fe()) == "unknown"


def test_replace_by_run_refreshes_instead_of_doubling(tmp_path: Path) -> None:
    db = _analysis_db(tmp_path)
    atlas_path = tmp_path / "atlas.db"
    run_analyzer2(db, atlas_path, source_run_id="run1")
    run_analyzer2(db, atlas_path, source_run_id="run1")

    conn = open_atlas(atlas_path)
    try:
        (count,) = conn.execute(
            "SELECT COUNT(*) FROM exec_edge WHERE source_run_id='run1'"
        ).fetchone()
    finally:
        conn.close()
    assert count == 1


def test_missing_link_table_degrades_without_failing(tmp_path: Path) -> None:
    # An analysis.db from before the link inventory still hunts; its tokens simply resolve less.
    db = _analysis_db(tmp_path, with_links=False)
    raw = sqlite3.connect(db)
    raw.execute("DROP TABLE fs_symlinks")  # the shape of a db built before the link inventory
    raw.commit()
    raw.close()

    atlas_path = tmp_path / "atlas.db"
    run_analyzer2(db, atlas_path, source_run_id="run1")
    conn = open_atlas(atlas_path)
    try:
        rows = conn.execute("SELECT target_resolution FROM exec_edge").fetchall()
    finally:
        conn.close()
    assert [r[0] for r in rows] == ["unmatched"]
