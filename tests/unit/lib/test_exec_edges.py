# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
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
    CLASSIFIER_RESOLUTIONS,
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
    binaries: set[str] | dict[str, tuple[str, ...]] | None = None,
    scripts: dict[str, tuple[str, ...]] | None = None,
) -> ExecEdgeInventory:
    """``links`` rows are (link_path, link_name, target_name, corrupt_reason); ``scripts`` maps a
    script basename to the path(s) the inventory holds for it.

    ``binaries`` may be a set of short names — expanded to one synthetic path each, the usual case
    — or a name -> paths mapping when a test needs a name that SEVERAL binaries answer to. The
    inventory holds paths because a short name is a label: two files can share one."""
    if binaries is None:
        binaries = {"web_daemon", "busybox"}
    bin_names = (
        binaries
        if isinstance(binaries, dict)
        else {name: (f"usr/sbin/{name}",) for name in binaries}
    )
    return ExecEdgeInventory(
        symlinks=build_symlink_index(list(links or [])),
        bin_names=bin_names,
        scripts=dict(scripts or {}),
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
    assert edge.target_binary == "usr/sbin/busybox"
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
    # target_binary now holds the PATH: the short name is what could be ambiguous.
    assert (shell_edge.target_token, shell_edge.target_binary) == ("helper", "usr/sbin/helper")
    assert exec_edge.target_layer == "exec_image"
    assert exec_edge.target_binary == "usr/sbin/helper"


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
    assert sorted(e.target_binary for e in edges) == ["usr/sbin/helper", "usr/sbin/other_tool"]


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
    assert sorted(e.target_binary for e in edges) == ["usr/sbin/helper", "usr/sbin/other_tool"]


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
    )


def test_classification_is_total_and_lands_in_exactly_one_of_six_states() -> None:
    # Every input gets exactly one state, and the image over the inputs is the whole six-state set
    # — no input falls through, and no seventh state exists.
    #
    # ★ Six, not eight: the classifier judges the NAME. Whether that name identifies ONE FILE is a
    # question about the inventory, not the token, and is decided at the row builder — see
    # test_a_name_two_binaries_answer_to_resolves_no_target.
    #
    # MUTATION (verified RED, 1 failed): in exec_edges.classify_target_resolution delete the final
    # `return UNMATCHED` and let the function fall off the end -> the unmatched inputs come back
    # None, so the image is no longer a subset of the six states.
    produced = {_classify(spec) for spec in _CLASSIFY_INPUTS}
    assert produced <= CLASSIFIER_RESOLUTIONS
    assert produced == CLASSIFIER_RESOLUTIONS  # the fixtures cover every state
    assert CLASSIFIER_RESOLUTIONS < TARGET_RESOLUTIONS  # the column holds strictly more
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
    #      0, so "the link IS there" is gone entirely.
    inv = _inventory(
        links=[("bin/tool_x", "tool_x", "helper_tool", None)],
        binaries={"web_daemon", "busybox"},
    )
    (edge,) = _edges([_prov("system", _const("tool_x --run"))], inv)
    assert edge.target_resolution == "unmatched"
    assert edge.symlink_target_unresolved == 1
    assert (edge.symlink_ambiguous, edge.symlink_corrupt) == (0, 0)
    assert edge.target_binary is None


def test_script_target_resolves_but_never_grants_an_entry_site() -> None:
    inv = _inventory(binaries={"web_daemon"}, scripts={"restart.sh": ("etc/init.d/restart.sh",)})
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
    # keyed by PATH — a short-name key would offer the site to every binary of that name
    assert list(sites) == ["usr/sbin/busybox"]
    assert sites["usr/sbin/busybox"][0]["kind"] == "exec_edge"
    assert sites["usr/sbin/busybox"][0]["launcher_binary"] == "web_daemon"


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


# ── launched scripts: recognition, addressability, and the multi-candidate boundary ───


def test_a_script_without_a_dot_sh_suffix_still_resolves() -> None:
    # ★ C1. A script invoked as a program is usually the one with NO suffix — an init.d entry, an
    # sbin helper. Demanding `.sh` on top of inventory membership pushed those into `unmatched`,
    # which reads as "I do not recognize this token" about a file the inventory holds by name.
    #
    # MUTATION (verified RED, 1 failed): in exec_edges.classify_target_resolution restore the
    # suffix gate — `if in_non_binary and token.endswith(".sh"):` — and this token falls to
    # 'unmatched'.
    inv = _inventory(binaries={"web_daemon"}, scripts={"getmac": ("usr/sbin/getmac",)})
    (edge,) = _edges([_prov("system", _const("getmac eth0"))], inv)
    assert edge.target_resolution == "resolved_script"


def test_single_path_script_records_the_path_so_the_edge_is_answerable() -> None:
    # ★ A2. A resolved script edge used to leave target_binary NULL, so the read tool — which looks
    # up by that column — could never answer for a script. The path is what gets recorded, not the
    # token: a third of these tokens are bare, and storing whichever spelling the callsite happened
    # to use would fill one column with two kinds of key.
    #
    # MUTATION (verified RED, 1 failed): in exec_edges._build_row delete the
    # `elif resolution == RESOLVED_SCRIPT and len(script_paths) == 1:` branch -> target_binary is
    # None again and the edge is unanswerable.
    inv = _inventory(binaries={"web_daemon"}, scripts={"getmac": ("usr/sbin/getmac",)})
    (edge,) = _edges([_prov("system", _const("/usr/sbin/getmac eth0"))], inv)
    assert (edge.target_resolution, edge.target_binary) == ("resolved_script", "usr/sbin/getmac")


def test_a_name_held_by_several_scripts_is_left_unpicked() -> None:
    # ★ The multi-candidate boundary. Two directories hold genuinely different scripts under one
    # name. The edge still says "a script resolved" — that much is known — but names none of them:
    # picking one would be a guess, and the candidates stay recoverable by looking the basename up
    # in the script inventory.
    #
    # MUTATION (verified RED, 1 failed): in exec_edges._build_row drop the single-path condition —
    # `elif resolution == RESOLVED_SCRIPT and script_paths:` with `target_binary = script_paths[0]`
    # -> one of the two candidates is silently chosen.
    inv = _inventory(
        binaries={"web_daemon"},
        scripts={"led_ctl": ("etc/init.d/led_ctl", "usr/sbin/led_ctl")},
    )
    (edge,) = _edges([_prov("system", _const("led_ctl on"))], inv)
    assert edge.target_resolution == "resolved_script"
    assert edge.target_binary is None


def test_script_edge_answers_to_both_its_short_name_and_its_path(tmp_path: Path) -> None:
    # ★ A2-r. Storing scripts by path makes the lookup key heterogeneous: binaries answer to a
    # short name, scripts to a path. A reader asking `launched_by("getmac")` would get 0 rows and
    # read it as "nothing launches it" — the exact misreading this whole surface exists to prevent.
    # A short name is therefore matched against the stored path's basename as well.
    #
    # MUTATION (verified RED, 1 failed): in query/exec_edges.launched_by drop the alternative —
    # `where = ["target_binary = ?"]` with a single param -> the short-name query returns 0.
    from treasure_map.lib.atlas.models import ExecEdgeRow
    from treasure_map.lib.atlas.writer import add_exec_edges

    conn = open_atlas(tmp_path / "atlas.db")
    try:
        add_exec_edges(
            conn,
            [
                ExecEdgeRow(
                    source_run_id="run1",
                    launcher_binary="web_daemon",
                    launcher_function="starter",
                    exec_api="system",
                    target_token="getmac",
                    target_resolution="resolved_script",
                    target_binary="usr/sbin/getmac",
                )
            ],
        )
        assert launched_by(conn, "getmac", run_id="run1")["count"] == 1
        assert launched_by(conn, "usr/sbin/getmac", run_id="run1")["count"] == 1
        # exact basename comparison, never a suffix match
        assert launched_by(conn, "mac", run_id="run1")["count"] == 0
        assert launched_by(conn, "foogetmac", run_id="run1")["count"] == 0
    finally:
        conn.close()


# ── looking an edge up by the spelling a reader actually has ──────────────────────────


def _edge_row(**kw: Any) -> Any:
    from treasure_map.lib.atlas.models import ExecEdgeRow

    base: dict[str, Any] = {
        "source_run_id": "run1",
        "launcher_binary": "web_daemon",
        "launcher_function": "starter",
        "exec_api": "system",
        "target_resolution": "resolved_direct",
    }
    return ExecEdgeRow(**{**base, **kw})


def _seeded_atlas(tmp_path: Path) -> Any:
    """One edge of each storage shape, plus two decoys a sloppy match would grab."""
    from treasure_map.lib.atlas.writer import add_exec_edges

    conn = open_atlas(tmp_path / "atlas.db")
    add_exec_edges(
        conn,
        [
            # a script: stored by its root-relative path, the token as the code wrote it
            _edge_row(
                target_token="/usr/sbin/webs_update.sh",
                target_binary="usr/sbin/webs_update.sh",
                target_resolution="resolved_script",
            ),
            # a binary: stored by short name, the token again as the code wrote it
            _edge_row(target_token="/usr/sbin/pluginmanager", target_binary="pluginmanager"),
            # a symlink-renamed target: no spelling of the token is the stored name
            _edge_row(
                target_token="/bin/sh",
                target_binary="busybox",
                target_resolution="resolved_symlink",
            ),
            # decoys: only a prefix/suffix match would return these
            _edge_row(target_token="foopluginmanager", target_binary="foopluginmanager"),
            _edge_row(target_token="manager", target_binary="manager"),
        ],
    )
    return conn


def test_a_token_copied_verbatim_out_of_an_edge_finds_that_edge(tmp_path: Path) -> None:
    # ★ P1. The spelling a reader has in hand is the edge's own target_token — the code's own text,
    # so it carries a leading slash. Targets are stored the way the inventory holds them, which
    # never does. Both stored shapes must answer that query, or the reader gets a zero and reads it
    # as "nothing launches this" — the misreading this whole surface exists to prevent.
    #
    # MUTATIONS (each verified RED, 1 failed): in query/exec_edges.launched_by delete
    #  (a) the second comparison and its `query_unrooted` param -> the script query returns 0;
    #  (b) the third comparison and its `query_basename` param -> the binary query returns 0.
    conn = _seeded_atlas(tmp_path)
    try:
        assert launched_by(conn, "/usr/sbin/webs_update.sh")["count"] == 1  # stored relative
        assert launched_by(conn, "/usr/sbin/pluginmanager")["count"] == 1  # stored short
        # the stored spellings keep working, unchanged
        assert launched_by(conn, "usr/sbin/webs_update.sh")["count"] == 1
        assert launched_by(conn, "pluginmanager")["count"] == 1
        # a short name still reaches a script stored by path
        assert launched_by(conn, "webs_update.sh")["count"] == 1
    finally:
        conn.close()


def test_a_symlink_renamed_target_answers_zero_and_says_where_to_look(tmp_path: Path) -> None:
    # ★ The one case that stays at zero on purpose: no spelling of `/bin/sh` is `busybox`. Guessing
    # would mean resolving links at read time, which is the write side's job and was already done —
    # the edge carries both names. The docstring points at target_binary rather than leaving the
    # reader with an unexplained empty.
    conn = _seeded_atlas(tmp_path)
    try:
        assert launched_by(conn, "/bin/sh")["count"] == 0
        assert launched_by(conn, "busybox")["count"] == 1  # the exit named in the docstring
    finally:
        conn.close()
    assert "target_binary" in launched_by.__doc__
    assert "symlink" in launched_by.__doc__.lower()


def test_the_overlay_path_mismatch_is_documented_with_its_way_out() -> None:
    # ★ A launched script is stored under the path the extraction produced, whose first segment can
    # differ from the runtime path the code names (an overlay `rom/` prefix). No spelling of one is
    # the other, so a logical-path token answers zero — measured on a real firmware, a handful of
    # edges. The prefix is not stripped automatically: it differs per firmware and per extraction,
    # so there is nothing exact to strip and a loose pattern would be guessing. What makes that
    # acceptable is that the way out is WRITTEN DOWN, so the zero is never left unexplained.
    #
    # MUTATION (verified RED, 1 failed): delete the overlay paragraph from launched_by's docstring
    # -> the zero has no documented exit again.
    doc = launched_by.__doc__ or ""
    assert "overlay" in doc.lower()
    assert "SHORT NAME" in doc
    assert "does not guess" in doc


def test_lookup_never_matches_on_a_prefix_or_suffix(tmp_path: Path) -> None:
    # Every comparison is exact equality. The decoys differ from the query by a prefix and by a
    # path segment, and both must stay out — a widened match would attribute another binary's
    # launcher to this one.
    #
    # MUTATION (verified RED, 1 failed): in query/exec_edges.launched_by widen the first comparison
    # to `target_binary LIKE '%' || ?` -> the foopluginmanager decoy is returned too.
    conn = _seeded_atlas(tmp_path)
    try:
        assert launched_by(conn, "pluginmanager")["count"] == 1
        assert launched_by(conn, "/usr/sbin/pluginmanager")["count"] == 1
        assert launched_by(conn, "manager")["count"] == 1  # the decoy answers only to itself
    finally:
        conn.close()


def test_a_short_name_query_is_one_comparison_repeated(tmp_path: Path) -> None:
    # A query with no slash collapses all three spellings to the same string, so the added
    # comparisons cannot change what a short-name lookup returns — the property that makes this
    # safe to widen. Asserted on the queries themselves rather than on a remembered count.
    import posixpath

    for name in ("busybox", "sh", "pluginmanager", "manager"):
        assert name == name.lstrip("/") == posixpath.basename(name)
    conn = _seeded_atlas(tmp_path)
    try:
        got = {e["target_binary"] for e in launched_by(conn, "busybox")["edges"]}
        assert got == {"busybox"}
    finally:
        conn.close()


# ── the scan status carries its detail where it is actually read ──────────────────────


def test_status_detail_rides_only_with_an_empty_answer(tmp_path: Path) -> None:
    # ★ The per-binary rows are read in exactly one situation: the answer came back empty and the
    # reader wants to know whether the launcher they suspect was even scanned. With an answer in
    # hand nobody reads them, and a real atlas has enough of them to bury the answer. The totals
    # ride along either way, so "did this pass cover anything" is always answerable.
    #
    # ★ The rows are WITHHELD when unread, never summarised away: an empty answer still returns
    # every one of them. Replacing them with the totals would leave a reader unable to tell
    # "scanned and found nothing" from "never scanned".
    #
    # MUTATION (verified RED, 1 failed): in query/exec_edges.launched_by pass
    # `per_binary=True` unconditionally -> the non-empty answer carries the detail again.
    from treasure_map.lib.atlas.models import DetectorScanStatusRow
    from treasure_map.lib.atlas.writer import add_detector_status

    conn = _seeded_atlas(tmp_path)
    try:
        add_detector_status(
            conn,
            [
                DetectorScanStatusRow("run1", "web_daemon", "exec_argv", 1, "scope", "note", 0, 5),
                DetectorScanStatusRow("run1", "quiet_lib", "exec_argv", 1, "scope", "note", 0, 0),
            ],
        )
        answered = launched_by(conn, "pluginmanager")
        empty = launched_by(conn, "nothing_launches_this")

        assert answered["count"] == 1
        assert "statuses" not in answered["exec_argv_status"]
        assert answered["exec_argv_status"]["scanned_total"] == 2
        assert answered["exec_argv_status"]["found_total"] == 5
        # the shared note stays in both shapes — it is what makes an empty answer readable
        assert answered["exec_argv_status"]["unsupported_note"] == "note"

        assert empty["count"] == 0
        assert [s["binary"] for s in empty["exec_argv_status"]["statuses"]] == [
            "web_daemon",
            "quiet_lib",
        ]
        assert empty["exec_argv_status"]["scanned_total"] == 2
        # a scanned-but-found-nothing binary is still listed: that is the evidence that an empty
        # answer about it is trustworthy, and dropping it would erase the distinction
        assert {"binary": "quiet_lib", "scanned": 1, "cap_hit": False, "found_count": 0} in empty[
            "exec_argv_status"
        ]["statuses"]
    finally:
        conn.close()


# ── recovering a program name from a built command template ───────────────────────────


def test_constant_argument_is_substituted_back_into_the_template() -> None:
    # ★ B1. `snprintf(buf, "%s '%s'", "/usr/sbin/tool -j", user)` builds a command whose first word
    # is a conversion, so the template alone resolves to nothing — while the program name sits
    # right there as a constant argument. Substituting the constants recovers it.
    #
    # The runtime argument is deliberately NOT substituted: its conversion stays, the visibility
    # still reports a placeholder, and no target is claimed for a value nobody has seen.
    #
    # MUTATION (verified RED, 1 failed): in exec_edges._arg_values stop substituting —
    # `out.append(fmt)` in place of `out.append(_substitute_constant_args(fmt, ...))` -> the first
    # word is '%s' and the target goes unresolved.
    inv = _inventory(binaries={"web_daemon", "tool"})
    prov = {
        "kind": "stack_buf",
        "stack_key": "sp-0x40",
        "writers": [
            {
                "writer": "snprintf@0x1",
                "dominates_sink": True,
                "fmt": "%s '%s'",
                "varargs": [
                    {"pos": 3, "spec": "%s", "source": _const("/usr/sbin/tool -j")},
                    {"pos": 4, "spec": "%s", "source": {"kind": "param", "name": "user"}},
                ],
            }
        ],
    }
    (edge,) = _edges([_prov("system", prov)], inv)
    assert edge.target_token == "/usr/sbin/tool"
    assert edge.target_binary == "usr/sbin/tool"
    assert edge.argv_visibility == "known_with_placeholder"
    assert edge.argv_template == "/usr/sbin/tool -j '%s'"


def test_a_runtime_first_word_is_never_fabricated() -> None:
    # The mirror of the above: when the first conversion's argument is NOT a constant, nothing is
    # substituted there and the target stays honestly unresolved. Substituting it would invent a
    # program name out of a value nobody has seen.
    #
    # ★ The load-bearing case is the SECOND one below. A parameter source carries no value at all,
    # so even a broken filter could not substitute it. A constant the extractor confirms but could
    # NOT read out as text does carry a value — the string "0x8f20" — and pasting that in would
    # name a program that does not exist. That is the fabrication the readable-constant test stops.
    #
    # MUTATION (verified RED, 1 failed): in exec_edges._substitute_constant_args delete
    # `if not isinstance(source, dict) or source.get("value_kind") != "literal_string": continue`
    # -> the unreadable constant is pasted in as if it were a name and the template becomes
    # "0x8f20 -j".
    inv = _inventory(binaries={"web_daemon", "tool"})

    def _writer(source: dict[str, Any]) -> dict[str, Any]:
        return {
            "kind": "stack_buf",
            "writers": [
                {
                    "writer": "snprintf@0x1",
                    "dominates_sink": True,
                    "fmt": "%s -j",
                    "varargs": [{"pos": 3, "spec": "%s", "source": source}],
                }
            ],
        }

    (from_param,) = _edges([_prov("system", _writer({"kind": "param", "name": "p"}))], inv)
    assert from_param.target_resolution == "unresolved"

    unreadable = {"kind": "constant", "value": "0x8f20", "value_kind": "ambiguous_0x"}
    (from_unreadable,) = _edges([_prov("system", _writer(unreadable))], inv)
    assert from_unreadable.target_resolution == "unresolved"
    assert from_unreadable.argv_template == "%s -j"


def test_substitution_maps_conversions_to_arguments_by_the_shared_scanner() -> None:
    # A local count of '%' characters gets the mapping wrong the moment a format uses %% or a
    # *-supplied width — and putting a constant at the wrong offset names the WRONG program, which
    # is worse than naming none. The mapping comes from the scanner the read layer already uses.
    #
    # MUTATION (verified RED, 1 failed): in exec_edges._substitute_constant_args drop the star
    # guard — remove `or conv.stars` from the skip condition -> the *-width case substitutes at the
    # wrong offset and the recovered token changes.
    from treasure_map.lib.hunt.exec_edges import _substitute_constant_args

    args = [
        {"source": _const("AAA")},
        {"source": _const("BBB")},
        {"source": _const("CCC")},
    ]
    # %% consumes nothing, so the first conversion still takes argument 0
    assert _substitute_constant_args("100%% %s", args) == "100%% AAA"
    # a *-width consumes an argument of its own before the conversion
    assert _substitute_constant_args("%*s", args) == "%*s"
    assert _substitute_constant_args("%s %s", args) == "AAA BBB"
    # a %d is a number, never a program name
    assert _substitute_constant_args("%d %s", args) == "%d BBB"


def test_shared_scanner_and_the_read_layer_agree_on_arity() -> None:
    # The scanner is shared precisely so these cannot drift; an off-by-one does not fail loudly, it
    # silently attributes the wrong argument to a conversion.
    from treasure_map.lib.fmt_spec import arity, conversions
    from treasure_map.lib.query.triage import _fmt_arity

    for fmt, expected in [
        ("", 0),
        ("no conversions", 0),
        ("%s", 1),
        ("%%", 0),
        ("100%% done: %s", 1),
        ("%*s", 2),
        ("%-10.*s %s", 3),
        ("%ld %s", 2),
        ("trailing %", 0),
    ]:
        assert arity(fmt) == expected, fmt
        assert _fmt_arity(fmt) == expected, fmt
    # every conversion's arg_index is below the arity it reports
    for conv in conversions("%-10.*s %s %d"):
        assert conv.arg_index < arity("%-10.*s %s %d")


# ── end-to-end: the hunt writes the table, the status, and the capability ─────────────


def _analysis_db(tmp_path: Path, *, with_links: bool = True) -> Path:
    """A minimal analysis.db: a daemon that execs /bin/sh, plus the link making that busybox."""
    db_path = tmp_path / "analysis.db"
    conn = open_db(db_path)
    for bid, name in ((1, "web_daemon"), (2, "busybox")):
        conn.execute(
            # last_seen_at is LOAD-BEARING: the exec inventory reads current_binaries, which
            # selects on MAX(last_seen_at); NULL never equals NULL, so omitting it empties the
            # inventory and every token reads as unmatched.
            "INSERT INTO binaries (id, name, path, sha256, last_seen_at) "
            "VALUES (?, ?, ?, ?, '2026-01-01T00:00:00')",
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


def test_hunt_wires_the_script_inventory_end_to_end(tmp_path: Path) -> None:
    # ★ END-TO-END WIRING for the script path. Every other script test builds the inventory by
    # hand, so all of them stay green even if the hunt never loads a path out of analysis.db — the
    # classic shape where the library is tested and the wiring is not. This one goes through the
    # real loader: a shell_script row with a path, a caller that launches it by bare name, and a
    # read tool that answers for it.
    #
    # MUTATION (verified RED, 1 failed): in analyzer2._load_exec_inventory drop the paths —
    # `scripts={k: () for k in scripts}` in place of the sorted-tuple mapping -> the edge resolves
    # but carries no target_binary, so launched_by answers 0.
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256) VALUES (1, 'web_daemon', "
        "'/usr/sbin/web_daemon', ?)",
        ("d" * 64,),
    )
    conn.execute(
        "INSERT INTO functions (binary_id, name, address, pseudocode, callees, sink_provenance) "
        "VALUES (1, 'starter', '00011000', ?, ?, ?)",
        (
            'void starter(void){ system("getmac eth0"); }',
            json.dumps(["system"]),
            json.dumps([_prov("system", _const("getmac eth0"))]),
        ),
    )
    # a launched script with NO .sh suffix — the shape the suffix gate used to hide
    conn.execute(
        "INSERT INTO non_binary_files (kind, name, path, sha256) "
        "VALUES ('shell_script', 'getmac', 'usr/sbin/getmac', ?)",
        ("e" * 64,),
    )
    conn.commit()
    conn.close()

    atlas_path = tmp_path / "atlas.db"
    run_analyzer2(db, atlas_path, source_run_id="run1")

    conn2 = open_atlas(atlas_path)
    try:
        rows = conn2.execute(
            "SELECT target_resolution, target_binary FROM exec_edge WHERE source_run_id='run1'"
        ).fetchall()
        by_short = launched_by(conn2, "getmac", run_id="run1")
        by_path = launched_by(conn2, "usr/sbin/getmac", run_id="run1")
    finally:
        conn2.close()
    assert [tuple(r) for r in rows] == [("resolved_script", "usr/sbin/getmac")]
    assert by_short["count"] == 1, "a reader asking by short name must not get a silent 0"
    assert by_path["count"] == 1


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
    status = result["exec_argv_status"]
    assert status["statuses"], "an empty result with no status reads as a confident 'none'"
    assert all(s["scanned"] == 1 for s in status["statuses"])
    # ★ The note and the scope describe the PASS, so they are carried ONCE at the top rather than
    # copied onto every binary — on a real atlas that copy made the status several times the size
    # of the answer it annotates, and pushed a count:0 result over the response limit.
    note = status["unsupported_note"]
    assert "thin command wrapper" in note
    assert "posix_spawn" in note
    assert status["supported_scope"]
    assert not any("unsupported_note" in s for s in status["statuses"]), (
        "the shared note must not be duplicated per binary"
    )
    assert set(status["statuses"][0]) == {"binary", "scanned", "cap_hit", "found_count"}


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
            # last_seen_at is LOAD-BEARING: the exec inventory reads current_binaries, which
            # selects on MAX(last_seen_at); NULL never equals NULL, so omitting it empties the
            # inventory and every token reads as unmatched.
            "INSERT INTO binaries (id, name, path, sha256, last_seen_at) "
            "VALUES (?, ?, ?, ?, '2026-01-01T00:00:00')",
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


# ── a short name two binaries answer to resolves no target ────────────────────────────


def test_a_name_two_binaries_answer_to_resolves_no_target() -> None:
    """★ The name resolved; the FILE did not.

    ``target_binary`` is what a reader follows to open the launched program. Storing the bare short
    name meant an edge pointing at a name two files answer to — follow it and you land on whichever
    one you happen to look up. When the inventory holds several paths under the name, no target is
    recorded and the state says which half succeeded, so the edge is still there as a launch FACT
    while the target is honestly undecided.

    MUTATION: keep ``target_binary = base`` (the short name) -> RED, both because the target is no
    longer None and because the state stays ``resolved_direct``.
    """
    inv = _inventory(
        binaries={"helper": ("usr/sbin/helper", "opt/bin/helper"), "solo": ("bin/solo",)}
    )
    edges = _edges([_prov("system", _const("helper -d"))], inventory=inv)
    assert len(edges) == 1
    assert edges[0].target_resolution == "ambiguous_direct"
    assert edges[0].target_binary is None
    assert edges[0].target_token == "helper"  # the launch itself is still recorded

    # the counterpart: one path under the name -> the path IS the target
    solo = _edges([_prov("system", _const("solo -x"))], inventory=inv)
    assert (solo[0].target_resolution, solo[0].target_binary) == ("resolved_direct", "bin/solo")


def test_a_symlink_landing_on_an_ambiguous_name_resolves_no_target() -> None:
    """One hop on, same rule: the link's target NAME is held by several files.

    MUTATION: take ``match.matched_targets[0]`` as the target again -> RED.
    """
    inv = _inventory(
        links=[("bin/sh", "sh", "busybox", None)],
        binaries={"busybox": ("bin/busybox", "usr/bin/busybox")},
    )
    edges = _edges([_prov("execl", _const("/bin/sh"))], inventory=inv)
    assert edges[0].target_resolution == "ambiguous_symlink_target"
    assert edges[0].target_binary is None


def test_an_ambiguous_target_grants_no_entry_site() -> None:
    """An entry site says "this binary is launched here". With the file undecided, offering the
    site to every namesake would be entry evidence for a program nobody launches.

    MUTATION: add the two ambiguous states to ``enters_entry_reach`` -> RED.
    """
    for state in ("ambiguous_direct", "ambiguous_symlink_target"):
        assert enters_entry_reach(state) is False
    inv = _inventory(binaries={"helper": ("usr/sbin/helper", "opt/bin/helper")})
    assert exec_entry_sites(_edges([_prov("system", _const("helper -d"))], inventory=inv)) == {}
