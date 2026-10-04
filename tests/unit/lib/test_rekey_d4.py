# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""D4 rekey: the disposition logic (remap / not_traced / phantom_removed / STOP) and the atomic
apply. Synthetic functions and DBs — no firmware needed."""

from __future__ import annotations

import json

import pytest

from treasure_map.lib.hunt.rekey_d4 import (
    Disposition,
    FuncFacts,
    RekeyStopError,
    disposition_for,
    parse_numbered_ref,
    phantom_offsets,
)


def _tok(pc: str, name: str, nth: int, op_addr: str, opcode: int = 7) -> dict:
    """A bridge call-token for the ``nth`` textual ``name(`` (no space before the paren), whose
    text_off marks the name START, mirroring what the extractor emits."""
    idx = -1
    for _ in range(nth + 1):
        idx = pc.index(name + "(", idx + 1)
    return {"call_token": name, "text_off": idx, "op_addr": op_addr, "opcode": opcode}


def _facts(
    pc: str,
    callees: list[str],
    tokens: list[dict],
    *,
    entry: str = "0x1000",
    body: list | None = None,
    sha: str = "deadbeefca",
    pchash: str = "h1",
    stub: dict[int, str] | None = None,
) -> FuncFacts:
    return FuncFacts(
        address=entry,
        binary_sha256=sha,
        pseudocode=pc,
        pseudocode_hash=pchash,
        callees=json.dumps(callees),
        call_tokens=json.dumps(tokens),
        body_ranges=json.dumps(body if body is not None else [["0x1000", "0x2000"]]),
        stub_names=stub or {},
    )


# ── parse_numbered_ref ───────────────────────────────────────────────────────────────────────────


def test_parse_numbered_ref_and_non_numbered() -> None:
    assert parse_numbered_ref("runx#deadbeef:00401b30@cmd#2") == (
        "runx",
        "deadbeef",
        "00401b30",
        "cmd",
        2,
    )
    # bare, wrapper, and already-offset refs are not numbered per-callsite refs
    assert parse_numbered_ref("runx#deadbeef:00401b30@cmd") is None
    assert parse_numbered_ref("runx#deadbeef:00401b30@cmd_via_wrapper") is None
    assert parse_numbered_ref("runx#deadbeef:00401b30@cmd@0x000480") is None


# ── remap (traced) ───────────────────────────────────────────────────────────────────────────────


def test_disposition_remap_for_a_traced_call() -> None:
    """A real in-body call gets remapped to its address-offset ref, and the ref is confirmed present
    in the re-hunted instances (a cross-check)."""
    pc = "\nint f(char *p)\n\n{\n  system(p);\n  return 0;\n}\n"
    facts = _facts(pc, ["system"], [_tok(pc, "system", 0, "0x1200")])
    # the func address is canonicalized (0x1000 -> 00001000) and the offset is signed/padded
    new_ref = "run#deadbeef:00001000@cmd@0x000200"
    disp = disposition_for(
        "run", "0x1000", "cmd", 0, facts, "h1", {new_ref}, old_sink_anchor="system"
    )
    assert disp == Disposition("remap", new_ref=new_ref)


# ── phantom_removed ──────────────────────────────────────────────────────────────────────────────


def test_disposition_phantom_removed_for_declaration() -> None:
    """A stub-named wrapper's declaration is the #0 enumerated 'call'; it is a phantom, and the
    bridge emits no token there, so it is retired — never remapped onto the real call after it."""
    pc = "\nvoid FUN_00409000(char *p)\n\n{\n  system(p);\n}\n"
    stub = {0x409000: "system"}
    # bridge token only at the REAL system call (op in body); NONE at the declaration
    facts = _facts(
        pc, ["system"], [_tok(pc, "system", 0, "0x1200")], stub=stub, body=[["0x1000", "0x2000"]]
    )
    disp = disposition_for("run", "0x1000", "cmd", 0, facts, "h1", None, old_sink_anchor="system")
    assert disp.kind == "phantom_removed"
    # and the REAL call (index 1 in the strip-off enumeration) remaps normally
    real = disposition_for("run", "0x1000", "cmd", 1, facts, "h1", None, old_sink_anchor="system")
    assert real.kind == "remap"


def test_disposition_phantom_removed_for_string_literal() -> None:
    """`fopen(` inside a message literal is a phantom callsite; no bridge token there -> retired."""
    pc = '\nint f(void)\n\n{\n  syslog(3,"fopen() failed");\n  FILE *q = fopen("/x","r");\n}\n'
    # the real fopen is the 2nd textual `fopen(`; give it a token, none for the literal one
    facts = _facts(pc, ["fopen"], [_tok(pc, "fopen", 1, "0x1400")])
    # strip-off enumeration: index 0 = the literal phantom, index 1 = the real call
    disp = disposition_for(
        "run", "0x1000", "path_sink", 0, facts, "h1", None, old_sink_anchor="fopen"
    )
    assert disp.kind == "phantom_removed"


# ── not_traced ───────────────────────────────────────────────────────────────────────────────────


def test_disposition_not_traced_out_of_body() -> None:
    """A real call whose bridge address falls outside the function body (inlined into a neighbour)
    is not_traced — no offset anchor is forged."""
    pc = "\nint f(char *p)\n\n{\n  memcpy(a, p, 4);\n}\n"
    facts = _facts(pc, ["memcpy"], [_tok(pc, "memcpy", 0, "0x9999")], body=[["0x1000", "0x2000"]])
    disp = disposition_for("run", "0x1000", "copy", 0, facts, "h1", None, old_sink_anchor="memcpy")
    assert disp == Disposition("not_traced", reason="out_of_body")


def test_disposition_not_traced_no_bridge_token() -> None:
    """A real textual call the bridge produced no token for (register-indirect / unrendered) is
    not_traced — never guessed."""
    pc = "\nint f(char *p)\n\n{\n  system(p);\n}\n"
    facts = _facts(pc, ["system"], [])  # no tokens at all
    disp = disposition_for("run", "0x1000", "cmd", 0, facts, "h1", None, old_sink_anchor="system")
    assert disp.kind == "not_traced"


def test_disposition_not_traced_when_pseudocode_hash_moved() -> None:
    """The text moved since the ref was minted (the one known C++ template case), so the ref's index
    can no longer be trusted to land on the same call -> not_traced."""
    pc = "\nint f(char *p)\n\n{\n  system(p);\n}\n"
    facts = _facts(pc, ["system"], [_tok(pc, "system", 0, "0x1200")], pchash="NEW_HASH")
    disp = disposition_for(
        "run", "0x1000", "cmd", 0, facts, "OLD_HASH", None, old_sink_anchor="system"
    )
    assert disp == Disposition("not_traced", reason="pseudocode_hash changed")


# ── STOP (fail-closed) ───────────────────────────────────────────────────────────────────────────


def test_stop_when_phantom_offset_carries_a_bridge_token() -> None:
    """Over-strip guard: a PHANTOM member that has a bridge token means the enumerator removed a
    REAL call. Rather than exempt a real candidate as a phantom, STOP."""
    pc = "\nvoid FUN_00409000(char *p)\n\n{\n  system(p);\n}\n"
    stub = {0x409000: "system"}
    # forge a token at the DECLARATION paren too (as if the bridge saw a call there)
    decl_paren = pc.index("FUN_00409000(") + len("FUN_00409000")
    bad = [
        {
            "call_token": "FUN_00409000",
            "text_off": pc.index("FUN_00409000"),
            "op_addr": "0x1100",
            "opcode": 7,
        },
        _tok(pc, "system", 0, "0x1200"),
    ]
    facts = _facts(pc, ["system"], bad, stub=stub)
    assert decl_paren  # the phantom offset exists
    with pytest.raises(RekeyStopError, match="phantom offset carries a bridge token"):
        disposition_for("run", "0x1000", "cmd", 0, facts, "h1", None, old_sink_anchor="system")


def test_stop_when_index_absent_from_old_enumeration() -> None:
    """An index the producing pass's own enumeration cannot place (neither phantom nor real) means
    the pass genuinely lost the call -> STOP, never a silent drop."""
    pc = "\nint f(char *p)\n\n{\n  system(p);\n}\n"
    facts = _facts(pc, ["system"], [_tok(pc, "system", 0, "0x1200")])
    with pytest.raises(RekeyStopError, match="absent from old enumeration"):
        disposition_for("run", "0x1000", "cmd", 5, facts, "h1", None, old_sink_anchor="system")


def test_stop_when_computed_ref_absent_from_rehunt() -> None:
    """The executor and the re-hunt use the same bridge + enumerator, so a computed new_ref the
    re-hunt did not produce means they disagree -> STOP."""
    pc = "\nint f(char *p)\n\n{\n  system(p);\n}\n"
    facts = _facts(pc, ["system"], [_tok(pc, "system", 0, "0x1200")])
    with pytest.raises(RekeyStopError, match="absent from re-hunt"):
        disposition_for(
            "run",
            "0x1000",
            "cmd",
            0,
            facts,
            "h1",
            {"some#other:ref@cmd@0x0"},
            old_sink_anchor="system",
        )


def test_stop_on_unknown_sink_class() -> None:
    pc = "\nint f(char *p)\n\n{\n  system(p);\n}\n"
    facts = _facts(pc, ["system"], [_tok(pc, "system", 0, "0x1200")])
    with pytest.raises(RekeyStopError, match="unknown sink_class"):
        disposition_for("run", "0x1000", "nonsense", 0, facts, "h1", None, old_sink_anchor="system")


# ── phantom_offsets ──────────────────────────────────────────────────────────────────────────────


def test_phantom_offsets_is_exactly_the_stripped_matches() -> None:
    """PHANTOM is the strip-off minus strip-on offsets — a real direct call never enters it."""
    pc = "\nvoid FUN_00409000(char *p)\n\n{\n  system(p);\n}\n"
    stub = {0x409000: "system"}
    ph = phantom_offsets(pc, {"system"}, stub)
    assert ph == {pc.index("FUN_00409000(") + len("FUN_00409000")}
    # a clean function has no phantom
    clean = "\nint f(void)\n\n{\n  system(x);\n  system(y);\n}\n"
    assert phantom_offsets(clean, {"system"}, {}) == set()


# ── driver: build_mapping + apply_rekey over synthetic atlases + a re-hunted workspace ────────────


def _driver_setup(tmp_path):  # type: ignore[no-untyped-def]
    """A re-hunted workspace analysis.db + an old and a new atlas, wired so one overlay anchor
    remaps and one is left stale. Returns (old_atlas, new_atlas, run_to_workspace, refs)."""

    from treasure_map.lib import overlay
    from treasure_map.lib.analyze.ghidra_ingest import IngestStats, _ingest_one_binary
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.atlas.models import InstanceRow
    from treasure_map.lib.atlas.writer import add_instance, upsert_pattern
    from treasure_map.lib.storage.connection import open_db

    # traced function (remaps) and an out-of-body function (stays stale)
    pc_ok = "\nint f(char *p)\n\n{\n  system(p);\n}\n"
    pc_oob = "\nint g(char *p)\n\n{\n  memcpy(a, p, 4);\n}\n"
    tok_ok = {
        "call_token": "system",
        "text_off": pc_ok.index("system"),
        "op_addr": "0x401200",
        "opcode": 7,
    }
    tok_oob = {
        "call_token": "memcpy",
        "text_off": pc_oob.index("memcpy"),
        "op_addr": "0x99999",  # outside the body range below
        "opcode": 7,
    }
    ws = tmp_path / "ws" / "analysis.db"
    ws.parent.mkdir(parents=True)
    wconn = open_db(ws)
    wconn.execute("INSERT INTO binaries (id, name, sha256) VALUES (1,'b','deadbeefcafe')")
    data = {
        "functions": [
            {
                "name": "f",
                "address": "00401000",
                "pseudocode": pc_ok,
                "callees": ["system"],
                "call_tokens": [tok_ok],
                "body_ranges": [["0x401000", "0x401500"]],
            },
            {
                "name": "g",
                "address": "00402000",
                "pseudocode": pc_oob,
                "callees": ["memcpy"],
                "call_tokens": [tok_oob],
                "body_ranges": [["0x402000", "0x402500"]],
            },
        ]
    }
    _ingest_one_binary(wconn, 1, data, IngestStats(), None)
    wconn.commit()
    hashes = {a: h for a, h in wconn.execute("SELECT address, pseudocode_hash FROM functions")}
    wconn.close()

    old_ref_ok = "run1#deadbeef:00401000@cmd#0"
    old_ref_oob = "run1#deadbeef:00402000@copy#0"
    new_ref_ok = "run1#deadbeef:00401000@cmd@0x000200"

    # old atlas: the two numbered instances with their stored per-instance hashes
    old_atlas = tmp_path / "old.db"
    ocon = open_atlas(old_atlas)
    pid = upsert_pattern(ocon, source_class="param", sink_class="cmd", call_sequence_shape="c")
    for ref, addr, sink in (
        (old_ref_ok, "00401000", "system"),
        (old_ref_oob, "00402000", "memcpy"),
    ):
        add_instance(
            ocon,
            InstanceRow(
                pattern_id=pid,
                source_run_id="run1",
                evidence_ref=ref,
                pseudocode_hash=hashes[addr],
                reachability_status="unknown",
                sink_anchor=sink,
            ),
        )
    ocon.commit()
    ocon.close()

    # new atlas: the re-hunted instance (offset ref) + the two persistent overlay anchors (old refs)
    new_atlas = tmp_path / "new.db"
    ncon = open_atlas(new_atlas)
    npid = upsert_pattern(ncon, source_class="param", sink_class="cmd", call_sequence_shape="c")
    add_instance(
        ncon,
        InstanceRow(
            pattern_id=npid,
            source_run_id="run1",
            evidence_ref=new_ref_ok,
            pseudocode_hash=hashes["00401000"],
            reachability_status="unknown",
        ),
    )
    overlay.upsert_overlay(ncon, evidence_ref=old_ref_ok, verdict="suspicious", rationale="dig")
    overlay.upsert_overlay(ncon, evidence_ref=old_ref_oob, verdict="exploitable", rationale="dig")
    ncon.commit()
    ncon.close()

    return old_atlas, new_atlas, {"run1": ws}, (old_ref_ok, old_ref_oob, new_ref_ok)


def test_driver_remaps_traced_and_leaves_oob_stale(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """End-to-end: the traced overlay anchor is remapped to its offset ref; the out-of-body one is
    left stale (its old ref, now resolving to no instance)."""
    import sqlite3

    from treasure_map.lib.hunt.rekey_d4 import apply_rekey, build_mapping

    old_atlas, new_atlas, r2w, (ok, oob, new_ok) = _driver_setup(tmp_path)
    mapping = build_mapping(old_atlas, new_atlas, r2w)
    assert mapping[ok].kind == "remap"
    assert mapping[ok].new_ref == new_ok
    assert mapping[oob].kind == "not_traced"

    report = apply_rekey(new_atlas, mapping, dry_run=False)
    assert report.overlay_remapped == 1
    assert report.overlay_stale == 1

    con = sqlite3.connect(new_atlas)
    anchors = {r[0] for r in con.execute("SELECT anchor_ref FROM overlay")}
    con.close()
    assert new_ok in anchors  # traced anchor moved to the offset ref
    assert oob in anchors  # OOB anchor left in place (stale, resolves to nothing)
    assert ok not in anchors  # old traced ref is gone


def test_driver_dry_run_writes_nothing(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """dry_run computes the report without touching the overlay anchors."""
    import sqlite3

    from treasure_map.lib.hunt.rekey_d4 import apply_rekey, build_mapping

    old_atlas, new_atlas, r2w, (ok, oob, new_ok) = _driver_setup(tmp_path)
    mapping = build_mapping(old_atlas, new_atlas, r2w)
    report = apply_rekey(new_atlas, mapping, dry_run=True)
    assert report.overlay_remapped == 1

    con = sqlite3.connect(new_atlas)
    anchors = {r[0] for r in con.execute("SELECT anchor_ref FROM overlay")}
    con.close()
    assert ok in anchors and new_ok not in anchors  # unchanged under dry_run


# ── guards and the write path (rekey hardening) ─────────────────────────────────────────────────


def test_a_ref_left_in_place_must_not_still_resolve(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """not_traced / phantom_removed leave the old anchor in place, which is only safe if the ref
    now resolves to nothing. If the re-hunt still carries that exact ref, stop.

    MUTATION (must go RED): drop the "still resolves" check in build_mapping."""
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.atlas.models import InstanceRow
    from treasure_map.lib.atlas.writer import add_instance, upsert_pattern
    from treasure_map.lib.hunt.rekey_d4 import build_mapping

    old_atlas, new_atlas, r2w, (_ok, oob, _new) = _driver_setup(tmp_path)
    con = open_atlas(new_atlas)
    pid = upsert_pattern(con, source_class="param", sink_class="copy", call_sequence_shape="c")
    add_instance(
        con,
        InstanceRow(
            pattern_id=pid, source_run_id="run1", evidence_ref=oob, reachability_status="unknown"
        ),
    )
    con.commit()
    con.close()
    with pytest.raises(RekeyStopError, match="still resolves"):
        build_mapping(old_atlas, new_atlas, r2w)


def test_a_callsite_calling_another_sink_is_not_remapped() -> None:
    """The callee list moved (memcpy dropped from it) while the text did not: the old index now
    lands on the strcpy call. Same hash, valid index, real token — and the wrong call. not_traced.

    MUTATION (must go RED): drop the ``site.sink_name == old_sink_anchor`` check."""
    pc = "\nint f(char *a,char *b)\n\n{\n  memcpy(a,b,4);\n  strcpy(a,b);\n}\n"
    toks = [_tok(pc, "memcpy", 0, "0x1100"), _tok(pc, "strcpy", 0, "0x1200")]
    facts = _facts(pc, ["strcpy"], toks)  # memcpy no longer in the callee list
    disp = disposition_for("run", "0x1000", "copy", 0, facts, "h1", None, old_sink_anchor="memcpy")
    assert disp == Disposition("not_traced", reason="sink name drifted")


def test_a_missing_hash_is_unverifiable_not_a_pass() -> None:
    """Either side's hash missing proves nothing; the index can then not be trusted.

    MUTATION (must go RED): compare hashes only when both are present (the old rule)."""
    pc = "\nint f(char *p)\n\n{\n  system(p);\n}\n"
    facts = _facts(pc, ["system"], [_tok(pc, "system", 0, "0x1200")], pchash=None)  # type: ignore[arg-type]
    for old_hash in ("h1", None):
        disp = disposition_for(
            "run", "0x1000", "cmd", 0, facts, old_hash, None, old_sink_anchor="system"
        )
        assert disp == Disposition("not_traced", reason="pseudocode_hash unverifiable")


def _two_run_setup(tmp_path):  # type: ignore[no-untyped-def]
    """Two runs whose workspaces hold the SAME binary anchor and function address with different
    call addresses (the facts must not be shared between runs)."""
    from treasure_map.lib.analyze.ghidra_ingest import IngestStats, _ingest_one_binary
    from treasure_map.lib.atlas.connection import open_atlas
    from treasure_map.lib.atlas.models import InstanceRow
    from treasure_map.lib.atlas.writer import add_instance, upsert_pattern
    from treasure_map.lib.storage.connection import open_db

    pc = "\nint f(char *p)\n\n{\n  system(p);\n}\n"
    r2w, hashes = {}, {}
    for run, op in (("runa", "0x401200"), ("runb", "0x401300")):
        ws = tmp_path / run / "analysis.db"
        ws.parent.mkdir(parents=True)
        c = open_db(ws)
        c.execute("INSERT INTO binaries (id, name, sha256) VALUES (1,'b','deadbeefcafe')")
        tok = {"call_token": "system", "text_off": pc.index("system"), "op_addr": op, "opcode": 7}
        func = {
            "name": "f",
            "address": "00401000",
            "pseudocode": pc,
            "callees": ["system"],
            "call_tokens": [tok],
            "body_ranges": [["0x401000", "0x401500"]],
        }
        _ingest_one_binary(c, 1, {"functions": [func]}, IngestStats(), None)
        c.commit()
        hashes[run] = c.execute("SELECT pseudocode_hash FROM functions").fetchone()[0]
        c.close()
        r2w[run] = ws
    old_atlas, new_atlas = tmp_path / "old.db", tmp_path / "new.db"
    for path, refs in (
        (old_atlas, ["runa#deadbeef:00401000@cmd#0", "runb#deadbeef:00401000@cmd#0"]),
        (new_atlas, ["runa#deadbeef:00401000@cmd@0x000200", "runb#deadbeef:00401000@cmd@0x000300"]),
    ):
        con = open_atlas(path)
        pid = upsert_pattern(con, source_class="param", sink_class="cmd", call_sequence_shape="c")
        for ref in refs:
            run = ref.split("#", 1)[0]
            add_instance(
                con,
                InstanceRow(
                    pattern_id=pid,
                    source_run_id=run,
                    evidence_ref=ref,
                    pseudocode_hash=hashes[run],
                    reachability_status="unknown",
                    sink_anchor="system",
                ),
            )
        con.commit()
        con.close()
    return old_atlas, new_atlas, r2w


def test_function_facts_are_not_shared_across_runs(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Two runs can carry the same binary and the same function address; each run's ref is read
    against ITS workspace.

    MUTATION (must go RED): key the facts cache by (bin_anchor, func_addr) only."""
    from treasure_map.lib.hunt.rekey_d4 import build_mapping

    old_atlas, new_atlas, r2w = _two_run_setup(tmp_path)
    mapping = build_mapping(old_atlas, new_atlas, r2w)
    assert mapping["runa#deadbeef:00401000@cmd#0"].new_ref == "runa#deadbeef:00401000@cmd@0x000200"
    assert mapping["runb#deadbeef:00401000@cmd#0"].new_ref == "runb#deadbeef:00401000@cmd@0x000300"


def _truth_file(tmp_path, refs):  # type: ignore[no-untyped-def]
    truth = tmp_path / "truth.json"
    body = {
        "meta": {"note": "ledger — local only"},
        "recall": [
            {"id": f"t{i}", "evidence_ref": r, "note": "dig — later"} for i, r in enumerate(refs)
        ],
    }
    truth.write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return truth


def test_a_failed_commit_restores_the_truth_file(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """overlay (SQL) and truth (file) cannot share a transaction: when COMMIT fails after the truth
    file was replaced, the overlay rolls back AND the truth is restored byte-for-byte.

    MUTATION (must go RED): drop the restore-from-backup step."""
    import sqlite3

    from treasure_map.lib.hunt import rekey_d4

    old_atlas, new_atlas, r2w, (ok, _oob, _new) = _driver_setup(tmp_path)
    mapping = rekey_d4.build_mapping(old_atlas, new_atlas, r2w)
    truth = _truth_file(tmp_path, [ok])
    before = truth.read_bytes()

    def boom(conn):  # type: ignore[no-untyped-def]
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(rekey_d4, "_commit", boom)
    with pytest.raises(sqlite3.OperationalError):
        rekey_d4.apply_rekey(new_atlas, mapping, truth_path=truth, dry_run=False)
    assert truth.read_bytes() == before
    con = sqlite3.connect(new_atlas)
    anchors = {r[0] for r in con.execute("SELECT anchor_ref FROM overlay")}
    con.close()
    assert ok in anchors  # overlay rolled back too
    assert not any(p.name.endswith((".rekey_tmp", ".rekey_bak")) for p in tmp_path.iterdir())


def test_a_repoint_that_hits_no_row_stops(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Every remap must re-point exactly one overlay row; anything else stops and writes nothing.

    MUTATION (must go RED): ignore the rowcount returned by repoint_overlay_anchor."""
    import sqlite3

    from treasure_map.lib.hunt import rekey_d4

    old_atlas, new_atlas, r2w, (ok, _oob, _new) = _driver_setup(tmp_path)
    mapping = rekey_d4.build_mapping(old_atlas, new_atlas, r2w)
    monkeypatch.setattr(rekey_d4, "repoint_overlay_anchor", lambda *a, **k: 0)
    with pytest.raises(RekeyStopError, match="hit 0"):
        rekey_d4.apply_rekey(new_atlas, mapping, dry_run=False)
    con = sqlite3.connect(new_atlas)
    assert ok in {r[0] for r in con.execute("SELECT anchor_ref FROM overlay")}
    con.close()


def test_truth_rewrite_keeps_text_and_trailing_newline(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Re-pointing one truth entry leaves every other byte alone: non-ASCII characters stay literal
    (not \\u escapes) and the file keeps its final newline.

    MUTATION (must go RED): write with ensure_ascii's default, or drop the trailing newline."""
    from treasure_map.lib.hunt.rekey_d4 import apply_rekey, build_mapping

    old_atlas, new_atlas, r2w, (ok, _oob, new_ok) = _driver_setup(tmp_path)
    mapping = build_mapping(old_atlas, new_atlas, r2w)
    truth = _truth_file(tmp_path, [ok, "runz#facefeed:00001000@cmd_via_wrapper"])
    expected = truth.read_text(encoding="utf-8").replace(ok, new_ok)
    apply_rekey(new_atlas, mapping, truth_path=truth, dry_run=False)
    assert truth.read_text(encoding="utf-8") == expected
    assert "—" in truth.read_text(encoding="utf-8")


def test_a_remap_target_marked_degraded_stops(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """No per-callsite judgement moves onto a function-level degraded anchor.

    MUTATION (must go RED): drop the degraded-target check in build_mapping."""
    import json
    import sqlite3

    from treasure_map.lib.hunt.rekey_d4 import build_mapping

    old_atlas, new_atlas, r2w, (_ok, _oob, new_ok) = _driver_setup(tmp_path)
    con = sqlite3.connect(new_atlas)
    con.execute(
        "UPDATE instance SET flow_evidence = ? WHERE evidence_ref = ?",
        (json.dumps({"callsite_located": False, "anchor_degraded": "out_of_body"}), new_ok),
    )
    con.commit()
    con.close()
    with pytest.raises(RekeyStopError, match="degraded anchor"):
        build_mapping(old_atlas, new_atlas, r2w)
