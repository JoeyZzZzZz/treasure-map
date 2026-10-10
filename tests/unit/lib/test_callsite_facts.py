"""Call-site facts for a diff (lib/diff/callsite_facts, lib/diff/binexport2).

Synthetic data only: a hand-encoded BinExport2 message, a minimal analysis.db, a minimal .BinDiff.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.writer import begin_run
from treasure_map.lib.binary_id import BinaryRow
from treasure_map.lib.diff import binexport2 as bx
from treasure_map.lib.diff import callsite_facts as cf
from treasure_map.lib.hunt.bridge import op_addr_at
from treasure_map.lib.pattern.classes import call_offsets, stub_resolved_name
from treasure_map.lib.storage.connection import open_db

# ── a minimal protobuf encoder (wire format) for synthetic BinExport2 messages ────────────────


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _key(field: int, wire_type: int) -> bytes:
    return _varint(field << 3 | wire_type)


def _ld(field: int, body: bytes) -> bytes:
    return _key(field, 2) + _varint(len(body)) + body


def _insn(
    *,
    address: int | None = None,
    targets: tuple[int, ...] = (),
    raw: bytes | None = b"\x00\x00\x00\x00",
    packed: bool = False,
    extra: bytes = b"",
) -> bytes:
    body = b""
    if address is not None:
        body += _key(1, 0) + _varint(address)
    if packed and targets:
        body += _ld(2, b"".join(_varint(t) for t in targets))
    else:
        body += b"".join(_key(2, 0) + _varint(t) for t in targets)
    body += _key(3, 0) + _varint(7)  # mnemonic_index: an unread field
    if raw is not None:
        body += _ld(5, raw)
    return _ld(5, body + extra)


def _message(*insns: bytes, before: bytes = b"", after: bytes = b"") -> bytes:
    return before + b"".join(insns) + after


# ── T12: the BinExport2 reader ─────────────────────────────────────────────────────────────


def test_implicit_addresses_follow_the_previous_instruction_length() -> None:
    """An instruction written without an address sits right after the previous one: its address is
    the previous address plus the previous raw_bytes length. A jump in the flow carries an explicit
    address again.

    MUTATION (verified RED): advance by a fixed 4 bytes instead of the raw_bytes length -> the
    2-byte instruction's successor lands on the wrong address."""
    data = _message(
        _insn(address=0x1000, raw=b"\x01\x02\x03\x04"),
        _insn(raw=b"\x05\x06"),  # 0x1004
        _insn(targets=(0x2000,), raw=b"\x07\x08\x09\x0a"),  # 0x1006
        _insn(address=0x3000, targets=(0x4000, 0x4010)),  # explicit jump, two targets
        _insn(targets=(0x5000,), packed=True),  # 0x3004, packed encoding
        before=_ld(4, _ld(1, b"mov")),  # a mnemonic table before the instructions
        after=_ld(9, b"a string"),  # and an unrelated field after
    )
    got = [(i.address, i.call_targets) for i in bx.iter_instructions(data)]
    assert got == [
        (0x1000, ()),
        (0x1004, ()),
        (0x1006, (0x2000,)),
        (0x3000, (0x4000, 0x4010)),
        (0x3004, (0x5000,)),
    ]


def test_decode_call_targets_keeps_only_instructions_with_targets(tmp_path: Path) -> None:
    path = tmp_path / "x.BinExport"
    path.write_bytes(
        _message(
            _insn(address=0x1000),
            _insn(targets=(0x2000, 0x2000, 0x3000)),
            _insn(address=0x10, targets=(0x20,)),
        )
    )
    assert bx.decode_call_targets(path) == {
        "00001004": ["00002000", "00003000"],
        "00000010": ["00000020"],
    }


def test_an_instruction_without_raw_bytes_makes_the_next_implicit_address_uncertain() -> None:
    """Without the previous instruction's bytes the next implicit address cannot be reconstructed:
    it is marked uncertain (and its targets dropped) until an explicit address resets it."""
    data = _message(
        _insn(address=0x1000, raw=None),
        _insn(targets=(0x2000,)),  # cannot be placed
        _insn(address=0x1100, targets=(0x3000,)),
    )
    got = [(i.address, i.call_targets) for i in bx.iter_instructions(data)]
    assert got == [(0x1000, ()), (None, (0x2000,)), (0x1100, (0x3000,))]


@pytest.mark.parametrize(
    "data",
    [
        _insn(targets=(1,)),  # the first instruction has no address
        _insn(address=0x1000)[:-2],  # truncated
        _key(5, 3),  # an unsupported (group) wire type
    ],
)
def test_malformed_input_raises(data: bytes) -> None:
    with pytest.raises(bx.BinExportDecodeError):
        list(bx.iter_instructions(data))


def test_unreadable_file_is_a_decode_error(tmp_path: Path) -> None:
    with pytest.raises(bx.BinExportDecodeError):
        bx.decode_call_targets(tmp_path / "missing.BinExport")


# ── T2: call identity ──────────────────────────────────────────────────────────────────────


def _facts(**kw: object) -> cf.BinaryCallFacts:
    base: dict[str, object] = {"stub_names": {}, "unresolved_stubs": set(), "names": {}}
    base.update(kw)
    return cf.BinaryCallFacts(**base)  # type: ignore[arg-type]


def test_identity_rule_order() -> None:
    """MUTATION (verified RED): check the function table before the unresolved-stub set -> a stub
    that is also in the table reads as an ordinary table entry."""
    facts = _facts(
        stub_names={0x400: "system"},
        unresolved_stubs={"00000500"},
        names={
            "helper": ["00001000"],
            "dup": ["00002000", "00003000"],
            "FUN_00000500": ["00000500"],  # a stub that also sits in the function table
        },
    )
    got = {
        t: (i.name, i.addr, i.kind)
        for t in (
            "FUN_00000400",
            "FUN_00000500",
            "helper",
            "dup",
            "FUN_0000abcd",
            "thunk_FUN_0000abcd",
            "printf",
        )
        for i in [cf.derive_identity(t, facts)]
    }
    assert got == {
        "FUN_00000400": ("system", "00000400", "stub_resolved"),
        "FUN_00000500": ("FUN_00000500", "00000500", "stub_unresolved"),
        "helper": ("helper", "00001000", "table_entry"),
        "dup": ("dup", None, "name_ambiguous"),
        "FUN_0000abcd": ("FUN_0000abcd", "0000abcd", "fun_name_parsed"),
        "thunk_FUN_0000abcd": ("thunk_FUN_0000abcd", None, "name_only"),
        "printf": ("printf", None, "name_only"),
    }


@pytest.mark.parametrize(
    ("arch", "raw", "state"),
    [
        ("ARM:LE:32:v7", None, "not_applicable"),
        ("MIPS:BE:32:default", None, "not_determined"),
        ("MIPS:BE:32:default", "{}", "read"),
        ("MIPS:LE:32:default", '{"0x400": "system"}', "read"),
    ],
)
def test_stub_state(arch: str, raw: str | None, state: str) -> None:
    assert cf.stub_state(arch, raw) == state


def _analysis_db(
    path: Path,
    *,
    tokens: list[dict[str, object]],
    arch: str = "MIPS:BE:32:default",
    stub_names: str | None = '{"0x400": "system"}',
    unresolved: list[str] | None = None,
    other_funcs: list[tuple[str, str]] = (),  # type: ignore[assignment]
) -> BinaryRow:
    """A one-binary analysis.db: a caller function holding ``tokens`` plus ``other_funcs``."""
    conn = open_db(path)
    conn.execute(
        "INSERT INTO binaries (id, name, path, sha256, arch, stub_names, pass_version, "
        "last_seen_at, ghidra_ok) VALUES (1, 'libx', '/x/libx', 'feed', ?, ?, 'pv1', "
        "'2026-01-01T00:00:00', 1)",
        (arch, stub_names),
    )
    conn.execute(
        "INSERT INTO functions (binary_id, name, address, pseudocode, call_tokens, "
        "unresolved_external_calls) VALUES (1, 'caller', '0x1000', 'void caller(){}', ?, ?)",
        (json.dumps(tokens), json.dumps(unresolved or [])),
    )
    for name, addr in other_funcs:
        conn.execute(
            "INSERT INTO functions (binary_id, name, address, pseudocode) VALUES (1, ?, ?, 'x')",
            (name, addr),
        )
    conn.commit()
    conn.close()
    return BinaryRow(id=1, name="libx", path="/x/libx", sha256="feed")


def _tok(name: str, op_addr: str, opcode: int = 7, text_off: int = 0) -> dict[str, object]:
    return {"call_token": name, "op_addr": op_addr, "opcode": opcode, "text_off": text_off}


def test_read_side_facts_normalizes_addresses_and_reads_calls_only(tmp_path: Path) -> None:
    """Only CALL tokens (opcode 7) count; ``op_addr`` and the unresolved-stub list are normalized
    before matching (``0x56ff0`` and ``00056ff0`` are one address).

    MUTATION (verified RED): compare the unresolved-stub entries without normalizing them -> the
    stub reads as a parsed FUN_ name instead of an unresolved stub."""
    row = _analysis_db(
        tmp_path / "a.db",
        tokens=[
            _tok("FUN_00000400", "0x1010"),
            _tok("FUN_00056ff0", "0x1020"),
            _tok("helper", "0x1030", opcode=-1),  # the function's own name token: ignored
            _tok("helper", "0x1034"),
        ],
        unresolved=["0x56ff0"],
        other_funcs=[("helper", "0x2000")],
    )
    side = cf.read_side_facts(
        str(tmp_path / "a.db"), row, {"00001010", "00001020", "00001030", "00001034"}
    )
    assert side.state == "read" and side.stub_state == "read" and side.build_hash == "pv1"
    assert side.facts is not None
    got = {
        a: [(i.name, i.addr, i.kind) for i in cf.identities_at(a, side.facts)]
        for a in ("00001010", "00001020", "00001030", "00001034")
    }
    assert got == {
        "00001010": [("system", "00000400", "stub_resolved")],
        "00001020": [("FUN_00056ff0", "00056ff0", "stub_unresolved")],
        "00001030": [],
        "00001034": [("helper", "00002000", "table_entry")],
    }


def test_read_side_facts_states(tmp_path: Path) -> None:
    row = _analysis_db(tmp_path / "a.db", tokens=[_tok("helper", "0x1010")])
    assert cf.read_side_facts(str(tmp_path / "a.db"), row, {"00001010"}).state == "read"
    nobridge = _analysis_db(tmp_path / "n.db", tokens=[])
    assert cf.read_side_facts(str(tmp_path / "n.db"), nobridge, {"00001010"}).state == (
        "bridge_absent"
    )
    no_sha = BinaryRow(id=1, name="libx", path=None, sha256=None)
    assert cf.read_side_facts(str(tmp_path / "a.db"), no_sha, set()).state == "not_read"
    assert cf.read_side_facts(None, row, set()).state == "not_read"
    wrong = BinaryRow(id=1, name="libx", path=None, sha256="other")
    assert cf.read_side_facts(str(tmp_path / "a.db"), wrong, set()).state == "not_read"


def test_facts_json_shapes(tmp_path: Path) -> None:
    row = _analysis_db(tmp_path / "a.db", tokens=[_tok("helper", "0x1010")])
    side = cf.read_side_facts(str(tmp_path / "a.db"), row, {"00001010"})
    assert json.loads(cf.facts_json(side, "00001010", None) or "") == {
        "callees": [{"name": "helper", "addr": None, "kind": "name_only"}],
        "targets": None,
    }
    tg = {"00001010": ["00002000"]}
    assert json.loads(cf.facts_json(side, "00009999", tg) or "") == {"callees": [], "targets": []}
    not_read = cf.SideFacts("not_read", None, None, None)
    assert cf.facts_json(not_read, "00001010", tg) is None


# ── T3: the identity reader and the callsite enumerator agree on which call is which ──────────


def test_every_enumerated_call_resolves_to_its_own_name() -> None:
    """For every call ``call_offsets`` finds to a name (plain or stub-rendered), the bridge token
    at that call resolves — directly, or through the stub table — to that same name.

    MUTATION (verified RED): make ``stub_resolved_name`` match ``FUN_`` anywhere in the token
    (search instead of fullmatch) -> ``thunk_FUN_…`` resolves to a sink it does not call."""
    pc = (
        "void f(void){ system(a); FUN_00000400(b); thunk_FUN_00000400(c); "
        "memcpy(d,e,4); FUN_00000500(f); }"
    )
    stubs = {0x400: "system", 0x500: "memcpy"}
    tokens = []
    for name in ("system", "FUN_00000400", "thunk_FUN_00000400", "memcpy", "FUN_00000500"):
        start = pc.index(name + "(") if name != "FUN_00000400" else pc.index(" FUN_00000400(") + 1
        tokens.append(_tok(name, hex(0x1000 + start), text_off=start))
    tokens_json = json.dumps(tokens)
    for sink in ("system", "memcpy"):
        hits = call_offsets(pc, sink, stubs)
        assert len(hits) == 2, sink
        for paren in hits:
            op = op_addr_at(tokens_json, pc, paren)
            tok = next(t for t in tokens if t["op_addr"] == op)
            name = str(tok["call_token"])
            assert (stub_resolved_name(name, stubs) or name) == sink
    assert stub_resolved_name("thunk_FUN_00000400", stubs) is None


# ── T14: written by the diff, with the pairs, in one transaction ─────────────────────────────


def _bindiff(path: Path, hashes: tuple[str, str], pairs: list[tuple[int, int]]) -> Path:
    path.unlink(missing_ok=True)  # a re-run builds a fresh one, as the toolchain does
    con = sqlite3.connect(path)
    con.execute(
        "CREATE TABLE function (id INTEGER PRIMARY KEY, address1 BIGINT, name1 TEXT, "
        "address2 BIGINT, name2 TEXT, similarity DOUBLE, confidence DOUBLE, "
        "basicblocks INTEGER, edges INTEGER, instructions INTEGER)"
    )
    con.execute(
        "INSERT INTO function VALUES (1, ?, 'caller', ?, 'caller', 0.98, 0.97, 3, 2, 20)",
        (0x1000, 0x1000),
    )
    con.execute(
        "CREATE TABLE basicblock (id INT, functionid INT, address1 BIGINT, address2 BIGINT)"
    )
    con.execute("INSERT INTO basicblock VALUES (1, 1, ?, ?)", (0x1000, 0x1000))
    con.execute("CREATE TABLE instruction (basicblockid INT, address1 BIGINT, address2 BIGINT)")
    for a, b in pairs:
        con.execute("INSERT INTO instruction VALUES (1, ?, ?)", (a, b))
    con.execute("CREATE TABLE file (id INT, filename TEXT, hash CHARACTER(40))")
    con.executemany(
        "INSERT INTO file VALUES (?, ?, ?)", [(1, "before", hashes[0]), (2, "after", hashes[1])]
    )
    con.commit()
    con.close()
    return path


def _diff_fixture(tmp_path: Path) -> sqlite3.Connection:
    """Two runs of one binary; A's candidate calls system at 0x1010, matched to B's 0x1010 where B
    has no candidate but its call tokens record a call to system."""
    for side, sha in (("a", "fa"), ("b", "fb")):
        db = tmp_path / f"{side}.db"
        _analysis_db(db, tokens=[_tok("system", "0x1010")], arch="ARM:LE:32:v7", stub_names=None)
        conn = sqlite3.connect(db)
        conn.execute("UPDATE binaries SET sha256 = ?, path = ?", (sha, str(tmp_path / f"{side}_x")))
        conn.commit()
        conn.close()
        (tmp_path / f"{side}_x").write_bytes(b"\x7fELF")
    atlas = open_atlas(tmp_path / "atlas.db")
    for run, side in (("run_a", "a"), ("run_b", "b")):
        begin_run(
            atlas, run, analysis_db_path=str(tmp_path / f"{side}.db"), tool_version="0.0.1",
            ghidra_version="11.4.3",
        )  # fmt: skip
    atlas.execute("UPDATE run SET build_hash = 'pv1', hunt_commit = 'facefeed'")
    atlas.execute(
        "INSERT INTO pattern (source_class, sink_class, call_sequence_shape, "
        "structural_fingerprint, fingerprint_algo_version) VALUES "
        "('external_input', 'cmd', 's->s', 'fp', 'v1')"
    )
    atlas.execute(
        "INSERT INTO instance (pattern_id, evidence_ref, source_run_id, binary_content_hash, "
        "binary_path, sink_anchor) VALUES (1, 'run_a#deadbeef:00001000@cmd@0x000010', 'run_a', "
        "'fa', '/x/libx', 'system')"
    )
    atlas.commit()
    return atlas


def _run_diff(atlas: sqlite3.Connection, tmp_path: Path, monkeypatch, exports: bool):  # type: ignore[no-untyped-def]
    from treasure_map.lib.config.config import Config
    from treasure_map.lib.diff import driver

    bd = _bindiff(tmp_path / "x.BinDiff", ("fa", "fb"), [(0x1010, 0x1010)])
    if exports:
        for side in ("a", "b"):
            (tmp_path / f"{side}.BinExport").write_bytes(
                _message(_insn(address=0x1010, targets=(0x9000,)))
            )

    monkeypatch.setattr(driver, "_check_toolchain", lambda config: None)
    # the fixture runs were extracted by pipeline pv1 and hunted by commit facefeed; make those the
    # running ones, so both runs are confirmed current
    monkeypatch.setattr(driver, "_current_pass_version", lambda: "pv1")
    monkeypatch.setattr(driver, "_installed_commit", lambda: "facefeed")
    monkeypatch.setattr(
        driver, "_run_binexport", lambda so, cfg, out, side, t: tmp_path / f"{side}.BinExport"
    )
    monkeypatch.setattr(driver, "_run_bindiff", lambda ea, eb, out, t: bd)
    return driver.run_version_diff(atlas, "run_a", "run_b", "libx", config=Config())


def test_the_diff_writes_both_sides_facts_beside_the_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION (verified RED): drop the call-site facts step from ``_persist_success`` -> the
    pair has no facts and diff_meta no state."""
    atlas = _diff_fixture(tmp_path)
    summary = _run_diff(atlas, tmp_path, monkeypatch, exports=True)
    fa, fb = atlas.execute(
        "SELECT facts_a, facts_b FROM instruction_match WHERE diff_id = ?", (summary.diff_id,)
    ).fetchone()
    assert fa is not None and fb is not None, "no call-site facts were written for the pair"
    expect = {
        "callees": [{"name": "system", "addr": None, "kind": "name_only"}],
        "targets": ["00009000"],
    }
    assert json.loads(fa) == expect and json.loads(fb) == expect
    meta = atlas.execute(
        "SELECT callsite_facts_a, callsite_facts_b, callsite_facts_hash_a, callsite_facts_hash_b, "
        "stub_state_a, stub_state_b, diff_ok FROM diff_meta WHERE diff_id = ?",
        (summary.diff_id,),
    ).fetchone()
    assert tuple(meta) == ("read", "read", "pv1", "pv1", "not_applicable", "not_applicable", 1)
    assert summary.warnings == ()


def test_an_undecodable_binexport_leaves_the_diff_ok_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The BinExport targets are additive: a file that cannot be decoded keeps the diff, records
    targets as not decoded (null) and says so in the warnings. A re-run rewrites the facts."""
    atlas = _diff_fixture(tmp_path)
    summary = _run_diff(atlas, tmp_path, monkeypatch, exports=False)
    (fa,) = atlas.execute(
        "SELECT facts_a FROM instruction_match WHERE diff_id = ?", (summary.diff_id,)
    ).fetchone()
    assert json.loads(fa)["targets"] is None
    assert any("call targets not decoded" in w for w in summary.warnings)
    assert (
        atlas.execute(
            "SELECT diff_ok FROM diff_meta WHERE diff_id = ?", (summary.diff_id,)
        ).fetchone()[0]
        == 1
    )
    summary2 = _run_diff(atlas, tmp_path, monkeypatch, exports=True)
    rows = atlas.execute(
        "SELECT facts_a FROM instruction_match WHERE diff_id = ?", (summary2.diff_id,)
    ).fetchall()
    assert len(rows) == 1 and json.loads(rows[0][0])["targets"] == ["00009000"]
