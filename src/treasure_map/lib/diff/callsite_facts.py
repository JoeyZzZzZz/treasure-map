# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Call-site facts for a diff: WHAT the instruction at a matched address calls, on each side.

BinDiff pairs instructions by position and says nothing about what they call. When the sink overlay
lines a candidate's call up with an instruction on the other side that is NOT a candidate, the
callee there is only knowable from the other run's own extraction. This module derives it, for the
instruction_match addresses only, from that run's analysis.db (read-only), and stores it beside the
pair, together with the call targets the side's BinExport recorded.

IDENTITY of one CALL token (``call_tokens`` entry with opcode 7; its ``op_addr`` is the call
instruction's own address), first rule that applies:

1. ``stub_resolved``   the token is exactly ``FUN_<hex>`` and the binary's stub table resolves that
                       address: the import's name, at the stub's address.
2. ``stub_unresolved`` ``FUN_<hex>`` at an address this binary recorded as an unresolved stub call.
                       Checked BEFORE the function table: a stub can also sit in that table.
3. ``table_entry``     exactly one function of that name in this binary: its entry address.
4. ``name_ambiguous``  two or more functions of that name: the name, no address.
5. ``fun_name_parsed`` ``FUN_<hex>`` not in the table: the address the name spells.
6. ``name_only``       the name and nothing else.

Every address is normalized with ``refs._norm_addr`` before it is compared or used as a key — the
extractor writes ``op_addr`` and the unresolved-stub list unpadded (``0x56ff0``), and an
unnormalized key would simply never match, without any error.

This is a FACT about what the call token names, never a verdict; an address with no identity says
only that no CALL token was recorded there (a register-indirect call leaves none), not that the
instruction is not a call.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from treasure_map.lib.atlas.writer import set_callsite_facts_state, set_instruction_match_facts
from treasure_map.lib.binary_id import BinaryRow
from treasure_map.lib.facts import analysis_run_counts
from treasure_map.lib.hunt.refs import _norm_addr
from treasure_map.lib.pattern.classes import stub_resolved_name

KIND_STUB_RESOLVED = "stub_resolved"
KIND_STUB_UNRESOLVED = "stub_unresolved"
KIND_TABLE_ENTRY = "table_entry"
KIND_NAME_AMBIGUOUS = "name_ambiguous"
KIND_FUN_NAME_PARSED = "fun_name_parsed"
KIND_NAME_ONLY = "name_only"

FACTS_READ = "read"
FACTS_BRIDGE_ABSENT = "bridge_absent"
FACTS_NOT_READ = "not_read"

STUB_NOT_APPLICABLE = "not_applicable"
STUB_NOT_DETERMINED = "not_determined"
STUB_READ = "read"

_CALL_OPCODE = 7
_FUN_RE = re.compile(r"FUN_([0-9a-fA-F]+)")


@dataclass(frozen=True)
class CallIdentity:
    name: str
    addr: str | None  # normalized hex, or None when the rule gives no address
    kind: str

    def as_json(self) -> dict[str, Any]:
        return {"name": self.name, "addr": self.addr, "kind": self.kind}


@dataclass
class BinaryCallFacts:
    """One binary's inputs to identity derivation, read once per diff side."""

    stub_names: dict[int, str]  # resolved stub entry -> import name ({} when none)
    unresolved_stubs: set[str]  # normalized addresses of unresolved stub calls
    names: dict[str, list[str]]  # function name -> normalized entry addresses
    tokens_at: dict[str, list[str]] = field(default_factory=dict)  # wanted addr -> CALL tokens


def stub_state(arch: str | None, stub_names_raw: str | None) -> str:
    """The stub table's state: ``not_applicable`` off MIPS (no lazy-binding stub table is built);
    on MIPS ``not_determined`` when no table was recorded (NULL) and ``read`` when one was —
    including ``{}``, which says the table was read and resolved nothing."""
    if not (arch or "").upper().startswith("MIPS"):
        return STUB_NOT_APPLICABLE
    return STUB_NOT_DETERMINED if stub_names_raw is None else STUB_READ


def _parse_stub_table(raw: str | None) -> dict[int, str]:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    out: dict[int, str] = {}
    if isinstance(data, dict):
        for addr, name in data.items():
            try:
                out[int(str(addr), 16)] = str(name)
            except ValueError:
                continue
    return out


def _json_list(raw: str | None) -> list[Any]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return data if isinstance(data, list) else []


def derive_identity(token: str, facts: BinaryCallFacts) -> CallIdentity:
    """The identity one CALL token names (see the module docstring for the rule order)."""
    resolved = stub_resolved_name(token, facts.stub_names)
    fun = _FUN_RE.fullmatch(token)
    fun_addr = _norm_addr(hex(int(fun.group(1), 16))) if fun else None
    if resolved is not None:
        return CallIdentity(resolved, fun_addr, KIND_STUB_RESOLVED)
    if fun_addr is not None and fun_addr in facts.unresolved_stubs:
        return CallIdentity(token, fun_addr, KIND_STUB_UNRESOLVED)
    entries = facts.names.get(token, [])
    if len(entries) == 1:
        return CallIdentity(token, entries[0], KIND_TABLE_ENTRY)
    if len(entries) > 1:
        return CallIdentity(token, None, KIND_NAME_AMBIGUOUS)
    if fun_addr is not None:
        return CallIdentity(token, fun_addr, KIND_FUN_NAME_PARSED)
    return CallIdentity(token, None, KIND_NAME_ONLY)


def identities_at(addr: str, facts: BinaryCallFacts) -> list[CallIdentity]:
    """Every distinct identity of the CALL tokens recorded at ``addr`` (sorted; [] = none). Two or
    more is a real possibility (a shared tail rendered in several functions), and all are kept."""
    found = {derive_identity(t, facts) for t in facts.tokens_at.get(addr, [])}
    return sorted(found, key=lambda i: (i.name, i.addr or "", i.kind))


def load_binary_call_facts(
    conn: sqlite3.Connection,
    binary_id: int,
    arch_stub: tuple[str | None, str | None],
    wanted: set[str],
) -> BinaryCallFacts:
    """Read one binary's function names, unresolved stub calls and the CALL tokens at ``wanted``
    (normalized addresses). Tokens are de-duplicated per (function, address, token)."""
    _arch, stub_raw = arch_stub
    names: dict[str, list[str]] = {}
    unresolved: set[str] = set()
    seen: set[tuple[int, str, str]] = set()
    tokens_at: dict[str, list[str]] = {}
    cols = {r[1] for r in conn.execute("PRAGMA table_info(functions)")}
    has_tokens = "call_tokens" in cols
    has_unres = "unresolved_external_calls" in cols
    select = "SELECT id, name, address"
    select += ", call_tokens" if has_tokens else ", NULL"
    select += ", unresolved_external_calls" if has_unres else ", NULL"
    for fid, name, address, tokens_raw, unres_raw in conn.execute(
        select + " FROM functions WHERE binary_id = ?", (binary_id,)
    ):
        entry = _norm_addr(address) if address else None
        if name and entry is not None:
            names.setdefault(name, [])
            if entry not in names[name]:
                names[name].append(entry)
        for u in _json_list(unres_raw):
            norm = _norm_addr(str(u)) if u else None
            if norm is not None:
                unresolved.add(norm)
        if not wanted:
            continue
        for tok in _json_list(tokens_raw):
            if not isinstance(tok, dict) or tok.get("opcode") != _CALL_OPCODE:
                continue
            op = tok.get("op_addr")
            text = tok.get("call_token")
            if not isinstance(op, str) or not op or not isinstance(text, str) or not text:
                continue
            norm_op = _norm_addr(op)
            if norm_op is None or norm_op not in wanted:
                continue
            key = (fid, norm_op, text)
            if key in seen:
                continue
            seen.add(key)
            tokens_at.setdefault(norm_op, []).append(text)
    return BinaryCallFacts(
        stub_names=_parse_stub_table(stub_raw),
        unresolved_stubs=unresolved,
        names=names,
        tokens_at=tokens_at,
    )


_BUILD_HASH_CACHE: dict[tuple[str, int, int], str | None] = {}


def _build_hash(conn: sqlite3.Connection, path: str) -> str | None:
    """``analysis_run_counts(...)['build_hash']`` of the side's analysis.db — the same derivation
    the run row's ``build_hash`` comes from — cached per file version (a full diff reads the same
    two databases once per binary)."""
    try:
        st = os.stat(path)
        key = (path, st.st_mtime_ns, st.st_size)
    except OSError:
        key = None
    if key is not None and key in _BUILD_HASH_CACHE:
        return _BUILD_HASH_CACHE[key]
    value = analysis_run_counts(conn).get("build_hash")
    if key is not None:
        _BUILD_HASH_CACHE[key] = value
    return value if isinstance(value, str) else None


@dataclass
class SideFacts:
    state: str  # read | bridge_absent | not_read
    build_hash: str | None
    stub_state: str | None
    facts: BinaryCallFacts | None  # None unless state is read / bridge_absent


def read_side_facts(
    analysis_db_path: str | None, bin_row: BinaryRow, wanted: set[str]
) -> SideFacts:
    """Read one side's call-site inputs for ``wanted`` addresses, never raising for a database that
    cannot be read: that side is then ``not_read`` (its facts are absent, not empty)."""
    if not analysis_db_path or not bin_row.sha256:
        return SideFacts(FACTS_NOT_READ, None, None, None)
    try:
        conn = sqlite3.connect(f"file:{Path(analysis_db_path)}?mode=ro", uri=True)
    except sqlite3.Error:
        return SideFacts(FACTS_NOT_READ, None, None, None)
    try:
        conn.row_factory = sqlite3.Row
        bcols = {r[1] for r in conn.execute("PRAGMA table_info(binaries)")}
        arch_col = "arch" if "arch" in bcols else "NULL"
        stub_col = "stub_names" if "stub_names" in bcols else "NULL"
        row = conn.execute(
            f"SELECT {arch_col} AS arch, {stub_col} AS stub_names FROM binaries "  # noqa: S608
            "WHERE id = ? AND sha256 = ?",
            (bin_row.id, bin_row.sha256),
        ).fetchone()
        if row is None:
            return SideFacts(FACTS_NOT_READ, None, None, None)
        arch, stub_raw = row["arch"], row["stub_names"]
        conn.row_factory = None
        build_hash = _build_hash_with_rows(conn, analysis_db_path)
        # the same per-DATABASE decision the hunt makes (imported lazily: a heavy module)
        from treasure_map.lib.hunt.analyzer2 import _db_has_bridge

        bridged = _db_has_bridge(analysis_db_path)
        facts = load_binary_call_facts(
            conn, bin_row.id, (arch, stub_raw), wanted if bridged else set()
        )
        return SideFacts(
            FACTS_READ if bridged else FACTS_BRIDGE_ABSENT,
            build_hash,
            stub_state(arch, stub_raw),
            facts,
        )
    except sqlite3.Error:
        return SideFacts(FACTS_NOT_READ, None, None, None)
    finally:
        conn.close()


def _build_hash_with_rows(conn: sqlite3.Connection, path: str) -> str | None:
    prev = conn.row_factory
    conn.row_factory = sqlite3.Row
    try:
        return _build_hash(conn, path)
    finally:
        conn.row_factory = prev


def facts_json(side: SideFacts, addr: str, targets: Mapping[str, list[str]] | None) -> str | None:
    """The facts JSON for one side at one matched address, or None when that side was not read."""
    if side.state == FACTS_NOT_READ or side.facts is None:
        return None
    callees = (
        [i.as_json() for i in identities_at(addr, side.facts)] if side.state == FACTS_READ else []
    )
    tgt = None if targets is None else list(targets.get(addr, []))
    return json.dumps({"callees": callees, "targets": tgt}, sort_keys=True)


def derive_and_store_callsite_facts(
    atlas: sqlite3.Connection,
    *,
    diff_id: str,
    analysis_db_a: str | None,
    analysis_db_b: str | None,
    bin_a: BinaryRow,
    bin_b: BinaryRow,
    targets_a: Mapping[str, list[str]] | None,
    targets_b: Mapping[str, list[str]] | None,
    commit: bool = False,
) -> tuple[SideFacts, SideFacts]:
    """Derive both sides' call-site facts for THIS diff's instruction_match pairs and store them
    (the per-pair JSON + each side's state on diff_meta). Runs in the persist phase after the pairs
    are chosen; joins the caller's transaction (commit=False). Reads analysis.db read-only."""
    pairs: list[tuple[str, str]] = [
        (r[0], r[1])
        for r in atlas.execute(
            "SELECT addr_a, addr_b FROM instruction_match WHERE diff_id = ?", (diff_id,)
        )
    ]
    side_a = read_side_facts(analysis_db_a, bin_a, {a for a, _b in pairs})
    side_b = read_side_facts(analysis_db_b, bin_b, {b for _a, b in pairs})
    set_instruction_match_facts(
        atlas,
        diff_id,
        [(a, facts_json(side_a, a, targets_a), facts_json(side_b, b, targets_b)) for a, b in pairs],
        commit=False,
    )
    for name, side in (("a", side_a), ("b", side_b)):
        set_callsite_facts_state(
            atlas,
            diff_id,
            side=name,
            state=side.state,
            build_hash=side.build_hash,
            stub_state=side.stub_state,
            commit=False,
        )
    if commit:
        atlas.commit()
    return side_a, side_b
