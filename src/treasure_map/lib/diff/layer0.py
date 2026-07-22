# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Layer-0 parse: a ``.BinDiff`` SQLite -> the atlas function-alignment substrate.

This layer ONLY aligns; it never judges semantics. Every ``function_alignment`` row is the
deterministic fact "BinDiff matched these two addresses", NEVER "this function changed / did not
change" (a change verdict is a later stage). ``similarity`` is carried as a first-class raw BinDiff
fact (the change-magnitude axis a consumer triages on), which is not a change verdict.

It reads ONLY the ``function`` table of a ``.BinDiff`` (never the ``metadata`` aggregate score, a
different measurement basis). The parse itself has ZERO dependency on the tool that produced the
``.BinDiff`` -- it just consumes a SQLite file.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from treasure_map.lib.atlas.models import (
    DiffMetaRow,
    FunctionAlignmentRow,
    FunctionPresenceRow,
    RunRow,
)
from treasure_map.lib.atlas.writer import (
    add_diff_meta,
    add_function_alignment,
    add_function_presence,
    delete_diff,
)
from treasure_map.lib.errors import ConfigError
from treasure_map.lib.hunt.refs import _norm_addr
from treasure_map.lib.query.runs import get_run

# The confidence boundary between an aligned pair and an undetermined one. Owner-set: on the
# reference fixture it cuts 1815/1848 high-confidence (~98%), matching BinDiff's own overall
# confidence -- a natural boundary. Overridable, but this is the default.
ALIGN_THRESHOLD = 0.9


def norm_hex(value: int | str | None) -> str | None:
    """Canonicalize a BinDiff address to tmap's normalized hex (lowercase, 0x-free, zero-padded).

    BinDiff stores an address as a BIGINT DECIMAL (e.g. 234452), while tmap uses hex everywhere, so
    an integer is rendered to a hex string FIRST and then handed to the shared ``_norm_addr`` (the
    same canonicalizer evidence_ref uses -- never a second normalization). MVP boundary: a 32-bit
    space is covered; a >32-bit address SQLite stored as a signed negative is out of scope here (it
    would need masking), not silently mangled -- callers that meet one should flag it, not trust it.
    """
    if value is None:
        return None
    if isinstance(value, int):
        if value < 0:
            # Not covered (see docstring): a negative from a >63-bit unsigned would need masking;
            # kept verbatim so it is visibly wrong, never fabricated into a silently-valid hex.
            return str(value)
        return _norm_addr(format(value, "x"))
    return _norm_addr(value.replace("0x", "").replace("0X", ""))


def alignment_state(confidence: float, threshold: float = ALIGN_THRESHOLD) -> str:
    """'aligned' when confidence >= threshold, else 'alignment_undetermined'. A low-confidence pair
    is kept EXPLICITLY as undetermined (never dropped, never silently read as aligned)."""
    return "aligned" if confidence >= threshold else "alignment_undetermined"


@dataclass(frozen=True)
class AlignmentParse:
    """The result of parsing a ``.BinDiff`` function table (no atlas write yet)."""

    rows: list[FunctionAlignmentRow]
    matched_addrs_a: frozenset[str]
    matched_addrs_b: frozenset[str]


def parse_bindiff(
    bindiff_path: Path, diff_id: str, threshold: float = ALIGN_THRESHOLD
) -> AlignmentParse:
    """Parse a ``.BinDiff`` SQLite's ``function`` table into alignment-fact rows.

    Reads ONLY the ``function`` table (per-row confidence/similarity, never the metadata aggregate).
    ``alignment_confidence`` = BinDiff ``confidence`` (trust in the pairing); ``similarity`` is
    carried separately (change-magnitude). Addresses (BIGINT decimal) are normalized to tmap hex. A
    low-confidence pair is kept as ``alignment_undetermined``, never dropped."""
    con = sqlite3.connect(f"file:{bindiff_path}?mode=ro", uri=True)
    try:
        con.row_factory = sqlite3.Row
        raw = con.execute(
            "SELECT address1, name1, address2, name2, similarity, confidence, "
            "basicblocks, edges, instructions FROM function"
        ).fetchall()
    finally:
        con.close()
    rows: list[FunctionAlignmentRow] = []
    a_addrs: set[str] = set()
    b_addrs: set[str] = set()
    for r in raw:
        addr_a = norm_hex(r["address1"])
        addr_b = norm_hex(r["address2"])
        if addr_a is None or addr_b is None:
            continue  # a pair with an unparseable address is not a usable alignment fact
        conf = float(r["confidence"])
        rows.append(
            FunctionAlignmentRow(
                diff_id=diff_id,
                addr_a=addr_a,
                addr_b=addr_b,
                name_a=r["name1"],
                name_b=r["name2"],
                alignment_confidence=conf,
                similarity=float(r["similarity"]) if r["similarity"] is not None else None,
                alignment_state=alignment_state(conf, threshold),
                basicblocks=r["basicblocks"],
                edges=r["edges"],
                instructions=r["instructions"],
            )
        )
        a_addrs.add(addr_a)
        b_addrs.add(addr_b)
    return AlignmentParse(
        rows=rows, matched_addrs_a=frozenset(a_addrs), matched_addrs_b=frozenset(b_addrs)
    )


@dataclass(frozen=True)
class BaselineDomain:
    """One run's function inventory for the diffed binary: normalized addr -> decompiled? (the tmap
    functions table, NOT the diff tool's larger enumeration -- see the 737-phantom guard)."""

    # addr -> (name, decompiled) ; decompiled True/False from pseudocode presence
    functions: dict[str, tuple[str | None, bool]]

    @property
    def addrs(self) -> frozenset[str]:
        return frozenset(self.functions)

    @property
    def empty_count(self) -> int:
        return sum(1 for _n, dec in self.functions.values() if not dec)


def load_baseline(analysis_db_path: str, binary: str) -> BaselineDomain:
    """The baseline domain for one side: this run's ``functions`` rows for the diffed binary.

    ``binary`` matches ``binaries.name`` OR ``binaries.sha256`` (the sha is the stable selector).
    The domain is tmap's own inventory, which by design omits thunks / externals / micro-functions
    the diff tool keeps -- so presence uses THIS set, not the diff tool's larger one."""
    con = sqlite3.connect(f"file:{analysis_db_path}?mode=ro", uri=True)
    try:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT f.address, f.name, f.pseudocode FROM functions f "
            "JOIN binaries b ON b.id = f.binary_id WHERE b.name = ? OR b.sha256 = ?",
            (binary, binary),
        ).fetchall()
    finally:
        con.close()
    funcs: dict[str, tuple[str | None, bool]] = {}
    for r in rows:
        addr = norm_hex(r["address"])
        if addr is None:
            continue
        funcs[addr] = (r["name"], bool((r["pseudocode"] or "").strip()))
    return BaselineDomain(functions=funcs)


def _presence_state(decompiled: bool | None) -> str:
    """The three-state presence label for an unmatched baseline function. A cleanly-decompiled
    unmatched function is a genuine unmatched (add/delete/refactor -- a LATER stage judges which); a
    decompile gap or an unknown status is existence-UNDETERMINED and must NEVER read as add/delete.
    Mapped from the function's own decompile status (the cross-side literal-address ``inventory``
    comparison of the original spec does not apply across two different-address-space builds)."""
    if decompiled is True:
        return "unmatched_both_decompiled"
    if decompiled is False:
        return "unmatched_decompile_missing"
    return "inventory_mismatch"


@dataclass(frozen=True)
class SidePresence:
    rows: list[FunctionPresenceRow]
    unmatched: int
    out_of_inventory: int
    inventory_mismatch: int
    matched_in_domain: int


def compute_side_presence(
    diff_id: str, side: str, matched_addrs: frozenset[str], baseline: BaselineDomain
) -> SidePresence:
    """Per-side presence: baseline functions with no matched pair become explicit, countable rows;
    matched addrs NOT in the baseline are out_of_inventory (counted, never a presence row, never an
    add/delete). A presence row states ONLY 'not in a matched pair', never 'added'/'removed'."""
    unmatched_addrs = baseline.addrs - matched_addrs
    out_of_inventory = len(matched_addrs - baseline.addrs)
    matched_in_domain = len(matched_addrs & baseline.addrs)
    rows: list[FunctionPresenceRow] = []
    inv_mismatch = 0
    for addr in sorted(unmatched_addrs):
        name, decompiled = baseline.functions[addr]
        state = _presence_state(decompiled)
        if state == "inventory_mismatch":
            inv_mismatch += 1
        rows.append(
            FunctionPresenceRow(
                diff_id=diff_id,
                side=side,
                addr=addr,
                name=name,
                presence_state=state,
                decompiled=1 if decompiled else 0,
            )
        )
    return SidePresence(
        rows=rows,
        unmatched=len(unmatched_addrs),
        out_of_inventory=out_of_inventory,
        inventory_mismatch=inv_mismatch,
        matched_in_domain=matched_in_domain,
    )


def _version_skew(a: RunRow, b: RunRow) -> bool:
    """True when the two runs' ANALYSIS-TOOL versions differ. Compares tool_version (+ the
    ghidra_version when BOTH sides recorded it). NEVER firmware_sha256 (A and B are different
    firmware) or build_hash (a single-firmware stale signal). Does NOT detect build-side
    compiler/inlining skew (see the schema note)."""
    if a.tool_version != b.tool_version:
        return True
    if a.ghidra_version and b.ghidra_version and a.ghidra_version != b.ghidra_version:
        return True
    return False


def _resolve_run(atlas: sqlite3.Connection, run_id: str, side: str) -> RunRow:
    """Resolve a run to its lineage row, or raise -- an unresolved run (present but no recorded
    analysis.db path) is an explicit error, NEVER a silent empty domain or a guessed path."""
    run = get_run(atlas, run_id)
    if run is None:
        raise ConfigError(f"diff side {side}: run '{run_id}' is not in this atlas")
    if not run.resolved or not run.analysis_db_path:
        raise ConfigError(
            f"diff side {side}: run '{run_id}' has no recorded analysis.db path "
            "(present but unresolved) -- re-scan it to record its lineage before diffing"
        )
    return run


@dataclass(frozen=True)
class Layer0Result:
    diff_id: str
    matched_pairs: int
    alignment_undetermined: int
    meta: DiffMetaRow


def run_layer0_parse(
    atlas: sqlite3.Connection,
    *,
    bindiff_path: Path,
    run_a_id: str,
    run_b_id: str,
    binary_a: str,
    binary_b: str,
    diff_id: str | None = None,
    threshold: float = ALIGN_THRESHOLD,
    commit: bool = True,
) -> Layer0Result:
    """Parse a ``.BinDiff`` into the atlas (function_alignment + function_presence + diff_meta).

    Resolves each run's analysis.db via ``run.analysis_db_path`` (errors on an unresolved run, never
    guesses a workspace path), parses the alignment facts, computes per-side presence against each
    run's own function inventory (the baseline domain), and writes all three tables under one
    ``diff_id`` in a single replace-by-diff transaction (idempotent re-parse)."""
    run_a = _resolve_run(atlas, run_a_id, "a")
    run_b = _resolve_run(atlas, run_b_id, "b")
    did = diff_id or f"{run_a_id}::{run_b_id}"

    parsed = parse_bindiff(bindiff_path, did, threshold)
    assert run_a.analysis_db_path is not None  # _resolve_run guarantees it
    assert run_b.analysis_db_path is not None
    baseline_a = load_baseline(run_a.analysis_db_path, binary_a)
    baseline_b = load_baseline(run_b.analysis_db_path, binary_b)
    pres_a = compute_side_presence(did, "a", parsed.matched_addrs_a, baseline_a)
    pres_b = compute_side_presence(did, "b", parsed.matched_addrs_b, baseline_b)

    undetermined = sum(1 for r in parsed.rows if r.alignment_state == "alignment_undetermined")
    meta = DiffMetaRow(
        diff_id=did,
        run_a_id=run_a_id,
        run_b_id=run_b_id,
        tool_version_a=run_a.tool_version,
        tool_version_b=run_b.tool_version,
        ghidra_version_a=run_a.ghidra_version,
        ghidra_version_b=run_b.ghidra_version,
        version_skew=1 if _version_skew(run_a, run_b) else 0,
        bindiff_source=bindiff_path.name,
        matched_pairs=len(parsed.rows),
        alignment_undetermined=undetermined,
        functions_total_a=len(baseline_a.addrs),
        functions_total_b=len(baseline_b.addrs),
        matched_in_domain_a=pres_a.matched_in_domain,
        matched_in_domain_b=pres_b.matched_in_domain,
        unmatched_a=pres_a.unmatched,
        unmatched_b=pres_b.unmatched,
        out_of_inventory_a=pres_a.out_of_inventory,
        out_of_inventory_b=pres_b.out_of_inventory,
        inventory_mismatch_a=pres_a.inventory_mismatch,
        inventory_mismatch_b=pres_b.inventory_mismatch,
        functions_empty_a=baseline_a.empty_count,
        functions_empty_b=baseline_b.empty_count,
        presence_computed_a=1,
        presence_computed_b=1,
    )

    delete_diff(atlas, did, commit=False)
    add_function_alignment(atlas, parsed.rows, commit=False)
    add_function_presence(atlas, pres_a.rows + pres_b.rows, commit=False)
    add_diff_meta(atlas, meta, commit=False)
    if commit:
        atlas.commit()
    return Layer0Result(
        diff_id=did,
        matched_pairs=len(parsed.rows),
        alignment_undetermined=undetermined,
        meta=meta,
    )
