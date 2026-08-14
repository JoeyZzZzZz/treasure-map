# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
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
from treasure_map.lib.facts import _DECOMPILE_MIN_SIZE
from treasure_map.lib.hunt.refs import _norm_addr
from treasure_map.lib.query.runs import get_run
from treasure_map.version import UNKNOWN_VERSION

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


def _decompile_status(pseudocode: str | None, size_bytes: int | None) -> str:
    """Classify one baseline function's decompile outcome — the KEY distinction empty pseudocode
    hides: an empty body is NOT the same as a failed decompile.

      * ``ok``            — has pseudocode.
      * ``skipped_micro`` — empty AND size < _DECOMPILE_MIN_SIZE: the exporter skips micro-functions
                            (thunks / alignment stubs) BY DESIGN, so this is not an analysis gap.
      * ``failed``        — empty AND size >= _DECOMPILE_MIN_SIZE: a genuine decompile failure.
      * ``unknown``       — size unrecorded (NULL OR 0). ★ BOTH sentinels: functions.size_bytes is
                            ``INTEGER DEFAULT 0`` so it is never NULL in practice -- 0 is the real
                            "unrecorded" marker. A 0-size real function must NOT be swallowed into
                            skipped_micro (0 < MIN); size-unknown cannot be classified -> unknown.
    ``unknown`` is checked BEFORE the size comparison so 0 never falls through to skipped_micro."""
    if pseudocode and pseudocode.strip():
        return "ok"
    if size_bytes is None or size_bytes == 0:
        return "unknown"
    if size_bytes < _DECOMPILE_MIN_SIZE:
        return "skipped_micro"
    return "failed"


@dataclass(frozen=True)
class BaselineDomain:
    """One run's function inventory for the diffed binary: normalized addr -> (name, decompile
    status) over the tmap functions table (NOT the diff tool's larger enumeration -- the 737-phantom
    guard). ``decompile status`` is 4-state (see ``_decompile_status``): a design-skipped
    micro-function is told apart from a real decompile failure, so a benign skip is never inflated
    into an analysis gap."""

    # addr -> (name, decompile_status) ; status in ok / skipped_micro / failed / unknown
    functions: dict[str, tuple[str | None, str]]

    @property
    def addrs(self) -> frozenset[str]:
        return frozenset(self.functions)

    @property
    def failed_count(self) -> int:
        """Real decompile failures (size >= MIN, no pseudocode) — the same meaning as
        run.functions_empty. Does NOT include design-skipped micro-functions."""
        return sum(1 for _n, st in self.functions.values() if st == "failed")

    @property
    def skipped_micro_count(self) -> int:
        """Micro-functions the exporter skipped by design (size < MIN) — known-benign, NOT a gap."""
        return sum(1 for _n, st in self.functions.values() if st == "skipped_micro")


def load_baseline(analysis_db_path: str, binary: str) -> BaselineDomain:
    """The baseline domain for one side: this run's ``functions`` rows for the diffed binary.

    ``binary`` matches ``binaries.name`` OR ``binaries.sha256`` (the sha is the stable selector).
    The domain is tmap's own inventory, which by design omits thunks / externals / micro-functions
    the diff tool keeps -- so presence uses THIS set, not the diff tool's larger one. ``size_bytes``
    is read so an empty body is classified (design-skip vs real failure), never lumped 'missing'."""
    con = sqlite3.connect(f"file:{analysis_db_path}?mode=ro", uri=True)
    try:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT f.address, f.name, f.pseudocode, f.size_bytes FROM functions f "
            "JOIN binaries b ON b.id = f.binary_id WHERE b.name = ? OR b.sha256 = ?",
            (binary, binary),
        ).fetchall()
    finally:
        con.close()
    funcs: dict[str, tuple[str | None, str]] = {}
    for r in rows:
        addr = norm_hex(r["address"])
        if addr is None:
            continue
        funcs[addr] = (r["name"], _decompile_status(r["pseudocode"], r["size_bytes"]))
    return BaselineDomain(functions=funcs)


def _presence_state(status: str) -> str:
    """The presence label for an unmatched baseline function — about ANALYSIS COMPLETENESS, not the
    decompile action. ``ok`` (decompiled) and ``skipped_micro`` (design-skipped, no gap) are both
    ``unmatched_analysis_complete`` (existence is DETERMINED, a genuine unmatched a later stage may
    judge add/delete/refactor). ``failed`` and ``unknown`` are ``unmatched_analysis_incomplete``
    (a real gap -> existence UNDETERMINED, NEVER add/delete). ``unknown`` -> incomplete is the
    conservative direction: size unknown means 'no gap' cannot be asserted."""
    if status in ("ok", "skipped_micro"):
        return "unmatched_analysis_complete"
    return "unmatched_analysis_incomplete"


@dataclass(frozen=True)
class SidePresence:
    rows: list[FunctionPresenceRow]
    unmatched: int
    out_of_inventory: int
    inventory_mismatch: int
    matched_in_domain: int
    # The ACTUAL out-of-inventory address SET (matched addrs not in the baseline domain), not only
    # its count. Retained so a guard can assert it at the SET level: a count-level check flips green
    # when two categories happen to have equal cardinality (numbers coincide, elements misplace), so
    # the domain-swap regression must be caught by set equality, which is cardinality-independent.
    out_of_inventory_addrs: frozenset[str] = frozenset()


# decompile status -> the presence row's honest ``decompiled`` flag (1 / 0 / NULL-unknown).
_DECOMPILED_FLAG: dict[str, int | None] = {
    "ok": 1,
    "skipped_micro": 0,
    "failed": 0,
    "unknown": None,
}


def compute_side_presence(
    diff_id: str, side: str, matched_addrs: frozenset[str], baseline: BaselineDomain
) -> SidePresence:
    """Per-side presence: baseline functions with no matched pair become explicit, countable rows;
    matched addrs NOT in the baseline are out_of_inventory (counted, never a presence row, never an
    add/delete). A presence row states ONLY 'not in a matched pair', never 'added'/'removed'.

    ★ HONEST COVERAGE NOTE: the presence / baseline layer has NO real-firmware CI coverage. Every
    presence test uses a synthetic analysis.db; the A-side reference numbers (1111 / 737 / 34) rest
    on two one-off manual verifications with no live assertion, and the B-side (where the 'new
    function' signal would live) has never been run on real data because no patched run is ingested.
    The double-machine reproducibility that IS proven covers the .BinDiff EXPORT, not this layer."""
    unmatched_addrs = baseline.addrs - matched_addrs
    out_of_inventory_addrs = matched_addrs - baseline.addrs
    matched_in_domain = len(matched_addrs & baseline.addrs)
    rows: list[FunctionPresenceRow] = []
    for addr in sorted(unmatched_addrs):
        name, status = baseline.functions[addr]
        rows.append(
            FunctionPresenceRow(
                diff_id=diff_id,
                side=side,
                addr=addr,
                name=name,
                presence_state=_presence_state(status),
                decompiled=_DECOMPILED_FLAG[status],
            )
        )
    # inventory_mismatch is a cross-side-domain state, not derived per-side here (different builds
    # have disjoint address spaces), so it stays 0 in this path -- a valid-but-unreached state.
    return SidePresence(
        rows=rows,
        unmatched=len(unmatched_addrs),
        out_of_inventory=len(out_of_inventory_addrs),
        inventory_mismatch=0,
        matched_in_domain=matched_in_domain,
        out_of_inventory_addrs=frozenset(out_of_inventory_addrs),
    )


def _version_skew(a: RunRow, b: RunRow) -> bool:
    """True when the two runs' ANALYSIS-TOOL versions are not CONFIRMED equal.

    Compares tool_version and ghidra_version. NEVER firmware_sha256 (A and B are different firmware)
    or build_hash (a single-firmware stale signal). Does NOT detect build-side compiler/inlining
    skew, nor detector-logic drift inside one tool_version (see the schema note).

    ★ The ghidra criterion is deliberately NOT short-circuited on a missing value: a side recorded
    as ``unknown`` (or NULL, from a run predating collection) means we cannot confirm the two runs
    used the same decompiler, and cannot-confirm-same is not confirmed-same -- so it counts as skew.
    Reading a half-recorded pair as "no skew" would silently bias toward comparability exactly where
    the evidence is missing. Cost, accepted: diffs of runs scanned before the decompiler version was
    recorded degrade to undetermined until they are re-scanned."""
    if a.tool_version != b.tool_version:
        return True
    if not _confirmed_same_version(a.ghidra_version, b.ghidra_version):
        return True
    return False


def _confirmed_same_version(a: str | None, b: str | None) -> bool:
    """True ONLY when both sides carry a real version string and they are equal. A missing value or
    the explicit ``unknown`` sentinel on EITHER side is not a match -- it is unconfirmable."""
    if not a or not b:
        return False
    if a == UNKNOWN_VERSION or b == UNKNOWN_VERSION:
        return False
    return a == b


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


def _binary_sha256(analysis_db_path: str, binary: str) -> str | None:
    """The content sha256 of the diffed binary in this run's analysis.db (``binary`` = name OR
    sha256). None when the binary is not found."""
    con = sqlite3.connect(f"file:{analysis_db_path}?mode=ro", uri=True)
    try:
        row = con.execute(
            "SELECT sha256 FROM binaries WHERE name = ? OR sha256 = ?", (binary, binary)
        ).fetchone()
    finally:
        con.close()
    return row[0] if row is not None else None


def _binary_name(analysis_db_path: str, binary: str) -> str | None:
    """The SHORT NAME of the diffed binary in this run's analysis.db (``binary`` = name OR sha256).

    diff_meta stores the short name so the layer-2 per-binary filter (``string_keyed_edge.binary``
    holds short names) matches. Normalizing a caller-supplied sha256 HERE, at write time, is the
    fix for the over-filter trap: a read-side ``WHERE binary = <sha256>`` would zero-match and
    silently drop every edge of the binary. None when the binary is not found -- the diff cannot
    record a scope it cannot resolve, and the consumer then refuses rather than guessing."""
    con = sqlite3.connect(f"file:{analysis_db_path}?mode=ro", uri=True)
    try:
        row = con.execute(
            "SELECT name FROM binaries WHERE name = ? OR sha256 = ?", (binary, binary)
        ).fetchone()
    finally:
        con.close()
    return row[0] if row is not None else None


def _next_attempts(
    atlas: sqlite3.Connection, diff_id: str, cur_sha_a: str | None, cur_sha_b: str | None
) -> int:
    """The attempts count to record for THIS diff of ``diff_id``, sha-aware so it doubles as the
    attempts-reset gate.

    Reads the prior diff_meta row (if any) BEFORE it is deleted/replaced. The counter only CONTINUES
    when both sides' current sha256 POSITIVELY equal the prior row's -- i.e. the exact same content
    is being diffed again (a genuine retry). If the content changed (a recompiled binary) OR either
    side's sha is unknown, it RESETS to 1: a past 'hard boundary' verdict is void once the bytes
    differ, and an unknowable identity must never be counted as a repeat failure (that would falsely
    escalate toward the retry cap). Success and failure paths share this so both agree on the count.
    """
    row = atlas.execute(
        "SELECT diff_attempts, sha256_a, sha256_b FROM diff_meta WHERE diff_id = ?", (diff_id,)
    ).fetchone()
    if row is None:
        return 1
    prev_attempts = row[0] or 0
    prev_a, prev_b = row[1], row[2]
    same_content = (
        cur_sha_a is not None
        and cur_sha_b is not None
        and prev_a == cur_sha_a
        and prev_b == cur_sha_b
    )
    return prev_attempts + 1 if same_content else 1


def make_diff_id(run_a_id: str, run_b_id: str, binary: str) -> str:
    """The identity of ONE binary's diff between two runs: ``{run_a}::{run_b}::{binary}``.

    Including the binary makes the id UNIQUE per (run_a, run_b, binary), so diffing a second binary
    no longer overwrites the first: delete_diff / every ``WHERE diff_id = ?`` then naturally scopes
    to a single binary, with no read-side filter to add or forget. ``binary`` MUST be the normalized
    short name (== diff_meta.binary_a), never the raw ``--binary`` input (which may be a sha256), so
    the same binary always maps to one id. diff_id is an OPAQUE key — nothing splits or parses it —
    so appending a segment is safe for every consumer."""
    assert "::" not in binary, f"binary short name must not contain '::': {binary!r}"
    return f"{run_a_id}::{run_b_id}::{binary}"


def _bindiff_file_hashes(bindiff_path: Path) -> list[str]:
    """The two per-side content hashes from a ``.BinDiff``'s ``file`` table, ordered by id
    (id=1 = A/before ↔ address1, id=2 = B/after ↔ address2). The declared ``CHARACTER(40)`` does not
    truncate under SQLite dynamic typing, so a 64-char sha256 rides intact. [] when there is no
    ``file`` table (an older / hand-made .BinDiff) -- then the binary identity cannot be checked."""
    con = sqlite3.connect(f"file:{bindiff_path}?mode=ro", uri=True)
    try:
        try:
            rows = con.execute("SELECT hash FROM file ORDER BY id").fetchall()
        except sqlite3.OperationalError:
            return []  # no file table
    finally:
        con.close()
    return [r[0] for r in rows if r[0]]


def _validate_bindiff_binaries(
    bindiff_path: Path, run_a: RunRow, run_b: RunRow, binary_a: str, binary_b: str
) -> None:
    """Guard: the ``.BinDiff`` must be the comparison of THESE two binaries. Cross-firmware misuse
    (firmware X's .BinDiff over firmware Y's runs) would otherwise write a whole set of garbage
    alignment rows silently. Checks a DETERMINISTIC FACT (the file hashes on each side equal the
    resolved binaries' sha256s), never a judgement -- function-scope compliant. Skipped only when a
    .BinDiff has no file table (identity unverifiable, NOT a silent pass of a known mismatch)."""
    hashes = _bindiff_file_hashes(bindiff_path)
    if len(hashes) < 2:
        return  # no file table -> cannot verify (documented boundary)
    assert run_a.analysis_db_path is not None and run_b.analysis_db_path is not None
    sha_a = _binary_sha256(run_a.analysis_db_path, binary_a)
    sha_b = _binary_sha256(run_b.analysis_db_path, binary_b)
    if hashes[0] != sha_a or hashes[1] != sha_b:
        raise ConfigError(
            "this .BinDiff does not correspond to the two runs' binaries: its file-side hashes "
            f"({hashes[0]}, {hashes[1]}) do not match the resolved binary sha256s ({sha_a}, "
            f"{sha_b}) -- a cross-firmware .BinDiff would produce garbage alignment; refusing"
        )


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
    _validate_bindiff_binaries(bindiff_path, run_a, run_b, binary_a, binary_b)
    assert run_a.analysis_db_path is not None  # _resolve_run guarantees it
    assert run_b.analysis_db_path is not None
    # Normalize the target binary to its short name (== what diff_meta.binary_a stores), used for
    # BOTH the diff_id's binary segment and the diff_meta columns so the two are consistent by
    # construction. A version diff compares ONE binary, so the two sides must resolve to the same
    # short name (a rename across versions is not this model's job) — assert it, fail-fast.
    norm_a = _binary_name(run_a.analysis_db_path, binary_a)
    norm_b = _binary_name(run_b.analysis_db_path, binary_b)
    assert norm_a is not None and norm_b is not None  # binary must exist in the run (preflight)
    assert norm_a == norm_b, f"a version diff compares one binary: got {norm_a!r} vs {norm_b!r}"
    did = diff_id or make_diff_id(run_a_id, run_b_id, norm_a)

    parsed = parse_bindiff(bindiff_path, did, threshold)
    baseline_a = load_baseline(run_a.analysis_db_path, binary_a)
    baseline_b = load_baseline(run_b.analysis_db_path, binary_b)
    pres_a = compute_side_presence(did, "a", parsed.matched_addrs_a, baseline_a)
    pres_b = compute_side_presence(did, "b", parsed.matched_addrs_b, baseline_b)

    # sha256 of the diffed content on each side, recorded so the next full diff can skip an
    # unchanged binary (incremental) and reset the attempts counter when the content changed. Read
    # BEFORE delete_diff replaces the row -- _next_attempts needs the prior row.
    sha_a = _binary_sha256(run_a.analysis_db_path, binary_a)
    sha_b = _binary_sha256(run_b.analysis_db_path, binary_b)
    attempts = _next_attempts(atlas, did, sha_a, sha_b)

    undetermined = sum(1 for r in parsed.rows if r.alignment_state == "alignment_undetermined")
    meta = DiffMetaRow(
        diff_id=did,
        run_a_id=run_a_id,
        run_b_id=run_b_id,
        # the diff's target binary per side, normalized to the short name AT WRITE TIME so the
        # layer-2 per-binary filter matches (a caller-supplied sha256 would zero-match there). Same
        # value that forms the diff_id's binary segment above (consistent by construction).
        binary_a=norm_a,
        binary_b=norm_b,
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
        # functions_empty = REAL failures only (== run.functions_empty); micro_skipped kept SEPARATE
        # (design-skipped micro-funcs are known-benign, never merged into the failure count).
        functions_empty_a=baseline_a.failed_count,
        functions_empty_b=baseline_b.failed_count,
        micro_skipped_a=baseline_a.skipped_micro_count,
        micro_skipped_b=baseline_b.skipped_micro_count,
        presence_computed_a=1,
        presence_computed_b=1,
        # A successful parse: diff_ok=1 / status='ok'. This row is written with commit=False in the
        # real pipeline, so it only reaches disk when layer-2 also commits -- a layer-2 failure
        # rolls the whole transaction back, leaving NO ok=1 residue (the driver's failure path then
        # writes the honest failed row). attempts continues/reset by content identity (sha).
        diff_ok=1,
        diff_status="ok",
        diff_status_reason=None,
        diff_attempts=attempts,
        sha256_a=sha_a,
        sha256_b=sha_b,
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
