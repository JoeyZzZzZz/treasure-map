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

import json
import sqlite3
from bisect import bisect_right
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from treasure_map.lib.atlas.models import (
    DiffMetaRow,
    FunctionAlignmentRow,
    FunctionPresenceRow,
    InstructionMatchRow,
    RunRow,
)
from treasure_map.lib.atlas.writer import (
    add_diff_meta,
    add_function_alignment,
    add_function_presence,
    add_instruction_matches,
    delete_diff,
)
from treasure_map.lib.binary_id import BinaryRow
from treasure_map.lib.callsite_ref import callsite_abs_addr, wrapper_call_abs_addr
from treasure_map.lib.diff.currency import (
    COMPARED_COLUMNS,
    UNSTAMPED,
    DiffStamps,
    stamps_equal,
    toolchain_columns,
)
from treasure_map.lib.diff.export_report import ExportReport
from treasure_map.lib.errors import ConfigError
from treasure_map.lib.facts import _DECOMPILE_MIN_SIZE
from treasure_map.lib.hunt.refs import _norm_addr
from treasure_map.lib.query.runs import get_run
from treasure_map.lib.ro_db import ro_connect
from treasure_map.version import UNKNOWN_VERSION

# The confidence boundary between an aligned pair and an undetermined one. On a real-firmware diff
# it keeps roughly 98% of the pairs as high-confidence, matching BinDiff's own overall confidence
# -- a natural boundary. Overridable, but this is the default.
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
    bindiff_path: Path,
    diff_id: str,
    threshold: float = ALIGN_THRESHOLD,
    gaps_a: dict[str, str] | None = None,
    gaps_b: dict[str, str] | None = None,
    markup_a: frozenset[str] = frozenset(),
    markup_b: frozenset[str] = frozenset(),
) -> AlignmentParse:
    """Parse a ``.BinDiff`` SQLite's ``function`` table into alignment-fact rows.

    Reads ONLY the ``function`` table (per-row confidence/similarity, never the metadata aggregate).
    ``alignment_confidence`` = BinDiff ``confidence`` (trust in the pairing); ``similarity`` is
    carried separately (change-magnitude). Addresses (BIGINT decimal) are normalized to tmap hex. A
    low-confidence pair is kept as ``alignment_undetermined``, never dropped.

    ``gaps_a`` / ``gaps_b``: the functions each side's export could not represent faithfully
    (lib/diff/export_report, entry -> gap kind). A pair with either side among them is recorded with
    the gap and is ``alignment_undetermined`` whatever BinDiff's confidence: BinDiff matched what
    the export held, and the export did not hold that function as it is.

    ``markup_a`` / ``markup_b``: the functions each side's export wrote an operand of in its
    default form. Recorded on the pair as ``operand_markup_incomplete`` and nothing else: the
    export held the function's instructions, blocks and calls as they are."""
    gaps_a = gaps_a or {}
    gaps_b = gaps_b or {}
    con = ro_connect(bindiff_path)
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
        gap_a, gap_b = gaps_a.get(addr_a), gaps_b.get(addr_b)
        state = alignment_state(conf, threshold)
        if gap_a is not None or gap_b is not None:
            state = "alignment_undetermined"
        rows.append(
            FunctionAlignmentRow(
                diff_id=diff_id,
                addr_a=addr_a,
                addr_b=addr_b,
                name_a=r["name1"],
                name_b=r["name2"],
                alignment_confidence=conf,
                similarity=float(r["similarity"]) if r["similarity"] is not None else None,
                alignment_state=state,
                basicblocks=r["basicblocks"],
                edges=r["edges"],
                instructions=r["instructions"],
                export_gap_a=gap_a,
                export_gap_b=gap_b,
                operand_markup_incomplete_a=1 if addr_a in markup_a else 0,
                operand_markup_incomplete_b=1 if addr_b in markup_b else 0,
            )
        )
        a_addrs.add(addr_a)
        b_addrs.add(addr_b)
    return AlignmentParse(
        rows=rows, matched_addrs_a=frozenset(a_addrs), matched_addrs_b=frozenset(b_addrs)
    )


def _candidate_callsite_addrs(atlas: sqlite3.Connection, run_id: str, sha: str) -> set[str]:
    """Every sink-candidate CALLSITE address for one run's binary, normalized hex. tier-1 reads it
    from the ref's addressed suffix — for a wrapper candidate that is its call to the WRAPPER, the
    address the overlay lines it up by; a degraded candidate reads the hunt-side callsite_addr the
    extractor recovered into flow_evidence (absent before that backfill). Function-level fallbacks
    carry no address and contribute none."""
    out: set[str] = set()
    for ref, fe in atlas.execute(
        "SELECT evidence_ref, flow_evidence FROM instance "
        "WHERE source_run_id = ? AND binary_content_hash = ?",
        (run_id, sha),
    ):
        if not ref:
            continue
        ci = callsite_abs_addr(ref)
        if ci is None:
            ci = wrapper_call_abs_addr(ref)
        if ci is not None:
            h = norm_hex(ci)
            if h is not None:
                out.add(h)
            continue
        if fe:
            try:
                data = json.loads(fe)
            except (ValueError, TypeError):
                data = None
            ca = data.get("callsite_addr") if isinstance(data, dict) else None
            if isinstance(ca, str) and ca:
                h = norm_hex(ca)
                if h is not None:
                    out.add(h)
    return out


def parse_instruction_matches(
    bindiff_path: Path,
    diff_id: str,
    candidate_addrs_a: set[str],
    candidate_addrs_b: set[str],
) -> list[InstructionMatchRow]:
    """The BinDiff instruction matches (address1<->address2) on a candidate callsite of EITHER side.

    BinDiff's instruction table is positional only; it is scoped by basicblock -> function, so the
    containing A function entry is joined in. A pair is kept when its A address is a run-A candidate
    callsite OR its B address is a run-B candidate callsite (the fill stays candidate-sized). The
    B-side half lets a reader tell "B's candidate matched an A instruction that is not a candidate"
    apart from "B's candidate matched nothing". Matching is 1:1 on each side's address. [] when the
    .BinDiff has no instruction table (an older / hand-made one)."""
    if not candidate_addrs_a and not candidate_addrs_b:
        return []
    con = ro_connect(bindiff_path)
    try:
        try:
            raw = con.execute(
                "SELECT i.address1, i.address2, f.address1 FROM instruction i "
                "JOIN basicblock bb ON i.basicblockid = bb.id "
                "JOIN function f ON bb.functionid = f.id"
            ).fetchall()
        except sqlite3.OperationalError:
            return []
    finally:
        con.close()
    out: list[InstructionMatchRow] = []
    seen: set[str] = set()
    for a1, a2, fa in raw:
        addr_a, addr_b, func_a = norm_hex(a1), norm_hex(a2), norm_hex(fa)
        if addr_a is None or addr_b is None or func_a is None or addr_a in seen:
            continue
        if addr_a not in candidate_addrs_a and addr_b not in candidate_addrs_b:
            continue
        seen.add(addr_a)
        out.append(
            InstructionMatchRow(diff_id=diff_id, func_addr_a=func_a, addr_a=addr_a, addr_b=addr_b)
        )
    return out


def persist_instruction_matches(
    atlas: sqlite3.Connection,
    *,
    bindiff_path: Path,
    diff_id: str,
    run_a_id: str,
    sha_a: str | None,
    run_b_id: str,
    sha_b: str | None,
    commit: bool = False,
) -> int:
    """Parse + store the candidate-callsite instruction matches for one diff (the overlay's
    cross-side bridge). Runs in the persist phase while the .BinDiff is still on disk, AFTER
    run_layer0_parse (whose delete_diff already cleared any prior instruction_match for this
    diff_id). Joins the caller's transaction (commit=False). A side with no sha contributes no
    candidate addresses; a no-op when neither side has any.

    ★ The kept pairs are chosen by the A/B candidate callsites AS OF THIS DIFF. A later re-hunt that
    changes a run's candidate set or addresses (a new candidate shape, a re-split callsite) leaves
    these rows describing the old set, so such a re-hunt must be followed by re-running the diff."""
    addrs_a = _candidate_callsite_addrs(atlas, run_a_id, sha_a) if sha_a else set()
    addrs_b = _candidate_callsite_addrs(atlas, run_b_id, sha_b) if sha_b else set()
    rows = parse_instruction_matches(bindiff_path, diff_id, addrs_a, addrs_b)
    return add_instruction_matches(atlas, rows, commit=commit)


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
    # What the counterpart probe (``probe_counterparts``) reads of this side. ``spans``: addr ->
    # the function's body as inclusive (lo, hi) address ranges (its body_ranges, else entry ..
    # entry + size - 1; empty when neither was recorded). ``sizes``: addr -> size_bytes (None
    # when unrecorded).
    spans: dict[str, tuple[tuple[int, int], ...]] = field(default_factory=dict)
    sizes: dict[str, int | None] = field(default_factory=dict)
    # The binary's lazy-binding stub table, entry addr -> the import it calls
    # (binaries.stub_names). None = not determined (NULL, unparseable, not an object, or a column
    # this analysis.db does not have) — never read as "no stubs".
    stubs: dict[str, str] | None = None
    # The instructions the extraction's function promotion left outside every function, as
    # inclusive (lo, hi) ranges (binaries.promote_residual_ranges). None = not known: NULL, not
    # recorded by this analysis.db, unparseable, or truncated (a prefix cannot show a range is
    # absent).
    residual_ranges: tuple[tuple[int, int], ...] | None = None

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


def load_baseline(analysis_db_path: str, bin_row: BinaryRow) -> BaselineDomain:
    """The baseline domain for one side: this run's ``functions`` rows for the diffed binary.

    Takes the RESOLVED row, not a selector: the caller resolved it once at the entry (see
    ``preflight``) and passes the identity down. Selecting here by ``name OR sha256`` matched every
    binary sharing the short name and merged their function tables into one domain — same address
    from two files, one name silently winning — so presence and alignment were computed against a
    domain that belonged to no single binary. The domain is tmap's own inventory, which by design
    omits thunks / externals / micro-functions the diff tool keeps -- so presence uses THIS set,
    not the diff tool's larger one. ``size_bytes`` is read so an empty body is classified
    (design-skip vs real failure), never lumped 'missing'."""
    con = ro_connect(analysis_db_path)
    try:
        con.row_factory = sqlite3.Row
        fcols = {r[1] for r in con.execute("PRAGMA table_info(functions)")}
        ranges_sel = "body_ranges" if "body_ranges" in fcols else "NULL AS body_ranges"
        rows = con.execute(
            f"SELECT address, name, pseudocode, size_bytes, {ranges_sel} "  # noqa: S608
            "FROM functions WHERE binary_id = ?",
            (bin_row.id,),
        ).fetchall()
        bcols = {r[1] for r in con.execute("PRAGMA table_info(binaries)")}
        sel = [
            c if c in bcols else f"NULL AS {c}"
            for c in ("stub_names", "promote_residual_ranges", "promote_residual_ranges_truncated")
        ]
        brow = con.execute(
            f"SELECT {', '.join(sel)} FROM binaries WHERE id = ?",  # noqa: S608 -- literal
            (bin_row.id,),
        ).fetchone()
    finally:
        con.close()
    funcs: dict[str, tuple[str | None, str]] = {}
    spans: dict[str, tuple[tuple[int, int], ...]] = {}
    sizes: dict[str, int | None] = {}
    for r in rows:
        addr = norm_hex(r["address"])
        if addr is None:
            continue
        funcs[addr] = (r["name"], _decompile_status(r["pseudocode"], r["size_bytes"]))
        size = r["size_bytes"] if isinstance(r["size_bytes"], int) else None
        sizes[addr] = size
        spans[addr] = _body_spans(addr, size, r["body_ranges"])
    stubs: dict[str, str] | None = None
    residual: tuple[tuple[int, int], ...] | None = None
    if brow is not None:
        stubs = _stub_table(brow["stub_names"])
        if brow["promote_residual_ranges_truncated"] == 0:
            residual = _hex_ranges(brow["promote_residual_ranges"])
    return BaselineDomain(
        functions=funcs, spans=spans, sizes=sizes, stubs=stubs, residual_ranges=residual
    )


def _hex_ranges(raw: Any) -> tuple[tuple[int, int], ...] | None:
    """``[["0x<lo>","0x<hi>"], ...]`` (inclusive) as sorted int ranges; None when the value is not
    that shape (NULL, unparseable, or any element malformed — a partly read list cannot show that
    a range is absent)."""
    if not isinstance(raw, str):
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(data, list):
        return None
    out: list[tuple[int, int]] = []
    for item in data:
        if not (isinstance(item, list) and len(item) == 2):
            return None
        try:
            lo, hi = (int(str(v), 16) for v in item)
        except ValueError:
            return None
        if hi < lo:
            return None
        out.append((lo, hi))
    return tuple(sorted(out))


def _body_spans(addr: str, size: int | None, raw: Any) -> tuple[tuple[int, int], ...]:
    """One function's body as inclusive ranges: its recorded body_ranges, else entry .. entry +
    size - 1, else nothing."""
    ranges = _hex_ranges(raw)
    if ranges:
        return ranges
    if size:
        lo = int(addr, 16)
        return ((lo, lo + size - 1),)
    return ()


def _stub_table(raw: Any) -> dict[str, str] | None:
    """binaries.stub_names as {normalized entry addr: import name}, or None when it is not a JSON
    object (NULL = not determined; never read as "no stubs"). ``'{}'`` is a determined empty
    table."""
    if not isinstance(raw, str):
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    out: dict[str, str] = {}
    for k, v in data.items():
        addr = norm_hex(str(k))
        if addr is not None and isinstance(v, str) and v:
            out[addr] = v
    return out


def _presence_state(status: str, export_gap: str | None = None) -> str:
    """The presence label for an unmatched baseline function — about ANALYSIS COMPLETENESS, not the
    decompile action. ``ok`` (decompiled) and ``skipped_micro`` (design-skipped, no gap) are both
    ``unmatched_analysis_complete`` (existence is DETERMINED, a genuine unmatched a later stage may
    judge add/delete/refactor). ``failed`` and ``unknown`` are ``unmatched_analysis_incomplete``
    (a real gap -> existence UNDETERMINED, NEVER add/delete). ``unknown`` -> incomplete is the
    conservative direction: size unknown means 'no gap' cannot be asserted.

    A function its export could not represent faithfully (``export_gap``, lib/diff/export_report)
    is ``unmatched_analysis_incomplete`` whatever its decompile status: it may be unmatched only
    because BinDiff never saw it as it is."""
    if export_gap is not None:
        return "unmatched_analysis_incomplete"
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


# ── the counterpart probe (what the other side holds where an unmatched function maps) ─────────
#
# A presence row says only "not in a matched pair". Whether the other side has no such function is
# a separate question the pairing cannot answer: the function may have been missed by the pairing,
# or the other side's code there may never have been made a function. The probe maps the
# function's entry to the other side through the nearest pair at or below it (the shift of that
# pair) and reads what is at the mapped address:
#   unpaired       — a function that is itself in no pair there (a pairing the diff tool missed)
#   occupied       — a paired function (or an import stub) there: the spot is taken, which is what
#                    a deletion looks like once the following code moves up
#   uncovered      — no function there, and the other side's leftover code (the instructions its
#                    extraction left outside every function) is known and does not reach it
#   residual_code  — no function there, but leftover code does
#   coverage_unknown — no function there, and the other side's leftover code is not known
#   unmappable     — no pair at or below the function to map it by
PROBE_UNPAIRED = "unpaired"
PROBE_OCCUPIED = "occupied"
PROBE_UNCOVERED = "uncovered"
PROBE_RESIDUAL = "residual_code"
PROBE_COVERAGE_UNKNOWN = "coverage_unknown"
PROBE_UNMAPPABLE = "unmappable"

# A function whose counterpart may exist but is in no pair: existence is NOT determined, never
# read as an add/delete (every reader treats it like ``unmatched_analysis_incomplete``).
COUNTERPART_SUSPECTED = "counterpart_suspected"

# probe -> (presence_state, presence_reason) for a row that would otherwise be
# ``unmatched_analysis_complete``; a probe absent here leaves the row complete.
_PROBE_STATE: dict[str, tuple[str, str]] = {
    PROBE_UNPAIRED: (COUNTERPART_SUSPECTED, "counterpart_unpaired_at_mapped_address"),
    PROBE_RESIDUAL: ("unmatched_analysis_incomplete", "other_side_code_outside_functions"),
    PROBE_COVERAGE_UNKNOWN: ("unmatched_analysis_incomplete", "other_side_coverage_unknown"),
    PROBE_UNMAPPABLE: ("unmatched_analysis_incomplete", "counterpart_unmappable"),
}


@dataclass(frozen=True)
class CounterpartProbe:
    """What the other side holds where one unmatched function maps (see the section note)."""

    probe: str
    addr: str | None = None  # the other side's function covering the mapped address
    overlap: tuple[tuple[int, int], ...] = ()  # the leftover-code ranges the mapped span meets


def _probed_state(state: str, probe: CounterpartProbe | None) -> tuple[str, str | None]:
    """(presence_state, presence_reason): the probe moves only a row the decompile/export rules
    made ``unmatched_analysis_complete``."""
    if state != "unmatched_analysis_complete" or probe is None:
        return state, None
    moved = _PROBE_STATE.get(probe.probe)
    return moved if moved is not None else (state, None)


class _Coverage:
    """The other side's functions as an address index: which function covers an address."""

    def __init__(self, baseline: BaselineDomain) -> None:
        self.entries = {int(a, 16): a for a in baseline.functions}
        spans = sorted((lo, hi, addr) for addr, rs in baseline.spans.items() for lo, hi in rs)
        self.los = [lo for lo, _hi, _a in spans]
        self.spans = spans
        # running maximum of hi, so the backwards walk below stops once nothing earlier can reach y
        self.max_hi: list[int] = []
        top = -1
        for _lo, hi, _a in spans:
            top = max(top, hi)
            self.max_hi.append(top)

    def owner(self, y: int) -> str | None:
        if y in self.entries:
            return self.entries[y]
        i = bisect_right(self.los, y) - 1
        while i >= 0 and self.max_hi[i] >= y:
            lo, hi, addr = self.spans[i]
            if lo <= y <= hi:
                return addr
            i -= 1
        return None


def _overlap(ranges: tuple[tuple[int, int], ...], lo: int, hi: int) -> tuple[tuple[int, int], ...]:
    return tuple((a, b) for a, b in ranges if a <= hi and b >= lo)


def probe_counterparts(
    unmatched: frozenset[str],
    own: BaselineDomain,
    other: BaselineDomain,
    pairs: list[tuple[str, str]],
    occupied: frozenset[str],
) -> dict[str, CounterpartProbe]:
    """The counterpart probe of each ``unmatched`` function on one side.

    ``pairs``: every pair the diff keeps, as (this side's addr, the other side's addr), in either
    alignment state — the anchors. ``occupied``: the other side's addresses a found function is
    "taken" by (its paired functions, and its import stubs when the diff accounts them by name);
    any other function found there is itself in no pair. The mapped span is the function's entry
    shifted by its anchor pair, ``size_bytes`` long (one byte when its size is unrecorded)."""
    anchors = sorted((int(x, 16), int(y, 16)) for x, y in pairs)
    keys = [x for x, _y in anchors]
    cov = _Coverage(other)
    out: dict[str, CounterpartProbe] = {}
    for addr in unmatched:
        x = int(addr, 16)
        i = bisect_right(keys, x) - 1
        if i < 0:
            out[addr] = CounterpartProbe(PROBE_UNMAPPABLE)
            continue
        y = anchors[i][1] + (x - anchors[i][0])
        found = cov.owner(y)
        if found is not None:
            kind = PROBE_OCCUPIED if found in occupied else PROBE_UNPAIRED
            out[addr] = CounterpartProbe(kind, addr=found)
            continue
        if other.residual_ranges is None:
            out[addr] = CounterpartProbe(PROBE_COVERAGE_UNKNOWN)
            continue
        size = own.sizes.get(addr) or 1
        hit = _overlap(other.residual_ranges, y, y + size - 1)
        out[addr] = (
            CounterpartProbe(PROBE_RESIDUAL, overlap=hit)
            if hit
            else CounterpartProbe(PROBE_UNCOVERED)
        )
    return out


# ── import stubs (accounted by import name, outside the pairing) ─────────────────────────────


@dataclass(frozen=True)
class StubLedger:
    """The import stubs of the two sides, accounted by the import each one calls.

    A lazy-binding stub is a few instructions per import, laid out as a table; the diff tool pairs
    them by shape, and an export can rarely hold them as they are (on MIPS the next entry is the
    previous one's delay slot). Their identity is the import name read from the ELF structure, so
    they are paired by that name instead and kept out of the function pairs and the presence rows.
    Only when both sides' stub tables are determined: otherwise nothing is taken out (``enabled``
    False) and the stubs go through the pairing as before."""

    enabled: bool
    table_a: str  # resolved | unknown
    table_b: str
    pairs: int | None = None
    a_only: tuple[str, ...] | None = None
    b_only: tuple[str, ...] | None = None
    # pairs the diff tool made between a stub and a function that is not one: (addr_a, addr_b)
    mismatch: tuple[tuple[str, str], ...] = ()
    stubs_a: frozenset[str] = frozenset()
    stubs_b: frozenset[str] = frozenset()


def stub_ledger(stubs_a: dict[str, str] | None, stubs_b: dict[str, str] | None) -> StubLedger:
    """The stub accounting of a diff from the two sides' stub tables (pairs not split yet)."""
    table_a = "resolved" if stubs_a is not None else "unknown"
    table_b = "resolved" if stubs_b is not None else "unknown"
    if stubs_a is None or stubs_b is None:
        return StubLedger(enabled=False, table_a=table_a, table_b=table_b)
    names_a, names_b = set(stubs_a.values()), set(stubs_b.values())
    return StubLedger(
        enabled=True,
        table_a=table_a,
        table_b=table_b,
        pairs=len(names_a & names_b),
        a_only=tuple(sorted(names_a - names_b)),
        b_only=tuple(sorted(names_b - names_a)),
        stubs_a=frozenset(stubs_a),
        stubs_b=frozenset(stubs_b),
    )


def split_stub_pairs(
    parsed: AlignmentParse, ledger: StubLedger
) -> tuple[AlignmentParse, StubLedger]:
    """The parse without the pairs touching an import stub, and the ledger with the pairs that
    joined a stub to a function that is not one (kept as facts; that function is then unmatched).
    Unchanged when the ledger is not enabled."""
    if not ledger.enabled:
        return parsed, ledger
    kept: list[FunctionAlignmentRow] = []
    mismatch: list[tuple[str, str]] = []
    for r in parsed.rows:
        on_a, on_b = r.addr_a in ledger.stubs_a, r.addr_b in ledger.stubs_b
        if not on_a and not on_b:
            kept.append(r)
        elif on_a != on_b:
            mismatch.append((r.addr_a, r.addr_b))
    return (
        AlignmentParse(
            rows=kept,
            matched_addrs_a=frozenset(r.addr_a for r in kept),
            matched_addrs_b=frozenset(r.addr_b for r in kept),
        ),
        replace(ledger, mismatch=tuple(sorted(mismatch))),
    )


def _gap_split(
    report: ExportReport | None, ledger: StubLedger, side: str
) -> tuple[int | None, int | None]:
    """(gaps on import stubs, gaps on the rest) of one side's export report. Without a report both
    are None; without an enabled ledger the stubs are not told apart: (None, every gap)."""
    if report is None:
        return None, None
    gaps = report.gaps()
    if not ledger.enabled:
        return None, len(gaps)
    stubs = ledger.stubs_a if side == "a" else ledger.stubs_b
    on_stubs = sum(1 for a in gaps if a in stubs)
    return on_stubs, len(gaps) - on_stubs


# decompile status -> the presence row's honest ``decompiled`` flag (1 / 0 / NULL-unknown).
_DECOMPILED_FLAG: dict[str, int | None] = {
    "ok": 1,
    "skipped_micro": 0,
    "failed": 0,
    "unknown": None,
}


def compute_side_presence(
    diff_id: str,
    side: str,
    matched_addrs: frozenset[str],
    baseline: BaselineDomain,
    gaps: dict[str, str] | None = None,
    markup: frozenset[str] = frozenset(),
    probes: dict[str, CounterpartProbe] | None = None,
    stubs: frozenset[str] = frozenset(),
) -> SidePresence:
    """Per-side presence: baseline functions with no matched pair become explicit, countable rows;
    matched addrs NOT in the baseline are out_of_inventory (counted, never a presence row, never an
    add/delete). A presence row states ONLY 'not in a matched pair', never 'added'/'removed'.

    ``stubs``: this side's import-stub entries when the diff accounts them by import name
    (``stub_ledger``) — outside the domain here, so a stub is never a presence row. ``probes``:
    what the other side holds where each unmatched function maps (``probe_counterparts``). Every
    row carries its probe as facts; it changes the state only of a row that would otherwise be
    ``unmatched_analysis_complete`` (``_probed_state``) — a gap row stays what its gap makes it.

    ★ HONEST COVERAGE NOTE: the presence / baseline layer has NO real-firmware CI coverage. Every
    presence test uses a synthetic analysis.db; the A-side reference numbers (1111 / 737 / 34) rest
    on two one-off manual verifications with no live assertion, and the B-side (where the 'new
    function' signal would live) has never been run on real data because no patched run is ingested.
    The double-machine reproducibility that IS proven covers the .BinDiff EXPORT, not this layer."""
    domain = baseline.addrs - stubs
    unmatched_addrs = domain - matched_addrs
    out_of_inventory_addrs = matched_addrs - baseline.addrs
    matched_in_domain = len(matched_addrs & domain)
    rows: list[FunctionPresenceRow] = []
    gaps = gaps or {}
    probes = probes or {}
    for addr in sorted(unmatched_addrs):
        name, status = baseline.functions[addr]
        gap = gaps.get(addr)
        probe = probes.get(addr)
        state, reason = _probed_state(_presence_state(status, gap), probe)
        rows.append(
            FunctionPresenceRow(
                diff_id=diff_id,
                side=side,
                addr=addr,
                name=name,
                presence_state=state,
                decompiled=_DECOMPILED_FLAG[status],
                export_gap=gap,
                operand_markup_incomplete=1 if addr in markup else 0,
                counterpart_probe=probe.probe if probe is not None else None,
                counterpart_addr=probe.addr if probe is not None else None,
                presence_reason=reason,
                counterpart_overlap=(
                    json.dumps([[f"0x{lo:x}", f"0x{hi:x}"] for lo, hi in probe.overlap])
                    if probe is not None and probe.overlap
                    else None
                ),
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


def _next_attempts(
    atlas: sqlite3.Connection,
    diff_id: str,
    cur_sha_a: str | None,
    cur_sha_b: str | None,
    cur_stamps: DiffStamps,
) -> int:
    """The attempts count to record for THIS diff of ``diff_id``, aware of everything the diff was
    computed from, so it doubles as the attempts-reset gate.

    Reads the prior diff_meta row (if any) BEFORE it is deleted/replaced. The counter only CONTINUES
    when the same diff is being attempted again: both sides' current sha256 POSITIVELY equal the
    prior row's, AND every compared stamp (extraction pass, decompiler version, hunt-input digest,
    diff code version — see lib/diff/currency) equals the prior row's. Anything else RESETS it to 1:
    a past 'hard boundary' verdict is void once the bytes, the extraction, the hunt output or the
    diff code differ, and an unknowable sha must never be counted as a repeat failure (that would
    falsely escalate toward the retry cap). A prior row written before the stamps were recorded has
    them NULL, which differs from any current stamp, so its count resets once. Success and failure
    paths share this so both agree on the count.
    """
    row = atlas.execute(
        "SELECT diff_attempts, sha256_a, sha256_b, "  # noqa: S608 -- literal column list
        f"{', '.join(COMPARED_COLUMNS)} FROM diff_meta WHERE diff_id = ?",
        (diff_id,),
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
    prev_stamps = dict(zip(COMPARED_COLUMNS, row[3:], strict=True))
    same_inputs = stamps_equal(prev_stamps, cur_stamps.compared())
    return prev_attempts + 1 if (same_content and same_inputs) else 1


def _unstamped(run_a: RunRow, run_b: RunRow) -> DiffStamps:
    """The stamps of a diff written without them: only the runs' decompiler versions."""
    return replace(
        UNSTAMPED,
        a=replace(UNSTAMPED.a, ghidra_version=run_a.ghidra_version),
        b=replace(UNSTAMPED.b, ghidra_version=run_b.ghidra_version),
    )


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
    con = ro_connect(bindiff_path)
    try:
        try:
            rows = con.execute("SELECT hash FROM file ORDER BY id").fetchall()
        except sqlite3.OperationalError:
            return []  # no file table
    finally:
        con.close()
    return [r[0] for r in rows if r[0]]


def _validate_bindiff_binaries(bindiff_path: Path, bin_a: BinaryRow, bin_b: BinaryRow) -> None:
    """Guard: the ``.BinDiff`` must be the comparison of THESE two binaries. Cross-firmware misuse
    (firmware X's .BinDiff over firmware Y's runs) would otherwise write a whole set of garbage
    alignment rows silently. Checks a DETERMINISTIC FACT (the file hashes on each side equal the
    resolved binaries' sha256s), never a judgement -- function-scope compliant. Skipped only when a
    .BinDiff has no file table (identity unverifiable, NOT a silent pass of a known mismatch)."""
    hashes = _bindiff_file_hashes(bindiff_path)
    if len(hashes) < 2:
        return  # no file table -> cannot verify (documented boundary)
    # The resolved rows' own sha256s. A row whose sha256 is NULL (the schema allows it) cannot be
    # compared and lands on the same "cannot verify" boundary as a .BinDiff with no file table.
    sha_a, sha_b = bin_a.sha256, bin_b.sha256
    if sha_a is None or sha_b is None:
        return
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
    bin_a: BinaryRow,
    bin_b: BinaryRow,
    diff_id: str | None = None,
    threshold: float = ALIGN_THRESHOLD,
    commit: bool = True,
    stamps: DiffStamps | None = None,
    report_a: ExportReport | None = None,
    report_b: ExportReport | None = None,
    bindiff_vertex0_fallbacks: int | None = None,
) -> Layer0Result:
    """Parse a ``.BinDiff`` into the atlas (function_alignment + function_presence + diff_meta).

    Resolves each run's analysis.db via ``run.analysis_db_path`` (errors on an unresolved run, never
    guesses a workspace path), parses the alignment facts, computes per-side presence against each
    run's own function inventory (the baseline domain), and writes all three tables under one
    ``diff_id`` in a single replace-by-diff transaction (idempotent re-parse).

    ``stamps`` is what else the diff is computed from (lib/diff/currency), taken by the caller
    inside the same write transaction; they are written to diff_meta, and ghidra_version_a/b then
    hold each diffed binary's own decompiler version. Without them the row is written unstamped
    (NULL stamps, the runs' decompiler versions), which every reader reports as unverified.

    ``report_a`` / ``report_b``: each side's export report (lib/diff/export_report). The functions
    it lists are marked on their alignment / presence rows and never read as determined; its counts
    and ``bindiff_vertex0_fallbacks`` are written to diff_meta. None leaves them unrecorded."""
    run_a = _resolve_run(atlas, run_a_id, "a")
    run_b = _resolve_run(atlas, run_b_id, "b")
    _validate_bindiff_binaries(bindiff_path, bin_a, bin_b)
    assert run_a.analysis_db_path is not None  # _resolve_run guarantees it
    assert run_b.analysis_db_path is not None
    # The short name (== what diff_meta.binary_a stores) comes off the RESOLVED rows, used for BOTH
    # the diff_id's binary segment and the diff_meta columns so the two are consistent by
    # construction. A version diff compares ONE binary, so the two sides must be the same one; a
    # rename across versions is not this model's job. Raised, not asserted — this is reachable
    # input, and an assert vanishes under -O leaving a wrong name to flow into the diff_id.
    norm_a, norm_b = bin_a.name, bin_b.name
    if norm_a != norm_b:
        raise ConfigError(
            f"a version diff compares one binary, but the two sides resolved to different "
            f"names: {norm_a!r} (a) vs {norm_b!r} (b)"
        )
    did = diff_id or make_diff_id(run_a_id, run_b_id, norm_a)

    gaps_a = report_a.gaps() if report_a is not None else {}
    gaps_b = report_b.gaps() if report_b is not None else {}
    markup_a = report_a.operand_markup_degraded if report_a is not None else frozenset()
    markup_b = report_b.operand_markup_degraded if report_b is not None else frozenset()
    parsed = parse_bindiff(bindiff_path, did, threshold, gaps_a, gaps_b, markup_a, markup_b)
    baseline_a = load_baseline(run_a.analysis_db_path, bin_a)
    baseline_b = load_baseline(run_b.analysis_db_path, bin_b)
    # Import stubs are accounted by import name and taken out of the pairs and the presence rows
    # (W4); then every function left unmatched is probed for what the other side holds where it
    # maps (W3), with the pairs that remain as the anchors.
    parsed, ledger = split_stub_pairs(parsed, stub_ledger(baseline_a.stubs, baseline_b.stubs))
    pairs_ab = [(r.addr_a, r.addr_b) for r in parsed.rows]
    excl_a = ledger.stubs_a if ledger.enabled else frozenset()
    excl_b = ledger.stubs_b if ledger.enabled else frozenset()
    probes_a = probe_counterparts(
        baseline_a.addrs - excl_a - parsed.matched_addrs_a,
        baseline_a,
        baseline_b,
        pairs_ab,
        parsed.matched_addrs_b | excl_b,
    )
    probes_b = probe_counterparts(
        baseline_b.addrs - excl_b - parsed.matched_addrs_b,
        baseline_b,
        baseline_a,
        [(y, x) for x, y in pairs_ab],
        parsed.matched_addrs_a | excl_a,
    )
    pres_a = compute_side_presence(
        did, "a", parsed.matched_addrs_a, baseline_a, gaps_a, markup_a, probes_a, excl_a
    )
    pres_b = compute_side_presence(
        did, "b", parsed.matched_addrs_b, baseline_b, gaps_b, markup_b, probes_b, excl_b
    )
    stub_gaps_a, code_gaps_a = _gap_split(report_a, ledger, "a")
    stub_gaps_b, code_gaps_b = _gap_split(report_b, ledger, "b")

    # sha256 of the diffed content on each side, recorded so the next full diff can skip an
    # unchanged binary (incremental) and reset the attempts counter when the content changed. Read
    # BEFORE delete_diff replaces the row -- _next_attempts needs the prior row.
    sha_a, sha_b = bin_a.sha256, bin_b.sha256
    # What is written is what the attempts gate compares, so an unstamped write (the runs'
    # decompiler versions, every other stamp NULL) compares against the same shape next time.
    st = stamps if stamps is not None else _unstamped(run_a, run_b)
    attempts = _next_attempts(atlas, did, sha_a, sha_b, st)

    undetermined = sum(1 for r in parsed.rows if r.alignment_state == "alignment_undetermined")
    tools = toolchain_columns(st.toolchain)
    meta = DiffMetaRow(
        diff_id=did,
        run_a_id=run_a_id,
        run_b_id=run_b_id,
        # the diff's target binary per side, normalized to the short name AT WRITE TIME so the
        # layer-2 per-binary filter matches (a caller-supplied sha256 would zero-match there). Same
        # value that forms the diff_id's binary segment above (consistent by construction).
        binary_a=norm_a,
        binary_b=norm_b,
        # The PATH of the file actually diffed on each side. binary_a/binary_b hold the short name,
        # which a firmware can attach to several files; these say which one this diff was about.
        binary_path_a=bin_a.path,
        binary_path_b=bin_b.path,
        tool_version_a=run_a.tool_version,
        tool_version_b=run_b.tool_version,
        ghidra_version_a=st.a.ghidra_version,
        ghidra_version_b=st.b.ghidra_version,
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
        extraction_pass_a=st.a.extraction_pass,
        extraction_pass_b=st.b.extraction_pass,
        hunt_inputs_hash_a=st.a.hunt_inputs_hash,
        hunt_inputs_hash_b=st.b.hunt_inputs_hash,
        scanned_at_a=st.a.scanned_at,
        scanned_at_b=st.b.scanned_at,
        hunt_instances_a=st.a.hunt_instances,
        hunt_instances_b=st.b.hunt_instances,
        diff_code_version=st.diff_code_version,
        export_builder_a=report_a.builder if report_a else None,
        export_builder_b=report_b.builder if report_b else None,
        export_entry_addresses_added_a=report_a.entry_addresses_added if report_a else None,
        export_entry_addresses_added_b=report_b.entry_addresses_added if report_b else None,
        export_flow_graphs_dropped_a=report_a.flow_graphs_dropped if report_a else None,
        export_flow_graphs_dropped_b=report_b.flow_graphs_dropped if report_b else None,
        export_degenerate_functions_a=len(report_a.degenerate_functions) if report_a else None,
        export_degenerate_functions_b=len(report_b.degenerate_functions) if report_b else None,
        bindiff_vertex0_fallbacks=bindiff_vertex0_fallbacks,
        export_code_hash_a=st.a.export_code_hash,
        export_code_hash_b=st.b.export_code_hash,
        toolchain_ghidra=tools["toolchain_ghidra"],
        toolchain_binexport=tools["toolchain_binexport"],
        toolchain_bindiff=tools["toolchain_bindiff"],
        stub_table_a=ledger.table_a,
        stub_table_b=ledger.table_b,
        stub_pairs=ledger.pairs,
        stub_a_only=json.dumps(list(ledger.a_only)) if ledger.a_only is not None else None,
        stub_b_only=json.dumps(list(ledger.b_only)) if ledger.b_only is not None else None,
        stub_pair_mismatch=(
            json.dumps([list(m) for m in ledger.mismatch]) if ledger.enabled else None
        ),
        export_gaps_on_stubs_a=stub_gaps_a,
        export_gaps_on_stubs_b=stub_gaps_b,
        export_gaps_on_code_a=code_gaps_a,
        export_gaps_on_code_b=code_gaps_b,
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
