# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""D4 rekey: migrate durable evidence_ref anchors from the old text-ordinal suffix
(``<class>#<index>``) onto the new address-offset suffix (``<class>@<offset>``) after a churn +
full re-hunt has regenerated the instance table.

The crown-jewel invariant: a durable judgement (an overlay annotation, a ruler truth entry, a
private-exploit record) must NEVER silently migrate onto a DIFFERENT candidate. Every old numbered
ref resolves to exactly one disposition, and anything that cannot be PROVEN is left not_traced — the
old anchor is kept, visibly resolving to nothing — never guessed. The migration writes only after
every invariant has passed, in one transaction; any violation raises RekeyStopError and nothing is
written (fail-closed, atomic).

Why the join key is the text offset and never the occurrence (the one silent-mis-anchor trap): a
retired phantom callsite renumbers the real calls after it (occurrence 1/2/3 -> 0/1/2). So the old
ref's ``index`` is located in the SAME enumeration that produced it (``strip_phantoms=False``) to
recover the call's TEXT OFFSET, and the offset is what the bridge address is read at. The occurrence
only ever indexes within that old enumeration; it is never matched across the old and new worlds.

Why the new atlas carries no ``#index`` ref at all (see callsite_offset_suffix): so an old numbered
anchor that is not remapped resolves to NOTHING (visible staleness) instead of silently matching a
re-hunted ``#index`` that a retired phantom shifted onto a different call.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from treasure_map.lib.hunt.bridge import addr_in_body, op_addr_at
from treasure_map.lib.hunt.refs import _norm_offset, build_evidence_ref, callsite_offset_suffix
from treasure_map.lib.overlay import repoint_overlay_anchor
from treasure_map.lib.pattern.classes import call_offsets, sink_callsites
from treasure_map.lib.pattern.scanner import load_stub_names
from treasure_map.lib.pattern.shapes import classify

# sink_class -> the CallClasses attribute holding that class's sink names (shapes.classify)
_CLASS_ATTR: dict[str, str] = {
    "cmd": "cmd",
    "copy": "copy",
    "format": "fmt",
    "fmt_string": "fmt_string",
    "path_sink": "path_sink",
}
# a numbered suffix, e.g. "...@cmd#0"; the class is [a-z_]+, the ordinal digits
_NUMBERED_RE = re.compile(r"@([a-z_]+)#(\d+)$")


class RekeyStopError(Exception):
    """An invariant was violated; the migration must write nothing."""


@dataclass(frozen=True)
class Disposition:
    """What becomes of one old numbered ref.

    ``remap`` carries ``new_ref``. ``not_traced`` (no stable address) and ``phantom_removed`` (the
    ordinal named a retired phantom callsite) both leave the old anchor in place, resolving to
    nothing — visible staleness, never a silent re-point."""

    kind: str  # "remap" | "not_traced" | "phantom_removed"
    new_ref: str | None = None
    reason: str = ""


@dataclass(frozen=True)
class FuncFacts:
    """The re-hunted function a ref points into (new analysis.db + its stub table)."""

    address: str
    binary_sha256: str | None
    pseudocode: str
    pseudocode_hash: str | None
    callees: str | None
    call_tokens: str | None
    body_ranges: str | None
    stub_names: dict[int, str] = field(default_factory=dict)


def parse_numbered_ref(ref: str) -> tuple[str, str, str, str, int] | None:
    """(run, bin_anchor, func_addr, sink_class, index) for a ``<run>#<sha8>:<addr>@<class>#<n>``
    ref, or None when the ref is not a numbered per-callsite ref (bare, wrapper, or offset form)."""
    m = _NUMBERED_RE.search(ref)
    if m is None:
        return None
    head = ref[: m.start()]
    if "#" not in head or ":" not in head:
        return None
    run, rest = head.split("#", 1)
    bin_anchor, func_addr = rest.split(":", 1)
    return run, bin_anchor, func_addr, m.group(1), int(m.group(2))


def phantom_offsets(
    pseudocode: str, sink_names: Iterable[str], stub_names: dict[int, str] | None
) -> set[int]:
    """The retired phantom callsites of this function, as paren offsets: the offsets the enumerator
    counted before the D4 fix but not after.

    ``PHANTOM = call_offsets(strip=off) - call_offsets(strip=on)``, per name, unioned over the
    class's sink names, on ONE decompiled text with ONE ``classify`` — only the phantom-stripping
    toggle differs. Stripping never removes a real call, so the diff is exactly the declaration-line
    and string-literal matches, and a real direct call can never enter it."""
    ph: set[int] = set()
    for name in {n for n in sink_names if n}:
        off = set(call_offsets(pseudocode, name, stub_names, strip_phantoms=False))
        on = set(call_offsets(pseudocode, name, stub_names, strip_phantoms=True))
        ph |= off - on
    return ph


def disposition_for(
    run: str,
    func_addr: str,
    sink_class: str,
    index: int,
    facts: FuncFacts,
    old_pseudocode_hash: str | None,
    new_instance_refs: set[str] | None = None,
) -> Disposition:
    """The single disposition for one old numbered ref, computed against its re-hunted function.

    Fail-closed throughout: an unknown class, a moved body, a missing bridge token, or an
    out-of-body address all yield not_traced or RekeyStopError — never a guessed remap."""
    if sink_class not in _CLASS_ATTR:
        raise RekeyStopError(f"{run}#..:{func_addr}@{sink_class}#{index}: unknown sink_class")
    # The ref's index is located in the OLD enumeration, faithful only if the text did
    # not move; the stored per-instance hash vs the re-hunted function's hash proves it did not.
    if (
        old_pseudocode_hash is not None
        and facts.pseudocode_hash is not None
        and facts.pseudocode_hash != old_pseudocode_hash
    ):
        return Disposition("not_traced", reason="pseudocode_hash changed")
    pc = facts.pseudocode or ""
    names = getattr(classify(_loads_list(facts.callees)), _CLASS_ATTR[sink_class])
    # reproduce the enumeration that PRODUCED the old ref (phantoms still counted)
    old_sites = sink_callsites(pc, names, facts.stub_names, strip_phantoms=False)
    site = next((s for s in old_sites if s.index == index), None)
    if site is None:
        # not in the producing pass's own enumeration: cannot be a phantom (phantom ⊆ strip-off
        # offsets) nor a real call -> the pass genuinely lost it (a 0-times that is not a phantom)
        raise RekeyStopError(
            f"{run}#..:{func_addr}@{sink_class}#{index}: index absent from old enumeration"
        )
    if site.offset in phantom_offsets(pc, names, facts.stub_names):
        # cross-check: a real phantom has NO bridge token, since the bridge emits a
        # ClangFuncNameToken only at a real CALL. A token here means the enumerator over-stripped a
        # real call -> STOP rather than exempt a real candidate as a phantom.
        if op_addr_at(facts.call_tokens, pc, site.offset) is not None:
            raise RekeyStopError(
                f"{run}#..:{func_addr}@{sink_class}#{index}: phantom offset carries a bridge token"
            )
        return Disposition("phantom_removed", reason="declaration/literal phantom retired")
    addr = op_addr_at(facts.call_tokens, pc, site.offset)
    if addr is None:
        return Disposition("not_traced", reason="no bridge token (register-indirect/unrendered)")
    if not addr_in_body(addr, facts.body_ranges):
        return Disposition("not_traced", reason="sink address out of function body")
    offset = _norm_offset(addr, func_addr)
    if offset is None:
        return Disposition("not_traced", reason="offset unparseable")
    new_ref = build_evidence_ref(
        run,
        suffix=callsite_offset_suffix(sink_class, offset),
        binary_sha256=facts.binary_sha256,
        address=func_addr,
    )
    # The re-hunt must have produced this exact ref (it uses the same bridge + enumerator). Its
    # absence means the two disagree -> STOP rather than point a judgement at a ref nothing carries.
    if new_instance_refs is not None and new_ref not in new_instance_refs:
        raise RekeyStopError(
            f"{run}#..:{func_addr}@{sink_class}#{index}: computed {new_ref} absent from re-hunt"
        )
    return Disposition("remap", new_ref=new_ref)


def _loads_list(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        v = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


# ── driver: read the two atlases + the re-hunted workspaces, build the mapping, apply atomically ──


@dataclass
class RekeyReport:
    """What the migration did (or would do, under dry_run)."""

    dispositions: Counter[str] = field(default_factory=Counter)
    overlay_remapped: int = 0
    overlay_stale: int = 0
    truth_remapped: int = 0
    truth_stale: int = 0
    stale_refs: list[str] = field(default_factory=list)


def _func_facts(analysis_db: Path, bin_anchor: str, func_addr: str) -> FuncFacts | None:
    """Load one re-hunted function's facts from a workspace analysis.db (read-only), or None when
    the binary/function is not present."""
    uri = f"file:{analysis_db}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        conn.row_factory = sqlite3.Row
        brow = conn.execute(
            "SELECT id, sha256 FROM binaries WHERE substr(sha256, 1, ?) = ?",
            (len(bin_anchor), bin_anchor),
        ).fetchone()
        if brow is None:
            return None
        stub = load_stub_names(analysis_db).get(brow["id"], {})
        frow = conn.execute(
            "SELECT address, pseudocode, pseudocode_hash, callees, call_tokens, body_ranges "
            "FROM functions WHERE binary_id = ? AND address = ?",
            (brow["id"], func_addr),
        ).fetchone()
        if frow is None:
            return None
        return FuncFacts(
            address=frow["address"],
            binary_sha256=brow["sha256"],
            pseudocode=frow["pseudocode"] or "",
            pseudocode_hash=frow["pseudocode_hash"],
            callees=frow["callees"],
            call_tokens=frow["call_tokens"],
            body_ranges=frow["body_ranges"],
            stub_names=stub,
        )
    finally:
        conn.close()


def _new_instance_refs(new_atlas: Path) -> set[str]:
    conn = sqlite3.connect(f"file:{new_atlas}?mode=ro", uri=True)
    try:
        return {r[0] for r in conn.execute("SELECT evidence_ref FROM instance")}
    finally:
        conn.close()


def build_mapping(
    old_atlas: Path,
    new_atlas: Path,
    run_to_workspace: dict[str, Path],
) -> dict[str, Disposition]:
    """The ``old_ref -> Disposition`` map over EVERY old numbered instance ref (one entry each).

    Reads the old (pre-churn) atlas for the numbered refs and their per-instance pseudocode_hash,
    the re-hunted workspace analysis.db for each function's facts, and the new atlas for the set of
    refs the re-hunt produced (a cross-check). A function that vanished from the re-hunt, or an
    index the producing pass can no longer place, raises RekeyStopError — never a guess."""
    new_refs = _new_instance_refs(new_atlas)
    old = sqlite3.connect(f"file:{old_atlas}?mode=ro", uri=True)
    try:
        old.row_factory = sqlite3.Row
        rows = old.execute("SELECT evidence_ref, pseudocode_hash FROM instance").fetchall()
    finally:
        old.close()
    mapping: dict[str, Disposition] = {}
    facts_cache: dict[tuple[str, str], FuncFacts | None] = {}
    for row in rows:
        ref = row["evidence_ref"]
        parsed = parse_numbered_ref(ref)
        if parsed is None:
            continue  # bare / wrapper / already-offset refs are not migrated here
        if ref in mapping:
            raise RekeyStopError(f"duplicate old numbered ref: {ref}")
        run, bin_anchor, func_addr, sink_class, index = parsed
        ws = run_to_workspace.get(run)
        if ws is None:
            raise RekeyStopError(f"no workspace for run {run!r} (ref {ref})")
        key = (bin_anchor, func_addr)
        if key not in facts_cache:
            facts_cache[key] = _func_facts(ws, bin_anchor, func_addr)
        facts = facts_cache[key]
        if facts is None:
            raise RekeyStopError(
                f"function {func_addr} of {bin_anchor} absent from re-hunt (ref {ref})"
            )
        mapping[ref] = disposition_for(
            run, func_addr, sink_class, index, facts, row["pseudocode_hash"], new_refs
        )
    return mapping


def apply_rekey(
    new_atlas: Path,
    mapping: dict[str, Disposition],
    *,
    truth_path: Path | None = None,
    dry_run: bool = True,
) -> RekeyReport:
    """Re-point overlay (and, when given, the ruler truth file) from old refs to new, in one atlas
    transaction. ``remap`` updates the anchor; ``not_traced`` / ``phantom_removed`` leave it in
    place — with the new atlas carrying no ``#index`` ref, the un-remapped old anchor resolves to
    nothing (a stale anchor never silently re-points). private_exploit is left untouched here
    (0 rows). ``dry_run`` computes the report without writing."""
    report = RekeyReport()
    for d in mapping.values():
        report.dispositions[d.kind] += 1

    conn = sqlite3.connect(new_atlas)
    try:
        conn.row_factory = sqlite3.Row
        overlay = conn.execute("SELECT anchor_ref FROM overlay").fetchall()
        remaps: list[tuple[str, str]] = []  # (old_ref, new_ref)
        for orow in overlay:
            disp = mapping.get(orow["anchor_ref"])
            if disp is None:
                continue  # bare/wrapper overlay anchors: never numbered, never migrated
            if disp.kind == "remap" and disp.new_ref is not None:
                remaps.append((orow["anchor_ref"], disp.new_ref))
                report.overlay_remapped += 1
            else:
                report.overlay_stale += 1
                report.stale_refs.append(orow["anchor_ref"])
        if not dry_run:
            conn.execute("BEGIN")
            try:
                for old_ref, new_ref in remaps:
                    repoint_overlay_anchor(conn, old_ref=old_ref, new_ref=new_ref, commit=False)
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
    finally:
        conn.close()

    if truth_path is not None:
        _apply_truth(truth_path, mapping, report, dry_run=dry_run)
    return report


def _apply_truth(
    truth_path: Path, mapping: dict[str, Disposition], report: RekeyReport, *, dry_run: bool
) -> None:
    """Rewrite the ruler truth file's evidence_refs from old to new (remap only; a not_traced entry
    is left as-is and reported). Written via a temp file + rename so a partial write never corrupts
    the ledger."""
    data = json.loads(truth_path.read_text())
    changed = False
    for section in data.values():
        if not isinstance(section, list):
            continue
        for entry in section:
            if not isinstance(entry, dict):
                continue
            ref = entry.get("evidence_ref")
            if not isinstance(ref, str):
                continue
            disp = mapping.get(ref)
            if disp is None:
                continue
            if disp.kind == "remap" and disp.new_ref is not None:
                entry["evidence_ref"] = disp.new_ref
                report.truth_remapped += 1
                changed = True
            else:
                report.truth_stale += 1
                report.stale_refs.append(ref)
    if changed and not dry_run:
        tmp = truth_path.with_suffix(truth_path.suffix + ".rekey_tmp")
        tmp.write_text(json.dumps(data, indent=2))
        tmp.replace(truth_path)
