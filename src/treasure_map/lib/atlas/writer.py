# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Atlas writer — append-only insert + corroborate functions.

Append-only: insert and corroborate only; no wipe path exists.
Field names and query examples are neutral; they describe mechanism only.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from treasure_map.lib.atlas.models import InstanceRow
from treasure_map.lib.errors import ConfigError

_VALID_ORIGINS = ("custom", "vendor_modified_oss", "stock_oss_known", "unknown")


@dataclass(frozen=True)
class AtlasStats:
    """Counters returned by add_instances."""

    patterns_touched: int
    instances_added: int


def delete_run_instances(
    conn: sqlite3.Connection, source_run_id: str, *, commit: bool = True
) -> int:
    """Delete all instances of one run (replace-by-run refresh). Returns rows deleted.

    Touches ONLY this run_id's instance rows — other runs' append-and-corroborate evidence is
    untouched, and pattern rows (the shared accumulation layer) are never deleted. With
    commit=False the delete joins the caller's transaction (so a run refresh is atomic).
    """
    cur = conn.execute("DELETE FROM instance WHERE source_run_id = ?", (source_run_id,))
    if commit:
        conn.commit()
    return cur.rowcount


def upsert_pattern(
    conn: sqlite3.Connection,
    *,
    source_class: str,
    sink_class: str,
    call_sequence_shape: str,
    structural_fingerprint: str | None = None,
    fingerprint_algo_version: str = "v0",
    commit: bool = True,
) -> int:
    """Find-or-create a pattern row; return pattern_id. Commits unless commit=False.

    Dedup key:
    - non-None fingerprint: (structural_fingerprint, fingerprint_algo_version)
    - None fingerprint: class triple + structural_fingerprint IS NULL (never = NULL)
    On corroboration bumps last_updated_at. commit=False lets the caller batch this into a
    single transaction (e.g. replace-by-run).
    """
    if structural_fingerprint is not None:
        row = conn.execute(
            """SELECT pattern_id FROM pattern
               WHERE structural_fingerprint = ? AND fingerprint_algo_version = ?""",
            (structural_fingerprint, fingerprint_algo_version),
        ).fetchone()
    else:
        row = conn.execute(
            """SELECT pattern_id FROM pattern
               WHERE structural_fingerprint IS NULL
                 AND source_class = ?
                 AND sink_class = ?
                 AND call_sequence_shape = ?""",
            (source_class, sink_class, call_sequence_shape),
        ).fetchone()

    if row is not None:
        pattern_id: int = row[0]
        conn.execute(
            "UPDATE pattern SET last_updated_at = CURRENT_TIMESTAMP WHERE pattern_id = ?",
            (pattern_id,),
        )
        if commit:
            conn.commit()
        return pattern_id

    cur = conn.execute(
        """INSERT INTO pattern
           (source_class, sink_class, call_sequence_shape,
            structural_fingerprint, fingerprint_algo_version)
           VALUES (?, ?, ?, ?, ?)""",
        (
            source_class,
            sink_class,
            call_sequence_shape,
            structural_fingerprint,
            fingerprint_algo_version,
        ),
    )
    if commit:
        conn.commit()
    return int(cur.lastrowid)  # type: ignore[arg-type]


def _validate_instance(instance: InstanceRow, external_anchor: str | None) -> None:
    """Raise ConfigError on any hard-rule violation."""
    if not (instance.pseudocode_hash or instance.evidence_ref):
        raise ConfigError("instance requires pseudocode_hash or evidence_ref (traceability)")
    if not instance.source_run_id:
        raise ConfigError("instance.source_run_id must be non-empty (device_spread unit)")
    if instance.origin not in _VALID_ORIGINS:
        raise ConfigError(
            f"instance.origin must be one of {list(_VALID_ORIGINS)}; got {instance.origin!r}"
        )
    if instance.provenance_level in {"L2", "L3"} and not external_anchor:
        raise ConfigError(
            f"provenance_level={instance.provenance_level} requires a non-empty external_anchor"
        )


def _recompute_device_spread(conn: sqlite3.Connection, pattern_id: int) -> None:
    conn.execute(
        """UPDATE pattern SET
               device_spread = (
                   SELECT COUNT(DISTINCT source_run_id)
                   FROM instance
                   WHERE pattern_id = ?
               ),
               last_updated_at = CURRENT_TIMESTAMP
           WHERE pattern_id = ?""",
        (pattern_id, pattern_id),
    )


def add_instance(
    conn: sqlite3.Connection,
    instance: InstanceRow,
    *,
    external_anchor: str | None = None,
    commit: bool = True,
) -> int:
    """Insert one instance; return instance_id. Commits unless commit=False.

    Validates traceability, source_run_id, origin enum, and L2/L3 anchor requirement.
    Recomputes pattern.device_spread = COUNT(DISTINCT source_run_id) after insert. commit=False
    lets the caller batch many inserts (and a preceding delete) into one atomic transaction.
    """
    _validate_instance(instance, external_anchor)

    cur = conn.execute(
        """INSERT INTO instance
           (pattern_id, pseudocode_hash, source_anchor, sink_anchor, source_run_id,
            reachability_status, blocking_mechanism, provenance_level, external_anchor,
            fix_diff, scope_origin, evidence_ref, binary_path, binary_content_hash, origin,
            is_thin_cmd_wrapper, wrapped_sink)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            instance.pattern_id,
            instance.pseudocode_hash,
            instance.source_anchor,
            instance.sink_anchor,
            instance.source_run_id,
            instance.reachability_status,
            instance.blocking_mechanism,
            instance.provenance_level,
            external_anchor,
            instance.fix_diff,
            instance.scope_origin,
            instance.evidence_ref,
            instance.binary_path,
            instance.binary_content_hash,
            instance.origin,
            int(instance.is_thin_cmd_wrapper),
            instance.wrapped_sink,
        ),
    )
    _recompute_device_spread(conn, instance.pattern_id)
    if commit:
        conn.commit()
    return int(cur.lastrowid)  # type: ignore[arg-type]


def add_instances(
    conn: sqlite3.Connection,
    instances: list[InstanceRow],
    *,
    external_anchor: str | None = None,
) -> AtlasStats:
    """Insert a batch of instances in a single transaction; return AtlasStats. Commits.

    All instances share the same external_anchor. Validates each before any insert.
    Recomputes device_spread for all touched patterns once at end.
    """
    if not instances:
        return AtlasStats(patterns_touched=0, instances_added=0)

    for inst in instances:
        _validate_instance(inst, external_anchor)

    rows = [
        (
            inst.pattern_id,
            inst.pseudocode_hash,
            inst.source_anchor,
            inst.sink_anchor,
            inst.source_run_id,
            inst.reachability_status,
            inst.blocking_mechanism,
            inst.provenance_level,
            external_anchor,
            inst.fix_diff,
            inst.scope_origin,
            inst.evidence_ref,
            inst.binary_path,
            inst.binary_content_hash,
            inst.origin,
            int(inst.is_thin_cmd_wrapper),
            inst.wrapped_sink,
        )
        for inst in instances
    ]
    conn.executemany(
        """INSERT INTO instance
           (pattern_id, pseudocode_hash, source_anchor, sink_anchor, source_run_id,
            reachability_status, blocking_mechanism, provenance_level, external_anchor,
            fix_diff, scope_origin, evidence_ref, binary_path, binary_content_hash, origin,
            is_thin_cmd_wrapper, wrapped_sink)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        rows,
    )

    pattern_ids = {inst.pattern_id for inst in instances}
    for pid in pattern_ids:
        _recompute_device_spread(conn, pid)
    conn.commit()

    return AtlasStats(patterns_touched=len(pattern_ids), instances_added=len(instances))
