# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Atlas writer — append-only insert + corroborate functions.

Append-only: insert and corroborate only; no wipe path exists.
Field names and query examples are neutral; they describe mechanism only.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from treasure_map.lib.atlas.models import (
    InstanceRow,
    NvramDefaultRow,
    NvramFlowRow,
    PublicCvePatternRow,
    WebFormFieldRow,
)
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


def delete_run_nvram_flow(
    conn: sqlite3.Connection, source_run_id: str, *, commit: bool = True
) -> int:
    """Delete all nvram_key_flow rows of one run (replace-by-run refresh). Returns rows deleted.

    Touches ONLY this run_id's rows — other runs' nvram facts are untouched. With commit=False the
    delete joins the caller's transaction (so a run's flatten is atomic with its instance write)."""
    cur = conn.execute("DELETE FROM nvram_key_flow WHERE source_run_id = ?", (source_run_id,))
    if commit:
        conn.commit()
    return cur.rowcount


def add_nvram_flow_rows(
    conn: sqlite3.Connection, rows: list[NvramFlowRow], *, commit: bool = True
) -> int:
    """Insert flattened nvram op rows in one batch; return the count. Commits unless commit=False.

    Neutral per-op facts (key + key_kind three-state + write value source). No validation beyond the
    schema CHECKs — these are surfaced Ghidra def-use facts, never a scored verdict."""
    if not rows:
        return 0
    conn.executemany(
        """INSERT INTO nvram_key_flow
           (source_run_id, key, key_kind, binary, func, op, value_source, api, via_wrapper)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [
            (
                r.source_run_id,
                r.key,
                r.key_kind,
                r.binary,
                r.func,
                r.op,
                r.value_source,
                r.api,
                r.via_wrapper,
            )
            for r in rows
        ],
    )
    if commit:
        conn.commit()
    return len(rows)


def delete_run_nvram_defaults(
    conn: sqlite3.Connection, source_run_id: str, *, commit: bool = True
) -> int:
    """Delete all nvram_defaults rows of one run (replace-by-run refresh). Returns rows deleted.

    Touches ONLY this run_id's rows. With commit=False the delete joins the caller's transaction."""
    cur = conn.execute("DELETE FROM nvram_defaults WHERE source_run_id = ?", (source_run_id,))
    if commit:
        conn.commit()
    return cur.rowcount


def add_nvram_default_rows(
    conn: sqlite3.Connection, rows: list[NvramDefaultRow], *, commit: bool = True
) -> int:
    """Insert flattened router_defaults member rows in one batch; return the count.

    Neutral data-segment facts (key + default + flags). A key=NULL row records an unresolved member
    (keeps a located-but-incomplete table honest). No verdict — web_settable queries these."""
    if not rows:
        return 0
    conn.executemany(
        """INSERT INTO nvram_defaults
           (source_run_id, key, default_value, flags, member_index, binary)
           VALUES (?, ?, ?, ?, ?, ?)""",
        [
            (
                r.source_run_id,
                r.key,
                r.default_value,
                r.flags,
                r.member_index,
                r.binary,
            )
            for r in rows
        ],
    )
    if commit:
        conn.commit()
    return len(rows)


def delete_run_web_form_fields(
    conn: sqlite3.Connection, source_run_id: str, *, commit: bool = True
) -> int:
    """Delete all web_form_fields rows of one run (replace-by-run refresh). Returns rows deleted.

    Touches ONLY this run_id's rows. With commit=False the delete joins the caller's transaction."""
    cur = conn.execute("DELETE FROM web_form_fields WHERE source_run_id = ?", (source_run_id,))
    if commit:
        conn.commit()
    return cur.rowcount


def add_web_form_field_rows(
    conn: sqlite3.Connection, rows: list[WebFormFieldRow], *, commit: bool = True
) -> int:
    """Insert flattened editable-web-form-field rows in one batch; return the count.

    Neutral front-end facts (an editable field name + the asset it came from). No verdict —
    web_settable crosses these against the back-end nvram_key_flow constant keys."""
    if not rows:
        return 0
    conn.executemany(
        """INSERT INTO web_form_fields
           (source_run_id, field_keyword, source_asset, source_rule)
           VALUES (?, ?, ?, ?)""",
        [(r.source_run_id, r.field_keyword, r.source_asset, r.source_rule) for r in rows],
    )
    if commit:
        conn.commit()
    return len(rows)


def add_private_exploit(
    conn: sqlite3.Connection,
    *,
    evidence_ref: str,
    pattern: str,
    exploit_note: str,
    patch_form: str | None = None,
    cve_id: str | None = None,
    redact: str = "vendor_sensitive",
    attributed_to: str | None = None,
    commit: bool = True,
) -> int:
    """Append one exploited-hole record (admission bar = EXPLOITED); return the row id.

    Storage-side guard for the bar: ``evidence_ref`` / ``pattern`` / ``exploit_note`` must be
    non-blank after stripping (SQLite's NOT NULL only blocks NULL, letting ''/'   ' through — the
    bar is "an exploited hole with proof", so a blank proof field is rejected here too). This does
    NOT verify the exploit is real — that is a human's judgement, never asserted by the tool.
    Append-only: one evidence_ref may gather several rows (corroboration), a later write never
    overwrites."""
    for field, val in (
        ("evidence_ref", evidence_ref),
        ("pattern", pattern),
        ("exploit_note", exploit_note),
    ):
        if not (val and val.strip()):
            raise ConfigError(
                f"private_exploit.{field} must be non-blank (the admission bar is a proven exploit)"
            )
    cur = conn.execute(
        """INSERT INTO private_exploit
               (evidence_ref, pattern, exploit_note, patch_form, cve_id, redact, attributed_to)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            evidence_ref.strip(),
            pattern.strip(),
            exploit_note.strip(),
            patch_form,
            cve_id,
            redact,
            attributed_to,
        ),
    )
    if commit:
        conn.commit()
    return int(cur.lastrowid)  # type: ignore[arg-type]


def add_public_cve_patterns(
    conn: sqlite3.Connection, rows: list[PublicCvePatternRow], *, commit: bool = True
) -> dict[str, int]:
    """Idempotent import of public-CVE exploit forms; return {inserted, skipped}.

    A row whose ``(cve_id, pattern, source, sink)`` already exists is SKIPPED, so re-running the
    same import never silently doubles the rows (which would not inflate barrier depth — that counts
    private only — but would pollute the public listing). ``pattern`` must be non-blank."""
    inserted = skipped = 0
    for r in rows:
        if not (r.pattern and r.pattern.strip()):
            raise ConfigError("public_cve_pattern.pattern must be non-blank")
        exists = conn.execute(
            """SELECT 1 FROM public_cve_pattern
               WHERE IFNULL(cve_id, '') = IFNULL(?, '') AND pattern = ?
                 AND IFNULL(source, '') = IFNULL(?, '') AND IFNULL(sink, '') = IFNULL(?, '')
               LIMIT 1""",
            (r.cve_id, r.pattern, r.source, r.sink),
        ).fetchone()
        if exists is not None:
            skipped += 1
            continue
        conn.execute(
            """INSERT INTO public_cve_pattern (cve_id, pattern, source, sink, ref, notes, origin)
               VALUES (?, ?, ?, ?, ?, ?, 'external_import')""",
            (r.cve_id, r.pattern, r.source, r.sink, r.ref, r.notes),
        )
        inserted += 1
    if commit:
        conn.commit()
    return {"inserted": inserted, "skipped": skipped}


def begin_run(
    conn: sqlite3.Connection,
    run_id: str,
    *,
    analysis_db_path: str | None = None,
    firmware_path: str | None = None,
    firmware_sha256: str | None = None,
    build_hash: str | None = None,
    tool_version: str | None = None,
    ghidra_version: str | None = None,
    machine: str | None = None,
    commit: bool = True,
) -> None:
    """Mark a run's scan STARTED: upsert its ``run`` row with scan_status='in_progress'.

    Written BEFORE the run's instances, so a crash mid-scan leaves 'in_progress' (the honest "did
    not finish" signal) rather than a silently-missing run behind half-written candidates. A re-scan
    resets the row to in_progress with the fresh lineage (its old instances are being replaced).
    ``analysis_db_path`` is the run_id -> analysis.db resolver a run-aware fact tool routes on."""
    conn.execute(
        """INSERT INTO run
               (run_id, analysis_db_path, firmware_path, firmware_sha256, build_hash,
                tool_version, ghidra_version, machine, scan_status, scanned_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'in_progress', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
           ON CONFLICT(run_id) DO UPDATE SET
               analysis_db_path = excluded.analysis_db_path,
               firmware_path    = excluded.firmware_path,
               firmware_sha256  = excluded.firmware_sha256,
               build_hash       = excluded.build_hash,
               tool_version     = excluded.tool_version,
               ghidra_version   = excluded.ghidra_version,
               machine          = excluded.machine,
               scan_status      = 'in_progress',
               scanned_at       = CURRENT_TIMESTAMP,
               updated_at       = CURRENT_TIMESTAMP""",
        (
            run_id,
            analysis_db_path,
            firmware_path,
            firmware_sha256,
            build_hash,
            tool_version,
            ghidra_version,
            machine,
        ),
    )
    if commit:
        conn.commit()


def finish_run(
    conn: sqlite3.Connection,
    run_id: str,
    *,
    scan_status: str = "complete",
    binaries: int | None = None,
    functions: int | None = None,
    functions_empty: int | None = None,
    commit: bool = True,
) -> None:
    """Mark a run's scan FINISHED: set scan_status (default 'complete') + the analysis counts.

    Called AFTER the run's instances are committed. If the row is missing (a code path that skipped
    begin_run) it is inserted, so a finished run is never invisible in list_runs."""
    if scan_status not in ("in_progress", "complete", "partial", "failed"):
        raise ConfigError(
            f"scan_status must be in_progress/complete/partial/failed; got {scan_status!r}"
        )
    cur = conn.execute(
        """UPDATE run SET scan_status = ?, binaries = ?, functions = ?, functions_empty = ?,
               updated_at = CURRENT_TIMESTAMP
           WHERE run_id = ?""",
        (scan_status, binaries, functions, functions_empty, run_id),
    )
    if cur.rowcount == 0:
        conn.execute(
            """INSERT INTO run
                   (run_id, scan_status, binaries, functions, functions_empty,
                    scanned_at, updated_at)
               VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)""",
            (run_id, scan_status, binaries, functions, functions_empty),
        )
    if commit:
        conn.commit()


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
            reachability_status, blocking_mechanism, exposure_shape, provenance_level,
            external_anchor, fix_diff, scope_origin, evidence_ref, binary_path,
            binary_content_hash, origin, is_thin_cmd_wrapper, wrapped_sink, flow_evidence)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            instance.pattern_id,
            instance.pseudocode_hash,
            instance.source_anchor,
            instance.sink_anchor,
            instance.source_run_id,
            instance.reachability_status,
            instance.blocking_mechanism,
            instance.exposure_shape,
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
            instance.flow_evidence,
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
            inst.exposure_shape,
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
            inst.flow_evidence,
        )
        for inst in instances
    ]
    conn.executemany(
        """INSERT INTO instance
           (pattern_id, pseudocode_hash, source_anchor, sink_anchor, source_run_id,
            reachability_status, blocking_mechanism, exposure_shape, provenance_level,
            external_anchor, fix_diff, scope_origin, evidence_ref, binary_path,
            binary_content_hash, origin, is_thin_cmd_wrapper, wrapped_sink, flow_evidence)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        rows,
    )

    pattern_ids = {inst.pattern_id for inst in instances}
    for pid in pattern_ids:
        _recompute_device_spread(conn, pid)
    conn.commit()

    return AtlasStats(patterns_touched=len(pattern_ids), instances_added=len(instances))
