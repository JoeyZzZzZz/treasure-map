# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import os
from pathlib import Path

from treasure_map.lib.analyze.elf_inventory import scan_filesystem
from treasure_map.lib.analyze.symlinks import (
    SymlinkCollector,
    classify_symlink,
    write_symlinks,
)
from treasure_map.lib.storage.connection import open_db


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "fs"
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "busybox").write_bytes(b"\x7fELFnot-really")
    return root


def _link(root: Path, at: str, target: str) -> Path:
    p = root / at
    p.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, p)
    return p


# ── classify_symlink: the four damage classes + the clean one ─────────────────────────


def test_resolved_link_records_final_target(tmp_path: Path) -> None:
    # A link onto a real file inside the root resolves: resolved=1, no damage reason, and
    # target_name is the FINAL target's basename (what the edge layer matches binaries against).
    root = _root(tmp_path)
    rec = classify_symlink(_link(root, "bin/sh", "busybox"), root)
    assert (rec.link_path, rec.link_name, rec.target_name) == ("bin/sh", "sh", "busybox")
    assert (rec.resolved, rec.corrupt_reason) == (1, None)
    assert rec.target_raw == "busybox"  # verbatim readlink value, not the resolved path


def test_absolute_target_is_rerooted_at_firmware_root(tmp_path: Path) -> None:
    # An absolute target inside a firmware image is relative to the IMAGE root, not the host's.
    # /bin/busybox must resolve to <fs_root>/bin/busybox.
    #
    # MUTATION (verified RED, 1 failed): in symlinks._reroot change
    #   `cand = root / target.lstrip("/") if target.startswith("/") else link_parent / target`
    # to `cand = Path(target) if target.startswith("/") else link_parent / target`
    # -> the target escapes the root -> corrupt_reason='escapes_root', resolved=0.
    root = _root(tmp_path)
    rec = classify_symlink(_link(root, "bin/sh", "/bin/busybox"), root)
    assert (rec.resolved, rec.corrupt_reason, rec.target_name) == (1, None, "busybox")


def test_devnull_placeholder_is_recorded_as_damaged(tmp_path: Path) -> None:
    # An extraction tool that could not reproduce a link may leave /dev/null behind. That is
    # DAMAGE, not a resolution — recorded with its reason so the reader is never told the token
    # was simply absent.
    #
    # MUTATION (verified RED, 1 failed): in symlinks.classify_symlink neutralize the placeholder
    # test — replace `if os.path.normpath(raw) == _DEVNULL:` with `if False:` — so the link falls
    # through to the chain walk and is reported 'dangling' instead of 'devnull_placeholder'.
    root = _root(tmp_path)
    rec = classify_symlink(_link(root, "bin/find", "/dev/null"), root)
    assert (rec.resolved, rec.corrupt_reason) == (0, "devnull_placeholder")


def test_a_real_file_named_null_is_not_a_placeholder(tmp_path: Path) -> None:
    # The placeholder test is on the FULL path only. A link onto a genuine file called `null`
    # resolves normally — a basename test would falsely damage it.
    #
    # MUTATION (verified RED, 1 failed): in symlinks.classify_symlink widen the test to
    #   `if os.path.normpath(raw) == _DEVNULL or Path(raw).name == "null":`
    # -> this real target is flagged devnull_placeholder.
    root = _root(tmp_path)
    (root / "bin" / "null").write_bytes(b"real")
    rec = classify_symlink(_link(root, "bin/n", "null"), root)
    assert (rec.resolved, rec.corrupt_reason, rec.target_name) == (1, None, "null")


def test_dangling_link_is_recorded_as_damaged(tmp_path: Path) -> None:
    # Target inside the root, nothing there.
    root = _root(tmp_path)
    rec = classify_symlink(_link(root, "bin/gone", "missing_thing"), root)
    assert (rec.resolved, rec.corrupt_reason, rec.target_name) == (0, "dangling", "missing_thing")


def test_escaping_link_never_consults_the_host_filesystem(tmp_path: Path) -> None:
    # ★ A link climbing out of the firmware root must be recorded escapes_root WITHOUT testing
    # whether the host has such a file — a host file must never make a firmware link read as
    # resolved. The escape test therefore runs BEFORE the existence test. Here the climb lands on
    # a file that really does exist outside the root, so an existence-first order would report
    # resolved=1.
    #
    # MUTATION (verified RED, 1 failed): in symlinks.classify_symlink reorder the loop body so
    # existence is judged first — replace the `if nxt is None: return ... ESCAPES_ROOT` block with
    #   `if nxt is None:
    #        nxt = Path(os.path.normpath(current.parent / value))`
    # -> the outside file is found -> resolved=1, corrupt_reason=None.
    root = _root(tmp_path)
    outside = tmp_path / "outside_secret"
    outside.write_text("host content")
    rec = classify_symlink(_link(root, "bin/climb", "../../outside_secret"), root)
    assert (rec.resolved, rec.corrupt_reason) == (0, "escapes_root")


def test_symlink_cycle_terminates_as_unresolved(tmp_path: Path) -> None:
    # A -> B -> A must not read as resolved and must not spin.
    root = _root(tmp_path)
    _link(root, "bin/a", "b")
    rec = classify_symlink(_link(root, "bin/b", "a"), root)
    assert (rec.resolved, rec.corrupt_reason) == (0, "chain_unresolved")


def test_chain_through_two_links_reaches_the_real_target(tmp_path: Path) -> None:
    # sh -> ash -> busybox: the recorded target is the END of the chain, not the middle.
    root = _root(tmp_path)
    _link(root, "bin/ash", "busybox")
    rec = classify_symlink(_link(root, "bin/sh", "ash"), root)
    assert (rec.resolved, rec.target_name) == (1, "busybox")


# ── the collector: the walk must SEE the damaged links ────────────────────────────────


def test_collector_sees_links_that_is_file_would_hide(tmp_path: Path) -> None:
    # ★ THE ORDERING GUARD. is_file() FOLLOWS a symlink, so a dangling or /dev/null link answers
    # False there. A collector placed after an `is_file()` test therefore never sees exactly the
    # two damage classes that matter. Both must be collected here.
    #
    # MUTATION (verified RED, 1 failed): in elf_inventory.scan_filesystem put the is_file() test
    # FIRST — `if not fpath.is_file(): continue`, then compute `is_link` and `if is_link: continue`
    # -> collected names become {'good'} only, so the two damaged links vanish.
    root = _root(tmp_path)
    _link(root, "bin/dead", "nowhere")
    _link(root, "bin/placeholder", "/dev/null")
    _link(root, "bin/good", "busybox")
    collector = SymlinkCollector(root)
    scan_filesystem(root, symlink_collector=collector)
    by_name = {r.link_name: r for r in collector.records}
    assert set(by_name) == {"dead", "placeholder", "good"}
    assert by_name["dead"].corrupt_reason == "dangling"
    assert by_name["placeholder"].corrupt_reason == "devnull_placeholder"
    assert by_name["good"].resolved == 1


def test_collector_is_idempotent_across_walks(tmp_path: Path) -> None:
    # Keyed by link path, so two walks over the same root may share one collector without
    # double-counting (what makes the collector safe to share).
    root = _root(tmp_path)
    _link(root, "bin/sh", "busybox")
    collector = SymlinkCollector(root)
    scan_filesystem(root, symlink_collector=collector)
    scan_filesystem(root, symlink_collector=collector)
    assert len(collector.records) == 1


def test_scan_filesystem_still_skips_symlinked_binaries(tmp_path: Path) -> None:
    # Regression: collecting a link must not start ingesting it as a binary (Ghidra would write
    # output under the wrong name). The real ELF is found once, its link is not a second record.
    root = _root(tmp_path)
    _link(root, "bin/sh", "busybox")
    records = scan_filesystem(root, symlink_collector=SymlinkCollector(root))
    assert [r.name for r in records] == []  # the fixture bytes are not a loadable ELF


# ── persistence: wipe-and-rebuild into analysis.db ────────────────────────────────────


def test_write_symlinks_persists_both_lookup_columns(tmp_path: Path) -> None:
    # The edge layer looks up an absolute token by link_path and a bare token by link_name, so
    # both must land, together with the damage reason.
    #
    # MUTATION (verified RED, 1 failed): in symlinks.write_symlinks drop link_name from the
    # INSERT column list and its value from the row tuple -> the bare-name lookup column is NULL
    # -> assertion on ('bin/sh', 'sh', 'busybox', 1, None) fails.
    root = _root(tmp_path)
    _link(root, "bin/sh", "busybox")
    _link(root, "bin/find", "/dev/null")
    collector = SymlinkCollector(root)
    scan_filesystem(root, symlink_collector=collector)

    conn = open_db(tmp_path / "a.db")
    try:
        assert write_symlinks(conn, collector.records) == 2
        rows = conn.execute(
            "SELECT link_path, link_name, target_name, resolved, corrupt_reason "
            "FROM fs_symlinks ORDER BY link_path"
        ).fetchall()
        assert [tuple(r) for r in rows] == [
            ("bin/find", "find", "null", 0, "devnull_placeholder"),
            ("bin/sh", "sh", "busybox", 1, None),
        ]
    finally:
        conn.close()


def test_write_symlinks_is_wipe_and_rebuild(tmp_path: Path) -> None:
    # A re-analyze of a changed root replaces the inventory; a link that is gone must not linger.
    root = _root(tmp_path)
    _link(root, "bin/sh", "busybox")
    collector = SymlinkCollector(root)
    scan_filesystem(root, symlink_collector=collector)

    conn = open_db(tmp_path / "a.db")
    try:
        write_symlinks(conn, collector.records)
        write_symlinks(conn, [])
        assert conn.execute("SELECT COUNT(*) FROM fs_symlinks").fetchone()[0] == 0
    finally:
        conn.close()
