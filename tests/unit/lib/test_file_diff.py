# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The non-binary files of two runs, compared by path at read time (lib/query/file_diff, the
get_file_diff tool), and the judgements on them (annotate_diff with run_pair).

Every fixture is synthetic: two analysis databases, two firmware roots on disk and an atlas whose
run pair has no binary diff — files are compared whether or not one exists.
"""

from __future__ import annotations

import asyncio
import difflib
import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from tests.unit.lib.test_patch_view import DIFF, _listed, _pages, _summary_world
from tests.unit.lib.test_patch_view import current as current  # the fixture, shared
from treasure_map import mcp_app
from treasure_map.lib import overlay
from treasure_map.lib.analyze.ghidra_runner import current_pass_version
from treasure_map.lib.atlas.connection import open_atlas
from treasure_map.lib.atlas.writer import begin_run, finish_run
from treasure_map.lib.query import diff_review as dr
from treasure_map.lib.query import file_diff as fd
from treasure_map.lib.storage.connection import open_db

PAIR = "runA::runB"
STALE_BUILD = "0000staleaaaa000"
_WORDS = {"removed", "added", "gone", "new", "bounded", "safe", "fix", "patch", "regression"}
MATERIAL = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ-synthetic-material"
SECRET_VALUE = "hunter2-synthetic"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FW:
    """runA / runB (current) and runS (provably stale), each with its analysis.db and firmware
    root. No diff_meta row: the pair has no binary diff."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.path = tmp / "atlas.db"
        atlas = open_atlas(self.path)
        self.db: dict[str, sqlite3.Connection] = {}
        self.root: dict[str, Path] = {}
        self.db_path: dict[str, Path] = {}
        for side, run, build in (
            ("a", "runA", current_pass_version()),
            ("b", "runB", current_pass_version()),
            ("s", "runS", STALE_BUILD),
        ):
            db = tmp / f"analysis_{side}.db"
            self.db_path[side] = db
            self.db[side] = open_db(db)
            root = tmp / f"fw_{side}"
            root.mkdir()
            self.root[side] = root
            begin_run(
                atlas,
                run,
                analysis_db_path=str(db),
                firmware_path=str(root),
                build_hash=build,
            )
            finish_run(atlas, run, binaries=0, functions=0)
        atlas.commit()
        atlas.close()

    def file(
        self,
        side: str,
        path: str | None,
        kind: str,
        data: bytes | str | None = None,
        *,
        sha: str | None | bool = True,
        write: bool = True,
    ) -> int:
        """One non_binary_files row (sha256 of ``data`` unless ``sha`` is given or None), with the
        file written under the side's root."""
        raw = data.encode() if isinstance(data, str) else (data or b"")
        if write and path is not None:
            target = self.root[side] / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        digest = _sha(raw) if sha is True else (sha or None)
        cur = self.db[side].execute(
            "INSERT INTO non_binary_files (kind, name, path, sha256, size_bytes) "
            "VALUES (?, ?, ?, ?, ?)",
            (kind, Path(path or "nopath").name, path, digest, len(raw)),
        )
        self.db[side].commit()
        return int(cur.lastrowid or 0)

    def row(self, side: str, table: str, file_id: int, **cols: Any) -> None:
        names = ["file_id", *cols]
        self.db[side].execute(
            f"INSERT INTO {table} ({', '.join(names)}) VALUES ({', '.join('?' * len(names))})",
            (file_id, *cols.values()),
        )
        self.db[side].commit()

    def atlas(self) -> sqlite3.Connection:
        conn = open_atlas(self.path)
        return conn

    def diff(self, **kw: Any) -> dict[str, Any]:
        conn = self.atlas()
        try:
            return fd.file_diff(conn, "runA", "runB", **kw)
        finally:
            conn.close()

    def tools(self) -> dict[str, Any]:
        return mcp_app.make_tools(self.path)


@pytest.fixture
def fw(tmp_path: Path) -> FW:
    return FW(tmp_path)


def _by_path(out: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {e["path"]: e for e in out["entries"]}


# ── files by path, counted by kind ─────────────────────────────────────────────────────────


def _alignment_world(fw: FW) -> None:
    fw.file("a", "etc/only_a.sh", "shell_script", "echo a\n")
    fw.file("b", "etc/only_b.sh", "shell_script", "echo b\n")
    fw.file("a", "etc/changed.conf", "config_file", "k=1\n")
    fw.file("b", "etc/changed.conf", "config_file", "k=2\n")
    fw.file("a", "etc/same.conf", "config_file", "x=1\n")
    fw.file("b", "etc/same.conf", "config_file", "x=1\n")
    fw.file("a", "www/u.js", "web_asset", "var a;\n", sha=None)
    fw.file("b", "www/u.js", "web_asset", "var a;\n")
    fw.file("a", None, "shell_script", "x", write=False)
    fw.file("b", "lib/m.ko", "kernel_module", "ko-b")
    fw.file("a", "lib/m.ko", "kernel_module", "ko-a")
    fw.file("a", "etc/kind.txt", "config_file", "v=1\n")
    fw.file("b", "etc/kind.txt", "shell_script", "v=2\n")


def test_files_align_by_path_and_are_counted_by_kind(fw: FW) -> None:
    """Each path reads a_only / b_only / content_differs / same / undetermined (a side with no
    sha256 is never read as same); a row with no path is counted apart; a path whose kind
    differs carries both kinds and counts under the B side's. The counts match a hand count by
    path and sha256; a page lists the files that differ, same only when asked for.

    MUTATION (verified RED): read a missing sha256 as equal -> the undetermined file reads same
    -> RED."""
    _alignment_world(fw)
    out = fw.diff()
    assert out["counts"] == {
        "a_only": 1,
        "b_only": 1,
        "content_differs": 3,
        "same": 1,
        "undetermined": 1,
    }
    assert out["counts_by_kind"] == {
        "shell_script": dict(a_only=1, b_only=1, content_differs=1, same=0, undetermined=0),
        "config_file": dict(a_only=0, b_only=0, content_differs=1, same=1, undetermined=0),
        "web_asset": dict(a_only=0, b_only=0, content_differs=0, same=0, undetermined=1),
        "kernel_module": dict(a_only=0, b_only=0, content_differs=1, same=0, undetermined=0),
    }
    assert out["unaligned_null_path"] == {"a": 1, "b": 0}
    by = _by_path(out)
    assert set(by) == {
        "etc/only_a.sh",
        "etc/only_b.sh",
        "etc/changed.conf",
        "www/u.js",
        "lib/m.ko",
        "etc/kind.txt",
    }
    assert by["www/u.js"]["change"] == "undetermined"
    assert by["etc/kind.txt"]["kind_a"] == "config_file"
    assert by["etc/kind.txt"]["kind_b"] == "shell_script" and "kind" not in by["etc/kind.txt"]
    assert "content_differs" not in by["etc/changed.conf"] or by["etc/changed.conf"]["change"]
    assert not any(
        isinstance(v, bool) for e in out["entries"] for k, v in e.items() if k == "content_differs"
    )
    assert [e["path"] for e in fw.diff(change="same")["entries"]] == ["etc/same.conf"]
    assert {e["path"] for e in fw.diff(kind="config_file")["entries"]} == {
        "etc/changed.conf",
        "etc/kind.txt",
    }
    assert by["lib/m.ko"]["structured"] == {"structured_available": "no_ingester"}


# ── structured comparisons ─────────────────────────────────────────────────────────────────


def test_a_script_line_dropped_once_of_two_is_seen_with_its_count(fw: FW) -> None:
    """script_calls compare as a multiset of their raw lines: one of two identical lines dropped
    shows count 1, and a changed line shows on each side.

    MUTATION (verified RED): compare as sets -> the dropped duplicate is invisible -> RED."""
    a = fw.file("a", "sbin/run.sh", "shell_script", "a\n")
    b = fw.file("b", "sbin/run.sh", "shell_script", "b\n")
    for n in (3, 9):
        fw.row(
            "a",
            "script_calls",
            a,
            command="/sbin/ctl",
            raw_line="/sbin/ctl reboot &",
            line_number=n,
        )
    fw.row("a", "script_calls", a, command="/sbin/up", raw_line="/sbin/up -c 1", line_number=12)
    fw.row(
        "b", "script_calls", b, command="/sbin/ctl", raw_line=" /sbin/ctl reboot & ", line_number=4
    )
    fw.row("b", "script_calls", b, command="/sbin/up", raw_line="/sbin/up -c 2", line_number=12)
    block = _by_path(fw.diff())["sbin/run.sh"]["structured"]
    assert block["recorded_scope"] == fd.SCOPES["shell_script"]
    assert block["commands_a_only"] == [
        {"command": "/sbin/ctl", "raw_line": "/sbin/ctl reboot &", "line_number": 3, "count": 1},
        {"command": "/sbin/up", "raw_line": "/sbin/up -c 1", "line_number": 12, "count": 1},
    ]
    assert block["commands_b_only"] == [
        {"command": "/sbin/up", "raw_line": "/sbin/up -c 2", "line_number": 12, "count": 1}
    ]


def test_a_config_value_is_shown_unless_sensitive_and_no_rows_say_so(fw: FW) -> None:
    """A changed non-sensitive value shows both values; a sensitive one says only that it changed
    (its value nowhere in the output); keys on one side keep their count; no recorded entries on
    either side says so; recorded rows equal under a differing sha256 say so.

    MUTATION (verified RED): show a sensitive value -> RED."""
    a = fw.file("a", "etc/app.conf", "config_file", "a\n")
    b = fw.file("b", "etc/app.conf", "config_file", "b\n")
    fw.row("a", "config_entries", a, section="s", key="port", value="80", is_sensitive=0)
    fw.row("b", "config_entries", b, section="s", key="port", value="8080", is_sensitive=0)
    fw.row("a", "config_entries", a, section="s", key="pass", value="old-synthetic", is_sensitive=1)
    fw.row("b", "config_entries", b, section="s", key="pass", value=SECRET_VALUE, is_sensitive=1)
    fw.row("b", "config_entries", b, section=None, key="debug", value="1", is_sensitive=0)
    fw.file("a", "etc/plain.conf", "config_file", "1\n")
    fw.file("b", "etc/plain.conf", "config_file", "2\n")
    c = fw.file("a", "etc/rows.conf", "config_file", "1\n")
    d = fw.file("b", "etc/rows.conf", "config_file", "2\n")
    fw.row("a", "config_entries", c, section=None, key="k", value="v", is_sensitive=0)
    fw.row("b", "config_entries", d, section=None, key="k", value="v", is_sensitive=0)
    out = fw.diff()
    by = _by_path(out)
    block = by["etc/app.conf"]["structured"]
    assert block["keys_b_only"] == [{"section": None, "key": "debug", "count": 1}]
    assert block["keys_changed"] == [
        {"section": "s", "key": "pass", "value_changed": True},
        {"section": "s", "key": "port", "value": ["80", "8080"]},
    ]
    assert SECRET_VALUE not in json.dumps(out) and "old-synthetic" not in json.dumps(out)
    plain = by["etc/plain.conf"]["structured"]
    assert plain["structured_available"] == "no_recorded_rows"
    assert plain["no_recorded_entries"] is True
    assert by["etc/rows.conf"]["structured"]["recorded_rows_same"] is True


def test_credentials_by_identifier_or_by_row_never_with_material(fw: FW) -> None:
    """Credentials compare per (cred_type, algorithm): by identifier when each side's identifiers
    are non-empty and unique (material_changed for one whose material moved), else as a multiset
    of rows (identity_not_unique). The material is in no output, nor any hash computed over it;
    the one hash of it that is given is a file's own sha256 when the file's whole content is that
    material (a single-key PEM file) — the file-level sha256 every file carries.

    MUTATION (verified RED): compare the rows as a set -> a third identical certificate on B is
    invisible -> RED. MUTATION (verified RED): fall back to rows when identifiers are unique ->
    no identifiers_changed -> RED."""
    a = fw.file("a", "etc/shadow", "credential", "root:x\n")
    b = fw.file("b", "etc/shadow", "credential", "root:y\n")
    for side, fid, mat in (("a", a, "hash-a"), ("b", b, "hash-b")):
        fw.row(
            side,
            "credentials",
            fid,
            cred_type="shadow_entry",
            identifier="root",
            algorithm="sha512crypt",
            material=MATERIAL + mat,
            is_sensitive=1,
        )
    fw.row(
        "b",
        "credentials",
        b,
        cred_type="shadow_entry",
        identifier="admin",
        algorithm="sha512crypt",
        material=MATERIAL + "x",
        is_sensitive=1,
    )
    c = fw.file("a", "etc/pub.crt", "credential", "c1\n")
    d = fw.file("b", "etc/pub.crt", "credential", "c2\n")
    for _ in range(2):
        fw.row(
            "a",
            "credentials",
            c,
            cred_type="certificate",
            identifier=None,
            algorithm="rsa",
            material=MATERIAL,
            is_sensitive=0,
        )
    for _ in range(3):
        fw.row(
            "b",
            "credentials",
            d,
            cred_type="certificate",
            identifier=None,
            algorithm="rsa",
            material=MATERIAL,
            is_sensitive=0,
        )
    out = fw.diff()
    by = _by_path(out)
    shadow = by["etc/shadow"]["structured"]["groups"]
    assert shadow == [
        {
            "cred_type": "shadow_entry",
            "algorithm": "sha512crypt",
            "identifiers_a_only": [],
            "identifiers_b_only": ["admin"],
            "identifiers_changed": [{"identifier": "root", "material_changed": True}],
        }
    ]
    assert by["etc/pub.crt"]["structured"]["groups"] == [
        {
            "cred_type": "certificate",
            "algorithm": "rsa",
            "identity_not_unique": True,
            "rows_a": 2,
            "rows_b": 3,
            "rows_only_a": 0,
            "rows_only_b": 1,
        }
    ]
    text = json.dumps(out) + json.dumps(fw.diff(path="etc/shadow"))
    assert MATERIAL not in text and "hash-a" not in text
    # a single-key file: its sha256 is the material's, given as the file's own and nowhere else
    pem = MATERIAL + "-pem"
    e = fw.file("a", "etc/key.pem", "credential", pem)
    f = fw.file("b", "etc/key.pem", "credential", pem + "2")
    fw.row(
        "a",
        "credentials",
        e,
        cred_type="private_key",
        identifier=None,
        algorithm="rsa",
        material=pem,
        is_sensitive=1,
    )
    fw.row(
        "b",
        "credentials",
        f,
        cred_type="private_key",
        identifier=None,
        algorithm="rsa",
        material=pem + "2",
        is_sensitive=1,
    )
    key_page = fw.diff(path="etc/key.pem")
    assert key_page["entry"]["sha_a"] == _sha(pem.encode())
    assert pem not in json.dumps(key_page)
    assert json.dumps(key_page).count(_sha(pem.encode())) == 1
    for m in (MATERIAL, MATERIAL + "hash-a", MATERIAL + "hash-b"):
        assert _sha(m.encode()) not in text
        assert hashlib.md5(m.encode()).hexdigest() not in text  # noqa: S324 -- a probe only


def test_web_endpoints_and_form_fields_as_multisets(fw: FW) -> None:
    a = fw.file("a", "www/app.js", "web_asset", "1\n")
    b = fw.file("b", "www/app.js", "web_asset", "2\n")
    fw.row("a", "web_endpoints", a, asset_type="js", method="POST", path="/api/x", source="fetch")
    for _ in range(2):
        fw.row(
            "b", "web_endpoints", b, asset_type="js", method="POST", path="/api/x", source="fetch"
        )
    fw.row("a", "web_form_fields", a, field_keyword="wan_mode")
    block = _by_path(fw.diff())["www/app.js"]["structured"]
    assert block["endpoints_a_only"] == []
    assert block["endpoints_b_only"] == [
        {"asset_type": "js", "method": "POST", "path": "/api/x", "source": "fetch", "count": 1}
    ]
    assert block["form_fields_a_only"] == [{"field_keyword": "wan_mode", "count": 1}]


# ── the text difference ────────────────────────────────────────────────────────────────────


def test_the_hunk_is_difflib_and_a_list_page_gives_only_its_stats(fw: FW) -> None:
    """A file's own page gives the unified difference (3 lines of context, no file headers); the
    list page only its stats; a file on one side only is compared with an empty file.

    MUTATION (verified RED): put the hunk text on the list page -> RED."""
    old = "".join(f"line {i}\n" for i in range(20))
    new = old.replace("line 7\n", "line seven\n") + "tail\n"
    fw.file("a", "etc/rc", "shell_script", old)
    fw.file("b", "etc/rc", "shell_script", new)
    fw.file("b", "etc/fresh", "shell_script", "one\ntwo\n")
    expected = list(difflib.unified_diff(old.splitlines(), new.splitlines(), n=3, lineterm=""))[2:]
    listed = _by_path(fw.diff())
    assert "hunk" not in listed["etc/rc"]
    assert listed["etc/rc"]["hunk_stats"] == {
        "plus_lines": 2,
        "minus_lines": 1,
        "segments": 2,
        "bytes": len("\n".join(expected).encode()),
    }
    one = fw.diff(path="etc/rc")["entry"]
    assert one["hunk"]["lines"] == expected and one["hunk"]["next_hunk_offset"] is None
    fresh = fw.diff(path="etc/fresh")["entry"]
    assert fresh["change"] == "b_only"
    assert fresh["hunk"]["lines"] == ["@@ -0,0 +1,2 @@", "+one", "+two"]


def test_a_hunk_is_read_only_inside_the_root_and_only_as_scanned(fw: FW, tmp_path: Path) -> None:
    """A path resolving outside the firmware root, bytes that are not the scanned ones, a NUL
    byte, a missing file and a run with no root each name why there is no hunk.

    MUTATION (verified RED): drop the realpath containment -> the outside file is read -> RED.
    MUTATION (verified RED): skip the sha256 check -> the edited file is read -> RED."""
    outside = tmp_path / "host_secret.txt"
    outside.write_text("host file\n")
    fw.file("a", "etc/link", "config_file", "x\n")
    link = fw.root["b"] / "etc" / "link"
    link.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(outside, link)
    fw.file("b", "etc/link", "config_file", "host file\n", write=False)
    fw.file("a", "etc/edited", "config_file", "1\n")
    fw.file("b", "etc/edited", "config_file", "2\n")
    (fw.root["b"] / "etc" / "edited").write_text("edited after the scan\n")
    fw.file("a", "etc/bin", "config_file", "a\0b")
    fw.file("b", "etc/bin", "config_file", "a\0c")
    fw.file("a", "etc/gone", "config_file", "1\n")
    fw.file("b", "etc/gone", "config_file", "2\n")
    (fw.root["b"] / "etc" / "gone").unlink()
    by = _by_path(fw.diff())
    assert by["etc/link"].get("hunk_unavailable") == "outside_firmware_root"
    assert by["etc/edited"].get("hunk_unavailable") == "content_differs_from_scan"
    assert by["etc/bin"].get("hunk_unavailable") == "binary_content"
    assert by["etc/gone"].get("hunk_unavailable") == "file_missing"
    assert "host file" not in json.dumps(fw.diff(path="etc/link"))
    conn = fw.atlas()
    conn.execute("UPDATE run SET firmware_path = NULL WHERE run_id = 'runA'")
    conn.commit()
    conn.close()
    assert _by_path(fw.diff())["etc/bin"].get("hunk_unavailable") == "no_firmware_root"


_PEM = "-----BEGIN RSA PRIVATE KEY-----"
_HASH = "$saltsalt$" + "A" * 22
_CRYPT = f"root:$6{_HASH}:0:0"
# The ways a key or a hash sits inside a script or an asset: quoted, echoed, in a string literal
# with an escaped newline, printed, assigned, passed as an argument, in JSON, with rounds=.
_EMBEDDED = [
    f'echo "{_PEM}" > /tmp/k',
    'var k = "-----BEGIN PRIVATE KEY-----\\nMIIE";',
    "printf '-----BEGIN EC PRIVATE KEY-----\\n'",
    f'PASS="$1{_HASH}"',
    f"usermod -p '$1{_HASH}' root",
    f'{{"pw":"$1{_HASH}"}}',
    f"x $6$rounds=5000{_HASH}",
]


@pytest.mark.parametrize(
    ("kind", "b_text", "reason"),
    [
        ("credential", "key2\n", "credential_material"),
        ("shell_script", f"echo\n{_PEM}\nMIIB\n", "embedded_secret"),
        ("shell_script", f"echo\n{_CRYPT}\n", "embedded_secret"),
        *(("shell_script", f"echo\n{line}\n", "embedded_secret") for line in _EMBEDDED),
    ],
)
def test_a_secret_bearing_difference_gives_its_shape_only(
    fw: FW, kind: str, b_text: str, reason: str
) -> None:
    """A credential file, or a difference holding a full private-key header or crypt hash, gives
    no text — on the list page or its own page — only the shape of each segment.

    MUTATION (verified RED): leave the content scan out -> the key's text is given -> RED.
    MUTATION (verified RED): anchor the key header to a whole line, or read a hash only after a
    line start / ``:`` / ``=`` / ``,`` / space, without rounds= -> the embedded forms are given ->
    RED."""
    fw.file("a", "etc/f", kind, "echo\n")
    fw.file("b", "etc/f", kind, b_text)
    listed = _by_path(fw.diff())["etc/f"]
    assert listed.get("hunk_suppressed") == reason and "bytes" not in listed["hunk_stats"]
    one = fw.diff(path="etc/f")["entry"]
    assert "hunk" not in one and one["hunk_suppressed"] == reason
    segments = one["hunk_shape"]["segments"]
    assert segments and set(segments[0]) == {"range", "plus_lines", "minus_lines"}
    text = json.dumps(one)
    assert "PRIVATE KEY" not in text and "saltsalt" not in text and "key2" not in text


def test_a_sensitive_entry_suppresses_the_hunk(fw: FW) -> None:
    a = fw.file("a", "etc/app.conf", "config_file", "pass=old\n")
    b = fw.file("b", "etc/app.conf", "config_file", f"pass={SECRET_VALUE}\n")
    fw.row("b", "config_entries", b, section=None, key="pass", value=SECRET_VALUE, is_sensitive=1)
    assert a
    one = fw.diff(path="etc/app.conf")["entry"]
    assert one["hunk_suppressed"] == "sensitive_entry"
    assert SECRET_VALUE not in json.dumps(one)


def test_a_bare_dollar_one_is_not_a_secret(fw: FW) -> None:
    """A regex replacement holding ``$1$`` is not a crypt hash: the difference is given.

    MUTATION (verified RED): match a bare ``$1$`` substring -> RED."""
    fw.file("a", "etc/fix.sh", "shell_script", "echo\n")
    fw.file("b", "etc/fix.sh", "shell_script", "sed -e 's/\\$1\\$/x/' -e 's/$1$abc/y/' f $1$2\n")
    one = fw.diff(path="etc/fix.sh")["entry"]
    assert "hunk_suppressed" not in one and one["hunk"]["lines"][-1].startswith("+sed")


def test_a_secret_past_the_first_page_still_suppresses(fw: FW) -> None:
    """The scan reads the whole difference before it is paged: a key on a later page holds back
    every page.

    MUTATION (verified RED): scan the first page only -> RED."""
    big = "".join(f"echo {i} {'x' * 200}\n" for i in range(400))
    fw.file("a", "etc/long.sh", "shell_script", "start\n")
    fw.file("b", "etc/long.sh", "shell_script", big + _PEM + "\n")
    one = fw.diff(path="etc/long.sh")["entry"]
    assert one.get("hunk_suppressed") == "embedded_secret" and "hunk" not in one


def test_a_long_difference_pages_and_a_long_line_is_cut(fw: FW) -> None:
    """The text pages by hunk_offset within the page budget; one line longer than a piece is cut
    into pieces that join back to it (line_cut, cut_at the pieces that continue).

    MUTATION (verified RED): page by lines without cutting -> a page over the budget -> RED."""
    line = "v=" + "".join(chr(0x4E00 + i % 50) for i in range(155_000 // 3))
    fw.file("a", "www/big.js", "web_asset", "var a;\n")
    fw.file("b", "www/big.js", "web_asset", "var a;\n" + line + "\n")
    pieces: list[str] = []
    cut: list[int] = []
    offset: int | None = 0
    pages = 0
    while offset is not None:
        h = fw.diff(path="www/big.js", hunk_offset=offset)["entry"]["hunk"]
        assert len(json.dumps(h["lines"], separators=(",", ":"))) <= fd.HUNK_PAGE_BYTES + 100
        pieces += h["lines"]
        cut += h.get("cut_at", [])
        offset = h["next_hunk_offset"]
        pages += 1
    assert pages > 3 and cut
    first_plus = next(i for i, p in enumerate(pieces) if p.startswith("+v="))
    joined = "".join(pieces[first_plus : max(cut) + 2])
    assert joined == "+" + line


def _walk_file(tools: dict[str, Any], path: str) -> tuple[list[dict[str, Any]], list[int]]:
    """Every page of one file through the MCP tool — its structured lists by offset, then its
    text by hunk_offset — and each page's size in bytes."""
    pages, sizes = [], []
    offset: int | None = 0
    while offset is not None:
        page = tools["get_file_diff"](PAIR, path=path, offset=offset, limit=200)
        assert "error" not in page, page
        pages.append(page)
        sizes.append(len(json.dumps(page)))
        offset = page["entry"]["structured"]["lists_paging"]["next_offset"]
    hunk_offset = pages[0]["entry"].get("hunk", {}).get("next_hunk_offset")
    while hunk_offset is not None:
        page = tools["get_file_diff"](PAIR, path=path, hunk_offset=hunk_offset)
        assert "error" not in page, page
        assert "structured" not in page["entry"]
        assert page["entry"]["structured_on_page"] == "hunk_offset=0"
        pages.append(page)
        sizes.append(len(json.dumps(page)))
        hunk_offset = page["entry"]["hunk"]["next_hunk_offset"]
    return pages, sizes


def test_a_file_with_many_recorded_rows_pages_within_the_budget(fw: FW) -> None:
    """A script with 600 recorded lines per side and a long difference: through the MCP tool its
    own page gives the structured lists a page at a time (offset) and the text a page at a time
    (hunk_offset), each page within 48,000 bytes, the lists only on the pages with hunk_offset 0
    and the text only on those with offset 0; the pages together hold every item once.

    MUTATION (verified RED): give the whole structured block on every page -> pages over the
    budget -> RED."""
    a_lines = [f"/usr/sbin/tool --set opt_{i} {'v' * 60} &" for i in range(600)]
    b_lines = [f"/usr/sbin/tool --set opt_{i} {'w' * 60} &" for i in range(600)]
    a = fw.file("a", "etc/init.sh", "shell_script", "\n".join(a_lines) + "\n")
    b = fw.file("b", "etc/init.sh", "shell_script", "\n".join(b_lines) + "\n")
    for side, fid, lines in (("a", a, a_lines), ("b", b, b_lines)):
        for n, line in enumerate(lines, start=1):
            fw.row(
                side, "script_calls", fid, command="/usr/sbin/tool", raw_line=line, line_number=n
            )
    pages, sizes = _walk_file(fw.tools(), "etc/init.sh")
    assert len(pages) > 4 and max(sizes) <= 48_000, sizes
    assert not any(p.get("over_budget") for p in pages)
    seen_a = [
        i["raw_line"]
        for p in pages
        if "structured" in p["entry"]
        for i in p["entry"]["structured"]["commands_a_only"]
    ]
    seen_b = [
        i["raw_line"]
        for p in pages
        if "structured" in p["entry"]
        for i in p["entry"]["structured"]["commands_b_only"]
    ]
    assert seen_a == a_lines and seen_b == b_lines
    with_text = [p for p in pages if "hunk" in p["entry"]]
    assert all(p["entry"].get("hunk_on_page") is None for p in with_text)
    assert any(p["entry"].get("hunk_on_page") == "offset=0" for p in pages)
    text = [x for p in with_text for x in p["entry"]["hunk"]["lines"]]
    expected = list(difflib.unified_diff(a_lines, b_lines, n=3, lineterm=""))[2:]
    assert text == expected


def test_a_suppressed_shape_pages_and_both_offsets_are_refused(fw: FW) -> None:
    """A suppressed difference of many segments gives its shape a page at a time; offset and
    hunk_offset both above 0 is refused, naming which pages what."""
    a = "".join(f"k{i}=1\n" + "".join(f"# {i}.{j}\n" for j in range(7)) for i in range(600))
    b = a.replace("=1", "=2") + _PEM + "\n"
    fw.file("a", "etc/big.conf", "config_file", a)
    fw.file("b", "etc/big.conf", "config_file", b)
    tools = fw.tools()
    sizes, segments = [], 0
    hunk_offset: int | None = 0
    while hunk_offset is not None:
        page = tools["get_file_diff"](PAIR, path="etc/big.conf", hunk_offset=hunk_offset)
        shape = page["entry"]["hunk_shape"]
        sizes.append(len(json.dumps(page)))
        segments += len(shape["segments"])
        hunk_offset = shape["next_hunk_offset"]
    assert len(sizes) > 1 and max(sizes) <= 48_000 and segments == shape["total_segments"]
    both = tools["get_file_diff"](PAIR, path="etc/big.conf", offset=1, hunk_offset=1)
    assert "error" in both and "not both" in both["error"]


def test_a_list_page_cuts_each_list_to_ten_and_says_so(fw: FW) -> None:
    """On a list page each structured list keeps 10 items, its total under lists_cut; the file's
    own page holds them all.

    MUTATION (verified RED): leave the list-page lists whole -> RED."""
    a = fw.file("a", "www/app.js", "web_asset", "1\n")
    fw.file("b", "www/app.js", "web_asset", "2\n")
    for i in range(14):
        fw.row("a", "web_form_fields", a, field_keyword=f"field_{i:02d}")
    block = _by_path(fw.diff())["www/app.js"]["structured"]
    assert len(block["form_fields_a_only"]) == fd.LIST_PAGE_ITEMS == 10
    assert block["lists_cut"]["totals"] == {"form_fields_a_only": 14}
    own = fw.diff(path="www/app.js")["entry"]["structured"]
    assert len(own["form_fields_a_only"]) == 14


def test_a_path_recorded_twice_keeps_its_first_row_and_counts_the_rest(fw: FW) -> None:
    """A second record of a path already seen on a side does not replace the first: the first
    row is the file, the second is counted under duplicate_path_rows.

    MUTATION (verified RED): let the last record of a path stand -> RED."""
    fw.file("a", "etc/twice", "shell_script", "one\n")
    fw.file("a", "etc/twice", "shell_script", "two\n", write=False)
    fw.file("b", "etc/twice", "shell_script", "one\n")
    out = fw.diff(change="same")
    assert out["duplicate_path_rows"] == {"a": 1, "b": 0}
    assert [e["path"] for e in out["entries"]] == ["etc/twice"]
    assert out["counts"]["same"] == 1 and out["counts"]["content_differs"] == 0


def test_a_list_page_fits_the_response_budget(fw: FW) -> None:
    """Through the MCP tool, a page of many large differing files holds their stats only and fits
    48,000 bytes; the rest is reachable with next_offset."""
    for i in range(60):
        fw.file("a", f"www/p{i}.js", "web_asset", "a\n" * 2000)
        fw.file("b", f"www/p{i}.js", "web_asset", "b\n" * 2000)
    out = fw.tools()["get_file_diff"](PAIR, limit=200)
    assert "error" not in out, out
    assert len(json.dumps(out)) <= 48_000 and "over_budget" not in out
    assert out["next_offset"] is not None or out["total_entries"] == len(out["entries"])


# ── judging a file ─────────────────────────────────────────────────────────────────────────


def _anchor(path: str) -> str:
    return f"{PAIR}#non_binary#{path}"


def test_a_file_is_judged_by_run_pair_and_read_back_concluded(fw: FW) -> None:
    """annotate_diff(run_pair=...) writes a judgement on a file of a pair with no binary diff;
    list_overlays and get_file_diff read it concluded, basis unchanged, diff_id null with its run
    pair. Its file moving reads changed + needs_recheck; its path gone from both sides reads
    anchor_unresolved.

    MUTATION (verified RED): read the file judgements through the binary diffs (no file path) ->
    source_diff_gone -> RED."""
    fw.file("a", "etc/rc", "shell_script", "a\n")
    fw.file("b", "etc/rc", "shell_script", "b\n")
    tools = fw.tools()
    w = tools["annotate_diff"](_anchor("etc/rc"), "changed_real", "read it", run_pair=PAIR)
    assert w["written"] is True and w["run_pair"] == PAIR, w
    listed = tools["list_overlays"](anchor_kind="diff_subject", run_id=PAIR)
    (row,) = listed["overlays"]
    assert row["diff_id"] is None and row.get("run_pair") == PAIR
    assert (row["review_state"], row["basis_state"]) == ("concluded", "unchanged")
    assert row["source_stale"] is False
    assert _by_path(tools["get_file_diff"](PAIR))["etc/rc"]["review_state"] == "concluded"
    fw.db["b"].execute("UPDATE non_binary_files SET sha256 = ? WHERE path = 'etc/rc'", ("f" * 64,))
    fw.db["b"].commit()
    (row,) = tools["list_overlays"](anchor_kind="diff_subject", run_id=PAIR)["overlays"]
    assert (row["review_state"], row["basis_state"]) == ("needs_recheck", "changed")
    assert row["basis_moved"]["sha_b"][1] == "f" * 64
    for side in ("a", "b"):
        fw.db[side].execute("DELETE FROM non_binary_files WHERE path = 'etc/rc'")
        fw.db[side].commit()
    (row,) = tools["list_overlays"](anchor_kind="diff_subject", run_id=PAIR)["overlays"]
    assert row["basis_state"] == "anchor_unresolved"


def test_an_open_verdict_reads_open(fw: FW) -> None:
    fw.file("a", "etc/rc", "shell_script", "a\n")
    fw.file("b", "etc/rc", "shell_script", "b\n")
    tools = fw.tools()
    tools["annotate_diff"](_anchor("etc/rc"), "change_inconclusive", "unsure", run_pair=PAIR)
    (row,) = tools["list_overlays"](anchor_kind="diff_subject", run_id=PAIR)["overlays"]
    assert (row["review_state"], row["basis_state"]) == ("inconclusive", "unchanged")


def test_file_review_takes_the_callers_staleness(fw: FW) -> None:
    """The review state rests on the source_stale the caller passes: false reads the verdict,
    true (a stale run) and None (not checked) read needs_recheck.

    MUTATION (verified RED): ignore source_stale (pass {}) -> every file judgement reads
    needs_recheck -> RED."""
    fw.file("a", "etc/rc", "shell_script", "a\n")
    fw.file("b", "etc/rc", "shell_script", "b\n")
    conn = fw.atlas()
    try:
        overlay.annotate_diff(
            conn,
            anchor_ref=_anchor("etc/rc"),
            verdict="changed_real",
            rationale="r",
            run_pair=PAIR,
        )
        states = {
            stale: fd.file_review(conn, "runA", "runB", source_stale=stale)[_anchor("etc/rc")].state
            for stale in (False, True, None)
        }
    finally:
        conn.close()
    assert states == {False: "concluded", True: "needs_recheck", None: "needs_recheck"}


def test_list_overlays_reads_a_stale_side_as_needs_recheck(fw: FW) -> None:
    """Listed with no run pair, a file judgement whose pair has a stale run reads needs_recheck
    with the run named, beside one on a current pair that reads concluded — the MCP layer's
    reading of each pair's two runs.

    MUTATION (verified RED): let the MCP staleness reading always say current -> the stale pair's
    judgement reads concluded -> RED."""
    for side, path in (("a", "etc/rc"), ("b", "etc/rc"), ("s", "etc/rc")):
        fw.file(side, path, "shell_script", f"{side}\n")
    conn = fw.atlas()
    try:
        for pair in (PAIR, "runA::runS"):
            overlay.annotate_diff(
                conn,
                anchor_ref=f"{pair}#non_binary#etc/rc",
                verdict="changed_real",
                rationale="r",
                run_pair=pair,
            )
    finally:
        conn.close()
    rows = {
        o["run_pair"]: o
        for o in fw.tools()["list_overlays"](anchor_kind="diff_subject")["overlays"]
    }
    assert (rows[PAIR]["review_state"], rows[PAIR]["source_stale"]) == ("concluded", False)
    stale = rows["runA::runS"]
    assert (stale["review_state"], stale["source_stale"]) == ("needs_recheck", True)
    assert stale["source_stale_reason"] == "stale_scan:runS"


def test_annotate_diff_takes_exactly_one_of_diff_id_and_run_pair(fw: FW) -> None:
    fw.file("a", "etc/rc", "shell_script", "a\n")
    fw.file("b", "etc/rc", "shell_script", "b\n")
    tools = fw.tools()
    both = tools["annotate_diff"](
        _anchor("etc/rc"), "changed_real", "r", diff_id="x", run_pair=PAIR
    )
    neither = tools["annotate_diff"](_anchor("etc/rc"), "changed_real", "r")
    for out in (both, neither):
        assert out["written"] is False and "exactly one of diff_id" in out["error"]
    fn = tools["annotate_diff"](
        f"{PAIR}#function_pair#libx::1::2", "changed_real", "r", run_pair=PAIR
    )
    assert fn["written"] is False and "pass diff_id" in fn["error"]
    gone = tools["annotate_diff"](_anchor("etc/none"), "changed_real", "r", run_pair=PAIR)
    assert gone["written"] is False and "names no file" in gone["error"]
    batch = tools["annotate_diff_batch"](
        [{"anchor_ref": _anchor("etc/rc"), "verdict": "changed_real", "rationale": "r"}]
    )
    assert batch["written"] is False and "exactly one of diff_id" in batch["error"]
    grouped = tools["annotate_diff"](
        _anchor("etc/rc"), "changed_real", "r", group_ref="g#f2:x", run_pair=PAIR
    )
    assert grouped["written"] is False and "group_ref" in grouped["error"]


def test_the_tool_schema_takes_run_pair_and_anchor_first(fw: FW) -> None:
    """Through the server: anchor_ref is required, run_pair accepted by name, a batch keyed by
    run_pair writes all of its file anchors."""
    fw.file("a", "etc/rc", "shell_script", "a\n")
    fw.file("b", "etc/rc", "shell_script", "b\n")
    fw.file("a", "etc/x", "config_file", "a\n")
    fw.file("b", "etc/x", "config_file", "b\n")
    server = mcp_app.build_server(fw.path)

    def call(name: str, args: dict[str, Any]) -> Any:
        res = asyncio.run(server.call_tool(name, args))
        blocks = res[0] if isinstance(res, tuple) else res
        return json.loads(blocks[0].text)

    out = call(
        "annotate_diff",
        {
            "anchor_ref": _anchor("etc/rc"),
            "verdict": "changed_real",
            "rationale": "r",
            "run_pair": PAIR,
        },
    )
    assert out["written"] is True, out
    with pytest.raises(Exception, match="anchor_ref"):
        asyncio.run(
            server.call_tool("annotate_diff", {"verdict": "changed_real", "run_pair": PAIR})
        )
    batch = call(
        "annotate_diff_batch",
        {
            "run_pair": PAIR,
            "annotations": [
                {"anchor_ref": _anchor("etc/rc"), "verdict": "changed_real", "rationale": "r"},
                {
                    "anchor_ref": _anchor("etc/x"),
                    "verdict": "change_inconclusive",
                    "rationale": "r",
                },
            ],
        },
    )
    assert batch["written"] is True and batch["count"] == 2, batch


def test_checked_on_a_file_resolves_file_anchors_and_names_what_needs_diff_id(fw: FW) -> None:
    """With run_pair alone, ``checked`` resolves a file's anchor; a function anchor is refused
    naming diff_id; a file anchor naming no file is refused.

    MUTATION (verified RED): resolve checked against the binary view only -> the file anchor
    does not count -> RED."""
    fw.file("a", "etc/rc", "shell_script", "a\n")
    fw.file("b", "etc/rc", "shell_script", "b\n")
    fw.file("a", "etc/other", "shell_script", "a\n")
    fw.file("b", "etc/other", "shell_script", "b\n")
    tools = fw.tools()

    def judge(checked: list[str]) -> dict[str, Any]:
        return tools["annotate_diff"](
            _anchor("etc/rc"),
            "no_real_change",
            None,
            checked=checked,
            why_unchanged="w",
            run_pair=PAIR,
        )

    assert judge([_anchor("etc/other")])["written"] is True
    fn = judge([f"{PAIR}#function_pair#libx::00001000::00001000"])
    assert fn["written"] is False and "pass diff_id" in fn["error"]
    ghost = judge([_anchor("etc/ghost")])
    assert ghost["written"] is False and "names no file" in ghost["error"]
    assert judge(["a plain note"])["written"] is False


def test_a_non_binary_subject_has_no_entry() -> None:
    """A file subject has no view entry: Subject.entry defaults to None.

    MUTATION (verified RED): make entry required again -> RED."""
    import dataclasses

    defaults = {f.name: f.default for f in dataclasses.fields(dr.Subject)}
    assert defaults["entry"] is None
    s = dr.Subject("non_binary", {"change": "same"})
    assert s.entry is None and s.row_view is None
    assert dr.key_binary("non_binary", "etc/rc") is None
    assert dr.split_anchor(_anchor("etc/rc"), "runA", "runB") == ("non_binary", "etc/rc")
    assert not dr.belongs_to(
        _anchor("etc/rc"),
        {"run_pair": PAIR},
        diff_id="d",
        run_a="runA",
        run_b="runB",
        binary="libx",
    )


# ── a stale side, either one ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize("pair", ["runS::runB", "runA::runS"])
def test_a_stale_run_on_either_side_is_refused_with_no_binary_diff(fw: FW, pair: str) -> None:
    """The pair has no diff_meta row, so the gate is per run: get_file_diff, annotate_diff with
    run_pair and list_overlays on the pair are each refused when either run is stale.

    MUTATION (verified RED): gate through diff_meta only -> served -> RED."""
    tools = fw.tools()
    for result in (
        tools["get_file_diff"](pair),
        tools["annotate_diff"](f"{pair}#non_binary#etc/rc", "changed_real", "r", run_pair=pair),
        tools["annotate_diff_batch"](
            [
                {
                    "anchor_ref": f"{pair}#non_binary#etc/rc",
                    "verdict": "changed_real",
                    "rationale": "r",
                }
            ],
            run_pair=pair,
        ),
        tools["list_overlays"](anchor_kind="diff_subject", run_id=pair),
    ):
        assert "stale_scan" in result, result
    assert "stale_scan" not in tools["get_file_diff"](PAIR)


def test_an_unknown_pair_is_an_error(fw: FW) -> None:
    out = fw.tools()["get_file_diff"]("runA::nope")
    assert "error" in out and "does not name two runs" in out["error"]


# ── nothing stored, nothing else moved ─────────────────────────────────────────────────────


def _atlas_tables(path: Path) -> dict[str, list[Any]]:
    conn = sqlite3.connect(path)
    try:
        names = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        out = {
            n: conn.execute(f"SELECT * FROM {n}").fetchall()  # noqa: S608
            for n in sorted(names)
            if n not in ("overlay", "sqlite_sequence")
        }
        out["sqlite_sequence"] = conn.execute(
            "SELECT * FROM sqlite_sequence WHERE name <> 'overlay'"
        ).fetchall()
        return out
    finally:
        conn.close()


def test_reading_and_judging_files_stores_nothing_but_the_judgement(fw: FW) -> None:
    """get_file_diff and a judgement on a file leave both analysis databases byte for byte and
    every atlas table but overlay as they were; the firmware roots are only read."""
    fw.file("a", "etc/rc", "shell_script", "a\n")
    fw.file("b", "etc/rc", "shell_script", "b\n")
    for conn in fw.db.values():
        conn.close()
    before = {s: p.read_bytes() for s, p in fw.db_path.items()}
    tables = _atlas_tables(fw.path)
    tools = fw.tools()
    tools["get_file_diff"](PAIR)
    tools["get_file_diff"](PAIR, path="etc/rc")
    assert tools["annotate_diff"](_anchor("etc/rc"), "changed_real", "r", run_pair=PAIR)["written"]
    assert {s: p.read_bytes() for s, p in fw.db_path.items()} == before
    assert _atlas_tables(fw.path) == tables


def test_the_labels_say_nothing_of_what_a_change_means(fw: FW) -> None:
    """Every key and enumerated value get_file_diff emits (list, summary, a file's page, a
    suppressed one) is free of words that say what a change means.

    MUTATION (verified RED): name the stats added_lines / removed_lines -> RED."""
    _alignment_world(fw)
    a = fw.file("a", "etc/s.sh", "shell_script", "a\n")
    b = fw.file("b", "etc/s.sh", "shell_script", "b\n")
    fw.row("a", "script_calls", a, command="c", raw_line="c 1", line_number=1)
    fw.row("b", "script_calls", b, command="c", raw_line="c 2", line_number=1)
    fw.file("a", "etc/k", "credential", "1\n")
    fw.file("b", "etc/k", "credential", "2\n")

    def labels(value: Any) -> set[str]:
        if isinstance(value, dict):
            out = set(value)
            for k, v in value.items():
                if k in (
                    "change",
                    "kind",
                    "hunk_suppressed",
                    "hunk_unavailable",
                    "structured_available",
                    "review_state",
                    "detail",
                ):
                    out.add(str(v))
                if k not in ("legend", "caveats", "lines", "path", "raw_line", "command"):
                    out |= labels(v)
            return out
        if isinstance(value, list):
            return set().union(*(labels(v) for v in value)) if value else set()
        return set()

    found: set[str] = set()
    for out in (
        fw.diff(),
        fw.diff(detail="summary"),
        fw.diff(path="etc/s.sh"),
        fw.diff(path="etc/k"),
    ):
        found |= labels(out)
    assert {
        "a_only",
        "b_only",
        "content_differs",
        "plus_lines",
        "minus_lines",
        "commands_a_only",
        "hunk_suppressed",
        "credential_material",
    } <= found
    for label in found:
        words = set(label.lower().replace("-", "_").split("_"))
        assert not words & _WORDS, label


# ── beside a binary diff of the same run pair ──────────────────────────────────────────────


def _add_files(w: Any) -> None:
    for side, text in (("a", "1"), ("b", "2")):
        w.adb[side].execute(
            "INSERT INTO non_binary_files (kind, name, path, sha256, size_bytes) "
            "VALUES ('shell_script', 'rc', 'etc/rc', ?, 1)",
            (_sha(text.encode()),),
        )
        w.adb[side].commit()


def _snapshot(w: Any) -> str:
    return json.dumps(
        [_pages(w), _pages(w, detail="summary"), _pages(w, sort_by="candidate_tier", band=True)]
    )


def test_a_file_judgement_leaves_every_binary_diff_page_as_it_was(
    tmp_path: Path, current: None
) -> None:
    """★ A judgement on a file of the run pair is not about any binary diff: every page of the
    pair's binary diff (full, summary, banded) is byte for byte what it was — no dangling
    judgement, no moved progress. The control: a judgement on one of its entries does move them.

    MUTATION (verified RED): let belongs_to take a non_binary anchor -> the file judgement
    dangles on the binary diff's pages -> RED."""
    w = _summary_world(tmp_path)
    _add_files(w)
    before = _snapshot(w)
    overlay.annotate_diff(
        w.atlas, anchor_ref=_anchor("etc/rc"), verdict="changed_real", rationale="r", run_pair=PAIR
    )
    assert _snapshot(w) == before
    entry = _listed(_pages(w))[0]
    overlay.annotate_diff(
        w.atlas,
        anchor_ref=entry["anchor_ref"],
        verdict="changed_real",
        rationale="r",
        diff_id=DIFF,
    )
    assert _snapshot(w) != before  # the pages do read judgements


def test_a_file_anchor_beside_a_binary_diff(tmp_path: Path, current: None) -> None:
    """With a binary diff of the pair: a file anchor may be written with that diff_id; a batch by
    diff_id may mix it with a function anchor (all or none — a file anchor of another pair fails
    the whole batch); checked resolves a function anchor when a diff_id names the pair; a file
    anchor cannot be promoted; get_diff_meta is what it was but for its non_binary block."""
    from treasure_map.lib.query.diff_align import get_diff_meta

    w = _summary_world(tmp_path)
    _add_files(w)
    tools = mcp_app.make_tools(w.path)
    entry = _listed(_pages(w))[0]
    out = tools["annotate_diff"](
        _anchor("etc/rc"),
        "no_real_change",
        None,
        checked=[entry["anchor_ref"]],
        why_unchanged="w",
        diff_id=DIFF,
    )
    assert out["written"] is True, out
    bad = tools["annotate_diff_batch"](
        [
            {"anchor_ref": entry["anchor_ref"], "verdict": "changed_real", "rationale": "r"},
            {
                "anchor_ref": "runB::runA#non_binary#etc/rc",
                "verdict": "changed_real",
                "rationale": "r",
            },
        ],
        diff_id=DIFF,
    )
    assert bad["written"] is False and bad["count"] == 0, bad
    rows = w.atlas.execute("SELECT anchor_ref FROM overlay").fetchall()
    assert [r[0] for r in rows] == [_anchor("etc/rc")]
    good = tools["annotate_diff_batch"](
        [
            {"anchor_ref": entry["anchor_ref"], "verdict": "changed_real", "rationale": "r"},
            {"anchor_ref": _anchor("etc/rc"), "verdict": "changed_real", "rationale": "r"},
        ],
        diff_id=DIFF,
    )
    assert good["written"] is True and good["count"] == 2, good
    refused = tools["promote"](DIFF, _anchor("etc/rc"), "runA#x", "suspicious", "r")
    assert "non-binary file has no candidate rows" in json.dumps(refused)
    meta = tools["get_diff_meta"](DIFF)
    assert meta["non_binary"]["counts"]["content_differs"] == 1
    assert meta["non_binary"]["next"] == f'get_file_diff(run_pair="{PAIR}")'
    assert {k: v for k, v in meta.items() if k != "non_binary"} == json.loads(
        json.dumps(get_diff_meta(w.atlas, DIFF))
    )


def test_a_withheld_binary_diff_does_not_hold_back_its_files(tmp_path: Path, current: None) -> None:
    """A binary diff undetermined as a whole does not reach the pair's files: a file judgement
    written through its diff_id is taken and reads concluded."""
    w = _summary_world(tmp_path)
    _add_files(w)
    w.atlas.execute("UPDATE diff_meta SET diff_ok = 0 WHERE diff_id = ?", (DIFF,))
    w.atlas.commit()
    overlay.annotate_diff(
        w.atlas, anchor_ref=_anchor("etc/rc"), verdict="changed_real", rationale="r", diff_id=DIFF
    )
    listed = overlay.list_overlays(
        w.atlas,
        anchor_kind="diff_subject",
        run_id=PAIR,
        file_staleness=lambda a, b: {"source_stale": False, "source_stale_reason": None},
    )
    (row,) = [o for o in listed["overlays"] if o["anchor_ref"] == _anchor("etc/rc")]
    assert (row["review_state"], row["basis_state"], row["diff_id"]) == (
        "concluded",
        "unchanged",
        None,
    )
