# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the non-binary ingester framework, ShellScript ingester (Round C),
and ConfigFile ingester (Round D)."""

from __future__ import annotations

from pathlib import Path

from treasure_map.lib.analyze.non_binary.config_file import (
    CONFIG_RISK_RULES,
    _detect_config,
    _ingest_config,
)
from treasure_map.lib.analyze.non_binary.framework import NonBinaryFile
from treasure_map.lib.analyze.non_binary.orchestrator import run_all_ingesters
from treasure_map.lib.analyze.non_binary.shell_script import (
    SHELL_RISK_RULES,
    _detect_shell,
    _ingest_shell,
)
from treasure_map.lib.storage.connection import open_db

# ── Allowed vuln_hint vocabularies (§5.3) ────────────────────────────────────

_ALLOWED_SHELL_HINTS = frozenset(label for label, _ in SHELL_RISK_RULES)
_ALLOWED_CONFIG_HINTS = frozenset(label for label, _ in CONFIG_RISK_RULES)
_ALLOWED_HINTS = _ALLOWED_SHELL_HINTS  # legacy alias used by Round C tests


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_file(
    tmp_path: Path,
    name: str,
    content: str,
    *,
    rel_path: str | None = None,
) -> NonBinaryFile:
    fpath = tmp_path / name
    fpath.write_text(content, encoding="utf-8")
    raw = content.encode("utf-8")
    head = raw[:512]
    import hashlib

    sha = hashlib.sha256(raw).hexdigest()
    return NonBinaryFile(
        path=fpath,
        rel_path=rel_path or name,
        name=name,
        sha256=sha,
        size_bytes=len(raw),
        head=head,
        text=content,
    )


def _make_binary_file(tmp_path: Path, name: str) -> NonBinaryFile:
    """Fake ELF magic — should be skipped by the orchestrator."""
    fpath = tmp_path / name
    data = b"\x7fELF" + b"\x00" * 60
    fpath.write_bytes(data)
    import hashlib

    sha = hashlib.sha256(data).hexdigest()
    return NonBinaryFile(
        path=fpath,
        rel_path=name,
        name=name,
        sha256=sha,
        size_bytes=len(data),
        head=data[:512],
        text=None,
    )


# ── _detect_shell: shebang cases ──────────────────────────────────────────────


def test_detect_shell_sh_shebang(tmp_path: Path) -> None:
    f = _make_file(tmp_path, "init.sh", "#!/bin/sh\necho hello\n")
    assert _detect_shell(f) == "sh"


def test_detect_shell_bash_shebang(tmp_path: Path) -> None:
    f = _make_file(tmp_path, "setup", '#!/bin/bash\neval "$cmd"\n')
    assert _detect_shell(f) == "bash"


def test_detect_shell_ash_shebang(tmp_path: Path) -> None:
    f = _make_file(tmp_path, "run", "#!/bin/ash\nnvram_get wan_ifname\n")
    assert _detect_shell(f) == "ash"


def test_detect_shell_dot_sh_extension(tmp_path: Path) -> None:
    f = _make_file(tmp_path, "watchdog.sh", "echo starting\n")
    assert _detect_shell(f) == "sh"


def test_detect_shell_returns_none_for_non_script(tmp_path: Path) -> None:
    f = _make_file(tmp_path, "config.conf", "[section]\nkey=value\n")
    assert _detect_shell(f) is None


def test_detect_shell_returns_none_for_binary(tmp_path: Path) -> None:
    f = _make_binary_file(tmp_path, "daemon")
    assert _detect_shell(f) is None


# ── _ingest_shell: row + label assertions ─────────────────────────────────────

_FIXTURE_SCRIPT = """\
#!/bin/sh
# Main web daemon init script
nvram get wan_ifname
eval "$CMD"
rm -f /var/run/$SOCK
echo "starting main web daemon"
"""


def test_ingest_shell_correct_rows(tmp_path: Path) -> None:
    conn = open_db(tmp_path / "analysis.db")
    f = _make_file(tmp_path, "web_daemon_init.sh", _FIXTURE_SCRIPT)

    file_id = conn.execute(
        "INSERT INTO non_binary_files (kind, subtype, name, path, sha256, size_bytes, detected_via)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("shell_script", "sh", f.name, f.rel_path, f.sha256, f.size_bytes, "shebang"),
    ).lastrowid
    conn.commit()

    count = _ingest_shell(conn, int(file_id), f)  # type: ignore[arg-type]
    conn.commit()

    assert count >= 2

    rows = conn.execute(
        "SELECT command, vuln_hint FROM script_calls WHERE file_id = ?", (file_id,)
    ).fetchall()
    hints = {row[1] for row in rows}

    assert "eval_injection" in hints
    assert "config_file_injection" in hints

    for row in rows:
        assert row[1] in _ALLOWED_HINTS, f"vuln_hint {row[1]!r} not in allowed vocabulary"

    conn.close()


def test_ingest_shell_skips_benign_lines(tmp_path: Path) -> None:
    conn = open_db(tmp_path / "analysis.db")
    f = _make_file(tmp_path, "benign.sh", "#!/bin/sh\necho hello\nmkdir /tmp/work\n")

    file_id = conn.execute(
        "INSERT INTO non_binary_files (kind, subtype, name, path, sha256, size_bytes, detected_via)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("shell_script", "sh", f.name, f.rel_path, f.sha256, f.size_bytes, "shebang"),
    ).lastrowid
    conn.commit()

    count = _ingest_shell(conn, int(file_id), f)  # type: ignore[arg-type]
    conn.commit()
    assert count == 0
    conn.close()


def test_ingest_shell_all_hints_categorical(tmp_path: Path) -> None:
    """Every vuln_hint in the DB must come from the fixed label vocabulary."""
    conn = open_db(tmp_path / "analysis.db")
    script = '#!/bin/sh\neval "$x"\nbash -c "$cmd"\nnvram_get key\nrm -rf /tmp/$dir\n'
    f = _make_file(tmp_path, "attack_surface.sh", script)

    file_id = conn.execute(
        "INSERT INTO non_binary_files (kind, subtype, name, path, sha256, size_bytes, detected_via)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("shell_script", "sh", f.name, f.rel_path, f.sha256, f.size_bytes, "shebang"),
    ).lastrowid
    conn.commit()
    _ingest_shell(conn, int(file_id), f)  # type: ignore[arg-type]
    conn.commit()

    rows = conn.execute("SELECT vuln_hint FROM script_calls").fetchall()
    for (hint,) in rows:
        assert hint in _ALLOWED_HINTS, f"unexpected vuln_hint: {hint!r}"
    conn.close()


# ── run_all_ingesters: orchestrator integration ───────────────────────────────


def _build_fixture_tree(root: Path) -> None:
    """Build a minimal firmware-like directory tree for orchestrator tests."""
    (root / "bin").mkdir()
    (root / "etc").mkdir()

    # shell script — should be ingested
    (root / "etc" / "web_daemon_init.sh").write_text(
        '#!/bin/sh\nnvram get wan_ifname\neval "$CMD"\n', encoding="utf-8"
    )

    # plain text file — no matching ingester, should be silently skipped
    (root / "etc" / "service.txt").write_text("[service]\nport=80\n", encoding="utf-8")

    # ELF magic stub — must be skipped by the walker
    elf_stub = root / "bin" / "main_service"
    elf_stub.write_bytes(b"\x7fELF" + b"\x00" * 60)


def test_orchestrator_ingests_shell_skips_elf(tmp_path: Path) -> None:
    fs_root = tmp_path / "firmware"
    fs_root.mkdir()
    _build_fixture_tree(fs_root)

    conn = open_db(tmp_path / "analysis.db")
    stats = run_all_ingesters(conn, fs_root)

    assert stats.files_ingested == 1
    assert stats.by_kind.get("shell_script", 0) == 1
    assert stats.sub_rows.get("shell_script", 0) >= 1

    rows = conn.execute("SELECT kind, name FROM non_binary_files").fetchall()
    names = {row[1] for row in rows}
    assert "web_daemon_init.sh" in names
    assert "main_service" not in names

    conn.close()


def test_orchestrator_idempotent(tmp_path: Path) -> None:
    """Running run_all_ingesters twice must yield identical row counts."""
    fs_root = tmp_path / "firmware"
    fs_root.mkdir()
    _build_fixture_tree(fs_root)

    conn = open_db(tmp_path / "analysis.db")
    stats1 = run_all_ingesters(conn, fs_root)
    stats2 = run_all_ingesters(conn, fs_root)

    assert stats1.files_ingested == stats2.files_ingested
    assert stats1.sub_rows == stats2.sub_rows

    count = conn.execute("SELECT COUNT(*) FROM non_binary_files").fetchone()[0]
    assert count == stats2.files_ingested

    conn.close()


def test_orchestrator_skip_ingester(tmp_path: Path) -> None:
    """skip_ingesters={'shell_script'} must produce zero rows."""
    fs_root = tmp_path / "firmware"
    fs_root.mkdir()
    _build_fixture_tree(fs_root)

    conn = open_db(tmp_path / "analysis.db")
    stats = run_all_ingesters(conn, fs_root, skip_ingesters=frozenset({"shell_script"}))

    assert stats.files_ingested == 0
    assert stats.sub_rows == {}
    assert conn.execute("SELECT COUNT(*) FROM non_binary_files").fetchone()[0] == 0

    conn.close()


# ── Round D: _detect_config ───────────────────────────────────────────────────


def test_detect_config_conf_extension(tmp_path: Path) -> None:
    f = _make_file(tmp_path, "httpd.conf", "port=80\n")
    assert _detect_config(f) == "conf"


def test_detect_config_cfg_extension(tmp_path: Path) -> None:
    f = _make_file(tmp_path, "system.cfg", "[net]\nip=192.168.1.1\n")
    assert _detect_config(f) == "cfg"


def test_detect_config_ini_extension(tmp_path: Path) -> None:
    f = _make_file(tmp_path, "settings.ini", "[main]\ndebug=1\n")
    assert _detect_config(f) == "ini"


def test_detect_config_txt_returns_none(tmp_path: Path) -> None:
    f = _make_file(tmp_path, "readme.txt", "some text\n")
    assert _detect_config(f) is None


def test_detect_config_binary_returns_none(tmp_path: Path) -> None:
    f = _make_binary_file(tmp_path, "firmware.bin")
    assert _detect_config(f) is None


def test_detect_config_no_extension_returns_none(tmp_path: Path) -> None:
    f = _make_file(tmp_path, "Makefile", "all:\n\techo done\n")
    assert _detect_config(f) is None


# ── Round D: _ingest_config — flagged rows, is_sensitive, categorical hints ──

_FIXTURE_CONF = """\
[web]
port=80
admin_password=changeme
auth_required=off
debug=1
max_connections=100
"""


def test_ingest_config_flagged_only(tmp_path: Path) -> None:
    conn = open_db(tmp_path / "analysis.db")
    f = _make_file(tmp_path, "httpd.conf", _FIXTURE_CONF)

    file_id = conn.execute(
        "INSERT INTO non_binary_files (kind, subtype, name, path, sha256, size_bytes, detected_via)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("config_file", "conf", f.name, f.rel_path, f.sha256, f.size_bytes, "extension"),
    ).lastrowid
    conn.commit()

    count = _ingest_config(conn, int(file_id), f)  # type: ignore[arg-type]
    conn.commit()

    # port, max_connections are benign — only the 3 flagged lines should be recorded
    assert count == 3

    rows = conn.execute(
        "SELECT key, is_sensitive, vuln_hint FROM config_entries WHERE file_id = ?",
        (file_id,),
    ).fetchall()
    hints = {row[2] for row in rows}
    sensitive_keys = {row[0] for row in rows if row[1] == 1}

    assert "hardcoded_credential" in hints
    assert "auth_disabled" in hints
    assert "debug_enabled" in hints
    assert "admin_password" in sensitive_keys

    for row in rows:
        assert row[2] in _ALLOWED_CONFIG_HINTS, f"unexpected vuln_hint: {row[2]!r}"

    conn.close()


def test_ingest_config_is_sensitive_only_on_credential(tmp_path: Path) -> None:
    """is_sensitive must be 1 for hardcoded_credential and 0 for other hints."""
    conn = open_db(tmp_path / "analysis.db")
    content = "auth_required=off\ndebug=1\n"
    f = _make_file(tmp_path, "service.conf", content)

    file_id = conn.execute(
        "INSERT INTO non_binary_files (kind, subtype, name, path, sha256, size_bytes, detected_via)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("config_file", "conf", f.name, f.rel_path, f.sha256, f.size_bytes, "extension"),
    ).lastrowid
    conn.commit()
    _ingest_config(conn, int(file_id), f)  # type: ignore[arg-type]
    conn.commit()

    rows = conn.execute(
        "SELECT is_sensitive FROM config_entries WHERE file_id = ?", (file_id,)
    ).fetchall()
    for (s,) in rows:
        assert s == 0

    conn.close()


def test_ingest_config_tolerant_sectionless(tmp_path: Path) -> None:
    """A config file with no [section] header must parse without raising."""
    conn = open_db(tmp_path / "analysis.db")
    content = "admin_password=secret123\ndebug=1\n"
    f = _make_file(tmp_path, "bare.conf", content)

    file_id = conn.execute(
        "INSERT INTO non_binary_files (kind, subtype, name, path, sha256, size_bytes, detected_via)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("config_file", "conf", f.name, f.rel_path, f.sha256, f.size_bytes, "extension"),
    ).lastrowid
    conn.commit()
    count = _ingest_config(conn, int(file_id), f)  # type: ignore[arg-type]
    conn.commit()

    assert count >= 1
    # section should be NULL for sectionless entries
    rows = conn.execute(
        "SELECT section FROM config_entries WHERE file_id = ?", (file_id,)
    ).fetchall()
    for (sec,) in rows:
        assert sec is None

    conn.close()


def test_ingest_config_tolerant_key_space_value(tmp_path: Path) -> None:
    """A 'key value' (space-separated) line must parse and be classified."""
    conn = open_db(tmp_path / "analysis.db")
    content = "debug 1\n"
    f = _make_file(tmp_path, "openwrt.conf", content)

    file_id = conn.execute(
        "INSERT INTO non_binary_files (kind, subtype, name, path, sha256, size_bytes, detected_via)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("config_file", "conf", f.name, f.rel_path, f.sha256, f.size_bytes, "extension"),
    ).lastrowid
    conn.commit()
    count = _ingest_config(conn, int(file_id), f)  # type: ignore[arg-type]
    conn.commit()

    assert count == 1
    row = conn.execute(
        "SELECT key, value, vuln_hint FROM config_entries WHERE file_id = ?", (file_id,)
    ).fetchone()
    assert row[0] == "debug"
    assert row[1] == "1"
    assert row[2] == "debug_enabled"

    conn.close()


def test_ingest_config_benign_lines_not_recorded(tmp_path: Path) -> None:
    conn = open_db(tmp_path / "analysis.db")
    content = "port=80\nmax_connections=100\nlisten_address=0.0.0.0\n"
    f = _make_file(tmp_path, "benign.conf", content)

    file_id = conn.execute(
        "INSERT INTO non_binary_files (kind, subtype, name, path, sha256, size_bytes, detected_via)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("config_file", "conf", f.name, f.rel_path, f.sha256, f.size_bytes, "extension"),
    ).lastrowid
    conn.commit()
    count = _ingest_config(conn, int(file_id), f)  # type: ignore[arg-type]
    conn.commit()

    assert count == 0
    conn.close()


# ── Round D: mixed shell + config tree, DD2 sub_rows mapping ─────────────────


def _build_mixed_fixture_tree(root: Path) -> None:
    """Firmware tree with one shell script and one config file."""
    (root / "etc").mkdir()

    (root / "etc" / "web_daemon_init.sh").write_text(
        '#!/bin/sh\nnvram get wan_ifname\neval "$CMD"\n', encoding="utf-8"
    )
    (root / "etc" / "httpd.conf").write_text(
        "admin_password=changeme\nauth_required=off\ndebug=1\n",
        encoding="utf-8",
    )


def test_orchestrator_mixed_tree_sub_rows(tmp_path: Path) -> None:
    """Mixed tree: sub_rows must separate shell and config counts."""
    fs_root = tmp_path / "firmware"
    fs_root.mkdir()
    _build_mixed_fixture_tree(fs_root)

    conn = open_db(tmp_path / "analysis.db")
    stats = run_all_ingesters(conn, fs_root)

    assert stats.files_ingested == 2
    assert stats.by_kind.get("shell_script", 0) == 1
    assert stats.by_kind.get("config_file", 0) == 1
    assert "shell_script" in stats.sub_rows
    assert "config_file" in stats.sub_rows
    assert stats.sub_rows["shell_script"] >= 1
    assert stats.sub_rows["config_file"] >= 1

    conn.close()


def test_orchestrator_skip_config_ingester(tmp_path: Path) -> None:
    """skip_ingesters={'config_file'} processes shell but skips config."""
    fs_root = tmp_path / "firmware"
    fs_root.mkdir()
    _build_mixed_fixture_tree(fs_root)

    conn = open_db(tmp_path / "analysis.db")
    stats = run_all_ingesters(conn, fs_root, skip_ingesters=frozenset({"config_file"}))

    assert stats.by_kind.get("shell_script", 0) == 1
    assert stats.by_kind.get("config_file", 0) == 0
    assert "config_file" not in stats.sub_rows
    assert conn.execute("SELECT COUNT(*) FROM config_entries").fetchone()[0] == 0

    conn.close()
