# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the non-binary ingester framework, ShellScript ingester (Round C),
ConfigFile ingester (Round D), Credential ingester (Round E), and WebAsset ingester
(Round F)."""

from __future__ import annotations

from pathlib import Path

import pytest

from treasure_map.lib.analyze.non_binary.config_file import (
    CONFIG_RISK_RULES,
    _detect_config,
    _ingest_config,
)
from treasure_map.lib.analyze.non_binary.credential import (
    CREDENTIAL_HINTS,
    _detect_credential,
    _ingest_credential,
)
from treasure_map.lib.analyze.non_binary.framework import NonBinaryFile
from treasure_map.lib.analyze.non_binary.orchestrator import run_all_ingesters
from treasure_map.lib.analyze.non_binary.shell_script import (
    SHELL_RISK_RULES,
    _detect_shell,
    _ingest_shell,
)
from treasure_map.lib.analyze.non_binary.web_asset import (
    WEB_ENDPOINT_HINTS,
    _classify_endpoint,
    _detect_web_asset,
    _ingest_web_asset,
)
from treasure_map.lib.storage.connection import open_db

# ── Allowed vuln_hint vocabularies ───────────────────────────────────────────

_ALLOWED_SHELL_HINTS = frozenset(label for label, _ in SHELL_RISK_RULES)
_ALLOWED_CONFIG_HINTS = frozenset(label for label, _ in CONFIG_RISK_RULES)
_ALLOWED_CRED_HINTS = CREDENTIAL_HINTS
_ALLOWED_WEB_HINTS = WEB_ENDPOINT_HINTS
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


# ── Round D: mixed shell + config tree, sub_rows mapping ─────────────────────


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


# ── Round E: _detect_credential ───────────────────────────────────────────────


def test_detect_credential_pem_extension(tmp_path: Path) -> None:
    content = "-----BEGIN RSA PRIVATE KEY-----\nFAKE\n-----END RSA PRIVATE KEY-----\n"
    f = _make_file(tmp_path, "server.pem", content)
    assert _detect_credential(f) == "pem"


def test_detect_credential_key_extension_with_begin(tmp_path: Path) -> None:
    content = "-----BEGIN EC PRIVATE KEY-----\nFAKE\n-----END EC PRIVATE KEY-----\n"
    f = _make_file(tmp_path, "tls.key", content)
    assert _detect_credential(f) == "pem"


def test_detect_credential_shadow_basename(tmp_path: Path) -> None:
    f = _make_file(tmp_path, "shadow", "root::18000:0:99999:7:::\n")
    assert _detect_credential(f) == "shadow"


def test_detect_credential_passwd_basename(tmp_path: Path) -> None:
    f = _make_file(tmp_path, "passwd", "root:x:0:0:root:/root:/bin/sh\n")
    assert _detect_credential(f) == "passwd"


def test_detect_credential_txt_returns_none(tmp_path: Path) -> None:
    f = _make_file(tmp_path, "readme.txt", "no credentials here\n")
    assert _detect_credential(f) is None


def test_detect_credential_conf_returns_none(tmp_path: Path) -> None:
    f = _make_file(tmp_path, "httpd.conf", "port=80\n")
    assert _detect_credential(f) is None


def test_detect_credential_binary_returns_none(tmp_path: Path) -> None:
    f = _make_binary_file(tmp_path, "daemon")
    assert _detect_credential(f) is None


# ── Round E: _ingest_credential — PEM blocks ──────────────────────────────────

# Clearly fake truncated placeholders — not real or usable keys (committed to repo).
_FIXTURE_PEM_PRIVKEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n"
    "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n"
    "-----END RSA PRIVATE KEY-----\n"
)

_FIXTURE_PEM_CERT = (
    "-----BEGIN CERTIFICATE-----\n"
    "FAKECERTIFICATEFAKECERTIFICATEFAKECERTIFICATE\n"
    "FAKECERTIFICATEFAKECERTIFICATEFAKECERTIFICATE\n"
    "-----END CERTIFICATE-----\n"
)

_FIXTURE_PEM_PUBKEY = (
    "-----BEGIN PUBLIC KEY-----\n"
    "FAKEPUBLICKEYFAKEPUBLICKEYFAKEPUBLICKEY\n"
    "-----END PUBLIC KEY-----\n"
)


def _insert_nbf(conn: object, kind: str, subtype: str, f: NonBinaryFile) -> int:
    import sqlite3

    assert isinstance(conn, sqlite3.Connection)
    row_id = conn.execute(
        "INSERT INTO non_binary_files (kind, subtype, name, path, sha256, size_bytes, detected_via)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (kind, subtype, f.name, f.rel_path, f.sha256, f.size_bytes, "test"),
    ).lastrowid
    conn.commit()
    return int(row_id)  # type: ignore[arg-type]


def test_ingest_credential_pem_private_key(tmp_path: Path) -> None:
    """Private-key block → hardcoded_private_key, is_sensitive=1, material holds block."""
    conn = open_db(tmp_path / "analysis.db")
    f = _make_file(tmp_path, "server.pem", _FIXTURE_PEM_PRIVKEY)
    file_id = _insert_nbf(conn, "credential", "pem", f)

    count = _ingest_credential(conn, file_id, f)
    conn.commit()

    assert count == 1
    row = conn.execute(
        "SELECT cred_type, algorithm, is_sensitive, vuln_hint, material FROM credentials"
        " WHERE file_id = ?",
        (file_id,),
    ).fetchone()
    assert row[0] == "private_key"
    assert row[1] == "rsa_private"
    assert row[2] == 1
    assert row[3] == "hardcoded_private_key"
    # material must hold the observed block so findings are independently verifiable
    assert row[4] is not None
    assert "-----BEGIN RSA PRIVATE KEY-----" in row[4]
    assert "-----END RSA PRIVATE KEY-----" in row[4]

    conn.close()


def test_ingest_credential_pem_certificate(tmp_path: Path) -> None:
    conn = open_db(tmp_path / "analysis.db")
    f = _make_file(tmp_path, "ca.crt", _FIXTURE_PEM_CERT)
    file_id = _insert_nbf(conn, "credential", "pem", f)

    count = _ingest_credential(conn, file_id, f)
    conn.commit()

    assert count == 1
    row = conn.execute(
        "SELECT cred_type, is_sensitive, vuln_hint FROM credentials WHERE file_id = ?",
        (file_id,),
    ).fetchone()
    assert row[0] == "certificate"
    assert row[1] == 0
    assert row[2] == "certificate_present"

    conn.close()


def test_ingest_credential_pem_public_key(tmp_path: Path) -> None:
    conn = open_db(tmp_path / "analysis.db")
    f = _make_file(tmp_path, "id_rsa.pub", _FIXTURE_PEM_PUBKEY)
    file_id = _insert_nbf(conn, "credential", "pem", f)

    count = _ingest_credential(conn, file_id, f)
    conn.commit()

    assert count == 1
    row = conn.execute(
        "SELECT cred_type, is_sensitive, vuln_hint FROM credentials WHERE file_id = ?",
        (file_id,),
    ).fetchone()
    assert row[0] == "public_key"
    assert row[1] == 0
    assert row[2] == "public_key_present"

    conn.close()


def test_ingest_credential_pem_multi_block(tmp_path: Path) -> None:
    """A file with both a private key and a certificate produces two rows."""
    content = _FIXTURE_PEM_PRIVKEY + _FIXTURE_PEM_CERT
    conn = open_db(tmp_path / "analysis.db")
    f = _make_file(tmp_path, "bundle.pem", content)
    file_id = _insert_nbf(conn, "credential", "pem", f)

    count = _ingest_credential(conn, file_id, f)
    conn.commit()

    assert count == 2
    hints = {
        r[0]
        for r in conn.execute(
            "SELECT vuln_hint FROM credentials WHERE file_id = ?", (file_id,)
        ).fetchall()
    }
    assert "hardcoded_private_key" in hints
    assert "certificate_present" in hints

    conn.close()


# ── Round E: _ingest_credential — shadow file ────────────────────────────────

# Generic shadow fixture lines — vendor-neutral, clearly fake hashes.
_FIXTURE_SHADOW_EMPTY_ROOT = "root::18000:0:99999:7:::\n"
_FIXTURE_SHADOW_MD5 = "webadmin:$1$" + "fakesalt$fakemd5hash123abc:18000:0:99999:7:::\n"
_FIXTURE_SHADOW_SHA512 = "sysadmin:$6$" + "fakesalt$fakesha512hashfake:18000:0:99999:7:::\n"
_FIXTURE_SHADOW_LOCKED_BANG = "guest:!:18000:0:99999:7:::\n"
_FIXTURE_SHADOW_LOCKED_STAR = "daemon:*:18000:0:99999:7:::\n"


def test_ingest_credential_shadow_empty_root(tmp_path: Path) -> None:
    conn = open_db(tmp_path / "analysis.db")
    f = _make_file(tmp_path, "shadow", _FIXTURE_SHADOW_EMPTY_ROOT)
    file_id = _insert_nbf(conn, "credential", "shadow", f)

    count = _ingest_credential(conn, file_id, f)
    conn.commit()

    assert count == 1
    row = conn.execute(
        "SELECT identifier, is_sensitive, vuln_hint FROM credentials WHERE file_id = ?",
        (file_id,),
    ).fetchone()
    assert row[0] == "root"
    assert row[1] == 0
    assert row[2] == "empty_root_password"

    conn.close()


def test_ingest_credential_shadow_md5_hash(tmp_path: Path) -> None:
    """md5crypt hash → weak_password_hash_algo, is_sensitive=1, material holds hash field."""
    conn = open_db(tmp_path / "analysis.db")
    f = _make_file(tmp_path, "shadow", _FIXTURE_SHADOW_MD5)
    file_id = _insert_nbf(conn, "credential", "shadow", f)

    count = _ingest_credential(conn, file_id, f)
    conn.commit()

    assert count == 1
    row = conn.execute(
        "SELECT algorithm, is_sensitive, vuln_hint, material FROM credentials WHERE file_id = ?",
        (file_id,),
    ).fetchone()
    assert row[0] == "md5crypt"
    assert row[1] == 1
    assert row[2] == "weak_password_hash_algo"
    # material must hold the observed hash field for verifiability
    assert row[3] is not None
    assert row[3].startswith("$1$")

    conn.close()


def test_ingest_credential_shadow_sha512_hash(tmp_path: Path) -> None:
    conn = open_db(tmp_path / "analysis.db")
    f = _make_file(tmp_path, "shadow", _FIXTURE_SHADOW_SHA512)
    file_id = _insert_nbf(conn, "credential", "shadow", f)

    count = _ingest_credential(conn, file_id, f)
    conn.commit()

    assert count == 1
    row = conn.execute(
        "SELECT algorithm, vuln_hint FROM credentials WHERE file_id = ?", (file_id,)
    ).fetchone()
    assert row[0] == "sha512crypt"
    assert row[1] == "present_password_hash"

    conn.close()


def test_ingest_credential_shadow_locked_skipped(tmp_path: Path) -> None:
    """Locked entries (! and *) must produce zero rows."""
    content = _FIXTURE_SHADOW_LOCKED_BANG + _FIXTURE_SHADOW_LOCKED_STAR
    conn = open_db(tmp_path / "analysis.db")
    f = _make_file(tmp_path, "shadow", content)
    file_id = _insert_nbf(conn, "credential", "shadow", f)

    count = _ingest_credential(conn, file_id, f)
    conn.commit()

    assert count == 0
    n = conn.execute("SELECT COUNT(*) FROM credentials WHERE file_id=?", (file_id,)).fetchone()[0]
    assert n == 0

    conn.close()


def test_ingest_credential_all_hints_categorical(tmp_path: Path) -> None:
    """Every vuln_hint written to the DB must be in the fixed vocabulary."""
    conn = open_db(tmp_path / "analysis.db")
    combined = _FIXTURE_SHADOW_EMPTY_ROOT + _FIXTURE_SHADOW_MD5 + _FIXTURE_SHADOW_SHA512
    f = _make_file(tmp_path, "shadow", combined)
    file_id = _insert_nbf(conn, "credential", "shadow", f)
    _ingest_credential(conn, file_id, f)
    conn.commit()

    rows = conn.execute(
        "SELECT vuln_hint FROM credentials WHERE file_id = ? AND vuln_hint IS NOT NULL",
        (file_id,),
    ).fetchall()
    for (hint,) in rows:
        assert hint in _ALLOWED_CRED_HINTS, f"unexpected vuln_hint: {hint!r}"

    conn.close()


def test_ingest_credential_is_sensitive_correct(tmp_path: Path) -> None:
    """is_sensitive=1 for private key + hash; 0 for cert, public key, empty password."""
    conn = open_db(tmp_path / "analysis.db")

    pem_bundle = _FIXTURE_PEM_PRIVKEY + _FIXTURE_PEM_CERT + _FIXTURE_PEM_PUBKEY
    f_pem = _make_file(tmp_path, "bundle.pem", pem_bundle)
    fid_pem = _insert_nbf(conn, "credential", "pem", f_pem)
    _ingest_credential(conn, fid_pem, f_pem)

    f_shadow = _make_file(tmp_path, "shadow", _FIXTURE_SHADOW_EMPTY_ROOT + _FIXTURE_SHADOW_MD5)
    fid_shadow = _insert_nbf(conn, "credential", "shadow", f_shadow)
    _ingest_credential(conn, fid_shadow, f_shadow)
    conn.commit()

    sensitive = {
        r[0]
        for r in conn.execute("SELECT vuln_hint FROM credentials WHERE is_sensitive = 1").fetchall()
    }
    non_sensitive = {
        r[0]
        for r in conn.execute(
            "SELECT vuln_hint FROM credentials WHERE is_sensitive = 0 AND vuln_hint IS NOT NULL"
        ).fetchall()
    }

    assert "hardcoded_private_key" in sensitive
    assert "weak_password_hash_algo" in sensitive
    assert "certificate_present" in non_sensitive
    assert "public_key_present" in non_sensitive
    assert "empty_root_password" in non_sensitive

    conn.close()


# ── Round E: orchestrator integration — skip credential ingester ──────────────


def _build_credential_fixture_tree(root: Path) -> None:
    """Firmware tree with a shadow file and a PEM key file."""
    (root / "etc").mkdir()
    (root / "etc" / "shadow").write_text(
        _FIXTURE_SHADOW_EMPTY_ROOT + _FIXTURE_SHADOW_MD5,
        encoding="utf-8",
    )
    (root / "etc" / "server.pem").write_text(_FIXTURE_PEM_PRIVKEY, encoding="utf-8")


def test_orchestrator_credential_sub_rows(tmp_path: Path) -> None:
    """Credential tree: both files ingested, sub_rows['credential'] >= 2."""
    fs_root = tmp_path / "firmware"
    fs_root.mkdir()
    _build_credential_fixture_tree(fs_root)

    conn = open_db(tmp_path / "analysis.db")
    stats = run_all_ingesters(conn, fs_root)

    assert stats.by_kind.get("credential", 0) == 2
    assert stats.sub_rows.get("credential", 0) >= 2

    conn.close()


def test_orchestrator_skip_credential_ingester(tmp_path: Path) -> None:
    """skip_ingesters={'credential'} must leave credentials table empty."""
    fs_root = tmp_path / "firmware"
    fs_root.mkdir()
    _build_credential_fixture_tree(fs_root)

    conn = open_db(tmp_path / "analysis.db")
    stats = run_all_ingesters(conn, fs_root, skip_ingesters=frozenset({"credential"}))

    assert stats.by_kind.get("credential", 0) == 0
    assert "credential" not in stats.sub_rows
    assert conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0] == 0

    conn.close()


# ── Round F: _detect_web_asset ────────────────────────────────────────────────


def test_detect_web_asset_js_extension(tmp_path: Path) -> None:
    f = _make_file(tmp_path, "app.js", 'fetch("/api/status");\n')
    assert _detect_web_asset(f) == "js"


def test_detect_web_asset_html_extension(tmp_path: Path) -> None:
    f = _make_file(tmp_path, "index.html", "<html></html>\n")
    assert _detect_web_asset(f) == "html"


def test_detect_web_asset_htm_normalizes_to_html(tmp_path: Path) -> None:
    f = _make_file(tmp_path, "page.htm", "<html></html>\n")
    assert _detect_web_asset(f) == "html"


def test_detect_web_asset_mjs_normalizes_to_js(tmp_path: Path) -> None:
    f = _make_file(tmp_path, "module.mjs", "export default {};\n")
    assert _detect_web_asset(f) == "js"


def test_detect_web_asset_cgi_extension(tmp_path: Path) -> None:
    # non-shell .cgi (no shebang) → claimed by web_asset
    f = _make_file(tmp_path, "handler.cgi", "Content-Type: text/html\n\nhello\n")
    assert _detect_web_asset(f) == "cgi"


def test_detect_web_asset_php_extension(tmp_path: Path) -> None:
    f = _make_file(tmp_path, "index.php", "<?php echo 'ok'; ?>\n")
    assert _detect_web_asset(f) == "php"


def test_detect_web_asset_txt_returns_none(tmp_path: Path) -> None:
    f = _make_file(tmp_path, "readme.txt", "plain text\n")
    assert _detect_web_asset(f) is None


def test_detect_web_asset_binary_returns_none(tmp_path: Path) -> None:
    f = _make_binary_file(tmp_path, "firmware.bin")
    assert _detect_web_asset(f) is None


def test_detect_web_asset_no_extension_returns_none(tmp_path: Path) -> None:
    f = _make_file(tmp_path, "Makefile", "all:\n\techo done\n")
    assert _detect_web_asset(f) is None


# ── Round F: _classify_endpoint ───────────────────────────────────────────────


def test_classify_endpoint_api_path(tmp_path: Path) -> None:
    assert _classify_endpoint("/api/status") == "api_endpoint"


def test_classify_endpoint_cgi_bin(tmp_path: Path) -> None:
    assert _classify_endpoint("/cgi-bin/handler") == "cgi_endpoint"


def test_classify_endpoint_external_url(tmp_path: Path) -> None:
    assert _classify_endpoint("http://example.com/api") == "external_url"


def test_classify_endpoint_param_question_mark(tmp_path: Path) -> None:
    assert _classify_endpoint("/api/search?q=test") == "param_in_endpoint"


def test_classify_endpoint_param_template_var(tmp_path: Path) -> None:
    assert _classify_endpoint("/api/${endpoint}") == "param_in_endpoint"


# ── Round F: _ingest_web_asset — JS endpoint extraction ──────────────────────

# Vendor-neutral generic fixtures. Paths use /api/ and /cgi-bin/ conventions.
_FIXTURE_JS_ENDPOINTS = """\
// SPA API client
fetch("/api/status");
axios.post("/api/login", {data: "x"});
xhr.open("POST", "/cgi-bin/handler", true);
// repeated call — must deduplicate:
fetch("/api/status");
"""

_FIXTURE_HTML_FORM = """\
<!DOCTYPE html>
<html>
<body>
<form action="/api/save" method="post">
  <input type="text" name="data">
  <button type="submit">Submit</button>
</form>
</body>
</html>
"""

_FIXTURE_JS_DEDUP = """\
fetch("/api/x");
fetch("/api/x");
fetch("/api/x");
"""


def test_ingest_web_asset_js_fetch_axios_xhr(tmp_path: Path) -> None:
    """JS file: fetch, axios, XHR each produce a correctly attributed row."""
    conn = open_db(tmp_path / "analysis.db")
    f = _make_file(tmp_path, "app.js", _FIXTURE_JS_ENDPOINTS)
    file_id = _insert_nbf(conn, "web_asset", "js", f)

    count = _ingest_web_asset(conn, file_id, f)
    conn.commit()

    assert count >= 3

    rows = conn.execute(
        "SELECT source, method, path, vuln_hint FROM web_endpoints WHERE file_id = ?",
        (file_id,),
    ).fetchall()

    sources = {r[0] for r in rows}
    assert "fetch" in sources
    assert "axios" in sources
    assert "xhr" in sources

    # axios row: method extracted from the verb
    axios_rows = [r for r in rows if r[0] == "axios"]
    assert len(axios_rows) >= 1
    assert axios_rows[0][1] == "POST"
    assert axios_rows[0][2] == "/api/login"
    assert axios_rows[0][3] == "api_endpoint"

    # xhr row: method and cgi-bin path
    xhr_rows = [r for r in rows if r[0] == "xhr"]
    assert len(xhr_rows) >= 1
    assert xhr_rows[0][1] == "POST"
    assert "/cgi-bin/handler" in xhr_rows[0][2]
    assert xhr_rows[0][3] == "cgi_endpoint"

    # fetch row: no method, api path
    fetch_rows = [r for r in rows if r[0] == "fetch"]
    assert len(fetch_rows) >= 1
    assert fetch_rows[0][1] is None
    assert fetch_rows[0][2] == "/api/status"

    conn.close()


def test_ingest_web_asset_html_form(tmp_path: Path) -> None:
    """HTML form with action + method produces a single correct row."""
    conn = open_db(tmp_path / "analysis.db")
    f = _make_file(tmp_path, "save.html", _FIXTURE_HTML_FORM)
    file_id = _insert_nbf(conn, "web_asset", "html", f)

    count = _ingest_web_asset(conn, file_id, f)
    conn.commit()

    assert count >= 1

    form_rows = conn.execute(
        "SELECT method, path, vuln_hint FROM web_endpoints WHERE file_id = ? AND source = 'form'",
        (file_id,),
    ).fetchall()
    assert len(form_rows) == 1
    assert form_rows[0][0] == "POST"
    assert form_rows[0][1] == "/api/save"
    assert form_rows[0][2] == "api_endpoint"

    conn.close()


def test_ingest_web_asset_dedup_same_call(tmp_path: Path) -> None:
    """Three identical fetch() calls produce exactly one row for that source+path."""
    conn = open_db(tmp_path / "analysis.db")
    f = _make_file(tmp_path, "dup.js", _FIXTURE_JS_DEDUP)
    file_id = _insert_nbf(conn, "web_asset", "js", f)

    _ingest_web_asset(conn, file_id, f)
    conn.commit()

    fetch_count = conn.execute(
        "SELECT COUNT(*) FROM web_endpoints WHERE file_id = ? AND source = 'fetch'",
        (file_id,),
    ).fetchone()[0]
    assert fetch_count == 1

    conn.close()


def test_ingest_web_asset_dedup_multi_rule_same_path(tmp_path: Path) -> None:
    """A path matched by both a specific rule and the literal catch-all → one row only.

    Regression for the (method,path,source) dedup scheme that allowed literal to
    double-count paths already recorded by fetch/axios/xhr/form.
    """
    conn = open_db(tmp_path / "analysis.db")
    # fetch("/api/x") is hit by the 'fetch' rule AND by the 'literal' catch-all.
    f = _make_file(tmp_path, "api.js", 'fetch("/api/x");\n')
    file_id = _insert_nbf(conn, "web_asset", "js", f)

    count = _ingest_web_asset(conn, file_id, f)
    conn.commit()

    # Dedup on path: fetch rule wins (comes first); literal skipped → exactly 1 row.
    assert count == 1
    path_rows = conn.execute(
        "SELECT COUNT(*) FROM web_endpoints WHERE file_id = ? AND path = '/api/x'",
        (file_id,),
    ).fetchone()[0]
    assert path_rows == 1

    conn.close()


def test_ingest_web_asset_all_hints_categorical(tmp_path: Path) -> None:
    """Every vuln_hint written to web_endpoints must be in the fixed vocabulary."""
    conn = open_db(tmp_path / "analysis.db")
    f = _make_file(tmp_path, "multi.js", _FIXTURE_JS_ENDPOINTS)
    file_id = _insert_nbf(conn, "web_asset", "js", f)
    _ingest_web_asset(conn, file_id, f)
    conn.commit()

    rows = conn.execute(
        "SELECT vuln_hint FROM web_endpoints WHERE file_id = ? AND vuln_hint IS NOT NULL",
        (file_id,),
    ).fetchall()
    assert len(rows) >= 1
    for (hint,) in rows:
        assert hint in _ALLOWED_WEB_HINTS, f"unexpected vuln_hint: {hint!r}"

    conn.close()


def test_ingest_web_asset_binary_returns_zero(tmp_path: Path) -> None:
    conn = open_db(tmp_path / "analysis.db")
    f = _make_binary_file(tmp_path, "blob.bin")
    file_id = _insert_nbf(conn, "web_asset", "bin", f)

    count = _ingest_web_asset(conn, file_id, f)
    conn.commit()

    assert count == 0
    conn.close()


# ── Round F: orchestrator integration — shebang precedence + sub_rows ────────


def _build_web_fixture_tree(root: Path) -> None:
    """Firmware tree with web assets and a shell-backed CGI for shebang-precedence testing."""
    (root / "www").mkdir()

    (root / "www" / "app.js").write_text(
        'fetch("/api/status");\naxios.post("/api/login");\n',
        encoding="utf-8",
    )
    (root / "www" / "index.html").write_text(
        '<form action="/api/save" method="post"></form>\n',
        encoding="utf-8",
    )
    # shell shebang → claimed by shell_script, not web_asset
    (root / "www" / "update.cgi").write_text(
        "#!/bin/sh\necho Content-Type: text/html\necho\n",
        encoding="utf-8",
    )


def test_orchestrator_web_asset_sub_rows(tmp_path: Path) -> None:
    """Web asset tree: JS + HTML ingested; sub_rows['web_asset'] >= 1."""
    fs_root = tmp_path / "firmware"
    fs_root.mkdir()
    _build_web_fixture_tree(fs_root)

    conn = open_db(tmp_path / "analysis.db")
    stats = run_all_ingesters(conn, fs_root)

    # app.js and index.html are web assets; update.cgi goes to shell_script
    assert stats.by_kind.get("web_asset", 0) >= 2
    assert stats.sub_rows.get("web_asset", 0) >= 1

    conn.close()


def test_orchestrator_fd3_shell_cgi_claimed_by_shell_script(tmp_path: Path) -> None:
    """A shell-shebang .cgi is claimed by shell_script, not web_asset."""
    fs_root = tmp_path / "firmware"
    fs_root.mkdir()
    _build_web_fixture_tree(fs_root)

    conn = open_db(tmp_path / "analysis.db")
    run_all_ingesters(conn, fs_root)

    # update.cgi has #!/bin/sh → shell_script ingester claims it first
    cgi_rows = conn.execute(
        "SELECT kind FROM non_binary_files WHERE name = 'update.cgi'"
    ).fetchall()
    assert len(cgi_rows) == 1
    assert cgi_rows[0][0] == "shell_script"

    conn.close()


def test_orchestrator_skip_web_asset_ingester(tmp_path: Path) -> None:
    """skip_ingesters={'web_asset'} must leave web_endpoints table empty."""
    fs_root = tmp_path / "firmware"
    fs_root.mkdir()
    _build_web_fixture_tree(fs_root)

    conn = open_db(tmp_path / "analysis.db")
    stats = run_all_ingesters(conn, fs_root, skip_ingesters=frozenset({"web_asset"}))

    assert stats.by_kind.get("web_asset", 0) == 0
    assert "web_asset" not in stats.sub_rows
    assert conn.execute("SELECT COUNT(*) FROM web_endpoints").fetchone()[0] == 0

    conn.close()


# ── Exception isolation (orchestrator hardening) ──────────────────────────────


def test_orchestrator_isolates_ingester_exceptions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A throwing ingester must not abort the run; healthy ingesters still process files.

    Uses a synthetic throwing ingester injected via INGESTER_REGISTRY to verify:
    - run_all_ingesters returns normally (no exception propagated)
    - the healthy shell_script ingester still produces rows
    - the failed file leaves no orphan master row in non_binary_files
    """
    root = tmp_path / "fs"
    (root / "etc").mkdir(parents=True)
    (root / "init.sh").write_text('#!/bin/sh\neval "$cmd"\n', encoding="utf-8")
    (root / "etc" / "app.conf").write_text("admin_password=changeme\n", encoding="utf-8")

    import treasure_map.lib.analyze.non_binary as nb_pkg
    from treasure_map.lib.analyze.non_binary.config_file import _detect_config
    from treasure_map.lib.analyze.non_binary.framework import NonBinaryIngester
    from treasure_map.lib.analyze.non_binary.shell_script import SHELL_SCRIPT_INGESTER

    def _boom(conn: object, file_id: int, f: object) -> int:
        raise RuntimeError("synthetic ingest failure")

    throwing_config = NonBinaryIngester(kind="config_file", detect=_detect_config, ingest=_boom)
    monkeypatch.setattr(nb_pkg, "INGESTER_REGISTRY", [SHELL_SCRIPT_INGESTER, throwing_config])

    conn = open_db(tmp_path / "analysis.db")
    stats = run_all_ingesters(conn, root)

    # Run completed without raising; healthy ingester produced rows.
    assert stats.sub_rows.get("shell_script", 0) >= 1

    # Failed file left no orphan master row.
    leftover = conn.execute(
        "SELECT COUNT(*) FROM non_binary_files WHERE kind = 'config_file'"
    ).fetchone()[0]
    assert leftover == 0

    conn.close()
