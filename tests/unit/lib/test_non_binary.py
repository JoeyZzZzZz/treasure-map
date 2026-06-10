# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the non-binary ingester framework and ShellScript ingester."""

from __future__ import annotations

from pathlib import Path

from treasure_map.lib.analyze.non_binary.framework import NonBinaryFile
from treasure_map.lib.analyze.non_binary.orchestrator import run_all_ingesters
from treasure_map.lib.analyze.non_binary.shell_script import (
    SHELL_RISK_RULES,
    _detect_shell,
    _ingest_shell,
)
from treasure_map.lib.storage.connection import open_db

# ── Allowed vuln_hint vocabulary (§5.3) ──────────────────────────────────────

_ALLOWED_HINTS = frozenset(label for label, _ in SHELL_RISK_RULES)


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

    # plain text — no matching ingester, should be silently skipped
    (root / "etc" / "service.conf").write_text("[service]\nport=80\n", encoding="utf-8")

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
    assert stats.script_calls >= 1

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
    assert stats1.script_calls == stats2.script_calls

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
    assert stats.script_calls == 0
    assert conn.execute("SELECT COUNT(*) FROM non_binary_files").fetchone()[0] == 0

    conn.close()
