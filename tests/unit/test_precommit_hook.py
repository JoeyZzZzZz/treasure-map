# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the §5.5 vendor-watchlist pre-commit hook.

Each test creates an isolated git repository in tmp_path, copies in the hook
and watchlist, stages a diff, and invokes the hook directly to verify it
passes or fails as expected.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

_REPO_ROOT = Path(__file__).parent.parent.parent
_HOOK_SRC = _REPO_ROOT / ".githooks" / "pre-commit"
_WATCHLIST_SRC = _REPO_ROOT / ".githooks" / "vendor-watchlist.txt"


def _init_repo(tmp_path: Path) -> Path:
    """Create a minimal git repo with the hook installed."""
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Test"],
        check=True,
        capture_output=True,
    )

    hooks_dir = repo / ".githooks"
    hooks_dir.mkdir()
    shutil.copy(_HOOK_SRC, hooks_dir / "pre-commit")
    shutil.copy(_WATCHLIST_SRC, hooks_dir / "vendor-watchlist.txt")
    (hooks_dir / "pre-commit").chmod(0o755)

    subprocess.run(
        ["git", "-C", str(repo), "config", "core.hooksPath", ".githooks"],
        check=True,
        capture_output=True,
    )

    # Initial commit so HEAD exists (needed for git diff --cached to work)
    readme = repo / "README"
    readme.write_text("init\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "README"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "--no-verify", "-m", "init"],
        check=True,
        capture_output=True,
    )
    return repo


def _run_hook(repo: Path) -> subprocess.CompletedProcess[str]:
    """Run the pre-commit hook directly (not via git commit) in the repo."""
    hook = repo / ".githooks" / "pre-commit"
    return subprocess.run(
        [str(hook)],
        cwd=str(repo),
        capture_output=True,
        text=True,
    )


def test_hook_passes_clean_diff(tmp_path: Path) -> None:
    """A staged file with no vendor identifiers must not block the commit."""
    repo = _init_repo(tmp_path)
    generic = repo / "init_script.sh"
    generic.write_text(
        "#!/bin/sh\nnvram_get wan_ifname\necho 'main web daemon'\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["git", "-C", str(repo), "add", "init_script.sh"], check=True, capture_output=True
    )

    result = _run_hook(repo)
    assert result.returncode == 0, (
        f"hook should pass; stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def _first_plain_watchlist_token(watchlist_path: Path) -> str:
    """Return the first non-comment, non-regex line from the watchlist (a literal vendor name)."""
    for line in watchlist_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and not any(c in stripped for c in r"[]()?"):
            return stripped
    raise RuntimeError("No plain token found in watchlist")


def test_hook_blocks_vendor_token(tmp_path: Path) -> None:
    """A staged file containing a watchlist token must cause hook exit code 1.

    The vendor name is loaded from the watchlist at test runtime so no literal
    vendor identifier appears in the committed test source (§5.5).
    """
    token = _first_plain_watchlist_token(_WATCHLIST_SRC)
    repo = _init_repo(tmp_path)
    bad_file = repo / "config.py"
    bad_file.write_text(f'CAMERA_MODEL = "{token} device"\n', encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "config.py"], check=True, capture_output=True)

    result = _run_hook(repo)
    assert result.returncode != 0, "hook should block a commit with a vendor token"
    assert "COMMIT BLOCKED" in result.stdout or "COMMIT BLOCKED" in result.stderr


def test_hook_watchlist_not_scanned_against_itself(tmp_path: Path) -> None:
    """Staging a change to the watchlist file itself must not trigger the hook."""
    repo = _init_repo(tmp_path)
    watchlist = repo / ".githooks" / "vendor-watchlist.txt"
    existing = watchlist.read_text(encoding="utf-8")
    watchlist.write_text(existing + "\n# added comment\n", encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(repo), "add", ".githooks/vendor-watchlist.txt"],
        check=True,
        capture_output=True,
    )

    result = _run_hook(repo)
    assert result.returncode == 0, (
        f"modifying the watchlist itself should not be blocked; stdout={result.stdout!r}"
    )
