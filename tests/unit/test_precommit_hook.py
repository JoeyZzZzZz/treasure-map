# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the §5.5 vendor-watchlist pre-commit hook.

The real brand watchlist is intentionally NOT committed (it lives outside the
repo). These tests therefore synthesize their own watchlist in tmp_path using a
fabricated, non-real vendor token, and point the hook at it via the
TM_VENDOR_WATCHLIST environment variable. Each test creates an isolated git
repo, stages a diff, and invokes the hook directly.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

_REPO_ROOT = Path(__file__).parent.parent.parent
_HOOK_SRC = _REPO_ROOT / ".githooks" / "pre-commit"
_EXAMPLE_SRC = _REPO_ROOT / ".githooks" / "vendor-watchlist.example.txt"

# Fabricated, NOT a real vendor name — safe to appear in committed test source (§5.5).
_FAKE_VENDOR = "Acmecorp"

# Synthetic model number built from two non-matching halves so neither component
# triggers the hook's PCRE regex or any literal watchlist entry on this source file.
# Left half alone fails the lookahead (no digit follows directly); right half is
# plain digits with no uppercase prefix.
_FAKE_MODEL_NUM = "ZZ-X" + "99"


def _init_repo(tmp_path: Path, watchlist_lines: list[str] | None = None) -> tuple[Path, Path]:
    """Create a minimal git repo with the hook + a synthetic watchlist installed.

    Returns (repo_path, watchlist_path). The synthetic watchlist contains
    _FAKE_VENDOR by default. The committed brand-free example is also copied in so
    the resolver's fallback path exists.
    """
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
    shutil.copy(_EXAMPLE_SRC, hooks_dir / "vendor-watchlist.example.txt")
    (hooks_dir / "pre-commit").chmod(0o755)

    watchlist = hooks_dir / "vendor-watchlist.txt"
    lines = watchlist_lines if watchlist_lines is not None else [_FAKE_VENDOR]
    watchlist.write_text("# synthetic test watchlist\n" + "\n".join(lines) + "\n", encoding="utf-8")

    subprocess.run(
        ["git", "-C", str(repo), "config", "core.hooksPath", ".githooks"],
        check=True,
        capture_output=True,
    )

    # Initial commit so HEAD exists (needed for git diff --cached).
    (repo / "README").write_text("init\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "README"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "--no-verify", "-m", "init"],
        check=True,
        capture_output=True,
    )
    return repo, watchlist


def _run_hook(repo: Path, watchlist: Path) -> subprocess.CompletedProcess[str]:
    """Run the pre-commit hook directly, pinning the watchlist via TM_VENDOR_WATCHLIST."""
    hook = repo / ".githooks" / "pre-commit"
    env = os.environ.copy()
    env["TM_VENDOR_WATCHLIST"] = str(watchlist)
    return subprocess.run(
        [str(hook)],
        cwd=str(repo),
        capture_output=True,
        text=True,
        env=env,
    )


def test_hook_passes_clean_diff(tmp_path: Path) -> None:
    """A staged file with no vendor identifiers must not block the commit."""
    repo, watchlist = _init_repo(tmp_path)
    generic = repo / "init_script.sh"
    generic.write_text(
        "#!/bin/sh\nnvram_get wan_ifname\necho 'main web daemon'\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["git", "-C", str(repo), "add", "init_script.sh"], check=True, capture_output=True
    )

    result = _run_hook(repo, watchlist)
    assert result.returncode == 0, (
        f"hook should pass; stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_hook_blocks_vendor_token(tmp_path: Path) -> None:
    """A staged file containing a watchlist token must cause hook exit code 1."""
    repo, watchlist = _init_repo(tmp_path)
    bad_file = repo / "config.py"
    bad_file.write_text(f'DEVICE = "{_FAKE_VENDOR} camera"\n', encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "config.py"], check=True, capture_output=True)

    result = _run_hook(repo, watchlist)
    assert result.returncode != 0, "hook should block a commit with a vendor token"
    assert "COMMIT BLOCKED" in result.stdout or "COMMIT BLOCKED" in result.stderr


def test_hook_blocks_model_number_via_example(tmp_path: Path) -> None:
    """The brand-free example's model-number regex must block model-shaped tokens."""
    repo, _ = _init_repo(tmp_path)
    example = repo / ".githooks" / "vendor-watchlist.example.txt"
    bad_file = repo / "notes.md"
    bad_file.write_text(f"device model {_FAKE_MODEL_NUM} referenced\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "notes.md"], check=True, capture_output=True)

    result = _run_hook(repo, example)
    assert result.returncode != 0, "model-number-shaped token should block via example regex"

    # And a plain UPPERCASE-HYPHEN word must NOT false-positive.
    subprocess.run(["git", "-C", str(repo), "reset"], check=True, capture_output=True)
    ok_file = repo / "ok.md"
    ok_file.write_text("we use a WIPE-AND-REBUILD strategy\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "ok.md"], check=True, capture_output=True)
    result2 = _run_hook(repo, example)
    assert result2.returncode == 0, f"plain hyphenated word must pass; stdout={result2.stdout!r}"


def test_hook_watchlist_not_scanned_against_itself(tmp_path: Path) -> None:
    """Staging a change to the watchlist file itself must not trigger the hook."""
    repo, watchlist = _init_repo(tmp_path)
    # The active watchlist is .githooks/vendor-watchlist.txt (an excluded path).
    watchlist.write_text(
        watchlist.read_text(encoding="utf-8") + f"\n{_FAKE_VENDOR}2\n", encoding="utf-8"
    )
    subprocess.run(
        ["git", "-C", str(repo), "add", ".githooks/vendor-watchlist.txt"],
        check=True,
        capture_output=True,
    )

    result = _run_hook(repo, watchlist)
    assert result.returncode == 0, (
        f"modifying the watchlist itself should not be blocked; stdout={result.stdout!r}"
    )
