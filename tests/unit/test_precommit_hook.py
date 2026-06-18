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
_COMMIT_MSG_SRC = _REPO_ROOT / ".githooks" / "commit-msg"
_LIB_SRC = _REPO_ROOT / ".githooks" / "lib.sh"
_EXAMPLE_SRC = _REPO_ROOT / ".githooks" / "vendor-watchlist.example.txt"
_CI_SCRIPT = _REPO_ROOT / "scripts" / "check-vendor-neutrality.sh"

# Fabricated, NOT a real vendor name — safe to appear in committed test source.
_FAKE_VENDOR = "Acmecorp"

# Synthetic model number built from two non-matching halves so neither component
# triggers the hook's PCRE regex or any literal watchlist entry on this source file.
# Left half alone fails the lookahead (no digit follows directly); right half is
# plain digits with no uppercase prefix.
_FAKE_MODEL_NUM = "ZZ-X" + "99"

# Lower-case run-together model form (e.g. an all-lowercase IoT model). Assembled
# from two halves so the literal never appears in this committed source file: the
# prefix half has no trailing digits and the digit half has no leading letters, so
# neither half matches the model regex on this file.
_FAKE_LC_MODEL = "dcs" + "932"

# Technical tokens of the same letters+digits shape that MUST NOT be flagged. Only
# sha256 actually reaches the >=3-digit regex (the rest have <3 digits); all are
# whitelisted by the example's negative lookahead.
_TECH_SAFE_WORDS = ["md5", "sha256", "base64", "arm32", "ipv4", "crc32", "utf8", "int64"]


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
    shutil.copy(_COMMIT_MSG_SRC, hooks_dir / "commit-msg")
    shutil.copy(_LIB_SRC, hooks_dir / "lib.sh")
    shutil.copy(_EXAMPLE_SRC, hooks_dir / "vendor-watchlist.example.txt")
    (hooks_dir / "pre-commit").chmod(0o755)
    (hooks_dir / "commit-msg").chmod(0o755)

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


def _run_commit_msg(repo: Path, watchlist: Path, message: str) -> subprocess.CompletedProcess[str]:
    """Run the commit-msg hook against a message, pinning the watchlist."""
    hook = repo / ".githooks" / "commit-msg"
    msg_file = repo / ".git" / "COMMIT_EDITMSG"
    msg_file.write_text(message, encoding="utf-8")
    env = os.environ.copy()
    env["TM_VENDOR_WATCHLIST"] = str(watchlist)
    return subprocess.run(
        [str(hook), str(msg_file)],
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


def test_hook_blocks_lowercase_runtogether_model(tmp_path: Path) -> None:
    """A lowercase, no-hyphen model (e.g. dcs932) in diff content is blocked by the example."""
    repo, _ = _init_repo(tmp_path)
    example = repo / ".githooks" / "vendor-watchlist.example.txt"
    bad_file = repo / "notes.md"
    bad_file.write_text(f"analysed device {_FAKE_LC_MODEL} firmware\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "notes.md"], check=True, capture_output=True)

    result = _run_hook(repo, example)
    assert result.returncode != 0, "lowercase run-together model should block via example regex"
    assert "COMMIT BLOCKED" in result.stdout


def test_hook_does_not_flag_technical_words(tmp_path: Path) -> None:
    """Technical tokens of the same shape (md5/sha256/base64/arm32/...) must NOT be flagged."""
    repo, _ = _init_repo(tmp_path)
    example = repo / ".githooks" / "vendor-watchlist.example.txt"
    src = repo / "hashing.md"
    src.write_text(
        "We hash with " + " and ".join(_TECH_SAFE_WORDS) + " on arm32 and x86 targets.\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(repo), "add", "hashing.md"], check=True, capture_output=True)

    result = _run_hook(repo, example)
    assert result.returncode == 0, (
        f"technical words must not false-positive; stdout={result.stdout!r}"
    )


def test_commit_msg_blocks_model_number(tmp_path: Path) -> None:
    """A model number in the COMMIT MESSAGE is blocked by the commit-msg hook (the missed hole)."""
    repo, _ = _init_repo(tmp_path)
    example = repo / ".githooks" / "vendor-watchlist.example.txt"
    msg = f"fix(analyze): handle {_FAKE_LC_MODEL} firmware quirk\n"
    result = _run_commit_msg(repo, example, msg)
    assert result.returncode != 0, "model number in commit message should be blocked"
    assert "COMMIT BLOCKED" in result.stdout


def test_commit_msg_allows_clean_message(tmp_path: Path) -> None:
    """A vendor-neutral commit message passes the commit-msg hook."""
    repo, _ = _init_repo(tmp_path)
    example = repo / ".githooks" / "vendor-watchlist.example.txt"
    result = _run_commit_msg(
        repo, example, "fix(analyze): handle IoT camera firmware quirk\n\nUses sha256 digests.\n"
    )
    assert result.returncode == 0, (
        f"clean message (incl. sha256) must pass; stdout={result.stdout!r}"
    )


def _commit(repo: Path, path: str, content: str, message: str) -> str:
    """Write+stage+commit a file with --no-verify; return the new commit sha."""
    (repo / path).write_text(content, encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", path], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "--no-verify", "-m", message],
        check=True,
        capture_output=True,
    )
    out = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    )
    return out.stdout.strip()


def _run_ci(repo: Path, watchlist: Path, base: str, head: str) -> subprocess.CompletedProcess[str]:
    """Run the CI backstop over base..head, pinning the watchlist to the example."""
    env = os.environ.copy()
    env["TM_VENDOR_WATCHLIST"] = str(watchlist)
    return subprocess.run(
        ["bash", str(_CI_SCRIPT), base, head],
        cwd=str(repo),
        capture_output=True,
        text=True,
        env=env,
    )


def test_ci_backstop_blocks_model_in_diff_content(tmp_path: Path) -> None:
    """CI fails when a lowercase model appears in diff CONTENT over the range (hook bypassed)."""
    repo, _ = _init_repo(tmp_path)
    example = repo / ".githooks" / "vendor-watchlist.example.txt"
    base = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    head = _commit(repo, "fw.md", f"flashed {_FAKE_LC_MODEL} image\n", "docs: add flashing note")
    result = _run_ci(repo, example, base, head)
    assert result.returncode != 0, "CI must catch a model in diff content even past a bypassed hook"
    assert "diff content" in result.stdout


def test_ci_backstop_blocks_model_in_commit_message(tmp_path: Path) -> None:
    """CI fails when a model appears only in the COMMIT MESSAGE (diff clean)."""
    repo, _ = _init_repo(tmp_path)
    example = repo / ".githooks" / "vendor-watchlist.example.txt"
    base = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    # Diff content is vendor-neutral; the model hides in the message only.
    head = _commit(repo, "fw.md", "flashed the IoT camera image\n", f"docs: note {_FAKE_LC_MODEL}")
    result = _run_ci(repo, example, base, head)
    assert result.returncode != 0, "CI must catch a model that sits only in the commit message"
    assert "commit message" in result.stdout


def test_ci_backstop_passes_clean_range(tmp_path: Path) -> None:
    """CI passes for a vendor-neutral diff + message range."""
    repo, _ = _init_repo(tmp_path)
    example = repo / ".githooks" / "vendor-watchlist.example.txt"
    base = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    head = _commit(
        repo, "fw.md", "flashed the IoT camera image (sha256 verified)\n", "docs: flashing note"
    )
    result = _run_ci(repo, example, base, head)
    assert result.returncode == 0, f"clean range must pass; stdout={result.stdout!r}"


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
