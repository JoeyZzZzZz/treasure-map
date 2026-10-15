# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""scripts/check_dco.py: a pull request passes only when every commit is signed off by its
author."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_dco.py"


def _repo(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    repo = tmp_path / "r"
    repo.mkdir()
    env = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Ada Dev",
        "GIT_AUTHOR_EMAIL": "ada@example.invalid",
        "GIT_COMMITTER_NAME": "Ada Dev",
        "GIT_COMMITTER_EMAIL": "ada@example.invalid",
    }
    subprocess.run(["git", "init", "-q"], cwd=repo, env=env, check=True)
    _commit(repo, env, "base")
    return repo, env


def _commit(repo: Path, env: dict[str, str], msg: str, *extra: str) -> str:
    (repo / "f").write_text(msg)
    subprocess.run(["git", "add", "f"], cwd=repo, env=env, check=True)
    subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", msg, *extra],
        cwd=repo,
        env=env,
        check=True,
    )
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, env=env, check=True, capture_output=True, text=True
    ).stdout.strip()


def _check(repo: Path, env: dict[str, str], base: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- this interpreter, the script, fixed arguments
        [sys.executable, str(_SCRIPT), base, "HEAD"],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_signed_off_commits_pass(tmp_path: Path) -> None:
    repo, env = _repo(tmp_path)
    base = _commit(repo, env, "start")
    _commit(repo, env, "one", "-s")
    _commit(repo, env, "two", "-s")
    res = _check(repo, env, base)
    assert res.returncode == 0, res.stdout + res.stderr


def test_an_unsigned_commit_fails_the_check(tmp_path: Path) -> None:
    """MUTATION: pass whatever the trailers say -> RED."""
    repo, env = _repo(tmp_path)
    base = _commit(repo, env, "start")
    _commit(repo, env, "one", "-s")
    bad = _commit(repo, env, "two")
    res = _check(repo, env, base)
    assert res.returncode == 1 and bad[:12] in res.stdout


def test_a_sign_off_by_someone_else_is_not_the_authors(tmp_path: Path) -> None:
    """MUTATION: accept any Signed-off-by line -> RED."""
    repo, env = _repo(tmp_path)
    base = _commit(repo, env, "start")
    _commit(repo, env, "one", "--trailer", "Signed-off-by: Someone Else <x@example.invalid>")
    res = _check(repo, env, base)
    assert res.returncode == 1


def test_a_range_that_cannot_be_read_never_passes(tmp_path: Path) -> None:
    repo, env = _repo(tmp_path)
    res = _check(repo, env, "0" * 40)
    assert res.returncode == 2
