# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Tests for the vendor-watchlist pre-commit hook.

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

import pytest

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
_FAKE_LC_MODEL = "zqx" + "481"

# Upper-case run-together model form with a ONE-letter prefix run into four digits — the shape the
# lower-case rule (which needs at least two letters) does not reach. Assembled from halves for the
# same reason as above.
_FAKE_UC_MODEL = "Q" + "7310"

# Technical tokens of the same letters+digits shape that MUST NOT be flagged. Only
# sha256 actually reaches the >=3-digit regex (the rest have <3 digits); all are
# whitelisted by the example's negative lookahead.
_TECH_SAFE_WORDS = ["md5", "sha256", "base64", "arm32", "ipv4", "crc32", "utf8", "int64"]

# Lower-case model with a single trailing letter (a size/revision suffix). Assembled from halves
# so the full token never appears literally in this committed source file.
_FAKE_LC_MODEL_SUFFIX = _FAKE_LC_MODEL + "m"

# Lint rule codes, an interpreter tag and key/cipher sizes of the letters+digits shape that the
# generic lowercase regex must let through (all whitelisted by its negative lookahead), so they
# are safe to spell out in this committed source file.
_WHITELISTED_TECH = ["UP035", "TRY003", "py312", "ed25519", "aes256", "sha256s", "uint64s"]


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


def test_hook_blocks_uppercase_runtogether_model(tmp_path: Path) -> None:
    """A one-letter upper-case model-shaped token is blocked by the example, while a lint code of
    the same letter-then-digits shape (three digits) is not.

    MUTATION: delete the pattern from the example -> RED (the model-shaped token passes); widen
    it to three digits -> RED (the lint code is blocked)."""
    repo, _ = _init_repo(tmp_path)
    example = repo / ".githooks" / "vendor-watchlist.example.txt"
    bad_file = repo / "notes.md"
    bad_file.write_text(f"tested on {_FAKE_UC_MODEL} hardware\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "notes.md"], check=True, capture_output=True)
    result = _run_hook(repo, example)
    assert result.returncode != 0, "upper-case run-together model should block via example regex"

    subprocess.run(["git", "-C", str(repo), "reset"], check=True, capture_output=True)
    ok_file = repo / "ok.md"
    ok_file.write_text("the S608 and E501 lint codes are suppressed here\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "ok.md"], check=True, capture_output=True)
    result2 = _run_hook(repo, example)
    assert result2.returncode == 0, f"a lint code must pass; stdout={result2.stdout!r}"


def test_hook_blocks_lowercase_runtogether_model(tmp_path: Path) -> None:
    """A lowercase, no-hyphen model-shaped token in diff content is blocked by the example."""
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


def test_example_whitelists_lint_crypto_and_interpreter_tokens(tmp_path: Path) -> None:
    """The generic lowercase regex must let lint rule codes (UP035, TRY003), an interpreter tag
    (py312), key/cipher sizes (ed25519, aes256) and their plurals (sha256s, uint64s — the same
    optional trailing letter the model form takes) through, while STILL catching a real lowercase
    model shape — so the exemption did not simply switch the regex off.

    MUTATION: delete ``|ed25519`` from the example's negative-lookahead whitelist -> ed25519 is
    flagged, the clean-tokens run returns non-zero -> RED (observed: 1 failed). MUTATION: delete
    the whole lowercase regex line -> the model-shape run returns 0 -> RED (observed: 1 failed).
    MUTATION: drop the ``[a-z]?`` before the whitelist lookahead's closing ``\\b`` -> sha256s
    reads as a model -> RED."""
    repo, _ = _init_repo(tmp_path)
    example = repo / ".githooks" / "vendor-watchlist.example.txt"

    clean = repo / "tech.md"
    clean.write_text("rule codes " + " ".join(_WHITELISTED_TECH) + " are fine\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "tech.md"], check=True, capture_output=True)
    result = _run_hook(repo, example)
    assert result.returncode == 0, (
        f"whitelisted technical tokens must not be flagged; stdout={result.stdout!r}"
    )

    subprocess.run(["git", "-C", str(repo), "reset"], check=True, capture_output=True)
    model = repo / "model.md"
    model.write_text(f"analysed device {_FAKE_LC_MODEL} firmware\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "model.md"], check=True, capture_output=True)
    assert _run_hook(repo, example).returncode != 0, "a real model shape must still be caught"


def test_example_catches_lowercase_model_with_trailing_letter(tmp_path: Path) -> None:
    """A lowercase run-together model can carry a single trailing letter (a size/revision suffix);
    that form slipped through because the digit run had to end at a word boundary.

    MUTATION: drop the trailing ``[a-z]?`` from the example's lowercase regex -> the suffixed
    model passes the hook -> RED (observed: 1 failed)."""
    repo, _ = _init_repo(tmp_path)
    example = repo / ".githooks" / "vendor-watchlist.example.txt"
    bad = repo / "notes.md"
    bad.write_text(f"tested on {_FAKE_LC_MODEL_SUFFIX} units\n", encoding="utf-8")
    _git(repo, "add", "notes.md")
    result = _run_hook(repo, example)
    assert result.returncode != 0 and "COMMIT BLOCKED" in result.stdout, result.stdout


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


def test_the_whole_tree_at_head_is_clean_under_the_example() -> None:
    """A v* tag push has no usable base, so the release-time check scans the WHOLE tree at HEAD,
    not the pushed range. Run that exact mode, with the committed example list, over this
    repository: any regex change that flags existing text fails here on the main push instead of
    on the day a tag is cut (where it would stop the release).

    MUTATION: drop the ``[a-z]?`` before the example whitelist lookahead's closing ``\\b`` ->
    existing "sha256s" text reads as a model -> RED (observed: 1 failed)."""
    inside = subprocess.run(
        ["git", "-C", str(_REPO_ROOT), "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
    )
    if inside.returncode != 0:
        pytest.skip("not a git checkout")
    result = _run_ci(_REPO_ROOT, _EXAMPLE_SRC, "", "HEAD")
    assert "whole tree" in result.stdout + result.stderr, "the scan did not run in whole-tree mode"
    assert result.returncode == 0, result.stdout + result.stderr


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


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def test_a_renamed_file_is_scanned_whole(tmp_path: Path) -> None:
    """A pure rename used to show no content to the scan, so a file committed past the hook could
    be moved in again unseen.

    MUTATION: drop --no-renames from the hook's diff -> RED."""
    repo, watchlist = _init_repo(tmp_path)
    _commit(repo, "a.md", f"analysed device {_FAKE_LC_MODEL} firmware\n", "docs: add")
    _git(repo, "mv", "a.md", "b.md")
    result = _run_hook(repo, watchlist)
    assert result.returncode != 0 and "COMMIT BLOCKED" in result.stdout, result.stdout


def test_a_file_name_is_scanned(tmp_path: Path) -> None:
    """A model number in a FILE NAME is as public as one in its content.

    MUTATION: drop the staged-path scan from the hook -> RED."""
    repo, watchlist = _init_repo(tmp_path)
    name = f"{_FAKE_LC_MODEL}.md"
    (repo / name).write_text("generic notes\n", encoding="utf-8")
    _git(repo, "add", name)
    result = _run_hook(repo, watchlist)
    assert result.returncode != 0 and name in result.stdout, result.stdout


def test_the_generic_patterns_apply_alongside_a_fuller_list(tmp_path: Path) -> None:
    """A fuller local list adds names; it must not take the example's generic model shapes away.
    The synthetic list here holds only a vendor name, not the model-number regexes.

    MUTATION: scan only the given list in tm_scan_text -> RED."""
    repo, watchlist = _init_repo(tmp_path)  # watchlist = [_FAKE_VENDOR] only
    bad = repo / "notes.md"
    bad.write_text(f"analysed device {_FAKE_LC_MODEL} firmware\n", encoding="utf-8")
    _git(repo, "add", "notes.md")
    result = _run_hook(repo, watchlist)
    assert result.returncode != 0 and "COMMIT BLOCKED" in result.stdout, result.stdout


def test_dotted_section_and_private_doc_references_are_blocked(tmp_path: Path) -> None:
    """The section scan missed a dashed, dotted reference; the private-doc scan missed a design
    or spec file named in passing. Plain prose with a number passes.

    MUTATION: drop the dotted-section alternative from TM_SECTREF -> RED.
    MUTATION: drop the *_spec/_design.md alternative from TM_PRIVDOC -> RED."""
    for i, text in enumerate(
        ("the section" + "-6.4 invariant\n", "as the map" + "_design.md notes say\n")
    ):
        (tmp_path / f"case{i}").mkdir()
        repo, watchlist = _init_repo(tmp_path / f"case{i}")
        (repo / "x.py").write_text(f"# {text}", encoding="utf-8")
        _git(repo, "add", "x.py")
        result = _run_hook(repo, watchlist)
        assert result.returncode != 0 and "COMMIT BLOCKED" in result.stdout, text
    (tmp_path / "clean").mkdir()
    repo, watchlist = _init_repo(tmp_path / "clean")
    (repo / "x.py").write_text("# section 6 lists the limits\n", encoding="utf-8")
    _git(repo, "add", "x.py")
    assert _run_hook(repo, watchlist).returncode == 0


def test_ci_without_a_base_scans_the_whole_tree(tmp_path: Path) -> None:
    """A first push (no usable base) used to look only at HEAD~1..HEAD, so anything committed
    earlier went through unseen.

    MUTATION: fall back to HEAD~1 again when the base is not a commit -> RED."""
    repo, _ = _init_repo(tmp_path)
    example = repo / ".githooks" / "vendor-watchlist.example.txt"
    _commit(repo, "old.md", f"flashed {_FAKE_LC_MODEL} image\n", "docs: old note")
    head = _commit(repo, "new.md", "a clean note\n", "docs: new note")
    result = _run_ci(repo, example, "0" * 40, head)
    assert result.returncode != 0 and "whole tree" in result.stdout, result.stdout


def test_ci_scans_merge_commit_messages(tmp_path: Path) -> None:
    """A merge message names a branch, and a branch name can carry a model number.

    MUTATION: put --no-merges back on the message scan -> RED."""
    repo, _ = _init_repo(tmp_path)
    example = repo / ".githooks" / "vendor-watchlist.example.txt"
    base = _git(repo, "rev-parse", "HEAD")
    main_branch = _git(repo, "rev-parse", "--abbrev-ref", "HEAD")
    _git(repo, "checkout", "-q", "-b", "topic")
    _commit(repo, "t.md", "topic work\n", "docs: topic")
    _git(repo, "checkout", "-q", main_branch)
    _commit(repo, "m.md", "main work\n", "docs: main")
    _git(
        repo, "merge", "-q", "--no-ff", "--no-verify", "-m", f"merge {_FAKE_LC_MODEL} work", "topic"
    )
    head = _git(repo, "rev-parse", "HEAD")
    result = _run_ci(repo, example, base, head)
    assert result.returncode != 0 and "commit message" in result.stdout, result.stdout


def test_ci_backstop_scans_a_renamed_file_whole(tmp_path: Path) -> None:
    """A pure rename shows no added content over the range, so a model committed past the hook
    could be moved to a new name unseen by CI. --no-renames makes CI diff the renamed file as a
    fresh add and scan it whole.

    MUTATION: drop --no-renames from ADDED_ALL in check-vendor-neutrality.sh -> git reports the
    change as a rename (filtered out by --diff-filter=ACM), its content is not re-scanned -> RED
    (observed: 1 failed)."""
    repo, _ = _init_repo(tmp_path)
    example = repo / ".githooks" / "vendor-watchlist.example.txt"
    base = _commit(repo, "a.md", f"analysed device {_FAKE_LC_MODEL} firmware\n", "docs: add")
    _git(repo, "mv", "a.md", "b.md")
    subprocess.run(
        ["git", "-C", str(repo), "commit", "--no-verify", "-m", "docs: rename"],
        check=True,
        capture_output=True,
    )
    head = _git(repo, "rev-parse", "HEAD")
    result = _run_ci(repo, example, base, head)
    assert result.returncode != 0 and "diff content" in result.stdout, result.stdout


def test_ci_backstop_scans_a_file_name(tmp_path: Path) -> None:
    """A model number in a FILE NAME is as public as one in content; CI scans the added paths too,
    not only the added lines.

    MUTATION: drop the staged-path scan (the ``$PATHS`` half of the scanned text) from
    check-vendor-neutrality.sh -> the model in the name is not scanned, the clean content passes
    -> RED (observed: 1 failed)."""
    repo, _ = _init_repo(tmp_path)
    example = repo / ".githooks" / "vendor-watchlist.example.txt"
    base = _git(repo, "rev-parse", "HEAD")
    name = f"{_FAKE_LC_MODEL}.md"
    head = _commit(repo, name, "generic notes\n", "docs: add a note")
    result = _run_ci(repo, example, base, head)
    assert result.returncode != 0 and name in result.stdout, result.stdout
