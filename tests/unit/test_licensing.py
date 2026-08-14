# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The tree carries exactly one licence, and it is the one LICENSE states.

A relicense is a single sweep, but staying relicensed is not: the next file someone adds carries
whatever header they copied from, and a stale header is the kind of thing nobody reads twice.
Mixed licence markers in one tree are worse than either licence on its own — a reader cannot tell
which terms apply, and an automated scanner reports both.

So this is not a record of the sweep, it is the invariant the sweep established.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]

# The licence the project is under. Written out rather than read from LICENSE, so the check cannot
# be satisfied by changing LICENSE alone.
_SPDX = "Apache-2.0"
_COPYRIGHT = "Copyright (C) 2026 JoeyZzZzZz"

# LICENSE holds the full Apache text, which necessarily contains the words below in their own
# right; NOTICE quotes the boilerplate. Both are checked separately for what they should say.
_LICENCE_TEXT_FILES = {"LICENSE", "NOTICE"}

# ── SELF-REFERENCE. Read the admission rule before adding to this. ────────────────────
#
# This file has to spell the superseded markers out: its mutation recipes name the exact header to
# put back, and there is no way to say "restore the old identifier" that a reader can act on
# without writing the identifier. Scanning itself, it reports itself.
#
# ADMISSION RULE — the ONLY thing that belongs here: a file whose job is to assert the ABSENCE of
# a marker, and which therefore must quote it. Not a general escape hatch; anything else that trips
# the scan is fixed in the file, never parked here. (The repo's neutrality hooks carry the same
# rule for the same reason — see .githooks/lib.sh.)
#
# The exemption is closed off below: this file's OWN header is asserted separately, so skipping it
# here cannot let it drift to a different licence.
_SELF_REFERENTIAL = {"test_licensing.py"}

_SUPERSEDED = re.compile(r"agpl|affero", re.IGNORECASE)


def _tracked() -> list[Path]:
    out = subprocess.run(  # noqa: S603 -- fixed argv, no shell
        ["git", "ls-files", "-z"],  # noqa: S607
        cwd=_REPO,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [_REPO / name for name in out.split("\0") if name]


def _readable_text(path: Path) -> str | None:
    try:
        return path.read_text()
    except (UnicodeDecodeError, OSError):
        return None  # a binary fixture carries no header to check


def test_no_superseded_licence_marker_survives_anywhere() -> None:
    # ★ MUTATION (verified RED, 1 failed): put `# SPDX-License-Identifier: AGPL-3.0-only` back on
    # any tracked file, or the word "AGPL" back into the README, and this names the file.
    offenders = []
    for path in _tracked():
        if path.name in _LICENCE_TEXT_FILES | _SELF_REFERENTIAL:
            continue
        text = _readable_text(path)
        if text and _SUPERSEDED.search(text):
            offenders.append(str(path.relative_to(_REPO)))
    assert not offenders, "superseded licence markers still in the tree:\n  " + "\n  ".join(
        offenders
    )


def test_every_spdx_identifier_in_the_tree_is_the_project_licence() -> None:
    # A file may carry no SPDX header; it may not carry a DIFFERENT one. Two licences in one tree
    # leave a reader unable to tell which terms apply to what.
    #
    # ★ MUTATION (verified RED, 1 failed): change any file's identifier to `MIT` and this reports
    # the value it found.
    found: set[str] = set()
    files = 0
    for path in _tracked():
        if path.name in _SELF_REFERENTIAL:
            continue  # its mutation recipes quote other identifiers; own header asserted below
        text = _readable_text(path)
        if not text:
            continue
        for match in re.finditer(r"SPDX-License-Identifier:\s*(\S+)", text):
            found.add(match.group(1))
            files += 1
    # a scan that found nothing would pass the assertion below without checking anything
    assert files > 100, f"only {files} SPDX headers seen — is the scan still finding source files?"
    assert found == {_SPDX}, f"expected only {_SPDX!r}, found {sorted(found)}"


def test_copyright_lines_are_the_single_project_year() -> None:
    # ★ MUTATION (verified RED, 1 failed): restore a `Copyright (C) 2025-2026 JoeyZzZzZz` line
    # anywhere and this names the file.
    stale = []
    for path in _tracked():
        if path.name in _LICENCE_TEXT_FILES | _SELF_REFERENTIAL:
            continue
        text = _readable_text(path)
        if not text:
            continue
        for match in re.finditer(r"Copyright \(C\) [-0-9]+ JoeyZzZzZz", text):
            if match.group(0) != _COPYRIGHT:
                stale.append(f"{path.relative_to(_REPO)}: {match.group(0)}")
    assert not stale, "copyright lines that are not the project's:\n  " + "\n  ".join(stale)


def test_the_exemption_stays_one_file_wide() -> None:
    # The admission rule above is the whole safety of the exemption, and a rule that lives only in
    # a comment is one edit away from being a way to silence a real violation: add the offending
    # file to the set and the gate agrees with it. Pinned to the one file that genuinely cannot be
    # scanned — widening it has to be a deliberate change here, not a quiet append.
    #
    # ★ MUTATION (verified RED, 1 failed): add any second name to _SELF_REFERENTIAL and this fails.
    assert _SELF_REFERENTIAL == {"test_licensing.py"}


def test_the_exempt_file_carries_the_project_licence_itself() -> None:
    # The exemption above is scoped to the MARKERS this file must quote; it must not become a hole
    # where this file's own header drifts unnoticed. Asserted directly, on its own first lines.
    #
    # ★ MUTATION (verified RED, 1 failed): change this file's own SPDX header and it fails.
    head = Path(__file__).read_text().splitlines()[:2]
    assert head[0] == f"# {_COPYRIGHT}"
    assert head[1] == f"# SPDX-License-Identifier: {_SPDX}"


def test_license_file_is_the_apache_text_and_notice_exists() -> None:
    license_text = (_REPO / "LICENSE").read_text()
    assert license_text.lstrip().startswith("Apache License")
    # a few load-bearing clauses, so a truncated or summarised copy does not pass as the licence
    assert "Version 2.0, January 2004" in license_text
    assert "http://www.apache.org/licenses/" in license_text
    assert '"AS IS" BASIS' in license_text

    notice = (_REPO / "NOTICE").read_text()
    assert _COPYRIGHT in notice
    assert "Apache License, Version 2.0" in notice


def test_package_metadata_declares_the_same_licence() -> None:
    # The classifier is what an installer and an index show; disagreeing with LICENSE there is the
    # version of this drift the most people would see.
    pyproject = (_REPO / "pyproject.toml").read_text()
    assert "License :: OSI Approved :: Apache Software License" in pyproject
    assert "License :: OSI Approved :: GNU" not in pyproject


def test_the_declared_version_is_one_value() -> None:
    # Two version strings mean whichever one a reader happens to look at is a coin flip; the value
    # itself is stamped onto every run this tool records.
    #
    # ★ MUTATION (verified RED, 1 failed): change either of the two and this fails naming both.
    pyproject = (_REPO / "pyproject.toml").read_text()
    version_py = (_REPO / "src" / "treasure_map" / "version.py").read_text()
    packaged = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    runtime = re.search(r'^__version__\s*=\s*"([^"]+)"', version_py, re.MULTILINE)
    assert packaged and runtime
    assert packaged.group(1) == runtime.group(1), (
        f"pyproject says {packaged.group(1)}, version.py says {runtime.group(1)}"
    )
