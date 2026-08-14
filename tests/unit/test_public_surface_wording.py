# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The public surface must not make tmap the one doing the judging.

tmap supplies FACTS a model cannot generate for itself; the model and the person do the reasoning.
The text a user meets first — `tmap --help`, a command's one-line summary, the legal notice — is
where that distinction is easiest to lose, because a judgement word reads as a feature. "finds the
exploit path", "suspicious sinks": each quietly promotes the tool from witness to judge, and a
reader who believes it stops verifying.

This gate is a fixed, hand-written list of words checked against the actual public text. It is not
derived from the source, so it cannot drift into agreeing with whatever the source happens to say.
"""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "treasure_map"
_CLI = _SRC / "cli"
_NOTICE = _SRC / "lib" / "notice.py"
_PYPROJECT = _REPO / "pyproject.toml"

# ── SCOPE. Read this before widening it. ──────────────────────────────────────────────
#
# This gate scans the `help=` / `short_help=` strings and the click command/group docstrings under
# cli/, plus lib/notice.py and the package metadata in pyproject.toml. That is the text a user
# reads without asking for it.
#
# The package description belongs here even though it is not "help text": it is the single line an
# index and an installer show, so it reaches more people than any string in the CLI, and it is the
# easiest one to forget when the framing is fixed everywhere else. It was, in fact, the one that
# survived the first pass. Keywords ride along for the same reason — free text we choose. The
# classifiers do not: their vocabulary is PyPI's, not ours.
#
# It deliberately does NOT scan mcp_app.py. The `suspicious` / `exploitable` words there are the
# OVERLAY VERDICT VOCABULARY — the set a human or agent writes into an annotation
# (inconclusive / suspicious / excluded / safe / exploitable). Their subject is the annotator, not
# tmap, and the code has to spell them because they are stored values compared by name. Widening
# this gate to "all public text" without first exempting that vocabulary would produce a wall of
# false positives, and the way out of a wall of false positives is usually to weaken the blacklist
# or edit the vocabulary — either of which is worse than the gap being closed.
#
# The private exploit ledger CLI is exempt for a related reason: "exploit" there is the name of the
# thing the tool records, not a claim tmap makes about firmware.
_EXEMPT_FILES = {"exploit_cli.py"}

# Words that make tmap the ACTOR of a judgement. Hand-maintained on purpose.
_JUDGEMENT_WORDS = re.compile(
    r"exploit-path|suspicious|dangerous|\bvulnerable\b",
    re.IGNORECASE,
)

# A NEGATED use is the opposite failure and must not be flagged: "not a verdict", "not exploits,
# payloads, or attack code" are the honest disclaimers, and a gate that punished them would push
# the text toward saying less about its own limits.
#
# ★ Currently this exempts NOTHING — no public string contains a negated form of a blacklisted
# word. It is here so that adding one later does not force a choice between an honest disclaimer
# and a green gate. Its behaviour is pinned by a test below rather than left to the day it fires.
_NEGATED = re.compile(
    r"\bnot\s+(?:a\s+|an\s+)?(?:\w+\s+){0,2}?"
    r"(?:verdict|exploits?|exploit-path|payloads?|attack code|suspicious|dangerous|vulnerable)",
    re.IGNORECASE,
)


def _flag(text: str) -> list[str]:
    """The judgement words in ``text``, minus any that sit inside a negated disclaimer."""
    return [m.group(0) for m in _JUDGEMENT_WORDS.finditer(text) if not _covers(text, m)]


def _covers(text: str, match: re.Match[str]) -> bool:
    """Is this hit part of a negated disclaimer?"""
    return any(
        n.start() <= match.start() and match.end() <= n.end() for n in _NEGATED.finditer(text)
    )


def _is_click_decorator(node: ast.expr) -> bool:
    func = node.func if isinstance(node, ast.Call) else node
    while isinstance(func, ast.Attribute):
        if func.attr in ("group", "command"):
            return True
        func = func.value
    return False


def _public_strings(path: Path) -> list[tuple[int, str, str]]:
    """(line, kind, text) for every string this file puts in front of a user unasked."""
    out: list[tuple[int, str, str]] = []
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg in ("help", "short_help") and isinstance(kw.value, ast.Constant):
                    if isinstance(kw.value.value, str):
                        out.append((kw.value.lineno, kw.arg, kw.value.value))
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            doc = ast.get_docstring(node)
            if doc and any(_is_click_decorator(d) for d in node.decorator_list):
                out.append((node.lineno, "command docstring", doc))
    return out


def _package_metadata_strings() -> list[tuple[str, str]]:
    """(field, text) for the free-text public metadata: what an index and an installer show."""
    project = tomllib.loads(_PYPROJECT.read_text()).get("project", {})
    out: list[tuple[str, str]] = []
    description = project.get("description")
    if isinstance(description, str):
        out.append(("description", description))
    for keyword in project.get("keywords", []):
        if isinstance(keyword, str):
            out.append(("keyword", keyword))
    return out


def test_package_metadata_never_makes_tmap_the_judge() -> None:
    # ★ The description is the most widely read sentence the project has — one line on an index
    # page, in front of everyone who never opens the README. It kept "exploit-path discovery" after
    # the CLI had been fixed, which is exactly why it is scanned now rather than trusted.
    #
    # MUTATION (verified RED, 1 failed): put the old description back in pyproject.toml —
    # `description = "IoT firmware patch diff and exploit-path discovery"` — and this names it.
    fields = _package_metadata_strings()
    # a scan that read nothing would pass the assertion below without checking anything
    assert any(f == "description" for f, _ in fields), "no description found — did the read break?"
    offences = [f"{field}: {word!r} in {text!r}" for field, text in fields for word in _flag(text)]
    assert not offences, (
        "package metadata must not cast tmap as the one judging — it is the line an index shows:"
        "\n  " + "\n  ".join(offences)
    )


def test_cli_help_text_never_makes_tmap_the_judge() -> None:
    # ★ MUTATION (verified RED, 1 failed): put the old wording back in cli/main.py —
    # `"""Treasure Map — IoT firmware exploit-path discovery."""` — and this fails naming
    # main.py and the word. Verified the same way for each of the other two sites.
    #
    # Before the wording was fixed this flagged exactly three strings and nothing else
    # (main.py's group docstring, hunt's and scan's short_help), so it starts from a clean
    # green rather than a pile of pre-existing noise.
    offences: list[str] = []
    scanned: list[str] = []
    for path in sorted(_CLI.glob("*.py")):
        if path.name in _EXEMPT_FILES:
            continue
        for lineno, kind, text in _public_strings(path):
            scanned.append(text)
            for word in _flag(text):
                first = text.splitlines()[0]
                offences.append(f"{path.name}:{lineno} ({kind}) {word!r} in {first!r}")
    # ★ A clean scan and a scan of NOTHING look identical from the assertion below, so pin that the
    # corpus is really being read. Without this the gate goes quietly green if the glob, the
    # exemption list, or the string extractor ever stops finding text.
    assert len(scanned) > 40, (
        f"only {len(scanned)} public strings found — is the scan still working?"
    )
    assert any("Treasure Map" in s for s in scanned), "the front-door docstring was not scanned"
    assert any("scan's 2nd stage" in s for s in scanned), "a command short_help was not scanned"
    assert not offences, (
        "public help text must not cast tmap as the one judging — it supplies facts, the reader "
        "judges:\n  " + "\n  ".join(offences)
    )


def test_legal_notice_never_makes_tmap_the_judge() -> None:
    # The notice is the most-quoted public text there is; its disclaimers must survive the gate.
    for match in re.finditer(r'"([^"]*)"', _NOTICE.read_text()):
        assert not _flag(match.group(1)), match.group(1)


def test_a_negated_disclaimer_is_not_mistaken_for_a_claim() -> None:
    # The whitelist branch fires on nothing in the tree today, so its behaviour is pinned here
    # instead of on the day someone first needs it. Same word, opposite meaning: the claim is
    # flagged, the disclaimer is not.
    #
    # MUTATION (verified RED, 1 failed): drop the negation filter — `return [m.group(0) for m in
    # _JUDGEMENT_WORDS.finditer(text)]` in _flag — and the disclaimers below start failing.
    assert _flag("this run found a suspicious sink") == ["suspicious"]
    assert _flag("a lead, NOT a verdict") == []
    assert _flag("analysis leads for human review — not exploits, payloads, or attack code") == []
    assert _flag("a mechanism label, not a suspicious-code claim") == []
    # and the filter must not swallow a claim that merely sits near a negation
    assert _flag("not a verdict; the suspicious path is highlighted") == ["suspicious"]


def test_the_scope_note_stays_with_the_gate() -> None:
    # The reason mcp_app.py is out of scope has to travel WITH the code, or a later widening
    # rediscovers the wall of false positives the hard way.
    #
    # ★ Read only the COMMENT BLOCK above _EXEMPT_FILES, not the whole file: a first version of
    # this searched the file text and so was satisfied by the words inside its own assertion —
    # green no matter what happened to the comment it was guarding.
    #
    # MUTATION (verified RED, 1 failed): reword the scope comment to drop "OVERLAY VERDICT
    # VOCABULARY" and this fails.
    lines = Path(__file__).read_text().splitlines()
    end = next(i for i, ln in enumerate(lines) if ln.startswith("_EXEMPT_FILES"))
    note = "\n".join(ln for ln in lines[:end] if ln.startswith("#"))
    assert "mcp_app.py" in note
    assert "OVERLAY VERDICT VOCABULARY" in note
    # and why the package metadata IS in scope, since that is the boundary most recently moved
    assert "pyproject.toml" in note
