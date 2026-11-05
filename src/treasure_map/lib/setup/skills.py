# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The diff-review agent skill on this machine: where each agent reads it, whose file is there, and
writing it through the install ledger.

A skills directory is shared between agents, so tmap writes each directory once, however many of
the chosen agents read it. A file there is in one of these states:

  * ``missing``  — no ``SKILL.md``.
  * ``aligned``  — exactly the skill this tmap ships.
  * ``stale``    — tmap's (the ledger records it, its frontmatter name is the skill's), an
    earlier text; it is replaced.
  * ``legacy``   — byte for byte a version an earlier tmap shipped before the ledger recorded
    skills (installed by hand); it is replaced, and recorded from then on.
  * ``foreign``  — anything else (a file the ledger never recorded, an edited copy of an old
    version, a symbolic link); it is NEVER modified.
  * ``invalid``  — not a readable regular file; nothing is written.

A write is recorded ``pending`` (target path and sha256) before the file moves into place, read
back, and only then ``committed``.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml

from treasure_map.lib.setup.ledger import Ledger

SKILL_DIRNAME = "tmap-diff-review"
SKILL_FILE = "SKILL.md"
ID_PREFIX = "skill:"

SkillState = Literal["missing", "aligned", "stale", "legacy", "foreign", "invalid"]

# sha256 of each text an earlier tmap shipped (skills/diff-review.md, installed verbatim by
# `tmap review skill --install`), before the ledger recorded skills.
LEGACY_SHA256 = frozenset(
    {
        "9c0d4c05f95cb3e313070431db58e8b57f736e94850608904eacc90c536484d8",  # 2,962 bytes
        "17e4d906c3e3d942a9d7e2480c8e3b42c8b41bf04ee1d7d0775aab980cf0d271",  # 3,144 bytes
    }
)


# Where each agent reads personal skills (<root>/<skill name>/SKILL.md):
#   Claude Code: ~/.claude/skills — https://code.claude.com/docs/en/skills
#   Codex: $HOME/.agents/skills (not ~/.codex/skills) — https://learn.chatgpt.com/docs/build-skills
#   Cursor: ~/.agents/skills and ~/.cursor/skills, and also ~/.claude/skills and ~/.codex/skills
#     — https://cursor.com/docs/context/skills
def claude_root(home: Path) -> Path:
    return home / ".claude" / "skills"


def agents_root(home: Path) -> Path:
    return home / ".agents" / "skills"


def known_roots(home: Path) -> tuple[Path, ...]:
    """Every directory tmap may write the skill into (and so ``tmap uninstall`` may remove it
    from)."""
    return (claude_root(home), agents_root(home))


def target_roots(selected: Iterable[str], home: Path) -> list[Path]:
    """The skills directories to write for the agents chosen in THIS run, each once. Cursor reads
    the Claude Code and Codex directories too, so it adds one only when neither of those agents was
    chosen."""
    chosen = set(selected)
    out: list[Path] = []
    if "claude-code" in chosen:
        out.append(claude_root(home))
    if "codex" in chosen:
        out.append(agents_root(home))
    if "cursor" in chosen and not chosen & {"claude-code", "codex"}:
        out.append(agents_root(home))
    return list(dict.fromkeys(out))


# Agents tmap writes no skill for: what to do by hand instead.
MANUAL: dict[str, str] = {
    # Uploaded as a ZIP of the skill folder:
    #   https://support.claude.com/en/articles/12512180-using-skills-in-claude
    "claude-desktop": (
        "Claude Desktop: tmap does not install agent skills there. To add the diff-review skill, "
        f"save `tmap review skill` as {SKILL_DIRNAME}/{SKILL_FILE}, zip that folder and upload it "
        "under Customize > Skills (code execution must be on)"
    ),
    # Whether and where dsh loads agent skills is not documented to tmap.
    "dsh": (
        "dsh: tmap does not know whether dsh loads agent skills, or from where; "
        "`tmap review skill` prints the diff-review skill"
    ),
}


def skill_path(root: Path) -> Path:
    return root / SKILL_DIRNAME / SKILL_FILE


def entry_id(path: Path) -> str:
    return f"{ID_PREFIX}{path}"


def shipped_bytes() -> bytes:
    """The skill this tmap ships, as it is written to disk."""
    from treasure_map.cli.review_cli import skill_text

    return skill_text().encode("utf-8")


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str | None:
    try:
        return sha256_of(path.read_bytes())
    except OSError:
        return None


def frontmatter_name(data: bytes) -> str | None:
    """The ``name`` in the file's leading ``---`` block, or None."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.startswith("---\n"):
        return None
    end = text.find("\n---", 4)
    if end < 0:
        return None
    try:
        meta = yaml.safe_load(text[4:end])
    except yaml.YAMLError:
        return None
    name = meta.get("name") if isinstance(meta, dict) else None
    return name if isinstance(name, str) else None


@dataclass(frozen=True)
class SkillStatus:
    root: Path
    path: Path
    state: SkillState
    detail: str = ""


def classify(root: Path, ledger: Ledger, want: bytes) -> SkillStatus:
    """What is at ``root``'s skill path, against ``want`` and the ledger's committed record."""
    path = skill_path(root)

    def status(state: SkillState, detail: str = "") -> SkillStatus:
        return SkillStatus(root, path, state, detail)

    if path.parent.is_symlink() or path.is_symlink():
        return status("foreign", "a symbolic link; tmap does not write through it")
    if path.parent.exists() and not path.parent.is_dir():
        return status("invalid", f"{path.parent} is not a directory")
    if not path.exists():
        return status("missing")
    if not path.is_file():
        return status("invalid", "not a regular file")
    try:
        data = path.read_bytes()
    except OSError as exc:
        return status("invalid", f"unreadable: {exc}")
    if data == want:
        return status("aligned")
    if sha256_of(data) in LEGACY_SHA256:
        return status("legacy", "an earlier tmap's version, installed by hand")
    rec = ledger.committed(entry_id(path))
    if rec is not None and rec.path == str(path):
        if frontmatter_name(data) == SKILL_DIRNAME:
            return status("stale", "tmap's, from an earlier version")
        return status("foreign", f"its name is no longer {SKILL_DIRNAME}")
    return status("foreign", "tmap did not install it")


def replace_command(root: Path) -> str:
    """What a person runs to replace a file tmap will not touch."""
    return f"tmap review skill --install {root} --force"


def _write(path: Path, data: bytes) -> None:
    """Replace ``path`` in one step (temporary file beside it, fsync, ``os.replace``)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _read_back(path: Path) -> bytes:
    """The bytes a write left behind (a seam a test uses to simulate a bad write)."""
    return path.read_bytes()


class SkillWriteError(OSError):
    """The file read back differs from what was written."""


def write_plain(path: Path, data: bytes) -> None:
    """Write without recording (a directory tmap does not manage), then read it back."""
    _write(path, data)
    if _read_back(path) != data:
        raise SkillWriteError(f"{path}: the file read back differs from what was written")


def install(path: Path, data: bytes, ledger: Ledger) -> None:
    """Write ``data`` at ``path`` through the ledger: pending (path, sha256) -> write -> read back
    equal -> committed. A failed read-back leaves the entry pending for the next run to settle."""
    eid = entry_id(path)
    prior = ledger.committed(eid)
    prior_sha = prior.extra.get("sha256") if prior is not None else None
    extra: dict[str, str] = {"sha256": sha256_of(data)}
    if isinstance(prior_sha, str):
        extra["prior_sha256"] = prior_sha
    ledger.add_pending(eid, "file", path, **extra)
    _write(path, data)
    if sha256_of(_read_back(path)) != extra["sha256"]:
        raise SkillWriteError(f"{path}: the file read back differs from what was written")
    entry = ledger.find(eid)
    assert entry is not None
    entry.extra.pop("prior_sha256", None)
    ledger.commit(eid)


def recover(ledger: Ledger) -> list[str]:
    """Settle the skill entries an interrupted write left pending: the new file in place ->
    committed; the file it was replacing still there -> that one's record restored; anything else
    -> the entry is dropped and the file left as it is."""
    lines: list[str] = []
    for entry in [e for e in ledger.pending() if e.id.startswith(ID_PREFIX)]:
        path = Path(entry.path)
        now = file_sha256(path) if path.is_file() and not path.is_symlink() else None
        new, old = entry.extra.get("sha256"), entry.extra.get("prior_sha256")
        if now is not None and now == new:
            entry.extra.pop("prior_sha256", None)
            ledger.commit(entry.id)
            lines.append(f"recovered the skill at {path} (interrupted run verified)")
        elif now is not None and now == old:
            entry.extra.pop("prior_sha256", None)
            ledger.commit(entry.id, sha256=old)
            lines.append(f"kept the earlier skill at {path} (its replacement was interrupted)")
        else:
            ledger.remove(entry.id)
            if path.exists():
                lines.append(f"left {path} in place: an unfinished skill write tmap cannot prove")
    return lines


def removable(path: Path, recorded_sha: object, home: Path) -> str | None:
    """None when the recorded skill at ``path`` may be removed; else why not: only a
    ``tmap-diff-review/SKILL.md`` directly in one of tmap's skills directories, still holding what
    tmap wrote."""
    in_known = os.path.realpath(path.parent.parent) in {
        os.path.realpath(r) for r in known_roots(home)
    }
    if path.name != SKILL_FILE or path.parent.name != SKILL_DIRNAME or not in_known:
        return f"{path} is not where tmap installs its skill; not removed"
    if path.is_symlink() or path.parent.is_symlink():
        return f"{path} is a symbolic link; not removed"
    if not path.exists():
        return None
    if not isinstance(recorded_sha, str) or file_sha256(path) != recorded_sha:
        return f"{path} changed since tmap installed it; not removed"
    return None
