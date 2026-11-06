# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The diff-review agent skill on this machine: where each agent reads it, whose file is there, and
writing it through the install ledger.

A skills directory is shared between agents, so tmap writes each directory once, however many of
the chosen agents read it. A file there is in one of these states:

  * ``missing``  — no ``SKILL.md``.
  * ``aligned``  — exactly the skill this tmap ships.
  * ``stale``    — tmap's (the ledger records it, and it still holds exactly the bytes tmap
    wrote), an earlier text; it is replaced — in every directory tmap manages, not only the ones
    the agents chosen in a run read.
  * ``legacy``   — byte for byte a version an earlier tmap shipped before the ledger recorded
    skills (installed by hand); it is replaced — in every directory tmap manages, like ``stale``
    (nothing is created where it is missing) — and recorded from then on.
  * ``foreign``  — anything else (a file the ledger never recorded, a recorded file changed since
    tmap wrote it, an edited copy of an old version, a symbolic link); it is NEVER modified. Even
    ``--force`` replaces only the file itself (a link at ``SKILL.md`` included), never what a
    linked ``tmap-diff-review`` directory points at.
  * ``invalid``  — not a readable regular file; nothing is written.

A write is recorded ``pending`` (target path, sha256 and the directories it creates) before the
file moves into place, read back, and only then ``committed``. ``tmap uninstall`` removes a file
only while it still holds the recorded bytes, and then the directories that write created, each
only when empty.

Claude Code's directory follows ``CLAUDE_CONFIG_DIR``; ``~/.claude/skills`` stays one of tmap's
directories while that is set (tmap wrote there whenever it was not, and Cursor reads it), and a
write into ``$CLAUDE_CONFIG_DIR/skills`` records the variable, so an uninstall run without it
names the command that would take the file back.
"""

from __future__ import annotations

import hashlib
import os
import shlex
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from treasure_map.lib.query import diff_skill
from treasure_map.lib.query.diff_skill import SKILL_DIRNAME
from treasure_map.lib.setup.clients import claude_config_override
from treasure_map.lib.setup.ledger import Entry, Ledger

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
#   Claude Code: ~/.claude/skills ($CLAUDE_CONFIG_DIR/skills when that is set, the same override
#     its MCP registration follows) — https://code.claude.com/docs/en/skills
#   Codex: $HOME/.agents/skills (not ~/.codex/skills) — https://learn.chatgpt.com/docs/build-skills
#   Cursor: ~/.agents/skills and ~/.cursor/skills, and also ~/.claude/skills and ~/.codex/skills
#     — https://cursor.com/docs/context/skills
def claude_root(home: Path, environ: Mapping[str, str]) -> Path:
    base = claude_config_override(environ)
    return (base if base is not None else home / ".claude") / "skills"


def agents_root(home: Path) -> Path:
    return home / ".agents" / "skills"


def default_claude_root(home: Path) -> Path:
    """Claude Code's directory when ``CLAUDE_CONFIG_DIR`` is not set."""
    return home / ".claude" / "skills"


def cursor_roots(home: Path) -> tuple[Path, ...]:
    """The personal skills directories Cursor reads (fixed paths; no environment variable moves
    them)."""
    return tuple(home / d / "skills" for d in (".agents", ".cursor", ".claude", ".codex"))


def named_roots(home: Path, environ: Mapping[str, str]) -> tuple[tuple[str, Path], ...]:
    """Every directory tmap may write the skill into (and so ``tmap uninstall`` may remove it
    from), each with the short name the doctor reports it under. ``~/.claude/skills`` stays one
    while CLAUDE_CONFIG_DIR moves Claude Code's: tmap wrote there whenever it was unset."""
    claude = claude_root(home, environ)
    out = [("claude", claude)]
    if not is_known(default_claude_root(home), [claude]):
        out.append(("claude.default", default_claude_root(home)))
    out.append(("agents", agents_root(home)))
    return tuple(out)


def known_roots(home: Path, environ: Mapping[str, str]) -> tuple[Path, ...]:
    return tuple(root for _name, root in named_roots(home, environ))


def is_known(root: Path, known: Iterable[Path]) -> bool:
    """Whether ``root`` is one of the ``known`` directories (compared with links resolved)."""
    return os.path.realpath(root) in {os.path.realpath(r) for r in known}


def target_roots(selected: Iterable[str], home: Path, environ: Mapping[str, str]) -> list[Path]:
    """The skills directories to write for the agents chosen in THIS run, each once. Cursor reads
    the Codex directory and the default Claude Code one too, so it adds one only when no directory
    already chosen is one Cursor reads (Claude Code's, moved by CLAUDE_CONFIG_DIR, is not)."""
    chosen = set(selected)
    out: list[Path] = []
    if "claude-code" in chosen:
        out.append(claude_root(home, environ))
    if "codex" in chosen:
        out.append(agents_root(home))
    if "cursor" in chosen and not any(is_known(r, cursor_roots(home)) for r in out):
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
    return diff_skill.skill_text().encode("utf-8")


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str | None:
    try:
        return sha256_of(path.read_bytes())
    except OSError:
        return None


@dataclass(frozen=True)
class SkillStatus:
    root: Path
    path: Path
    state: SkillState
    detail: str = ""


def classify(root: Path, ledger: Ledger, want: bytes, *, known: Iterable[Path]) -> SkillStatus:
    """What is at ``root``'s skill path, against ``want`` and the ledger's committed record.
    ``known`` is the directories tmap manages (``known_roots``): a file elsewhere is never in the
    ledger, and is said so rather than called someone else's."""
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
        # Only the very bytes tmap wrote are tmap's to replace: the same test uninstall applies
        # before it deletes the file (``removable``).
        if sha256_of(data) == rec.extra.get("sha256"):
            return status("stale", "tmap's, from an earlier version")
        return status("foreign", "changed since tmap installed it")
    if not is_known(root, known):
        return status("foreign", "not in tmap's install ledger (a directory tmap does not manage)")
    return status("foreign", "tmap did not install it")


def replace_command(root: Path) -> str:
    """What a person runs to replace a file tmap will not touch."""
    return f"tmap review skill --install {root} --force"


def next_step(st: SkillStatus) -> str:
    """What a person does about a file tmap will not touch: the command that replaces it — or,
    for a ``tmap-diff-review`` directory that is a link (which not even ``--force`` writes
    through), to change the link first."""
    if st.path.parent.is_symlink():
        return f"{st.path.parent} is a link; remove or replace it first"
    return "to replace it: " + replace_command(st.root)


class SkillWriteError(OSError):
    """The file read back differs from what was written, or the write would go through a link."""


def _refuse_linked_dir(path: Path) -> None:
    """A ``tmap-diff-review`` directory that is a symbolic link is someone else's: not even
    ``--force`` writes into what it points at (a link at ``SKILL.md`` itself is replaced as a
    link, its target untouched)."""
    if path.parent.is_symlink():
        raise SkillWriteError(
            f"{path.parent} is a symbolic link to {os.readlink(path.parent)}; tmap does not write "
            "through it — remove or replace the link first"
        )


def _missing_dirs(directory: Path) -> list[Path]:
    """``directory`` and each of its parents that does not exist yet, outermost first."""
    out: list[Path] = []
    for d in (directory, *directory.parents):
        if d.exists() or d.is_symlink():
            break
        out.append(d)
    return out[::-1]


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


def write_plain(path: Path, data: bytes) -> None:
    """Write without recording (a directory tmap does not manage), then read it back."""
    _refuse_linked_dir(path)
    _write(path, data)
    if _read_back(path) != data:
        raise SkillWriteError(f"{path}: the file read back differs from what was written")


def claude_config_dir_of(root: Path, home: Path, environ: Mapping[str, str]) -> Path | None:
    """``CLAUDE_CONFIG_DIR`` when it is set and ``root`` is the Claude Code directory it moved
    (what a write there records, for an uninstall run without the variable)."""
    base = claude_config_override(environ)
    if base is None or not is_known(root, [claude_root(home, environ)]):
        return None
    if is_known(root, [default_claude_root(home)]):
        return None  # the default directory: found without the variable
    return base


def install(
    path: Path, data: bytes, ledger: Ledger, *, claude_config_dir: Path | None = None
) -> None:
    """Write ``data`` at ``path`` through the ledger: pending (path, sha256, the directories this
    write creates — kept from the earlier record on a replacement — and the ``claude_config_dir``
    it is written under, if any) -> write -> read back equal -> committed. A failed read-back
    leaves the entry pending for the next run to settle."""
    _refuse_linked_dir(path)
    eid = entry_id(path)
    prior = ledger.committed(eid)
    prior_sha = prior.extra.get("sha256") if prior is not None else None
    prior_dirs = prior.extra.get("created_dirs") if prior is not None else None
    extra: dict[str, object] = {"sha256": sha256_of(data)}
    if isinstance(prior_sha, str):
        extra["prior_sha256"] = prior_sha
    created = [d for d in prior_dirs if isinstance(d, str)] if isinstance(prior_dirs, list) else []
    created += [str(d) for d in _missing_dirs(path.parent) if str(d) not in created]
    if created:
        extra["created_dirs"] = created
    if claude_config_dir is not None:
        extra["claude_config_dir"] = str(claude_config_dir)
    ledger.add_pending(eid, "file", path, **extra)
    _write(path, data)
    if sha256_of(_read_back(path)) != extra["sha256"]:
        raise SkillWriteError(f"{path}: the file read back differs from what was written")
    entry = ledger.find(eid)
    assert entry is not None
    entry.extra.pop("prior_sha256", None)
    ledger.commit(eid)


def recover(ledger: Ledger, *, prune: bool = True) -> list[str]:
    """Settle the skill entries an interrupted write left pending: the new file in place ->
    committed; the file it was replacing still there -> that one's record restored; anything else
    -> the entry is dropped and the file left as it is (when no file is there — a first write cut
    off before it moved in — the directories that write created go too, each only when empty;
    with ``prune`` false nothing on disk is touched)."""
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
            if prune and not path.exists() and not path.is_symlink():
                prune_dirs(path, entry.extra.get("created_dirs"), parent=False)
            if path.exists():
                lines.append(f"left {path} in place: an unfinished skill write tmap cannot prove")
    return lines


class _Unsaved(Ledger):
    """A copy of a ledger that is never written back."""

    def save(self) -> None:
        pass


def settled_copy(ledger: Ledger) -> Ledger:
    """The ledger as ``recover`` would leave it, on a copy that is never written back and with
    nothing on disk changed (what the doctor and uninstall's plan read)."""
    copy = _Unsaved(ledger.path, [Entry.from_json(e.to_json()) for e in ledger.entries])
    recover(copy, prune=False)
    return copy


def removable(
    path: Path,
    recorded_sha: object,
    home: Path,
    environ: Mapping[str, str],
    *,
    claude_config_dir: object = None,
) -> str | None:
    """None when the recorded skill at ``path`` may be removed; else why not: only a
    ``tmap-diff-review/SKILL.md`` directly in one of tmap's skills directories, still holding what
    tmap wrote. One written under a ``claude_config_dir`` this run does not have is refused with
    the command that runs under it."""
    in_known = is_known(path.parent.parent, known_roots(home, environ))
    if path.name != SKILL_FILE or path.parent.name != SKILL_DIRNAME or not in_known:
        now = claude_config_override(environ)
        if (
            isinstance(claude_config_dir, str)
            and claude_config_dir
            and (now is None or os.path.realpath(now) != os.path.realpath(claude_config_dir))
        ):
            return (
                f"{path} was installed while CLAUDE_CONFIG_DIR={claude_config_dir}; not removed — "
                f"run `CLAUDE_CONFIG_DIR={shlex.quote(claude_config_dir)} tmap uninstall`"
            )
        return f"{path} is not where tmap installs its skill; not removed"
    if path.is_symlink() or path.parent.is_symlink():
        return f"{path} is a symbolic link; not removed"
    if not path.exists():
        return None
    if not isinstance(recorded_sha, str) or file_sha256(path) != recorded_sha:
        return f"{path} changed since tmap installed it; not removed"
    return None


def prune_dirs(path: Path, created: object, *, parent: bool = True) -> list[Path]:
    """After the skill at ``path`` is removed: its ``tmap-diff-review`` directory (unless
    ``parent`` is false) and the directories above it that tmap's write created (the ledger's
    ``created_dirs``), deepest first, each only when nothing is left in it. A recorded directory
    that is not one of ``path``'s parents, or is a symbolic link, is left alone."""
    parents = set(path.parents)
    dirs = {path.parent} if parent else set()
    if isinstance(created, list):
        dirs |= {Path(d) for d in created if isinstance(d, str) and Path(d) in parents}
    removed: list[Path] = []
    for d in sorted(dirs, key=lambda p: len(p.parts), reverse=True):
        if d.is_symlink() or not d.is_dir():
            continue
        try:
            d.rmdir()  # only when nothing else is left in it
        except OSError:
            continue
        removed.append(d)
    return removed
