# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The diff-review agent skill on this machine: where each agent reads it, whose file is there, and
writing it through the install ledger.

A skills directory is shared between agents, so tmap writes each directory once, however many of
the chosen agents read it: ``~/.agents/skills`` whenever any agent is chosen (Codex, Cursor and dsh
read it), plus Claude Code's own directory and dsh's. A file there is in one of these states:

  * ``missing``  — no ``SKILL.md``.
  * ``aligned``  — exactly the skill this tmap ships.
  * ``stale``    — tmap's (the ledger records it, and it still holds exactly the bytes tmap
    wrote), an earlier text; it is replaced — in every directory tmap manages, not only the ones
    the agents chosen in a run read.
  * ``legacy``   — byte for byte a text an earlier tmap shipped and this one no longer does, but
    not the bytes the ledger records there (no record: installed by hand, or written where an
    earlier tmap did not record; or a recorded copy overwritten since with another such text — a
    copy still holding its recorded bytes is ``stale``, whatever its text); it is replaced — in
    every directory tmap manages, like ``stale`` (nothing is created where it is missing) — and
    recorded from then on.
  * ``foreign``  — anything else (a file the ledger never recorded, a recorded file changed since
    tmap wrote it, an edited copy of an old version, a symbolic link); it is NEVER modified. Even
    ``--force`` replaces only the file itself (a link at ``SKILL.md`` included), never what a
    linked ``tmap-diff-review`` directory points at.
  * ``invalid``  — not a readable regular file; nothing is written.

A write is recorded ``pending`` (target path, sha256 and the directories it creates) before the
file moves into place, read back, and only then ``committed``. ``tmap uninstall`` removes a file
only while it still holds the recorded bytes, and then the directories that write created, each
only when empty.

Every write is recorded, ``tmap review skill --install <dir>`` into any directory included (the
entry keeps that directory as ``root``): a directory the ledger holds a skill for is one tmap
manages from then on — the doctor reports it, init replaces tmap's copy there, uninstall takes it
back.

Claude Code's directory follows ``CLAUDE_CONFIG_DIR``; ``~/.claude/skills`` stays one of tmap's
directories while that is set (tmap wrote there whenever it was not, and Cursor reads it), and a
write into ``$CLAUDE_CONFIG_DIR/skills`` records the variable, so an uninstall run without it
names the command that would take the file back. dsh's directory follows ``$DSH_HOME`` the same
way (``~/.dsh/skills`` stays one of tmap's while that is set).
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
from treasure_map.lib.setup.clients import claude_config_override, dsh_home_dir, home_relative
from treasure_map.lib.setup.ledger import Entry, Ledger

SKILL_FILE = "SKILL.md"
ID_PREFIX = "skill:"

SkillState = Literal["missing", "aligned", "stale", "legacy", "foreign", "invalid"]

# sha256 of every text a tmap has shipped that this one no longer does. Changing the shipped text
# adds its sha256 here (a test holds the current one and fails until it is).
LEGACY_SHA256 = frozenset(
    {
        "9c0d4c05f95cb3e313070431db58e8b57f736e94850608904eacc90c536484d8",  # 2,962 bytes
        "17e4d906c3e3d942a9d7e2480c8e3b42c8b41bf04ee1d7d0775aab980cf0d271",  # 3,144 bytes
        "ac9653260d39760ada0505833306d4bc15ca7e6a92733e98a2e777dea2ab03ef",  # 3,126 bytes
        "72a1c74391c1c878e694b31c5e6160107a7160cc37c342b2e41345fd41553b4e",  # 3,387 bytes
        "81cb1c8a3f38f56e1db267cd05eefd0e4dc01fa90ff0b51d624555ff3b2c7055",  # 3,741 bytes
        "d0e126bdab7520511c1db4827c5f51b03d22c0b8749caacf1b193bc9d76de496",  # 4,658 bytes
        "afdcd8f7b7904a454fd8be56a41dbb5b60edecaa9387435a20f819b2158095cf",  # 4,727 bytes
    }
)


# Where each agent reads personal skills (<root>/<skill name>/SKILL.md):
#   Claude Code: ~/.claude/skills ($CLAUDE_CONFIG_DIR/skills when that is set, the same override
#     its MCP registration follows) — https://code.claude.com/docs/en/skills
#   Codex: $HOME/.agents/skills (not ~/.codex/skills) — https://learn.chatgpt.com/docs/build-skills
#   Cursor: ~/.agents/skills and ~/.cursor/skills, and also ~/.claude/skills and ~/.codex/skills
#     — https://cursor.com/docs/context/skills
#   dsh: $DSH_HOME/skills (~/.dsh/skills), then $DSH_AGENTS_HOME/skills (~/.agents/skills), each
#     one level deep — as dsh describes itself; not checked against a run of dsh
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


def dsh_root(home: Path, environ: Mapping[str, str]) -> Path:
    """dsh's own skills directory, ``$DSH_HOME/skills`` (``~/.dsh/skills``): dsh prefers it to
    ``~/.agents/skills``."""
    return dsh_home_dir(home, environ) / "skills"


def default_dsh_root(home: Path) -> Path:
    """dsh's directory when ``DSH_HOME`` is not set."""
    return home / ".dsh" / "skills"


def dsh_agents_root(home: Path, environ: Mapping[str, str]) -> Path | None:
    """``$DSH_AGENTS_HOME/skills`` when that is set (not blank): where dsh then reads the shared
    agents' skills; None when dsh reads ``~/.agents/skills``."""
    base = (environ.get("DSH_AGENTS_HOME") or "").strip()
    return home_relative(base, home) / "skills" if base else None


def named_roots(home: Path, environ: Mapping[str, str]) -> tuple[tuple[str, Path], ...]:
    """Every directory tmap writes the skill into for some agent (and so ``tmap uninstall`` may
    remove it from), each with the short name the doctor reports it under — whichever agents a
    run chose: a copy in any of them is seen, and tmap's replaced. ``~/.claude/skills`` stays one
    while CLAUDE_CONFIG_DIR moves Claude Code's (tmap wrote there whenever it was unset), and
    ``~/.dsh/skills`` while DSH_HOME moves dsh's."""
    out: list[tuple[str, Path]] = []

    def add(name: str, root: Path) -> None:
        if not is_known(root, [r for _n, r in out]):
            out.append((name, root))

    claude = claude_root(home, environ)
    add("claude", claude)
    add("claude.default", default_claude_root(home))
    add("agents", agents_root(home))
    add("dsh", dsh_root(home, environ))
    add("dsh.default", default_dsh_root(home))
    dsh_agents = dsh_agents_root(home, environ)
    if dsh_agents is not None:
        add("dsh.agents", dsh_agents)
    return tuple(out)


def known_roots(home: Path, environ: Mapping[str, str]) -> tuple[Path, ...]:
    return tuple(root for _name, root in named_roots(home, environ))


def is_known(root: Path, known: Iterable[Path]) -> bool:
    """Whether ``root`` is one of the ``known`` directories (compared with links resolved)."""
    return os.path.realpath(root) in {os.path.realpath(r) for r in known}


def target_roots(selected: Iterable[str], home: Path, environ: Mapping[str, str]) -> list[Path]:
    """The skills directories to write for the agents chosen in THIS run, each once:
    ``~/.agents/skills`` whenever any agent is chosen (Codex reads it, Cursor and dsh too), and
    Claude Code's and dsh's own directories when those are chosen."""
    chosen = set(selected)
    if not chosen:
        return []
    out: list[Path] = []
    if "claude-code" in chosen:
        out.append(claude_root(home, environ))
    out.append(agents_root(home))
    if "dsh" in chosen:
        out.append(dsh_root(home, environ))
        dsh_agents = dsh_agents_root(home, environ)
        if dsh_agents is not None:
            out.append(dsh_agents)
    return list(dict.fromkeys(out))


def shared_note(root: Path, home: Path) -> str:
    """What a plan line says of a directory more than one agent reads ("" for any other)."""
    if is_known(root, [agents_root(home)]):
        return " — a directory shared between agents: others read the skill there too"
    return ""


def recorded_roots(ledger: Ledger) -> tuple[Path, ...]:
    """The directories the ledger holds a skill for (committed or pending), each once: only an
    absolute ``<root>/tmap-diff-review/SKILL.md`` gives its ``<root>`` — a relative path would
    name a different file from every other working directory."""
    out: list[Path] = []
    for e in ledger.entries:
        if not e.id.startswith(ID_PREFIX):
            continue
        path = Path(e.path)
        if path.name != SKILL_FILE or path.parent.name != SKILL_DIRNAME or not path.is_absolute():
            continue
        out.append(path.parent.parent)
    return tuple(dict.fromkeys(out))


def custom_name(root: Path) -> str:
    """The doctor's short name for a recorded directory outside ``named_roots``: from its path
    alone, so it never changes when another directory is recorded."""
    return "custom." + hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:8]


def managed_roots(
    home: Path, environ: Mapping[str, str], ledger: Ledger
) -> tuple[tuple[str, Path], ...]:
    """``named_roots`` and each other directory the ledger holds a skill for: every directory tmap
    reports, and replaces its own copy in. Being here never makes a file tmap's to replace — that
    is ``classify``'s ledger record or an earlier shipped text."""
    named = named_roots(home, environ)
    known = [r for _n, r in named]
    extra = [(custom_name(r), r) for r in recorded_roots(ledger) if not is_known(r, known)]
    return (*named, *extra)


# Agents tmap writes no skill for: what to do by hand instead.
MANUAL: dict[str, str] = {
    # Uploaded as a ZIP of the skill folder:
    #   https://support.claude.com/en/articles/12512180-using-skills-in-claude
    "claude-desktop": (
        "Claude Desktop: tmap does not install agent skills there. To add the diff-review skill, "
        f"save `tmap review skill` as {SKILL_DIRNAME}/{SKILL_FILE}, zip that folder and upload it "
        "under Customize > Skills (code execution must be on)"
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
    ``known`` is the directories tmap manages (``managed_roots``' paths): an unrecorded file
    elsewhere is said to be outside the ledger rather than called someone else's."""
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
    rec = ledger.committed(entry_id(path))
    recorded = rec is not None and rec.path == str(path)
    # Only the very bytes tmap wrote are tmap's to replace: the same test uninstall applies before
    # it deletes the file (``removable``). Read before the earlier texts, so a copy tmap recorded
    # is said to be tmap's even when its text is one of them.
    if recorded and rec is not None and sha256_of(data) == rec.extra.get("sha256"):
        return status("stale", "tmap's, from an earlier version")
    # An earlier tmap's text byte for byte is tmap's to replace, recorded or not (a recorded copy
    # overwritten since with another earlier text too).
    if sha256_of(data) in LEGACY_SHA256:
        return status("legacy", "an earlier tmap's version")
    if recorded:
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
    """Write ``data`` at ``path`` through the ledger: pending (path, sha256, its skills directory
    as ``root``, the directories this write creates — kept from the earlier record on a
    replacement — and the ``claude_config_dir`` it is written under, if any) -> write -> read back
    equal -> committed. A failed read-back leaves the entry pending for the next run to settle."""
    _refuse_linked_dir(path)
    eid = entry_id(path)
    prior = ledger.committed(eid)
    prior_sha = prior.extra.get("sha256") if prior is not None else None
    prior_dirs = prior.extra.get("created_dirs") if prior is not None else None
    extra: dict[str, object] = {"sha256": sha256_of(data), "root": str(path.parent.parent)}
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
    recorded_root: object = None,
) -> str | None:
    """None when the recorded skill at ``path`` may be removed; else why not: only a
    ``tmap-diff-review/SKILL.md`` directly in one of tmap's skills directories — or in the
    absolute directory its entry recorded as ``root`` — still holding what tmap wrote. One written
    under a ``claude_config_dir`` this run does not have is refused first, with the command that
    runs under it."""
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
    in_known = is_known(path.parent.parent, known_roots(home, environ)) or (
        isinstance(recorded_root, str)
        and recorded_root == str(path.parent.parent)
        and path.is_absolute()
    )
    if path.name != SKILL_FILE or path.parent.name != SKILL_DIRNAME or not in_known:
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
