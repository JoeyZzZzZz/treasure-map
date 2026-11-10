# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The diff-review skill on disk: one write per shared skills directory, only tmap's own file is
ever rewritten, every write goes through the ledger, and uninstall takes back exactly that."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest
from click.testing import CliRunner, Result

from treasure_map.cli import review_cli
from treasure_map.lib.query import diff_skill
from treasure_map.lib.setup import clients as cl
from treasure_map.lib.setup import skills as sk
from treasure_map.lib.setup import uninstall as un
from treasure_map.lib.setup.doctor import DoctorInputs, _skill_checks
from treasure_map.lib.setup.initializer import InitResult, run_init
from treasure_map.lib.setup.ledger import LEDGER_NAME, Ledger
from treasure_map.lib.setup.toolchain_lock import load_lock

from . import fakes

_FIXTURES = Path(__file__).parents[3] / "fixtures" / "skills"
_LEGACY = _FIXTURES / "legacy_diff_review_3144.md"
# Every text an earlier tmap shipped, as git holds it (the first two before the ledger recorded
# skills, the others since).
_LEGACY_ALL = (
    _FIXTURES / "legacy_diff_review_2962.md",
    _LEGACY,
    _FIXTURES / "legacy_diff_review_3126.md",
    _FIXTURES / "legacy_diff_review_3387.md",
    _FIXTURES / "legacy_diff_review_3741.md",
)


def _shipped() -> bytes:
    return diff_skill.skill_text().encode("utf-8")


@pytest.fixture()
def newer(monkeypatch: pytest.MonkeyPatch) -> bytes:
    """A shipped skill that is none of the earlier versions (the real one may still equal one)."""
    text = diff_skill.skill_text() + "\nA newer line.\n"
    monkeypatch.setattr(diff_skill, "skill_text", lambda: text)
    return text.encode("utf-8")


def _ledger(home: Path) -> Ledger:
    return Ledger.load(home / ".treasure-map" / "toolchain" / LEDGER_NAME)


def _init(
    home: Path,
    clients: Sequence[str],
    echo: list[str] | None = None,
    environ: Mapping[str, str] | None = None,
) -> InitResult:
    return run_init(
        non_interactive=True,
        clients=clients,
        prompt=lambda _m: "",
        echo=(echo.append if echo is not None else lambda _m: None),
        platform=fakes.linux(),
        host=fakes.make_host(home, environ=environ),
        tmap=None,
    )


def _skill_files(home: Path) -> set[Path]:
    return {p for p in home.rglob(sk.SKILL_FILE) if ".treasure-map" not in p.parts}


def _uninstall(home: Path, environ: Mapping[str, str] | None = None) -> un.UninstallReport:
    tm = home / ".treasure-map"
    env = dict(environ or {})
    return un.uninstall(
        home=home,
        tm_home=tm,
        client_host=cl.ClientHost(home, env, fakes.linux(), lambda _n: None, fakes.fake_run()),
        tmap=None,
        config_path=tm / "config.yaml",
        echo=lambda _m: None,
    )


def _doctor(
    home: Path, requested: Sequence[str] = (), environ: Mapping[str, str] | None = None
) -> dict[str, tuple[str, str]]:
    env = dict(environ or {})
    inp = DoctorInputs(
        platform=fakes.linux(),
        host=fakes.make_host(home, environ=env),
        client_host=cl.ClientHost(home, env, fakes.linux(), lambda _n: None, fakes.fake_run()),
        cfg=None,
        lock=load_lock(),
        tmap=None,
        check_only=True,
        requested_clients=requested,
    )
    return {c.name: (c.state, c.detail) for c in _skill_checks(inp)}


# ── where ─────────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("clients", "roots"),
    [
        (("claude-code", "codex", "cursor"), (".claude", ".agents")),
        (("cursor",), (".agents",)),
        (("claude-code", "cursor"), (".claude", ".agents")),
        (("codex", "cursor"), (".agents",)),
        (("claude-desktop", "dsh"), (".agents", ".dsh")),
    ],
    ids=["cc_codex_cursor", "cursor_alone", "cc_cursor", "codex_cursor", "desktop_dsh"],
)
def test_each_shared_skills_directory_is_written_once(
    tmp_path: Path, clients: tuple[str, ...], roots: tuple[str, ...]
) -> None:
    """★ The directories come from the agents chosen in this run, each once: ~/.agents/skills
    whenever any agent is chosen, plus Claude Code's and dsh's own.

    MUTATION: Codex into ~/.codex/skills -> RED; ~/.agents/skills only for Codex or Cursor ->
    desktop_dsh has no ~/.agents copy -> RED."""
    home = tmp_path / "h"
    _init(home, clients)
    want = {home / r / "skills" / sk.SKILL_DIRNAME / sk.SKILL_FILE for r in roots}
    assert _skill_files(home) == want
    assert all(p.read_bytes() == _shipped() for p in want)
    ledger = _ledger(home)
    for p in want:
        entry = ledger.committed(sk.entry_id(p))
        assert entry is not None and entry.kind == "file" and entry.path == str(p)
        assert entry.extra["sha256"] == hashlib.sha256(_shipped()).hexdigest()


def test_claude_desktop_gets_steps_to_follow_and_no_file_of_its_own(tmp_path: Path) -> None:
    """Claude Desktop reads no skills directory: the steps are printed, and nothing is written
    for it beyond the shared ~/.agents/skills every run writes.

    MUTATION: give Claude Desktop the ~/.claude/skills directory -> a file is written there ->
    RED; drop the printed steps -> RED."""
    home = tmp_path / "h"
    echo: list[str] = []
    _init(home, ("claude-desktop",), echo)
    assert _skill_files(home) == {sk.skill_path(sk.agents_root(home))}
    assert any("Claude Desktop: tmap does not install agent skills" in ln for ln in echo)


def test_a_dry_run_and_a_second_init_write_nothing(tmp_path: Path) -> None:
    """MUTATION: plan an install for an aligned file -> the second run plans an action -> RED."""
    home = tmp_path / "h"
    run_init(
        dry_run=True,
        non_interactive=True,
        clients=("claude-code",),
        prompt=lambda _m: "",
        platform=fakes.linux(),
        host=fakes.make_host(home),
        tmap=None,
    )
    assert _skill_files(home) == set()
    _init(home, ("claude-code",))
    echo: list[str] = []
    _init(home, ("claude-code",), echo)
    assert not any("install the diff-review skill" in ln.lower() for ln in echo)


# ── whose file ────────────────────────────────────────────────────────────────────────────────


def test_a_foreign_skill_is_never_rewritten_and_the_command_is_given(tmp_path: Path) -> None:
    """★ Same name, never recorded by tmap: left as it is, and the command to replace it named.

    MUTATION: take a name match alone as tmap's (no ledger record needed) -> overwritten -> RED."""
    home = tmp_path / "h"
    path = sk.skill_path(sk.claude_root(home, {}))
    path.parent.mkdir(parents=True)
    mine = b"---\nname: tmap-diff-review\ndescription: my own\n---\nmine\n"
    path.write_bytes(mine)
    result = _init(home, ("claude-code",))
    assert path.read_bytes() == mine
    assert _ledger(home).find(sk.entry_id(path)) is None
    cmd = f"tmap review skill --install {sk.claude_root(home, {})} --force"
    assert any(cmd in n for n in result.needs_you)
    assert _doctor(home)["skill.claude"][0] == "warn"


def test_a_symbolic_link_is_foreign(tmp_path: Path, newer: bytes) -> None:
    """A link is never written, even when what it points at is an earlier shipped version.

    MUTATION: drop the symbolic-link test -> the link is replaced -> RED."""
    home = tmp_path / "h"
    target = tmp_path / "elsewhere.md"
    target.write_bytes(_LEGACY.read_bytes())
    path = sk.skill_path(sk.agents_root(home))
    path.parent.mkdir(parents=True)
    path.symlink_to(target)
    result = _init(home, ("codex",))
    assert path.is_symlink() and target.read_bytes() == _LEGACY.read_bytes() != newer
    assert any("symbolic link" in n for n in result.needs_you)


@pytest.mark.parametrize(
    ("fixture", "size"),
    list(zip(_LEGACY_ALL, (2962, 3144, 3126, 3387, 3741), strict=True)),
    ids=["2962", "3144", "3126", "3387", "3741"],
)
def test_a_hand_installed_earlier_version_is_replaced_and_recorded(
    tmp_path: Path, newer: bytes, fixture: Path, size: int
) -> None:
    """★ Byte for byte the skill an earlier tmap shipped (put there by hand, or by `tmap review
    skill --install` where it did not record): replaced, and recorded from then on. One case per
    shipped text (E-m3c: each fixture is skills/diff-review.md exactly as git holds that version).

    MUTATION: drop the earlier-version hashes -> foreign -> left -> RED; drop only the 2,962-byte
    hash from LEGACY_SHA256 -> the 2962 case -> RED (1 failed: the file is left); the same for
    each of the texts shipped after the ledger recorded skills (3126, 3387, 3741) — a copy written
    where an earlier tmap did not record it is found by its text alone."""
    old = fixture.read_bytes()
    assert len(old) == size
    home = tmp_path / "h"
    path = sk.skill_path(sk.claude_root(home, {}))
    path.parent.mkdir(parents=True)
    path.write_bytes(old)
    assert _doctor(home)["skill.claude"][0] == "warn"
    _init(home, ("claude-code",))
    assert path.read_bytes() == newer == _shipped()
    assert hashlib.sha256(old).hexdigest() in sk.LEGACY_SHA256
    entry = _ledger(home).committed(sk.entry_id(path))
    assert entry is not None and entry.extra["sha256"] == hashlib.sha256(newer).hexdigest()


def test_an_edited_copy_of_an_earlier_version_is_foreign(tmp_path: Path, newer: bytes) -> None:
    """One character changed: no longer a version tmap shipped, so not tmap's to replace.

    MUTATION: recognise an earlier version by its name instead of its hash -> replaced -> RED."""
    edited = _LEGACY.read_bytes().replace(b"unit by unit", b"unit by Unit", 1)
    assert edited != _LEGACY.read_bytes()
    home = tmp_path / "h"
    path = sk.skill_path(sk.claude_root(home, {}))
    path.parent.mkdir(parents=True)
    path.write_bytes(edited)
    result = _init(home, ("claude-code",))
    assert path.read_bytes() == edited and path.read_bytes() != newer
    assert any("--force" in n for n in result.needs_you)


def test_a_recorded_skill_goes_stale_when_the_shipped_text_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, newer: bytes
) -> None:
    """★ The doctor reports a skill tmap installed whose text this tmap no longer ships, and the
    next init replaces it.

    MUTATION: classify a recorded, differing file as aligned -> the doctor says ok -> RED;
    as foreign -> init leaves it -> RED."""
    home = tmp_path / "h"
    _init(home, ("claude-code",))
    assert _doctor(home)["skill.claude"][0] == "ok"
    changed = diff_skill.skill_text() + "\nchanged\n"
    monkeypatch.setattr(diff_skill, "skill_text", lambda: changed)
    state, detail = _doctor(home)["skill.claude"]
    assert state == "warn" and "earlier version" in detail
    _init(home, ("claude-code",))
    path = sk.skill_path(sk.claude_root(home, {}))
    assert path.read_bytes() == changed.encode("utf-8")
    entry = _ledger(home).committed(sk.entry_id(path))
    assert entry is not None
    assert entry.extra["sha256"] == hashlib.sha256(changed.encode("utf-8")).hexdigest()
    assert "prior_sha256" not in entry.extra


def test_the_doctor_reports_one_line_per_skills_directory(tmp_path: Path) -> None:
    """MUTATION: a requested directory without the skill as info -> RED; an unreadable SKILL.md as
    ok/warn -> RED."""
    home = tmp_path / "h"
    assert {k: v[0] for k, v in _doctor(home).items()} == {
        "skill.claude": "info",
        "skill.agents": "info",
        "skill.dsh": "info",
    }
    assert _doctor(home, ("cursor",))["skill.agents"][0] == "missing"
    _init(home, ("cursor",))
    assert _doctor(home, ("cursor",))["skill.agents"][0] == "ok"
    sk.skill_path(sk.claude_root(home, {})).mkdir(parents=True)  # a directory named SKILL.md
    assert _doctor(home)["skill.claude"][0] == "wrong"


# ── the ledger ────────────────────────────────────────────────────────────────────────────────


def test_a_write_that_does_not_read_back_stays_pending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pending (path, sha256) before the write; committed only once the file reads back equal.

    MUTATION: commit before the read-back -> the entry is committed -> RED."""
    ledger = Ledger(tmp_path / LEDGER_NAME)
    path = sk.skill_path(tmp_path / "skills")
    data = b"---\nname: tmap-diff-review\n---\nbody\n"
    monkeypatch.setattr(sk, "_read_back", lambda _p: b"torn")
    with pytest.raises(sk.SkillWriteError):
        sk.install(path, data, ledger)
    entry = Ledger.load(ledger.path).find(sk.entry_id(path))
    assert entry is not None and entry.state == "pending" and entry.path == str(path)
    assert entry.extra["sha256"] == hashlib.sha256(data).hexdigest()
    monkeypatch.undo()
    reloaded = Ledger.load(ledger.path)
    assert sk.recover(reloaded)  # the file is in place: settled as committed
    assert reloaded.committed(sk.entry_id(path)) is not None


def test_an_interrupted_replacement_keeps_the_earlier_record(tmp_path: Path) -> None:
    """The write was cut off before the new file moved in: the old one is still tmap's.

    MUTATION: drop the earlier-record branch -> the entry is dropped (the file turns foreign) ->
    RED."""
    ledger = Ledger(tmp_path / LEDGER_NAME)
    path = sk.skill_path(tmp_path / "skills")
    old = b"---\nname: tmap-diff-review\n---\nold\n"
    sk.install(path, old, ledger)
    old_sha = hashlib.sha256(old).hexdigest()
    ledger.add_pending(sk.entry_id(path), "file", path, sha256="0" * 64, prior_sha256=old_sha)
    sk.recover(ledger)
    entry = ledger.committed(sk.entry_id(path))
    assert entry is not None and entry.extra == {"sha256": old_sha}


# ── uninstall ─────────────────────────────────────────────────────────────────────────────────


def test_uninstall_removes_the_skills_init_installed(tmp_path: Path) -> None:
    """★ init -> uninstall: both files and their tmap-diff-review directories are gone.

    MUTATION: drop the skill branch (falls through to "outside the toolchain") -> RED; leave
    the emptied directory -> RED."""
    home = Path.home()
    _init(home, ("claude-code", "codex"))
    assert len(_skill_files(home)) == 2
    report = _uninstall(home)
    assert not report.refused, report.refused
    assert _skill_files(home) == set()
    for root in sk.known_roots(home, {}):
        assert not (root / sk.SKILL_DIRNAME).exists()
    assert not (home / ".treasure-map" / "toolchain" / LEDGER_NAME).exists()


def test_uninstall_keeps_a_skill_edited_since_and_lists_it(tmp_path: Path) -> None:
    """★ One character changed after tmap wrote it: kept, and listed as refused.

    MUTATION: drop the sha256 comparison -> removed -> RED."""
    home = Path.home()
    _init(home, ("claude-code",))
    path = sk.skill_path(sk.claude_root(home, {}))
    edited = path.read_bytes().replace(b"tmap", b"Tmap", 1)
    path.write_bytes(edited)
    ledger = _ledger(home)
    lines = un.plan_lines(
        ledger,
        cl.survey(cl.ClientHost(home, {}, fakes.linux(), lambda _n: None, fakes.fake_run()), None),
        toolchain_dir=home / ".treasure-map" / "toolchain",
        home=home,
        environ={},
    )
    assert f"refuse {path}: {path} changed since tmap installed it; not removed" in lines
    report = _uninstall(home)
    assert path.read_bytes() == edited
    assert f"{path} changed since tmap installed it; not removed" in report.refused


@pytest.mark.parametrize(
    "rel",
    [
        "elsewhere/tmap-diff-review/SKILL.md",
        ".claude/skills/other/SKILL.md",
        ".claude/skills/tmap-diff-review/README.md",
        ".claude/skills/tmap-diff-review/nested/tmap-diff-review/SKILL.md",
    ],
    ids=["outside_the_known_directories", "another_skill", "another_file", "nested"],
)
def test_uninstall_refuses_a_recorded_skill_path_tmap_does_not_write(
    tmp_path: Path, rel: str
) -> None:
    """★ The ledger's path changed to somewhere tmap never writes the skill: refused, even though
    the bytes still hash to the record.

    MUTATION: drop the known-directory check -> outside_the_known_directories and nested are
    removed -> RED."""
    home = Path.home()
    path = home / rel
    path.parent.mkdir(parents=True)
    data = _shipped()
    path.write_bytes(data)
    ledger = _ledger(home)
    ledger.add_pending(sk.entry_id(path), "file", path, sha256=hashlib.sha256(data).hexdigest())
    ledger.commit(sk.entry_id(path))
    report = _uninstall(home)
    assert path.is_file() and path.read_bytes() == data
    assert any("is not where tmap installs its skill" in r for r in report.refused)


# ── tmap review skill --install ───────────────────────────────────────────────────────────────


def _install(root: Path, *extra: str) -> object:
    return CliRunner().invoke(review_cli.review, ["skill", "--install", str(root), *extra])


def test_review_skill_install_follows_the_same_rules(tmp_path: Path) -> None:
    """★ Into a directory tmap manages: recorded; a second run changes nothing; a foreign file is
    refused unless --force.

    MUTATION: write over a foreign file without --force -> RED."""
    home = Path.home()
    root = sk.claude_root(home, {})
    path = sk.skill_path(root)
    res = _install(root)
    assert res.exit_code == 0, res.output  # type: ignore[attr-defined]
    assert path.read_bytes() == _shipped()
    assert _ledger(home).committed(sk.entry_id(path)) is not None
    assert "already current" in _install(root).output  # type: ignore[attr-defined]

    other = sk.skill_path(sk.agents_root(home))
    other.parent.mkdir(parents=True)
    other.write_bytes(b"mine\n")
    res = _install(sk.agents_root(home))
    assert res.exit_code != 0 and "--force" in res.output  # type: ignore[attr-defined]
    assert other.read_bytes() == b"mine\n"
    res = _install(sk.agents_root(home), "--force")
    assert res.exit_code == 0 and other.read_bytes() == _shipped()  # type: ignore[attr-defined]
    assert _ledger(home).committed(sk.entry_id(other)) is not None


def test_review_skill_install_elsewhere_is_recorded_with_its_root(
    tmp_path: Path, newer: bytes
) -> None:
    """★ Any directory: written and recorded, committed, with the sha256 and the directory as
    ``root``; an earlier shipped version there is replaced without --force, and the output no
    longer says the file is outside the ledger.

    MUTATION: write a directory outside named_roots unrecorded again -> RED; drop ``root`` from
    install's record -> RED."""
    root = tmp_path / "skills"
    path = sk.skill_path(root)
    path.parent.mkdir(parents=True)
    path.write_bytes(_LEGACY.read_bytes())
    res = _install(root)
    assert res.exit_code == 0, res.output  # type: ignore[attr-defined]
    assert path.read_bytes() == newer
    assert "not in tmap's install ledger" not in res.output  # type: ignore[attr-defined]
    entry = _ledger(Path.home()).committed(sk.entry_id(path))
    assert entry is not None and entry.path == str(path)
    assert entry.extra["sha256"] == hashlib.sha256(newer).hexdigest()
    assert entry.extra["root"] == str(root) and Path(entry.extra["root"]).is_absolute()


# ── a recorded file changed since, links, other directories ─────────────────────────────────


def _install_r(root: Path, *extra: str) -> Result:
    return CliRunner().invoke(review_cli.review, ["skill", "--install", str(root), *extra])


def test_a_recorded_skill_edited_since_is_not_rewritten(tmp_path: Path) -> None:
    """★ FC11: the ledger records the file, but the user edited it since (name kept). It is no
    longer the bytes tmap wrote: init leaves it and names the command that would replace it, the
    doctor does not call it an earlier tmap version, and uninstall keeps it — init and uninstall
    agree on what is tmap's.

    MUTATION: drop the sha256 comparison from classify's ledger branch (a recorded file is stale
    again) -> the doctor says "an earlier version" and init overwrites the edit -> RED."""
    home = Path.home()
    _init(home, ("claude-code",))
    path = sk.skill_path(sk.claude_root(home, {}))
    assert _ledger(home).committed(sk.entry_id(path)) is not None
    edited = path.read_bytes() + b"\n- my own rule\n"  # the name is kept
    path.write_bytes(edited)
    state, detail = _doctor(home)["skill.claude"]
    assert state == "warn" and "changed since tmap installed it" in detail
    assert "earlier version" not in detail
    result = _init(home, ("claude-code",))
    assert path.read_bytes() == edited
    cmd = f"tmap review skill --install {sk.claude_root(home, {})} --force"
    assert any("changed since tmap installed it" in n and cmd in n for n in result.needs_you)
    rep = _uninstall(home)
    assert path.read_bytes() == edited and any("changed since" in r for r in rep.refused)


def test_init_looks_again_before_it_writes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """FC11: the plan found tmap's stale copy, but the user edited it after the plan was shown
    (here: while it was printed). init classifies it again before the write and leaves it.

    MUTATION: drop the second classify before ``sk.install`` -> the edit is overwritten -> RED."""
    home = Path.home()
    _init(home, ("claude-code",))
    path = sk.skill_path(sk.claude_root(home, {}))
    changed = diff_skill.skill_text() + "\nchanged\n"
    monkeypatch.setattr(diff_skill, "skill_text", lambda: changed)
    edited = path.read_bytes() + b"- my own rule\n"

    def echo(line: str) -> None:
        if line == "Plan:":
            path.write_bytes(edited)

    result = run_init(
        non_interactive=True,
        clients=("claude-code",),
        prompt=lambda _m: "",
        echo=echo,
        platform=fakes.linux(),
        host=fakes.make_host(home),
        tmap=None,
    )
    assert path.read_bytes() == edited
    assert any("changed since tmap installed it" in n and "--force" in n for n in result.needs_you)


def test_init_updates_tmaps_copy_in_a_directory_no_chosen_agent_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ E-m2: installed for dsh (~/.dsh), then the shipped text changes and init runs for
    Claude Code alone: tmap's unchanged copy in ~/.dsh is brought up to date too, and the doctor
    then reports every directory current. An edited copy there is still left alone.

    MUTATION: drop init's pass over the known directories outside this run's targets -> the
    ~/.dsh copy keeps the old text -> RED."""
    home = tmp_path / "h"
    _init(home, ("dsh",))
    agents = sk.skill_path(sk.dsh_root(home, {}))
    assert agents.read_bytes() == _shipped()
    changed = diff_skill.skill_text() + "\nchanged\n"
    monkeypatch.setattr(diff_skill, "skill_text", lambda: changed)
    _init(home, ("claude-code",))
    assert agents.read_bytes() == changed.encode("utf-8")
    assert sk.skill_path(sk.claude_root(home, {})).read_bytes() == changed.encode("utf-8")
    entry = _ledger(home).committed(sk.entry_id(agents))
    assert entry is not None
    assert entry.extra["sha256"] == hashlib.sha256(changed.encode("utf-8")).hexdigest()
    assert {k: v[0] for k, v in _doctor(home).items()} == {
        "skill.claude": "ok",
        "skill.agents": "ok",
        "skill.dsh": "ok",
    }
    edited = agents.read_bytes() + b"mine\n"
    agents.write_bytes(edited)
    monkeypatch.setattr(diff_skill, "skill_text", lambda: changed + "again\n")
    _init(home, ("claude-code",))
    assert agents.read_bytes() == edited


def test_force_does_not_write_through_a_linked_skill_directory(tmp_path: Path) -> None:
    """★ E-m1: ``tmap-diff-review`` is a link to the user's own directory. ``--force`` refuses,
    naming where the link points; the user's file there is untouched and nothing is recorded. A
    link at SKILL.md itself is still replaced as a link (its target untouched).

    MUTATION: drop the linked-directory refusal from install -> the user's SKILL.md is
    overwritten -> RED; refuse a link at SKILL.md too -> the second half -> RED."""
    home = Path.home()
    root = sk.claude_root(home, {})
    theirs = tmp_path / "dotfiles" / "tmap-diff-review"
    theirs.mkdir(parents=True)
    mine = b"---\nname: tmap-diff-review\n---\nmine\n"
    (theirs / sk.SKILL_FILE).write_bytes(mine)
    root.mkdir(parents=True)
    (root / sk.SKILL_DIRNAME).symlink_to(theirs, target_is_directory=True)
    res = _install_r(root, "--force")
    assert res.exit_code != 0
    assert f"symbolic link to {theirs}" in res.output
    assert (theirs / sk.SKILL_FILE).read_bytes() == mine
    assert _ledger(home).find(sk.entry_id(sk.skill_path(root))) is None

    other = sk.agents_root(home)
    target = tmp_path / "elsewhere.md"
    target.write_bytes(mine)
    link = sk.skill_path(other)
    link.parent.mkdir(parents=True)
    link.symlink_to(target)
    res = _install_r(other, "--force")
    assert res.exit_code == 0, res.output
    assert not link.is_symlink() and link.read_bytes() == _shipped()
    assert target.read_bytes() == mine


def test_a_linked_skill_directory_holding_an_earlier_version_is_not_written(
    tmp_path: Path, newer: bytes
) -> None:
    """E-m3a: the ``tmap-diff-review`` directory is a link to a directory whose SKILL.md is byte
    for byte an earlier shipped text. Still foreign: init plans no write and leaves the file, and
    the doctor names the link. Neither offers the ``--force`` command, which would refuse it.

    MUTATION: drop the ``path.parent.is_symlink()`` half of classify's link test -> legacy ->
    init plans the install -> RED; make next_step always give the --force command -> RED."""
    home = tmp_path / "h"
    theirs = tmp_path / "dotfiles" / "tmap-diff-review"
    theirs.mkdir(parents=True)
    (theirs / sk.SKILL_FILE).write_bytes(_LEGACY.read_bytes())
    root = sk.claude_root(home, {})
    root.mkdir(parents=True)
    (root / sk.SKILL_DIRNAME).symlink_to(theirs, target_is_directory=True)
    echo: list[str] = []
    result = _init(home, ("claude-code",), echo)
    assert not any("install the diff-review skill" in ln for ln in echo)
    assert (theirs / sk.SKILL_FILE).read_bytes() == _LEGACY.read_bytes() != newer
    hint = f"{root / sk.SKILL_DIRNAME} is a link; remove or replace it first"
    assert any("symbolic link" in n and hint in n for n in result.needs_you)
    assert not any("--force" in n for n in result.needs_you)  # --force would refuse it
    state, detail = _doctor(home)["skill.claude"]
    assert state == "warn" and "symbolic link" in detail and "--force" not in detail


def test_uninstall_refuses_a_recorded_skill_replaced_by_a_link(tmp_path: Path) -> None:
    """E-m3b: after init, SKILL.md is swapped for a link to a byte-identical file elsewhere. The
    bytes still hash to the record, but a link is not tmap's file: refused, the link and its
    target both left.

    MUTATION: drop ``path.is_symlink()`` from removable -> the link is removed -> RED."""
    home = Path.home()
    _init(home, ("claude-code",))
    path = sk.skill_path(sk.claude_root(home, {}))
    copy = tmp_path / "copy.md"
    copy.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(copy)
    report = _uninstall(home)
    assert path.is_symlink() and copy.read_bytes() == _shipped()
    assert f"{path} is a symbolic link; not removed" in report.refused


def test_a_directory_tmap_does_not_manage_is_said_so(tmp_path: Path) -> None:
    """E-m4: a file in a directory outside tmap's known ones is never in the ledger (tmap review
    skill --install writes there unrecorded), so it is said to be outside the ledger — not that
    tmap did not install it. In a directory tmap manages, an unrecorded file keeps that wording.

    MUTATION: give every unrecorded file the "tmap did not install it" detail -> RED."""
    home = Path.home()
    known = sk.known_roots(home, {})
    root = tmp_path / "skills"
    path = sk.skill_path(root)
    path.parent.mkdir(parents=True)
    path.write_bytes(b"an older text\n")
    wording = "not in tmap's install ledger (a directory tmap does not manage)"
    st = sk.classify(root, _ledger(home), _shipped(), known=known)
    assert st.state == "foreign" and st.detail == wording
    res = _install_r(root)
    assert res.exit_code != 0 and wording in res.output
    assert path.read_bytes() == b"an older text\n"
    managed = sk.skill_path(sk.agents_root(home))
    managed.parent.mkdir(parents=True)
    managed.write_bytes(b"an older text\n")
    st = sk.classify(sk.agents_root(home), _ledger(home), _shipped(), known=known)
    assert st.state == "foreign" and st.detail == "tmap did not install it"


def test_uninstall_removes_the_directories_its_install_created(tmp_path: Path) -> None:
    """★ E-m5: init for Codex creates ~/.agents and ~/.agents/skills; uninstall takes both away
    again. ~/.claude existed before (only ~/.claude/skills was created): it stays.

    MUTATION: record no created directories -> ~/.agents/skills and ~/.agents remain -> RED;
    record every parent, existing or not -> ~/.claude (empty after) is removed -> RED."""
    home = Path.home()
    (home / ".claude").mkdir()
    _init(home, ("claude-code", "codex"))
    entry = _ledger(home).committed(sk.entry_id(sk.skill_path(sk.agents_root(home))))
    assert entry is not None
    report = _uninstall(home)
    assert not report.refused, report.refused
    assert not (home / ".agents" / "skills").exists()
    assert not (home / ".agents").exists()
    assert not sk.claude_root(home, {}).exists()
    assert (home / ".claude").is_dir()


def test_uninstall_keeps_a_created_directory_that_is_not_empty(tmp_path: Path) -> None:
    """E-m5: a directory tmap created but the user has put something in since is kept (and so
    is everything above it).

    MUTATION: remove the created directories with rmtree instead of rmdir -> the user's file
    goes -> RED."""
    home = Path.home()
    _init(home, ("codex",))
    theirs = home / ".agents" / "skills" / "another" / "SKILL.md"
    theirs.parent.mkdir(parents=True)
    theirs.write_bytes(b"mine\n")
    report = _uninstall(home)
    assert not report.refused, report.refused
    assert theirs.is_file() and theirs.read_bytes() == b"mine\n"
    assert not (home / ".agents" / "skills" / sk.SKILL_DIRNAME).exists()


def test_claude_code_skills_follow_claude_config_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ E-m6: with CLAUDE_CONFIG_DIR set, Claude Code's skill goes into $CLAUDE_CONFIG_DIR/skills
    — where its MCP registration goes too — the doctor reads it there, uninstall takes it back,
    and `tmap review skill --install` there records it as a directory tmap manages.

    MUTATION: claude_root ignores the override -> the skill lands in ~/.claude/skills -> RED."""
    home = Path.home()
    cfg = tmp_path / "claude-config"
    env = {"CLAUDE_CONFIG_DIR": str(cfg)}
    run_init(
        non_interactive=True,
        clients=("claude-code",),
        prompt=lambda _m: "",
        echo=lambda _m: None,
        platform=fakes.linux(),
        host=fakes.make_host(home, environ=env),
        tmap=None,
    )
    want = cfg / "skills" / sk.SKILL_DIRNAME / sk.SKILL_FILE
    assert _skill_files(home) == {sk.skill_path(sk.agents_root(home))}  # the shared one only
    assert want.read_bytes() == _shipped()
    assert _ledger(home).committed(sk.entry_id(want)) is not None
    chost = cl.ClientHost(home, env, fakes.linux(), lambda _n: None, fakes.fake_run())
    inp = DoctorInputs(
        platform=fakes.linux(),
        host=fakes.make_host(home, environ=env),
        client_host=chost,
        cfg=None,
        lock=load_lock(),
        tmap=None,
        check_only=True,
    )
    checks = {c.name: (c.state, c.detail) for c in _skill_checks(inp)}
    assert checks["skill.claude"] == ("ok", str(want))
    tm = home / ".treasure-map"
    report = un.uninstall(
        home=home,
        tm_home=tm,
        client_host=chost,
        tmap=None,
        config_path=tm / "config.yaml",
        echo=lambda _m: None,
    )
    assert not report.refused, report.refused
    assert not want.exists()
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(cfg))
    res = _install_r(cfg / "skills")
    assert res.exit_code == 0, res.output
    assert "not in tmap's install ledger" not in res.output
    assert _ledger(home).committed(sk.entry_id(want)) is not None


def test_uninstall_settles_an_interrupted_replacement_first(tmp_path: Path) -> None:
    """★ E-m9: a replacement cut off before the new file moved in leaves a pending entry (new
    sha256, prior = the file still there). Uninstall settles it first, so it removes tmap's file
    instead of calling it "changed since"; the plan it prints agrees, and printing it writes
    nothing.

    MUTATION: drop the recover call from uninstall -> refused "changed since" -> RED; drop it from
    plan_lines only -> the plan says refuse -> RED; let plan_lines settle the real ledger (not a
    copy) -> the ledger file changes -> RED."""
    home = Path.home()
    _init(home, ("claude-code",))
    path = sk.skill_path(sk.claude_root(home, {}))
    ledger = _ledger(home)
    old_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    ledger.add_pending(sk.entry_id(path), "file", path, sha256="0" * 64, prior_sha256=old_sha)
    before = ledger.path.read_bytes()
    lines = un.plan_lines(
        _ledger(home),
        cl.survey(cl.ClientHost(home, {}, fakes.linux(), lambda _n: None, fakes.fake_run()), None),
        toolchain_dir=home / ".treasure-map" / "toolchain",
        home=home,
        environ={},
    )
    assert f"remove {path} ({sk.entry_id(path)})" in lines
    assert ledger.path.read_bytes() == before
    report = _uninstall(home)
    assert not report.refused, report.refused
    assert not path.exists()


# ── CLAUDE_CONFIG_DIR, interrupted writes, the copies outside this run's directories ─────────


def test_cursor_still_gets_the_skill_when_claude_config_dir_is_set(tmp_path: Path) -> None:
    """★ CLAUDE_CONFIG_DIR moves Claude Code's directory to one Cursor does not read (Cursor reads
    only fixed paths under the home). Chosen together, both still get the skill: one in
    $CLAUDE_CONFIG_DIR/skills, one in ~/.agents/skills.

    MUTATION (verified RED, 1 failed): skip Cursor's directory whenever Claude Code or Codex is
    chosen (the old test) -> only $CLAUDE_CONFIG_DIR/skills is written -> RED."""
    home = Path.home()
    cfg = tmp_path / "cfg"
    _init(home, ("claude-code", "cursor"), environ={"CLAUDE_CONFIG_DIR": str(cfg)})
    assert sk.skill_path(cfg / "skills").read_bytes() == _shipped()
    cursor_reads = [home / d / "skills" for d in (".agents", ".cursor", ".claude", ".codex")]
    assert any(sk.skill_path(r).is_file() for r in cursor_reads)
    assert _skill_files(home) == {sk.skill_path(sk.agents_root(home))}


def test_a_copy_in_the_default_claude_directory_stays_tmaps_under_claude_config_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ Installed for Claude Code with CLAUDE_CONFIG_DIR unset (~/.claude/skills), then the
    variable is set. The earlier copy is still one of tmap's: init brings it up to date, the doctor
    reports it on a line of its own, and uninstall takes it back.

    MUTATION (verified RED, 1 failed): drop the default Claude Code directory from named_roots
    while the variable is set -> the copy is neither refreshed nor removable -> RED."""
    home = Path.home()
    _init(home, ("claude-code",))
    default = sk.skill_path(home / ".claude" / "skills")
    assert default.read_bytes() == _shipped()
    env = {"CLAUDE_CONFIG_DIR": str(tmp_path / "cfg")}
    changed = diff_skill.skill_text() + "\nchanged\n"
    monkeypatch.setattr(diff_skill, "skill_text", lambda: changed)
    _init(home, ("claude-code",), environ=env)
    assert default.read_bytes() == changed.encode("utf-8")
    assert _doctor(home, environ=env)["skill.claude.default"] == ("ok", str(default))
    # unset: the named directories, and $CLAUDE_CONFIG_DIR/skills as one the ledger holds a skill
    # for
    custom = "skill." + sk.custom_name(tmp_path / "cfg" / "skills")
    assert set(_doctor(home)) == {"skill.claude", "skill.agents", "skill.dsh", custom}
    report = _uninstall(home, env)
    assert not report.refused, report.refused
    assert not default.exists()


def test_uninstall_without_claude_config_dir_names_the_command_for_a_copy_written_under_it(
    tmp_path: Path,
) -> None:
    """★ Installed with CLAUDE_CONFIG_DIR set, uninstalled without it: $CLAUDE_CONFIG_DIR/skills
    is not one of this run's directories, so the file is kept — and the refusal names the command
    that removes it. Run that way, it is removed.

    MUTATION (verified RED, 1 failed): record no claude_config_dir at install -> RED; give the
    bare "not where tmap installs its skill" refusal even so -> RED (1 failed)."""
    home = Path.home()
    cfg = tmp_path / "cfg"
    env = {"CLAUDE_CONFIG_DIR": str(cfg)}
    _init(home, ("claude-code",), environ=env)
    path = sk.skill_path(cfg / "skills")
    entry = _ledger(home).committed(sk.entry_id(path))
    assert entry is not None and entry.extra.get("claude_config_dir") == str(cfg)
    report = _uninstall(home)
    assert path.read_bytes() == _shipped()
    assert any(
        f"was installed while CLAUDE_CONFIG_DIR={cfg}" in r
        and f"`CLAUDE_CONFIG_DIR={cfg} tmap uninstall`" in r
        for r in report.refused
    ), report.refused
    report = _uninstall(home, env)
    assert not report.refused, report.refused
    assert not path.exists()


def test_the_doctor_settles_an_interrupted_replacement_as_uninstall_does(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ A replacement cut off before the new file moved in leaves a pending entry. The doctor
    reads it settled (the earlier file is still tmap's, so: an earlier version), not as a file
    tmap did not install with a --force command — and writes nothing to the ledger.

    MUTATION (verified RED, 1 failed): drop the settled copy from the doctor's skill checks ->
    "tmap did not install it ... --force" -> RED."""
    home = Path.home()
    _init(home, ("claude-code",))
    path = sk.skill_path(sk.claude_root(home, {}))
    old_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    changed = diff_skill.skill_text() + "\nchanged\n"
    monkeypatch.setattr(diff_skill, "skill_text", lambda: changed)
    ledger = _ledger(home)
    new_sha = hashlib.sha256(changed.encode("utf-8")).hexdigest()
    ledger.add_pending(sk.entry_id(path), "file", path, sha256=new_sha, prior_sha256=old_sha)
    before = ledger.path.read_bytes()
    state, detail = _doctor(home)["skill.claude"]
    assert "tmap did not install it" not in detail and "--force" not in detail
    assert state == "warn" and "earlier version" in detail
    assert ledger.path.read_bytes() == before


def test_an_earlier_version_outside_this_runs_directories_is_replaced_too(
    tmp_path: Path, newer: bytes
) -> None:
    """★ An earlier tmap's text, installed by hand in ~/.dsh/skills (never recorded); init then
    runs for Claude Code alone, which does not write ~/.dsh. That copy — which dsh prefers to
    ~/.agents/skills — is replaced and recorded, as the doctor said it would be. The text is one
    shipped after the ledger recorded skills, so only the named directory finds it.

    MUTATION (verified RED, 1 failed): replace only stale copies outside this run's directories
    (not earlier versions) -> the ~/.dsh copy keeps the old text -> RED. MUTATION: leave dsh out
    of named_roots -> RED."""
    home = tmp_path / "h"
    agents = sk.skill_path(sk.dsh_root(home, {}))
    agents.parent.mkdir(parents=True)
    old = (_FIXTURES / "legacy_diff_review_3387.md").read_bytes()
    agents.write_bytes(old)
    assert _ledger(home).find(sk.entry_id(agents)) is None
    state, detail = _doctor(home)["skill.dsh"]
    assert state == "warn" and detail.endswith("; `tmap init` replaces it")
    _init(home, ("claude-code",))
    assert agents.read_bytes() == newer
    assert _ledger(home).committed(sk.entry_id(agents)) is not None
    missing = sk.skill_path(sk.dsh_root(tmp_path / "h2", {}))
    _init(tmp_path / "h2", ("claude-code",))
    assert not missing.parent.exists()  # nothing is created where there was no copy


def test_an_interrupted_first_install_leaves_no_empty_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """★ The first write for Codex is cut off after it made ~/.agents/skills/tmap-diff-review but
    before the file moved in. The pending entry records those directories; once it is settled
    (here by uninstall) they go, each only because it is empty. The doctor, reading the settled
    state on a copy, removes nothing.

    MUTATION (verified RED, 1 failed): drop the directory pruning from recover's discard branch ->
    ~/.agents stays -> RED. MUTATION (verified RED, 1 failed): let the doctor's settled copy prune
    -> the directories vanish at the doctor -> RED."""
    home = Path.home()

    class _Os:  # os as skills.py sees it, its replace cut off (the ledger's own save untouched)
        def __getattr__(self, name: str) -> object:
            return getattr(os, name)

        def replace(self, _a: object, _b: object) -> None:
            raise KeyboardInterrupt

    monkeypatch.setattr(sk, "os", _Os())
    with pytest.raises(KeyboardInterrupt):
        _init(home, ("codex",))
    monkeypatch.undo()
    path = sk.skill_path(sk.agents_root(home))
    assert path.parent.is_dir() and not path.exists()
    _doctor(home)
    assert path.parent.is_dir()  # the doctor changes nothing on disk
    report = _uninstall(home)
    assert not report.refused, report.refused
    assert not (home / ".agents").exists()


def test_review_skill_install_does_not_offer_force_for_a_linked_directory(tmp_path: Path) -> None:
    """★ Without --force, a ``tmap-diff-review`` directory that is a link is refused with the step
    that works (change the link) — not "--force replaces it", which --force would refuse too.

    MUTATION (verified RED, 1 failed): give the foreign refusal "(--force replaces it)" again ->
    RED."""
    root = sk.claude_root(Path.home(), {})
    theirs = tmp_path / "dot" / sk.SKILL_DIRNAME
    theirs.mkdir(parents=True)
    (theirs / sk.SKILL_FILE).write_bytes(b"mine\n")
    root.mkdir(parents=True)
    (root / sk.SKILL_DIRNAME).symlink_to(theirs, target_is_directory=True)
    res = _install_r(root)
    assert res.exit_code != 0
    assert "--force replaces it" not in res.output, res.output
    assert f"{root / sk.SKILL_DIRNAME} is a link; remove or replace it first" in res.output
    assert (theirs / sk.SKILL_FILE).read_bytes() == b"mine\n"


def test_force_into_an_unmanaged_directory_does_not_write_through_a_link(tmp_path: Path) -> None:
    """A directory tmap does not manage (written unrecorded) whose ``tmap-diff-review`` is a link:
    --force refuses, naming where the link points, and the file there is untouched.

    MUTATION (verified RED, 1 failed): drop the linked-directory refusal from write_plain -> the
    user's file is overwritten -> RED."""
    root = tmp_path / "custom"
    theirs = tmp_path / "dot" / sk.SKILL_DIRNAME
    theirs.mkdir(parents=True)
    (theirs / sk.SKILL_FILE).write_bytes(b"mine\n")
    root.mkdir()
    (root / sk.SKILL_DIRNAME).symlink_to(theirs, target_is_directory=True)
    res = _install_r(root, "--force")
    assert res.exit_code != 0 and f"symbolic link to {theirs}" in res.output
    assert (theirs / sk.SKILL_FILE).read_bytes() == b"mine\n"


def test_a_recorded_directory_that_is_not_above_the_skill_is_never_removed(
    tmp_path: Path,
) -> None:
    """A ``created_dirs`` entry that is not one of the skill file's parents (an empty directory of
    the user's) is ignored by uninstall.

    MUTATION (verified RED, 1 failed): take every recorded directory, parent or not -> the user's
    empty directory is removed -> RED."""
    home = Path.home()
    _init(home, ("codex",))
    unrelated = home / "empty-but-mine"
    unrelated.mkdir()
    ledger = _ledger(home)
    entry = ledger.find(sk.entry_id(sk.skill_path(sk.agents_root(home))))
    assert entry is not None
    entry.extra["created_dirs"] = [*entry.extra["created_dirs"], str(unrelated)]
    ledger.save()
    report = _uninstall(home)
    assert not report.refused, report.refused
    assert unrelated.is_dir()


def test_the_created_directories_survive_a_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The directories the first write created are kept in the record when a later init replaces
    the file (that write creates none), so uninstall still takes them away.

    MUTATION (verified RED, 1 failed): record only the directories the latest write created ->
    ~/.agents stays after uninstall -> RED."""
    home = Path.home()
    _init(home, ("codex",))
    changed = diff_skill.skill_text() + "\nchanged\n"
    monkeypatch.setattr(diff_skill, "skill_text", lambda: changed)
    _init(home, ("codex",))
    assert sk.skill_path(sk.agents_root(home)).read_bytes() == changed.encode("utf-8")
    report = _uninstall(home)
    assert not report.refused, report.refused
    assert not (home / ".agents").exists()
