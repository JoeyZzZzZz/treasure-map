# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The diff-review skill on disk: one write per shared skills directory, only tmap's own file is
ever rewritten, every write goes through the ledger, and uninstall takes back exactly that."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from pathlib import Path

import pytest
from click.testing import CliRunner

from treasure_map.cli import review_cli
from treasure_map.lib.setup import clients as cl
from treasure_map.lib.setup import skills as sk
from treasure_map.lib.setup import uninstall as un
from treasure_map.lib.setup.doctor import DoctorInputs, _skill_checks
from treasure_map.lib.setup.initializer import InitResult, run_init
from treasure_map.lib.setup.ledger import LEDGER_NAME, Ledger
from treasure_map.lib.setup.toolchain_lock import load_lock

from . import fakes

_LEGACY = Path(__file__).parents[3] / "fixtures" / "skills" / "legacy_diff_review_3144.md"


def _shipped() -> bytes:
    return review_cli.skill_text().encode("utf-8")


@pytest.fixture()
def newer(monkeypatch: pytest.MonkeyPatch) -> bytes:
    """A shipped skill that is none of the earlier versions (the real one may still equal one)."""
    text = review_cli.skill_text() + "\nA newer line.\n"
    monkeypatch.setattr(review_cli, "skill_text", lambda: text)
    return text.encode("utf-8")


def _ledger(home: Path) -> Ledger:
    return Ledger.load(home / ".treasure-map" / "toolchain" / LEDGER_NAME)


def _init(home: Path, clients: Sequence[str], echo: list[str] | None = None) -> InitResult:
    return run_init(
        non_interactive=True,
        clients=clients,
        prompt=lambda _m: "",
        echo=(echo.append if echo is not None else lambda _m: None),
        platform=fakes.linux(),
        host=fakes.make_host(home),
        tmap=None,
    )


def _skill_files(home: Path) -> set[Path]:
    return {p for p in home.rglob(sk.SKILL_FILE) if ".treasure-map" not in p.parts}


def _uninstall(home: Path) -> un.UninstallReport:
    tm = home / ".treasure-map"
    return un.uninstall(
        home=home,
        tm_home=tm,
        client_host=cl.ClientHost(home, {}, fakes.linux(), lambda _n: None, fakes.fake_run()),
        tmap=None,
        config_path=tm / "config.yaml",
        echo=lambda _m: None,
    )


def _doctor(home: Path, requested: Sequence[str] = ()) -> dict[str, tuple[str, str]]:
    inp = DoctorInputs(
        platform=fakes.linux(),
        host=fakes.make_host(home),
        client_host=cl.ClientHost(home, {}, fakes.linux(), lambda _n: None, fakes.fake_run()),
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
        (("claude-code", "cursor"), (".claude",)),
        (("codex", "cursor"), (".agents",)),
        (("claude-desktop", "dsh"), ()),
    ],
    ids=["cc_codex_cursor", "cursor_alone", "cc_cursor", "codex_cursor", "desktop_dsh"],
)
def test_each_shared_skills_directory_is_written_once(
    tmp_path: Path, clients: tuple[str, ...], roots: tuple[str, ...]
) -> None:
    """★ The directories come from the agents chosen in this run, each once: Cursor reads the
    Claude Code and Codex directories, so it adds one only when neither was chosen.

    MUTATION: drop Cursor's "neither was chosen" test -> cc_cursor writes two -> RED; Codex into
    ~/.codex/skills -> RED."""
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


def test_claude_desktop_and_dsh_get_steps_to_follow_and_no_file(tmp_path: Path) -> None:
    """MUTATION: give Claude Desktop the ~/.claude/skills directory -> a file is written -> RED;
    drop the printed steps -> RED."""
    home = tmp_path / "h"
    echo: list[str] = []
    _init(home, ("claude-desktop", "dsh"), echo)
    assert _skill_files(home) == set()
    assert any("Claude Desktop: tmap does not install agent skills" in ln for ln in echo)
    assert any("dsh: tmap does not know whether dsh loads agent skills" in ln for ln in echo)


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
    path = sk.skill_path(sk.claude_root(home))
    path.parent.mkdir(parents=True)
    mine = b"---\nname: tmap-diff-review\ndescription: my own\n---\nmine\n"
    path.write_bytes(mine)
    result = _init(home, ("claude-code",))
    assert path.read_bytes() == mine
    assert _ledger(home).find(sk.entry_id(path)) is None
    cmd = f"tmap review skill --install {sk.claude_root(home)} --force"
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


def test_a_hand_installed_earlier_version_is_replaced_and_recorded(
    tmp_path: Path, newer: bytes
) -> None:
    """★ Byte for byte the skill an earlier tmap shipped (put there by `tmap review skill
    --install` before the ledger knew skills): replaced, and recorded from then on.

    MUTATION: drop the earlier-version hashes -> foreign -> left -> RED."""
    old = _LEGACY.read_bytes()
    assert len(old) == 3144 and hashlib.sha256(old).hexdigest() in sk.LEGACY_SHA256
    home = tmp_path / "h"
    path = sk.skill_path(sk.claude_root(home))
    path.parent.mkdir(parents=True)
    path.write_bytes(old)
    assert _doctor(home)["skill.claude"][0] == "warn"
    _init(home, ("claude-code",))
    assert path.read_bytes() == newer == _shipped()
    entry = _ledger(home).committed(sk.entry_id(path))
    assert entry is not None and entry.extra["sha256"] == hashlib.sha256(newer).hexdigest()


def test_an_edited_copy_of_an_earlier_version_is_foreign(tmp_path: Path, newer: bytes) -> None:
    """One character changed: no longer a version tmap shipped, so not tmap's to replace.

    MUTATION: recognise an earlier version by its name instead of its hash -> replaced -> RED."""
    edited = _LEGACY.read_bytes().replace(b"unit by unit", b"unit by Unit", 1)
    assert edited != _LEGACY.read_bytes()
    home = tmp_path / "h"
    path = sk.skill_path(sk.claude_root(home))
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
    changed = review_cli.skill_text() + "\nchanged\n"
    monkeypatch.setattr(review_cli, "skill_text", lambda: changed)
    state, detail = _doctor(home)["skill.claude"]
    assert state == "warn" and "earlier version" in detail
    _init(home, ("claude-code",))
    path = sk.skill_path(sk.claude_root(home))
    assert path.read_bytes() == changed.encode("utf-8")
    entry = _ledger(home).committed(sk.entry_id(path))
    assert entry is not None
    assert entry.extra == {"sha256": hashlib.sha256(changed.encode("utf-8")).hexdigest()}


def test_the_doctor_reports_one_line_per_skills_directory(tmp_path: Path) -> None:
    """MUTATION: a requested directory without the skill as info -> RED; an unreadable SKILL.md as
    ok/warn -> RED."""
    home = tmp_path / "h"
    assert {k: v[0] for k, v in _doctor(home).items()} == {
        "skill.claude": "info",
        "skill.agents": "info",
    }
    assert _doctor(home, ("cursor",))["skill.agents"][0] == "missing"
    _init(home, ("cursor",))
    assert _doctor(home, ("cursor",))["skill.agents"][0] == "ok"
    sk.skill_path(sk.claude_root(home)).mkdir(parents=True)  # a directory named SKILL.md
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
    for root in sk.known_roots(home):
        assert not (root / sk.SKILL_DIRNAME).exists()
    assert not (home / ".treasure-map" / "toolchain" / LEDGER_NAME).exists()


def test_uninstall_keeps_a_skill_edited_since_and_lists_it(tmp_path: Path) -> None:
    """★ One character changed after tmap wrote it: kept, and listed as refused.

    MUTATION: drop the sha256 comparison -> removed -> RED."""
    home = Path.home()
    _init(home, ("claude-code",))
    path = sk.skill_path(sk.claude_root(home))
    edited = path.read_bytes().replace(b"tmap", b"Tmap", 1)
    path.write_bytes(edited)
    ledger = _ledger(home)
    lines = un.plan_lines(
        ledger,
        cl.survey(cl.ClientHost(home, {}, fakes.linux(), lambda _n: None, fakes.fake_run()), None),
        toolchain_dir=home / ".treasure-map" / "toolchain",
        home=home,
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
    root = sk.claude_root(home)
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


def test_review_skill_install_elsewhere_is_not_recorded(tmp_path: Path, newer: bytes) -> None:
    """A directory tmap does not manage: written, never recorded (uninstall could not take it
    back); an earlier shipped version there is still replaced without --force.

    MUTATION: record it -> RED."""
    root = tmp_path / "skills"
    path = sk.skill_path(root)
    path.parent.mkdir(parents=True)
    path.write_bytes(_LEGACY.read_bytes())
    res = _install(root)
    assert res.exit_code == 0, res.output  # type: ignore[attr-defined]
    assert path.read_bytes() == newer
    assert _ledger(Path.home()).find(sk.entry_id(path)) is None
