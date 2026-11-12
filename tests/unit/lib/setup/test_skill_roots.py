# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Which skills directories tmap writes and manages: ~/.agents/skills for every run, dsh's own
directory, every directory `tmap review skill --install` was pointed at (recorded with its root),
and every text an earlier tmap shipped recognised wherever it is found."""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest
from click.testing import CliRunner, Result

from treasure_map.cli import review_cli
from treasure_map.lib.query import diff_skill
from treasure_map.lib.setup import clients as cl
from treasure_map.lib.setup import skills as sk
from treasure_map.lib.setup.initializer import run_init
from treasure_map.lib.setup.ledger import Entry, Ledger

from . import fakes
from .test_skills import _doctor, _init, _ledger, _uninstall

_FIXTURES = Path(__file__).parents[3] / "fixtures" / "skills"
_V3126 = _FIXTURES / "legacy_diff_review_3126.md"
_V3387 = _FIXTURES / "legacy_diff_review_3387.md"
_V3741 = _FIXTURES / "legacy_diff_review_3741.md"
_V4658 = _FIXTURES / "legacy_diff_review_4658.md"
_V4727 = _FIXTURES / "legacy_diff_review_4727.md"
_V5107 = _FIXTURES / "legacy_diff_review_5107.md"
_SRC = Path(__file__).parents[4] / "src"

# The text this tmap ships. Changing it means adding this value to LEGACY_SHA256 and the new one
# here.
SHIPPED_SHA256 = "50d0557f8e7a285e94f28dea60789baaaf03471f0064688aa7cc94f1d841de7b"


@pytest.fixture()
def newer(monkeypatch: pytest.MonkeyPatch) -> bytes:
    text = diff_skill.skill_text() + "\nA newer line.\n"
    monkeypatch.setattr(diff_skill, "skill_text", lambda: text)
    return text.encode("utf-8")


def _install(root: str | Path, *extra: str) -> Result:
    return CliRunner().invoke(review_cli.review, ["skill", "--install", str(root), *extra])


def _plan(
    home: Path, clients: Sequence[str], environ: Mapping[str, str] | None = None
) -> list[str]:
    """The skill lines of a dry run's full plan."""
    echo: list[str] = []
    run_init(
        dry_run=True,
        non_interactive=True,
        clients=clients,
        prompt=lambda _m: "",
        echo=echo.append,
        platform=fakes.linux(),
        host=fakes.make_host(home, environ=environ),
        tmap=None,
    )
    return [ln for ln in "\n".join(echo).splitlines() if "diff-review skill" in ln]


def _host(home: Path, environ: Mapping[str, str]) -> cl.ClientHost:
    return cl.ClientHost(home, dict(environ), fakes.linux(), lambda _n: None, fakes.fake_run())


def _record(ledger: Ledger, path: Path, data: bytes, **extra: object) -> None:
    ledger.add_pending(sk.entry_id(path), "file", path, sha256=sk.sha256_of(data), **extra)
    ledger.commit(sk.entry_id(path))


# ── ~/.agents/skills for every run ───────────────────────────────────────────────────────────


def test_claude_code_alone_writes_the_shared_agents_directory_too(tmp_path: Path) -> None:
    """MUTATION: add ~/.agents/skills only when Codex or Cursor is chosen -> RED."""
    home = tmp_path / "h"
    target = sk.skill_path(sk.agents_root(home))
    assert any(f"→ {target}" in ln and "install" in ln for ln in _plan(home, ["claude-code"]))


def test_the_shared_directory_is_planned_once(tmp_path: Path) -> None:
    """Also when dsh's agents directory is the shared one.

    MUTATION: drop the de-duplication in target_roots -> two actions -> RED."""
    home = tmp_path / "h"
    target = sk.skill_path(sk.agents_root(home))
    assert sum(f"→ {target}" in ln for ln in _plan(home, ["codex", "cursor"])) == 1
    env = {"DSH_AGENTS_HOME": str(home / ".agents")}
    assert sum(f"→ {target}" in ln for ln in _plan(home, ["codex", "dsh"], env)) == 1


def test_no_agent_chosen_writes_no_skill(tmp_path: Path) -> None:
    """MUTATION: add ~/.agents/skills even when nothing is chosen -> RED."""
    home = tmp_path / "h"
    assert sk.target_roots([], home, {}) == []
    assert _plan(home, []) == []


@pytest.mark.parametrize(
    ("chosen", "want"),
    [
        (["claude-code"], {".claude", ".agents"}),
        (["codex"], {".agents"}),
        (["cursor"], {".agents"}),
        (["dsh"], {".dsh", ".agents"}),
        (["claude-desktop"], {".agents"}),
        ([], set()),
    ],
    ids=["claude-code", "codex", "cursor", "dsh", "claude-desktop", "none"],
)
def test_each_agent_alone_writes_these_directories(
    tmp_path: Path, chosen: list[str], want: set[str]
) -> None:
    """MUTATION: dsh gets only ~/.agents/skills -> RED; Claude Code without ~/.agents -> RED."""
    home = tmp_path / "h"
    assert set(sk.target_roots(chosen, home, {})) == {home / d / "skills" for d in want}


def test_the_plan_names_the_shared_directory_by_its_full_path_and_says_it_is_shared(
    tmp_path: Path,
) -> None:
    """MUTATION: drop the note on the shared directory -> RED; name the directory relative to the
    home -> RED."""
    home = tmp_path / "h"
    lines = [ln for ln in _plan(home, ["claude-code"]) if "/.agents/" in ln]
    assert len(lines) == 1
    assert f"in {sk.agents_root(home)} — a directory shared between agents" in lines[0]
    assert sk.agents_root(home).is_absolute()


# ── dsh ──────────────────────────────────────────────────────────────────────────────────────


def test_dsh_gets_its_own_directory_and_the_shared_one(tmp_path: Path) -> None:
    """MUTATION: keep dsh as a hand-only agent (no directory) -> RED."""
    home = tmp_path / "h"
    lines = _plan(home, ["dsh"])
    for root in (home / ".dsh" / "skills", home / ".agents" / "skills"):
        assert any(f"→ {sk.skill_path(root)}" in ln for ln in lines), lines
    assert len([ln for ln in lines if "→" in ln]) == 2


def test_dsh_is_no_longer_told_to_do_it_by_hand(tmp_path: Path) -> None:
    """MUTATION: keep dsh in MANUAL -> RED."""
    home = tmp_path / "h"
    echo: list[str] = []
    _init(home, ("dsh",), echo)
    assert "dsh" not in sk.MANUAL
    assert not any("dsh:" in ln and "agent skills" in ln for ln in echo)
    assert sk.skill_path(sk.dsh_root(home, {})).read_bytes() == sk.shipped_bytes()


def test_dsh_home_moves_its_directory(tmp_path: Path) -> None:
    """MUTATION: ignore $DSH_HOME -> RED."""
    home = tmp_path / "h"
    env = {"DSH_HOME": str(tmp_path / "x")}
    assert tmp_path / "x" / "skills" in sk.target_roots(["dsh"], home, env)
    _init(home, ("dsh",), environ=env)
    assert sk.skill_path(tmp_path / "x" / "skills").read_bytes() == sk.shipped_bytes()


def test_a_blank_dsh_home_is_unset(tmp_path: Path) -> None:
    """MUTATION: read $DSH_HOME without stripping it -> RED."""
    home = tmp_path / "h"
    assert sk.target_roots(["dsh"], home, {"DSH_HOME": "   "}) == [
        home / ".agents" / "skills",
        home / ".dsh" / "skills",
    ]


def test_dsh_agents_home_adds_its_directory_only_when_set_and_dsh_is_chosen(
    tmp_path: Path,
) -> None:
    """MUTATION: always add a second agents directory for dsh -> RED."""
    home = tmp_path / "h"
    env = {"DSH_AGENTS_HOME": str(tmp_path / "y")}
    assert tmp_path / "y" / "skills" in sk.target_roots(["dsh"], home, env)
    assert set(sk.target_roots(["dsh"], home, {})) == {
        home / ".dsh" / "skills",
        home / ".agents" / "skills",
    }
    assert tmp_path / "y" / "skills" not in sk.target_roots(["codex"], home, env)


@pytest.mark.parametrize(
    ("value", "want"),
    [(None, ".dsh"), ("", ".dsh"), ("   ", ".dsh"), ("~", ""), ("~/x", "x"), ("/abs/p", None)],
    ids=["unset", "empty", "blank", "tilde", "tilde_x", "absolute"],
)
def test_the_mcp_layer_and_the_skills_directory_read_dsh_home_alike(
    tmp_path: Path, value: str | None, want: str | None
) -> None:
    """MUTATION: a second $DSH_HOME reading in skills.py that does not expand ``~`` -> tilde and
    tilde_x -> RED."""
    home = tmp_path / "h"
    env = {} if value is None else {"DSH_HOME": value}
    expected = Path("/abs/p") if want is None else (home / want if want else home)
    assert cl.dsh_home(_host(home, env)) == expected
    assert sk.dsh_root(home, env) == expected / "skills"


def test_dsh_home_is_read_in_one_place() -> None:
    """MUTATION: read $DSH_HOME a second time anywhere under src/ (even correctly) -> RED."""
    hits = [
        (p.relative_to(_SRC), n)
        for p in sorted(_SRC.rglob("*.py"))
        for n in [len(re.findall(r"""["']DSH_HOME["']""", p.read_text(encoding="utf-8")))]
        if n
    ]
    assert hits == [(Path("treasure_map/lib/setup/clients.py"), 1)]


@pytest.mark.parametrize(
    "module", ["treasure_map.lib.setup.clients", "treasure_map.lib.setup.uninstall"]
)
def test_the_setup_modules_import_on_their_own(module: str) -> None:
    """skills imports clients, never the other way round.

    MUTATION: put the $DSH_HOME rule in skills.py and have clients import it -> ImportError ->
    RED."""
    done = subprocess.run(
        [sys.executable, "-c", f"import {module}"], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr


# ── ~/.dsh/skills is one of tmap's directories ───────────────────────────────────────────────


def test_dsh_is_a_named_directory(tmp_path: Path) -> None:
    """MUTATION: dsh's directory only in target_roots, not named_roots -> RED."""
    home = tmp_path / "h"
    named = dict(sk.named_roots(home, {}))
    assert named["dsh"] == sk.dsh_root(home, {})


def test_the_default_dsh_directory_stays_named_while_dsh_home_moves_it(tmp_path: Path) -> None:
    """MUTATION: always add dsh.default -> the unset case has it -> RED."""
    home = tmp_path / "h"
    moved = dict(sk.named_roots(home, {"DSH_HOME": str(tmp_path / "x")}))
    assert moved["dsh"] == tmp_path / "x" / "skills"
    assert moved["dsh.default"] == home / ".dsh" / "skills"
    names = [n for n, _r in sk.named_roots(home, {})]
    assert names.count("dsh") == 1 and "dsh.default" not in names
    paths = [r for _n, r in sk.named_roots(home, {})]
    assert len(paths) == len(set(paths))
    agents = dict(sk.named_roots(home, {"DSH_AGENTS_HOME": str(tmp_path / "y")}))
    assert agents["dsh.agents"] == tmp_path / "y" / "skills"


# ── every --install is recorded, with its root ───────────────────────────────────────────────


def test_there_is_one_way_to_write_the_skill() -> None:
    """MUTATION: keep write_plain -> RED."""
    assert not hasattr(sk, "write_plain")
    assert not [p for p in _SRC.rglob("*.py") if "write_plain" in p.read_text(encoding="utf-8")]


def test_an_entry_without_a_root_still_reads_and_a_root_survives_a_round_trip() -> None:
    """MUTATION: make ``root`` a required key -> the older entry no longer reads -> RED."""
    old = {"id": "skill:/a/tmap-diff-review/SKILL.md", "state": "committed", "kind": "file"}
    old["path"] = "/a/tmap-diff-review/SKILL.md"
    e = Entry.from_json({**old, "sha256": "0" * 64})
    assert "root" not in e.extra
    new = Entry.from_json({**old, "sha256": "0" * 64, "root": "/a"})
    assert Entry.from_json(new.to_json()).extra["root"] == "/a"


def test_a_root_that_is_not_the_files_directory_lets_nothing_be_removed(tmp_path: Path) -> None:
    """In a directory tmap does not otherwise manage, ``root`` counts only as the very directory
    the file is in.

    MUTATION: accept any string ``root`` -> removed -> RED."""
    home = tmp_path / "h"
    path = sk.skill_path(tmp_path / "custom")
    path.parent.mkdir(parents=True)
    path.write_bytes(b"x")
    sha = sk.sha256_of(b"x")
    why = sk.removable(path, sha, home, {}, recorded_root=str(tmp_path / "elsewhere"))
    assert why is not None and "not where tmap installs its skill" in why
    assert sk.removable(path, sha, home, {}, recorded_root=str(tmp_path / "custom")) is None


def test_a_project_directory_once_installed_into_is_kept_current_and_named_in_full(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION: init does not read the directories the ledger holds a skill for -> no update ->
    RED."""
    home = Path.home()
    proj = tmp_path / "proj" / ".agents" / "skills"
    assert _install(proj).exit_code == 0
    changed = diff_skill.skill_text() + "\nchanged\n"
    monkeypatch.setattr(diff_skill, "skill_text", lambda: changed)
    lines = _plan(home, ["claude-code"])
    assert any(f"update the diff-review skill tmap installed in {proj}" in ln for ln in lines)
    _init(home, ("claude-code",))
    assert sk.skill_path(proj).read_bytes() == changed.encode("utf-8")


# ── uninstall takes back a recorded directory ────────────────────────────────────────────────


def test_uninstall_takes_back_an_install_into_any_directory(tmp_path: Path) -> None:
    """MUTATION: removable accepts known_roots only -> refused -> RED."""
    home = Path.home()
    root = tmp_path / "new" / "skills"
    assert _install(root).exit_code == 0
    assert sk.skill_path(root).is_file()
    report = _uninstall(home)
    assert not report.refused, report.refused
    assert not (tmp_path / "new").exists()


def test_uninstall_keeps_a_recorded_file_changed_since(tmp_path: Path) -> None:
    """MUTATION: let ``root`` stand in for the sha256 comparison -> removed -> RED."""
    home = Path.home()
    root = tmp_path / "skills"
    assert _install(root).exit_code == 0
    path = sk.skill_path(root)
    path.write_bytes(path.read_bytes() + b"!")
    report = _uninstall(home)
    assert path.is_file()
    assert f"{path} changed since tmap installed it; not removed" in report.refused


def test_a_root_does_not_widen_the_shape_test(tmp_path: Path) -> None:
    """MUTATION: fold the shape test into the ``or`` with ``root`` -> removed -> RED."""
    home = tmp_path / "h"
    path = tmp_path / "custom" / "not-tmap" / sk.SKILL_FILE
    path.parent.mkdir(parents=True)
    path.write_bytes(b"x")
    why = sk.removable(path, sk.sha256_of(b"x"), home, {}, recorded_root=str(tmp_path / "custom"))
    assert why is not None and "not where tmap installs its skill" in why


def test_a_root_does_not_widen_the_link_test(tmp_path: Path) -> None:
    """MUTATION: skip the linked-directory refusal on a recorded root -> written / removed ->
    RED."""
    home = tmp_path / "h"
    root = tmp_path / "custom"
    theirs = tmp_path / "theirs"
    theirs.mkdir()
    (theirs / sk.SKILL_FILE).write_bytes(b"x")
    root.mkdir()
    (root / sk.SKILL_DIRNAME).symlink_to(theirs, target_is_directory=True)
    path = sk.skill_path(root)
    with pytest.raises(sk.SkillWriteError):
        sk.install(path, b"y", Ledger(tmp_path / "l.json"))
    why = sk.removable(path, sk.sha256_of(b"x"), home, {}, recorded_root=str(root))
    assert why == f"{path} is a symbolic link; not removed"
    assert (theirs / sk.SKILL_FILE).read_bytes() == b"x"


def test_a_copy_written_under_claude_config_dir_is_refused_without_it_even_with_a_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The CLAUDE_CONFIG_DIR refusal comes before the directory test, so a ``root`` that makes
    the directory tmap's does not skip it.

    MUTATION: leave the refusal inside the failed-directory branch -> removed without the
    variable -> RED."""
    home = Path.home()
    cfg = tmp_path / "cc"
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(cfg))
    assert _install(cfg / "skills").exit_code == 0
    path = sk.skill_path(cfg / "skills")
    entry = _ledger(home).committed(sk.entry_id(path))
    assert entry is not None and entry.extra["claude_config_dir"] == str(cfg)
    assert entry.extra["root"] == str(cfg / "skills")
    monkeypatch.delenv("CLAUDE_CONFIG_DIR")
    report = _uninstall(home)
    assert path.is_file()
    assert any(f"`CLAUDE_CONFIG_DIR={cfg} tmap uninstall`" in r for r in report.refused)
    report = _uninstall(home, {"CLAUDE_CONFIG_DIR": str(cfg)})
    assert not report.refused, report.refused
    assert not path.exists()


def test_a_custom_root_is_removable_with_its_root_and_not_without(tmp_path: Path) -> None:
    home = tmp_path / "h"
    path = sk.skill_path(tmp_path / "custom")
    path.parent.mkdir(parents=True)
    path.write_bytes(b"x")
    sha = sk.sha256_of(b"x")
    assert sk.removable(path, sha, home, {}, recorded_root=str(tmp_path / "custom")) is None
    why = sk.removable(path, sha, home, {})
    assert why is not None and "not where tmap installs its skill" in why


@pytest.mark.parametrize("where", ["claude", "agents", "dsh"])
def test_an_entry_without_claude_config_dir_is_judged_as_before(tmp_path: Path, where: str) -> None:
    """MUTATION: refuse at the CLAUDE_CONFIG_DIR step when the entry has no such key -> RED."""
    home = tmp_path / "h"
    path = sk.skill_path(dict(sk.named_roots(home, {}))[where])
    path.parent.mkdir(parents=True)
    path.write_bytes(b"x")
    assert sk.removable(path, sk.sha256_of(b"x"), home, {}) is None
    assert sk.removable(path, sk.sha256_of(b"x"), home, {"CLAUDE_CONFIG_DIR": "/c"}) is None


# ── the directories the ledger holds a skill for ────────────────────────────────────────────


def test_the_doctor_reports_a_recorded_directory_under_a_name_from_its_path(
    tmp_path: Path,
) -> None:
    """MUTATION: the doctor reads named_roots only -> no line -> RED."""
    home = Path.home()
    root = tmp_path / "skills"
    assert _install(root).exit_code == 0
    checks = _doctor(home)
    name = "skill." + sk.custom_name(root)
    assert re.fullmatch(r"skill\.custom\.[0-9a-f]{8}", name)
    assert checks[name] == ("ok", str(sk.skill_path(root)))


def test_a_pending_entry_names_its_directory(tmp_path: Path) -> None:
    """MUTATION: read committed entries only -> RED."""
    ledger = Ledger(tmp_path / "l.json")
    path = sk.skill_path(tmp_path / "skills")
    ledger.add_pending(sk.entry_id(path), "file", path, sha256="0" * 64)
    assert sk.recorded_roots(ledger) == (tmp_path / "skills",)


def test_a_recorded_directory_is_brought_up_to_date(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION: init's directories are known_roots (not the ledger's too) -> left -> RED."""
    home = Path.home()
    root = tmp_path / "skills"
    assert _install(root).exit_code == 0
    changed = diff_skill.skill_text() + "\nchanged\n"
    monkeypatch.setattr(diff_skill, "skill_text", lambda: changed)
    state, detail = _doctor(home)["skill." + sk.custom_name(root)]
    assert state == "warn" and "earlier version" in detail
    _init(home, ("codex",))
    assert sk.skill_path(root).read_bytes() == changed.encode("utf-8")


@pytest.mark.parametrize(
    "rel", ["x/y/SKILL.md", "x/tmap-diff-review/README.md", "x/other/SKILL.md"]
)
def test_only_a_skill_shaped_path_names_a_directory(tmp_path: Path, rel: str) -> None:
    """MUTATION: take any entry's grandparent -> RED."""
    ledger = Ledger(tmp_path / "l.json")
    _record(ledger, tmp_path / rel, b"x")
    assert sk.recorded_roots(ledger) == ()


def test_the_short_name_comes_from_the_path_alone(tmp_path: Path) -> None:
    """MUTATION: number the recorded directories in path order -> P2's name moves -> RED."""
    home = tmp_path / "h"
    p1, p2 = tmp_path / "a" / "skills", tmp_path / "b" / "skills"
    want = "custom." + hashlib.sha256(str(p2).encode("utf-8")).hexdigest()[:8]
    ledger = Ledger(tmp_path / "l.json")
    _record(ledger, sk.skill_path(p2), b"x")
    assert dict((r, n) for n, r in sk.managed_roots(home, {}, ledger))[p2] == want
    _record(ledger, sk.skill_path(p1), b"x")
    names = dict((r, n) for n, r in sk.managed_roots(home, {}, ledger))
    assert names[p2] == want and names[p1] != want


def test_a_recorded_directory_never_makes_a_foreign_file_tmaps(
    tmp_path: Path, newer: bytes
) -> None:
    """MUTATION: plan a replacement for whatever is in a managed directory -> planned -> RED (the
    write itself is refused again when init looks a second time)."""
    home = Path.home()
    root = tmp_path / "skills"
    assert _install(root).exit_code == 0
    path = sk.skill_path(root)
    path.write_bytes(b"---\nname: tmap-diff-review\ndescription: mine\n---\nmine\n")
    state, detail = _doctor(home)["skill." + sk.custom_name(root)]
    assert state == "warn" and "changed since tmap installed it" in detail
    assert not any(f"→ {path}" in ln for ln in _plan(home, ["codex"]))  # not even planned
    _init(home, ("codex",))
    assert path.read_bytes().endswith(b"mine\n")
    res = _install(root)
    assert res.exit_code != 0 and "--force" in res.output
    assert path.read_bytes().endswith(b"mine\n")


def test_a_relative_entry_names_no_directory_from_any_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, newer: bytes
) -> None:
    """A relative path an earlier CLI recorded: init and the doctor leave the same relative path
    under another working directory alone.

    MUTATION: take relative entries too -> init replaces the file under the new working directory
    -> RED."""
    home = Path.home()
    rel = Path("rel") / "skills" / sk.SKILL_DIRNAME / sk.SKILL_FILE
    old = b"an earlier text tmap wrote\n"
    _record(_ledger(home), rel, old)
    assert sk.recorded_roots(_ledger(home)) == ()
    elsewhere = tmp_path / "cwd"
    (elsewhere / rel).parent.mkdir(parents=True)
    (elsewhere / rel).write_bytes(old)
    monkeypatch.chdir(elsewhere)
    _doctor(home)
    _init(home, ("codex",))
    assert (elsewhere / rel).read_bytes() == old


def test_a_recorded_file_that_is_gone_is_info_and_its_record_kept(tmp_path: Path) -> None:
    """MUTATION: report it as missing -> RED; init drops the entry -> the created directories
    are no longer taken back -> RED."""
    home = Path.home()
    root = tmp_path / "made" / "skills"
    assert _install(root).exit_code == 0
    path = sk.skill_path(root)
    path.unlink()
    state, detail = _doctor(home)["skill." + sk.custom_name(root)]
    assert state == "info" and "`tmap uninstall`" in detail
    _init(home, ("codex",))
    assert _ledger(home).find(sk.entry_id(path)) is not None
    assert not path.exists()  # nothing is created there
    report = _uninstall(home)
    assert not report.refused, report.refused
    assert _ledger(home).find(sk.entry_id(path)) is None
    assert not (tmp_path / "made").exists()


# ── --install <dir> is made absolute ─────────────────────────────────────────────────────────


def test_a_relative_install_directory_is_recorded_absolute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION: drop ``.absolute()`` -> the ledger holds a relative path and uninstall from B
    removes B's file -> RED."""
    home = Path.home()
    a, b = tmp_path / "A", tmp_path / "B"
    a.mkdir()
    theirs = sk.skill_path(b / "sub" / "skills")
    theirs.parent.mkdir(parents=True)
    theirs.write_bytes(sk.shipped_bytes())
    monkeypatch.chdir(a)
    assert _install("sub/skills").exit_code == 0
    path = sk.skill_path(a / "sub" / "skills")
    entry = _ledger(home).committed(sk.entry_id(path))
    assert entry is not None and entry.path == str(path)
    assert entry.extra["root"] == str(a / "sub" / "skills")
    assert all(Path(d).is_absolute() for d in entry.extra["created_dirs"])
    monkeypatch.chdir(b)
    report = _uninstall(home)
    assert not report.refused, report.refused
    assert not path.exists() and not (a / "sub").exists()
    assert theirs.read_bytes() == sk.shipped_bytes()


def test_a_tilde_install_directory_is_the_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MUTATION: drop ``.expanduser()`` -> written under <cwd>/~ -> RED."""
    monkeypatch.chdir(tmp_path)
    assert _install("~/x").exit_code == 0
    assert sk.skill_path(Path.home() / "x").read_bytes() == sk.shipped_bytes()
    assert not (tmp_path / "~").exists()


def test_a_directory_reached_through_a_link_stays_the_recorded_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """~/.agents is a link: an earlier tmap's install there is recorded under the link's path,
    and a later init still finds it tmap's.

    MUTATION: ``.resolve()`` instead of ``.absolute()`` -> recorded under the link's target ->
    init calls the file foreign and leaves it -> RED."""
    home = Path.home()
    real = tmp_path / "real-agents"
    (real / "skills").mkdir(parents=True)
    (home / ".agents").symlink_to(real, target_is_directory=True)
    earlier = diff_skill.skill_text() + "\nearlier\n"
    monkeypatch.setattr(diff_skill, "skill_text", lambda: earlier)
    assert _install(home / ".agents" / "skills").exit_code == 0
    later = earlier + "later\n"
    monkeypatch.setattr(diff_skill, "skill_text", lambda: later)
    path = sk.skill_path(home / ".agents" / "skills")
    st = sk.classify(home / ".agents" / "skills", _ledger(home), later.encode("utf-8"), known=[])
    assert st.state == "stale"
    _init(home, ("codex",))
    assert path.read_bytes() == later.encode("utf-8")


# ── every earlier shipped text ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "fixture",
    [_V5107, _V4727, _V4658, _V3741, _V3387, _V3126],
    ids=["5107", "4727", "4658", "3741", "3387", "3126"],
)
def test_a_text_shipped_since_the_ledger_is_replaced_without_a_record(
    tmp_path: Path, newer: bytes, fixture: Path
) -> None:
    """MUTATION: drop that text's sha256 from LEGACY_SHA256 -> foreign -> left -> RED."""
    home = tmp_path / "h"
    path = sk.skill_path(sk.agents_root(home))
    path.parent.mkdir(parents=True)
    path.write_bytes(fixture.read_bytes())
    assert _ledger(home).find(sk.entry_id(path)) is None
    assert any(f"→ {path}" in ln for ln in _plan(home, ["claude-code"]))
    _init(home, ("claude-code",))
    assert path.read_bytes() == newer


def test_the_shipped_text_is_pinned_and_not_an_earlier_one() -> None:
    """Changing the skill text fails here until its sha256 is added to LEGACY_SHA256 (so a copy
    of the old text is still replaced) and the new one pinned.

    MUTATION: change one word of the skill template -> RED."""
    now = hashlib.sha256(sk.shipped_bytes()).hexdigest()
    assert now == SHIPPED_SHA256
    assert now not in sk.LEGACY_SHA256
    assert len(sk.LEGACY_SHA256) == 8


def test_one_byte_changed_in_an_earlier_text_is_foreign(tmp_path: Path, newer: bytes) -> None:
    """MUTATION: recognise an earlier text by its length or its first bytes -> replaced -> RED."""
    home = tmp_path / "h"
    edited = bytearray(_V3387.read_bytes())
    edited[-2] = ord("#") if edited[-2] != ord("#") else ord("!")
    path = sk.skill_path(sk.agents_root(home))
    path.parent.mkdir(parents=True)
    path.write_bytes(bytes(edited))
    result = _init(home, ("codex",))
    assert path.read_bytes() == bytes(edited)
    assert any(str(path) in n and "--force" in n for n in result.needs_you)


# ── a recorded copy is read before the earlier texts ──────────────────────────────────────────


def _recorded_copy(home: Path, data: bytes, recorded: bytes) -> Path:
    """``data`` at the Claude Code skill path, the ledger recording ``recorded`` there."""
    path = sk.skill_path(sk.claude_root(home, {}))
    path.parent.mkdir(parents=True)
    path.write_bytes(data)
    _record(_ledger(home), path, recorded, root=str(path.parents[1]))
    return path


def _classify(home: Path, want: bytes) -> sk.SkillStatus:
    return sk.classify(sk.claude_root(home, {}), _ledger(home), want, known=[])


def test_a_recorded_copy_of_an_earlier_text_is_tmaps(tmp_path: Path, newer: bytes) -> None:
    """★ T-F4a: the text tmap shipped until now, written by tmap (the ledger records those very
    bytes), is ``stale`` — tmap's, from an earlier version — though that text is now also one of
    LEGACY_SHA256's; replaced all the same.

    MUTATION (verified RED, 1 failed): read LEGACY_SHA256 before the ledger -> legacy -> RED."""
    home = tmp_path / "h"
    old = _V3741.read_bytes()
    assert sk.sha256_of(old) in sk.LEGACY_SHA256  # the precondition
    path = _recorded_copy(home, old, old)
    st = _classify(home, newer)
    assert (st.state, st.detail) == ("stale", "tmap's, from an earlier version")
    _init(home, ("claude-code",))
    assert path.read_bytes() == newer


def test_a_recorded_copy_overwritten_with_an_earlier_text_is_still_replaced(
    tmp_path: Path, newer: bytes
) -> None:
    """★ T-F4b: the ledger records other bytes there, but the file is byte for byte an earlier
    tmap's text: ``legacy`` (tmap's text, so tmap's to replace), not ``foreign``.

    MUTATION (verified RED, 1 failed): read the whole ledger block (both of its answers) before
    LEGACY_SHA256 -> foreign -> left -> RED."""
    home = tmp_path / "h"
    path = _recorded_copy(home, _V3387.read_bytes(), b"another text tmap wrote\n")
    st = _classify(home, newer)
    assert (st.state, st.detail) == ("legacy", "an earlier tmap's version")
    _init(home, ("claude-code",))
    assert path.read_bytes() == newer


def test_a_recorded_copy_changed_into_no_tmap_text_is_left(tmp_path: Path, newer: bytes) -> None:
    """★ T-F4c: the ledger records other bytes there and the file is no text tmap shipped:
    ``foreign`` (changed since tmap installed it), never modified.

    MUTATION (verified RED, 1 failed): drop the recorded-but-changed answer after LEGACY_SHA256 ->
    "not in tmap's install ledger" -> RED."""
    home = tmp_path / "h"
    edited = b"a person's own edit\n"
    path = _recorded_copy(home, edited, b"another text tmap wrote\n")
    st = _classify(home, newer)
    assert (st.state, st.detail) == ("foreign", "changed since tmap installed it")
    _init(home, ("claude-code",))
    assert path.read_bytes() == edited


# What tmap init and the doctor do with each kind of file at the skill path: the same before and
# after T-F4 moved the recorded copy ahead of the earlier texts (checked against d3eb840).
_CASES: dict[str, tuple[bool, str]] = {
    "missing": (True, "info"),
    "aligned": (False, "ok"),
    "recorded": (True, "warn"),
    "recorded_earlier_text": (True, "warn"),
    "earlier_text": (True, "warn"),
    "recorded_overwritten_earlier": (True, "warn"),
    "recorded_changed": (False, "warn"),
    "unrecorded": (False, "warn"),
    "invalid": (False, "wrong"),
}


@pytest.mark.parametrize("case", sorted(_CASES))
def test_what_is_replaced_is_the_same_in_every_state(
    tmp_path: Path, newer: bytes, case: str
) -> None:
    """★ T-F4d: over every state classify gives (and both ways a file can be ``legacy`` or
    ``stale``), whether init replaces the file and what the doctor reports are unchanged — only
    the wording of one state moved. The table was read from d3eb840 by the same test body."""
    home = tmp_path / "h"
    path = sk.skill_path(sk.claude_root(home, {}))
    earlier = _V3387.read_bytes()
    other = b"another text tmap wrote\n"
    if case == "aligned":
        _recorded_copy(home, newer, newer)
    elif case == "recorded":
        _recorded_copy(home, other, other)
    elif case == "recorded_earlier_text":
        _recorded_copy(home, earlier, earlier)
    elif case == "earlier_text":
        path.parent.mkdir(parents=True)
        path.write_bytes(earlier)
    elif case == "recorded_overwritten_earlier":
        _recorded_copy(home, earlier, other)
    elif case == "recorded_changed":
        _recorded_copy(home, b"a person's own edit\n", other)
    elif case == "unrecorded":
        path.parent.mkdir(parents=True)
        path.write_bytes(b"a person's own skill\n")
    elif case == "invalid":
        path.mkdir(parents=True)
    before = path.read_bytes() if path.is_file() else None
    level = _doctor(home)["skill.claude"][0]
    _init(home, ("claude-code",))
    after = path.read_bytes() if path.is_file() else None
    replaced = after == newer and before != newer
    assert (replaced, level) == _CASES[case], (replaced, level)
