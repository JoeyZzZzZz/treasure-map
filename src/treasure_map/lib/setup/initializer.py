# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""``tmap init``: set up ~/.treasure-map, the toolchain, and the agents — and say what it did.

Discover (read only, plus questions) → Plan → Select agents → Confirm → Apply → Doctor. Nothing is
written before the plan is confirmed; ``--dry-run`` stops after printing it and ``--check-only``
runs the doctor alone. The toolchain (JDK 21, Ghidra 11.4.3, BinExport, BinDiff 8) is reused when
it is already installed and checks out, and otherwise downloaded from the pinned lock — the only
network access tmap has. Analysis itself never touches the network.
"""

from __future__ import annotations

import logging
import os
import shutil
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

from treasure_map.lib.config.config import Config, _source_env_file, resolve_relative_paths
from treasure_map.lib.errors import TreasureMapError
from treasure_map.lib.setup.tmap_files import ENV_TEXT, config_text

logger = logging.getLogger(__name__)

# Default config matching config.example.yaml; stores env var names, never values. Only keys tmap
# reads are written (an older init's ghidra.mode and log_level still load; nothing reads them).
# max_parallel_jvms is deliberately ABSENT here: _configure_parallelism probes the machine at init
# and writes the derived value (a hardcoded default would mask a wrong-sized pool). If it were ever
# missing from config.yaml, config.py's GhidraConfig default (4) is the safety fallback.
_DEFAULT_CONFIG_YAML: dict[str, Any] = {
    "ghidra": {
        "headless_timeout_seconds": 300,
        "local": {"home": None},
    },
    "toolchain": {"java_home": None, "bindiff": None},
    "workspace_dir": "~/.treasure-map/workspaces",
    "atlas": {"db_path": "~/.treasure-map/atlas.db"},
}


class PlatformUnsupportedError(TreasureMapError):
    """This platform has no supported toolchain; init wrote nothing."""


class InitAbortedError(TreasureMapError):
    """The user stopped init (Ctrl-C in the agent selector); nothing was changed."""


class SetupError(TreasureMapError):
    """A path the user named explicitly failed its check; init does not substitute another."""


@dataclass(frozen=True)
class InitResult:
    """Outcome of run_init. ``checks`` are the doctor's findings (name, ok, detail, state)."""

    config_path: Path
    env_path: Path
    atlas_dir: Path
    checks: tuple[Any, ...]
    failed: bool = False  # a toolchain action failed
    # applied / nothing_to_do: what this run did with the plan. The CLI renders from the plan
    # itself; these two are the result's own record of it, read by the plan tests.
    applied: bool = False
    nothing_to_do: bool = False
    dry_run: bool = False
    registered: tuple[str, ...] = ()  # agents whose entry this run wrote (they need a restart)
    needs_you: tuple[str, ...] = ()
    runs: Any = None  # doctor.RunsCurrency | None


def _provision_dirs(paths: Iterable[Path]) -> None:
    for d in paths:
        d.mkdir(parents=True, exist_ok=True)


def _configured_dirs(cfg: Config) -> list[Path]:
    """Resolve the directories named by the loaded config (provisioned == checked).

    Using the config-resolved paths here — and the same ones in the doctor — keeps
    provisioning and preflight consistent regardless of HOME vs Path.home() drift.
    """
    return [cfg.workspace_dir, cfg.atlas.db_path.parent]


def _noop_echo(_msg: str) -> None:
    return None


def _write_config(
    config_path: Path, *, force: bool, echo: Callable[[str], None] = _noop_echo
) -> None:
    """Write the default config.yaml, or reuse an existing one (idempotent).

    If the file is present and force is False, it is reused untouched — init is safe to
    re-run and to run after a reinstall (the program is fresh but ~/.treasure-map/ persists).
    force regenerates the default structure; it never touches .env or atlas.db.
    """
    if config_path.exists() and not force:
        echo("  Config : config.yaml exists — reusing (pass --force to regenerate the structure).")
        return
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(config_text(config_path, _DEFAULT_CONFIG_YAML))


def _write_env(env_path: Path, *, echo: Callable[[str], None] = _noop_echo) -> None:
    """Create ~/.treasure-map/.env — KEY=value lines every tmap command sets, unless the variable
    is already in its environment — when there is none. An existing .env is never changed."""
    if env_path.exists():
        echo(f"  .env   : {env_path} exists — kept as it is.")
        return
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text(ENV_TEXT)
    os.chmod(env_path, 0o600)


def _seed_watchlist() -> None:
    """Seed the vendor watchlist from the committed example if a destination is configured.

    Destination is taken from the TM_VENDOR_WATCHLIST environment variable. If unset, this
    is a no-op (the user chooses where the watchlist lives; the tool does not assume a path).
    """
    dst_env = os.environ.get("TM_VENDOR_WATCHLIST")
    if not dst_env:
        return
    src = Path(".githooks") / "vendor-watchlist.example.txt"
    dst = Path(dst_env)
    if src.exists() and not dst.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def _default_workspace_dir() -> str:
    return str(_DEFAULT_CONFIG_YAML["workspace_dir"])


def _configured_workspace_dir(config_path: Path) -> str:
    """Return workspace_dir from an existing config.yaml, or the default if unset/unreadable."""
    if not config_path.exists():
        return _default_workspace_dir()
    try:
        data: dict[str, Any] = yaml.safe_load(config_path.read_text()) or {}
    except Exception:
        return _default_workspace_dir()
    value = data.get("workspace_dir")
    return str(value) if value else _default_workspace_dir()


def _configured_max_parallel(config_path: Path) -> int | None:
    """Return ghidra.max_parallel_jvms from an existing config.yaml, or None if unset/unreadable."""
    if not config_path.exists():
        return None
    try:
        data: dict[str, Any] = yaml.safe_load(config_path.read_text()) or {}
    except Exception:
        return None
    value = (data.get("ghidra") or {}).get("max_parallel_jvms")
    return int(value) if isinstance(value, int) else None


def _set_max_parallel(config_path: Path, value: int) -> None:
    """Write ghidra.max_parallel_jvms into config.yaml, preserving the rest of the file."""
    data: dict[str, Any] = yaml.safe_load(config_path.read_text()) or {}
    data.setdefault("ghidra", {})["max_parallel_jvms"] = value
    config_path.write_text(config_text(config_path, data))


def _configure_parallelism(
    config_path: Path,
    *,
    force: bool,
    echo: Callable[[str], None],
) -> None:
    """Probe the machine (physical cores + memory) and write the derived ``max_parallel_jvms``.

    First init (or ``--force``, which regenerated the config without the value) detects and writes;
    a re-run keeps an already-written value untouched (the operator may have hand-tuned it —
    re-probe only on ``--force``). CPU knee = physical cores, memory budget = MemTotal × a
    conservative fraction; the smaller wins (see lib/machine.py). The probe method is logged so an
    imprecise detection (WSL2/container falling back off /proc/cpuinfo) is visible, never trusted.
    """
    from treasure_map.lib.machine import (
        derive_parallelism,
        mem_total,
        physical_cores,
    )

    current = _configured_max_parallel(config_path)
    if current is not None and not force:
        echo(f"  Parallelism: max_parallel_jvms={current} (kept; --force to re-detect).")
        return
    probe = physical_cores()
    mem = mem_total()
    derived = derive_parallelism(probe.count, mem.mb)
    _set_max_parallel(config_path, derived)
    echo(
        f"  Parallelism: {probe.count} physical cores ({probe.method}) / {mem.mb}MB "
        f"({mem.method}) -> max_parallel_jvms={derived}."
    )


def _configure_completion(
    *,
    non_interactive: bool,
    prompt: Callable[[str], str],
    echo: Callable[[str], None],
) -> tuple[Path | None, Path | None, bool]:
    """Install shell tab-completion (a standard init step; bash + zsh). Best-effort + honest.

    The script goes to the shell's own autoload directory. When that alone will not make the shell
    load it, an INTERACTIVE init then asks (Y/N, Enter = yes) and appends a marked, idempotent block
    to the rc only on a yes; a decline — and every non-interactive run — writes no rc and just
    prints the one line to add. init never changes an rc the user did not agree to.

    Any failure is echoed, never swallowed, and the doctor's ``completion`` check reports the state
    (installed / active / the one line to add). No ``--no-completion`` flag: a completion script has
    no side effects, so a skip toggle would only push a non-decision onto the user.

    Returns (the installed script, the rc now carrying the activation block, whether this run
    created that rc) — what the install ledger records so ``tmap uninstall`` removes exactly these
    and nothing else (a file tmap created, and that holds nothing else, goes too).
    """
    from treasure_map.lib.setup.completion import (
        detect_shell,
        install_completion,
        unsupported_reason,
    )

    shell = detect_shell()
    if shell is None:
        echo("  Completion: shell is not bash/zsh — skipped (nothing to install).")
        return None, None, False
    why = unsupported_reason(shell)
    if why is not None:
        echo(f"  Completion: {why} — skipped.")
        return None, None, False
    try:
        outcome = install_completion(shell, Path.home())
    except OSError as exc:
        echo(f"  Completion: could not install for {shell}: {exc}")
        return None, None, False
    if outcome is None:
        echo(f"  Completion: no installer for {shell} — skipped.")
        return None, None, False
    state = "installed" if outcome.wrote else "already up to date"
    echo(f"  Completion: {state} for {shell} at {outcome.path}")
    if outcome.wrote and outcome.active:
        # A shell that is already running does not load a script installed under it (zsh reads
        # $fpath when compinit runs at startup), so a tab pressed right after init does nothing.
        echo(
            "              takes effect in a new shell: open a new terminal, "
            "or run `exec $SHELL -l`"
        )
    rc: Path | None = None
    created = False
    if not outcome.active and outcome.activation_hint:
        rc, created = _offer_activation(
            shell,
            outcome.path,
            outcome.activation_hint,
            non_interactive=non_interactive,
            prompt=prompt,
            echo=echo,
        )
    return outcome.path, rc, created


def _offer_activation(
    shell: str,
    script_path: Path,
    hint: str,
    *,
    non_interactive: bool,
    prompt: Callable[[str], str],
    echo: Callable[[str], None],
) -> tuple[Path | None, bool]:
    """Ask whether to add the activation line to the rc, and add it only on a yes.

    Non-interactive runs never ask and never write — an unattended init changing a shell rc is
    precisely the no-consent edit the rule forbids, and there is nobody there to agree. Ambiguous
    input is treated as no: only Enter / y / yes writes, so an unrecognised answer errs toward
    leaving the user's file alone. Returns (the rc when it now carries tmap's block, whether this
    run created that file).
    """
    from treasure_map.lib.setup.completion import activate_completion, rc_path

    rc = rc_path(shell, Path.home())
    if non_interactive or rc is None:
        echo(f"              to activate, {hint}")
        return None, False
    answer = (
        prompt(
            f"Add tmap's completion line to ~/{rc.name} now? "
            "tab-completion won't work until you do [Y/n]"
        )
        .strip()
        .lower()
    )
    if answer not in ("", "y", "yes"):
        echo(f"              to activate, {hint}")
        return None, False
    result = activate_completion(shell, Path.home(), script_path)
    if result is None or not result.ok:
        detail = f": {result.error}" if result is not None and result.error else ""
        echo(f"              could not write ~/{rc.name}{detail}")
        echo(f"              to activate, {hint}")
        return None, False
    if result.already:
        echo(f"              ~/{rc.name} already has the tmap block — nothing to add.")
        return rc, False
    echo(
        f"              added to ~/{rc.name} — restart your shell or run "
        f"`source ~/{rc.name}` to activate now."
    )
    return rc, result.created


# ── reading and writing config keys ──────────────────────────────────────────────────────────

_GHIDRA_HOME_KEY = ("ghidra", "local", "home")
_JAVA_HOME_KEY = ("toolchain", "java_home")
_BINDIFF_KEY = ("toolchain", "bindiff")
_WORKSPACE_KEY = ("workspace_dir",)
_ATLAS_KEY = ("atlas", "db_path")


def _flatten(node: Any, prefix: str = "") -> dict[str, Any]:
    """A nested mapping as ``{"a.b.c": leaf}``."""
    if not isinstance(node, dict):
        return {prefix: node} if prefix else {}
    out: dict[str, Any] = {}
    for k, v in node.items():
        out.update(_flatten(v, f"{prefix}.{k}" if prefix else str(k)))
    return out


def _force_resets(raw: dict[str, Any], kept: dict[tuple[str, ...], str]) -> list[str]:
    """What ``--force`` changes in a readable config.yaml: every value it holds that the rebuilt
    file (the defaults plus ``kept``) will not — so the plan names each one before it goes."""
    after = _flatten(_DEFAULT_CONFIG_YAML)
    after.update({".".join(k): v for k, v in kept.items()})
    out = []
    for key, old in _flatten(raw).items():
        if key == "ghidra.max_parallel_jvms":
            continue  # re-detected, listed on its own
        new = after.get(key)
        if old != new and not _same_path(old, new):
            out.append(f"{key}: {old!r} -> {'unset' if key not in after else repr(new)}")
    return out


def _backup_config(config_path: Path) -> Path:
    """Copy config.yaml to the first free ``config.yaml.tmap.backup[.N]``; an earlier backup is
    never overwritten."""
    base = config_path.with_name(config_path.name + ".tmap.backup")
    backup, n = base, 0
    while backup.exists():
        n += 1
        backup = base.with_name(f"{base.name}.{n}")
    shutil.copy2(config_path, backup)
    return backup


def _read_config(config_path: Path) -> tuple[Config | None, dict[str, Any], str | None]:
    """(validated config, raw mapping, why it is unreadable). Absent = (None, {}, None). The
    validated config reads a relative path from the file's directory, as every tmap command does."""
    if not config_path.exists():
        return None, {}, None
    try:
        raw = yaml.safe_load(config_path.read_text()) or {}
        if not isinstance(raw, dict):
            raise ValueError(f"top level is a {type(raw).__name__}, not a mapping")
        return Config.model_validate(resolve_relative_paths(raw, config_path)), raw, None
    except Exception as exc:
        reason = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
        return None, {}, reason


def _raw_get(raw: dict[str, Any], keys: tuple[str, ...]) -> Any:
    node: Any = raw
    for k in keys:
        if not isinstance(node, dict):
            return None
        node = node.get(k)
    return node


def _same_path(a: object, b: object) -> bool:
    if a is None or b is None:
        return a is b
    return os.path.realpath(os.path.expanduser(str(a))) == os.path.realpath(
        os.path.expanduser(str(b))
    )


def _set_keys(config_path: Path, values: dict[tuple[str, ...], str]) -> None:
    """Write nested keys into config.yaml, preserving the rest of the file."""
    data: dict[str, Any] = yaml.safe_load(config_path.read_text()) or {}
    for keys, value in values.items():
        node = data
        for k in keys[:-1]:
            child = node.get(k)
            if not isinstance(child, dict):
                child = {}
                node[k] = child
            node = child
        node[keys[-1]] = value
    config_path.write_text(config_text(config_path, data))


def _absolute(entered: str) -> str:
    """A path typed at a prompt or given on the command line, as config.yaml must hold it: a
    relative one meant the current directory, and config.yaml reads a relative path from its own
    directory — so it is made absolute here. A ``~`` path stays as typed."""
    return entered if os.path.isabs(os.path.expanduser(entered)) else os.path.abspath(entered)


def _ask_workspace_dir(
    config_path: Path,
    *,
    non_interactive: bool,
    prompt: Callable[[str], str],
    echo: Callable[[str], None],
) -> str | None:
    """The workspace base the user typed, or None to keep the current one (collected now and
    written only once the plan is applied)."""
    current = _configured_workspace_dir(config_path)
    if non_interactive:
        echo(f"  Workspace base: {current}")
        return None
    entered = prompt(f"Workspace base directory [{current}], Enter to keep").strip()
    if not entered:
        echo(f"  Workspace base: {current} (kept)")
        return None
    return _absolute(entered)


# ── the run ──────────────────────────────────────────────────────────────────────────────────

Mode = Literal["interactive", "yes", "non-interactive"]


@dataclass
class _Choice:
    """The component tmap will use: an existing install, a download, or nothing."""

    path: Path | None = None  # existing: jdk java_home / ghidra root / bindiff exe
    managed: bool = False
    download: bool = False
    note: str | None = None


@dataclass
class _Context:
    host: Any
    lock: Any
    mode: Mode
    prompt: Callable[[str], str]
    echo: Callable[[str], None]


_SIZE_LABEL = {"jdk": "JDK 21", "ghidra": "Ghidra 11.4.3", "bindiff": "BinDiff 8"}


def _managed_paths(ledger: Any, entry_id: str, key: str | None = None) -> list[Path]:
    e = ledger.committed(entry_id)
    if e is None:
        return []
    value = e.extra.get(key) if key else e.path
    return [Path(value)] if isinstance(value, str) else []


def _ask_or_download(ctx: _Context, component: str) -> _Choice:
    """Nothing usable was found: download it (interactive and ``--yes``), or leave it unset
    (``--non-interactive``).

    Interactive init no longer asks for a path per component — the per-tool "enter a path or press
    Enter to download" prompts were the ones that felt like too many download confirmations. A
    single "Not installed — will download" notice is printed once for all missing tools (see
    run_init), and the one Apply confirmation covers the downloads. Anyone with an install tmap did
    not discover points at it with ``--ghidra`` / ``--java-home`` / ``--bindiff``."""
    if ctx.mode == "non-interactive":
        label = _SIZE_LABEL[component]
        ctx.echo(f"  {label}: not found; left unset (--non-interactive does not download).")
        return _Choice()
    return _Choice(download=True)


def _report_candidates(ctx: _Context, label: str, cands: Sequence[Any], chosen: Any) -> None:
    if chosen is not None:
        note = f" ({chosen.note})" if chosen.note else ""
        ctx.echo(f"  {label}: {chosen.path} [{chosen.source}]{note}")
    others = [c for c in cands if c is not chosen]
    for c in others:
        state = "also usable" if c.ok else f"not used: {c.why_not}"
        ctx.echo(f"      {c.path} [{c.source}] — {state}")


def _choose_ghidra(
    ctx: _Context, *, explicit: Path | None, config_home: Path | None, ledger: Any
) -> _Choice:
    from treasure_map.lib.setup.discover import check_ghidra, discover_ghidra, first_ok

    want = ctx.lock.component("ghidra").version
    plat = ctx.host.platform
    if explicit is not None:
        _v, why = check_ghidra(explicit, plat, want)
        if why is not None:
            raise SetupError(f"--ghidra {explicit}: {why}")
        return _Choice(path=explicit)
    cands = discover_ghidra(
        ctx.host, config_home=config_home, want=want, managed=_managed_paths(ledger, "ghidra")
    )
    chosen = first_ok(cands)
    _report_candidates(ctx, "Ghidra", cands, chosen)
    if chosen is not None:
        return _Choice(path=chosen.path, managed=chosen.managed, note=chosen.note)
    return _ask_or_download(ctx, "ghidra")


def _choose_jdk(
    ctx: _Context,
    *,
    explicit: Path | None,
    config_java_home: Path | None,
    ghidra_home: Path | None,
    ledger: Any,
) -> _Choice:
    from treasure_map.lib.setup.discover import check_jdk, discover_jdk, first_ok

    if explicit is not None:
        _v, why = check_jdk(explicit)
        if why is not None:
            raise SetupError(f"--java-home {explicit}: {why}")
        return _Choice(path=explicit)
    cands = discover_jdk(
        ctx.host,
        config_java_home=config_java_home,
        ghidra_home=ghidra_home,
        pinned=ctx.lock.component("jdk").version,
        managed=_managed_paths(ledger, "jdk", "java_home"),
    )
    chosen = first_ok(cands)
    _report_candidates(ctx, "JDK", cands, chosen)
    if chosen is not None:
        return _Choice(path=chosen.path, managed=chosen.managed, note=chosen.note)
    return _ask_or_download(ctx, "jdk")


def _choose_bindiff(
    ctx: _Context, *, explicit: Path | None, config_bindiff: Path | None, ledger: Any
) -> _Choice:
    from treasure_map.lib.setup.discover import check_bindiff, discover_bindiff, first_ok

    pinned = ctx.lock.component("bindiff").version_line
    host = ctx.host

    def validate(p: Path) -> str | None:
        return check_bindiff(p, host.platform, host.run, pinned)[1]

    if explicit is not None:
        why = validate(explicit)
        if why is not None:
            raise SetupError(f"--bindiff {explicit}: {why}")
        return _Choice(path=explicit)
    cands = discover_bindiff(
        host,
        config_bindiff=config_bindiff,
        version_line=pinned,
        managed=_managed_paths(ledger, "bindiff", "exe"),
    )
    chosen = first_ok(cands)
    _report_candidates(ctx, "BinDiff", cands, chosen)
    if chosen is not None:
        return _Choice(path=chosen.path, managed=chosen.managed, note=chosen.note)
    return _ask_or_download(ctx, "bindiff")


def _asset_size(ctx: _Context, component: str) -> int:
    from treasure_map.lib.setup.toolchain_lock import asset_for

    return int(asset_for(ctx.lock, component, ctx.host.platform.key).size)


def _download_action(ctx: _Context, plan: Any, component: str, mirror: str | None) -> bool:
    """Add the download of ``component`` to the plan; False (and a needs-you line) when the
    artifact is not published yet."""
    from treasure_map.lib.setup.plan import Action, download_lines
    from treasure_map.lib.setup.toolchain_lock import asset_for, unavailable_reason

    comp = ctx.lock.component(component)
    asset = asset_for(ctx.lock, component, ctx.host.platform.key)
    why = unavailable_reason(comp, asset)
    if why is not None:
        plan.needs_you.append(why)
        return False
    titles = {
        "jdk": f"download JDK {comp.version}",
        "ghidra": f"download Ghidra {comp.version}",
        "binexport": f"install BinExport {comp.version}",
        "bindiff": f"download BinDiff {comp.version}",
    }
    kind = "install_binexport" if component == "binexport" else f"download_{component}"
    plan.add(
        Action(
            kind,
            titles[component],
            target=None,
            lines=download_lines(asset, mirror),
            asset=asset,
        )
    )
    return True


def run_init(
    *,
    force: bool = False,
    non_interactive: bool = False,
    check_only: bool = False,
    prompt: Callable[[str], str],
    echo: Callable[[str], None] = _noop_echo,
    assume_yes: bool = False,
    dry_run: bool = False,
    clients: Sequence[str] = (),
    ghidra: Path | None = None,
    java_home: Path | None = None,
    bindiff: Path | None = None,
    mirror: str | None = None,
    offline: Path | None = None,
    fetcher: Any = None,
    platform: Any = None,
    host: Any = None,
    client_host: Any = None,
    tmap: Path | None | Literal["detect"] = "detect",
    runs_probe: Callable[[Config | None], Any] | None = None,
    mcp_probe: Any = None,
    use_tty: bool | None = None,
) -> InitResult:
    """Set up ~/.treasure-map/, the toolchain and the agents, then run the doctor.

    Three modes: interactive (asks, confirms; the default), ``assume_yes`` (no questions;
    downloads what is missing; registers only ``clients``), ``non_interactive`` (no questions, no
    downloads; registers only ``clients``). ``check_only`` runs the doctor and writes nothing;
    ``dry_run`` prints the plan and writes nothing."""
    from treasure_map.lib.diff import toolchain as _toolchain
    from treasure_map.lib.diff.toolchain import binexport_lib_digest
    from treasure_map.lib.setup import clients as cl
    from treasure_map.lib.setup.discover import current_host, discover_binexport
    from treasure_map.lib.setup.doctor import DoctorInputs, run_doctor
    from treasure_map.lib.setup.fetch import (
        OfflineFetcher,
        UrlFetcher,
        recover_pending,
        sweep_staging,
    )
    from treasure_map.lib.setup.ledger import LEDGER_NAME, Ledger
    from treasure_map.lib.setup.plan import (
        OVERRIDE_KEY,
        TOOLCHAIN_KINDS,
        Action,
        Plan,
        ToolchainResult,
        apply_toolchain,
        binexport_target,
        override_line,
        verify_binexport,
    )
    from treasure_map.lib.setup.platform import detect_platform
    from treasure_map.lib.setup.selector import select
    from treasure_map.lib.setup.toolchain_env import apply_toolchain_env
    from treasure_map.lib.setup.toolchain_lock import asset_for, load_lock

    # 0. the platform gate — before anything is written
    plat = platform if platform is not None else detect_platform()
    if plat.support == "unsupported":
        raise PlatformUnsupportedError(f"{plat.key} is not supported: {plat.reason}")

    lock = load_lock()
    host = host if host is not None else current_host(plat)
    chost = client_host or cl.ClientHost(
        home=host.home, environ=host.environ, platform=plat, which=host.which, run=host.run
    )
    tmap_path = cl.tmap_executable() if tmap == "detect" else tmap
    mode: Mode = "yes" if assume_yes else ("non-interactive" if non_interactive else "interactive")
    ghidra, java_home, bindiff = (
        None if p is None else Path(_absolute(str(p))) for p in (ghidra, java_home, bindiff)
    )

    tm_home = Path.home() / ".treasure-map"
    config_path = tm_home / "config.yaml"
    env_path = tm_home / ".env"

    def _doctor(cfg: Config | None, requested: Sequence[str], runs: Any) -> tuple[Any, ...]:
        return tuple(
            run_doctor(
                DoctorInputs(
                    platform=plat,
                    host=host,
                    client_host=chost,
                    cfg=cfg,
                    lock=lock,
                    tmap=tmap_path,
                    check_only=check_only,
                    requested_clients=requested,
                    runs=runs,
                    mcp_probe=mcp_probe,
                    tm_home=tm_home,
                )
            )
        )

    if check_only:
        _source_env_file(env_path)
        cfg, _raw, _err = _read_config(config_path)
        runs = runs_probe(cfg) if runs_probe is not None else None
        return InitResult(config_path, env_path, tm_home, _doctor(cfg, (), runs), runs=runs)

    # 0b. leftovers of an interrupted run (never on a dry run: it writes nothing)
    ledger = Ledger.load(host.toolchain_dir / LEDGER_NAME)
    want_ghidra = lock.component("ghidra").version
    if not dry_run:
        sweep_staging(host.toolchain_dir)
        from treasure_map.lib.setup.discover import check_bindiff, check_ghidra, check_jdk

        def _jdk_ok(p: Path) -> str | None:
            e = ledger.find("jdk")
            jh = Path(e.extra.get("java_home", p)) if e is not None else p
            return check_jdk(jh)[1]

        def _bindiff_ok(p: Path) -> str | None:
            e = ledger.find("bindiff")
            exe = Path(e.extra.get("exe", p)) if e is not None else p
            return check_bindiff(exe, plat, host.run, lock.component("bindiff").version_line)[1]

        def _binexport_ok(p: Path) -> str | None:
            homes: list[Path] = []
            managed_ghidra = ledger.committed("ghidra")
            if managed_ghidra is not None:
                homes.append(Path(managed_ghidra.path))
            cfg_now, _r, _e = _read_config(config_path)
            if cfg_now is not None and cfg_now.ghidra.local.home is not None:
                homes.append(cfg_now.ghidra.local.home)
            if any(verify_binexport(host, h, p, want_ghidra) is None for h in homes):
                return None
            return "no configured Ghidra loads it"

        def _override_ok(p: Path) -> str | None:
            e = ledger.find("ghidra_jdk_override")
            want = e.extra.get("line_after") if e is not None else None
            return None if want is not None and override_line(p) == want else "not applied"

        for line in recover_pending(
            ledger,
            {
                "jdk": _jdk_ok,
                "ghidra": lambda p: check_ghidra(p, plat, want_ghidra)[1],
                "bindiff": _bindiff_ok,
                "binexport": _binexport_ok,
                "ghidra_jdk_override": _override_ok,
            },
            toolchain_dir=host.toolchain_dir,
        ):
            echo(f"  {line}")
        recovered = ledger.committed("binexport")
        if recovered is not None and "lib_digest" not in recovered.extra:
            ledger.commit("binexport", lib_digest=binexport_lib_digest(Path(recovered.path)))

    # 1. discover (read only, plus questions)
    existing_cfg, raw_cfg, cfg_error = _read_config(config_path)
    if cfg_error is not None:
        echo(f"  Config : {config_path} is unreadable ({cfg_error}); defaults are used.")
    ctx = _Context(host, lock, mode, prompt, echo)
    workspace = _ask_workspace_dir(
        config_path, non_interactive=(mode != "interactive"), prompt=prompt, echo=echo
    )
    g = _choose_ghidra(
        ctx,
        explicit=ghidra,
        config_home=existing_cfg.ghidra.local.home if existing_cfg else None,
        ledger=ledger,
    )
    j = _choose_jdk(
        ctx,
        explicit=java_home,
        config_java_home=existing_cfg.toolchain.java_home if existing_cfg else None,
        ghidra_home=g.path,
        ledger=ledger,
    )
    b = _choose_bindiff(
        ctx,
        explicit=bindiff,
        config_bindiff=existing_cfg.toolchain.bindiff if existing_cfg else None,
        ledger=ledger,
    )
    if plat.is_wsl:
        ws_now = workspace or _configured_workspace_dir(config_path)
        if str(os.path.expanduser(ws_now)).startswith("/mnt/"):
            echo(
                "  warning: Ghidra I/O over /mnt is an order of magnitude slower; "
                "keep workspaces under ~"
            )
    # One consolidated "will download" notice for the tools that are not installed — instead of a
    # separate path-or-download prompt per tool. The single Apply confirmation below covers them.
    if mode == "interactive":
        pending = [
            (_SIZE_LABEL[key], _asset_size(ctx, key))
            for key, choice in (("ghidra", g), ("jdk", j), ("bindiff", b))
            if choice.download
        ]
        if pending:
            width = max(len(label) for label, _ in pending)
            echo("")
            echo("Not installed — will download:")
            for label, size in pending:
                echo(f"  {label.ljust(width)}   {size / 1_000_000:.0f} MB")
            echo("  (use your own with --ghidra / --java-home / --bindiff)")
    survey = cl.survey(chost, tmap_path)

    # 2. plan
    plan = Plan()
    if not tm_home.is_dir():
        plan.add(Action("mkdir", "create ~/.treasure-map", target=tm_home))
    if cfg_error is not None:
        plan.add(
            Action(
                "rewrite_config",
                f"rewrite config (unreadable: {cfg_error})",
                target=config_path,
                lines=[f"backup {config_path}.tmap.backup"],
            )
        )
    tdir = host.toolchain_dir
    jdk_ok = j.path is not None or (j.download and _download_action(ctx, plan, "jdk", mirror))
    ghidra_ok = g.path is not None or (g.download and _download_action(ctx, plan, "ghidra", mirror))
    managed_ghidra_home: Path | None = None
    if g.download and ghidra_ok:
        managed_ghidra_home = tdir / (asset_for(lock, "ghidra", plat.key).root or "")
    elif g.managed:
        managed_ghidra_home = g.path
    managed_java_home: Path | None = None
    if j.download and jdk_ok:
        managed_java_home = tdir / (asset_for(lock, "jdk", plat.key).java_home or "")
    elif j.managed:
        managed_java_home = j.path
    if managed_ghidra_home is not None and managed_java_home is not None:
        props = managed_ghidra_home / "support" / "launch.properties"
        if override_line(props) != f"{OVERRIDE_KEY}{managed_java_home}":
            plan.add(
                Action(
                    "set_ghidra_jdk_override",
                    "point the managed Ghidra at the managed JDK (JAVA_HOME_OVERRIDE)",
                    target=props,
                )
            )
    # BinExport: only for a Ghidra that is (or will be) there
    if g.path is not None:
        finding = discover_binexport(
            host,
            g.path,
            pinned_digest=lock.component("binexport").lib_digest,
            managed=_managed_paths(ledger, "binexport"),
        )
        for legacy in finding.legacy:
            echo(f"  BinExport: {legacy} is ignored by Ghidra 11.4.3")
        chosen_be = finding.chosen()
        if chosen_be is not None:
            note = f" ({chosen_be.note})" if chosen_be.note else ""
            echo(f"  BinExport: {chosen_be.path}{note}")
        elif finding.unknown:
            plan.needs_you.append(
                f"BinExport: Ghidra's settings directory for {g.path} cannot be determined"
            )
        elif finding.candidates:
            for c in finding.candidates:
                plan.needs_you.append(f"BinExport at {c.path}: {c.why_not}")
        elif mode == "non-interactive":
            echo("  BinExport: not installed; left (--non-interactive does not download).")
        else:
            target = binexport_target(host, g.path, ledger)
            if target is None:
                plan.needs_you.append("BinExport: Ghidra's settings directory cannot be determined")
            elif _download_action(ctx, plan, "binexport", mirror):
                be = plan.of("install_binexport")
                assert be is not None
                be.target = target
    elif g.download and ghidra_ok:
        if _download_action(ctx, plan, "binexport", mirror):
            be = plan.of("install_binexport")
            assert be is not None and managed_ghidra_home is not None
            be.target = managed_ghidra_home / "Ghidra" / "Extensions" / "BinExport"
    if b.download:
        _download_action(ctx, plan, "bindiff", mirror)
    for kind, target in (
        ("download_jdk", managed_java_home),
        ("download_ghidra", managed_ghidra_home),
        ("download_bindiff", tdir / f"bindiff-{lock.component('bindiff').version}"),
    ):
        a = plan.of(kind)
        if a is not None:
            a.target = target

    # config keys
    desired: dict[tuple[str, ...], str] = {}
    if g.path is not None or managed_ghidra_home is not None:
        desired[_GHIDRA_HOME_KEY] = str(g.path or managed_ghidra_home)
    jh_value = j.path or managed_java_home
    if jh_value is not None:
        desired[_JAVA_HOME_KEY] = str(jh_value)
    if b.path is not None:
        desired[_BINDIFF_KEY] = str(b.path)
    elif plan.of("download_bindiff") is not None:
        exe = asset_for(lock, "bindiff", plat.key).exe or "bindiff"
        desired[_BINDIFF_KEY] = str(tdir / f"bindiff-{lock.component('bindiff').version}" / exe)
    if workspace is not None:
        desired[_WORKSPACE_KEY] = workspace
    elif force:  # --force rebuilds the structure: carry the kept workspace base across
        desired[_WORKSPACE_KEY] = _configured_workspace_dir(config_path)
    if force and cfg_error is None and isinstance(_raw_get(raw_cfg, _ATLAS_KEY), str):
        desired[_ATLAS_KEY] = str(_raw_get(raw_cfg, _ATLAS_KEY))  # where the data is, kept too
    changed = {
        k: v
        for k, v in desired.items()
        if force or cfg_error is not None or not _same_path(_raw_get(raw_cfg, k), v)
    }
    if changed or not config_path.exists() or force:
        plan.add(
            Action(
                "write_config",
                "write config.yaml",
                target=config_path,
                lines=[f"{'.'.join(k)}: {v}" for k, v in changed.items()]
                + (["ghidra.max_parallel_jvms: re-detected"] if force else [])
                + (
                    [f"reset {r}" for r in _force_resets(raw_cfg, desired)]
                    + [f"the current file is backed up first ({config_path.name}.tmap.backup)"]
                    if force and cfg_error is None and config_path.exists()
                    else []
                ),
            )
        )

    # 3. select agents
    if mode == "interactive":
        labels = []
        for cid in cl.CLIENT_IDS:
            st = survey.states[cid]
            bits = ["detected" if st.detected else "not found"]
            if st.state != "missing":
                bits.append(st.state)
            labels.append(f"{cl.LABELS[cid]} ({', '.join(bits)})")
        preselected = [survey.states[c].detected for c in cl.CLIENT_IDS]
        from treasure_map.lib.setup.selector import SelectionAbortedError

        try:
            picks = select(labels, preselected, prompt=prompt, echo=echo, use_tty=use_tty)
        except SelectionAbortedError as exc:
            raise InitAbortedError("aborted; nothing was changed") from exc
        selected = [c for c, on in zip(cl.CLIENT_IDS, picks, strict=True) if on]
    else:
        selected = [c for c in cl.CLIENT_IDS if c in clients]
    for cid in selected:
        st = survey.states[cid]
        label = cl.LABELS[cid]
        if tmap_path is None:
            plan.needs_you.append(
                f"{label}: tmap was not started as `tmap`; register it by hand:\n"
                + cl.manual_text(cid, None)
            )
            continue
        if st.state in ("missing", "stale"):
            plan.add(
                Action(
                    "register_client",
                    f"register treasure-map with {label}",
                    target=st.config_path,
                    lines=[f"command {tmap_path} mcp"]
                    + ([f"replaces a stale entry: {st.detail}"] if st.state == "stale" else [])
                    + (
                        [f"backup {st.config_path}.tmap.backup"]
                        if cid in ("cursor", "claude-desktop")
                        and st.config_path is not None
                        and st.config_path.exists()
                        else []
                    )
                    + (
                        ["restart dsh to load it; tools appear as mcp__treasure-map__*"]
                        if cid == "dsh"
                        else []
                    ),
                    client=cid,
                )
            )
        elif st.state in ("foreign", "invalid", "unknown"):
            plan.needs_you.append(f"{label}: {st.state} — {st.detail}; not modified")
        for d in st.shadowing:
            plan.add(
                Action(
                    "remove_shadowing_entry",
                    f"remove shadowing entry in {d}",
                    target=d,
                    lines=["claude mcp remove -s local treasure-map"],
                    client=cid,
                    project_dir=d,
                )
            )
        if st.state != "aligned":  # a working entry noted where it lives is not a to-do
            for r in st.reported:
                plan.needs_you.append(f"{label}: {r}")

    # 4. confirm
    echo("")
    echo("Plan:")
    # Terse numbered checklist for the confirmation; --dry-run prints the full plan (URLs, sha256).
    for line in plan.render() if dry_run else plan.summary():
        echo(line)
    if not plan.actions:
        echo("  everything current, nothing to do")
    if mode == "interactive":
        names = [cl.LABELS[c] for c in survey.detected()]
        echo(
            f"Pre-selected: agents detected on this machine ({', '.join(names) or 'none'}). "
            "Unselect any you don't want above."
        )
    if g.path is not None or managed_ghidra_home is not None:
        echo(
            "Note: Ghidra records the JDK it last ran with (java_home.save in its settings "
            "directory); a Ghidra 11.4.3 you start yourself without JAVA_HOME may pick that JDK."
        )
    if dry_run:
        echo("Dry run: nothing written.")
        return InitResult(
            config_path,
            env_path,
            tm_home,
            (),
            dry_run=True,
            needs_you=tuple(plan.needs_you),
        )
    if plan.actions and mode == "interactive":
        answer = prompt("Apply? [Y/n]").strip().lower()
        if answer not in ("", "y", "yes"):
            echo("Nothing changed.")
            runs = runs_probe(existing_cfg) if runs_probe is not None else None
            return InitResult(
                config_path,
                env_path,
                tm_home,
                _doctor(existing_cfg, (), runs),
                needs_you=tuple(plan.needs_you),
                runs=runs,
            )

    # 5. apply
    _provision_dirs([tm_home])
    if cfg_error is not None or (force and config_path.exists()):
        echo(f"  Config : backed up to {_backup_config(config_path)}")
    _write_config(config_path, force=force or cfg_error is not None, echo=echo)
    _write_env(env_path, echo=echo)
    _seed_watchlist()

    tres = ToolchainResult(java_home=j.path, ghidra_home=g.path, bindiff=b.path)
    if any(a.kind in TOOLCHAIN_KINDS for a in plan.actions):
        if fetcher is None:
            fetcher = OfflineFetcher(offline) if offline is not None else UrlFetcher()
        tres = apply_toolchain(
            plan,
            host=host,
            lock=lock,
            ledger=ledger,
            fetcher=fetcher,
            mirror=mirror,
            chosen_ghidra=g.path,
            chosen_jdk=j.path,
            echo=echo,
        )
        if tres.bindiff is None:
            tres.bindiff = b.path
    # config keys: only what is in place now
    to_write = dict(changed)
    if _GHIDRA_HOME_KEY in to_write and tres.ghidra_home is None:
        del to_write[_GHIDRA_HOME_KEY]
    elif tres.ghidra_home is not None and _GHIDRA_HOME_KEY in to_write:
        to_write[_GHIDRA_HOME_KEY] = str(tres.ghidra_home)
    if _JAVA_HOME_KEY in to_write and tres.java_home is None:
        del to_write[_JAVA_HOME_KEY]
    if _BINDIFF_KEY in to_write and tres.bindiff is None:
        del to_write[_BINDIFF_KEY]
    if to_write:
        _set_keys(config_path, to_write)
        for k, v in to_write.items():
            echo(f"  Config : {'.'.join(k)} = {v}")
    _configure_parallelism(config_path, force=force, echo=echo)

    cfg, _raw, _err = _read_config(config_path)
    if cfg is not None:
        apply_toolchain_env(cfg)
    _toolchain._current.clear()

    registered: list[str] = []
    needs_you = list(plan.needs_you)

    def _confirm_quit(msg: str) -> None:
        prompt(msg)

    for a in plan.actions:
        if a.kind == "register_client" and a.client is not None:
            try:
                out = cl.register(
                    a.client,
                    chost,
                    tmap_path,
                    confirm_quit=_confirm_quit if mode == "interactive" else None,
                )
            except OSError as exc:  # a permission or disk error: this agent only, reported
                echo(f"  ✗ {cl.LABELS[a.client]}: {exc}")
                needs_you.append(f"{cl.LABELS[a.client]}: could not write its configuration: {exc}")
                continue
            echo(f"  {'✓' if out.ok else '✗'} {cl.LABELS[a.client]}: {out.message}")
            if out.ok:
                registered.append(cl.LABELS[a.client])
            if not out.ok and out.manual:
                needs_you.append(
                    f"{cl.LABELS[a.client]}: {out.message}; add by hand:\n{out.manual}"
                )
        elif a.kind == "remove_shadowing_entry" and a.project_dir is not None:
            try:
                out = cl.remove_shadowing(chost, a.project_dir)
            except OSError as exc:
                echo(f"  ✗ {a.project_dir}: {exc}")
                needs_you.append(f"remove the local-scope entry in {a.project_dir}: {exc}")
                continue
            echo(f"  {'✓' if out.ok else '✗'} {out.message}")
            if not out.ok and out.manual:
                needs_you.append(f"{out.message}; run: {out.manual}")

    script, rc, rc_created = _configure_completion(
        non_interactive=(mode != "interactive"), prompt=prompt, echo=echo
    )
    if script is not None:
        # Keep an rc already recorded: a later run that does not ask (or is declined) must not
        # forget the block an earlier yes added — nor that tmap created that rc, which a run
        # finding the block already there cannot tell. Unchanged -> the ledger is not rewritten.
        prior = ledger.committed("completion")
        prior_rc = prior.extra.get("rc_block") if prior is not None else None
        prior_created = prior is not None and prior.extra.get("rc_created") is True
        rc_block = str(rc) if rc else prior_rc
        created = rc_created or (prior_created and rc_block == prior_rc)
        if (
            prior is None
            or prior.path != str(script)
            or prior_rc != rc_block
            or prior_created != created
        ):
            extra: dict[str, Any] = {"rc_created": True} if created else {}
            ledger.add_pending("completion", "file", script, rc_block=rc_block, **extra)
            ledger.commit("completion")

    if cfg is not None:
        try:
            _provision_dirs(_configured_dirs(cfg))
        except OSError as exc:
            needs_you.append(f"create the atlas and workspace directories: {exc}")
    _source_env_file(env_path)

    # 6. doctor
    runs = runs_probe(cfg) if runs_probe is not None else None
    checks = _doctor(cfg, selected, runs)
    return InitResult(
        config_path,
        env_path,
        tm_home,
        checks,
        failed=bool(tres.failed),
        applied=True,
        nothing_to_do=not plan.actions,
        registered=tuple(registered),
        needs_you=tuple(needs_you + tres.failed),
        runs=runs,
    )
