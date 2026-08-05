# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Onboarding initializer — local setup only; no network calls."""

from __future__ import annotations

import logging
import os
import shutil
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from treasure_map.lib.config.config import Config, _source_env_file

logger = logging.getLogger(__name__)

# Default config matching config.example.yaml; stores env var names, never values.
# max_parallel_jvms is deliberately ABSENT here: _configure_parallelism probes the machine at init
# and writes the derived value (a hardcoded default would mask a wrong-sized pool). If it were ever
# missing from config.yaml, config.py's GhidraConfig default (4) is the safety fallback.
_DEFAULT_CONFIG_YAML: dict[str, Any] = {
    "ghidra": {
        "mode": "local",
        "headless_timeout_seconds": 300,
        "local": {"home": None},
    },
    "workspace_dir": "~/.treasure-map/workspaces",
    "atlas": {"db_path": "~/.treasure-map/atlas.db"},
    "log_level": "INFO",
}


@dataclass(frozen=True)
class InitResult:
    """Outcome of run_init; checks is a sequence of (name, ok, detail) triples."""

    config_path: Path
    env_path: Path
    atlas_dir: Path
    checks: tuple[tuple[str, bool, str], ...]


def _collect_default_env_vars() -> list[str]:
    """API key env var names to scaffold into .env.

    The tool ships no built-in secrets — analysis is hermetic (no network calls), so there
    are no default keys to provision. Returns an empty list; the .env scaffold stays a bare
    placeholder the operator can add their own TM_* / env vars to.
    """
    return []


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
    config_path.write_text(yaml.safe_dump(_DEFAULT_CONFIG_YAML, default_flow_style=False))


def _existing_env_keys(env_path: Path) -> set[str]:
    """Return the variable names already present in an existing .env (KEY=value lines)."""
    keys: set[str] = set()
    for line in env_path.read_text().splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            keys.add(stripped.split("=", 1)[0].strip())
    return keys


def _write_env(
    env_path: Path,
    *,
    env_vars: list[str],
    prompt: Callable[[str], str],
    non_interactive: bool,
    echo: Callable[[str], None] = _noop_echo,
) -> None:
    """Write .env on first run; on a re-run never clobber existing secrets (idempotent).

    If .env already exists, present keys are preserved untouched and only configured vars
    that are MISSING are prompted for and appended — pressing Enter on a re-run can never
    wipe a saved key. This is independent of --force: init never regenerates or deletes .env.
    """
    env_path.parent.mkdir(parents=True, exist_ok=True)

    if env_path.exists():
        present = _existing_env_keys(env_path)
        missing = [v for v in env_vars if v not in present]
        if non_interactive or not missing:
            echo(f"  Secrets: keeping existing .env ({len(present)} keys).")
            return
        appended: list[str] = []
        for var_name in missing:
            value = prompt(f"Enter value for {var_name} (press Enter to skip)").strip()
            if value:
                appended.append(f"{var_name}={value}\n")
        if appended:
            with env_path.open("a") as fh:
                fh.write("".join(appended))
        echo(f"  Secrets: kept existing .env ({len(present)} keys), added {len(appended)}.")
        os.chmod(env_path, 0o600)
        return

    lines: list[str] = []
    for var_name in env_vars:
        value = (
            ""
            if non_interactive
            else prompt(f"Enter value for {var_name} (press Enter to skip)").strip()
        )
        if value:
            lines.append(f"{var_name}={value}\n")
    env_path.write_text("".join(lines))
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


def _configured_ghidra_home(config_path: Path) -> Path | None:
    """Return ghidra.local.home from an existing config.yaml, or None if unset/unreadable."""
    if not config_path.exists():
        return None
    try:
        data: dict[str, Any] = yaml.safe_load(config_path.read_text()) or {}
    except Exception:
        return None
    home = (data.get("ghidra") or {}).get("local", {}).get("home")
    return Path(os.path.expanduser(home)) if home else None


def _set_ghidra_home(config_path: Path, home: Path) -> None:
    """Write ghidra.local.home into config.yaml, preserving the rest of the file."""
    data: dict[str, Any] = yaml.safe_load(config_path.read_text()) or {}
    data.setdefault("ghidra", {}).setdefault("local", {})["home"] = str(home)
    config_path.write_text(yaml.safe_dump(data, default_flow_style=False))


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


def _set_workspace_dir(config_path: Path, value: str) -> None:
    """Write the top-level workspace_dir into config.yaml, preserving the rest of the file."""
    data: dict[str, Any] = yaml.safe_load(config_path.read_text()) or {}
    data["workspace_dir"] = value
    config_path.write_text(yaml.safe_dump(data, default_flow_style=False))


def _configure_workspace_dir(
    config_path: Path,
    *,
    non_interactive: bool,
    prompt: Callable[[str], str],
    echo: Callable[[str], None],
) -> None:
    """Confirm (or change) the workspace base directory; persist any override to config.yaml.

    Shows the current value (existing config value, else the default), lets the user press
    Enter to keep it or type a new path. Idempotent per R0e: re-init shows the existing value
    and does not clobber it; non-interactive keeps it with no prompt. Single-colon prompt (R0d).
    """
    current = _configured_workspace_dir(config_path)
    if non_interactive:
        echo(f"  Workspace base: {current}")
        return
    entered = prompt(f"Workspace base directory [{current}], Enter to keep").strip()
    if not entered:
        echo(f"  Workspace base: {current} (kept)")
        return
    _set_workspace_dir(config_path, entered)
    echo(f"  Workspace base: {entered} (saved)")


def _configure_ghidra(
    config_path: Path,
    *,
    non_interactive: bool,
    prompt: Callable[[str], str],
    echo: Callable[[str], None],
) -> None:
    """Detect Ghidra, or (interactively) prompt for and validate its install root.

    Auto-detect first (GHIDRA_HOME / PATH via the headless discovery); if found, accept it
    without prompting and PERSIST the resolved install root to config.yaml, so a later analyze
    in a new shell (where GHIDRA_HOME/PATH may be gone) still finds it. If not found, prompt for
    the install root and validate it contains support/analyzeHeadless before writing
    ghidra.local.home. Non-interactive or blank input leaves config unset (run-time
    auto-discovery), never blocking. This writes a path only — it never touches secrets.
    """
    from treasure_map.lib.analyze.ghidra_runner import find_headless
    from treasure_map.lib.config.config import GhidraConfig
    from treasure_map.lib.errors import GhidraNotFoundError

    # Existing config wins: find_headless(GhidraConfig()) only checks GHIDRA_HOME/PATH, so a
    # path already saved in config.yaml would otherwise be ignored and re-prompted in a new
    # shell. Net effective order: existing config -> GHIDRA_HOME -> PATH -> prompt.
    existing = _configured_ghidra_home(config_path)
    if existing is not None and (existing / "support" / "analyzeHeadless").exists():
        echo(f"  Ghidra : already configured at {existing}")
        return

    try:
        headless = find_headless(GhidraConfig())
        # headless is <root>/support/analyzeHeadless; its grandparent is the install root.
        root = headless.parent.parent
        _set_ghidra_home(config_path, root)
        echo(f"  Ghidra : found at {headless} — saved to config")
        return
    except GhidraNotFoundError:
        pass

    if non_interactive:
        echo("  Ghidra : not found; left unset (auto-discovery runs at analyze time).")
        return

    echo("  Ghidra : not auto-detected.")
    for _ in range(2):  # one prompt plus one retry on an invalid path
        entered = prompt(
            "Enter Ghidra install root (dir containing support/analyzeHeadless), Enter to skip"
        ).strip()
        if not entered:
            echo("  Ghidra : left unset (auto-discovery runs at analyze time).")
            return
        root = Path(os.path.expanduser(entered))
        if (root / "support" / "analyzeHeadless").exists():
            _set_ghidra_home(config_path, root)
            echo(f"  Ghidra : configured {root}")
            return
        echo(f"  Ghidra : {root} has no support/analyzeHeadless — try again or Enter to skip.")
    echo("  Ghidra : left unset (no valid path entered).")


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
    config_path.write_text(yaml.safe_dump(data, default_flow_style=False))


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
        mem_total_mb,
        physical_cores,
    )

    current = _configured_max_parallel(config_path)
    if current is not None and not force:
        echo(f"  Parallelism: max_parallel_jvms={current} (kept; --force to re-detect).")
        return
    probe = physical_cores()
    mem = mem_total_mb()
    derived = derive_parallelism(probe.count, mem)
    _set_max_parallel(config_path, derived)
    echo(
        f"  Parallelism: detected {probe.count} physical cores ({probe.method}) / {mem}MB "
        f"-> max_parallel_jvms={derived}."
    )


def _configure_completion(
    *,
    non_interactive: bool,
    prompt: Callable[[str], str],
    echo: Callable[[str], None],
) -> None:
    """Install shell tab-completion (a standard init step; bash + zsh). Best-effort + honest.

    The script goes to the shell's own autoload directory. When that alone will not make the shell
    load it, an INTERACTIVE init then asks (Y/N, Enter = yes) and appends a marked, idempotent block
    to the rc only on a yes; a decline — and every non-interactive run — writes no rc and just
    prints the one line to add. init never changes an rc the user did not agree to.

    Any failure is echoed, never swallowed, and the doctor's ``completion`` check reports the state
    (installed / active / the one line to add). No ``--no-completion`` flag: a completion script has
    no side effects, so a skip toggle would only push a non-decision onto the user.
    """
    from treasure_map.lib.setup.completion import detect_shell, install_completion

    shell = detect_shell()
    if shell is None:
        echo("  Completion: shell is not bash/zsh — skipped (nothing to install).")
        return
    try:
        outcome = install_completion(shell, Path.home())
    except OSError as exc:
        echo(f"  Completion: could not install for {shell}: {exc}")
        return
    if outcome is None:
        echo(f"  Completion: no installer for {shell} — skipped.")
        return
    state = "installed" if outcome.wrote else "already up to date"
    echo(f"  Completion: {state} for {shell} at {outcome.path}")
    if not outcome.active and outcome.activation_hint:
        _offer_activation(
            shell,
            outcome.path,
            outcome.activation_hint,
            non_interactive=non_interactive,
            prompt=prompt,
            echo=echo,
        )


def _offer_activation(
    shell: str,
    script_path: Path,
    hint: str,
    *,
    non_interactive: bool,
    prompt: Callable[[str], str],
    echo: Callable[[str], None],
) -> None:
    """Ask whether to add the activation line to the rc, and add it only on a yes.

    Non-interactive runs never ask and never write — an unattended init changing a shell rc is
    precisely the no-consent edit the rule forbids, and there is nobody there to agree. Ambiguous
    input is treated as no: only Enter / y / yes writes, so an unrecognised answer errs toward
    leaving the user's file alone.
    """
    from treasure_map.lib.setup.completion import activate_completion, rc_path

    rc = rc_path(shell, Path.home())
    if non_interactive or rc is None:
        echo(f"              to activate, {hint}")
        return
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
        return
    result = activate_completion(shell, Path.home(), script_path)
    if result is None or not result.ok:
        detail = f": {result.error}" if result is not None and result.error else ""
        echo(f"              could not write ~/{rc.name}{detail}")
        echo(f"              to activate, {hint}")
        return
    if result.already:
        echo(f"              ~/{rc.name} already has the tmap block — nothing to add.")
        return
    echo(
        f"              added to ~/{rc.name} — restart your shell or run "
        f"`source ~/{rc.name}` to activate now."
    )


def _run_doctor(tm_home: Path, cfg: Config | None) -> tuple[tuple[str, bool, str], ...]:
    """Run preflight checks and return (name, ok, detail) triples."""
    checks: list[tuple[str, bool, str]] = []

    # Ghidra
    if cfg is not None:
        try:
            from treasure_map.lib.analyze.ghidra_runner import find_headless

            headless = find_headless(cfg.ghidra)
            checks.append(("ghidra", True, str(headless)))
        except Exception as exc:
            checks.append(("ghidra", False, str(exc).split("\n")[0]))
    else:
        checks.append(("ghidra", False, "config unavailable"))

    # JDK 21
    java = shutil.which("java")
    checks.append(("java", java is not None, java or "not on PATH"))

    # Dirs writable — check the config-resolved locations (same ones run_init provisions).
    ws_path = cfg.workspace_dir if cfg is not None else tm_home / "workspaces"
    atlas_path = cfg.atlas.db_path.parent if cfg is not None else tm_home
    for label, path in [("atlas_dir", atlas_path), ("workspace_dir", ws_path)]:
        if path.exists():
            ok = os.access(path, os.W_OK)
            checks.append((label, ok, "writable" if ok else "not writable"))
        else:
            checks.append((label, False, "not provisioned"))

    # Shell completion: installed AND active? (honest — an inert completion is not presented clean.)
    from treasure_map.lib.setup.completion import completion_check

    checks.append(completion_check(Path.home()))

    return tuple(checks)


def run_init(
    *,
    force: bool = False,
    non_interactive: bool = False,
    check_only: bool = False,
    prompt: Callable[[str], str],
    echo: Callable[[str], None] = _noop_echo,
) -> InitResult:
    """Set up ~/.treasure-map/ with config.yaml, .env, and run preflight checks.

    No network calls. check_only=True inspects existing state without writing anything.
    echo, if given, receives human-readable progress lines (e.g. the Ghidra step).
    """
    tm_home = Path.home() / ".treasure-map"
    config_path = tm_home / "config.yaml"
    env_path = tm_home / ".env"
    atlas_dir = tm_home

    if not check_only:
        _provision_dirs([tm_home])
        _write_config(config_path, force=force, echo=echo)
        _write_env(
            env_path,
            env_vars=_collect_default_env_vars(),
            prompt=prompt,
            non_interactive=non_interactive,
            echo=echo,
        )
        _seed_watchlist()
        _configure_ghidra(
            config_path,
            non_interactive=non_interactive,
            prompt=prompt,
            echo=echo,
        )
        _configure_workspace_dir(
            config_path,
            non_interactive=non_interactive,
            prompt=prompt,
            echo=echo,
        )
        _configure_parallelism(config_path, force=force, echo=echo)
        # Before the doctor below: a yes here appends the activation line, so the preflight then
        # reads an rc that is genuinely set up and reports ✅ rather than a stale ❌.
        _configure_completion(non_interactive=non_interactive, prompt=prompt, echo=echo)

    # Source env file (non-override semantics) so doctor can see API keys.
    _source_env_file(env_path)

    # Load config from tm_home directly (avoids module-level _DEFAULT_CONFIG_PATH).
    cfg: Config | None = None
    if config_path.exists():
        try:
            raw: dict[str, Any] = yaml.safe_load(config_path.read_text()) or {}
            cfg = Config.model_validate(raw)
        except Exception:
            logger.debug("run_init: config load failed at %s", config_path)

    # Provision the config-resolved paths now that cfg is known, then run the doctor
    # against those same paths — provision and check can no longer disagree.
    if not check_only and cfg is not None:
        _provision_dirs(_configured_dirs(cfg))

    checks = _run_doctor(tm_home, cfg)
    return InitResult(
        config_path=config_path,
        env_path=env_path,
        atlas_dir=atlas_dir,
        checks=checks,
    )
