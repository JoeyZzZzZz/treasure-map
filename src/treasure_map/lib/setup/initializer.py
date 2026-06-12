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
_DEFAULT_CONFIG_YAML: dict[str, Any] = {
    "llm": {
        "tiers": {
            "S": {
                "provider": "deepseek",
                "model": "deepseek-chat",
                "base_url": "https://api.deepseek.com",
                "api_key_env": "DEEPSEEK_API_KEY",
                "max_cost_per_call_usd": 0.01,
            },
            "M": {
                "provider": "deepseek",
                "model": "deepseek-reasoner",
                "base_url": "https://api.deepseek.com",
                "api_key_env": "DEEPSEEK_API_KEY",
                "max_cost_per_call_usd": 0.10,
            },
            "L": {
                "provider": "anthropic",
                "model": "claude-opus-4-7",
                "base_url": "https://api.anthropic.com/v1",
                "api_key_env": "ANTHROPIC_API_KEY",
                "max_cost_per_call_usd": 1.00,
            },
        },
        "cost_guards": {
            "max_cost_per_run_usd": 5.0,
            "max_cost_per_day_usd": 20.0,
            "require_confirm_above_usd": 1.0,
        },
        "cache": {"enabled": True, "path": "~/.treasure-map/llm_cache.db"},
        "concurrency": {"S": 8, "M": 20, "L": 5},
        "retry": {"max_attempts": 4, "backoff_base_seconds": 5.0},
    },
    "ghidra": {
        "mode": "local",
        "headless_timeout_seconds": 300,
        "max_parallel_jvms": 4,
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
    """Return unique api_key_env names from _DEFAULT_CONFIG_YAML tiers, in order."""
    seen: dict[str, None] = {}
    for tier in _DEFAULT_CONFIG_YAML.get("llm", {}).get("tiers", {}).values():
        name = str(tier.get("api_key_env", ""))
        if name:
            seen[name] = None
    return list(seen)


def _provision_dirs(paths: Iterable[Path]) -> None:
    for d in paths:
        d.mkdir(parents=True, exist_ok=True)


def _configured_dirs(cfg: Config) -> list[Path]:
    """Resolve the directories named by the loaded config (provisioned == checked).

    Using the config-resolved paths here — and the same ones in the doctor — keeps
    provisioning and preflight consistent regardless of HOME vs Path.home() drift.
    """
    dirs = [cfg.workspace_dir, cfg.atlas.db_path.parent]
    if cfg.llm is not None:
        dirs.append(cfg.llm.cache.path.parent)
    return dirs


def _write_config(config_path: Path, *, force: bool) -> None:
    if config_path.exists() and not force:
        raise FileExistsError(f"{config_path} already exists — pass --force to overwrite")
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(yaml.safe_dump(_DEFAULT_CONFIG_YAML, default_flow_style=False))


def _write_env(
    env_path: Path,
    *,
    env_vars: list[str],
    prompt: Callable[[str], str],
    non_interactive: bool,
) -> None:
    env_path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for var_name in env_vars:
        value = (
            ""
            if non_interactive
            else prompt(f"Enter value for {var_name} (press Enter to skip): ").strip()
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

    # binwalk
    bw = shutil.which("binwalk")
    checks.append(("binwalk", bw is not None, bw or "not on PATH"))

    # API keys — per configured tier, deduplicated by api_key_env
    if cfg is not None and cfg.llm is not None:
        seen_keys: set[str] = set()
        for tier_name in ("S", "M", "L"):
            tier = getattr(cfg.llm.tiers, tier_name)
            if tier.api_key_env in seen_keys:
                continue
            seen_keys.add(tier.api_key_env)
            try:
                tier.resolve_api_key()
                checks.append((f"key:{tier.api_key_env}", True, "set"))
            except Exception:
                checks.append((f"key:{tier.api_key_env}", False, f"{tier.api_key_env} not set"))

    # Dirs writable — check the config-resolved locations (same ones run_init provisions).
    ws_path = cfg.workspace_dir if cfg is not None else tm_home / "workspaces"
    atlas_path = cfg.atlas.db_path.parent if cfg is not None else tm_home
    for label, path in [("atlas_dir", atlas_path), ("workspace_dir", ws_path)]:
        if path.exists():
            ok = os.access(path, os.W_OK)
            checks.append((label, ok, "writable" if ok else "not writable"))
        else:
            checks.append((label, False, "not provisioned"))

    return tuple(checks)


def run_init(
    *,
    force: bool = False,
    non_interactive: bool = False,
    check_only: bool = False,
    prompt: Callable[[str], str],
) -> InitResult:
    """Set up ~/.treasure-map/ with config.yaml, .env, and run preflight checks.

    No network calls. check_only=True inspects existing state without writing anything.
    """
    tm_home = Path.home() / ".treasure-map"
    config_path = tm_home / "config.yaml"
    env_path = tm_home / ".env"
    atlas_dir = tm_home

    if not check_only:
        _provision_dirs([tm_home])
        _write_config(config_path, force=force)
        _write_env(
            env_path,
            env_vars=_collect_default_env_vars(),
            prompt=prompt,
            non_interactive=non_interactive,
        )
        _seed_watchlist()

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
