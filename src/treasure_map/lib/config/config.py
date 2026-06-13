# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import logging
import os
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

from treasure_map.lib.errors import ConfigError

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = Path.home() / ".treasure-map" / "config.yaml"
_LOCAL_CONFIG_PATH = Path("config.yaml")


class TierConfig(BaseModel):
    provider: str
    model: str
    base_url: str
    api_key_env: str
    max_cost_per_call_usd: float = 1.0
    # Tri-state thinking control for DeepSeek-V4 (whose thinking defaults to ENABLED):
    #   None  -> send no thinking param (legacy behavior; correct for Anthropic and any
    #            endpoint we should not touch)
    #   False -> send an explicit disabled (needed to override V4's default-on)
    #   True  -> send enabled (plus reasoning_effort if set)
    thinking: bool | None = None
    reasoning_effort: str | None = None  # "high" | "max"; only sent when thinking is True

    @field_validator("reasoning_effort")
    @classmethod
    def _check_reasoning_effort(cls, v: str | None) -> str | None:
        if v is not None and v not in {"high", "max"}:
            raise ValueError(
                f"reasoning_effort must be 'high' or 'max' (got {v!r}); "
                "per DeepSeek docs low/medium map to high"
            )
        return v

    def resolve_api_key(self) -> str:
        key = os.environ.get(self.api_key_env, "")
        if not key:
            raise ConfigError(
                f"Environment variable '{self.api_key_env}' is not set "
                f"(required for provider '{self.provider}' tier)"
            )
        return key


class TiersConfig(BaseModel):
    S: TierConfig
    M: TierConfig
    L: TierConfig


class CostGuardConfig(BaseModel):
    max_cost_per_run_usd: float = 5.0
    max_cost_per_day_usd: float = 20.0
    require_confirm_above_usd: float = 1.0


class CacheConfig(BaseModel):
    enabled: bool = True
    path: Path = Field(default_factory=lambda: Path.home() / ".treasure-map" / "llm_cache.db")

    @field_validator("path", mode="before")
    @classmethod
    def expand_path(cls, v: Any) -> Path:
        return Path(os.path.expanduser(str(v)))


class AtlasConfig(BaseModel):
    db_path: Path = Field(default_factory=lambda: Path.home() / ".treasure-map" / "atlas.db")

    @field_validator("db_path", mode="before")
    @classmethod
    def expand_path(cls, v: Any) -> Path:
        return Path(os.path.expanduser(str(v)))


class ConcurrencyConfig(BaseModel):
    # DeepSeek-V4 flash supports up to 2500 concurrent requests, pro up to 500. These
    # defaults stay well under those caps (good throughput without hammering the API or a
    # free-tier plan); raise toward the provider cap if your plan allows it.
    S: int = 64  # flash, no thinking — fast; provider cap 2500
    M: int = 32  # flash + thinking — slower per call; provider cap 2500
    L: int = 8  # pro (cap 500) or a low-volume judgment tier (e.g. Claude)


class RetryConfig(BaseModel):
    max_attempts: int = 4
    backoff_base_seconds: float = 5.0


class LLMConfig(BaseModel):
    tiers: TiersConfig
    cost_guards: CostGuardConfig = Field(default_factory=CostGuardConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    concurrency: ConcurrencyConfig = Field(default_factory=ConcurrencyConfig)
    retry: RetryConfig = Field(default_factory=RetryConfig)


class GhidraMode(StrEnum):
    LOCAL = "local"  # M1 implemented
    DOCKER = "docker"  # M4 planned
    REMOTE = "remote"  # M4 planned


class GhidraLocalConfig(BaseModel):
    home: Path | None = None  # None = use discovery mechanism (see ghidra_runner.py)

    @field_validator("home", mode="before")
    @classmethod
    def expand_home(cls, v: Any) -> Path | None:
        if v is None:
            return None
        return Path(os.path.expanduser(str(v)))


class GhidraDockerConfig(BaseModel):
    image: str = "ghcr.io/joeyz/treasure-map-ghidra:11.2"


class GhidraRemoteConfig(BaseModel):
    endpoint: str = "http://localhost:8080"


class GhidraConfig(BaseModel):
    mode: GhidraMode = GhidraMode.LOCAL
    headless_timeout_seconds: int = 300
    max_parallel_jvms: int = 4
    local: GhidraLocalConfig = Field(default_factory=GhidraLocalConfig)
    docker: GhidraDockerConfig = Field(default_factory=GhidraDockerConfig)
    remote: GhidraRemoteConfig = Field(default_factory=GhidraRemoteConfig)


class Config(BaseModel):
    llm: LLMConfig | None = None
    ghidra: GhidraConfig = Field(default_factory=GhidraConfig)
    workspace_dir: Path = Field(
        default_factory=lambda: Path.home() / ".treasure-map" / "workspaces"
    )
    atlas: AtlasConfig = Field(default_factory=AtlasConfig)
    log_level: str = "INFO"

    @field_validator("workspace_dir", mode="before")
    @classmethod
    def expand_workspace(cls, v: Any) -> Path:
        return Path(os.path.expanduser(str(v)))


def _source_env_file(path: Path) -> None:
    """Read key=value pairs from path and set them in os.environ (non-override).

    Already-set env vars are never overwritten. Absent file is a silent no-op.
    Supports: blank lines, # comments, optional 'export ' prefix, single/double quotes.
    """
    if not path.exists():
        return
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:]
        if "=" not in line:
            logger.debug("_source_env_file: skipping malformed line")
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        if key not in os.environ:
            os.environ[key] = value


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def _apply_env_overrides(data: dict[str, Any]) -> dict[str, Any]:
    """Apply TM_* environment variable overrides using __ as nesting separator."""
    for key, value in os.environ.items():
        if not key.startswith("TM_"):
            continue
        parts = key[3:].lower().split("__")
        node: dict[str, Any] = data
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
    return data


def load_config(extra_path: Path | None = None) -> Config:
    """Load config from ~/.treasure-map/config.yaml, ./config.yaml, env vars (in that order)."""
    env_file_override = os.environ.get("TM_ENV_FILE")
    _source_env_file(
        Path(env_file_override) if env_file_override else Path.home() / ".treasure-map" / ".env"
    )

    raw: dict[str, Any] = {}

    for path in [_DEFAULT_CONFIG_PATH, _LOCAL_CONFIG_PATH]:
        if path.exists():
            logger.debug("Loading config from %s", path)
            with path.open() as f:
                loaded = yaml.safe_load(f) or {}
            raw = _deep_merge(raw, loaded)

    if extra_path and extra_path.exists():
        logger.debug("Loading config from %s", extra_path)
        with extra_path.open() as f:
            loaded = yaml.safe_load(f) or {}
        raw = _deep_merge(raw, loaded)

    raw = _apply_env_overrides(raw)

    try:
        return Config.model_validate(raw)
    except Exception as exc:
        raise ConfigError(f"Invalid configuration: {exc}") from exc
