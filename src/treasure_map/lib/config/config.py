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


class AtlasConfig(BaseModel):
    db_path: Path = Field(default_factory=lambda: Path.home() / ".treasure-map" / "atlas.db")

    @field_validator("db_path", mode="before")
    @classmethod
    def expand_path(cls, v: Any) -> Path:
        return Path(os.path.expanduser(str(v)))


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
