# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
import logging
import os
from enum import StrEnum
from pathlib import Path
from typing import Any, TypeGuard

import yaml
from pydantic import BaseModel, Field, field_validator

from treasure_map.lib.errors import ConfigError

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = Path.home() / ".treasure-map" / "config.yaml"


class AtlasConfig(BaseModel):
    db_path: Path = Field(default_factory=lambda: Path.home() / ".treasure-map" / "atlas.db")

    @field_validator("db_path", mode="before")
    @classmethod
    def expand_path(cls, v: Any) -> Path:
        return Path(os.path.expanduser(str(v)))


class GhidraMode(StrEnum):
    LOCAL = "local"  # the only implemented mode
    DOCKER = "docker"  # accepted by the schema, not implemented
    REMOTE = "remote"  # accepted by the schema, not implemented


class GhidraLocalConfig(BaseModel):
    home: Path | None = None  # None = use discovery mechanism (see ghidra_runner.py)

    @field_validator("home", mode="before")
    @classmethod
    def expand_home(cls, v: Any) -> Path | None:
        if v is None:
            return None
        return Path(os.path.expanduser(str(v)))


class GhidraDockerConfig(BaseModel):
    # No default image: the docker mode is not implemented yet, and the previous default named a
    # tag that does not exist. A wrong default is worse than none — it would fail at pull time with
    # a confusing "manifest unknown" instead of an honest "you have not configured an image".
    image: str = ""


class GhidraRemoteConfig(BaseModel):
    endpoint: str = "http://localhost:8080"


class GhidraConfig(BaseModel):
    mode: GhidraMode = GhidraMode.LOCAL  # not read; accepted so an older config.yaml still loads
    headless_timeout_seconds: int = 300
    max_parallel_jvms: int = 4
    local: GhidraLocalConfig = Field(default_factory=GhidraLocalConfig)
    docker: GhidraDockerConfig = Field(default_factory=GhidraDockerConfig)
    remote: GhidraRemoteConfig = Field(default_factory=GhidraRemoteConfig)


class ToolchainConfig(BaseModel):
    """Where the JDK and BinDiff that tmap runs live. ``tmap init`` writes these; when one is set,
    every tmap command puts it first in its own environment (``JAVA_HOME`` and ``PATH``) before
    starting Ghidra or BinDiff. None = leave the environment as it is."""

    java_home: Path | None = None  # a JDK root (bin/java and bin/javac)
    bindiff: Path | None = None  # the bindiff executable

    @field_validator("java_home", "bindiff", mode="before")
    @classmethod
    def expand_path(cls, v: Any) -> Path | None:
        if v is None:
            return None
        return Path(os.path.expanduser(str(v)))


class Config(BaseModel):
    ghidra: GhidraConfig = Field(default_factory=GhidraConfig)
    toolchain: ToolchainConfig = Field(default_factory=ToolchainConfig)
    workspace_dir: Path = Field(
        default_factory=lambda: Path.home() / ".treasure-map" / "workspaces"
    )
    atlas: AtlasConfig = Field(default_factory=AtlasConfig)
    log_level: str = "INFO"  # not read; accepted so an older config.yaml still loads
    # L0 xref fold threshold (edge contribution = callers × exporters). A high-fan-out symbol
    # above this is folded into the xref_folded_symbols ledger instead of exploding the xrefs table.
    # Keep in sync with xrefs.DEFAULT_FOLD_EDGE_THRESHOLD (a unit test asserts equality). Tune down
    # from the ledger produced on real large firmware if bombs slip under it.
    xref_fold_edge_threshold: int = 25_000

    @field_validator("workspace_dir", mode="before")
    @classmethod
    def expand_workspace(cls, v: Any) -> Path:
        return Path(os.path.expanduser(str(v)))


def _source_env_file(path: Path) -> None:
    """Read key=value pairs from path and set them in os.environ (non-override).

    Already-set env vars are never overwritten. Absent file is a silent no-op.
    Supports: blank lines, # comments, optional 'export ' prefix, single/double quotes.

    A relative path given to a ``TM_*`` variable that sets a path key (``PATH_KEYS``) is read from
    this file's directory, as a config file's is, and set already absolute: a child process
    inherits it absolute too.
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
            if key.startswith("TM_") and _env_keys(key) in PATH_KEYS and _is_relative(value):
                value = str(path.absolute().parent / value)
            os.environ[key] = value


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def _env_keys(name: str) -> tuple[str, ...]:
    """The config key a ``TM_*`` variable sets: ``TM_ATLAS__DB_PATH`` sets atlas.db_path."""
    return tuple(name[3:].lower().split("__"))


def _relative_env_path(name: str, value: str) -> ConfigError:
    return ConfigError(
        f"{name}={value!r} is a relative path; give it absolute or starting with ~ (a path in "
        "the environment has no file to be read from, and tmap never reads one from the working "
        "directory)"
    )


def _apply_env_overrides(data: dict[str, Any]) -> dict[str, Any]:
    """Apply TM_* environment variable overrides using __ as nesting separator.

    A path key (``PATH_KEYS``) must be given absolute or starting with ``~``: a relative one is a
    ConfigError naming the variable. A ``.env`` has already made its own relative paths absolute
    (``_source_env_file``)."""
    for key, value in os.environ.items():
        if not key.startswith("TM_"):
            continue
        parts = _env_keys(key)
        if parts in PATH_KEYS and _is_relative(value):
            raise _relative_env_path(key, value)
        node: dict[str, Any] = data
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
    return data


# The keys whose values are filesystem paths.
PATH_KEYS: tuple[tuple[str, ...], ...] = (
    ("ghidra", "local", "home"),
    ("toolchain", "java_home"),
    ("toolchain", "bindiff"),
    ("workspace_dir",),
    ("atlas", "db_path"),
)


def _is_relative(value: object) -> TypeGuard[str]:
    """A non-empty path string that is neither absolute nor ``~``-based."""
    return isinstance(value, str) and bool(value) and not os.path.isabs(os.path.expanduser(value))


def resolve_relative_paths(data: dict[str, Any], config_file: Path) -> dict[str, Any]:
    """A copy of ``data`` — one config file's mapping — with every relative path under
    ``PATH_KEYS`` made absolute against the directory ``config_file`` is in. A ``~`` path counts as
    absolute; anything else is left as it is.

    Never against the working directory: that is wherever tmap happens to run, often inside an
    unpacked, untrusted firmware tree, and a path in a config file would then name a different
    Ghidra or atlas from one directory to the next."""
    out = copy.deepcopy(data)
    base = config_file.absolute().parent
    for keys in PATH_KEYS:
        node: Any = out
        for k in keys[:-1]:
            node = node.get(k) if isinstance(node, dict) else None
        value = node.get(keys[-1]) if isinstance(node, dict) else None
        if _is_relative(value):
            node[keys[-1]] = str(base / value)
    return out


def _merge_file(raw: dict[str, Any], path: Path) -> dict[str, Any]:
    """``raw`` with one config file merged over it, its relative paths read from its own
    directory (``resolve_relative_paths``). Every way the file can fail — unreadable, not YAML,
    not a mapping where a mapping is expected — is a ConfigError naming the file, so a bad config
    surfaces as one exception type."""
    try:
        with path.open() as f:
            loaded = yaml.safe_load(f) or {}
        if not isinstance(loaded, dict):
            raise TypeError(f"top level is a {type(loaded).__name__}, not a mapping")
        return _deep_merge(raw, resolve_relative_paths(loaded, path))
    except (OSError, yaml.YAMLError, TypeError, AttributeError, ValueError) as exc:
        raise ConfigError(f"Invalid configuration in {path}: {exc}") from exc


def load_config(extra_path: Path | None = None) -> Config:
    """Load config from ~/.treasure-map/config.yaml, then ``extra_path`` (``-c``), then TM_* env
    vars, each over the last. A relative path in a file — a config file or the ``.env`` — is read
    from that file's directory. A path in the environment itself (a ``TM_*`` path key, and
    ``TM_ENV_FILE``) must be absolute or start with ``~``; a relative one is a ConfigError.

    Never from the working directory: tmap is run inside unpacked, untrusted firmware trees, and a
    ``config.yaml`` there would choose the Ghidra it executes and what goes first on PATH."""
    env_file_override = os.environ.get("TM_ENV_FILE")
    if _is_relative(env_file_override):
        raise _relative_env_path("TM_ENV_FILE", env_file_override)
    _source_env_file(
        Path(env_file_override) if env_file_override else Path.home() / ".treasure-map" / ".env"
    )

    raw: dict[str, Any] = {}

    paths = [_DEFAULT_CONFIG_PATH]
    if extra_path is not None:
        paths.append(extra_path)
    for path in paths:
        if path.exists():
            logger.debug("Loading config from %s", path)
            raw = _merge_file(raw, path)

    raw = _apply_env_overrides(raw)

    try:
        return Config.model_validate(raw)
    except Exception as exc:
        raise ConfigError(f"Invalid configuration: {exc}") from exc
