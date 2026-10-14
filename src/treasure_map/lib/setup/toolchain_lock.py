# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The pinned toolchain: the one place the versions, download URLs and checksums are written.

``toolchain_lock.json`` (shipped beside this module) names, per component and per platform, the
archive ``tmap init`` may download, its exact size and sha256, and how it unpacks. Nothing else
in tmap writes a version or a URL for the toolchain. A value still reading ``<…>`` is a
placeholder for an artifact not published yet: that component is reported unavailable, never
skipped in silence and never fetched.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

from treasure_map.lib.errors import ConfigError

COMPONENTS = ("jdk", "ghidra", "binexport", "bindiff")
_KINDS = ("tar.gz", "zip", "deb", "dmg-pkg")


class LockError(ConfigError):
    """The lock file is malformed, or names no asset for this platform."""


@dataclass(frozen=True)
class Asset:
    url: str
    sha256: str
    size: int
    kind: str  # tar.gz | zip | deb | dmg-pkg
    root: str | None = None  # the archive's single top-level directory
    java_home: str | None = None  # jdk: the JDK root, relative to the install directory's parent
    member_prefix: str | None = None  # deb: the only members unpacked
    exe: str | None = None  # bindiff: the executable, relative to the install directory
    app: str | None = None  # dmg-pkg: the .app bundle to copy out of the package

    @property
    def file_name(self) -> str:
        from urllib.parse import unquote, urlparse

        return unquote(Path(urlparse(self.url).path).name)


@dataclass(frozen=True)
class Component:
    name: str
    version: str
    assets: dict[str, Asset]
    source_commit: str | None = None
    lib_digest: str | None = None
    version_line: str | None = None


@dataclass(frozen=True)
class Lock:
    components: dict[str, Component]

    def component(self, name: str) -> Component:
        return self.components[name]


def is_placeholder(value: object) -> bool:
    return isinstance(value, str) and value.startswith("<")


def unavailable_reason(component: Component, asset: Asset) -> str | None:
    """Why this asset cannot be installed yet, or None when it can: a placeholder value (the
    artifact is not published) or a missing size."""
    values: list[object] = [asset.url, asset.sha256, component.lib_digest]
    if any(is_placeholder(v) for v in values) or asset.size <= 0:
        label = "BinExport" if component.name == "binexport" else component.name
        return f"unavailable: {label} artifact not published yet"
    return None


def placeholders(lock: Lock) -> list[str]:
    """Every placeholder (or zero size) left in the lock, as ``component.field`` — what the
    release workflow refuses to ship."""
    out: list[str] = []
    for comp in lock.components.values():
        for field in ("source_commit", "lib_digest", "version_line"):
            if is_placeholder(getattr(comp, field)):
                out.append(f"{comp.name}.{field}")
        for plat, asset in comp.assets.items():
            for field in ("url", "sha256"):
                if is_placeholder(getattr(asset, field)):
                    out.append(f"{comp.name}.{plat}.{field}")
            if asset.size <= 0:
                out.append(f"{comp.name}.{plat}.size")
    return out


def _asset(name: str, plat: str, raw: Any) -> Asset:
    if not isinstance(raw, dict):
        raise LockError(f"lock: {name}.{plat} is not an object")
    for key in ("url", "sha256", "size", "kind"):
        if key not in raw:
            raise LockError(f"lock: {name}.{plat} has no {key}")
    if raw["kind"] not in _KINDS:
        raise LockError(f"lock: {name}.{plat} has unknown kind {raw['kind']!r}")
    if not isinstance(raw["size"], int):
        raise LockError(f"lock: {name}.{plat}.size is not an integer")
    known = {"url", "sha256", "size", "kind", "root", "java_home", "member_prefix", "exe", "app"}
    extra = set(raw) - known
    if extra:
        raise LockError(f"lock: {name}.{plat} has unknown keys {sorted(extra)}")
    return Asset(**raw)


def parse_lock(data: Any) -> Lock:
    if not isinstance(data, dict) or data.get("schema") != 1:
        raise LockError("lock: schema is not 1")
    comps = data.get("components")
    if not isinstance(comps, dict) or set(comps) != set(COMPONENTS):
        raise LockError(f"lock: components must be exactly {COMPONENTS}")
    out: dict[str, Component] = {}
    for name in COMPONENTS:
        raw = comps[name]
        if not isinstance(raw, dict) or not isinstance(raw.get("version"), str):
            raise LockError(f"lock: {name} has no version")
        assets_raw = raw.get("assets")
        if not isinstance(assets_raw, dict) or not assets_raw:
            raise LockError(f"lock: {name} has no assets")
        out[name] = Component(
            name=name,
            version=raw["version"],
            assets={plat: _asset(name, plat, a) for plat, a in assets_raw.items()},
            source_commit=raw.get("source_commit"),
            lib_digest=raw.get("lib_digest"),
            version_line=raw.get("version_line"),
        )
    return Lock(components=out)


def load_lock(path: Path | None = None) -> Lock:
    """The shipped lock (or the one at ``path``), validated."""
    if path is None:
        text = files("treasure_map.lib.setup").joinpath("toolchain_lock.json").read_text()
    else:
        text = path.read_text()
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise LockError(f"lock: not JSON: {exc}") from exc
    return parse_lock(data)


def asset_for(lock: Lock, component: str, platform_key: str) -> Asset:
    """The asset for ``platform_key``: an exact match first, then ``<os>-*``, then ``*``. No
    match is an error — never another platform's archive."""
    assets = lock.component(component).assets
    os_name = platform_key.split("-", 1)[0]
    for key in (platform_key, f"{os_name}-*", "*"):
        if key in assets:
            return assets[key]
    raise LockError(f"no {component} build is pinned for {platform_key}")
