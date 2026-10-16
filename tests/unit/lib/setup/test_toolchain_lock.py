# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The pinned toolchain lock: the shipped file parses, assets resolve per platform and never
across platforms, and placeholders are visible."""

from __future__ import annotations

import pytest

from treasure_map.lib.setup.toolchain_lock import (
    LockError,
    asset_for,
    load_lock,
    placeholders,
    unavailable_reason,
)


def test_the_shipped_lock_parses_and_pins_each_platform() -> None:
    lock = load_lock()
    assert lock.component("ghidra").version == "11.4.3"
    assert asset_for(lock, "jdk", "linux-x86_64").java_home == "jdk-21.0.12.1+1"
    assert asset_for(lock, "jdk", "darwin-arm64").java_home == "jdk-21.0.12.1+1/Contents/Home"
    assert asset_for(lock, "bindiff", "darwin-arm64").kind == "dmg-pkg"  # via darwin-*
    assert asset_for(lock, "bindiff", "linux-x86_64").kind == "deb"
    assert asset_for(lock, "ghidra", "darwin-x86_64").kind == "zip"  # via *
    assert asset_for(lock, "ghidra", "linux-x86_64").file_name == (
        "ghidra_11.4.3_PUBLIC_20251203.zip"
    )


def test_no_asset_for_a_platform_is_an_error_never_another_platforms() -> None:
    """MUTATION: fall back to any asset of the component -> linux-aarch64 gets the amd64 deb ->
    RED."""
    lock = load_lock()
    with pytest.raises(LockError):
        asset_for(lock, "bindiff", "linux-aarch64")
    with pytest.raises(LockError):
        asset_for(lock, "jdk", "linux-aarch64")


def test_the_binexport_artifact_is_published_and_the_lock_has_no_placeholders() -> None:
    """The shipped lock pins a real, published BinExport build: the component resolves (no
    unavailable reason) and the lock carries no placeholder or zero-size field anywhere, so the
    release workflow's lock check has nothing left to refuse. Flipped from the pre-publish state
    when the BinExport build was pinned into the lock.

    MUTATION: blank any one of binexport's lib_digest / sha256 / size back to a placeholder (or 0)
    -> that field reappears in placeholders(lock) and the `== []` assertion fails."""
    lock = load_lock()
    comp = lock.component("binexport")
    asset = asset_for(lock, "binexport", "linux-x86_64")
    assert unavailable_reason(comp, asset) is None
    left = placeholders(lock)
    assert "binexport.lib_digest" not in left
    assert "binexport.*.sha256" not in left
    assert "binexport.*.size" not in left
    assert left == []  # nothing left to fill: the release is unblocked
    ghidra = lock.component("ghidra")
    assert unavailable_reason(ghidra, asset_for(lock, "ghidra", "linux-x86_64")) is None
