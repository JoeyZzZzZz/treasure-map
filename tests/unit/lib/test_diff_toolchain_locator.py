# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Where Ghidra 11.4 loads BinExport from, and the stamp a diff records for it.

Ghidra 11.4 loads extensions from its own ``Ghidra/Extensions`` and from the user settings
directory (``$XDG_CONFIG_HOME`` or ``~/.config`` / ``~/Library``, then ``[<user>-]ghidra/
ghidra_<version>_<release>``) — NOT from the old ``~/.ghidra/.ghidra_<version>`` one. The diff's
preflight (driver._binexport_present) and the toolchain stamp read the same locator, and the
stamp carries a digest of the jars so two builds of one version stamp apart."""

from __future__ import annotations

from pathlib import Path

import pytest

from treasure_map.lib.config.config import Config, GhidraConfig, GhidraLocalConfig
from treasure_map.lib.diff import driver
from treasure_map.lib.diff import toolchain as tc

from .setup import fakes

# conftest replaces detect_toolchain module-wide; the real one is what these tests are about.
_REAL_DETECT = tc.detect_toolchain


@pytest.fixture()
def ghidra(tmp_path: Path) -> Path:
    return fakes.make_ghidra(tmp_path / "opt" / "ghidra_11.4.3_PUBLIC")


def _dirs(home: Path, user_home: Path, environ: dict[str, str] | None = None) -> list[Path] | None:
    return tc.binexport_dirs(
        home, environ=environ or {}, user_home=user_home, platform="linux", user_name="tester"
    )


def test_settings_dir_rules(tmp_path: Path, ghidra: Path) -> None:
    """MUTATION: drop the ``<user>-`` prefix rule, accept a relative XDG_CONFIG_HOME, or ignore an
    uncommented -Dapplication.settingsdir -> RED."""
    home = tmp_path / "home"
    default = tc.ghidra_settings_dir(
        ghidra, environ={}, user_home=home, platform="linux", user_name="tester"
    )
    assert default == home / ".config" / "ghidra" / "ghidra_11.4.3_PUBLIC"
    mac = tc.ghidra_settings_dir(
        ghidra, environ={}, user_home=home, platform="darwin", user_name="tester"
    )
    assert mac == home / "Library" / "ghidra" / "ghidra_11.4.3_PUBLIC"
    inside = tc.ghidra_settings_dir(
        ghidra,
        environ={"XDG_CONFIG_HOME": str(home / "cfg")},
        user_home=home,
        platform="linux",
        user_name="tester",
    )
    assert inside == home / "cfg" / "ghidra" / "ghidra_11.4.3_PUBLIC"
    outside = tc.ghidra_settings_dir(
        ghidra,
        environ={"XDG_CONFIG_HOME": str(tmp_path / "elsewhere")},
        user_home=home,
        platform="linux",
        user_name="tester",
    )
    assert outside == tmp_path / "elsewhere" / "tester-ghidra" / "ghidra_11.4.3_PUBLIC"
    relative = tc.ghidra_settings_dir(
        ghidra,
        environ={"XDG_CONFIG_HOME": "relative/cfg"},
        user_home=home,
        platform="linux",
        user_name="tester",
    )
    assert relative is None
    (ghidra / "support" / "launch.properties").write_text(
        "VMARGS=-Dapplication.settingsdir=/somewhere\n"
    )
    assert (
        tc.ghidra_settings_dir(
            ghidra, environ={}, user_home=home, platform="linux", user_name="tester"
        )
        is None
    )


def test_only_the_loaded_locations_count(tmp_path: Path, ghidra: Path) -> None:
    """★ A copy only in the old ~/.ghidra directory is NOT loaded by Ghidra 11.4.3; one in the
    settings directory IS; one marked .uninstalled is not.

    MUTATION: restore the old directory set (install dir + ~/.ghidra/.ghidra_*) -> the first two
    assertions go RED."""
    home = tmp_path / "home"
    fakes.make_binexport(home / ".ghidra" / ".ghidra_11.4.3_PUBLIC" / "Extensions" / "BinExport")
    assert _dirs(ghidra, home) == []
    settings_copy = fakes.make_binexport(
        home / ".config" / "ghidra" / "ghidra_11.4.3_PUBLIC" / "Extensions" / "BinExport"
    )
    assert _dirs(ghidra, home) == [settings_copy]
    (settings_copy / "extension.properties.uninstalled").write_text("")
    assert _dirs(ghidra, home) == []


def test_two_loaded_copies_are_not_a_version(
    tmp_path: Path, ghidra: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Install dir AND settings dir both carry one: Ghidra may load either, so no stamp is given
    and the diff preflight does not call it present.

    MUTATION: take the first copy found -> RED."""
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    fakes.make_binexport(ghidra / "Ghidra" / "Extensions" / "BinExport")
    assert tc._binexport_version(ghidra) is not None
    assert driver._binexport_present(ghidra / "support" / "analyzeHeadless") is True
    fakes.make_binexport(
        home / ".config" / "ghidra" / "ghidra_11.4.3_PUBLIC" / "Extensions" / "BinExport"
    )
    assert tc._binexport_version(ghidra) is None
    assert driver._binexport_present(ghidra / "support" / "analyzeHeadless") is False


def test_a_symlinked_launcher_reads_the_same_as_the_stamp(
    tmp_path: Path, ghidra: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``analyzeHeadless`` reached through a symlink (a PATH shim) resolves to the install, for
    the preflight exactly as for detect_toolchain.

    MUTATION: drop ``.resolve()`` from _binexport_present -> the shim's grandparent has no
    Extensions -> False while the stamp says present -> RED."""
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    fakes.make_binexport(ghidra / "Ghidra" / "Extensions" / "BinExport")
    shim = tmp_path / "bin" / "analyzeHeadless"
    shim.parent.mkdir()
    shim.symlink_to(ghidra / "support" / "analyzeHeadless")
    bindiff = fakes.make_bindiff(tmp_path / "bin" / "bindiff")
    monkeypatch.setenv("PATH", f"{bindiff.parent}:/usr/bin:/bin")
    cfg = Config(ghidra=GhidraConfig(local=GhidraLocalConfig(home=ghidra)))
    found = _REAL_DETECT(cfg)
    assert found is not None and found.binexport.startswith("11.4.3+lib:")
    assert driver._binexport_present(shim) is True


def test_the_stamp_follows_the_jars(
    tmp_path: Path, ghidra: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A different build of the same version stamps differently — any jar under lib/.

    MUTATION: stamp the properties version alone -> RED."""
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    ext = fakes.make_binexport(ghidra / "Ghidra" / "Extensions" / "BinExport")
    first = tc._binexport_version(ghidra)
    assert (
        first is not None
        and first.startswith("11.4.3+lib:")
        and len(first) == len("11.4.3+lib:") + 12
    )
    (ext / "lib" / "BinExport.jar").write_bytes(b"jar-bytez")
    second = tc._binexport_version(ghidra)
    (ext / "lib" / "protobuf-java-3.25.jar").write_bytes(b"x")
    third = tc._binexport_version(ghidra)
    assert len({first, second, third}) == 3


def test_what_counts_as_a_loaded_copy(tmp_path: Path, ghidra: Path) -> None:
    """A Module.manifest.uninstalled marker removes a copy; a copy without lib/BinExport.jar is not
    loadable; the same directory reached twice (a symlinked settings dir) is one copy.

    MUTATION: drop any of the three rules -> RED."""
    home = tmp_path / "home"
    installed = fakes.make_binexport(ghidra / "Ghidra" / "Extensions" / "BinExport")
    (installed / "Module.manifest.uninstalled").write_text("")
    assert _dirs(ghidra, home) == []
    (installed / "Module.manifest.uninstalled").unlink()
    (installed / "lib" / "BinExport.jar").unlink()
    assert _dirs(ghidra, home) == []
    (installed / "lib" / "BinExport.jar").write_bytes(b"jar")
    settings_ext = home / ".config" / "ghidra" / "ghidra_11.4.3_PUBLIC" / "Extensions"
    settings_ext.mkdir(parents=True)
    (settings_ext / "BinExport").symlink_to(installed)
    assert _dirs(ghidra, home) == [installed]
