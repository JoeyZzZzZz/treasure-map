# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Discovery of an existing toolchain: every candidate checked at file level, never the first
one merely found."""

from __future__ import annotations

from pathlib import Path

import pytest

from treasure_map.lib.setup.discover import (
    check_jdk,
    discover_bindiff,
    discover_binexport,
    discover_ghidra,
    discover_jdk,
    first_ok,
)

from . import fakes


def test_a_wrong_ghidra_version_in_config_does_not_win(tmp_path: Path) -> None:
    """★ config names 11.4.2, PATH leads to 11.4.3: 11.4.3 is chosen, and both are listed.

    MUTATION: compare versions with ``startswith("11.4")`` -> the config's 11.4.2 wins -> RED."""
    old = fakes.make_ghidra(tmp_path / "old", version="11.4.2")
    new = fakes.make_ghidra(tmp_path / "new")
    host = fakes.make_host(
        tmp_path / "home", which={"analyzeHeadless": str(new / "support" / "analyzeHeadless")}
    )
    cands = discover_ghidra(host, config_home=old, want="11.4.3")
    assert [c.path for c in cands] == [old, new]
    assert [c.source for c in cands] == ["config", "PATH"]
    chosen = first_ok(cands)
    assert chosen is not None and chosen.path == new
    assert cands[0].why_not is not None and "11.4.2" in cands[0].why_not


def test_a_jre_is_not_a_jdk(tmp_path: Path) -> None:
    """Ghidra refuses a JRE. MUTATION: drop the javac check -> RED."""
    jre = fakes.make_jdk(tmp_path / "jre", javac=False)
    _v, why = check_jdk(jre)
    assert why is not None and "javac" in why
    host = fakes.make_host(tmp_path / "home", environ={"JAVA_HOME": str(jre)})
    cands = discover_jdk(host, config_java_home=None, ghidra_home=None, pinned="21.0.12.1+1")
    assert cands and not cands[0].ok
    assert check_jdk(fakes.make_jdk(tmp_path / "jdk17", "17.0.2"))[1] is not None


def test_a_jdk_patch_release_is_accepted_with_a_note(tmp_path: Path) -> None:
    jdk = fakes.make_jdk(tmp_path / "jdk", "21.0.4")
    host = fakes.make_host(tmp_path / "home")
    cands = discover_jdk(host, config_java_home=jdk, ghidra_home=None, pinned="21.0.12.1+1")
    assert cands[0].ok and cands[0].note and "21.0.12.1+1" in cands[0].note


def test_the_jdk_ghidra_saved_is_a_candidate(tmp_path: Path) -> None:
    home = tmp_path / "home"
    ghidra = fakes.make_ghidra(tmp_path / "g")
    jdk = fakes.make_jdk(tmp_path / "jdk")
    settings = home / ".config" / "ghidra" / "ghidra_11.4.3_PUBLIC"
    settings.mkdir(parents=True)
    (settings / "java_home.save").write_text(str(jdk))
    cands = discover_jdk(
        fakes.make_host(home), config_java_home=None, ghidra_home=ghidra, pinned="21.0.12.1+1"
    )
    assert [(c.path, c.source) for c in cands] == [(jdk, "java_home.save")]


def test_tmaps_own_directory_counts_only_through_the_ledger(tmp_path: Path) -> None:
    """A Ghidra under ~/.treasure-map/toolchain that the ledger does not record is not a
    candidate — neither as the user's nor as tmap's."""
    home = tmp_path / "home"
    stray = fakes.make_ghidra(home / ".treasure-map" / "toolchain" / "ghidra_11.4.3_PUBLIC")
    host = fakes.make_host(home)
    assert discover_ghidra(host, config_home=stray, want="11.4.3") == []
    managed = discover_ghidra(host, config_home=stray, want="11.4.3", managed=[stray])
    assert len(managed) == 1 and managed[0].managed and managed[0].ok


def test_the_directory_scan_finds_a_ghidra_by_name(tmp_path: Path) -> None:
    home = tmp_path / "home"
    g = fakes.make_ghidra(home / "tools" / "ghidra_11.4.3_PUBLIC")
    cands = discover_ghidra(fakes.make_host(home), config_home=None, want="11.4.3")
    assert [c.path for c in cands] == [g] and cands[0].source.startswith("scan:")


def test_binexport_two_copies_and_the_legacy_dir(tmp_path: Path) -> None:
    home = tmp_path / "home"
    ghidra = fakes.make_ghidra(tmp_path / "g")
    fakes.make_binexport(home / ".ghidra" / ".ghidra_11.4.3_PUBLIC" / "Extensions" / "BinExport")
    host = fakes.make_host(home)
    f = discover_binexport(host, ghidra, pinned_digest=None)
    assert f.candidates == [] and len(f.legacy) == 1 and not f.unknown
    fakes.make_binexport(ghidra / "Ghidra" / "Extensions" / "BinExport")
    assert discover_binexport(host, ghidra, pinned_digest=None).chosen() is not None
    fakes.make_binexport(
        home / ".config" / "ghidra" / "ghidra_11.4.3_PUBLIC" / "Extensions" / "BinExport"
    )
    two = discover_binexport(host, ghidra, pinned_digest=None)
    assert len(two.candidates) == 2 and two.chosen() is None
    assert all(c.why_not == "two copies; Ghidra may load either" for c in two.candidates)


def test_binexport_of_another_version_is_not_used(tmp_path: Path) -> None:
    ghidra = fakes.make_ghidra(tmp_path / "g")
    fakes.make_binexport(ghidra / "Ghidra" / "Extensions" / "BinExport", version="10.3.3")
    f = discover_binexport(fakes.make_host(tmp_path / "home"), ghidra, pinned_digest="0" * 64)
    assert f.chosen() is None and "10.3.3" in (f.candidates[0].why_not or "")


def test_bindiff_is_checked_by_running_it(tmp_path: Path) -> None:
    exe = fakes.make_bindiff(tmp_path / "bin" / "bindiff")
    host = fakes.make_host(tmp_path / "home", which={"bindiff": str(exe)})
    cands = discover_bindiff(host, config_bindiff=None, version_line=fakes.BINDIFF_LINE)
    assert cands[0].ok and cands[0].version == fakes.BINDIFF_LINE and cands[0].note is None
    other = discover_bindiff(host, config_bindiff=None, version_line="BinDiff 8 (@1, Jan 1 2024)")
    assert other[0].ok and other[0].note  # accepted, with the difference said


def test_a_scanned_directory_without_java_is_not_listed(tmp_path: Path) -> None:
    """A distribution's source-only sibling (``/usr/lib/jvm/openjdk-21`` holding just src.zip) is
    no Java install: listing it as "not used" reads like a missing JDK.

    MUTATION: list every scanned directory -> the source-only one appears -> RED."""
    import dataclasses

    jvm = tmp_path / "jvm"
    jdk = fakes.make_jdk(jvm / "java-21-openjdk-amd64")
    (jvm / "openjdk-21").mkdir()
    (jvm / "openjdk-21" / "src.zip").write_bytes(b"")
    broken = jvm / "half-installed"
    (broken / "bin").mkdir(parents=True)
    (broken / "bin" / "java").write_text("")
    host = dataclasses.replace(fakes.make_host(tmp_path / "home"), jdk_globs=(str(jvm / "*"),))
    cands = discover_jdk(host, config_java_home=None, ghidra_home=None, pinned="21.0.12.1+1")
    assert [c.path for c in cands] == [broken, jdk]  # a java with no release is still reported
    assert not cands[0].ok and cands[1].ok


def test_the_scan_skips_tmaps_directory_and_mnt(tmp_path: Path) -> None:
    """MUTATION: drop the skip list -> a Ghidra inside ~/.treasure-map is offered as the user's
    -> RED."""
    from treasure_map.lib.setup.discover import _shallow_ghidra_scan

    home = tmp_path / "home"
    fakes.make_ghidra(home / ".treasure-map" / "old" / "ghidra_11.4.3_PUBLIC")
    mine = fakes.make_ghidra(home / "tools" / "ghidra_11.4.3_PUBLIC")
    assert discover_ghidra(fakes.make_host(home), config_home=None, want="11.4.3")[0].path == mine
    assert len(discover_ghidra(fakes.make_host(home), config_home=None, want="11.4.3")) == 1
    mnt = tmp_path / "mnt"
    fakes.make_ghidra(mnt / "c" / "ghidra_11.4.3_PUBLIC")
    assert _shallow_ghidra_scan([tmp_path], skip=[mnt, home]) == []


def test_the_real_machine_probe_lists(monkeypatch: pytest.MonkeyPatch) -> None:
    """The system locations the unit conftest switches off are still the right ones.

    MUTATION: drop /usr/lib/jvm/* (or the /opt/bindiff, ~/.jdks entries) -> RED."""
    from treasure_map.lib.setup import discover

    monkeypatch.setattr(discover, "SYSTEM_PROBES", True)
    linux = discover.current_host(fakes.linux())
    assert "/usr/lib/jvm/*" in linux.jdk_globs
    assert any(g.endswith("/.jdks/*") for g in linux.jdk_globs)
    assert Path("/opt/bindiff/bin/bindiff") in linux.bindiff_paths
    assert Path("/opt") in linux.ghidra_scan_roots
    mac = discover.current_host(fakes.darwin_arm())
    assert "/Library/Java/JavaVirtualMachines/*/Contents/Home" in mac.jdk_globs
    assert Path("/Applications/BinDiff/BinDiff.app/Contents/MacOS/bin/bindiff") in mac.bindiff_paths


def test_the_macos_java_stub_is_not_a_jdk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """/usr/bin/java on a Mac is a launcher stub: listing /usr as a JDK that failed its check is
    noise on every init.

    MUTATION: take the java on PATH as a JDK home on macOS too -> /usr is a candidate -> RED."""
    from treasure_map.lib.setup import discover as d

    host = fakes.make_host(tmp_path, platform=fakes.darwin_arm(), which={"java": "/usr/bin/java"})
    monkeypatch.setattr(d.os.path, "realpath", lambda p: str(p))
    found = d.discover_jdk(host, config_java_home=None, ghidra_home=None, pinned="21.0.12.1")
    assert all(c.path != Path("/usr") for c in found)


def test_macos_home_jdks_are_looked_for_in_their_bundle_layout() -> None:
    """MUTATION: drop the macOS bundle globs -> an IntelliJ / sdkman JDK on a Mac is never seen
    and ~200MB is downloaded again -> RED."""
    from treasure_map.lib.setup.discover import current_host

    globs = current_host(fakes.darwin_arm()).jdk_globs
    assert any(g.endswith("Library/Java/JavaVirtualMachines/*/Contents/Home") for g in globs)
    assert any(g.endswith(".sdkman/candidates/java/*/Contents/Home") for g in globs)
    assert not any("Contents/Home" in g for g in current_host(fakes.linux()).jdk_globs)
