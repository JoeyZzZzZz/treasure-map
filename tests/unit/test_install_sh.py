# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""install.sh runs under a plain POSIX sh (dash on Debian/Ubuntu/WSL2) and validates what it is
given before doing anything."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "install.sh"
_SH = shutil.which("dash") or "/bin/sh"


def _fake_bin(tmp_path: Path, system: str = "Linux", machine: str = "x86_64") -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    for name, body in {
        "uname": f'#!/bin/sh\ncase "$1" in -s) echo {system};; -m) echo {machine};; esac\n',
        "uv": "#!/bin/sh\necho uv-called >&2\nexit 99\n",
        "curl": "#!/bin/sh\nexit 99\n",
    }.items():
        p = bin_dir / name
        p.write_text(body)
        p.chmod(0o755)
    for tool in ("grep", "printf", "env", "cat"):
        found = shutil.which(tool)
        if found and not (bin_dir / tool).exists():
            (bin_dir / tool).symlink_to(found)
    return bin_dir


def _run(tmp_path: Path, *args: str, **kw: str) -> subprocess.CompletedProcess[str]:
    bin_dir = _fake_bin(tmp_path, **kw)
    env = {"PATH": str(bin_dir), "HOME": str(tmp_path / "sh-home")}
    return subprocess.run(  # noqa: S603 -- fixed argv
        [_SH, str(_SCRIPT), *args],
        capture_output=True,
        text=True,
        env=env,
        stdin=subprocess.DEVNULL,
        timeout=30,
    )


def test_the_script_parses_as_posix_sh() -> None:
    """MUTATION: use ``set -o pipefail`` or ``[[ ]]`` -> dash refuses -> RED."""
    res = subprocess.run([_SH, "-n", str(_SCRIPT)], capture_output=True, text=True)  # noqa: S603
    assert res.returncode == 0, res.stderr
    code = [ln for ln in _SCRIPT.read_text().splitlines() if not ln.lstrip().startswith("#")]
    assert not any("pipefail" in ln or "[[" in ln for ln in code)


def test_dry_run_prints_the_plan_and_runs_nothing(tmp_path: Path) -> None:
    res = _run(tmp_path, "--version", "0.1.0", "--dry-run", "--no-init")
    assert res.returncode == 0, res.stderr
    assert "Version  : 0.1.0" in res.stdout and "Platform : linux-x86_64" in res.stdout
    assert "tmap-agents==0.1.0" in res.stdout and "uv-called" not in res.stderr
    assert not (tmp_path / "sh-home").exists()


@pytest.mark.parametrize("bad", ["1.2", "v0.1.0", "0.1.0; rm -rf /", ""])
def test_a_malformed_version_is_refused(tmp_path: Path, bad: str) -> None:
    res = _run(tmp_path, "--version", bad, "--dry-run")
    assert res.returncode != 0 and "not a version" in res.stderr


def test_an_unversioned_script_refuses(tmp_path: Path) -> None:
    res = _run(tmp_path, "--dry-run")
    assert res.returncode != 0 and "carries no version" in res.stderr


def test_linux_arm_is_refused_with_the_reason(tmp_path: Path) -> None:
    res = _run(tmp_path, "--version", "0.1.0", "--dry-run", machine="aarch64")
    assert res.returncode != 0 and "linux_arm_64" in res.stderr


@pytest.mark.skipif(shutil.which("sed") is None, reason="needs sed")
def test_the_released_script_runs(tmp_path: Path) -> None:
    """The release workflow's own substitution, applied to this script, gives a script that
    runs: the version lands in the assignment and the 'no version' guard does not fire.

    MUTATION: substitute every __TMAP_VERSION__ in the workflow AND name the placeholder
    literally in the guard -> every released script refuses to run -> RED."""
    workflow = (_SCRIPT.parent / ".github" / "workflows" / "release.yml").read_text()
    sed_line = next(ln.strip() for ln in workflow.splitlines() if ln.strip().startswith("sed "))
    command = sed_line.replace("install.sh > upload/install.sh", f'"{_SCRIPT}" > "{tmp_path}/r.sh"')
    res = subprocess.run(  # noqa: S603 -- the workflow's fixed command
        ["/bin/sh", "-c", command],
        capture_output=True,
        text=True,
        env={"V": "0.1.0", "PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        timeout=30,
    )
    assert res.returncode == 0, res.stderr
    script = tmp_path / "r.sh"
    assert 'TMAP_VERSION="0.1.0"' in script.read_text()
    bin_dir = _fake_bin(tmp_path)
    res = subprocess.run(  # noqa: S603
        [_SH, str(script), "--dry-run", "--no-init"],
        capture_output=True,
        text=True,
        env={"PATH": str(bin_dir), "HOME": str(tmp_path / "sh-home")},
        stdin=subprocess.DEVNULL,
        timeout=30,
    )
    assert res.returncode == 0, res.stderr
    assert "Version  : 0.1.0" in res.stdout


def test_the_plan_names_the_binary_and_a_failed_uv_download_says_so(tmp_path: Path) -> None:
    """MUTATION: pipe the uv installer straight into sh -> a failed download is reported as
    "uv cannot be found" -> RED."""
    res = _run(tmp_path, "--version", "0.1.0", "--dry-run", "--no-init")
    assert "Binary   :" in res.stdout and "tmap" in res.stdout
    bin_dir = _fake_bin(tmp_path)
    (bin_dir / "uv").unlink()  # no uv: the installer must be fetched, and curl fails
    for tool in ("mktemp", "rm", "sh"):
        found = shutil.which(tool)
        if found and not (bin_dir / tool).exists():
            (bin_dir / tool).symlink_to(found)
    res = subprocess.run(  # noqa: S603
        [_SH, str(_SCRIPT), "--version", "0.1.0", "--no-init"],
        capture_output=True,
        text=True,
        env={"PATH": str(bin_dir), "HOME": str(tmp_path / "sh-home")},
        stdin=subprocess.DEVNULL,
        timeout=30,
    )
    assert res.returncode != 0 and "could not download the uv installer" in res.stderr
