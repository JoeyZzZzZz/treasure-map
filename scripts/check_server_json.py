# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""server.json agrees with the package it points at — the MCP registry's publish preconditions.

    python scripts/check_server_json.py [repo root]

The registry hosts metadata only: at publish time it fetches the named PyPI package and looks for
an ``mcp-name: <server name>`` marker in its README (the PyPI long description) to prove the
publisher owns it. Everything that marker, the package name and the version are checked against
lives in four separate files here, so a release can go out with them disagreeing and fail only at
the last step — after PyPI already has the version, which cannot be re-used. This is that check,
run in CI on every push, in the same spirit as the release's "the tag matches __version__" gate.

Each rule is stated once and the message says which file to change.
"""

from __future__ import annotations

import json
import runpy
import sys
import tomllib
from pathlib import Path

# The marker is matched by the registry, so it has to end on a boundary: a newline, whitespace, an
# HTML tag, or the comment close. Glued to a sentence-ending period it does not match.
_BOUNDARY = ("\n", "\r", " ", "\t", "<", "-")


def problems(root: Path) -> list[str]:
    """Every disagreement found, as a message naming the file to change. Empty means consistent."""
    out: list[str] = []
    server = json.loads((root / "server.json").read_text(encoding="utf-8"))
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = runpy.run_path(str(root / "src" / "treasure_map" / "version.py"))["__version__"]

    name = server["name"]
    if server.get("version") != version:
        out.append(f"server.json version {server.get('version')!r} != __version__ {version!r}")

    packages = server.get("packages") or []
    if len(packages) != 1:
        out.append(f"server.json: expected exactly one package, found {len(packages)}")
    for i, pkg in enumerate(packages):
        where = f"server.json packages[{i}]"
        if pkg.get("version") != version:
            out.append(f"{where} version {pkg.get('version')!r} != __version__ {version!r}")
        if pkg.get("registryType") != "pypi":
            out.append(f"{where} registryType is {pkg.get('registryType')!r}, not 'pypi'")
        elif pkg.get("identifier") != pyproject["name"]:
            out.append(
                f"{where} identifier {pkg.get('identifier')!r} != the distribution name "
                f"{pyproject['name']!r} in pyproject.toml"
            )
        # A client told runtimeHint 'uvx' runs `uvx <identifier> <args>`, and uvx runs the command
        # named after the package: without that console script the published call does not start.
        if pkg.get("runtimeHint") == "uvx":
            scripts = pyproject.get("scripts", {})
            if pkg.get("identifier") not in scripts:
                out.append(
                    f"{where} hints uvx, so pyproject.toml [project.scripts] needs a "
                    f"{pkg.get('identifier')!r} entry point (it has: {sorted(scripts)})"
                )

    readme_name = pyproject["readme"]
    readme = (root / readme_name).read_text(encoding="utf-8")
    marker = f"mcp-name: {name}"
    at = readme.find(marker)
    if at < 0:
        out.append(
            f"{readme_name} carries no {marker!r} — the registry reads it from the PyPI "
            f"description to verify ownership of {pyproject['name']!r}"
        )
    else:
        after = readme[at + len(marker) : at + len(marker) + 1]
        if after and not after.startswith(_BOUNDARY):
            out.append(
                f"{readme_name}: the marker is followed by {after!r}; the registry needs a "
                f"boundary there (newline, whitespace, an HTML tag, or '-->')"
            )
    return out


def main(argv: list[str]) -> int:
    root = Path(argv[0]) if argv else Path(__file__).resolve().parent.parent
    found = problems(root)
    for line in found:
        print(line, file=sys.stderr)
    if found:
        return 1
    print("server.json agrees with version.py, pyproject.toml and the README marker")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
