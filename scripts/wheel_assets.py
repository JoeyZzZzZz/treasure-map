# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The non-.py files a tmap wheel must ship — one list, used by the tests, CI and the release.

    python scripts/wheel_assets.py dist/tmap_agents-*.whl [--with-build-info]   # zip contents
    python -I scripts/wheel_assets.py --installed   # an INSTALLED tmap resolves every asset

The second form is the one an editable install cannot fake: run from a fresh venv holding the
built wheel, it reads each asset through importlib.resources from the installed package.
"""

from __future__ import annotations

import sys
import zipfile

# (package, resource) for every non-.py file the runtime loads from disk.
ASSETS: tuple[tuple[str, str], ...] = (
    ("treasure_map.lib.analyze.ghidra", "ExportFunctions.java"),
    ("treasure_map.lib.analyze.ghidra", "extractor_names.tsv"),
    ("treasure_map.lib.diff.ghidra", "ExportBinExport.java"),
    ("treasure_map.lib.diff.ghidra", "FallbackBinExport2Builder.java"),
    ("treasure_map.lib.storage", "atlas_schema.sql"),
    ("treasure_map.lib.storage", "schema.sql"),
    ("treasure_map.lib.setup", "toolchain_lock.json"),
)


def wheel_paths() -> list[str]:
    """Each asset's path inside a wheel."""
    return [f"{pkg.replace('.', '/')}/{name}" for pkg, name in ASSETS]


def missing_from_wheel(wheel: str, extra: tuple[str, ...] = ()) -> list[str]:
    names = set(zipfile.ZipFile(wheel).namelist())
    return [p for p in (*wheel_paths(), *extra) if p not in names]


def missing_from_installed() -> list[str]:
    from importlib.resources import files

    return [f"{pkg}/{name}" for pkg, name in ASSETS if not (files(pkg) / name).is_file()]


def main(argv: list[str]) -> int:
    if argv == ["--installed"]:
        missing = missing_from_installed()
    elif argv and argv[0].endswith(".whl") and set(argv[1:]) <= {"--with-build-info"}:
        # The release bakes the commit in before building; any other build need not carry it.
        extra = ("treasure_map/_build_info.py",) if "--with-build-info" in argv[1:] else ()
        missing = missing_from_wheel(argv[0], extra)
    else:
        print(__doc__, file=sys.stderr)
        return 2
    if missing:
        print(f"missing: {missing}", file=sys.stderr)
        return 1
    print("all assets present")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
