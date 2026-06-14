# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Resolve a workspace spec (a name, a path, or nothing) to a concrete directory.

Pure resolution logic — no I/O, no Workspace construction. The CLI calls resolve_workspace
and echoes the result; the rule for distinguishing a managed NAME from a literal PATH lives
here so it is unit-testable and the CLI stays a thin wrapper (the three-layer rule: logic in
lib/, never in the CLI).
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from treasure_map.lib.errors import WorkspaceError

WorkspaceKind = Literal["name", "path", "auto"]

# A managed workspace name: starts alphanumeric, then letters/digits/'.'/'_'/'-'. A value that
# wants any other character (notably a path separator) is treated as an explicit path instead.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


@dataclass(frozen=True)
class ResolvedWorkspace:
    """The resolved workspace directory and how the spec was interpreted (for the echo).

    kind is "name" (managed under workspace_dir), "path" (a literal path used verbatim), or
    "auto" (no spec given — a deterministic name derived from the firmware root).
    """

    path: Path
    kind: WorkspaceKind


def _looks_like_path(spec: str) -> bool:
    # Any path-ish signal routes to literal-path handling: a separator, a home prefix, a
    # leading dot (./ .. .), or an absolute path. A click.Path type would erase these signals,
    # which is why the CLI passes the raw string.
    return (
        os.sep in spec
        or "/" in spec
        or spec.startswith("~")
        or spec.startswith(".")
        or os.path.isabs(spec)
    )


def resolve_workspace(spec: str | None, *, workspace_dir: Path, fs_root: Path) -> ResolvedWorkspace:
    """Resolve a workspace spec to a directory.

    - None  -> deterministic auto name `analyze_<fs_root-name>_<hash8>` under workspace_dir,
      where hash8 is derived from the resolved fs_root path (path-stable so re-runs resume;
      collision-safe across different firmware sharing a basename).
    - a PATH (separator / ~ / leading '.' / absolute) -> used verbatim (kind "path").
    - otherwise a NAME -> validated and placed under workspace_dir (kind "name").

    Raises WorkspaceError for an illegal name.
    """
    if spec is None:
        digest = hashlib.sha1(str(fs_root.resolve()).encode()).hexdigest()[:8]
        name = f"analyze_{fs_root.name}_{digest}"
        return ResolvedWorkspace(workspace_dir / name, "auto")

    if _looks_like_path(spec):
        return ResolvedWorkspace(Path(os.path.expanduser(spec)), "path")

    if not _NAME_RE.match(spec) or spec in (".", ".."):
        raise WorkspaceError(
            f"invalid workspace name {spec!r}: a name may contain only letters, digits, "
            "'.', '_', '-' and must start alphanumeric; use an explicit path (with a '/') "
            "for anything else"
        )
    return ResolvedWorkspace(workspace_dir / spec, "name")
