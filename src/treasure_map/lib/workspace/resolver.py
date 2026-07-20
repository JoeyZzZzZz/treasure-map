# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Resolve a workspace spec (a name, or nothing) to a concrete directory.

Pure resolution logic — no I/O, no Workspace construction. The CLI calls resolve_workspace
and echoes the result; the rule lives here so it is unit-testable and the CLI stays a thin
wrapper (the three-layer rule: logic in lib/, never in the CLI).

SINGLE SEMANTICS: ``-w`` is always a workspace NAME, placed under ``workspace_dir``. There is no
literal-path mode. A path mode used to exist, but it silently split one logical run across two
physical directories — ``-w router`` (managed) and ``-w ./router`` (a relative path resolved
against the current directory) landed in different places, so a re-scan written one way could not
see data written the other, and it left 0-byte orphan databases behind. A workspace is now
addressed one way only, so the same name always maps to the same directory.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from treasure_map.lib.errors import WorkspaceError

WorkspaceKind = Literal["name", "auto"]

# A managed workspace name: starts alphanumeric, then letters/digits/'.'/'_'/'-'. Anything else
# (notably a path separator) is not a name — it is rejected with a message pointing at name usage.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


@dataclass(frozen=True)
class ResolvedWorkspace:
    """The resolved workspace directory and how the spec was interpreted (for the echo).

    kind is "name" (a managed name under workspace_dir) or "auto" (no spec given — a deterministic
    name derived from the firmware root). Both live under workspace_dir; there is no path mode.
    """

    path: Path
    kind: WorkspaceKind


def _looks_like_path(spec: str) -> bool:
    # A path-ish signal (separator, home prefix, leading dot, or absolute path) means the caller
    # passed a path where a NAME is expected — surfaced as a targeted error, never resolved as one.
    return (
        os.sep in spec
        or "/" in spec
        or spec.startswith("~")
        or spec.startswith(".")
        or os.path.isabs(spec)
    )


def resolve_workspace(spec: str | None, *, workspace_dir: Path, fs_root: Path) -> ResolvedWorkspace:
    """Resolve a workspace spec to a directory under ``workspace_dir``.

    - None -> a deterministic auto name ``analyze_<fs_root-name>_<hash8>`` (hash8 derived from the
      resolved fs_root path: path-stable so re-runs resume; collision-safe across different firmware
      sharing a basename).
    - a NAME -> validated and placed under workspace_dir (kind "name").

    A path-like spec is rejected: ``-w`` is a name, not a path (raises WorkspaceError).
    """
    if spec is None:
        digest = hashlib.sha1(str(fs_root.resolve()).encode()).hexdigest()[:8]
        name = f"analyze_{fs_root.name}_{digest}"
        return ResolvedWorkspace(workspace_dir / name, "auto")

    if _looks_like_path(spec):
        # A path where a name is expected — the exact mix-up that used to split a run in two. Reject
        # it with the managed base and a name suggestion, rather than resolving to a stray dir.
        suggestion = Path(spec).name or "my_run"
        raise WorkspaceError(
            f"workspace {spec!r} looks like a path, but -w takes a NAME, not a path. "
            f"tmap keeps workspaces under {workspace_dir}; pass just a name "
            f"(e.g. -w {suggestion}) and it is placed there."
        )

    if not _NAME_RE.match(spec):
        raise WorkspaceError(
            f"invalid workspace name {spec!r}: a name may contain only letters, digits, "
            "'.', '_', '-' and must start with a letter or digit."
        )
    return ResolvedWorkspace(workspace_dir / spec, "name")


def list_workspace_names(workspace_dir: Path) -> list[str]:
    """The existing workspace names (immediate sub-directories) under ``workspace_dir``, sorted.

    Backs shell completion for ``scan -w`` so a RE-scan can pick an existing name without a typo
    (a typo would silently start a fresh workspace). Completion only SUGGESTS these — a brand-new
    name is still accepted, since scanning new firmware must always be possible. Returns [] when the
    base directory does not exist yet (never raises: a completion helper must not error)."""
    try:
        return sorted(p.name for p in workspace_dir.iterdir() if p.is_dir())
    except OSError:
        return []
