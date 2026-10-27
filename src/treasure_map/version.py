# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib
import json
import re
from importlib.metadata import Distribution, distribution

# The one place the version is written: pyproject.toml reads it from here (dynamic version).
__version__ = "0.1.1"

# The explicit "we could not confirm which version produced this" sentinel for any recorded
# analysis-tool version. It is a VALUE, never None: a missing/undetectable version must stay
# visible and be read conservatively (cannot-confirm-same is not confirmed-same), and a None
# would instead let a comparison short-circuit into a silent "no skew".
UNKNOWN_VERSION = "unknown"

_DIST_NAME = "tmap-agents"

_COMMIT_RE = re.compile(r"[0-9a-f]{40}")


def _dist(name: str) -> Distribution | None:
    try:
        return distribution(name)
    except Exception:
        return None


def _baked_commit() -> str | None:
    """The commit a release build wrote into ``treasure_map/_build_info.py``, or None. Only the
    release workflow writes that file, on a clean tree at the tagged commit; git ignores it."""
    try:
        module = importlib.import_module("treasure_map._build_info")
    except ImportError:
        return None
    commit = getattr(module, "COMMIT", None)
    return commit if isinstance(commit, str) and _COMMIT_RE.fullmatch(commit) else None


def installed_commit() -> str:
    """The git commit of the tmap that is ACTUALLY RUNNING, or the unknown sentinel.

    Read from the distribution's own install record — what pip/uv wrote down when it installed
    this code — so it identifies the artifact in use rather than the state of some checkout.

    ★ Never derived from the working tree. Asking git for HEAD would answer confidently and
    sometimes wrongly: an editable install with uncommitted edits runs code that no commit
    describes, and a commit id invented for it would mark a scan as reproducible when it is not.
    An install with no recorded commit (an editable one, most often a developer's) yields the
    unknown sentinel instead, which the staleness rules treat as "cannot confirm this is current"
    — the conservative reading, never as "current".

    Which record is trusted depends on how the code was installed:

      * an install with a ``direct_url.json`` (from git, a local directory, a wheel given by path,
        an editable checkout) — only the VCS commit it records. A ``_build_info.py`` left in such
        a tree may describe some other build, so it is never read there.
      * an install from a package index, which writes no ``direct_url.json`` — the commit the
        release build baked into ``_build_info.py``.
    """
    dist = _dist(_DIST_NAME)
    if dist is None:
        return UNKNOWN_VERSION
    try:
        raw = dist.read_text("direct_url.json")
    except Exception:
        return UNKNOWN_VERSION
    if raw:
        try:
            info = json.loads(raw)
        except (TypeError, ValueError):
            return UNKNOWN_VERSION
        vcs = info.get("vcs_info") if isinstance(info, dict) else None
        commit = vcs.get("commit_id") if isinstance(vcs, dict) else None
        return commit if isinstance(commit, str) and commit else UNKNOWN_VERSION
    return _baked_commit() or UNKNOWN_VERSION
