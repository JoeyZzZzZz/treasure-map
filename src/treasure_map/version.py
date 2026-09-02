# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from importlib.metadata import distribution

__version__ = "0.1.0"

# The explicit "we could not confirm which version produced this" sentinel for any recorded
# analysis-tool version. It is a VALUE, never None: a missing/undetectable version must stay
# visible and be read conservatively (cannot-confirm-same is not confirmed-same), and a None
# would instead let a comparison short-circuit into a silent "no skew".
UNKNOWN_VERSION = "unknown"


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
    """
    try:
        raw = distribution("treasure-map").read_text("direct_url.json")
    except Exception:
        return UNKNOWN_VERSION
    if not raw:
        return UNKNOWN_VERSION
    try:
        info = json.loads(raw)
    except (TypeError, ValueError):
        return UNKNOWN_VERSION
    vcs = info.get("vcs_info") if isinstance(info, dict) else None
    commit = vcs.get("commit_id") if isinstance(vcs, dict) else None
    return commit if isinstance(commit, str) and commit else UNKNOWN_VERSION
