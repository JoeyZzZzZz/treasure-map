# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""``config.yaml`` and ``.env`` in ~/.treasure-map: written by ``tmap init``, or by the user.

``tmap uninstall --purge-data`` deletes the ones tmap wrote and keeps the ones it did not, so tmap
marks its own with a first-line comment. Every tmap write of config.yaml goes through
``config_text``, which keeps the mark on a file that has it and never adds it to one that does
not: rewriting a user's file leaves it the user's."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

MARK = "# Written by tmap init."
_HEADER = f"{MARK} `tmap uninstall --purge-data` deletes this file.\n"
ENV_TEXT = (
    _HEADER
    + "# KEY=value lines here are set for every tmap command; a variable already set in the "
    "environment wins.\n"
)


def written_by_tmap(path: Path) -> bool:
    """Whether ``path`` starts with tmap's mark. A file that cannot be read is not tmap's."""
    try:
        with path.open("rb") as fh:
            return fh.readline().startswith(MARK.encode())
    except OSError:
        return False


def config_text(path: Path, data: dict[str, Any]) -> str:
    """The text tmap writes to config.yaml at ``path``: ``data`` as YAML, marked when tmap creates
    the file or the file already carries the mark."""
    body = yaml.safe_dump(data, default_flow_style=False)
    if not path.exists() or written_by_tmap(path):
        return _HEADER + body
    return body
