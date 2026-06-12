# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""WebAsset ingester: detect + ingest HTML/JS/CGI/PHP/etc. web asset files.

Detection: file extension in {html, htm, js, mjs, cgi, php, asp, aspx, jsp, jspx}.
Ingestion: ordered regex extraction of HTTP endpoint references (fetch / axios / XHR /
ajax / form action / cgi_ref / literal path). Stores each endpoint path verbatim as
evidence (the firmware's OWN content; not generated). vuln_hint is categorical
only. No AST parser, no new dependency.

A .cgi that begins with a shell shebang is claimed first by the shell_script
ingester (registry index 0) -- its command-injection view is the higher-value analysis.
web_asset covers pure web assets (html/js/templates) and non-shell CGI/PHP only.

ENDPOINT_RULES note: goform and cgi-bin are generic embedded-web-server conventions
(boa/GoAhead), not vendor brands. Do NOT add vendor-specific handler names.
"""

from __future__ import annotations

import re
import sqlite3

from treasure_map.lib.analyze.non_binary.framework import (
    NonBinaryFile,
    NonBinaryIngester,
)

# Categorical vuln_hint vocabulary. Observation labels only -- never a payload.
WEB_ENDPOINT_HINTS: frozenset[str] = frozenset(
    {
        "api_endpoint",
        "cgi_endpoint",
        "param_in_endpoint",
        "external_url",
    }
)

_WEB_EXTENSIONS = frozenset(
    {"html", "htm", "js", "mjs", "cgi", "php", "asp", "aspx", "jsp", "jspx"}
)

_EXT_NORMALIZE: dict[str, str] = {"htm": "html", "mjs": "js"}

# Ordered compiled endpoint-extraction rules. Group semantics by source:
#   fetch / ajax / cgi_ref / literal : group(1) = path
#   axios                             : group(1) = verb, group(2) = path
#   xhr                               : group(1) = method, group(2) = path
#   form                              : group(1) = attribute blob (post-processed below)
_RULES: list[tuple[str, re.Pattern[str]]] = [
    (
        "fetch",
        re.compile(r"""fetch\(\s*['"]([^'"]+)['"]""", re.IGNORECASE),
    ),
    (
        "axios",
        re.compile(
            r"""axios\.(get|post|put|delete|patch)\(\s*['"]([^'"]+)['"]""",
            re.IGNORECASE,
        ),
    ),
    (
        "xhr",
        re.compile(
            r"""\.open\(\s*['"]([A-Za-z]+)['"]\s*,\s*['"]([^'"]+)['"]""",
            re.IGNORECASE,
        ),
    ),
    (
        "ajax",
        re.compile(r"""url\s*:\s*['"]([^'"]+)['"]""", re.IGNORECASE),
    ),
    (
        "form",
        # [^>]* matches across newlines (character class, not .)
        re.compile(r"""<form\b([^>]*)>""", re.IGNORECASE),
    ),
    (
        "cgi_ref",
        re.compile(r"""(/cgi-bin/[A-Za-z0-9_.\-]+)"""),
    ),
    (
        "literal",
        re.compile(r"""['"](/(?:api|rest|goform|cgi-bin)/[^'"\s]*)['"]"""),
    ),
]

_FORM_ACTION_RE = re.compile(r"""\baction\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
_FORM_METHOD_RE = re.compile(r"""\bmethod\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)


def _detect_web_asset(f: NonBinaryFile) -> str | None:
    """Return normalized extension subtype if the file is a web asset, else None."""
    if f.text is None:
        return None
    ext = f.name.rsplit(".", 1)[-1].lower() if "." in f.name else ""
    if ext not in _WEB_EXTENSIONS:
        return None
    return _EXT_NORMALIZE.get(ext, ext)


def _classify_endpoint(path: str) -> str:
    """Return categorical vuln_hint for an endpoint path/URL (labels only)."""
    if "/cgi-bin/" in path.lower():
        return "cgi_endpoint"
    if path.startswith(("http://", "https://")):
        return "external_url"
    if "?" in path or "${" in path or "{{" in path:
        return "param_in_endpoint"
    return "api_endpoint"


def _ingest_web_asset(conn: sqlite3.Connection, file_id: int, f: NonBinaryFile) -> int:
    """Extract and insert web endpoint rows (relevant-only evidence).

    Stores the asset's OWN endpoint references verbatim -- never generates attack output.
    Deduplicates within file on path: specific rules precede the literal catch-all, so
    the first (most context-rich) match wins and literal never double-counts.
    """
    if f.text is None:
        return 0

    subtype = _detect_web_asset(f)
    if subtype is None:
        return 0

    text = f.text
    seen: set[str] = set()  # dedup on path; rule order ensures specific rules win
    rows: list[tuple[int, str, str | None, str, str, str]] = []

    for source, pattern in _RULES:
        for m in pattern.finditer(text):
            method: str | None = None
            path: str | None = None

            if source == "axios":
                method = m.group(1).upper()
                path = m.group(2)
            elif source == "xhr":
                method = m.group(1).upper()
                path = m.group(2)
            elif source == "form":
                attrs = m.group(1)
                am = _FORM_ACTION_RE.search(attrs)
                if am is None:
                    continue
                path = am.group(1)
                mm = _FORM_METHOD_RE.search(attrs)
                method = mm.group(1).upper() if mm else None
            else:
                path = m.group(1)

            if not path:
                continue

            if path in seen:
                continue
            seen.add(path)

            vuln_hint = _classify_endpoint(path)
            rows.append((file_id, subtype, method, path, source, vuln_hint))

    if rows:
        conn.executemany(
            """INSERT INTO web_endpoints
               (file_id, asset_type, method, path, source, vuln_hint)
               VALUES (?, ?, ?, ?, ?, ?)""",
            rows,
        )
    return len(rows)


WEB_ASSET_INGESTER = NonBinaryIngester(
    kind="web_asset",
    detect=_detect_web_asset,
    ingest=_ingest_web_asset,
)
