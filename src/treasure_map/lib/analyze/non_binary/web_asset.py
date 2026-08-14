# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""WebAsset ingester: detect + ingest HTML/JS/CGI/PHP/etc. web asset files.

Detection: file extension in {html, htm, js, mjs, cgi, php, asp, aspx, jsp, jspx}.
Ingestion: ordered regex extraction of HTTP endpoint references (fetch / axios / XHR /
ajax / form action / cgi_ref / literal path). Stores each endpoint path verbatim as
evidence (the firmware's OWN content; not generated). No AST parser, no new dependency.

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

# ── SaTC front-end surface: USER-EDITABLE form field names (M1) ────────────────────────────────
# A field name is collected only when it is EDITABLE. The name/type attributes sit before any value,
# so matching a tag up to its first '>' is enough even when the value carries a server-side <% %>
# template (which itself contains '>'). Field names are nvram-key-shaped ([A-Za-z0-9_]).
_NAME_ATTR_RE = re.compile(r"""\bname\s*=\s*['"]?([A-Za-z0-9_]+)""", re.IGNORECASE)
_TYPE_ATTR_RE = re.compile(r"""\btype\s*=\s*['"]?([A-Za-z]+)""", re.IGNORECASE)
_INPUT_TAG_RE = re.compile(r"""<input\b([^>]*)>""", re.IGNORECASE)
_TEXTAREA_TAG_RE = re.compile(r"""<textarea\b([^>]*)>""", re.IGNORECASE)
_SELECT_TAG_RE = re.compile(r"""<select\b([^>]*)>""", re.IGNORECASE)
# A JS assignment that WRITES a form field's value (the field is scripted, hence settable).
_JS_FORM_ASSIGN_RE = re.compile(r"""\bdocument\.form\.([A-Za-z0-9_]+)\.value\s*=""", re.IGNORECASE)
# A form-fill helper: nvram_char_to_ascii("area", "key") pre-populates a field from an nvram value —
# the 2nd argument names the key. Catches editable keys a hidden mirror field would otherwise hide.
_NVRAM_ASCII_RE = re.compile(
    r"""nvram_char_to_ascii\(\s*['"][^'"]*['"]\s*,\s*['"]([A-Za-z0-9_]+)['"]""",
    re.IGNORECASE,
)


def _extract_form_fields(text: str) -> list[tuple[str, str]]:
    """Extract (field_keyword, source_rule) pairs for USER-EDITABLE web form fields.

    Editable = a <textarea>/<select> (always user-entry), a NON-hidden <input>, a JS form-value
    assignment, or an nvram_char_to_ascii form-fill. A ``<input type="hidden">`` is a read-only
    round-trip value (e.g. a firmware-version echo from nvram_get) — DELIBERATELY excluded, so a
    displayed-but-not-settable key never enters the front-end surface. Deduped on (keyword, rule).
    """
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def emit(keyword: str | None, rule: str) -> None:
        if not keyword:
            return
        pair = (keyword, rule)
        if pair in seen:
            return
        seen.add(pair)
        out.append(pair)

    for attrs in _INPUT_TAG_RE.findall(text):
        tm = _TYPE_ATTR_RE.search(attrs)
        if tm is not None and tm.group(1).lower() == "hidden":
            continue  # a hidden input is a read-only round-trip value, not user-editable
        nm = _NAME_ATTR_RE.search(attrs)
        emit(nm.group(1) if nm else None, "input")
    for attrs in _TEXTAREA_TAG_RE.findall(text):
        nm = _NAME_ATTR_RE.search(attrs)
        emit(nm.group(1) if nm else None, "textarea")
    for attrs in _SELECT_TAG_RE.findall(text):
        nm = _NAME_ATTR_RE.search(attrs)
        emit(nm.group(1) if nm else None, "select")
    for kw in _JS_FORM_ASSIGN_RE.findall(text):
        emit(kw, "js_assign")
    for kw in _NVRAM_ASCII_RE.findall(text):
        emit(kw, "nvram_ascii")
    return out


def _detect_web_asset(f: NonBinaryFile) -> str | None:
    """Return normalized extension subtype if the file is a web asset, else None."""
    if f.text is None:
        return None
    ext = f.name.rsplit(".", 1)[-1].lower() if "." in f.name else ""
    if ext not in _WEB_EXTENSIONS:
        return None
    return _EXT_NORMALIZE.get(ext, ext)


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
    rows: list[tuple[int, str, str | None, str, str]] = []

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

            rows.append((file_id, subtype, method, path, source))

    if rows:
        conn.executemany(
            """INSERT INTO web_endpoints
               (file_id, asset_type, method, path, source)
               VALUES (?, ?, ?, ?, ?)""",
            rows,
        )

    # M1 SaTC front-end surface: user-editable form field names (a separate table; does not affect
    # the endpoint count this returns). Read-only <input type=hidden> round-trip fields are excluded
    # inside _extract_form_fields, so a displayed-but-not-settable key never enters the surface.
    field_rows = [(file_id, kw, rule) for kw, rule in _extract_form_fields(text)]
    if field_rows:
        conn.executemany(
            """INSERT INTO web_form_fields (file_id, field_keyword, source_rule)
               VALUES (?, ?, ?)""",
            field_rows,
        )
    return len(rows)


WEB_ASSET_INGESTER = NonBinaryIngester(
    kind="web_asset",
    detect=_detect_web_asset,
    ingest=_ingest_web_asset,
)
